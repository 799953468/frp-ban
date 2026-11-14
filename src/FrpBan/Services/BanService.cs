using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;
using FrpBan.Configuration;
using FrpBan.Models;
using FrpBan.Protocol;
using FrpBan.Security;
using Microsoft.Extensions.Options;

namespace FrpBan.Services;

/// <summary>Canonical IP bans with a bounded, coalescing, single-writer persistence queue.</summary>
public sealed class BanService : IBanService, IDisposable, IAsyncDisposable
{
    private readonly PluginSettings _settings;
    private readonly ILogger<BanService> _logger;
    private readonly IpExemptionList _exemptions;
    private readonly ConcurrentDictionary<string, BanEntry> _bans = new(StringComparer.Ordinal);

    private readonly Channel<byte> _changes = Channel.CreateBounded<byte>(new BoundedChannelOptions(1)
    {
        SingleReader = true,
        FullMode = BoundedChannelFullMode.DropWrite,
    });

    private readonly Timer _cleanupTimer;
    private readonly Timer _retryTimer;
    private readonly Task _persistenceTask;
    private readonly object _lifecycle = new();
    private TaskCompletionSource<Exception?>? _pendingPersistence;
    private TaskCompletionSource<Exception?>? _activePersistence;
    private Task? _disposeTask;
    private int _isDirty;

    /// <summary>Creates the ban store and starts its single persistence worker.</summary>
    public BanService(IOptions<PluginSettings> settings, ILogger<BanService> logger)
    {
        _settings = settings.Value;
        _logger = logger;
        _exemptions = new IpExemptionList(_settings.ExemptAddresses);
        _persistenceTask = PersistLoopAsync();
        _cleanupTimer = new Timer(CleanupExpiredBans, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
        _retryTimer = new Timer(_ =>
        {
            if (Volatile.Read(ref _isDirty) != 0)
            {
                _changes.Writer.TryWrite(0);
            }
        }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    /// <summary>Loads active, non-exempt bans before traffic is accepted; corrupted storage fails startup.</summary>
    public void Load()
    {
        if (!File.Exists(_settings.BanFilePath))
        {
            return;
        }

        List<BanEntry> entries;
        using (var stream = File.OpenRead(_settings.BanFilePath))
        {
            entries = JsonSerializer.Deserialize(stream, ServerJsonContext.Default.ListBanEntry)
                      ?? throw new InvalidDataException("Ban file must contain a JSON array.");
        }

        var exemptCount = 0;
        foreach (var entry in entries)
        {
            if (entry is null || !entry.IsActive)
            {
                continue;
            }

            var ip = IpAddressUtilities.Normalize(entry.Ip);
            if (ip is null)
            {
                throw new InvalidDataException("Ban file contains an invalid IP address.");
            }

            if (IsExempt(ip))
            {
                exemptCount++;
                continue;
            }

            if (!_bans.ContainsKey(ip) && _bans.Count >= _settings.MaxBanEntries)
            {
                throw new InvalidDataException("Ban file exceeds MaxBanEntries.");
            }

            _bans.AddOrUpdate(ip, entry with { Ip = ip }, (_, previous) =>
                previous.BannedAt > entry.BannedAt ? previous : entry with { Ip = ip });
        }

        // Rewrite only after the entire file has passed validation.
        if (exemptCount > 0)
        {
            MarkDirty();
            _logger.LogInformation("Removed {Count} persisted bans for exempt addresses", exemptCount);
        }

        _logger.LogInformation("Loaded {Count} active bans", _bans.Count);
    }

    /// <inheritdoc/>
    public bool IsExempt(string ip)
    {
        return _exemptions.Contains(ip);
    }

    /// <inheritdoc/>
    public bool IsBanned(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return false;
        }

        if (_bans.TryGetValue(ip, out var entry))
        {
            return entry.IsActive;
        }

        var key = IpAddressUtilities.Normalize(ip);
        return key is not null && key != ip && _bans.TryGetValue(key, out entry) && entry.IsActive;
    }

    /// <inheritdoc/>
    public Task BanAsync(string ip, string reason, int? durationSeconds = null)
    {
        var key = IpAddressUtilities.Normalize(ip) ?? throw new ArgumentException("Invalid IP address.", nameof(ip));
        ArgumentNullException.ThrowIfNull(reason);
        if (reason.Length > 1024)
        {
            throw new ArgumentException("Ban reason exceeds 1024 characters.", nameof(reason));
        }

        var duration = durationSeconds ?? _settings.DefaultBanDurationSeconds;
        ArgumentOutOfRangeException.ThrowIfNegative(duration);
        var now = DateTimeOffset.UtcNow;
        var entry = new BanEntry(key, reason, now, duration == 0 ? null : now.AddSeconds(duration));
        Task persistence;
        lock (_lifecycle)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            if (IsExempt(key))
            {
                _logger.LogDebug("Ignored ban request for exempt address {Ip}", key);
                return Task.CompletedTask;
            }

            if (_bans.TryGetValue(key, out var previous))
            {
                // A ban request may extend protection, but must never shorten or undo it.
                // Retain the original reason and timestamp when its ban is stronger.
                if (previous.ExpiresAt is null ||
                    entry.ExpiresAt is { } requestedExpiry && previous.ExpiresAt >= requestedExpiry)
                {
                    return WaitForPersistence();
                }
            }
            else if (_bans.Count >= _settings.MaxBanEntries)
            {
                throw new InvalidOperationException("Maximum ban capacity reached.");
            }

            _bans[key] = entry;
            MarkDirty();
            persistence = WaitForPersistence();
        }

        _logger.LogWarning("Banned {Ip}: {Reason}, expires {Expires}", key, reason, entry.ExpiresAt);
        return persistence;
    }

    /// <inheritdoc/>
    public Task UnbanAsync(string ip)
    {
        var key = IpAddressUtilities.Normalize(ip) ?? throw new ArgumentException("Invalid IP address.", nameof(ip));
        lock (_lifecycle)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            if (_bans.TryRemove(key, out _))
            {
                MarkDirty();
            }

            return WaitForPersistence();
        }
    }

    /// <inheritdoc/>
    public IReadOnlyList<BanEntry> GetActiveBans()
    {
        return _bans.Values.Where(entry => entry.IsActive).ToArray();
    }

    // Called under _lifecycle so a request joins the batch containing its mutation.
    // Duplicate requests must also wait for an unfinished write, or retry a failed one.
    private Task WaitForPersistence()
    {
        if (Volatile.Read(ref _isDirty) == 0)
        {
            return _activePersistence is null ? Task.CompletedTask : EnsurePersistedAsync(_activePersistence.Task);
        }

        _pendingPersistence ??= new TaskCompletionSource<Exception?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _changes.Writer.TryWrite(0);
        return EnsurePersistedAsync(_pendingPersistence.Task);
    }

    private static async Task EnsurePersistedAsync(Task<Exception?> persistence)
    {
        var failure = await persistence.ConfigureAwait(false);
        if (failure is not null)
        {
            throw new IOException("Unable to persist ban changes; changes remain pending for retry.", failure);
        }
    }

    private void MarkDirty()
    {
        Interlocked.Exchange(ref _isDirty, 1);
        _changes.Writer.TryWrite(0);
    }

    private void CleanupExpiredBans(object? state)
    {
        lock (_lifecycle)
        {
            foreach (var pair in _bans)
            {
                // Compare both key and value so an expiry sweep cannot delete a refreshed ban.
                if (!pair.Value.IsActive && ((ICollection<KeyValuePair<string, BanEntry>>)_bans).Remove(pair))
                {
                    MarkDirty();
                }
            }
        }
    }

    private async Task PersistLoopAsync()
    {
        while (await _changes.Reader.WaitToReadAsync().ConfigureAwait(false))
        {
            // Merge bursts of changes instead of scheduling a disk writer per ban.
            await Task.Delay(100).ConfigureAwait(false);
            while (_changes.Reader.TryRead(out _))
            {
            }

            await PersistAsync().ConfigureAwait(false);
        }
    }

    private async Task PersistAsync()
    {
        TaskCompletionSource<Exception?> completion;
        IReadOnlyList<BanEntry> snapshot;
        lock (_lifecycle)
        {
            // Capture the snapshot and its waiters together. Later changes belong to the next batch.
            if (Interlocked.Exchange(ref _isDirty, 0) == 0)
            {
                return;
            }

            snapshot = GetActiveBans();
            completion = _pendingPersistence ?? new TaskCompletionSource<Exception?>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pendingPersistence = null;
            _activePersistence = completion;
        }

        var path = _settings.BanFilePath;
        string? temporaryPath = null;
        Exception? failure = null;
        try
        {
            path = Path.GetFullPath(path);
            temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write,
                             FileShare.None, 16384, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, snapshot, ServerJsonContext.Default.BanEntryArray).ConfigureAwait(false);
                await stream.FlushAsync().ConfigureAwait(false);
            }

            File.Move(temporaryPath, path, overwrite: true);
        }
        catch (Exception ex)
        {
            failure = ex;
            _logger.LogError(ex, "Failed to persist bans to {Path}; changes remain pending", path);
        }
        finally
        {
            try
            {
                if (temporaryPath is not null)
                {
                    File.Delete(temporaryPath);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }

            lock (_lifecycle)
            {
                if (failure is not null)
                {
                    Interlocked.Exchange(ref _isDirty, 1);
                }

                _activePersistence = null;
                // Background cleanup/retry batches may have no callers to observe a faulted task.
                completion.SetResult(failure);
            }
        }
    }

    /// <summary>Drains pending writes; repeated disposal is safe.</summary>
    public ValueTask DisposeAsync()
    {
        lock (_lifecycle)
        {
            return new ValueTask(_disposeTask ??= DisposeCoreAsync());
        }
    }

    private async Task DisposeCoreAsync()
    {
        await _cleanupTimer.DisposeAsync().ConfigureAwait(false);
        await _retryTimer.DisposeAsync().ConfigureAwait(false);
        _changes.Writer.TryComplete();
        await _persistenceTask.ConfigureAwait(false);
        await PersistAsync().ConfigureAwait(false);
        if (Volatile.Read(ref _isDirty) != 0)
        {
            throw new IOException("Unable to flush pending bans during shutdown.");
        }
    }

    /// <summary>Synchronous disposal adapter for callers without an asynchronous lifetime.</summary>
    public void Dispose()
    {
        DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}