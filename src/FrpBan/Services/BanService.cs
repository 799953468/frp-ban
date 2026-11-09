using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;
using FrpBan.Configuration;
using FrpBan.Models;
using FrpBan.Protocol;
using Microsoft.Extensions.Options;

namespace FrpBan.Services;

/// <summary>Canonical IP bans with a bounded, coalescing, single-writer persistence queue.</summary>
public sealed class BanService : IBanService, IDisposable, IAsyncDisposable
{
    private readonly PluginSettings _settings;
    private readonly ILogger<BanService> _logger;
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
    private Task? _disposeTask;
    private int _isDirty;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    /// <summary>Creates the ban store and starts its single persistence worker.</summary>
    public BanService(IOptions<PluginSettings> settings, ILogger<BanService> logger)
    {
        _settings = settings.Value;
        _logger = logger;
        _persistenceTask = PersistLoopAsync();
        _cleanupTimer = new Timer(CleanupExpiredBans, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
        _retryTimer = new Timer(_ =>
        {
            if (Volatile.Read(ref _isDirty) != 0)
                _changes.Writer.TryWrite(0);
        }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    /// <summary>Loads active bans before traffic is accepted; corrupted storage fails startup.</summary>
    public void Load()
    {
        if (!File.Exists(_settings.BanFilePath))
            return;
        using var stream = File.OpenRead(_settings.BanFilePath);
        var entries = JsonSerializer.Deserialize<List<BanEntry?>>(stream, JsonOptions)
                      ?? throw new InvalidDataException("Ban file must contain a JSON array.");
        foreach (var entry in entries)
        {
            if (entry is null || !entry.IsActive)
                continue;
            var ip = IpAddressUtilities.Normalize(entry.Ip);
            if (ip is null)
                throw new InvalidDataException("Ban file contains an invalid IP address.");
            if (!_bans.ContainsKey(ip) && _bans.Count >= _settings.MaxBanEntries)
                throw new InvalidDataException("Ban file exceeds MaxBanEntries.");
            _bans.AddOrUpdate(ip, entry with { Ip = ip }, (_, previous) =>
                previous.BannedAt > entry.BannedAt ? previous : entry with { Ip = ip });
        }
        _logger.LogInformation("Loaded {Count} active bans", _bans.Count);
    }

    /// <inheritdoc/>
    public bool IsBanned(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return false;
        if (_bans.TryGetValue(ip, out var entry)) return entry.IsActive;
        var key = IpAddressUtilities.Normalize(ip);
        return key is not null && key != ip && _bans.TryGetValue(key, out entry) && entry.IsActive;
    }

    /// <inheritdoc/>
    public Task BanAsync(string ip, string reason, int? durationSeconds = null)
    {
        var key = IpAddressUtilities.Normalize(ip) ?? throw new ArgumentException("Invalid IP address.", nameof(ip));
        ArgumentNullException.ThrowIfNull(reason);
        if (reason.Length > 1024)
            throw new ArgumentException("Ban reason exceeds 1024 characters.", nameof(reason));
        var duration = durationSeconds ?? _settings.DefaultBanDurationSeconds;
        ArgumentOutOfRangeException.ThrowIfNegative(duration);
        var now = DateTimeOffset.UtcNow;
        var entry = new BanEntry(key, reason, now, duration == 0 ? null : now.AddSeconds(duration));
        lock (_lifecycle)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            if (!_bans.ContainsKey(key) && _bans.Count >= _settings.MaxBanEntries)
                throw new InvalidOperationException("Maximum ban capacity reached.");
            _bans[key] = entry;
            MarkDirty();
        }
        _logger.LogWarning("Banned {Ip}: {Reason}, expires {Expires}", key, reason, entry.ExpiresAt);
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task UnbanAsync(string ip)
    {
        var key = IpAddressUtilities.Normalize(ip) ?? throw new ArgumentException("Invalid IP address.", nameof(ip));
        lock (_lifecycle)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            if (_bans.TryRemove(key, out _))
                MarkDirty();
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public IReadOnlyList<BanEntry> GetActiveBans() => _bans.Values.Where(entry => entry.IsActive).ToArray();

    private void MarkDirty()
    {
        Interlocked.Exchange(ref _isDirty, 1);
        _changes.Writer.TryWrite(0);
    }

    private void CleanupExpiredBans(object? state)
    {
        foreach (var pair in _bans)
            // Compare both key and value so an expiry sweep cannot delete a refreshed ban.
            if (!pair.Value.IsActive && ((ICollection<KeyValuePair<string, BanEntry>>)_bans).Remove(pair))
                MarkDirty();
    }

    private async Task PersistLoopAsync()
    {
        while (await _changes.Reader.WaitToReadAsync().ConfigureAwait(false))
        {
            // Merge bursts of changes instead of scheduling a disk writer per ban.
            await Task.Delay(100).ConfigureAwait(false);
            while (_changes.Reader.TryRead(out _)) { }
            await PersistAsync().ConfigureAwait(false);
        }
    }

    private async Task PersistAsync()
    {
        // Clear before taking the snapshot. Changes during a write stay dirty and queued.
        if (Interlocked.Exchange(ref _isDirty, 0) == 0)
            return;
        var path = _settings.BanFilePath;
        string? temporaryPath = null;
        try
        {
            path = Path.GetFullPath(path);
            temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var snapshot = GetActiveBans();
            await using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write,
                             FileShare.None, 16384, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, snapshot, JsonOptions).ConfigureAwait(false);
                await stream.FlushAsync().ConfigureAwait(false);
            }
            File.Move(temporaryPath, path, overwrite: true);
        }
        catch (Exception ex)
        {
            Interlocked.Exchange(ref _isDirty, 1);
            _logger.LogError(ex, "Failed to persist bans to {Path}; changes remain pending", path);
        }
        finally
        {
            try { if (temporaryPath is not null) File.Delete(temporaryPath); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    /// <summary>Drains pending writes; repeated disposal is safe.</summary>
    public ValueTask DisposeAsync()
    {
        lock (_lifecycle)
            return new ValueTask(_disposeTask ??= DisposeCoreAsync());
    }

    private async Task DisposeCoreAsync()
    {
        await _cleanupTimer.DisposeAsync().ConfigureAwait(false);
        await _retryTimer.DisposeAsync().ConfigureAwait(false);
        _changes.Writer.TryComplete();
        await _persistenceTask.ConfigureAwait(false);
        await PersistAsync().ConfigureAwait(false);
        if (Volatile.Read(ref _isDirty) != 0)
            throw new IOException("Unable to flush pending bans during shutdown.");
    }

    /// <summary>Synchronous disposal adapter for callers without an asynchronous lifetime.</summary>
    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
}
