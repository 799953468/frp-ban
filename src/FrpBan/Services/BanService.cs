using System.Text.Json;
using FrpBan.Configuration;
using FrpBan.Models;
using Microsoft.Extensions.Options;

namespace FrpBan.Services;

/// <summary>
/// Thread-safe, file-persisted implementation of <see cref="IBanService"/>.
/// Bans are kept in memory for fast lookup and flushed to disk periodically.
/// Expired bans are cleaned up automatically.
/// </summary>
public sealed class BanService : IBanService, IDisposable
{
    private readonly PluginSettings _settings;
    private readonly ILogger<BanService> _logger;
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly Dictionary<string, BanEntry> _bans = [];
    private readonly Timer _cleanupTimer;
    private readonly Timer _persistTimer;
    private volatile bool _isDirty;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
    };

    public BanService(IOptions<PluginSettings> settings, ILogger<BanService> logger)
    {
        _settings = settings.Value;
        _logger = logger;

        // Clean up expired bans every 5 minutes
        _cleanupTimer = new Timer(CleanupExpiredBans, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));

        // Persist dirty state every 30 seconds (batch writes)
        _persistTimer = new Timer(PersistIfDirty, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    // Called once during startup via IHostedService or explicit init.
    public void Load()
    {
        var path = _settings.BanFilePath;
        if (!File.Exists(path))
            return;

        try
        {
            var json = File.ReadAllText(path);
            var entries = JsonSerializer.Deserialize<List<BanEntry>>(json, JsonOptions);
            if (entries is null) return;

            _lock.EnterWriteLock();
            try
            {
                foreach (var entry in entries.Where(e => e.IsActive))
                    _bans[entry.Ip] = entry;
            }
            finally { _lock.ExitWriteLock(); }

            _logger.LogInformation("Loaded {Count} active bans from {Path}", _bans.Count, path);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load ban file from {Path}", path);
        }
    }

    /// <inheritdoc/>
    public bool IsBanned(string ip)
    {
        _lock.EnterReadLock();
        try
        {
            return _bans.TryGetValue(ip, out var entry) && entry.IsActive;
        }
        finally { _lock.ExitReadLock(); }
    }

    /// <inheritdoc/>
    public async Task BanAsync(string ip, string reason, int? durationSeconds = null, CancellationToken cancellationToken = default)
    {
        var duration = durationSeconds ?? _settings.DefaultBanDurationSeconds;
        var expiresAt = duration > 0
            ? DateTimeOffset.UtcNow.AddSeconds(duration)
            : (DateTimeOffset?)null;

        var entry = new BanEntry(ip, reason, DateTimeOffset.UtcNow, expiresAt);

        _lock.EnterWriteLock();
        try { _bans[ip] = entry; }
        finally { _lock.ExitWriteLock(); }

        _logger.LogWarning("Banned {Ip} — reason: {Reason}, expires: {Expires}",
            ip, reason, expiresAt?.ToString("o") ?? "never");

        _isDirty = true;

        // Force immediate persist for critical operations, but don't block
        _ = Task.Run(PersistAsync);
    }

    /// <inheritdoc/>
    public async Task UnbanAsync(string ip)
    {
        bool removed;
        _lock.EnterWriteLock();
        try { removed = _bans.Remove(ip); }
        finally { _lock.ExitWriteLock(); }

        if (removed)
        {
            _logger.LogInformation("Unbanned {Ip}", ip);
            _isDirty = true;
            _ = Task.Run(PersistAsync);
        }
    }

    /// <inheritdoc/>
    public IReadOnlyList<BanEntry> GetActiveBans()
    {
        _lock.EnterReadLock();
        try
        {
            var result = new List<BanEntry>(_bans.Count);
            foreach (var entry in _bans.Values)
            {
                if (entry.IsActive)
                    result.Add(entry);
            }
            return result;
        }
        finally { _lock.ExitReadLock(); }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Removes expired bans from memory. Called periodically by timer.
    /// </summary>
    private void CleanupExpiredBans(object? state)
    {
        var now = DateTimeOffset.UtcNow;
        var toRemove = new List<string>();

        _lock.EnterReadLock();
        try
        {
            foreach (var (ip, entry) in _bans)
            {
                if (!entry.IsActive)
                    toRemove.Add(ip);
            }
        }
        finally { _lock.ExitReadLock(); }

        if (toRemove.Count == 0)
            return;

        _lock.EnterWriteLock();
        try
        {
            foreach (var ip in toRemove)
                _bans.Remove(ip);
        }
        finally { _lock.ExitWriteLock(); }

        _logger.LogInformation("Cleaned up {Count} expired bans", toRemove.Count);
        _isDirty = true;
    }

    /// <summary>
    /// Persists to disk only if there are pending changes. Called periodically by timer.
    /// </summary>
    private void PersistIfDirty(object? state)
    {
        if (_isDirty)
        {
            _ = Task.Run(PersistAsync);
        }
    }

    private async Task PersistAsync()
    {
        var path = _settings.BanFilePath;
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            List<BanEntry> snapshot;
            _lock.EnterReadLock();
            try { snapshot = [.. _bans.Values]; }
            finally { _lock.ExitReadLock(); }

            var json = JsonSerializer.Serialize(snapshot, JsonOptions);
            await File.WriteAllTextAsync(path, json);

            _isDirty = false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist ban list to {Path}", path);
        }
    }

    public void Dispose()
    {
        _cleanupTimer?.Dispose();
        _persistTimer?.Dispose();
        _lock?.Dispose();

        // Final persist on shutdown
        if (_isDirty)
        {
            PersistAsync().GetAwaiter().GetResult();
        }
    }
}

