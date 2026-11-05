using System.Text.Json;
using FrpBan.Configuration;
using FrpBan.Models;
using Microsoft.Extensions.Options;

namespace FrpBan.Services;

/// <summary>
/// Thread-safe, file-persisted implementation of <see cref="IBanService"/>.
/// Bans are kept in memory for fast lookup and flushed to disk on every change.
/// </summary>
public sealed class BanService(
    IOptions<PluginSettings> settings,
    ILogger<BanService> logger) : IBanService
{
    private readonly PluginSettings _settings = settings.Value;
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly Dictionary<string, BanEntry> _bans = [];

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
    };

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

            logger.LogInformation("Loaded {Count} active bans from {Path}", _bans.Count, path);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to load ban file from {Path}", path);
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
    public async Task BanAsync(string ip, string reason, int? durationSeconds = null)
    {
        var duration = durationSeconds ?? _settings.DefaultBanDurationSeconds;
        var expiresAt = duration > 0
            ? DateTimeOffset.UtcNow.AddSeconds(duration)
            : (DateTimeOffset?)null;

        var entry = new BanEntry(ip, reason, DateTimeOffset.UtcNow, expiresAt);

        _lock.EnterWriteLock();
        try { _bans[ip] = entry; }
        finally { _lock.ExitWriteLock(); }

        logger.LogWarning("Banned {Ip} — reason: {Reason}, expires: {Expires}",
            ip, reason, expiresAt?.ToString("o") ?? "never");

        await PersistAsync();
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
            logger.LogInformation("Unbanned {Ip}", ip);
            await PersistAsync();
        }
    }

    /// <inheritdoc/>
    public IReadOnlyList<BanEntry> GetActiveBans()
    {
        _lock.EnterReadLock();
        try
        {
            return _bans.Values.Where(e => e.IsActive).ToList();
        }
        finally { _lock.ExitReadLock(); }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

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
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to persist ban list to {Path}", path);
        }
    }
}
