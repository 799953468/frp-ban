using System.Collections.Concurrent;
using System.Text.Json;
using FrpBan.Configuration;
using FrpBan.Models;
using Microsoft.Extensions.Options;

namespace FrpBan.Services;

/// <summary>
/// Thread-safe, file-persisted implementation of <see cref="IBanService"/>.
/// Bans are kept in memory for fast lookup and flushed to disk periodically.
/// Expired bans are cleaned up automatically.
/// PERFORMANCE: Uses ConcurrentDictionary for lock-free reads.
/// </summary>
public sealed class BanService : IBanService, IDisposable
{
    private readonly PluginSettings _settings;
    private readonly ILogger<BanService> _logger;
    private readonly ConcurrentDictionary<string, BanEntry> _bans = new();
    private readonly Timer _cleanupTimer;
    private readonly Timer _persistTimer;
    private int _isDirty; // 0 = clean, 1 = dirty (atomic operations)

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

            foreach (var entry in entries.Where(e => e.IsActive))
            {
                _bans.TryAdd(entry.Ip, entry);
            }

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
        // Lock-free read with ConcurrentDictionary
        return _bans.TryGetValue(ip, out var entry) && entry.IsActive;
    }

    /// <inheritdoc/>
    public async Task BanAsync(string ip, string reason, int? durationSeconds = null)
    {
        var duration = durationSeconds ?? _settings.DefaultBanDurationSeconds;
        var expiresAt = duration > 0
            ? DateTimeOffset.UtcNow.AddSeconds(duration)
            : (DateTimeOffset?)null;

        var entry = new BanEntry(ip, reason, DateTimeOffset.UtcNow, expiresAt);
        _bans[ip] = entry; // ConcurrentDictionary handles thread safety

        _logger.LogWarning("Banned {Ip} — reason: {Reason}, expires: {Expires}",
            ip, reason, expiresAt?.ToString("o") ?? "never");

        MarkDirty();

        // Force immediate persist for critical operations, but don't block
        _ = Task.Run(PersistAsync);
    }

    /// <inheritdoc/>
    public async Task UnbanAsync(string ip)
    {
        bool removed = _bans.TryRemove(ip, out _);

        if (removed)
        {
            _logger.LogInformation("Unbanned {Ip}", ip);
            MarkDirty();
            _ = Task.Run(PersistAsync);
        }
    }

    /// <inheritdoc/>
    public IReadOnlyList<BanEntry> GetActiveBans()
    {
        var result = new List<BanEntry>(_bans.Count);
        foreach (var entry in _bans.Values)
        {
            if (entry.IsActive)
                result.Add(entry);
        }
        return result;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Atomically marks the service as dirty (needs persist).
    /// </summary>
    private void MarkDirty() => Interlocked.Exchange(ref _isDirty, 1);

    /// <summary>
    /// Atomically checks and clears the dirty flag.
    /// </summary>
    private bool CheckAndClearDirty() => Interlocked.Exchange(ref _isDirty, 0) == 1;

    /// <summary>
    /// Removes expired bans from memory. Called periodically by timer.
    /// </summary>
    private void CleanupExpiredBans(object? state)
    {
        var toRemove = new List<string>();

        foreach (var (ip, entry) in _bans)
        {
            if (!entry.IsActive)
                toRemove.Add(ip);
        }

        if (toRemove.Count == 0)
            return;

        foreach (var ip in toRemove)
        {
            _bans.TryRemove(ip, out _);
        }

        _logger.LogInformation("Cleaned up {Count} expired bans", toRemove.Count);
        MarkDirty();
    }

    /// <summary>
    /// Persists to disk only if there are pending changes. Called periodically by timer.
    /// </summary>
    private void PersistIfDirty(object? state)
    {
        if (_isDirty == 1)
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

            var snapshot = _bans.Values.ToList();
            var json = JsonSerializer.Serialize(snapshot, JsonOptions);
            await File.WriteAllTextAsync(path, json);

            CheckAndClearDirty(); // Atomic clear
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

        // Final persist on shutdown
        if (_isDirty == 1)
        {
            PersistAsync().GetAwaiter().GetResult();
        }
    }
}

