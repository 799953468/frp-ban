using FrpBan.Models;

namespace FrpBan.Services;

/// <summary>
/// Thread-safe service for managing the IP ban list.
/// </summary>
public interface IBanService
{
    /// <summary>Returns true if the IP is currently banned (active, not expired).</summary>
    bool IsBanned(string ip);

    /// <summary>
    /// Adds or refreshes a ban for the given IP.
    /// </summary>
    /// <param name="ip">The IP address to ban.</param>
    /// <param name="reason">Human-readable reason for the ban.</param>
    /// <param name="durationSeconds">Duration in seconds; 0 or null means permanent.</param>
    Task BanAsync(string ip, string reason, int? durationSeconds = null);

    /// <summary>Removes the ban for the given IP. No-op if not banned.</summary>
    Task UnbanAsync(string ip);

    /// <summary>Returns a snapshot of all currently active bans.</summary>
    IReadOnlyList<BanEntry> GetActiveBans();
}
