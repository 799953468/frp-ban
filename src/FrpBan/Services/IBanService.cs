using FrpBan.Models;

namespace FrpBan.Services;

/// <summary>
/// Thread-safe service for managing the IP ban list.
/// </summary>
public interface IBanService
{
    /// <summary>Returns whether a valid IP is exempt from bans under the startup configuration.</summary>
    /// <param name="ip">The IP literal to check, without a port.</param>
    /// <returns>True for an exempt IP; false for other or invalid addresses.</returns>
    bool IsExempt(string ip);

    /// <summary>Returns true if the IP is currently banned (active, not expired).</summary>
    bool IsBanned(string ip);

    /// <summary>
    /// Adds or extends a ban for the given IP, preserving any existing later expiry or permanent ban.
    /// Valid requests for exempt addresses are ignored.
    /// </summary>
    /// <param name="ip">The IP address to ban.</param>
    /// <param name="reason">Human-readable reason for the ban.</param>
    /// <param name="durationSeconds">Duration in seconds; 0 is permanent, null uses the configured default.</param>
    Task BanAsync(string ip, string reason, int? durationSeconds = null);

    /// <summary>Removes the ban for the given IP. No-op if not banned.</summary>
    Task UnbanAsync(string ip);

    /// <summary>Returns a snapshot of all currently active bans.</summary>
    IReadOnlyList<BanEntry> GetActiveBans();
}