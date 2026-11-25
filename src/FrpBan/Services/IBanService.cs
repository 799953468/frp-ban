using FrpBan.Models;
using FrpBan.Protocol;

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
    /// This is the single place ban requests are validated; callers map the returned status.
    /// Success statuses complete only after persistence succeeds.
    /// </summary>
    /// <param name="ip">The IP address to ban; IPv4-mapped IPv6 is stored as IPv4.</param>
    /// <param name="reason">Human-readable reason, 1–1024 characters after trimming whitespace.</param>
    /// <param name="durationSeconds">Duration in seconds; 0 is permanent, null uses the configured default.</param>
    /// <returns>
    /// <see cref="BanStatus.Applied"/>, <see cref="BanStatus.AlreadyBanned"/>, <see cref="BanStatus.Exempt"/>,
    /// <see cref="BanStatus.Invalid"/>, or <see cref="BanStatus.CapacityReached"/>.
    /// </returns>
    /// <exception cref="IOException">Storage failed; the change stays in memory and pending for retry.</exception>
    /// <exception cref="ObjectDisposedException">The service is shutting down.</exception>
    Task<BanStatus> BanAsync(string ip, string reason, int? durationSeconds = null);

    /// <summary>
    /// Removes the ban for the given IP and waits for persistence. No-op if not banned and no writes are pending.
    /// Storage failures leave changes pending and throw IOException.
    /// </summary>
    Task UnbanAsync(string ip);

    /// <summary>Returns a snapshot of all currently active bans.</summary>
    IReadOnlyList<BanEntry> GetActiveBans();
}