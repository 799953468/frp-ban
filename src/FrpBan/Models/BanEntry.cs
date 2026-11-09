namespace FrpBan.Models;

/// <summary>
/// Represents a single banned IP address with optional expiry.
/// </summary>
public sealed record BanEntry(
    string Ip,
    string Reason,
    DateTimeOffset BannedAt,
    DateTimeOffset? ExpiresAt
)
{
    /// <summary>
    /// Returns true if this entry has not yet expired.
    /// Permanent bans (ExpiresAt is null) never expire.
    /// </summary>
    public bool IsActive => ExpiresAt is null || ExpiresAt > DateTimeOffset.UtcNow;
}
