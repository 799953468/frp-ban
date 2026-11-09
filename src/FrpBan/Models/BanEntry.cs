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

/// <summary>
/// Request body for the POST /api/bans endpoint.
/// </summary>
public sealed record BanRequest(
    string Ip,
    string? Reason,
    /// <summary>Duration in seconds. 0 or null means permanent. Must be non-negative.</summary>
    int? DurationSeconds
)
{
    /// <summary>
    /// Validates the request parameters.
    /// </summary>
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Ip))
            return "IP address is required.";

        if (!System.Net.IPAddress.TryParse(Ip, out _))
            return "Invalid IP address format.";

        if (DurationSeconds is < 0)
            return "Duration must be non-negative.";

        return null;
    }
};
