using System.ComponentModel.DataAnnotations;

namespace FrpBan.Configuration;

/// <summary>
/// Configuration settings for the frp-ban plugin server.
/// Bind via appsettings.json section "PluginSettings".
/// </summary>
public sealed class PluginSettings
{
    /// <summary>
    /// Bearer token required to call the /api/* management endpoints.
    /// </summary>
    [Required]
    public string Token { get; init; } = string.Empty;

    /// <summary>
    /// Path to the JSON file used to persist the ban list across restarts.
    /// </summary>
    public string BanFilePath { get; init; } = "/var/lib/frp-ban/bans.json";

    /// <summary>
    /// Path to the access log file monitored by fail2ban.
    /// Each unauthorised API access is appended here in a parseable format.
    /// </summary>
    public string AccessLogPath { get; init; } = "/var/log/frp-ban/access.log";

    /// <summary>
    /// IP addresses or CIDR prefixes allowed to call the frps plugin endpoint
    /// (POST /handler). Typically only localhost. Empty list = allow all.
    /// </summary>
    public List<string> AllowedPluginAddresses { get; init; } = ["127.0.0.1", "::1"];

    /// <summary>
    /// Default ban duration in seconds. 0 means permanent.
    /// </summary>
    public int DefaultBanDurationSeconds { get; init; } = 3600;
}
