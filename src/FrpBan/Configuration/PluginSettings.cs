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
    /// Path to the main application log file (managed by Serilog).
    /// Used for general application logging with automatic rotation.
    /// </summary>
    public string AppLogPath { get; init; } = "/var/log/frp-ban/frp-ban-.log";

    /// <summary>
    /// IP addresses or CIDR prefixes allowed to call the frps plugin endpoint
    /// (POST /handler). Typically only localhost. Empty list = allow all.
    /// </summary>
    public List<string> AllowedPluginAddresses { get; init; } = ["127.0.0.1", "::1"];

    /// <summary>
    /// Default ban duration in seconds. 0 means permanent.
    /// </summary>
    public int DefaultBanDurationSeconds { get; init; } = 3600;

    /// <summary>
    /// TLS/HTTPS configuration settings for client-server communication.
    /// </summary>
    public TlsSettings? Tls { get; init; }
}

/// <summary>
/// TLS/HTTPS configuration for secure client-server communication.
/// </summary>
public sealed class TlsSettings
{
    /// <summary>
    /// Enable TLS for client-server communication.
    /// </summary>
    public bool Enabled { get; init; }

    /// <summary>
    /// Enable TCP listener for client connections (binary protocol).
    /// </summary>
    public bool TcpListenerEnabled { get; init; } = true;

    /// <summary>
    /// Port for TCP listener with TLS (e.g., 9443).
    /// </summary>
    public int Port { get; init; } = 9443;

    /// <summary>
    /// Path to the server TLS certificate file (.pfx or .pem).
    /// </summary>
    public string? CertificatePath { get; init; }

    /// <summary>
    /// Password for the certificate file (if using .pfx).
    /// </summary>
    public string? CertificatePassword { get; init; }

    /// <summary>
    /// Path to the private key file (if using .pem certificate).
    /// </summary>
    public string? KeyPath { get; init; }

    /// <summary>
    /// Allow self-signed certificates. Useful for development/testing.
    /// WARNING: Do not use in production with untrusted sources.
    /// </summary>
    public bool AllowSelfSignedCertificates { get; init; }

    /// <summary>
    /// Require client certificates for mutual TLS (mTLS).
    /// </summary>
    public bool RequireClientCertificate { get; init; }

    /// <summary>
    /// Path to the CA certificate for validating client certificates (mTLS).
    /// </summary>
    public string? ClientCertificateAuthority { get; init; }
}

