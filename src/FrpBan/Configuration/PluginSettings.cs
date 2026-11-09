using System.ComponentModel.DataAnnotations;

namespace FrpBan.Configuration;

/// <summary>
/// Configuration settings for the frp-ban plugin server.
/// Bind via appsettings.json section "PluginSettings".
/// </summary>
public sealed class PluginSettings : IValidatableObject
{
    /// <summary>
    /// Bearer token required for TLS client authentication.
    /// </summary>
    [Required]
    public string Token { get; init; } = string.Empty;

    /// <summary>
    /// Path to the JSON file used to persist the ban list across restarts.
    /// </summary>
    public string BanFilePath { get; init; } = "/var/lib/frp-ban/bans.json";

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
    [Range(0, int.MaxValue)]
    public int DefaultBanDurationSeconds { get; init; } = 3600;

    /// <summary>Maximum distinct stored bans to bound memory and persistence size.</summary>
    [Range(1, 1000000)]
    public int MaxBanEntries { get; init; } = 100000;

    /// <summary>
    /// TLS/TCP configuration settings for client-server communication.
    /// </summary>
    public TlsSettings? Tls { get; init; }

    /// <inheritdoc/>
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (string.IsNullOrWhiteSpace(Token) || Token.StartsWith("CHANGE_ME", StringComparison.OrdinalIgnoreCase) || Token.Length < 32)
            yield return new ValidationResult("Token must be a non-placeholder secret of at least 32 characters.", [nameof(Token)]);
        if (string.IsNullOrWhiteSpace(BanFilePath))
            yield return new ValidationResult("BanFilePath is required.", [nameof(BanFilePath)]);
        if (Tls is not null)
            foreach (var result in Tls.Validate(new ValidationContext(Tls)))
                yield return result;
    }
}

/// <summary>
/// TLS/TCP configuration for secure client-server communication.
/// </summary>
public sealed class TlsSettings : IValidatableObject
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
    /// Require client certificates for mutual TLS (mTLS).
    /// </summary>
    public bool RequireClientCertificate { get; init; }

    /// <summary>
    /// Path to the CA certificate for validating client certificates (mTLS).
    /// </summary>
    public string? ClientCertificateAuthority { get; init; }

    /// <summary>Maximum number of simultaneous TLS sessions.</summary>
    public int MaxConcurrentConnections { get; init; } = 100;
    /// <summary>Maximum new connections per IP in a one-minute window.</summary>
    public int MaxConnectionsPerMinute { get; init; } = 10;
    /// <summary>Maximum protocol messages per IP in a one-minute window.</summary>
    public int MaxMessagesPerMinute { get; init; } = 120;
    /// <summary>Deadline covering both TLS and HELLO authentication.</summary>
    public int HandshakeTimeoutSeconds { get; init; } = 10;
    /// <summary>Deadline to receive each subsequent complete frame.</summary>
    public int IdleTimeoutSeconds { get; init; } = 90;
    /// <summary>Deadline to send a response.</summary>
    public int WriteTimeoutSeconds { get; init; } = 10;

    /// <inheritdoc/>
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (Port is < 1 or > 65535 || MaxConcurrentConnections is < 1 or > 10000 ||
            MaxConnectionsPerMinute < 1 || MaxMessagesPerMinute < 1 ||
            HandshakeTimeoutSeconds is < 1 or > 300 || IdleTimeoutSeconds is < 1 or > 86400 ||
            WriteTimeoutSeconds is < 1 or > 300)
            yield return new ValidationResult("Invalid TLS port, limits, or timeouts.");
        if (Enabled && TcpListenerEnabled && string.IsNullOrWhiteSpace(CertificatePath))
            yield return new ValidationResult("TLS requires a server CertificatePath.");
    }
}


