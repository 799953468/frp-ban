using System.ComponentModel.DataAnnotations;

namespace FrpBan.Client.Configuration;

/// <summary>
/// Configuration settings for the frp-ban client.
/// Bind via appsettings.json section "ClientSettings".
/// </summary>
public sealed class ClientSettings : IValidatableObject
{
    /// <summary>
    /// Server address (hostname or IP) for client connection.
    /// </summary>
    public string ServerAddress { get; set; } = "localhost";

    /// <summary>
    /// Server port for TCP listener.
    /// </summary>
    public int ServerPort { get; set; } = 9443;

    /// <summary>
    /// Bearer token for API authentication (same as server token).
    /// </summary>
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// TLS/HTTPS configuration for client-side certificate validation and authentication.
    /// </summary>
    public ClientTlsSettings Tls { get; set; } = new();

    /// <summary>
    /// Reconnection policy settings.
    /// </summary>
    public ReconnectionSettings Reconnection { get; set; } = new();

    /// <summary>
    /// Path to rules configuration file (YAML).
    /// </summary>
    public string? RulesPath { get; set; }

    /// <summary>
    /// Application log path (for file logging).
    /// </summary>
    public string? AppLogPath { get; set; }

    /// <summary>Deadline for TCP, TLS and HELLO together.</summary>
    public int ConnectionTimeoutSeconds { get; set; } = 15;

    /// <summary>Deadline for a queued protocol request and its response.</summary>
    public int RequestTimeoutSeconds { get; set; } = 10;

    /// <summary>Maximum queued bans retained in memory during a connection outage.</summary>
    public int MaxPendingBans { get; set; } = 1024;

    /// <inheritdoc/>
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        return Validate();
    }

    /// <summary>Validates settings without reflection so checks also run in Native AOT builds.</summary>
    public IEnumerable<ValidationResult> Validate()
    {
        if (string.IsNullOrWhiteSpace(ServerAddress) || ServerPort is < 1 or > 65535)
        {
            yield return new ValidationResult("A valid server address and port are required.");
        }

        if (string.IsNullOrWhiteSpace(Token) || Token.Length < 32 || Token.StartsWith("CHANGE_ME", StringComparison.OrdinalIgnoreCase))
        {
            yield return new ValidationResult("Token must be a non-placeholder secret of at least 32 characters.");
        }

        if (Tls is null || !Tls.Enabled)
        {
            yield return new ValidationResult("TLS must be enabled.");
        }

        if (ConnectionTimeoutSeconds is < 1 or > 300 || RequestTimeoutSeconds is < 1 or > 300)
        {
            yield return new ValidationResult("Connection and request timeouts must be between 1 and 300 seconds.");
        }

        if (MaxPendingBans is < 1 or > 100000)
        {
            yield return new ValidationResult("MaxPendingBans must be between 1 and 100000.");
        }

        if (Reconnection is null || Reconnection.InitialDelayMs < 1 ||
            Reconnection.MaxDelayMs < Reconnection.InitialDelayMs || Reconnection.MaxRetries < -1 ||
            !double.IsFinite(Reconnection.BackoffMultiplier) || Reconnection.BackoffMultiplier is < 1 or > 100 ||
            Reconnection.HealthCheckIntervalMs < 1)
        {
            yield return new ValidationResult("Invalid reconnection policy.");
        }
    }
}

/// <summary>
/// TLS/HTTPS configuration for the client.
/// </summary>
public sealed class ClientTlsSettings
{
    /// <summary>
    /// Enable TLS for client-server communication.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Path to the client certificate file (.pfx).
    /// </summary>
    public string? ClientCertificatePath { get; set; }

    /// <summary>
    /// Password for the client certificate file (.pfx).
    /// </summary>
    public string? ClientCertificatePassword { get; set; }

    /// <summary>
    /// Path to CA certificate for server validation.
    /// </summary>
    public string? CaCertificatePath { get; set; }

    /// <summary>
    /// Allow self-signed certificates (development only).
    /// </summary>
    public bool AllowSelfSignedCertificates { get; set; }

    /// <summary>
    /// Validate server certificate (should be true for production).
    /// </summary>
    public bool ValidateServerCertificate { get; set; } = true;
}

/// <summary>
/// Reconnection policy configuration.
/// </summary>
public sealed class ReconnectionSettings
{
    /// <summary>
    /// Maximum number of retries (-1 = infinite).
    /// </summary>
    public int MaxRetries { get; set; } = -1;

    /// <summary>
    /// Initial delay in milliseconds before first retry.
    /// </summary>
    public int InitialDelayMs { get; set; } = 1000;

    /// <summary>
    /// Maximum delay in milliseconds between retries.
    /// </summary>
    public int MaxDelayMs { get; set; } = 30000;

    /// <summary>
    /// Backoff multiplier (e.g., 2.0 = exponential backoff).
    /// </summary>
    public double BackoffMultiplier { get; set; } = 2.0;

    /// <summary>
    /// Health check interval in milliseconds (PING).
    /// </summary>
    public int HealthCheckIntervalMs { get; set; } = 30000;
}