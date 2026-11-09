namespace FrpBan.Client.Configuration;

/// <summary>
/// Configuration settings for the frp-ban client.
/// Bind via appsettings.json section "ClientSettings".
/// </summary>
public sealed class ClientSettings
{
    /// <summary>
    /// Server address (hostname or IP) for client connection.
    /// </summary>
    public string ServerAddress { get; init; } = "localhost";

    /// <summary>
    /// Server port for TCP listener.
    /// </summary>
    public int ServerPort { get; init; } = 9443;

    /// <summary>
    /// Bearer token for API authentication (same as server token).
    /// </summary>
    public string Token { get; init; } = string.Empty;

    /// <summary>
    /// TLS/HTTPS configuration for client-side certificate validation and authentication.
    /// </summary>
    public ClientTlsSettings Tls { get; init; } = new();

    /// <summary>
    /// Reconnection policy settings.
    /// </summary>
    public ReconnectionSettings Reconnection { get; init; } = new();

    /// <summary>
    /// Input method: "stdin" (read from standard input).
    /// </summary>
    public string InputMethod { get; init; } = "stdin";

    /// <summary>
    /// Application log path (for file logging).
    /// </summary>
    public string? AppLogPath { get; init; }
}

/// <summary>
/// TLS/HTTPS configuration for the client.
/// </summary>
public sealed class ClientTlsSettings
{
    /// <summary>
    /// Enable TLS for client-server communication.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Path to the client certificate file (.pfx).
    /// </summary>
    public string? ClientCertificatePath { get; init; }

    /// <summary>
    /// Password for the client certificate file (.pfx).
    /// </summary>
    public string? ClientCertificatePassword { get; init; }

    /// <summary>
    /// Path to CA certificate for server validation.
    /// </summary>
    public string? CaCertificatePath { get; init; }

    /// <summary>
    /// Allow self-signed certificates (development only).
    /// </summary>
    public bool AllowSelfSignedCertificates { get; init; }

    /// <summary>
    /// Validate server certificate (should be true for production).
    /// </summary>
    public bool ValidateServerCertificate { get; init; } = true;
}

/// <summary>
/// Reconnection policy configuration.
/// </summary>
public sealed class ReconnectionSettings
{
    /// <summary>
    /// Maximum number of retries (-1 = infinite).
    /// </summary>
    public int MaxRetries { get; init; } = -1;

    /// <summary>
    /// Initial delay in milliseconds before first retry.
    /// </summary>
    public int InitialDelayMs { get; init; } = 1000;

    /// <summary>
    /// Maximum delay in milliseconds between retries.
    /// </summary>
    public int MaxDelayMs { get; init; } = 30000;

    /// <summary>
    /// Backoff multiplier (e.g., 2.0 = exponential backoff).
    /// </summary>
    public double BackoffMultiplier { get; init; } = 2.0;

    /// <summary>
    /// Health check interval in milliseconds (PING).
    /// </summary>
    public int HealthCheckIntervalMs { get; init; } = 30000;
}
