namespace FrpBan.Client.Configuration;

/// <summary>
/// Configuration for a ban rule (fail2ban-like).
/// </summary>
public sealed class BanRule
{
    /// <summary>
    /// Rule name.
    /// </summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>
    /// Is this rule enabled.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Log source configuration.
    /// </summary>
    public LogSource LogSource { get; init; } = new();

    /// <summary>
    /// Matching expressions (regex or JSON field matching).
    /// </summary>
    public List<MatchExpression> Matching { get; init; } = new();

    /// <summary>
    /// Ban action configuration.
    /// </summary>
    public BanAction Action { get; init; } = new();
}

/// <summary>
/// Log source to monitor.
/// </summary>
public sealed class LogSource
{
    /// <summary>
    /// Source type: "file" or "journal".
    /// </summary>
    public string Type { get; init; } = "file";

    /// <summary>
    /// File path (for type="file").
    /// </summary>
    public string? Path { get; init; }

    /// <summary>
    /// Journal service name (for type="journal").
    /// </summary>
    public string? Service { get; init; }
}

/// <summary>
/// Match expression for log lines.
/// </summary>
public sealed class MatchExpression
{
    /// <summary>
    /// Expression type: "regex" or "json".
    /// </summary>
    public string Type { get; init; } = "regex";

    /// <summary>
    /// Regex pattern with named groups like (?P&lt;ip&gt;...).
    /// </summary>
    public string? Pattern { get; init; }

    /// <summary>
    /// JSON field path (e.g., "event.client_ip") for type="json".
    /// </summary>
    public string? JsonPath { get; init; }

    /// <summary>
    /// Expected value for JSON field (optional, null means any value matches).
    /// </summary>
    public string? JsonValue { get; init; }
}

/// <summary>
/// Ban action when rule triggers.
/// </summary>
public sealed class BanAction
{
    /// <summary>
    /// Action type: "immediate" or "threshold".
    /// </summary>
    public string Type { get; init; } = "threshold";

    /// <summary>
    /// Time window in seconds (for type="threshold").
    /// </summary>
    public int WindowSeconds { get; init; } = 60;

    /// <summary>
    /// Number of matches required to trigger ban (for type="threshold").
    /// </summary>
    public int MaxMatches { get; init; } = 5;

    /// <summary>
    /// Ban duration in seconds.
    /// </summary>
    public int BanDurationSeconds { get; init; } = 3600;

    /// <summary>
    /// Reason for ban (will be sent to server).
    /// </summary>
    public string Reason { get; init; } = "Rule triggered";
}

/// <summary>
/// Rules configuration container.
/// </summary>
public sealed class RulesConfiguration
{
    /// <summary>
    /// List of ban rules.
    /// </summary>
    public List<BanRule> Rules { get; init; } = new();
}
