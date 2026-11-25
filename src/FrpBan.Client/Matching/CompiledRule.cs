using System.Text.RegularExpressions;
using FrpBan.Client.Configuration;
using FrpBan.Protocol;

namespace FrpBan.Client.Matching;

/// <summary>Where a rule reads log lines from.</summary>
public enum LogSourceKind
{
    /// <summary>Tail a log file.</summary>
    File,

    /// <summary>Follow a systemd unit's journal.</summary>
    Journal,
}

/// <summary>When a rule requests a ban.</summary>
public enum BanActionKind
{
    /// <summary>Ban on the first match.</summary>
    Immediate,

    /// <summary>Ban after MaxMatches matches from one IP within WindowSeconds.</summary>
    Threshold,
}

/// <summary>How a matching expression extracts IP addresses from a line.</summary>
public enum MatchKind
{
    /// <summary>Every match of a regex with a named group "ip".</summary>
    Regex,

    /// <summary>A field of a JSON log line, optionally conditioned on another field.</summary>
    Json,
}

/// <summary>A validated matching expression with its regex or JSON paths prepared.</summary>
/// <param name="Kind">Expression kind.</param>
/// <param name="Regex">Compiled regex for <see cref="MatchKind.Regex"/>.</param>
/// <param name="JsonPath">Field path for <see cref="MatchKind.Json"/>.</param>
/// <param name="JsonValue">When set, the field must equal this value and the IP is read from <paramref name="IpJsonPath"/>.</param>
/// <param name="IpJsonPath">IP field path used when <paramref name="JsonValue"/> is set.</param>
public sealed record CompiledExpression(
    MatchKind Kind,
    Regex? Regex,
    string[]? JsonPath,
    string? JsonValue,
    string[]? IpJsonPath);

/// <summary>
/// A validated, ready-to-run ban rule. Compiling once at load time replaces repeated string checks
/// on every log line, and the rule owns its threshold counters instead of keeping them in a side table.
/// </summary>
public sealed class CompiledRule
{
    /// <summary>Upper bound for each regex evaluation, protecting against catastrophic backtracking.</summary>
    public static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

    private CompiledRule(BanRule definition, LogSourceKind sourceKind, BanActionKind actionKind, IReadOnlyList<CompiledExpression> expressions)
    {
        Definition = definition;
        SourceKind = sourceKind;
        ActionKind = actionKind;
        Expressions = expressions;
        if (actionKind == BanActionKind.Threshold)
        {
            Threshold = new ThresholdState();
        }
    }

    /// <summary>The configuration this rule was compiled from.</summary>
    public BanRule Definition { get; }

    /// <summary>Rule name, unique across loaded rules.</summary>
    public string Name => Definition.Name;

    /// <summary>Whether a monitor should run for this rule.</summary>
    public bool Enabled => Definition.Enabled;

    /// <summary>Log source kind; the path or service is in <see cref="Definition"/>.</summary>
    public LogSourceKind SourceKind { get; }

    /// <summary>When matches turn into bans.</summary>
    public BanActionKind ActionKind { get; }

    /// <summary>Prepared matching expressions, evaluated in order.</summary>
    public IReadOnlyList<CompiledExpression> Expressions { get; }

    /// <summary>Per-IP match timestamps; present only for threshold rules.</summary>
    internal ThresholdState? Threshold { get; }

    /// <summary>Validates and compiles a rule definition.</summary>
    /// <exception cref="InvalidDataException">The definition is invalid; the message says why.</exception>
    public static CompiledRule Compile(BanRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (string.IsNullOrWhiteSpace(rule.Name))
            throw Invalid("Rule name is required.");

        var source = rule.LogSource switch
        {
            { Type: "file", Path: { } path } when !string.IsNullOrWhiteSpace(path) => LogSourceKind.File,
            { Type: "journal", Service: { } service } when !string.IsNullOrWhiteSpace(service) && !service.Contains('\0') =>
                LogSourceKind.Journal,
            { Type: "file" } => throw Invalid("A file log source requires a path."),
            { Type: "journal" } => throw Invalid("A journal log source requires a service name without null characters."),
            _ => throw Invalid("A log source of type 'file' or 'journal' is required."),
        };

        if (rule.Matching is not { Count: > 0 and <= 100 })
            throw Invalid("Rules require between 1 and 100 matching expressions.");

        var action = rule.Action?.Type switch
        {
            "immediate" => BanActionKind.Immediate,
            "threshold" => BanActionKind.Threshold,
            _ => throw Invalid("Action type must be 'immediate' or 'threshold'."),
        };
        if (rule.Action.BanDurationSeconds < 0 || rule.Action.MaxMatches is < 1 or > 10000 ||
            rule.Action.WindowSeconds is < 1 or > 86400 || rule.MaxTrackedIps is < 1 or > 100000 ||
            rule.Action.Reason is null || rule.Action.Reason.Length > ProtocolConstants.MaxReasonLength)
        {
            throw Invalid("Invalid action, threshold, duration, or state limits.");
        }

        return new CompiledRule(rule, source, action, rule.Matching.Select(CompileExpression).ToArray());
    }

    private static CompiledExpression CompileExpression(MatchExpression? expression)
    {
        switch (expression)
        {
            case null:
                throw Invalid("Matching expressions cannot be null.");
            case { Type: "regex" }:
                if (string.IsNullOrWhiteSpace(expression.Pattern) || expression.Pattern.Length > 4096)
                    throw Invalid("Regex patterns must contain between 1 and 4096 characters.");
                Regex regex;
                try
                {
                    regex = new Regex(expression.Pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout);
                }
                catch (ArgumentException ex)
                {
                    throw Invalid($"Invalid regex: {ex.Message}");
                }

                if (!regex.GetGroupNames().Contains("ip", StringComparer.Ordinal))
                    throw Invalid("Regex patterns require a named group (?<ip>...).");
                return new CompiledExpression(MatchKind.Regex, regex, null, null, null);
            case { Type: "json", JsonPath: { } jsonPath } when !string.IsNullOrWhiteSpace(jsonPath):
                return new CompiledExpression(MatchKind.Json, null, jsonPath.Split('.'), expression.JsonValue,
                    (expression.IpJsonPath ?? "ip").Split('.'));
            default:
                throw Invalid("Expressions require a regex pattern or JSON field path.");
        }
    }

    private static InvalidDataException Invalid(string message) => new(message);

    /// <summary>Threshold counters, guarded by their own lock.</summary>
    internal sealed class ThresholdState
    {
        public object Gate { get; } = new();
        public Dictionary<string, Queue<DateTimeOffset>> Matches { get; } = new(StringComparer.Ordinal);
        public DateTimeOffset NextCleanup;
        public bool CapacityWarningLogged;
    }
}
