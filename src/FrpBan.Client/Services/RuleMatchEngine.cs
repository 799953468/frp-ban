using System.Text.Json;
using System.Text.RegularExpressions;
using FrpBan.Client.Configuration;
using Microsoft.Extensions.Logging;

namespace FrpBan.Client.Services;

/// <summary>
/// Rule matching engine for detecting ban conditions.
/// Supports regex patterns and JSON field matching.
/// </summary>
public sealed class RuleMatchEngine
{
    private readonly ILogger<RuleMatchEngine> _logger;
    private readonly Dictionary<string, RuleState> _ruleStates = new();

    public RuleMatchEngine(ILogger<RuleMatchEngine> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Processes a log line and returns ban requests if rules match.
    /// </summary>
    public List<(string ip, int? durationSeconds, string reason)> ProcessLogLine(
        string logLine,
        BanRule rule)
    {
        var results = new List<(string ip, int? durationSeconds, string reason)>();

        if (!rule.Enabled)
            return results;

        try
        {
            // Try to extract IP from log line using match expressions
            var ips = ExtractIpsFromLog(logLine, rule.Matching);
            if (ips.Count == 0)
                return results; // No match

            _logger.LogDebug("Rule '{Rule}' matched IP(s): {IPs}", rule.Name, string.Join(",", ips));

            // Get or create rule state
            var stateKey = rule.Name;
            if (!_ruleStates.TryGetValue(stateKey, out var state))
            {
                state = new RuleState();
                _ruleStates[stateKey] = state;
            }

            // Process each matched IP
            foreach (var ip in ips)
            {
                var banRequest = ProcessIpMatch(ip, rule, state);
                if (banRequest.HasValue)
                    results.Add(banRequest.Value);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing rule '{Rule}' against log line", rule.Name);
        }

        return results;
    }

    private List<string> ExtractIpsFromLog(string logLine, List<MatchExpression> expressions)
    {
        var ips = new List<string>();

        foreach (var expr in expressions)
        {
            if (expr.Type == "regex" && expr.Pattern != null)
            {
                ips.AddRange(ExtractIpsFromRegex(logLine, expr.Pattern));
            }
            else if (expr.Type == "json" && expr.JsonPath != null)
            {
                ips.AddRange(ExtractIpsFromJson(logLine, expr.JsonPath, expr.JsonValue));
            }
        }

        return ips.Distinct().ToList();
    }

    private List<string> ExtractIpsFromRegex(string logLine, string pattern)
    {
        var ips = new List<string>();
        try
        {
            var regex = new Regex(pattern, RegexOptions.Compiled);
            var match = regex.Match(logLine);

            if (match.Success && match.Groups.TryGetValue("ip", out var ipGroup))
            {
                var ip = ipGroup.Value;
                if (!string.IsNullOrWhiteSpace(ip))
                    ips.Add(ip);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Invalid regex pattern: {Pattern}", pattern);
        }

        return ips;
    }

    private List<string> ExtractIpsFromJson(string logLine, string jsonPath, string? expectedValue)
    {
        var ips = new List<string>();
        try
        {
            var doc = JsonDocument.Parse(logLine);
            var root = doc.RootElement;

            // Navigate JSON path
            var value = NavigateJsonPath(root, jsonPath);
            if (value.HasValue)
            {
                var stringValue = value.Value.GetString();
                if (!string.IsNullOrWhiteSpace(stringValue))
                {
                    // If expectedValue is set, only match if it matches
                    if (expectedValue == null || stringValue.Equals(expectedValue, StringComparison.OrdinalIgnoreCase))
                    {
                        ips.Add(stringValue);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to parse as JSON or navigate path '{Path}'", jsonPath);
        }

        return ips;
    }

    private JsonElement? NavigateJsonPath(JsonElement element, string path)
    {
        var parts = path.Split('.');
        var current = element;

        foreach (var part in parts)
        {
            if (current.ValueKind == JsonValueKind.Object && current.TryGetProperty(part, out var next))
            {
                current = next;
            }
            else
            {
                return null;
            }
        }

        return current;
    }

    private (string ip, int? durationSeconds, string reason)? ProcessIpMatch(
        string ip,
        BanRule rule,
        RuleState state)
    {
        if (rule.Action.Type == "immediate")
        {
            // Immediate ban
            return (ip, rule.Action.BanDurationSeconds, rule.Action.Reason);
        }
        else if (rule.Action.Type == "threshold")
        {
            // Threshold-based ban
            var windowStart = DateTimeOffset.UtcNow.AddSeconds(-rule.Action.WindowSeconds);

            // Clean old entries
            if (!state.IpMatches.TryGetValue(ip, out var matches))
            {
                matches = new List<DateTimeOffset>();
                state.IpMatches[ip] = matches;
            }

            matches.RemoveAll(m => m < windowStart);
            matches.Add(DateTimeOffset.UtcNow);

            _logger.LogDebug("IP {IP} matches count in {WindowSec}s window: {Count}/{Max}",
                ip, rule.Action.WindowSeconds, matches.Count, rule.Action.MaxMatches);

            if (matches.Count >= rule.Action.MaxMatches)
            {
                // Clear the state for this IP
                state.IpMatches.Remove(ip);
                return (ip, rule.Action.BanDurationSeconds, rule.Action.Reason);
            }
        }

        return null;
    }

    private sealed class RuleState
    {
        public Dictionary<string, List<DateTimeOffset>> IpMatches { get; } = new();
    }
}
