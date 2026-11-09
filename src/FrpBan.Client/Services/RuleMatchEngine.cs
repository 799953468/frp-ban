using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using FrpBan.Client.Configuration;
using FrpBan.Client.Matching;
using FrpBan.Protocol;
using Microsoft.Extensions.Logging;

namespace FrpBan.Client.Services;

/// <summary>Matches bounded log lines using cached regexes and isolated, synchronized rule state.</summary>
public sealed class RuleMatchEngine(ILogger<RuleMatchEngine> logger, TimeProvider? timeProvider = null)
{
    /// <summary>Maximum accepted log-line length in characters.</summary>
    public const int MaxLogLineLength = 65536;
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly ConditionalWeakTable<BanRule, RuleState> _states = new();

    /// <summary>Returns canonical IP ban requests for a single complete log line.</summary>
    public List<(string ip, int? durationSeconds, string reason)> ProcessLogLine(string logLine, BanRule rule)
    {
        var results = new List<(string ip, int? durationSeconds, string reason)>();
        if (!rule.Enabled || logLine.Length > MaxLogLineLength || rule.Action.BanDurationSeconds < 0)
            return results;
        var ips = ExtractIps(logLine, rule.Matching);
        if (rule.Action.Type == "immediate")
        {
            foreach (var ip in ips)
                results.Add((ip, rule.Action.BanDurationSeconds, rule.Action.Reason));
            return results;
        }
        if (rule.Action.Type != "threshold" || rule.Action.MaxMatches < 1 || rule.Action.WindowSeconds < 1)
            return results;

        var state = _states.GetValue(rule, _ => new RuleState());
        var now = _time.GetUtcNow();
        var cutoff = now.AddSeconds(-rule.Action.WindowSeconds);
        lock (state.Gate)
        {
            if (now >= state.NextCleanup)
            {
                foreach (var pair in state.Matches.ToArray())
                {
                    Prune(pair.Value, cutoff);
                    if (pair.Value.Count == 0)
                        state.Matches.Remove(pair.Key);
                }
                state.NextCleanup = now.AddSeconds(Math.Min(rule.Action.WindowSeconds, 60));
                state.CapacityWarningLogged = false;
            }
            foreach (var ip in ips)
            {
                if (!state.Matches.TryGetValue(ip, out var matches))
                {
                    if (state.Matches.Count >= rule.MaxTrackedIps)
                    {
                        if (!state.CapacityWarningLogged)
                            logger.LogWarning("Rule {Rule} reached its tracked IP limit", rule.Name);
                        state.CapacityWarningLogged = true;
                        continue;
                    }
                    state.Matches[ip] = matches = new Queue<DateTimeOffset>();
                }
                Prune(matches, cutoff);
                matches.Enqueue(now);
                if (matches.Count >= rule.Action.MaxMatches)
                {
                    state.Matches.Remove(ip);
                    results.Add((ip, rule.Action.BanDurationSeconds, rule.Action.Reason));
                }
            }
        }
        return results;
    }

    private HashSet<string> ExtractIps(string line, List<MatchExpression> expressions)
    {
        var ips = new HashSet<string>(StringComparer.Ordinal);
        JsonDocument? document = null;
        var jsonAttempted = false;
        try
        {
            foreach (var expression in expressions)
            {
                try
                {
                    if (expression.Type == "regex" && expression.Pattern is not null)
                    {
                        foreach (Match match in RuleRegex.Get(expression).Matches(line))
                            AddIp(match.Groups["ip"].Value);
                    }
                    else if (expression.Type == "json" && expression.JsonPath is not null)
                    {
                        if (!jsonAttempted)
                        {
                            jsonAttempted = true;
                            document = JsonDocument.Parse(line);
                        }
                        if (document is null)
                            continue;
                        var value = Navigate(document.RootElement, expression.JsonPath);
                        if (value is null)
                            continue;
                        if (expression.JsonValue is not null)
                        {
                            if (!string.Equals(Scalar(value.Value), expression.JsonValue, StringComparison.OrdinalIgnoreCase))
                                continue;
                            // A condition field (e.g. status=401) is not itself an IP address.
                            value = Navigate(document.RootElement, expression.IpJsonPath ?? "ip");
                        }
                        if (value is not null)
                            AddIp(Scalar(value.Value));
                    }
                }
                catch (RegexMatchTimeoutException)
                {
                    logger.LogWarning("Regex timed out; pattern {Pattern}", expression.Pattern);
                }
                catch (ArgumentException ex)
                {
                    logger.LogWarning(ex, "Invalid rule expression");
                }
                catch (JsonException)
                {
                    // A non-JSON log line is a normal non-match.
                }
            }
        }
        finally { document?.Dispose(); }
        return ips;

        void AddIp(string? value)
        {
            if (IpAddressUtilities.Normalize(value) is { } ip)
                ips.Add(ip);
        }
    }

    private static string? Scalar(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString(),
        JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => value.GetRawText(),
        _ => null,
    };

    private static JsonElement? Navigate(JsonElement current, string path)
    {
        foreach (var part in path.Split('.'))
        {
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(part, out var next))
                return null;
            current = next;
        }
        return current;
    }

    private static void Prune(Queue<DateTimeOffset> matches, DateTimeOffset cutoff)
    {
        while (matches.TryPeek(out var timestamp) && timestamp <= cutoff)
            matches.Dequeue();
    }

    private sealed class RuleState
    {
        public object Gate { get; } = new();
        public Dictionary<string, Queue<DateTimeOffset>> Matches { get; } = new(StringComparer.Ordinal);
        public DateTimeOffset NextCleanup;
        public bool CapacityWarningLogged;
    }
}
