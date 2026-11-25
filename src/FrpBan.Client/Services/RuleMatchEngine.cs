using System.Text.Json;
using System.Text.RegularExpressions;
using FrpBan.Client.Matching;
using FrpBan.Protocol;
using Microsoft.Extensions.Logging;

namespace FrpBan.Client.Services;

/// <summary>Evaluates complete log lines against compiled rules. Stateless apart from the rules' own counters.</summary>
public sealed class RuleMatchEngine(ILogger<RuleMatchEngine> logger, TimeProvider? timeProvider = null)
{
    /// <summary>Maximum accepted log-line length in characters.</summary>
    public const int MaxLogLineLength = 65536;

    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <summary>Returns canonical IP ban requests for a single complete log line.</summary>
    public IReadOnlyList<BanMatch> ProcessLogLine(string logLine, CompiledRule rule)
    {
        if (!rule.Enabled || logLine.Length > MaxLogLineLength)
            return [];
        var ips = ExtractIps(logLine, rule.Expressions);
        if (ips.Count == 0)
            return [];

        var action = rule.Definition.Action;
        if (rule.ActionKind == BanActionKind.Immediate)
            return ips.Select(ip => new BanMatch(ip, action.BanDurationSeconds, action.Reason)).ToList();

        var results = new List<BanMatch>();
        var state = rule.Threshold!;
        var now = _time.GetUtcNow();
        var cutoff = now.AddSeconds(-action.WindowSeconds);
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

                state.NextCleanup = now.AddSeconds(Math.Min(action.WindowSeconds, 60));
                state.CapacityWarningLogged = false;
            }

            foreach (var ip in ips)
            {
                if (!state.Matches.TryGetValue(ip, out var matches))
                {
                    if (state.Matches.Count >= rule.Definition.MaxTrackedIps)
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
                if (matches.Count >= action.MaxMatches)
                {
                    state.Matches.Remove(ip);
                    results.Add(new BanMatch(ip, action.BanDurationSeconds, action.Reason));
                }
            }
        }

        return results;
    }

    private HashSet<string> ExtractIps(string line, IReadOnlyList<CompiledExpression> expressions)
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
                    if (expression.Kind == MatchKind.Regex)
                    {
                        foreach (Match match in expression.Regex!.Matches(line))
                            AddIp(match.Groups["ip"].Value);
                        continue;
                    }

                    if (!jsonAttempted)
                    {
                        jsonAttempted = true;
                        document = JsonDocument.Parse(line);
                    }

                    if (document is null || Navigate(document.RootElement, expression.JsonPath!) is not { } value)
                        continue;
                    if (expression.JsonValue is not null)
                    {
                        if (!string.Equals(Scalar(value), expression.JsonValue, StringComparison.OrdinalIgnoreCase))
                            continue;
                        // A condition field (e.g. status=401) is not itself an IP address.
                        if (Navigate(document.RootElement, expression.IpJsonPath!) is not { } ipValue)
                            continue;
                        value = ipValue;
                    }

                    AddIp(Scalar(value));
                }
                catch (RegexMatchTimeoutException)
                {
                    logger.LogWarning("Regex timed out; pattern {Pattern}", expression.Regex);
                }
                catch (JsonException)
                {
                    // A non-JSON log line is a normal non-match.
                }
            }
        }
        finally
        {
            document?.Dispose();
        }

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

    private static JsonElement? Navigate(JsonElement current, string[] path)
    {
        foreach (var part in path)
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
}
