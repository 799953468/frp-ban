using System.Runtime.CompilerServices;
using FrpBan.Client.Configuration;
using FrpBan.Client.Matching;
using FrpBan.Client.Services;

namespace FrpBan.Tests;

/// <summary>
/// Test convenience: lets matching tests pass a <see cref="BanRule"/> definition directly. Each definition
/// is compiled once and reused, so threshold counters accumulate across calls as they do in production.
/// A missing name or file path gets a placeholder, because these tests exercise matching rather than
/// source validation (covered by RulesLoaderTests). Journal sources are compiled exactly as given.
/// </summary>
internal static class RuleTestExtensions
{
    private static readonly ConditionalWeakTable<BanRule, CompiledRule> Cache = new();

    public static CompiledRule Compiled(this BanRule rule) => Cache.GetValue(rule, definition =>
        CompiledRule.Compile(new BanRule
        {
            Name = string.IsNullOrWhiteSpace(definition.Name) ? "test rule" : definition.Name,
            Enabled = definition.Enabled,
            LogSource = definition.LogSource is { Type: "file", Path: null }
                ? new LogSource { Type = "file", Path = "/tmp/frp-ban-test.log" }
                : definition.LogSource,
            Matching = definition.Matching,
            Action = definition.Action,
            MaxTrackedIps = definition.MaxTrackedIps,
        }));

    public static IReadOnlyList<BanMatch> ProcessLogLine(this RuleMatchEngine engine, string line, BanRule rule) =>
        engine.ProcessLogLine(line, rule.Compiled());
}
