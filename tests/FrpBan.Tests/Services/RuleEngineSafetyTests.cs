using System.Collections.Concurrent;
using FrpBan.Client.Configuration;
using FrpBan.Client.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace FrpBan.Tests.Services;

public class RuleEngineSafetyTests
{
    private static BanRule CreateRule(int threshold = 2, int maxIps = 10000) => new()
    {
        Name = "same-name", MaxTrackedIps = maxIps,
        Matching = [new MatchExpression { Pattern = @"(?<ip>\S+) failed" }],
        Action = new BanAction { Type = "threshold", MaxMatches = threshold, WindowSeconds = 60 },
    };
    private static RuleMatchEngine CreateEngine(TimeProvider? time = null) =>
        new(NullLogger<RuleMatchEngine>.Instance, time);

    [Fact]
    public void ConcurrentMatches_DoNotLoseOrDuplicateThresholdEvents()
    {
        var engine = CreateEngine();
        var rule = CreateRule(threshold: 50);
        var results = new ConcurrentBag<string>();
        Parallel.For(0, 1000, _ =>
        {
            foreach (var result in engine.ProcessLogLine("192.0.2.1 failed", rule))
                results.Add(result.ip);
        });
        Assert.Equal(20, results.Count);
    }

    [Fact]
    public void EqualRuleNames_DoNotShareCounters()
    {
        var engine = CreateEngine();
        var first = CreateRule();
        var second = CreateRule();
        Assert.Empty(engine.ProcessLogLine("192.0.2.1 failed", first));
        Assert.Empty(engine.ProcessLogLine("192.0.2.1 failed", second));
        Assert.Single(engine.ProcessLogLine("192.0.2.1 failed", first));
    }

    [Fact]
    public void ExpiredCounters_AreEvictedAndCapacityIsReusable()
    {
        var time = new ManualTime();
        var engine = CreateEngine(time);
        var rule = CreateRule(maxIps: 1);
        Assert.Empty(engine.ProcessLogLine("192.0.2.1 failed", rule));
        Assert.Empty(engine.ProcessLogLine("192.0.2.2 failed", rule));
        time.Advance(TimeSpan.FromSeconds(61));
        Assert.Empty(engine.ProcessLogLine("192.0.2.2 failed", rule));
        Assert.Single(engine.ProcessLogLine("192.0.2.2 failed", rule));
    }

    [Fact]
    public void InvalidExtractedIp_IsDiscarded()
    {
        var rule = CreateRule(threshold: 1);
        Assert.Empty(CreateEngine().ProcessLogLine("999.999.999.999 failed", rule));
    }

    [Fact]
    public void NumericJsonCondition_ExtractsIpFromSeparateField()
    {
        var rule = new BanRule
        {
            Matching = [new MatchExpression { Type = "json", JsonPath = "status", JsonValue = "401", IpJsonPath = "request.ip" }],
            Action = new BanAction { Type = "immediate" },
        };
        var result = CreateEngine().ProcessLogLine("{\"status\":401,\"request\":{\"ip\":\"192.0.2.1\"}}", rule);
        Assert.Equal("192.0.2.1", Assert.Single(result).ip);
    }

    [Fact]
    public void OversizedLine_IsIgnored()
    {
        Assert.Empty(CreateEngine().ProcessLogLine(new string('x', RuleMatchEngine.MaxLogLineLength + 1), CreateRule()));
    }

    [Fact]
    public void EveryRegexMatch_IsConsidered()
    {
        var results = CreateEngine().ProcessLogLine("192.0.2.1 failed 192.0.2.2 failed", CreateRule(threshold: 1));
        Assert.Equal(2, results.Count);
    }

    [Fact]
    public void PathologicalRegex_IsInterruptedByTheTimeout()
    {
        var logger = new Mock<ILogger<RuleMatchEngine>>();
        var engine = new RuleMatchEngine(logger.Object);
        var rule = new BanRule
        {
            Matching = [new MatchExpression { Pattern = @"^(?<ip>(a+)+)$" }],
            Action = new BanAction { Type = "immediate" },
        };
        Assert.Empty(engine.ProcessLogLine(new string('a', 20000) + "!", rule));
        Assert.Contains(logger.Invocations, invocation => invocation.Method.Name == "Log" &&
            invocation.Arguments[2].ToString()!.Contains("timed out", StringComparison.Ordinal));
    }

    private sealed class ManualTime : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan elapsed) => _now += elapsed;
    }
}
