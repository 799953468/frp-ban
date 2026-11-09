using FrpBan.Client.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace FrpBan.Tests.Configuration;

public class RulesLoaderTests
{
    [Fact]
    public void BundledRules_AreValidAndDetectSshAttacks()
    {
        var rules = new RulesLoader(NullLogger<RulesLoader>.Instance)
            .LoadRules(Path.Combine(AppContext.BaseDirectory, "rules.d"));
        Assert.Equal(2, rules.Count);
        var engine = new RuleMatchEngine(NullLogger<RuleMatchEngine>.Instance);
        foreach (var rule in rules)
        {
            var line = rule.Name == "SSH Brute Force"
                ? "sshd: Failed password for root from 192.0.2.1 port 22 ssh2"
                : "sshd: Invalid user nobody from 192.0.2.1 port 22";
            for (var i = 1; i < rule.Action.MaxMatches; i++) Assert.Empty(engine.ProcessLogLine(line, rule));
            Assert.Equal("192.0.2.1", Assert.Single(engine.ProcessLogLine(line, rule)).ip);
        }
    }
}
