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
            for (var i = 1; i < rule.Action.MaxMatches; i++)
            {
                Assert.Empty(engine.ProcessLogLine(line, rule));
            }

            Assert.Equal("192.0.2.1", Assert.Single(engine.ProcessLogLine(line, rule)).ip);
        }
    }

    [Fact]
    public void YamlAliasesQuotedScalarsAndDefaults_ArePreserved()
    {
        var rules = LoadYaml("""
                             rules:
                               - name: "null"
                                 logSource: &source
                                   path: /tmp/auth.log
                                 matching: &matching
                                   - pattern: 'Failed from (?<ip>\S+)'
                                 action:
                                   reason: |
                                     First line
                                     Second line
                                   banDurationSeconds: "120"
                               - name: second
                                 enabled: false
                                 logSource: *source
                                 matching: *matching
                             """);

        Assert.Equal(2, rules.Count);
        Assert.Equal("null", rules[0].Name);
        Assert.True(rules[0].Enabled);
        Assert.Equal("file", rules[0].LogSource.Type);
        Assert.Equal(120, rules[0].Action.BanDurationSeconds);
        Assert.Equal("First line\nSecond line\n", rules[0].Action.Reason);
        Assert.False(rules[1].Enabled);
        Assert.Equal("/tmp/auth.log", rules[1].LogSource.Path);
        Assert.Equal(rules[0].Matching[0].Pattern, rules[1].Matching[0].Pattern);
        Assert.Equal(5, rules[1].Action.MaxMatches);
    }

    [Theory]
    [InlineData("enabled: invalid")]
    [InlineData("maxTrackedIps: invalid")]
    [InlineData("maxTrackedIps: 2147483648")]
    [InlineData("unknownProperty: true")]
    [InlineData("action: null")]
    [InlineData("action: []")]
    [InlineData("action: { maxMatches: 0 }")]
    [InlineData("action: { reason: null }")]
    public void InvalidYamlRules_AreRejected(string property)
    {
        var yaml = """
                   rules:
                     - name: test
                       logSource: { path: /tmp/auth.log }
                       matching:
                         - pattern: '(?<ip>\S+)'
                   """ + "\n    " + property + "\n";

        Assert.Empty(LoadYaml(yaml));
    }

    [Fact]
    public void NullItems_AreRejectedWithoutDiscardingOtherRules()
    {
        var rules = LoadYaml("""
                             rules:
                               - null
                               - name: valid
                                 logSource: { path: /tmp/auth.log }
                                 matching:
                                   - type: json
                                     jsonPath: event
                                     jsonValue: "null"
                                     ipJsonPath: address
                             """);

        var rule = Assert.Single(rules);
        Assert.Equal("null", rule.Matching[0].JsonValue);
        var engine = new RuleMatchEngine(NullLogger<RuleMatchEngine>.Instance);
        for (var i = 1; i < rule.Action.MaxMatches; i++)
        {
            Assert.Empty(engine.ProcessLogLine("""{"event":"null","address":"192.0.2.1"}""", rule));
        }

        Assert.Equal("192.0.2.1", Assert.Single(engine.ProcessLogLine(
            """{"event":"null","address":"192.0.2.1"}""", rule)).ip);
    }

    [Theory]
    [InlineData("yes", "0x78", true, 120)]
    [InlineData("ON", "0170", true, 120)]
    [InlineData("n", "0b1111000", false, 120)]
    [InlineData("off", "2:00", false, 120)]
    [InlineData("true", "1_200", true, 1200)]
    [InlineData("false", "+120", false, 120)]
    public void LegacyYamlScalarForms_ArePreserved(string enabled, string duration, bool expectedEnabled, int expectedDuration)
    {
        var yaml = $$"""
                     rules:
                       - name: legacy
                         enabled: {{enabled}}
                         logSource: { path: /tmp/auth.log }
                         matching:
                           - pattern: '(?<ip>\S+)'
                         action:
                           banDurationSeconds: {{duration}}
                     """;

        var rule = Assert.Single(LoadYaml(yaml));
        Assert.Equal(expectedEnabled, rule.Enabled);
        Assert.Equal(expectedDuration, rule.Action.BanDurationSeconds);
    }

    private static List<FrpBan.Client.Configuration.BanRule> LoadYaml(string yaml)
    {
        var path = Path.Combine(Path.GetTempPath(), $"frp-ban-rules-{Guid.NewGuid():N}.yaml");
        try
        {
            File.WriteAllText(path, yaml);
            return new RulesLoader(NullLogger<RulesLoader>.Instance).LoadRules(path);
        }
        finally
        {
            File.Delete(path);
        }
    }
}