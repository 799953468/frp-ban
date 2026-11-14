using FrpBan.Client.Configuration;
using FrpBan.Client.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace FrpBan.Tests.Configuration;

public class DefaultSshRuleSecurityTests
{
    [Theory]
    [InlineData("192.0.2.10", "192.0.2.10")]
    [InlineData("2001:db8::20", "2001:db8::20")]
    [InlineData("2001:0db8:0000:0000:0000:0000:0000:0020", "2001:db8::20")]
    [InlineData("::ffff:192.0.2.10", "192.0.2.10")]
    [InlineData("::1", "::1")]
    public void BundledRules_DetectIpv4AndIpv6Sources(string source, string expectedIp)
    {
        AssertDetectedSource("sshd[123]:", "audit", source, expectedIp);
    }

    [Theory]
    [InlineData("sshd:")]
    [InlineData("sshd[123]:")]
    [InlineData("Nov 14 12:00:00 host sshd[123]:")]
    [InlineData("Nov  4 12:00:00 host sshd[123]:")]
    [InlineData("2026-11-14T12:00:00Z host sshd[123]:")]
    [InlineData("2026-11-14T12:00:00.123456+08:00 host sshd[123]:")]
    [InlineData("2026-11-14T12:00:00-05:00 host sshd-session[123]:")]
    [InlineData("Nov 14 12:00:00 host sshd-auth[123]:")]
    public void BundledRules_AcceptSupportedSshLogPrefixes(string prefix)
    {
        AssertDetectedSource(prefix, "audit", "2001:db8::20", "2001:db8::20", preauth: true);
    }

    [Theory]
    [InlineData("192.0.2.10", "192.0.2.10")]
    [InlineData("2001:db8::20", "2001:db8::20")]
    [InlineData("::ffff:192.0.2.10", "192.0.2.10")]
    public void BundledRules_IgnoreAddressesAndFakeConnectionSuffixesInsideUsernames(string source, string expectedIp)
    {
        AssertDetectedSource("Nov 14 12:00:00 host sshd[123]:",
            "audit from 198.51.100.42 port 22 ssh2 [preauth] from 203.0.113.42",
            source, expectedIp);
    }

    [Theory]
    [InlineData("not-an-ip", "")]
    [InlineData("192.0.2.10.attacker", "")]
    [InlineData("2001:db8::invalid", "")]
    [InlineData("999.999.999.999", "")]
    [InlineData("192.0.2.10", " unexpected trailing text")]
    [InlineData("192.0.2.10", "\n")]
    public void BundledRules_RejectInvalidSourceOrSuffixWithoutFallingBackToUsername(string source, string suffix)
    {
        foreach (var rule in LoadBundledRules())
        {
            var line = BuildLogLine(rule, "sshd[123]:", "audit from 198.51.100.42 port 22 ssh2", source) + suffix;
            AssertIgnored(rule, line);
        }
    }

    [Theory]
    [InlineData("app[456]: sshd[123]:")]
    [InlineData("Nov 14 12:00:00 host app[456]: sshd[123]:")]
    [InlineData("2026-11-14T12:00:00Z host app[456]: sshd[123]:")]
    public void BundledRules_RejectSshTextInsideOtherApplicationsLogs(string prefix)
    {
        foreach (var rule in LoadBundledRules())
        {
            AssertIgnored(rule, BuildLogLine(rule, prefix, "audit", "192.0.2.10"));
        }
    }

    private static void AssertDetectedSource(string prefix, string username, string source, string expectedIp,
        bool preauth = false)
    {
        foreach (var rule in LoadBundledRules())
        {
            var engine = new RuleMatchEngine(NullLogger<RuleMatchEngine>.Instance);
            var line = BuildLogLine(rule, prefix, username, source);
            if (preauth)
            {
                line += " [preauth]";
            }

            for (var index = 1; index < rule.Action.MaxMatches; index++)
            {
                Assert.Empty(engine.ProcessLogLine(line, rule));
            }

            Assert.Equal(expectedIp, Assert.Single(engine.ProcessLogLine(line, rule)).ip);
        }
    }

    private static void AssertIgnored(BanRule rule, string line)
    {
        var engine = new RuleMatchEngine(NullLogger<RuleMatchEngine>.Instance);
        for (var index = 0; index <= rule.Action.MaxMatches; index++)
        {
            Assert.Empty(engine.ProcessLogLine(line, rule));
        }
    }

    private static string BuildLogLine(BanRule rule, string prefix, string username, string source)
    {
        if (rule.Name == "SSH Brute Force")
        {
            return $"{prefix} Failed password for invalid user {username} from {source} port 54321 ssh2";
        }

        return $"{prefix} Invalid user {username} from {source} port 54321";
    }

    private static List<BanRule> LoadBundledRules()
    {
        var rules = new RulesLoader(NullLogger<RulesLoader>.Instance)
            .LoadRules(Path.Combine(AppContext.BaseDirectory, "rules.d"));
        Assert.Equal(2, rules.Count);
        return rules;
    }
}