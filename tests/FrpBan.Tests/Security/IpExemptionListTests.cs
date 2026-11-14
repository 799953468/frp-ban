using FrpBan.Security;
using Xunit;

namespace FrpBan.Tests.Security;

public class IpExemptionListTests
{
    [Theory]
    [InlineData("192.0.2.1", "192.0.2.1", true)]
    [InlineData("192.0.2.1", "192.0.2.10", false)]
    [InlineData("192.0.2.1", "::ffff:192.0.2.1", true)]
    [InlineData("::ffff:192.0.2.1", "192.0.2.1", true)]
    [InlineData("2001:db8::1", "2001:0DB8:0000:0000:0000:0000:0000:0001", true)]
    [InlineData("2001:db8::1", "2001:db8::2", false)]
    [InlineData("192.0.2.0/24", "192.0.2.0", true)]
    [InlineData("192.0.2.0/24", "192.0.2.255", true)]
    [InlineData("192.0.2.0/24", "192.0.1.255", false)]
    [InlineData("192.0.2.0/24", "192.0.3.0", false)]
    [InlineData("192.0.2.0/24", "::ffff:192.0.2.42", true)]
    [InlineData("::ffff:192.0.2.0/120", "192.0.2.42", true)]
    [InlineData("::ffff:192.0.2.0/120", "::ffff:192.0.2.42", true)]
    [InlineData("::ffff:192.0.2.0/120", "192.0.3.0", false)]
    [InlineData("::ffff:0.0.0.0/96", "198.51.100.1", true)]
    [InlineData("2001:db8::/32", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", true)]
    [InlineData("2001:db8::/32", "2001:db9::", false)]
    [InlineData("192.0.2.1/32", "192.0.2.1", true)]
    [InlineData("192.0.2.1/32", "192.0.2.2", false)]
    [InlineData("2001:db8::1/128", "2001:db8::1", true)]
    [InlineData("2001:db8::1/128", "2001:db8::2", false)]
    [InlineData("0.0.0.0/0", "203.0.113.1", true)]
    [InlineData("0.0.0.0/0", "::ffff:203.0.113.1", true)]
    [InlineData("0.0.0.0/0", "2001:db8::1", false)]
    [InlineData("::/0", "2001:db8::1", true)]
    [InlineData("::/0", "192.0.2.1", false)]
    [InlineData("::/0", "::ffff:192.0.2.1", false)]
    [InlineData("192.0.2.1", "192.0.2.1:1234", false)]
    [InlineData("192.0.2.1", "not-an-ip", false)]
    [InlineData("192.0.2.1", "", false)]
    [InlineData("192.0.2.1", null, false)]
    public void Contains_MatchesCanonicalAddressesAndNetworkBoundaries(string entry, string? address, bool expected)
    {
        var exemptions = new IpExemptionList([entry]);

        Assert.Equal(expected, exemptions.Contains(address));
    }

    [Fact]
    public void EmptyList_DoesNotExemptAnyAddress()
    {
        var exemptions = new IpExemptionList([]);

        Assert.False(exemptions.Contains("127.0.0.1"));
        Assert.False(exemptions.Contains("::1"));
        Assert.False(exemptions.Contains("192.0.2.1"));
    }

    [Fact]
    public void Entries_AreSnapshottedAtConstruction()
    {
        var entries = new List<string> { "192.0.2.1", "2001:db8::/32" };
        var exemptions = new IpExemptionList(entries);

        entries.Clear();
        entries.Add("198.51.100.1");

        Assert.True(exemptions.Contains("192.0.2.1"));
        Assert.True(exemptions.Contains("2001:db8::1"));
        Assert.False(exemptions.Contains("198.51.100.1"));
    }
}