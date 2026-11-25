using System.Net;
using FrpBan.Configuration;
using FrpBan.Security;
using Microsoft.Extensions.Options;
using Xunit;

namespace FrpBan.Tests.Security;

public class PluginAddressFilterTests
{
    [Theory]
    [InlineData("::ffff:127.0.0.1", true)]
    [InlineData("192.0.2.7", true)]
    [InlineData("192.0.3.7", false)]
    [InlineData("2001:db8::abcd", true)]
    [InlineData("2001:db9::1", false)]
    public void CompiledNetworks_HandleMappedAndNativeAddresses(string address, bool allowed)
    {
        var filter = new PluginAddressFilter(Options.Create(new PluginSettings
        {
            AllowedPluginAddresses = ["127.0.0.1", "192.0.2.0/24", "2001:db8::/32"],
        }));
        Assert.Equal(allowed, filter.IsAllowed(IPAddress.Parse(address)));
        Assert.False(filter.IsAllowed(null));
    }

    [Theory]
    [InlineData("192.0.2.0/33")]
    [InlineData("::/129")]
    [InlineData("not-an-address")]
    [InlineData("192.0.2.1/24")]
    public void InvalidWhitelist_FailsStartup(string entry)
    {
        var settings = new PluginSettings { AllowedPluginAddresses = [entry] };
        Assert.Contains(settings.Validate(), result => result.MemberNames.Contains(nameof(PluginSettings.AllowedPluginAddresses)));
        var error = Assert.Throws<ArgumentException>(() => new PluginAddressFilter(Options.Create(settings)));
        Assert.Contains(nameof(PluginSettings.AllowedPluginAddresses), error.Message);
    }

    [Fact]
    public void EmptyWhitelist_AllowsEveryPeer()
    {
        var filter = new PluginAddressFilter(Options.Create(new PluginSettings { AllowedPluginAddresses = [] }));
        Assert.True(filter.IsAllowed(IPAddress.Parse("203.0.113.1")));
    }
}
