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
    public void InvalidWhitelist_FailsStartup(string entry) => Assert.Throws<FormatException>(() =>
        new PluginAddressFilter(Options.Create(new PluginSettings { AllowedPluginAddresses = [entry] })));
}
