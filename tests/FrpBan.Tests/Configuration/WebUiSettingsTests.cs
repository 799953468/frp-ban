using FrpBan.Configuration;
using Xunit;

namespace FrpBan.Tests.Configuration;

public sealed class WebUiSettingsTests
{
    private const string ClientToken = "test-client-secret-at-least-32-characters";
    private const string ManagementToken = "test-admin-secret-at-least-32-characters";

    [Fact]
    public void Management_IsDisabledByDefaultAndNeedsNoSecret()
    {
        var settings = new PluginSettings { Token = ClientToken };
        Assert.False(settings.WebUi.Enabled);
        Assert.Empty(settings.Validate());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("short")]
    [InlineData("CHANGE_ME_TO_A_LONG_RANDOM_SECRET")]
    [InlineData("test token containing spaces and over 32 characters")]
    [InlineData("test-token-containing-非ascii-over32-characters")]
    [InlineData(ClientToken)]
    public void EnabledManagement_RejectsInvalidAndSharedTokens(string? token)
    {
        var settings = new PluginSettings { Token = ClientToken, WebUi = new WebUiSettings { Enabled = true, Token = token! } };
        Assert.True(new PluginSettingsValidator().Validate(null, settings).Failed);
    }

    [Fact]
    public void EnabledManagement_RejectsOversizedToken()
    {
        var settings = new WebUiSettings { Enabled = true, Token = new string('x', 257) };
        Assert.NotEmpty(settings.Validate(ClientToken));
    }

    [Theory]
    [InlineData("hostname.example")]
    [InlineData("192.0.2.1/24")]
    [InlineData("2001:db8::/129")]
    public void EnabledManagement_ValidatesAllowedNetworks(string address)
    {
        var settings = new WebUiSettings { Enabled = true, Token = ManagementToken, AllowedAddresses = [address] };
        Assert.NotEmpty(settings.Validate(ClientToken));
    }

    [Fact]
    public void EnabledManagement_AcceptsValidNetworksAndExplicitEmptyList()
    {
        var settings = new WebUiSettings
        {
            Enabled = true, Token = ManagementToken, AllowedAddresses = ["127.0.0.1", "::1", "192.0.2.0/24", "2001:db8::/32"]
        };
        Assert.Empty(settings.Validate(ClientToken));
        settings.AllowedAddresses = [];
        Assert.Empty(settings.Validate(ClientToken));
        settings.AllowedAddresses = null!;
        Assert.NotEmpty(settings.Validate(ClientToken));
    }
}