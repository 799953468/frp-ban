using System.ComponentModel.DataAnnotations;
using FrpBan.Client.Configuration;
using FrpBan.Client.Services;
using FrpBan.Configuration;
using FrpBan.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace FrpBan.Tests.Configuration;

public class SettingsValidationTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("not-an-address")]
    [InlineData("example.com")]
    [InlineData("192.0.2.1:80")]
    [InlineData("192.0.2.0/33")]
    [InlineData("192.0.2.0/-1")]
    [InlineData("192.0.2.1/24")]
    [InlineData("2001:db8::/129")]
    [InlineData("2001:db8::1/32")]
    [InlineData("::ffff:192.0.2.0/95")]
    public void InvalidExemption_FailsStartupValidationAndStoreConstruction(string? entry)
    {
        var settings = new PluginSettings
        {
            Token = "a-non-placeholder-secret-with-32-characters",
            ExemptAddresses = [entry!],
        };

        var result = new PluginSettingsValidator().Validate(null, settings);

        Assert.True(result.Failed);
        Assert.Contains("ExemptAddresses", result.FailureMessage);
        Assert.Throws<ArgumentException>(() =>
        {
            using (var service = new BanService(Options.Create(settings), NullLogger<BanService>.Instance))
            {
                service.Load();
            }
        });
    }

    [Fact]
    public void NullExemptionList_FailsStartupValidation()
    {
        var settings = new PluginSettings
        {
            Token = "a-non-placeholder-secret-with-32-characters",
            ExemptAddresses = null!,
        };

        var result = new PluginSettingsValidator().Validate(null, settings);

        Assert.True(result.Failed);
        Assert.Contains("ExemptAddresses", result.FailureMessage);
    }

    [Fact]
    public void ValidAndEmptyExemptionLists_PassStartupValidation()
    {
        var settings = new PluginSettings
        {
            Token = "a-non-placeholder-secret-with-32-characters",
        };
        var validator = new PluginSettingsValidator();

        Assert.True(validator.Validate(null, settings).Succeeded);

        settings.ExemptAddresses = ["192.0.2.1", "192.0.2.0/24", "2001:db8::1", "2001:db8::/32", "::ffff:192.0.2.0/120"];

        Assert.True(validator.Validate(null, settings).Succeeded);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("short")]
    [InlineData("CHANGE_ME_TO_A_LONG_RANDOM_SECRET")]
    public void PlaceholderOrWeakToken_IsRejected(string token)
    {
        var settings = new PluginSettings { Token = token };
        Assert.False(Validator.TryValidateObject(settings, new ValidationContext(settings), [], true));
    }

    [Fact]
    public void NestedTlsSettings_AreValidated()
    {
        var settings = new PluginSettings
        {
            Token = "a-non-placeholder-secret-with-32-characters",
            Tls = new TlsSettings { Port = 70000, HandshakeTimeoutSeconds = 0 },
        };
        Assert.False(Validator.TryValidateObject(settings, new ValidationContext(settings), [], true));
    }

    [Fact]
    public void InvalidClientBackoff_IsRejected()
    {
        var settings = new ClientSettings
        {
            Token = "a-non-placeholder-secret-with-32-characters",
            Reconnection = new ReconnectionSettings { BackoffMultiplier = double.NaN },
        };
        Assert.False(Validator.TryValidateObject(settings, new ValidationContext(settings), [], true));
    }

    [Fact]
    public async Task ExhaustedRetries_ReturnFalseInsteadOfAnUnthrottledLoop()
    {
        using var service = new ClientConnectionService(Options.Create(new ClientSettings
        {
            Reconnection = new ReconnectionSettings { MaxRetries = 0 },
        }), NullLogger<ClientConnectionService>.Instance);
        Assert.False(await service.WaitBeforeRetryAsync(CancellationToken.None));
    }
}