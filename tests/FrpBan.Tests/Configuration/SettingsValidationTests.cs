using System.ComponentModel.DataAnnotations;
using FrpBan.Client.Configuration;
using FrpBan.Client.Services;
using FrpBan.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace FrpBan.Tests.Configuration;

public class SettingsValidationTests
{
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
