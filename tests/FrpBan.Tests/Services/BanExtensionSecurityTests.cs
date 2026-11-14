using FrpBan.Configuration;
using FrpBan.Models;
using FrpBan.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace FrpBan.Tests.Services;

public class BanExtensionSecurityTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "frp-ban-extensions-" + Guid.NewGuid());

    [Theory]
    [InlineData(0, 1)]
    [InlineData(0, null)]
    [InlineData(7200, 1)]
    [InlineData(7200, 1800)]
    [InlineData(7200, null)]
    public async Task WeakerRequest_PreservesExistingBanAndPersistedExpiry(int originalDuration, int? requestedDuration)
    {
        BanEntry original;
        await using (var service = CreateService())
        {
            await service.BanAsync("192.0.2.10", "Original stronger ban", originalDuration);
            original = Assert.Single(service.GetActiveBans());

            await service.BanAsync("::ffff:192.0.2.10", "Weaker request", requestedDuration);

            Assert.Equal(original, Assert.Single(service.GetActiveBans()));
        }

        await using var restored = CreateService();
        restored.Load();
        Assert.Equal(original, Assert.Single(restored.GetActiveBans()));
    }

    [Theory]
    [InlineData(1, 7200)]
    [InlineData(3600, 0)]
    public async Task StrongerRequest_ExtendsOrMakesBanPermanent(int originalDuration, int requestedDuration)
    {
        await using var service = CreateService();
        await service.BanAsync("192.0.2.10", "Original ban", originalDuration);
        var original = Assert.Single(service.GetActiveBans());

        await service.BanAsync("192.0.2.10", "Stronger request", requestedDuration);

        var updated = Assert.Single(service.GetActiveBans());
        Assert.Equal("Stronger request", updated.Reason);
        if (requestedDuration == 0)
        {
            Assert.Null(updated.ExpiresAt);
        }
        else
        {
            Assert.True(updated.ExpiresAt > original.ExpiresAt);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7200)]
    public async Task ConcurrentWeakerRequests_CannotShortenExistingBan(int originalDuration)
    {
        await using var service = CreateService();
        await service.BanAsync("192.0.2.10", "Original stronger ban", originalDuration);
        var original = Assert.Single(service.GetActiveBans());

        await Parallel.ForEachAsync(Enumerable.Range(1, 64), async (duration, _) =>
        {
            await service.BanAsync("192.0.2.10", "Concurrent weaker request", duration);
        });

        Assert.Equal(original, Assert.Single(service.GetActiveBans()));
    }

    [Fact]
    public async Task ConcurrentRequests_KeepPermanentBanRegardlessOfOrder()
    {
        await using var service = CreateService();

        await Parallel.ForEachAsync(Enumerable.Range(0, 64), async (duration, _) =>
        {
            await service.BanAsync("192.0.2.10", "Concurrent request", duration);
        });

        Assert.Null(Assert.Single(service.GetActiveBans()).ExpiresAt);
    }

    [Fact]
    public async Task ExplicitUnban_AllowsANewTemporaryBan()
    {
        await using var service = CreateService();
        await service.BanAsync("192.0.2.10", "Permanent ban", 0);

        await service.UnbanAsync("192.0.2.10");
        Assert.False(service.IsBanned("192.0.2.10"));
        await service.BanAsync("192.0.2.10", "New temporary ban", 60);

        var entry = Assert.Single(service.GetActiveBans());
        Assert.Equal(TimeSpan.FromMinutes(1), entry.ExpiresAt - entry.BannedAt);
    }

    private BanService CreateService()
    {
        return new BanService(Options.Create(new PluginSettings
        {
            BanFilePath = Path.Combine(_directory, "bans.json"),
            DefaultBanDurationSeconds = 3600,
        }), NullLogger<BanService>.Instance);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}