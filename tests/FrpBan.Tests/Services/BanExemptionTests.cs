using System.Text.Json;
using FrpBan.Configuration;
using FrpBan.Handlers;
using FrpBan.Models;
using FrpBan.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace FrpBan.Tests.Services;

public class BanExemptionTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "frp-ban-exemptions-" + Guid.NewGuid());

    private string BanFile
    {
        get
        {
            return Path.Combine(_directory, "bans.json");
        }
    }

    [Theory]
    [InlineData("192.0.2.1", "::ffff:192.0.2.1", 0)]
    [InlineData("192.0.2.0/24", "192.0.2.42", 60)]
    [InlineData("2001:db8::/32", "2001:0DB8::1", null)]
    public async Task ExemptRequest_DoesNotCreateOrPersistABan(string exemption, string address, int? duration)
    {
        await using (var service = CreateService([exemption]))
        {
            Assert.True(service.IsExempt(address));

            await service.BanAsync(address, "exempt", duration);

            Assert.False(service.IsBanned(address));
            Assert.Empty(service.GetActiveBans());
        }

        Assert.False(File.Exists(BanFile));
    }

    [Fact]
    public async Task ExemptRequests_DoNotConsumeCapacityOrFailWhenFull()
    {
        await using (var service = CreateService(["192.0.2.0/24"], capacity: 1))
        {
            await service.BanAsync("192.0.2.1", "exempt", 0);
            await service.BanAsync("198.51.100.1", "blocked", 0);
            await service.BanAsync("192.0.2.2", "exempt after capacity reached", 0);

            Assert.Equal("198.51.100.1", Assert.Single(service.GetActiveBans()).Ip);
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            {
                await service.BanAsync("198.51.100.2", "over capacity", 0);
            });
        }
    }

    [Fact]
    public async Task NoExemptions_PreservesExistingBanBehavior()
    {
        await using (var service = CreateService([]))
        {
            await service.BanAsync("127.0.0.1", "explicit localhost ban", 0);

            Assert.False(service.IsExempt("127.0.0.1"));
            Assert.True(service.IsBanned("::ffff:127.0.0.1"));
        }
    }

    [Fact]
    public async Task Exemption_DoesNotBypassInputValidation()
    {
        await using (var service = CreateService(["192.0.2.0/24"]))
        {
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            {
                await service.BanAsync("192.0.2.1", "test", -1);
            });
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            {
                await service.BanAsync("192.0.2.1", null!, 0);
            });
            await Assert.ThrowsAsync<ArgumentException>(async () =>
            {
                await service.BanAsync("192.0.2.1", new string('x', 1025), 0);
            });
            Assert.Empty(service.GetActiveBans());
        }
    }

    [Theory]
    [InlineData("192.0.2.0/24", "::ffff:192.0.2.42")]
    [InlineData("2001:db8::/32", "2001:0DB8::1")]
    public async Task Load_RemovesExemptBansFromStorageBeforeCapacityCheck(string exemption, string exemptIp)
    {
        await WriteBansAsync([
            new BanEntry("198.51.100.1", "keep", DateTimeOffset.UtcNow, null),
            new BanEntry(exemptIp, "old permanent ban", DateTimeOffset.UtcNow, null),
        ]);

        await using (var service = CreateService([exemption], capacity: 1))
        {
            service.Load();

            Assert.False(service.IsBanned(exemptIp));
            Assert.Equal("198.51.100.1", Assert.Single(service.GetActiveBans()).Ip);
        }

        var persisted = JsonSerializer.Deserialize<List<BanEntry>>(await File.ReadAllTextAsync(BanFile))!;
        Assert.Equal("198.51.100.1", Assert.Single(persisted).Ip);

        // Removing the exemption must not resurrect a ban that was already cleared.
        await using (var restored = CreateService([]))
        {
            restored.Load();
            Assert.False(restored.IsBanned(exemptIp));
            Assert.True(restored.IsBanned("198.51.100.1"));
        }
    }

    [Fact]
    public async Task Load_OnlyExemptBans_PersistsAnEmptyArray()
    {
        await WriteBansAsync([new BanEntry("192.0.2.1", "old ban", DateTimeOffset.UtcNow, null)]);

        await using (var service = CreateService(["192.0.2.1"]))
        {
            service.Load();
            Assert.Empty(service.GetActiveBans());
        }

        Assert.Empty(JsonSerializer.Deserialize<List<BanEntry>>(await File.ReadAllTextAsync(BanFile))!);
    }

    [Fact]
    public async Task Load_InvalidRecordAfterExemptBan_DoesNotRewriteCorruptedStorage()
    {
        await WriteBansAsync([
            new BanEntry("192.0.2.1", "exempt", DateTimeOffset.UtcNow, null),
            new BanEntry("not-an-ip", "corrupted", DateTimeOffset.UtcNow, null),
        ]);
        var original = await File.ReadAllTextAsync(BanFile);

        await using (var service = CreateService(["192.0.2.1"]))
        {
            Assert.Throws<InvalidDataException>(service.Load);
        }

        Assert.Equal(original, await File.ReadAllTextAsync(BanFile));
    }

    [Theory]
    [InlineData("Login", "client_address", "[::ffff:192.0.2.1]:1234")]
    [InlineData("NewUserConn", "remote_addr", "192.0.2.1:1234")]
    [InlineData("Login", "client_address", "[2001:db8::1]:1234")]
    [InlineData("NewUserConn", "remote_addr", "[2001:0DB8::1]:1234")]
    public async Task Callbacks_AllowExemptPersistedBansAndRejectOtherBans(string operation, string addressField,
        string exemptEndpoint)
    {
        await WriteBansAsync([
            new BanEntry("192.0.2.1", "old IPv4 ban", DateTimeOffset.UtcNow, null),
            new BanEntry("2001:db8::1", "old IPv6 ban", DateTimeOffset.UtcNow, null),
            new BanEntry("198.51.100.1", "blocked", DateTimeOffset.UtcNow, null),
        ]);
        await using (var service = CreateService(["192.0.2.0/24", "2001:db8::/32"]))
        {
            service.Load();
            var handler = new PluginRequestHandler(service, NullLogger<PluginRequestHandler>.Instance);

            var exemptRequest = new PluginRequest("0.1.0", operation,
                JsonSerializer.SerializeToElement(new Dictionary<string, string> { [addressField] = exemptEndpoint }));
            var bannedRequest = new PluginRequest("0.1.0", operation,
                JsonSerializer.SerializeToElement(new Dictionary<string, string> { [addressField] = "198.51.100.1:1234" }));

            Assert.False((await handler.HandleAsync(exemptRequest, new DefaultHttpContext())).Reject);
            Assert.True((await handler.HandleAsync(bannedRequest, new DefaultHttpContext())).Reject);
        }
    }

    private BanService CreateService(List<string> exemptions, int capacity = 100000)
    {
        return new BanService(Options.Create(new PluginSettings
        {
            BanFilePath = BanFile,
            ExemptAddresses = exemptions,
            MaxBanEntries = capacity,
        }), NullLogger<BanService>.Instance);
    }

    private async Task WriteBansAsync(BanEntry[] entries)
    {
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(BanFile, JsonSerializer.Serialize(entries));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}