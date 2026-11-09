using System.Text.Json;
using FrpBan.Configuration;
using FrpBan.Models;
using FrpBan.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace FrpBan.Tests.Services;

public class BanPersistenceTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "frp-ban-tests-" + Guid.NewGuid());
    private string BanFile => Path.Combine(_directory, "bans.json");
    private BanService Create(int capacity = 100000) => new(Options.Create(new PluginSettings
    {
        BanFilePath = BanFile, MaxBanEntries = capacity,
    }), NullLogger<BanService>.Instance);

    [Fact]
    public async Task ConcurrentChanges_AreFullyFlushedAndReloadable()
    {
        var service = Create();
        await Parallel.ForEachAsync(Enumerable.Range(0, 500), async (i, _) =>
        {
            await service.BanAsync($"198.51.{i / 256}.{i % 256}", $"test-{i}", 0);
        });
        await service.DisposeAsync();
        await service.DisposeAsync();
        var entries = JsonSerializer.Deserialize<List<BanEntry>>(await File.ReadAllTextAsync(BanFile))!;
        Assert.Equal(500, entries.Count);
        await using var restored = Create();
        restored.Load();
        Assert.Equal(500, restored.GetActiveBans().Count);
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
    }

    [Theory]
    [InlineData("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1")]
    [InlineData("::ffff:192.0.2.1", "192.0.2.1")]
    public async Task CanonicalAddresses_CannotBypassBans(string input, string lookup)
    {
        await using var service = Create();
        await service.BanAsync(input, "test", 0);
        Assert.True(service.IsBanned(lookup));
        await service.UnbanAsync(lookup);
        Assert.False(service.IsBanned(input));
    }

    [Fact]
    public async Task InvalidInput_DoesNotCreateBans()
    {
        await using var service = Create();
        await Assert.ThrowsAsync<ArgumentException>(() => service.BanAsync("not-an-ip", "test"));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => service.BanAsync("192.0.2.1", "test", -1));
        Assert.Empty(service.GetActiveBans());
    }

    [Fact]
    public async Task Capacity_RejectsNewEntriesButAllowsRefreshingExistingBan()
    {
        await using var service = Create(capacity: 1);
        await service.BanAsync("192.0.2.1", "first");
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.BanAsync("192.0.2.2", "second"));
        await service.BanAsync("192.0.2.1", "updated");
        Assert.Equal("updated", Assert.Single(service.GetActiveBans()).Reason);
    }

    [Fact]
    public async Task CorruptedStorage_DoesNotSilentlyEraseProtection()
    {
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(BanFile, "{broken");
        await using var service = Create();
        Assert.Throws<JsonException>(() => service.Load());
        Assert.Equal("{broken", await File.ReadAllTextAsync(BanFile));
    }

    [Fact]
    public async Task NullDuration_UsesConfiguredDefault()
    {
        await using var service = Create();
        await service.BanAsync("192.0.2.1", "test", null);
        var entry = Assert.Single(service.GetActiveBans());
        Assert.Equal(TimeSpan.FromHours(1), entry.ExpiresAt - entry.BannedAt);
    }

    [Fact]
    public async Task FailedFinalFlush_IsReportedWithoutOverwritingOtherFiles()
    {
        Directory.CreateDirectory(_directory);
        var blocked = Path.Combine(_directory, "blocked");
        await File.WriteAllTextAsync(blocked, "unchanged");
        var service = new BanService(Options.Create(new PluginSettings
        {
            BanFilePath = Path.Combine(blocked, "bans.json"),
        }), NullLogger<BanService>.Instance);
        await service.BanAsync("192.0.2.1", "test");
        await Assert.ThrowsAsync<IOException>(() => service.DisposeAsync().AsTask());
        Assert.Equal("unchanged", await File.ReadAllTextAsync(blocked));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }
}
