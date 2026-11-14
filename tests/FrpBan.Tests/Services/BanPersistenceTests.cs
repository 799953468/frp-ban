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

    private string BanFile
    {
        get
        {
            return Path.Combine(_directory, "bans.json");
        }
    }

    private BanService Create(int capacity = 100000)
    {
        return new BanService(Options.Create(new PluginSettings
        {
            BanFilePath = BanFile,
            MaxBanEntries = capacity,
        }), NullLogger<BanService>.Instance);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3600)]
    public async Task BanAsync_CompletesOnlyAfterBanCanBeReloaded(int durationSeconds)
    {
        await using (var service = Create())
        {
            await service.BanAsync("192.0.2.1", "Persisted before acknowledgment", durationSeconds);
            var expected = Assert.Single(service.GetActiveBans());

            // Do not dispose the original store: shutdown must not be needed to save a successful request.
            await using (var restored = Create())
            {
                restored.Load();
                Assert.True(restored.IsBanned(expected.Ip));
                Assert.Equal(expected, Assert.Single(restored.GetActiveBans()));
            }
        }
    }

    [Fact]
    public async Task DuplicateBan_WaitsForPendingPersistence()
    {
        await using (var service = Create())
        {
            var first = service.BanAsync("192.0.2.1", "Original permanent ban", 0);
            var duplicate = service.BanAsync("192.0.2.1", "Shorter duplicate", 3600);
            await duplicate;

            await using (var restored = Create())
            {
                restored.Load();
                Assert.Equal("Original permanent ban", Assert.Single(restored.GetActiveBans()).Reason);
            }

            await first;
        }
    }

    [Fact]
    public async Task UnbanAsync_CompletesOnlyAfterRemovalCanBeReloaded()
    {
        await using (var service = Create())
        {
            await service.BanAsync("192.0.2.1", "Remove this ban", 0);
            await service.UnbanAsync("192.0.2.1");

            Assert.Empty(JsonSerializer.Deserialize<List<BanEntry>>(await File.ReadAllTextAsync(BanFile))!);
            await using (var restored = Create())
            {
                restored.Load();
                Assert.False(restored.IsBanned("192.0.2.1"));
            }
        }
    }

    [Fact]
    public async Task FailedBanPersistence_IsReportedAndDuplicateRequestRetries()
    {
        Directory.CreateDirectory(BanFile);
        await using (var service = Create())
        {
            await Assert.ThrowsAsync<IOException>(() => service.BanAsync("192.0.2.1", "Keep protection", 0));
            Assert.True(service.IsBanned("192.0.2.1"));
            Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));

            Directory.Delete(BanFile);
            await service.BanAsync("192.0.2.1", "Retry", 3600);
            await using (var restored = Create())
            {
                restored.Load();
                Assert.Equal("Keep protection", Assert.Single(restored.GetActiveBans()).Reason);
            }
        }
    }

    [Fact]
    public async Task FailedUnbanPersistence_IsReportedAndRepeatedRemovalRetries()
    {
        await using (var service = Create())
        {
            await service.BanAsync("192.0.2.1", "Original", 0);
            var original = await File.ReadAllTextAsync(BanFile);
            var backup = Path.Combine(_directory, "previous.json");
            File.Move(BanFile, backup);
            Directory.CreateDirectory(BanFile);

            await Assert.ThrowsAsync<IOException>(() => service.UnbanAsync("192.0.2.1"));
            Assert.False(service.IsBanned("192.0.2.1"));
            Assert.Equal(original, await File.ReadAllTextAsync(backup));

            Directory.Delete(BanFile);
            File.Move(backup, BanFile);
            await service.UnbanAsync("192.0.2.1");
            await using (var restored = Create())
            {
                restored.Load();
                Assert.Empty(restored.GetActiveBans());
            }
        }
    }

    [Fact]
    public async Task ConcurrentChanges_AreFullyFlushedAndReloadable()
    {
        await using (var service = Create())
        {
            await Parallel.ForEachAsync(Enumerable.Range(0, 500), async (i, _) =>
            {
                await service.BanAsync($"198.51.{i / 256}.{i % 256}", $"test-{i}", 0);
            });
            var entries = JsonSerializer.Deserialize<List<BanEntry>>(await File.ReadAllTextAsync(BanFile))!;
            Assert.Equal(500, entries.Count);
            await using (var restored = Create())
            {
                restored.Load();
                Assert.Equal(500, restored.GetActiveBans().Count);
            }

            Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
        }
    }

    [Fact]
    public async Task Shutdown_DrainsPendingRequestsAndCanBeRepeated()
    {
        var service = Create();
        var pending = new List<Task>();
        for (var index = 0; index < 100; index++)
        {
            pending.Add(service.BanAsync($"192.0.2.{index}", "Pending at shutdown", 0));
        }

        await service.DisposeAsync();
        await Task.WhenAll(pending).WaitAsync(TimeSpan.FromSeconds(10));
        await service.DisposeAsync();

        await using (var restored = Create())
        {
            restored.Load();
            Assert.Equal(100, restored.GetActiveBans().Count);
        }
    }

    [Fact]
    public async Task Load_RestoresOriginalExpiryAndSkipsExpiredBans()
    {
        var now = DateTimeOffset.UtcNow;
        var permanent = new BanEntry("192.0.2.1", "Permanent", now.AddDays(-1), null);
        var temporary = new BanEntry("2001:db8::1", "Temporary", now.AddMinutes(-30), now.AddMinutes(30));
        var expired = new BanEntry("192.0.2.2", "Expired while stopped", now.AddHours(-2), now.AddHours(-1));
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(BanFile, JsonSerializer.Serialize(new[] { permanent, temporary, expired }));

        await using (var restored = Create())
        {
            restored.Load();
            Assert.Equal(2, restored.GetActiveBans().Count);
            Assert.Contains(permanent, restored.GetActiveBans());
            Assert.Contains(temporary, restored.GetActiveBans());
            Assert.False(restored.IsBanned(expired.Ip));
        }
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
        await Assert.ThrowsAsync<IOException>(() => service.BanAsync("192.0.2.1", "test"));
        await Assert.ThrowsAsync<IOException>(() => service.DisposeAsync().AsTask());
        Assert.Equal("unchanged", await File.ReadAllTextAsync(blocked));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}