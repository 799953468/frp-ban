using System.Text.Json;
using FrpBan.Configuration;
using FrpBan.Models;
using FrpBan.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace FrpBan.Tests.Services;

public class BanServiceTests : IDisposable
{
    private readonly Mock<ILogger<BanService>> _loggerMock;
    private readonly IOptions<PluginSettings> _settings;
    private string _tempBanFile;

    public BanServiceTests()
    {
        _loggerMock = new Mock<ILogger<BanService>>();
        _tempBanFile = Path.Combine(Path.GetTempPath(), $"ban-{Guid.NewGuid()}.json");
        _settings = Options.Create(new PluginSettings
        {
            BanFilePath = _tempBanFile,
            DefaultBanDurationSeconds = 3600
        });
    }

    [Fact]
    public void IsBanned_WithNonExistentIp_ReturnsFalse()
    {
        // Arrange
        using var service = new BanService(_settings, _loggerMock.Object);

        // Act
        var result = service.IsBanned("192.168.1.1");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task BanAsync_AddsBanEntry()
    {
        // Arrange
        using var service = new BanService(_settings, _loggerMock.Object);
        var ip = "192.168.1.1";
        var reason = "Brute force attack";

        // Act
        await service.BanAsync(ip, reason, 3600);

        // Assert
        Assert.True(service.IsBanned(ip));
    }

    [Fact]
    public async Task BanAsync_WithPermanentBan_ExpiresAtIsNull()
    {
        // Arrange
        using var service = new BanService(_settings, _loggerMock.Object);
        var ip = "192.168.1.1";

        // Act
        await service.BanAsync(ip, "Permanent ban", durationSeconds: 0);
        var bans = service.GetActiveBans();

        // Assert
        var entry = bans.FirstOrDefault(b => b.Ip == ip);
        Assert.NotNull(entry);
        Assert.Null(entry.ExpiresAt);
    }

    [Fact]
    public async Task UnbanAsync_RemovesBanEntry()
    {
        // Arrange
        using var service = new BanService(_settings, _loggerMock.Object);
        var ip = "192.168.1.1";
        await service.BanAsync(ip, "Test ban", 3600);

        // Act
        await service.UnbanAsync(ip);

        // Assert
        Assert.False(service.IsBanned(ip));
    }

    [Fact]
    public async Task GetActiveBans_ReturnsOnlyActiveBans()
    {
        // Arrange
        using var service = new BanService(_settings, _loggerMock.Object);
        var ip1 = "192.168.1.1";
        var ip2 = "192.168.1.2";

        var expiredEntry = new BanEntry(ip2, "Expired ban", DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddSeconds(-1));
        await File.WriteAllTextAsync(_tempBanFile, JsonSerializer.Serialize(new[] { expiredEntry }));
        service.Load();
        await service.BanAsync(ip1, "Active ban", 3600);
        var bans = service.GetActiveBans();

        // Act & Assert - Should only have the active ban
        Assert.Single(bans);
        Assert.Equal(ip1, bans[0].Ip);
    }

    [Fact]
    public async Task BanAsync_WithSameIp_UpdatesExistingEntry()
    {
        // Arrange
        using var service = new BanService(_settings, _loggerMock.Object);
        var ip = "192.168.1.1";

        // Act
        await service.BanAsync(ip, "First reason", 3600);
        await service.BanAsync(ip, "Updated reason", 7200);
        var bans = service.GetActiveBans();

        // Assert
        var entry = bans.FirstOrDefault(b => b.Ip == ip);
        Assert.NotNull(entry);
        Assert.Equal("Updated reason", entry.Reason);
    }

    [Fact]
    public void Load_WithValidBanFile_LoadsBans()
    {
        // Arrange
        var bans = new List<BanEntry>
        {
            new BanEntry("192.168.1.1", "Test ban 1", DateTimeOffset.UtcNow, null),
            new BanEntry("192.168.1.2", "Test ban 2", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1))
        };

        var json = JsonSerializer.Serialize(bans, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_tempBanFile, json);

        using var service = new BanService(_settings, _loggerMock.Object);

        // Act
        service.Load();

        // Assert
        Assert.True(service.IsBanned("192.168.1.1"));
        Assert.True(service.IsBanned("192.168.1.2"));
    }

    [Fact]
    public void Load_WithNonExistentFile_DoesNotThrow()
    {
        // Arrange
        var settings = Options.Create(new PluginSettings
        {
            BanFilePath = "/tmp/nonexistent-file-" + Guid.NewGuid() + ".json",
            DefaultBanDurationSeconds = 3600
        });

        using var service = new BanService(settings, _loggerMock.Object);

        // Act & Assert
        service.Load(); // Should not throw
    }

    [Fact]
    public async Task BanAsync_ThreadSafety_MultipleBans()
    {
        // Arrange
        using var service = new BanService(_settings, _loggerMock.Object);
        var ips = Enumerable.Range(1, 100).Select(i => $"192.168.1.{i}").ToList();

        // Act
        var tasks = ips.Select(ip => service.BanAsync(ip, $"Ban {ip}", 3600)).ToList();
        await Task.WhenAll(tasks);

        // Assert
        var activeBans = service.GetActiveBans();
        Assert.Equal(100, activeBans.Count);
    }

    private void Dispose()
    {
        if (File.Exists(_tempBanFile))
            File.Delete(_tempBanFile);
    }

    void IDisposable.Dispose()
    {
        Dispose();
    }
}
