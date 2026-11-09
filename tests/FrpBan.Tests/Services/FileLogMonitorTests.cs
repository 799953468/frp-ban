using System.Threading.Channels;
using FrpBan.Client.Configuration;
using FrpBan.Client.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace FrpBan.Tests.Services;

public class FileLogMonitorTests
{
    [Fact]
    public async Task PartialLines_AreRetainedAndUnchangedSizeDoesNotReplay()
    {
        await using var monitor = await MonitorFixture.CreateAsync();
        await File.AppendAllTextAsync(monitor.Path, "Failed 192.0.2.9\nFailed 192.0.");
        Assert.Equal("192.0.2.9", await monitor.NextAsync());
        await File.AppendAllTextAsync(monitor.Path, "2.1\n");
        Assert.Equal("192.0.2.1", await monitor.NextAsync());
        File.SetLastWriteTimeUtc(monitor.Path, DateTime.UtcNow.AddSeconds(1));
        await Task.Delay(200);
        Assert.False(monitor.Matches.Reader.TryRead(out _));
    }

    [Fact]
    public async Task RenameRotation_ReadsReplacementFromTheBeginning()
    {
        await using var monitor = await MonitorFixture.CreateAsync();
        await File.AppendAllTextAsync(monitor.Path, "Failed 192.0.2.1\n");
        Assert.Equal("192.0.2.1", await monitor.NextAsync());
        File.Move(monitor.Path, monitor.Path + ".1");
        await File.WriteAllTextAsync(monitor.Path, "Failed 192.0.2.2\n");
        Assert.Equal("192.0.2.2", await monitor.NextAsync());
    }

    [Fact]
    public async Task CopyTruncation_ReadsTheNewContent()
    {
        await using var monitor = await MonitorFixture.CreateAsync();
        await File.AppendAllTextAsync(monitor.Path, "Failed 192.0.2.1\n");
        Assert.Equal("192.0.2.1", await monitor.NextAsync());
        await File.WriteAllTextAsync(monitor.Path, "Failed 192.0.2.2\n");
        Assert.Equal("192.0.2.2", await monitor.NextAsync());
    }

    [Fact]
    public async Task OversizedLine_IsSkippedWithoutLosingTheNextLine()
    {
        await using var monitor = await MonitorFixture.CreateAsync();
        await File.AppendAllTextAsync(monitor.Path, new string('x', RuleMatchEngine.MaxLogLineLength + 1) +
            "\nFailed 192.0.2.1\n");
        Assert.Equal("192.0.2.1", await monitor.NextAsync());
        Assert.False(monitor.Matches.Reader.TryRead(out _));
    }

    [Fact]
    public async Task Utf8Character_SplitAcrossAppendsIsPreserved()
    {
        await using var monitor = await MonitorFixture.CreateAsync(@"(?:Failed|攻击) (?<ip>\S+)");
        var bytes = System.Text.Encoding.UTF8.GetBytes("Failed 192.0.2.9\n攻击 192.0.2.1\n");
        var split = System.Text.Encoding.UTF8.GetByteCount("Failed 192.0.2.9\n") + 1;
        await using (var stream = new FileStream(monitor.Path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
            await stream.WriteAsync(bytes.AsMemory(0, split));
        Assert.Equal("192.0.2.9", await monitor.NextAsync());
        await using (var stream = new FileStream(monitor.Path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
            await stream.WriteAsync(bytes.AsMemory(split));
        Assert.Equal("192.0.2.1", await monitor.NextAsync());
    }

    private sealed class MonitorFixture : IAsyncDisposable
    {
        private readonly string _directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "frp-ban-log-" + Guid.NewGuid());
        private readonly CancellationTokenSource _stopping = new();
        private Task _task = Task.CompletedTask;
        public string Path => System.IO.Path.Combine(_directory, "auth.log");
        public Channel<string> Matches { get; } = Channel.CreateUnbounded<string>();

        public static async Task<MonitorFixture> CreateAsync(string pattern = @"Failed (?<ip>\S+)")
        {
            var fixture = new MonitorFixture();
            Directory.CreateDirectory(fixture._directory);
            await File.WriteAllTextAsync(fixture.Path, "ignored historical line\n");
            var rule = new BanRule
            {
                LogSource = new LogSource { Path = fixture.Path },
                Matching = [new MatchExpression { Pattern = pattern }],
                Action = new BanAction { Type = "immediate" },
            };
            var monitor = new FileLogMonitor(NullLogger.Instance, rule,
                new RuleMatchEngine(NullLogger<RuleMatchEngine>.Instance), matches =>
                {
                    foreach (var match in matches) fixture.Matches.Writer.TryWrite(match.ip);
                    return Task.CompletedTask;
                });
            fixture._task = monitor.StartAsync(fixture._stopping.Token);
            return fixture;
        }

        public async Task<string> NextAsync()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            return await Matches.Reader.ReadAsync(deadline.Token);
        }

        public async ValueTask DisposeAsync()
        {
            await _stopping.CancelAsync();
            await _task;
            _stopping.Dispose();
            Directory.Delete(_directory, recursive: true);
        }
    }
}
