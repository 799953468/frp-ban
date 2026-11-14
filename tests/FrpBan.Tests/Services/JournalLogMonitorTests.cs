using System.Diagnostics;
using System.Text;
using FrpBan.Client.Configuration;
using FrpBan.Client.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace FrpBan.Tests.Services;

public class JournalLogMonitorTests
{
    [Theory]
    [InlineData("sshd.service")]
    [InlineData("worker@instance.service")]
    [InlineData("--output=json")]
    [InlineData("ssh.service; touch /tmp/should-not-exist")]
    public void Command_FollowsOnlyNewMessagesAndKeepsServiceInOneArgument(string service)
    {
        var monitor = CreateMonitor(CreateRule(service: service));
        var command = monitor.CreateStartInfo();

        Assert.Equal("journalctl", command.FileName);
        Assert.False(command.UseShellExecute);
        Assert.True(command.RedirectStandardOutput);
        Assert.True(command.RedirectStandardError);
        Assert.Equal(Encoding.UTF8, command.StandardOutputEncoding);
        Assert.Equal(new[]
        {
            "--follow", "--lines=0", "--output=cat", "--no-pager", "--system", $"--unit={service}",
        }, command.ArgumentList);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void Command_RequiresService(string? service)
    {
        var monitor = CreateMonitor(CreateRule(service: service));
        Assert.Throws<InvalidOperationException>(() => monitor.CreateStartInfo());
    }

    [Fact]
    public async Task Output_MatchesRegexAndJsonAndPreservesDeliveryOrder()
    {
        var matches = new List<(string ip, int? duration, string reason)>();
        var monitor = CreateMonitor(CreateRule(), batch =>
        {
            matches.AddRange(batch);
            return Task.CompletedTask;
        });
        using (var reader = new ChunkedReader(
                   "Ignored\n攻击 192.0.2.1\r\n{\"ip\":\"2001:db8::1\"}\nFailed 192.0.2.2\n", 1))
        {
            await monitor.ProcessOutputAsync(reader, CancellationToken.None);
        }

        Assert.Equal(new[] { "192.0.2.1", "2001:db8::1", "192.0.2.2" }, matches.Select(match => match.ip));
        Assert.All(matches, match =>
        {
            Assert.Equal(120, match.duration);
            Assert.Equal("Journal test", match.reason);
        });
    }

    [Fact]
    public async Task Output_UsesExistingThresholdCounting()
    {
        var count = 0;
        var rule = CreateRule(action: new BanAction { Type = "threshold", MaxMatches = 2 });
        var monitor = CreateMonitor(rule, batch =>
        {
            count += batch.Count;
            return Task.CompletedTask;
        });
        using (var reader = new StringReader("Failed 192.0.2.1\nFailed 192.0.2.1\nFailed 192.0.2.1\n"))
        {
            await monitor.ProcessOutputAsync(reader, CancellationToken.None);
        }

        Assert.Equal(1, count);
    }

    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public async Task Output_BoundsPartialLinesAndRecoversAfterOversizedInput(string newline)
    {
        var matches = new List<string>();
        var monitor = CreateMonitor(CreateRule(), batch =>
        {
            matches.AddRange(batch.Select(match => match.ip));
            return Task.CompletedTask;
        });
        var prefix = "Failed 192.0.2.1 ";
        var maximumLine = prefix + new string('x', RuleMatchEngine.MaxLogLineLength - prefix.Length);
        using (var reader = new ChunkedReader(
                   maximumLine + newline + maximumLine + "x" + newline + "Failed 192.0.2.2" + newline, 13))
        {
            await monitor.ProcessOutputAsync(reader, CancellationToken.None);
        }

        Assert.Equal(new[] { "192.0.2.1", "192.0.2.2" }, matches);
    }

    [Fact]
    public async Task Output_DoesNotMatchTruncatedFinalMessage()
    {
        var matches = new List<string>();
        var monitor = CreateMonitor(CreateRule(), batch =>
        {
            matches.AddRange(batch.Select(match => match.ip));
            return Task.CompletedTask;
        });
        using (var reader = new StringReader("Failed 192.0.2.1"))
        {
            await monitor.ProcessOutputAsync(reader, CancellationToken.None);
        }

        Assert.Empty(matches);
    }

    [Fact]
    public async Task AlreadyCancelled_DoesNotStartAProcess()
    {
        using (var stopping = new CancellationTokenSource())
        {
            await stopping.CancelAsync();
            var monitor = CreateMonitor(CreateRule());
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => monitor.StartAsync(stopping.Token));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => monitor.MonitorProcessAsync(
                new ProcessStartInfo("does-not-exist"), stopping.Token));
        }
    }

    [Fact]
    public async Task UnsupportedPlatform_FailsExplicitly()
    {
        if (OperatingSystem.IsLinux())
        {
            return;
        }

        var monitor = CreateMonitor(CreateRule());
        await Assert.ThrowsAsync<PlatformNotSupportedException>(() => monitor.StartAsync(CancellationToken.None));
    }

    [Fact]
    public async Task MissingExecutable_ReportsActionableError()
    {
        var monitor = CreateMonitor(CreateRule());
        var command = monitor.CreateStartInfo();
        command.FileName = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "journalctl");
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            monitor.MonitorProcessAsync(command, CancellationToken.None));

        Assert.Contains("journalctl", error.Message);
        Assert.Contains("PATH", error.Message);
    }

    [UnixTheory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task ProcessExit_IsReportedWithDiagnosticsEvenForZeroExitCode(int exitCode)
    {
        var monitor = CreateMonitor(CreateRule());
        var command = ShellCommand($"printf 'Permission denied' >&2; exit {exitCode}");
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            monitor.MonitorProcessAsync(command, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Contains($"code {exitCode}", error.Message);
        Assert.Contains("Permission denied", error.Message);
    }

    [UnixFact]
    public async Task LargeStderr_IsDrainedWithoutBlockingStdout()
    {
        var matches = new List<string>();
        var monitor = CreateMonitor(CreateRule(), batch =>
        {
            matches.AddRange(batch.Select(match => match.ip));
            return Task.CompletedTask;
        });
        var command = ShellCommand("i=0; while [ \"$i\" -lt 10000 ]; do " +
                                   "printf 'diagnostic that fills a pipe buffer\\n' >&2; i=$((i+1)); done; " +
                                   "printf 'Failed 192.0.2.1\\n'; exit 1");
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            monitor.MonitorProcessAsync(command, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(new[] { "192.0.2.1" }, matches);
    }

    [UnixTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationOrDeliveryFailure_TerminatesTheFollower(bool failDelivery)
    {
        var pidPath = Path.Combine(Path.GetTempPath(), $"frp-ban-journal-{Guid.NewGuid():N}.pid");
        using (var stopping = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
        {
            var delivered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var monitor = CreateMonitor(CreateRule(), _ =>
            {
                delivered.TrySetResult();
                if (failDelivery)
                {
                    throw new InvalidDataException("Delivery failed");
                }

                return Task.CompletedTask;
            });
            var command = ShellCommand("printf '%s' \"$$\" > \"$1\"; printf 'Failed 192.0.2.1\\n'; exec sleep 60");
            command.ArgumentList.Add("journal-fixture");
            command.ArgumentList.Add(pidPath);
            var monitoring = monitor.MonitorProcessAsync(command, stopping.Token);
            try
            {
                await delivered.Task.WaitAsync(stopping.Token);
                var pid = int.Parse(await File.ReadAllTextAsync(pidPath, stopping.Token));
                if (failDelivery)
                {
                    var error = await Assert.ThrowsAsync<InvalidDataException>(() =>
                        monitoring.WaitAsync(TimeSpan.FromSeconds(5)));
                    Assert.Equal("Delivery failed", error.Message);
                }
                else
                {
                    await stopping.CancelAsync();
                    await monitoring.WaitAsync(TimeSpan.FromSeconds(5));
                }

                AssertProcessExited(pid);
            }
            finally
            {
                await stopping.CancelAsync();
                try
                {
                    await monitoring;
                }
                catch (InvalidDataException) when (failDelivery)
                {
                }

                File.Delete(pidPath);
            }
        }
    }

    private static void AssertProcessExited(int pid)
    {
        try
        {
            using (var process = Process.GetProcessById(pid))
            {
                Assert.True(process.HasExited);
            }
        }
        catch (ArgumentException)
        {
            // The operating system has already reaped the follower.
        }
    }

    private static ProcessStartInfo ShellCommand(string script)
    {
        var command = CreateMonitor(CreateRule()).CreateStartInfo();
        command.FileName = "/bin/sh";
        command.ArgumentList.Clear();
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add(script);
        return command;
    }

    private static JournalLogMonitor CreateMonitor(BanRule rule,
        Func<List<(string ip, int? durationSeconds, string reason)>, Task>? onMatches = null)
    {
        return new JournalLogMonitor(NullLogger.Instance, rule,
            new RuleMatchEngine(NullLogger<RuleMatchEngine>.Instance), onMatches ?? (_ => Task.CompletedTask));
    }

    private static BanRule CreateRule(string? service = "ssh.service", BanAction? action = null)
    {
        return new BanRule
        {
            Name = "journal-test",
            LogSource = new LogSource { Type = "journal", Service = service },
            Matching =
            [
                new MatchExpression { Pattern = @"(?:Failed|攻击) (?<ip>\S+)" },
                new MatchExpression { Type = "json", JsonPath = "ip" },
            ],
            Action = action ?? new BanAction { Type = "immediate", BanDurationSeconds = 120, Reason = "Journal test" },
        };
    }

    private sealed class ChunkedReader : StringReader
    {
        private readonly int _chunkSize;

        public ChunkedReader(string text, int chunkSize) : base(text)
        {
            _chunkSize = chunkSize;
        }

        public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken cancellationToken = default)
        {
            return base.ReadAsync(buffer[..Math.Min(buffer.Length, _chunkSize)], cancellationToken);
        }
    }

    public sealed class UnixFactAttribute : FactAttribute
    {
        public UnixFactAttribute()
        {
            if (OperatingSystem.IsWindows())
            {
                Skip = "The process fixture requires /bin/sh; journal monitoring itself requires Linux.";
            }
        }
    }

    public sealed class UnixTheoryAttribute : TheoryAttribute
    {
        public UnixTheoryAttribute()
        {
            if (OperatingSystem.IsWindows())
            {
                Skip = "The process fixture requires /bin/sh; journal monitoring itself requires Linux.";
            }
        }
    }
}