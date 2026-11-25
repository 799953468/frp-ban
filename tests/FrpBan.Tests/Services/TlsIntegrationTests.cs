using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FrpBan.Client.Configuration;
using FrpBan.Client.Services;
using FrpBan.Configuration;
using FrpBan.Protocol;
using FrpBan.Protocol.Transport;
using FrpBan.Services;
using FrpBan.Tests.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace FrpBan.Tests.Services;

public class TlsIntegrationTests : IAsyncLifetime
{
    private const string Token = "test-secret-with-at-least-32-characters";
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "frp-ban-tls-" + Guid.NewGuid());
    private readonly Mock<IBanService> _bans = new();
    private readonly List<TcpServerService> _servers = [];
    private TcpServerService _server = null!;
    private string AuthorityPath => Path.Combine(_directory, "ca.crt");

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);
        using var authority = TestCertificates.CreateAuthority();
        using var certificate = TestCertificates.CreateLeaf(authority);
        using var client = TestCertificates.CreateLeaf(authority, server: false);
        using var otherAuthority = TestCertificates.CreateAuthority();
        using var otherClient = TestCertificates.CreateLeaf(otherAuthority, server: false);
        await File.WriteAllBytesAsync(AuthorityPath, authority.Export(X509ContentType.Cert));
        await File.WriteAllBytesAsync(Path.Combine(_directory, "server.pfx"), certificate.Export(X509ContentType.Pfx));
        await File.WriteAllBytesAsync(Path.Combine(_directory, "client.pfx"), client.Export(X509ContentType.Pfx));
        await File.WriteAllBytesAsync(Path.Combine(_directory, "other.pfx"), otherClient.Export(X509ContentType.Pfx));
        _bans.Setup(service => service.BanAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>()))
            .ReturnsAsync(BanStatus.Applied);
        _server = await StartServerAsync();
    }

    private async Task<TcpServerService> StartServerAsync(bool mutualTls = false, int maxMessages = 120,
        IBanService? bans = null, ILogger<TcpServerService>? logger = null)
    {
        var server = new TcpServerService(logger ?? NullLogger<TcpServerService>.Instance, Options.Create(new PluginSettings
        {
            Token = Token,
            Tls = new TlsSettings
            {
                Enabled = true, Port = 0, CertificatePath = Path.Combine(_directory, "server.pfx"),
                RequireClientCertificate = mutualTls, ClientCertificateAuthority = AuthorityPath,
                HandshakeTimeoutSeconds = 2, MaxMessagesPerMinute = maxMessages,
            },
        }), bans ?? _bans.Object);
        _servers.Add(server);
        await server.StartAsync(CancellationToken.None);
        return server;
    }

    private ClientConnectionService CreateClient(TcpServerService? server = null, string token = Token, string? certificate = null) =>
        new(Options.Create(new ClientSettings
        {
            ServerAddress = "127.0.0.1", ServerPort = (server ?? _server).LocalEndpoint!.Port, Token = token,
            Tls = new ClientTlsSettings
            {
                CaCertificatePath = AuthorityPath,
                ClientCertificatePath = certificate is null ? null : Path.Combine(_directory, certificate),
            },
        }), NullLogger<ClientConnectionService>.Instance);

    [Fact]
    public async Task ClientCertificate_IsOptionalWhenMutualTlsIsDisabled()
    {
        using var client = CreateClient();
        Assert.True(await client.ConnectAsync(CancellationToken.None));
        Assert.True(await SendBanAsync(client, "192.0.2.1", null, null, CancellationToken.None));
        Assert.True(await client.SendPingAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ConcurrentBansAndPings_ReceiveTheirOwnReplies()
    {
        using var client = CreateClient();
        Assert.True(await client.ConnectAsync(CancellationToken.None));
        var exchanges = Enumerable.Range(0, 20).SelectMany(i => new[]
        {
            SendBanAsync(client, $"192.0.2.{i}", "test", 60, CancellationToken.None),
            client.SendPingAsync(CancellationToken.None),
        });
        Assert.All(await Task.WhenAll(exchanges), Assert.True);
        _bans.Verify(service => service.BanAsync(It.IsAny<string>(), "test", 60), Times.Exactly(20));
    }

    [Fact]
    public async Task InvalidToken_IsRejected()
    {
        using var client = CreateClient(token: "wrong-secret-with-at-least-32-characters");
        Assert.False(await client.ConnectAsync(CancellationToken.None));
        Assert.False(client.IsConnected);
    }

    [Fact]
    public async Task NegativeDuration_IsRejectedBeforeChangingStorage()
    {
        await using var store = new BanService(Options.Create(new PluginSettings
        {
            BanFilePath = Path.Combine(_directory, "bans.json"),
        }), NullLogger<BanService>.Instance);
        var server = await StartServerAsync(bans: store);
        using var client = CreateClient(server);
        Assert.True(await client.ConnectAsync(CancellationToken.None));
        Assert.Equal(BanStatus.Invalid,
            await client.SendBanRequestAsync(new BanRequestMessage("192.0.2.1", "test", -1), CancellationToken.None));
        Assert.Empty(store.GetActiveBans());
        Assert.False(File.Exists(Path.Combine(_directory, "bans.json")));
    }

    [Fact]
    public async Task StorageFailure_IsRetriedUntilTheBanIsDurable()
    {
        var attempts = 0;
        _bans.Setup(service => service.BanAsync("192.0.2.18", "retry", 60))
            .Returns(() => Interlocked.Increment(ref attempts) == 1
                ? Task.FromException<BanStatus>(new IOException("disk full"))
                : Task.FromResult(BanStatus.Applied));
        using var client = CreateClient();
        using var stopping = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Assert.True(await client.ConnectAsync(stopping.Token));
        var delivery = new BanDeliveryService(client,
            Options.Create(new ClientSettings { Reconnection = new ReconnectionSettings { InitialDelayMs = 10 } }),
            NullLogger<BanDeliveryService>.Instance);
        await delivery.EnqueueAsync(new BanMatch("192.0.2.18", 60, "retry"), stopping.Token);
        var worker = delivery.RunAsync(stopping.Token);
        try
        {
            while (Volatile.Read(ref attempts) < 2)
            {
                await Task.Delay(10, stopping.Token);
            }

            Assert.True(client.IsConnected);
        }
        finally
        {
            await stopping.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => worker);
        }
    }

    private static async Task<bool> SendBanAsync(ClientConnectionService client, string ip, string? reason,
        int? durationSeconds, CancellationToken cancellationToken) =>
        (await client.SendBanRequestAsync(new BanRequestMessage(ip, reason, durationSeconds), cancellationToken))
        ?.IsSuccess() == true;

    [Theory]
    [InlineData(0)]
    [InlineData(7200)]
    public async Task ShorterBanRequest_OverTlsPreservesExistingProtection(int originalDuration)
    {
        await using var store = new BanService(Options.Create(new PluginSettings
        {
            BanFilePath = Path.Combine(_directory, "bans.json"),
        }), NullLogger<BanService>.Instance);
        _bans.Setup(service => service.BanAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>()))
            .Returns((string ip, string reason, int? duration) =>
            {
                return store.BanAsync(ip, reason, duration);
            });
        using var client = CreateClient();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        Assert.True(await client.ConnectAsync(deadline.Token));
        Assert.True(await SendBanAsync(client, "192.0.2.10", "Original stronger ban", originalDuration,
            deadline.Token));
        var original = Assert.Single(store.GetActiveBans());

        Assert.True(await SendBanAsync(client, "::ffff:192.0.2.10", "Weaker request", 1, deadline.Token));

        Assert.Equal(original, Assert.Single(store.GetActiveBans()));
    }

    [Fact]
    public async Task ExemptBan_ReturnsExplicitRejectionAndKeepsTlsSessionUsable()
    {
        await using (var store = new BanService(Options.Create(new PluginSettings
                     {
                         BanFilePath = Path.Combine(_directory, "bans.json"),
                         ExemptAddresses = ["192.0.2.0/24"],
                     }), NullLogger<BanService>.Instance))
        {
            var server = await StartServerAsync(bans: store);
            using (var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            using (var client = new TcpClient())
            {
                await client.ConnectAsync("127.0.0.1", server.LocalEndpoint!.Port, deadline.Token);
                using (var tls = new SslStream(client.GetStream(), false, (_, _, _, _) => { return true; }))
                {
                    await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = "localhost",
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    }, deadline.Token);
                    var hello = new HelloMessage(ProtocolConstants.Version, "client",
                        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Token))));
                    await tls.WriteAsync(hello.Serialize(), deadline.Token);
                    Assert.IsType<HelloMessage>(await MessageTransport.ReadAsync(tls, deadline.Token));

                    var exemptRequest = new BanRequestMessage("::ffff:192.0.2.1", "exempt", 0);
                    await tls.WriteAsync(exemptRequest.Serialize(), deadline.Token);
                    var rejection = Assert.IsType<BanResponseMessage>(await MessageTransport.ReadAsync(tls, deadline.Token));

                    Assert.False(rejection.Success);
                    Assert.Equal("IP ::ffff:192.0.2.1 is exempt from bans", rejection.Message);
                    Assert.Empty(store.GetActiveBans());

                    var otherRequest = new BanRequestMessage("198.51.100.1", "blocked", 0);
                    await tls.WriteAsync(otherRequest.Serialize(), deadline.Token);
                    var accepted = Assert.IsType<BanResponseMessage>(await MessageTransport.ReadAsync(tls, deadline.Token));

                    Assert.True(accepted.Success);
                    Assert.Equal("198.51.100.1", Assert.Single(store.GetActiveBans()).Ip);
                }
            }
        }
    }

    [Fact]
    public async Task ExemptBan_DoesNotBlockQueuedNonExemptBan()
    {
        await using (var store = new BanService(Options.Create(new PluginSettings
                     {
                         BanFilePath = Path.Combine(_directory, "bans.json"),
                         ExemptAddresses = ["192.0.2.0/24"],
                     }), NullLogger<BanService>.Instance))
        {
            var server = await StartServerAsync(bans: store);
            using (var client = CreateClient(server))
            using (var stopping = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            {
                Assert.True(await client.ConnectAsync(stopping.Token));
                var delivery = new BanDeliveryService(client, Options.Create(new ClientSettings()),
                    NullLogger<BanDeliveryService>.Instance);
                await delivery.EnqueueAsync(new BanMatch("::ffff:192.0.2.1", 0, "exempt"), stopping.Token);
                await delivery.EnqueueAsync(new BanMatch("198.51.100.1", 0, "blocked"), stopping.Token);
                var worker = delivery.RunAsync(stopping.Token);
                try
                {
                    while (!store.IsBanned("198.51.100.1"))
                    {
                        await Task.Delay(10, stopping.Token);
                    }

                    Assert.True(client.IsConnected);
                    Assert.True(await client.SendPingAsync(stopping.Token));
                    Assert.False(store.IsBanned("192.0.2.1"));
                    Assert.Equal("198.51.100.1", Assert.Single(store.GetActiveBans()).Ip);
                }
                finally
                {
                    await stopping.CancelAsync();
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                    {
                        await worker;
                    });
                }
            }
        }
    }

    [Fact]
    public async Task PendingBan_IsDeliveredWhenConnectionBecomesAvailable()
    {
        using var client = CreateClient();
        using var stopping = new CancellationTokenSource();
        var delivered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _bans.Setup(service => service.BanAsync("192.0.2.17", "queued", 60))
            .Returns(() => { delivered.TrySetResult(); return Task.FromResult(BanStatus.Applied); });
        var delivery = new BanDeliveryService(client, Options.Create(new ClientSettings()),
            NullLogger<BanDeliveryService>.Instance);
        var worker = delivery.RunAsync(stopping.Token);
        try
        {
            await delivery.EnqueueAsync(new BanMatch("192.0.2.17", 60, "queued"), stopping.Token);
            Assert.False(delivered.Task.IsCompleted);
            Assert.True(await client.ConnectAsync(stopping.Token));
            await delivered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally
        {
            await stopping.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => worker);
        }
    }

    [Theory]
    [InlineData("client.pfx", true)]
    [InlineData("other.pfx", false)]
    [InlineData(null, false)]
    public async Task MutualTls_EnforcesConfiguredClientAuthority(string? certificate, bool expected)
    {
        var server = await StartServerAsync(mutualTls: true);
        using var client = CreateClient(server, certificate: certificate);
        Assert.Equal(expected, await client.ConnectAsync(CancellationToken.None));
    }

    [Fact]
    public async Task RateLimit_AppliesToMessagesOnAnExistingConnection()
    {
        var server = await StartServerAsync(maxMessages: 2);
        using var client = CreateClient(server);
        Assert.True(await client.ConnectAsync(CancellationToken.None));
        Assert.True(await client.SendPingAsync(CancellationToken.None));
        Assert.False(await SendBanAsync(client, "192.0.2.1", "test", 60, CancellationToken.None));
        _bans.Verify(service => service.BanAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>()), Times.Never);
    }

    [Fact]
    public async Task InvalidHello_ClosesSessionBeforePipelinedBan()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _server.LocalEndpoint!.Port, deadline.Token);
        using var tls = new SslStream(client.GetStream(), false, (_, _, _, _) => true);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost", EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        }, deadline.Token);
        var hello = new HelloMessage(ProtocolConstants.Version, "client", Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("wrong"))));
        var payload = hello.Serialize().Concat(new BanRequestMessage("192.0.2.1", "test", 60).Serialize()).ToArray();
        await tls.WriteAsync(payload, deadline.Token);
        Assert.IsType<ErrorMessage>(await MessageTransport.ReadAsync(tls, deadline.Token));
        Assert.Null(await MessageTransport.ReadAsync(tls, deadline.Token));
        _bans.Verify(service => service.BanAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>()), Times.Never);
    }

    [Fact]
    public async Task PreviousProtocolVersion_IsRejectedEvenWithValidToken()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var client = new TcpClient();
        await using var tls = await OpenRawTlsAsync(client, "127.0.0.1", deadline.Token);
        var hello = new HelloMessage("1.0", ProtocolConstants.ClientClientType,
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Token))));
        await tls.WriteAsync(hello.Serialize(), deadline.Token);
        Assert.IsType<ErrorMessage>(await MessageTransport.ReadAsync(tls, deadline.Token));
    }

    [Fact]
    public async Task UnknownFrameType_DisconnectsWithoutLoggingAnError()
    {
        var logger = new Mock<ILogger<TcpServerService>>();
        logger.Setup(log => log.IsEnabled(It.IsAny<LogLevel>())).Returns(true);
        var server = await StartServerAsync(logger: logger.Object);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", server.LocalEndpoint!.Port, deadline.Token);
        await using var tls = new SslStream(client.GetStream(), false, (_, _, _, _) => true);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost", EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        }, deadline.Token);
        await tls.WriteAsync(new byte[] { 0x7F, 0, 0, 0, 0 }, deadline.Token);
        Assert.Equal(0, await tls.ReadAsync(new byte[1], deadline.Token));
        logger.Verify(log => log.Log(LogLevel.Error, It.IsAny<EventId>(), It.IsAny<It.IsAnyType>(),
            It.IsAny<Exception?>(), It.IsAny<Func<It.IsAnyType, Exception?, string>>()), Times.Never);
    }

    [Fact]
    public async Task DefaultListener_AcceptsIPv6Clients()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var client = new TcpClient(System.Net.Sockets.AddressFamily.InterNetworkV6);
        await using var tls = await OpenRawTlsAsync(client, "::1", deadline.Token);
        var hello = new HelloMessage(ProtocolConstants.Version, ProtocolConstants.ClientClientType,
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Token))));
        await tls.WriteAsync(hello.Serialize(), deadline.Token);
        Assert.IsType<HelloMessage>(await MessageTransport.ReadAsync(tls, deadline.Token));
    }

    private async Task<SslStream> OpenRawTlsAsync(TcpClient client, string host, CancellationToken cancellationToken)
    {
        await client.ConnectAsync(host, _server.LocalEndpoint!.Port, cancellationToken);
        var tls = new SslStream(client.GetStream(), false, (_, _, _, _) => true);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost", EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        }, cancellationToken);
        return tls;
    }

    [Fact]
    public async Task SlowUnauthenticatedPeer_IsDisconnectedByHandshakeDeadline()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _server.LocalEndpoint!.Port, deadline.Token);
        Assert.Equal(0, await client.GetStream().ReadAsync(new byte[1], deadline.Token));
    }

    public async Task DisposeAsync()
    {
        foreach (var server in _servers)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await server.StopAsync(timeout.Token);
            server.Dispose();
        }
        Directory.Delete(_directory, recursive: true);
    }
}