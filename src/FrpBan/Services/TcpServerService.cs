using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FrpBan.Configuration;
using FrpBan.Protocol;
using FrpBan.Protocol.Security;
using FrpBan.Protocol.Transport;
using FrpBan.Security;
using Microsoft.Extensions.Options;

namespace FrpBan.Services;

/// <summary>Hosts bounded TLS sessions with mandatory token authentication and per-IP limits.</summary>
public sealed class TcpServerService : IHostedService, IDisposable, IAsyncDisposable
{
    private readonly ILogger<TcpServerService> _logger;
    private readonly PluginSettings _settings;
    private readonly IBanService _banService;
    private readonly SemaphoreSlim _connectionSlots;
    private readonly IpRateLimiter _connectionLimiter;
    private readonly IpRateLimiter _messageLimiter;
    private readonly byte[] _tokenHash;
    // Only the accept loop mutates this set. Stop waits for that loop first.
    private readonly HashSet<Task> _connections = [];
    private readonly CancellationTokenSource _stopping = new();
    private TcpListener? _listener;
    private Task? _listenerTask;
    private X509Certificate2? _serverCertificate;
    private X509Certificate2? _caCertificate;
    private SslStreamCertificateContext? _certificateContext;
    private readonly object _lifecycle = new();
    private Task? _stopTask;
    private Task? _disposeTask;

    internal IPEndPoint? LocalEndpoint => _listener?.LocalEndpoint as IPEndPoint;

    /// <summary>Creates a server using the configured connection and message limits.</summary>
    public TcpServerService(ILogger<TcpServerService> logger, IOptions<PluginSettings> settings,
        IBanService banService)
    {
        _logger = logger;
        _settings = settings.Value;
        _banService = banService;
        var tls = _settings.Tls ?? new TlsSettings();
        _connectionSlots = new SemaphoreSlim(tls.MaxConcurrentConnections);
        _connectionLimiter = new IpRateLimiter(tls.MaxConnectionsPerMinute);
        _messageLimiter = new IpRateLimiter(tls.MaxMessagesPerMinute);
        _tokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(_settings.Token));
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var tls = _settings.Tls;
        if (tls?.Enabled != true || !tls.TcpListenerEnabled)
            return Task.CompletedTask;

        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(tls.CertificatePath))
            throw new InvalidOperationException("TLS requires CertificatePath.");

        _serverCertificate = LoadCertificate(tls.CertificatePath, tls.CertificatePassword, tls.KeyPath);
        if (!_serverCertificate.HasPrivateKey)
            throw new InvalidOperationException("The server certificate must include its private key.");
        if (tls.RequireClientCertificate && !string.IsNullOrWhiteSpace(tls.ClientCertificateAuthority))
            _caCertificate = X509CertificateLoader.LoadCertificateFromFile(tls.ClientCertificateAuthority);

        _certificateContext = SslStreamCertificateContext.Create(_serverCertificate, null);
        _listener = new TcpListener(IPAddress.Any, tls.Port);
        _listener.Start();
        _listenerTask = ListenForConnectionsAsync(_stopping.Token);
        _logger.LogInformation("TLS listener started on port {Port}, limit {Limit}",
            tls.Port, tls.MaxConcurrentConnections);
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken)
    {
        lock (_lifecycle)
            return (_stopTask ??= StopCoreAsync()).WaitAsync(cancellationToken);
    }

    private async Task StopCoreAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        _listener?.Stop();
        if (_listenerTask is not null)
            await _listenerTask.ConfigureAwait(false);
        await Task.WhenAll(_connections).ConfigureAwait(false);
        _logger.LogInformation("TLS listener stopped");
    }

    private async Task ListenForConnectionsAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener!.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (cancellationToken.IsCancellationRequested &&
                                       ex is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                break;
            }
            catch (SocketException ex)
            {
                _logger.LogWarning(ex, "Transient error accepting a TLS connection");
                try { await Task.Delay(1000, cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
                continue;
            }

            var address = IpAddressUtilities.Normalize(
                ((IPEndPoint?)client.Client.RemoteEndPoint)?.Address.ToString()) ?? "unknown";
            if (!_connectionLimiter.TryAcquire(address) || !_connectionSlots.Wait(0))
            {
                client.Dispose();
                continue;
            }
            _connections.RemoveWhere(task => task.IsCompleted);
            _connections.Add(HandleClientAsync(client, address, cancellationToken));
        }
    }

    private async Task HandleClientAsync(TcpClient client, string address, CancellationToken cancellationToken)
    {
        using (client)
        {
            try
            {
                using var stream = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
                var tls = _settings.Tls!;
                using var handshake = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                handshake.CancelAfter(TimeSpan.FromSeconds(tls.HandshakeTimeoutSeconds));
                var options = new SslServerAuthenticationOptions
                {
                    ServerCertificateContext = _certificateContext,
                    ClientCertificateRequired = tls.RequireClientCertificate,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                };
                if (tls.RequireClientCertificate)
                    options.RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
                        CertificateTrust.Validate(certificate, chain, errors, _caCertificate, serverCertificate: false);
                await stream.AuthenticateAsServerAsync(options, handshake.Token).ConfigureAwait(false);

                var first = await MessageTransport.ReadAsync(stream, handshake.Token).ConfigureAwait(false);
                if (first is not HelloMessage hello || hello.Version != "1.0" || !ValidateToken(hello.TokenHash))
                {
                    await WriteAsync(stream, new ErrorMessage("Invalid handshake or token"), cancellationToken);
                    return;
                }
                if (!_messageLimiter.TryAcquire(address))
                    return;
                // TLS authenticates the server. Do not echo a reusable credential back to the peer.
                await WriteAsync(stream, new HelloMessage("1.0", "server", ""), cancellationToken);

                while (!cancellationToken.IsCancellationRequested)
                {
                    using var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    readTimeout.CancelAfter(TimeSpan.FromSeconds(tls.IdleTimeoutSeconds));
                    var message = await MessageTransport.ReadAsync(stream, readTimeout.Token).ConfigureAwait(false);
                    if (message is null)
                        break;
                    if (!_messageLimiter.TryAcquire(address))
                    {
                        await WriteAsync(stream, new ErrorMessage("Message rate limit exceeded"), cancellationToken);
                        break;
                    }
                    var response = message switch
                    {
                        PingMessage ping => new PongMessage(ping.SequenceNumber) as Message,
                        BanRequestMessage ban => await HandleBanRequestAsync(ban).ConfigureAwait(false),
                        _ => new ErrorMessage("Unexpected message type"),
                    };
                    await WriteAsync(stream, response, cancellationToken).ConfigureAwait(false);
                    if (response is ErrorMessage)
                        break;
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) when (ex is AuthenticationException or IOException or
                                       System.Text.Json.JsonException or InvalidOperationException or
                                       ArgumentException or KeyNotFoundException)
            {
                _logger.LogDebug(ex, "Rejected or disconnected TLS peer {Address}", address);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "TLS session failed for {Address}", address);
            }
            finally
            {
                _connectionSlots.Release();
            }
        }
    }

    private bool ValidateToken(string? tokenHash)
    {
        if (tokenHash is not { Length: 64 })
            return false;
        try
        {
            return CryptographicOperations.FixedTimeEquals(_tokenHash, Convert.FromHexString(tokenHash));
        }
        catch (FormatException) { return false; }
    }

    private async Task<Message> HandleBanRequestAsync(BanRequestMessage request)
    {
        if (IpAddressUtilities.Normalize(request.Ip) is null || request.DurationSeconds is < 0)
        {
            return new BanResponseMessage(false, "Invalid IP address or duration");
        }

        if (request.Reason?.Length > 1024)
        {
            return new BanResponseMessage(false, "Reason exceeds 1024 characters");
        }

        try
        {
            if (_banService.IsExempt(request.Ip))
            {
                return new BanResponseMessage(false, $"IP {request.Ip} is exempt from bans");
            }

            await _banService.BanAsync(request.Ip, request.Reason ?? "client request", request.DurationSeconds)
                .ConfigureAwait(false);
            return new BanResponseMessage(true, $"Banned {request.Ip}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to ban {Ip}", request.Ip);
            return new BanResponseMessage(false, "Unable to apply ban");
        }
    }

    private async Task WriteAsync(SslStream stream, Message message, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(_settings.Tls!.WriteTimeoutSeconds));
        await stream.WriteAsync(message.Serialize(), timeout.Token).ConfigureAwait(false);
    }

    private static X509Certificate2 LoadCertificate(string path, string? password, string? keyPath)
    {
        if (path.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".p12", StringComparison.OrdinalIgnoreCase))
            return X509CertificateLoader.LoadPkcs12FromFile(path, password);
        if (string.IsNullOrWhiteSpace(keyPath))
            throw new InvalidOperationException("PEM certificates require KeyPath.");
        return X509Certificate2.CreateFromPemFile(path, keyPath);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    /// <summary>Drains every active session before disposing certificates and connection slots.</summary>
    public ValueTask DisposeAsync()
    {
        lock (_lifecycle)
            return new ValueTask(_disposeTask ??= DisposeCoreAsync());
    }

    private async Task DisposeCoreAsync()
    {
        await StopAsync(CancellationToken.None).ConfigureAwait(false);
        _serverCertificate?.Dispose();
        _caCertificate?.Dispose();
        _stopping.Dispose();
        _connectionSlots.Dispose();
    }
}