using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FrpBan.Configuration;
using FrpBan.Protocol;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FrpBan.Services;

/// <summary>
/// TCP server service that listens for client connections over TLS.
/// Implements binary protocol for ban requests and responses.
/// </summary>
public sealed class TcpServerService : IHostedService
{
    private readonly ILogger<TcpServerService> _logger;
    private readonly IOptions<PluginSettings> _settings;
    private readonly IBanService _banService;
    private readonly IAccessLogService _accessLog;
    private TcpListener? _listener;
    private CancellationTokenSource? _cancellationTokenSource;
    private Task? _listenerTask;
    private X509Certificate2? _serverCertificate;
    private X509Certificate2? _caCertificate;

    public TcpServerService(
        ILogger<TcpServerService> logger,
        IOptions<PluginSettings> settings,
        IBanService banService,
        IAccessLogService accessLog)
    {
        _logger = logger;
        _settings = settings;
        _banService = banService;
        _accessLog = accessLog;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var tls = _settings.Value.Tls;
        if (tls?.Enabled != true || !tls.TcpListenerEnabled)
        {
            _logger.LogInformation("TLS TCP listener is disabled");
            return;
        }

        try
        {
            // Load server certificate
            if (string.IsNullOrWhiteSpace(tls.CertificatePath))
                throw new InvalidOperationException("TLS is enabled but CertificatePath is not specified");

            _serverCertificate = LoadCertificate(tls.CertificatePath, tls.CertificatePassword, tls.KeyPath);
            _logger.LogInformation("Loaded server certificate from {Path}", tls.CertificatePath);

            // Load CA certificate if mTLS is required
            if (tls.RequireClientCertificate && !string.IsNullOrWhiteSpace(tls.ClientCertificateAuthority))
            {
                _caCertificate = X509CertificateLoader.LoadCertificateFromFile(tls.ClientCertificateAuthority);
                _logger.LogInformation("Loaded CA certificate from {Path}", tls.ClientCertificateAuthority);
            }

            // Start listening
            _listener = new TcpListener(IPAddress.Any, tls.Port);
            _listener.Start();
            _logger.LogInformation("TCP listener started on port {Port}", tls.Port);

            _cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _listenerTask = ListenForConnectionsAsync(_cancellationTokenSource.Token);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start TCP server");
            throw;
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _cancellationTokenSource?.Cancel();
        if (_listenerTask != null)
        {
            try
            {
                await _listenerTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected
            }
        }
        _listener?.Stop();
        _logger.LogInformation("TCP listener stopped");
    }

    private async Task ListenForConnectionsAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var client = await _listener!.AcceptTcpClientAsync(cancellationToken);
                _logger.LogDebug("Client connected from {RemoteAddress}", client.Client.RemoteEndPoint);

                // Handle each client connection in the background
                _ = HandleClientAsync(client, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error accepting client connection");
            }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        var remoteAddress = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
        try
        {
            using (client)
            using (var networkStream = client.GetStream())
            {
                // Upgrade to TLS
                var sslStream = new SslStream(networkStream, leaveInnerStreamOpen: false);

                var serverCertCollection = new X509Certificate2Collection { _serverCertificate! };

                // Configure TLS options
                var sslOptions = new SslServerAuthenticationOptions
                {
                    ServerCertificateContext = SslStreamCertificateContext.Create(_serverCertificate!, serverCertCollection),
                    ClientCertificateRequired = _settings.Value.Tls?.RequireClientCertificate ?? false,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                };

                await sslStream.AuthenticateAsServerAsync(sslOptions, cancellationToken);
                _logger.LogDebug("TLS handshake completed with {RemoteAddress}", remoteAddress);

                // Handle protocol messages
                await HandleProtocolAsync(sslStream, remoteAddress, cancellationToken);
            }
        }
        catch (AuthenticationException ex)
        {
            _logger.LogWarning(ex, "TLS authentication failed with {RemoteAddress}", remoteAddress);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling client {RemoteAddress}", remoteAddress);
        }
    }

    private async Task HandleProtocolAsync(SslStream sslStream, string remoteAddress, CancellationToken cancellationToken)
    {
        var isAuthenticated = false;
        var buffer = new byte[16384];
        var receiveBuffer = new byte[0];

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                // Read from stream
                int bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                if (bytesRead == 0)
                {
                    _logger.LogDebug("Client {RemoteAddress} disconnected", remoteAddress);
                    break;
                }

                // Append to receive buffer
                Array.Resize(ref receiveBuffer, receiveBuffer.Length + bytesRead);
                Buffer.BlockCopy(buffer, 0, receiveBuffer, receiveBuffer.Length - bytesRead, bytesRead);

                // Process complete messages
                int offset = 0;
                while (offset < receiveBuffer.Length)
                {
                    var (message, bytesConsumed) = Message.Deserialize(receiveBuffer, offset);
                    if (message == null)
                        break; // Incomplete message, wait for more data

                    offset += bytesConsumed;

                    var response = await HandleMessageAsync(message, remoteAddress, isAuthenticated, cancellationToken);
                    if (message is HelloMessage)
                        isAuthenticated = response != null && response is not ErrorMessage;

                    if (response != null)
                    {
                        var responseBytes = response.Serialize();
                        await sslStream.WriteAsync(responseBytes, 0, responseBytes.Length, cancellationToken);
                    }

                    if (response is ErrorMessage errorMsg && errorMsg.ErrorText.Contains("token"))
                        break; // Disconnect on token error
                }

                // Remove processed bytes from buffer
                if (offset > 0)
                {
                    Array.Copy(receiveBuffer, offset, receiveBuffer, 0, receiveBuffer.Length - offset);
                    Array.Resize(ref receiveBuffer, receiveBuffer.Length - offset);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected during shutdown
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Protocol error with {RemoteAddress}", remoteAddress);
        }
    }

    private async Task<Message?> HandleMessageAsync(
        Message message,
        string remoteAddress,
        bool isAuthenticated,
        CancellationToken cancellationToken)
    {
        return message switch
        {
            HelloMessage hello => HandleHello(hello, remoteAddress),
            BanRequestMessage banReq when isAuthenticated => await HandleBanRequestAsync(banReq, remoteAddress, cancellationToken),
            PingMessage ping => new PongMessage(ping.SequenceNumber),
            _ when !isAuthenticated => new ErrorMessage("Not authenticated. Send HELLO first."),
            _ => new ErrorMessage($"Unexpected message type: {message.Type}"),
        };
    }

    private Message HandleHello(HelloMessage hello, string remoteAddress)
    {
        _logger.LogDebug("HELLO from {RemoteAddress}: version={Version}, type={ClientType}",
            remoteAddress, hello.Version, hello.ClientType);

        // Verify token hash
        var tokenHash = ComputeTokenHash(_settings.Value.Token);
        if (tokenHash != hello.TokenHash)
        {
            _logger.LogWarning("Invalid token hash from {RemoteAddress}", remoteAddress);
            _accessLog.LogUnauthorized(remoteAddress, "/tls", "HELLO");
            return new ErrorMessage("Invalid token");
        }

        _logger.LogInformation("Client {RemoteAddress} authenticated", remoteAddress);
        return new HelloMessage("1.0", "server", tokenHash);
    }

    private async Task<Message> HandleBanRequestAsync(
        BanRequestMessage banReq,
        string remoteAddress,
        CancellationToken cancellationToken)
    {
        _logger.LogDebug("BAN_REQUEST from {RemoteAddress}: IP={Ip}, Reason={Reason}",
            remoteAddress, banReq.Ip, banReq.Reason);

        try
        {
            // Validate IP
            if (string.IsNullOrWhiteSpace(banReq.Ip) || !System.Net.IPAddress.TryParse(banReq.Ip, out _))
            {
                return new BanResponseMessage(false, "Invalid IP address");
            }

            // Ban the IP
            var reason = banReq.Reason ?? "client request";
            await _banService.BanAsync(banReq.Ip, reason, banReq.DurationSeconds);

            _accessLog.LogBanAction(remoteAddress, "BAN", banReq.Ip);
            _logger.LogInformation("Banned {Ip} from {RemoteAddress}", banReq.Ip, remoteAddress);

            return new BanResponseMessage(true, $"Banned {banReq.Ip}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing ban request from {RemoteAddress}", remoteAddress);
            return new BanResponseMessage(false, ex.Message);
        }
    }

    private X509Certificate2 LoadCertificate(string certPath, string? password, string? keyPath)
    {
        if (certPath.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase))
        {
            return string.IsNullOrWhiteSpace(password)
                ? X509CertificateLoader.LoadPkcs12FromFile(certPath, null)
                : X509CertificateLoader.LoadPkcs12FromFile(certPath, password);
        }
        else if (certPath.EndsWith(".pem", StringComparison.OrdinalIgnoreCase) ||
                 certPath.EndsWith(".crt", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(keyPath))
                throw new InvalidOperationException("KeyPath is required for PEM certificates");
            return X509Certificate2.CreateFromPemFile(certPath, keyPath);
        }
        else
        {
            throw new InvalidOperationException($"Unsupported certificate format: {certPath}");
        }
    }

    private string ComputeTokenHash(string token)
    {
        using (var sha256 = SHA256.Create())
        {
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToHexString(hash);
        }
    }
}
