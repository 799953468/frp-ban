using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FrpBan.Client.Configuration;
using FrpBan.Protocol;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FrpBan.Client.Services;

/// <summary>
/// Manages TLS connection to frp-ban server with auto-reconnect capability.
/// Implements binary protocol for communication.
/// </summary>
public sealed class ClientConnectionService
{
    private readonly ClientSettings _settings;
    private readonly ILogger<ClientConnectionService> _logger;
    private SslStream? _sslStream;
    private TcpClient? _tcpClient;
    private bool _isConnected;
    private int _reconnectAttempts;
    private int _currentDelayMs;
    private X509Certificate2? _clientCertificate;
    private X509Certificate2? _caCertificate;
    private uint _pingSequence;

    public ClientConnectionService(IOptions<ClientSettings> settings, ILogger<ClientConnectionService> logger)
    {
        _settings = settings.Value;
        _logger = logger;
        _isConnected = false;
        _reconnectAttempts = 0;
        _currentDelayMs = _settings.Reconnection.InitialDelayMs;
        _pingSequence = 0;
    }

    public bool IsConnected => _isConnected;

    /// <summary>
    /// Connects to the server with TLS handshake.
    /// </summary>
    public async Task<bool> ConnectAsync(CancellationToken cancellationToken)
    {
        try
        {
            // Load certificates
            if (_clientCertificate == null)
                _clientCertificate = LoadClientCertificate();
            if (_caCertificate == null && _settings.Tls.CaCertificatePath != null)
                _caCertificate = X509CertificateLoader.LoadCertificateFromFile(_settings.Tls.CaCertificatePath);

            // Connect TCP
            _tcpClient = new TcpClient();
            await _tcpClient.ConnectAsync(_settings.ServerAddress, _settings.ServerPort, cancellationToken);
            _logger.LogInformation("Connected to {Server}:{Port}", _settings.ServerAddress, _settings.ServerPort);

            // Upgrade to TLS
            var networkStream = _tcpClient.GetStream();

            // For client, we can use a RemoteCertificateValidationCallback in SslStream
            var sslStream = new SslStream(
                networkStream,
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: ValidateServerCertificate
            );

            var clientCertCollection = new X509CertificateCollection();
            if (_clientCertificate != null)
                clientCertCollection.Add(_clientCertificate);

            var sslOptions = new SslClientAuthenticationOptions
            {
                ClientCertificates = clientCertCollection,
                TargetHost = _settings.ServerAddress,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            };

            await sslStream.AuthenticateAsClientAsync(sslOptions, cancellationToken);
            _sslStream = sslStream;
            _logger.LogInformation("TLS handshake completed");

            // Send HELLO
            var tokenHash = ComputeTokenHash(_settings.Token);
            var hello = new HelloMessage("1.0", "frp-ban-client", tokenHash);
            var helloBytes = hello.Serialize();
            await _sslStream.WriteAsync(helloBytes, 0, helloBytes.Length, cancellationToken);
            _logger.LogDebug("Sent HELLO handshake");

            // Receive HELLO response
            var buffer = new byte[1024];
            int bytesRead = await _sslStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
            if (bytesRead > 0)
            {
                var (response, _) = Message.Deserialize(buffer, 0);
                if (response is HelloMessage && !(response is ErrorMessage))
                {
                    _isConnected = true;
                    _reconnectAttempts = 0;
                    _currentDelayMs = _settings.Reconnection.InitialDelayMs;
                    _logger.LogInformation("Successfully authenticated with server");
                    return true;
                }
            }

            _logger.LogError("Invalid HELLO response from server");
            Disconnect();
            return false;
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Connection attempt cancelled");
            Disconnect();
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Connection attempt failed");
            Disconnect();
            return false;
        }
    }

    /// <summary>
    /// Disconnects from the server.
    /// </summary>
    public void Disconnect()
    {
        _isConnected = false;
        _sslStream?.Dispose();
        _tcpClient?.Dispose();
        _sslStream = null;
        _tcpClient = null;
        _logger.LogDebug("Disconnected from server");
    }

    /// <summary>
    /// Sends a ban request to the server.
    /// </summary>
    public async Task<bool> SendBanRequestAsync(string ip, string? reason, int? durationSeconds, CancellationToken cancellationToken)
    {
        if (!_isConnected || _sslStream == null)
        {
            _logger.LogWarning("Cannot send ban request: not connected");
            return false;
        }

        try
        {
            var banReq = new BanRequestMessage(ip, reason, durationSeconds);
            var banReqBytes = banReq.Serialize();
            await _sslStream.WriteAsync(banReqBytes, 0, banReqBytes.Length, cancellationToken);
            _logger.LogDebug("Sent BAN_REQUEST: IP={Ip}", ip);

            // Read response
            var buffer = new byte[1024];
            int bytesRead = await _sslStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
            if (bytesRead > 0)
            {
                var (response, _) = Message.Deserialize(buffer, 0);
                if (response is BanResponseMessage banResp)
                {
                    if (banResp.Success)
                    {
                        _logger.LogInformation("Ban request successful: {Message}", banResp.Message);
                        return true;
                    }
                    else
                    {
                        _logger.LogWarning("Ban request failed: {Message}", banResp.Message);
                        return false;
                    }
                }
            }

            _logger.LogError("Invalid response to ban request");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending ban request");
            _isConnected = false;
            return false;
        }
    }

    /// <summary>
    /// Sends a PING health check message.
    /// </summary>
    public async Task<bool> SendPingAsync(CancellationToken cancellationToken)
    {
        if (!_isConnected || _sslStream == null)
            return false;

        try
        {
            _pingSequence++;
            var ping = new PingMessage(_pingSequence);
            var pingBytes = ping.Serialize();
            await _sslStream.WriteAsync(pingBytes, 0, pingBytes.Length, cancellationToken);

            // Read PONG response
            var buffer = new byte[256];
            int bytesRead = await _sslStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
            if (bytesRead > 0)
            {
                var (response, _) = Message.Deserialize(buffer, 0);
                if (response is PongMessage pong && pong.SequenceNumber == _pingSequence)
                {
                    _logger.LogDebug("Received PONG with sequence {Seq}", pong.SequenceNumber);
                    return true;
                }
            }

            _logger.LogWarning("No PONG response");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Health check failed");
            _isConnected = false;
            return false;
        }
    }

    /// <summary>
    /// Waits before retrying connection, with exponential backoff.
    /// </summary>
    public async Task WaitBeforeRetryAsync(CancellationToken cancellationToken)
    {
        var maxRetries = _settings.Reconnection.MaxRetries;
        if (maxRetries >= 0 && _reconnectAttempts >= maxRetries)
        {
            _logger.LogError("Maximum reconnection attempts reached ({Attempts}), giving up", maxRetries);
            return;
        }

        _reconnectAttempts++;
        var delayMs = Math.Min(_currentDelayMs, _settings.Reconnection.MaxDelayMs);
        _logger.LogInformation("Reconnecting in {Delay}ms (attempt {Attempt})", delayMs, _reconnectAttempts);

        try
        {
            await Task.Delay(delayMs, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // Expected during shutdown
        }

        // Increase delay for next attempt
        _currentDelayMs = (int)(_currentDelayMs * _settings.Reconnection.BackoffMultiplier);
    }

    private bool ValidateServerCertificate(
        object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors)
    {
        if (!_settings.Tls.ValidateServerCertificate)
        {
            _logger.LogWarning("Server certificate validation disabled (development mode)");
            return true;
        }

        if (certificate == null)
        {
            _logger.LogError("Server did not provide certificate");
            return false;
        }

        // If self-signed certificates are allowed
        if (_settings.Tls.AllowSelfSignedCertificates &&
            sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
        {
            _logger.LogWarning("Accepting self-signed server certificate: {Subject}", certificate.Subject);
            return true;
        }

        // Validate against CA if provided
        if (_caCertificate != null && chain != null)
        {
            chain.ChainPolicy.ExtraStore.Add(_caCertificate);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            if (chain.Build(new X509Certificate2(certificate)))
            {
                _logger.LogInformation("Server certificate validated against CA");
                return true;
            }
        }

        // Standard validation
        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            _logger.LogInformation("Server certificate validated");
            return true;
        }

        _logger.LogError("Server certificate validation failed: {Errors}", sslPolicyErrors);
        return false;
    }

    private X509Certificate2 LoadClientCertificate()
    {
        var certPath = _settings.Tls.ClientCertificatePath;
        if (string.IsNullOrWhiteSpace(certPath))
            throw new InvalidOperationException("Client certificate path is not configured");

        if (!certPath.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Only .pfx certificates are supported");

        var cert = string.IsNullOrWhiteSpace(_settings.Tls.ClientCertificatePassword)
            ? X509CertificateLoader.LoadPkcs12FromFile(certPath, null)
            : X509CertificateLoader.LoadPkcs12FromFile(certPath, _settings.Tls.ClientCertificatePassword);

        _logger.LogInformation("Loaded client certificate from {Path}", certPath);
        return cert;
    }

    private string ComputeTokenHash(string token)
    {
        using (var sha256 = SHA256.Create())
        {
            var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(token));
            return Convert.ToHexString(hash);
        }
    }
}
