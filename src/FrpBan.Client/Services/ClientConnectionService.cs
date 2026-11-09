using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FrpBan.Client.Configuration;
using FrpBan.Protocol;
using FrpBan.Protocol.Security;
using FrpBan.Protocol.Transport;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FrpBan.Client.Services;

/// <summary>Serializes TLS exchanges so health checks and bans cannot consume each other's replies.</summary>
public sealed class ClientConnectionService : IDisposable
{
    private readonly ClientSettings _settings;
    private readonly ILogger<ClientConnectionService> _logger;
    private readonly SemaphoreSlim _exchanges = new(1, 1);
    private readonly object _state = new();
    private readonly string _tokenHash;
    private SslStream? _sslStream;
    private TcpClient? _tcpClient;
    private volatile bool _isConnected;
    private int _reconnectAttempts;
    private int _currentDelayMs;
    private X509Certificate2? _clientCertificate;
    private X509Certificate2? _caCertificate;
    private uint _pingSequence;
    private int _disposed;

    /// <summary>Creates a connection manager with bounded request deadlines.</summary>
    public ClientConnectionService(IOptions<ClientSettings> settings, ILogger<ClientConnectionService> logger)
    {
        _settings = settings.Value;
        _logger = logger;
        _currentDelayMs = _settings.Reconnection.InitialDelayMs;
        _tokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(_settings.Token)));
    }

    /// <summary>Indicates whether the HELLO exchange completed successfully.</summary>
    public bool IsConnected => _isConnected;

    /// <summary>Connects, validates TLS, and authenticates within one deadline.</summary>
    public async Task<bool> ConnectAsync(CancellationToken cancellationToken)
    {
        await _exchanges.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            Disconnect();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(_settings.ConnectionTimeoutSeconds));
            if (!string.IsNullOrWhiteSpace(_settings.Tls.ClientCertificatePath))
                _clientCertificate ??= X509CertificateLoader.LoadPkcs12FromFile(
                    _settings.Tls.ClientCertificatePath, _settings.Tls.ClientCertificatePassword);
            if (!string.IsNullOrWhiteSpace(_settings.Tls.CaCertificatePath))
                _caCertificate ??= X509CertificateLoader.LoadCertificateFromFile(_settings.Tls.CaCertificatePath);

            var client = new TcpClient();
            lock (_state) { _tcpClient = client; }
            await client.ConnectAsync(_settings.ServerAddress, _settings.ServerPort, timeout.Token).ConfigureAwait(false);
            var stream = new SslStream(client.GetStream(), false, ValidateServerCertificate);
            lock (_state) { _sslStream = stream; }
            var certificates = new X509CertificateCollection();
            if (_clientCertificate is not null)
                certificates.Add(_clientCertificate);
            await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = _settings.ServerAddress,
                ClientCertificates = certificates,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            }, timeout.Token).ConfigureAwait(false);
            await stream.WriteAsync(new HelloMessage("1.0", "frp-ban-client", _tokenHash).Serialize(), timeout.Token)
                .ConfigureAwait(false);
            var reply = await MessageTransport.ReadAsync(stream, timeout.Token).ConfigureAwait(false);
            if (reply is not HelloMessage { Version: "1.0", ClientType: "server" })
                throw new InvalidDataException("Server rejected HELLO.");
            lock (_state)
            {
                if (!ReferenceEquals(_sslStream, stream))
                    return false;
                _isConnected = true;
            }
            _reconnectAttempts = 0;
            _currentDelayMs = _settings.Reconnection.InitialDelayMs;
            _logger.LogInformation("Authenticated with {Server}:{Port}", _settings.ServerAddress, _settings.ServerPort);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Disconnect();
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Connection or authentication failed");
            Disconnect();
            return false;
        }
        finally { _exchanges.Release(); }
    }

    /// <summary>Closes the current session; a pending exchange is interrupted safely.</summary>
    public void Disconnect()
    {
        lock (_state)
        {
            _isConnected = false;
            _sslStream?.Dispose();
            _tcpClient?.Dispose();
            _sslStream = null;
            _tcpClient = null;
        }
    }

    /// <summary>Sends a ban and waits for its corresponding response.</summary>
    public async Task<bool> SendBanRequestAsync(string ip, string? reason, int? durationSeconds,
        CancellationToken cancellationToken)
    {
        var response = await ExchangeAsync(new BanRequestMessage(ip, reason, durationSeconds), cancellationToken)
            .ConfigureAwait(false);
        if (response is BanResponseMessage ban)
        {
            if (!ban.Success)
                _logger.LogWarning("Ban request rejected: {Message}", ban.Message);
            return ban.Success;
        }
        return false;
    }

    /// <summary>Sends a health check and verifies the matching sequence number.</summary>
    public async Task<bool> SendPingAsync(CancellationToken cancellationToken)
    {
        var sequence = unchecked((uint)Interlocked.Increment(ref _pingSequence));
        return await ExchangeAsync(new PingMessage(sequence), cancellationToken).ConfigureAwait(false)
            is PongMessage pong && pong.SequenceNumber == sequence;
    }

    private async Task<Message?> ExchangeAsync(Message request, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(_settings.RequestTimeoutSeconds));
        // Include queue time in the deadline so callers cannot build an unbounded wait queue.
        var acquired = false;
        try
        {
            await _exchanges.WaitAsync(timeout.Token).ConfigureAwait(false);
            acquired = true;
            var stream = _sslStream;
            if (!_isConnected || stream is null)
                return null;
            await stream.WriteAsync(request.Serialize(), timeout.Token).ConfigureAwait(false);
            var response = await MessageTransport.ReadAsync(stream, timeout.Token).ConfigureAwait(false);
            if (response is BanResponseMessage && request is BanRequestMessage ||
                response is PongMessage pong && request is PingMessage ping && pong.SequenceNumber == ping.SequenceNumber)
                return response;
            throw new InvalidDataException("Unexpected server response.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (acquired) Disconnect();
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Protocol exchange failed");
            if (acquired) Disconnect();
            return null;
        }
        finally { if (acquired) _exchanges.Release(); }
    }

    /// <summary>Waits with capped exponential backoff; returns false when retries are exhausted.</summary>
    public async Task<bool> WaitBeforeRetryAsync(CancellationToken cancellationToken)
    {
        if (_settings.Reconnection.MaxRetries >= 0 && _reconnectAttempts >= _settings.Reconnection.MaxRetries)
        {
            _logger.LogError("Maximum reconnection attempts reached");
            return false;
        }
        _reconnectAttempts++;
        var delay = Math.Min(_currentDelayMs, _settings.Reconnection.MaxDelayMs);
        _logger.LogInformation("Reconnecting in {Delay}ms (attempt {Attempt})", delay, _reconnectAttempts);
        await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        _currentDelayMs = (int)Math.Min(_settings.Reconnection.MaxDelayMs,
            delay * _settings.Reconnection.BackoffMultiplier);
        return true;
    }

    private bool ValidateServerCertificate(object sender, X509Certificate? certificate,
        X509Chain? chain, SslPolicyErrors errors)
    {
        var environment = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") ??
                          Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        var development = string.Equals(environment, "Development", StringComparison.OrdinalIgnoreCase);
        if (!_settings.Tls.ValidateServerCertificate)
            return development && certificate is not null;
        if (_settings.Tls.AllowSelfSignedCertificates && development && _caCertificate is null &&
            certificate is not null && certificate.Subject == certificate.Issuer)
        {
            using var authority = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
            return CertificateTrust.Validate(certificate, chain, errors, authority, serverCertificate: true);
        }
        return CertificateTrust.Validate(certificate, chain, errors, _caCertificate, serverCertificate: true);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        Disconnect();
        _clientCertificate?.Dispose();
        _caCertificate?.Dispose();
        _exchanges.Dispose();
    }
}
