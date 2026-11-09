# frp-ban

High-performance security plugin for [frps](https://github.com/fatedier/frp) that blocks banned IP addresses using a TLS-encrypted custom TCP protocol for distributed IP ban management.

## Features

- ✅ **Frp Plugin Integration** — Intercepts banned IPs at frps Login/NewUserConn stage
- ✅ **TLS Encrypted Communication** — Binary protocol + TLS 1.2/1.3 between server and clients
- ✅ **Rule Engine** — Client monitors log files and triggers bans automatically based on regex patterns
- ✅ **High Performance** — ConcurrentDictionary lookup, pooled bounded frames, cached regexes, event-driven log tailing
- ✅ **Production Hardened** — Bounded connections and queues, per-IP connection/message limits, handshake deadlines

---

## Architecture

```
 CLIENT MACHINE (FrpBan.Client)          FRP SERVER
 ┌──────────────────────────────┐       ┌──────────────────────────────────┐
 │ frpc                          │       │ frps (:7000)                     │
 │   │                           │       │   │ plugin callbacks              │
 │   ▼ frp tunnel                │◄─────►│   ▼                               │
 │ services (SSH, web, ...)      │       │ FrpBan (:9000 HTTP, :9443 TLS)  │
 │                               │       │   POST /handler  (Login/NewUser)  │
 │ FrpBan.Client                 │       │                                   │
 │  ├─ Log monitors (rules.d/)   │       │ BanService (ConcurrentDict)      │
 │  │   FileSystemWatcher        │       │   ├─ IsBanned() O(1) lookup      │
 │  │   rule matching engine     │       │   └─ Auto-expire expired bans    │
 │  ▼                            │       │                                   │
 │  TLS client ──────────────────┼──────►│ TCP server (:9443)               │
 │    auto-reconnect             │       │   ├─ TLS 1.2/1.3 only            │
 │    health check (ping/pong)   │       │   ├─ Connection + message limits  │
 │    exponential backoff        │       │   └─ Connection pool (max 100)   │
 └──────────────────────────────┘       └──────────────────────────────────┘
```

**Workflow:**
1. frps calls FrpBan's `POST /handler` before each `Login` and `NewUserConn` operation
2. FrpBan checks in-memory ban list, rejects banned IPs from establishing tunnels
3. Client FrpBan.Client monitors log files, sends ban requests via TLS connection when attack patterns match
4. Server receives ban requests, updates memory and persistent storage, blocks that IP from subsequent connections

---

## Project Structure

```
src/
├── FrpBan.Protocol/          # Shared binary protocol library
│   ├── Message.cs            # Bounded message framing (max 64 KiB body)
│   ├── Messages/             # Individual wire message types
│   ├── Transport/            # Exact asynchronous frame reads
│   ├── Security/             # Shared TLS trust validation
│   └── MessageType.cs        # Protocol message types
├── FrpBan/                   # Server application
│   ├── Services/
│   │   ├── BanService.cs     # ConcurrentDictionary-based ban storage
│   │   └── TcpServerService.cs  # TLS server + rate limiting
│   ├── Endpoints/            # HTTP mapping and pre-body authorization
│   ├── Security/             # Cached callback networks and bounded rate limits
│   ├── Handlers/
│   │   └── PluginRequestHandler.cs  # frps plugin handler
│   └── Configuration/
│       └── PluginSettings.cs
└── FrpBan.Client/            # Client application
    ├── Services/
    │   ├── ClientConnectionService.cs  # Auto-reconnect TLS client
    │   ├── BanDeliveryService.cs # Bounded retry queue for disconnected clients
    │   ├── FileLogMonitor.cs  # Serialized, bounded UTF-8 log tailing
    │   ├── RuleMatchEngine.cs # Regex pattern matching engine
    │   └── RulesLoader.cs     # YAML rule configuration loader
    └── rules.d/               # Ban rule definitions (YAML)

tests/FrpBan.Tests/            # Unit, security and loopback integration tests
Directory.Build.props         # Shared build properties
Directory.Packages.props      # Central NuGet package versions
```

---

## Security Features

### ✅ Implemented Protections

- **TLS rate limiting**: 10 new connections and 120 protocol messages/minute per IP (configurable)
- **Connection pooling**: Max 100 concurrent TLS connections (configurable)
- **Bounded input**: 64 KiB protocol/HTTP body limit, 64 Ki-character log-line limit
- **TLS 1.2/1.3 only**: Disabled outdated protocols
- **CIDR validation**: Validated prefix lengths (0-32 for IPv4, 0-128 for IPv6)
- **Production TLS enforcement**: Cannot disable certificate validation in production
- **Atomic persistence**: One coalescing writer and same-directory atomic file replacement

---

## Configuration

### Server (`src/FrpBan/appsettings.json`)

```json
{
  "PluginSettings": {
    "Token": "CHANGE_ME_TO_A_LONG_RANDOM_SECRET",
    "BanFilePath": "/var/lib/frp-ban/bans.json",
    "AppLogPath": "/var/log/frp-ban/frp-ban-.log",
    "AllowedPluginAddresses": ["127.0.0.1", "::1", "192.168.1.0/24"],
    "DefaultBanDurationSeconds": 3600,
    "Tls": {
      "Enabled": true,
      "TcpListenerEnabled": true,
      "Port": 9443,
      "CertificatePath": "/etc/frp-ban/certs/server.pfx",
      "CertificatePassword": "your-cert-password",
      "RequireClientCertificate": false
    }
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "urls": "http://127.0.0.1:9000"
}
```

| Key | Description |
|-----|-------------|
| `Token` | TLS client authentication token (use env var `PluginSettings__Token` in production) |
| `BanFilePath` | JSON file path for persistent ban storage |
| `AppLogPath` | Serilog log file path (auto-rotated) |
| `AllowedPluginAddresses` | IPs/CIDR allowed to call `/handler` (frps localhost), empty = allow all |
| `DefaultBanDurationSeconds` | Default ban duration (seconds), `0` = permanent |
| `Tls.Enabled` | Enable TLS TCP listener |
| `Tls.Port` | TLS listener port (default: 9443) |
| `Logging.LogLevel.Default` | Minimum log level: Debug, Information, Warning, Error |

**Production configuration:**
```bash
# Use environment variables for secrets
export PluginSettings__Token="$(openssl rand -base64 32)"
export PluginSettings__Tls__CertificatePassword="$(cat /etc/frp-ban/certs/password.txt)"
```

Startup rejects placeholder tokens and secrets shorter than 32 characters. HTTP
callbacks bind to loopback by default; configure the listener and trusted callback
addresses explicitly if frps runs on another host. Ban durations use `null` for
the configured default and `0` for a permanent ban.

TLS deadlines and limits are configured under `PluginSettings.Tls`:
`MaxConcurrentConnections` (100), `MaxConnectionsPerMinute` (10),
`MaxMessagesPerMinute` (120), `HandshakeTimeoutSeconds` (10),
`IdleTimeoutSeconds` (90), and `WriteTimeoutSeconds` (10).

### Client (`src/FrpBan.Client/appsettings.json`)

```json
{
  "ClientSettings": {
    "ServerAddress": "frps.example.com",
    "ServerPort": 9443,
    "Token": "CHANGE_ME_TO_A_LONG_RANDOM_SECRET",
    "RulesPath": "./rules.d",
    "Tls": {
      "ValidateServerCertificate": true,
      "AllowSelfSignedCertificates": false,
      "ClientCertificatePath": null,
      "ClientCertificatePassword": null,
      "CaCertificatePath": null
    },
    "Reconnection": {
      "InitialDelayMs": 5000,
      "MaxDelayMs": 300000,
      "BackoffMultiplier": 2.0,
      "MaxRetries": -1,
      "HealthCheckIntervalMs": 30000
    }
  }
}
```

Client certificates are optional unless the server requires mTLS. Configure
`CaCertificatePath` for a private CA; otherwise system trust is used.
`ConnectionTimeoutSeconds` defaults to 15, `RequestTimeoutSeconds` to 10, and
`MaxPendingBans` to 1024. Queued bans retry after reconnection and remain in memory
only; normal process shutdown drains tasks but does not persist this client queue.

### Ban Rules (`src/FrpBan.Client/rules.d/*.yaml`)

Example: `01-ssh-bruteforce.yaml`
```yaml
rules:
  - name: ssh-bruteforce
    enabled: true
    logSource:
      type: file
      path: /var/log/auth.log
    matching:
      - type: regex
        pattern: 'Failed password.*from (?<ip>\d+\.\d+\.\d+\.\d+)'
    action:
      type: threshold
      maxMatches: 5
      windowSeconds: 300
      banDurationSeconds: 3600
      reason: SSH brute force attempt
    maxTrackedIps: 10000
```

**Rule options:**
- `type: file` — Monitor file with FileSystemWatcher (efficient, no polling)
- `type: journal` — Not implemented; rejected during rule loading
- `action.type: threshold` — Trigger after `maxMatches` in `windowSeconds`
- `banDurationSeconds: 0` — Permanent ban

---

## Build & Run

### Release packages

Tagged releases provide Windows `.zip`, macOS `.tar.gz`, and Linux
`.deb`, `.rpm`, Arch `.pkg.tar.zst`, Alpine `.apk` and portable `.tar.gz` builds for
x64 and ARM64. These packages contain the server and its .NET runtime.
See [Release packaging and installation](docs/RELEASING.md) for the full matrix,
configuration steps and GitHub/GitLab CI runner requirements.

### Build

```bash
# Build all projects
dotnet build FrpBan.slnx

# Publish server (self-contained)
dotnet publish src/FrpBan -c Release -r linux-x64 --self-contained -o ./publish/server

# Publish client
dotnet publish src/FrpBan.Client -c Release -r linux-x64 --self-contained -o ./publish/client
```

### Development

```bash
# Run server
cd src/FrpBan
dotnet run

# Run client
cd src/FrpBan.Client
dotnet run
```

### Generate TLS Certificates

```bash
# Self-signed certificate for development
openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -days 365 -nodes \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
openssl pkcs12 -export -out server.pfx -inkey server-key.pem -in server-cert.pem

# Set ClientSettings.Tls.CaCertificatePath to server-cert.pem for this local certificate.
# For production, use Let's Encrypt or your organization's CA
```

---

## Deployment

### Server (systemd)

Install the appropriate native package using the steps in
[Release packaging and installation](docs/RELEASING.md). Packages install the
service, runtime and configuration directories; configure the token and TLS
certificate before starting the service.

```bash
sudo nano /etc/frp-ban/appsettings.json
# Configure Token and Tls.CertificatePath, or set secrets in /etc/frp-ban/env.
sudo systemctl enable --now frp-ban
sudo systemctl status frp-ban
journalctl -u frp-ban -f
```

### Client (systemd)

Create `/etc/systemd/system/frp-ban-client.service`:
```ini
[Unit]
Description=FrpBan Client - Automated IP Ban Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=frp-ban
WorkingDirectory=/opt/frp-ban-client
ExecStart=/opt/frp-ban-client/FrpBan.Client
Restart=always
RestartSec=10
EnvironmentFile=/etc/frp-ban/client.env

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable frp-ban-client
sudo systemctl start frp-ban-client
```

---

## frps Configuration

Add to `frps.toml`:

```toml
[[httpPlugins]]
name = "frp-ban"
addr = "127.0.0.1:9000"
path = "/handler"
ops  = ["Login", "NewUserConn"]
```

---

## Logging

### Application Logs

- **Path**: `PluginSettings.AppLogPath` (default: `/var/log/frp-ban/frp-ban-.log`)
- **Rotation**: Daily + 100MB file size limit
- **Retention**: 30 days
- **Format**: `YYYY-MM-DD HH:mm:ss.fff [LEVEL] Message`

```bash
# Real-time (systemd)
sudo journalctl -u frp-ban -f

# Real-time (log file)
sudo tail -f /var/log/frp-ban/frp-ban-$(date +%Y%m%d).log

# Search errors
sudo grep -i error /var/log/frp-ban/frp-ban-*.log
```

---

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Ban lookup (IsBanned) | ConcurrentDictionary lookup with canonical IP keys |
| Max concurrent TLS connections | 100 (configurable) |
| TLS connection rate | 10 new connections/minute per IP (configurable) |
| Protocol message rate | 120 messages/minute per IP (configurable) |
| Max protocol/HTTP body | 64 KiB |
| Frame buffers | Pooled on demand; no fixed 1 MiB receive buffer |
| File monitoring | Event-driven, serialized reads with bounded partial-line state |
| Regex matching | Cached per expression, 100 ms timeout |
| Persistence | One writer, approximately 100 ms burst coalescing, atomic replace |

These describe implementation limits, not benchmark results. Production latency,
throughput, and memory usage depend on workload and require measurement.

---

## Troubleshooting

### Client cannot connect

1. Check TLS certificate:
   ```bash
   openssl s_client -connect frps.example.com:9443 -showcerts
   ```

2. Check token hash:
   ```bash
   echo -n "your-token" | sha256sum
   ```

3. View server logs:
   ```bash
   journalctl -u frp-ban -n 50
   ```

### High memory usage

- Check ban count: inspect `/var/lib/frp-ban/bans.json`
- Review ban expiration settings
- Monitor for ban list pollution

### TLS connection failures

- Ensure `ValidateServerCertificate` matches environment (disable only in development)
- Check certificate expiration: `openssl x509 -in server-cert.pem -noout -dates`
- Configure CA certificate path for self-signed certificates

---

## Protocol Specification

### Binary Message Format

```
[Type: 1 byte][Length: 4 bytes big-endian][Body: variable]
```

**Message Types:**
- `0x01` HELLO — Handshake (includes token hash)
- `0x02` BAN_REQUEST — Ban request
- `0x03` BAN_RESPONSE — Ban response
- `0x04` PING — Health check
- `0x05` PONG — Health check response
- `0x06` ERROR — Error message

**Body Format**: JSON (UTF-8)

---

## License

MIT License

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**Security vulnerabilities**: Please report privately to the maintainer.

---

## Roadmap

- [ ] Systemd journal monitoring support (`type: journal`)
- [ ] IP whitelist/exemption list
- [ ] Prometheus metrics endpoint
- [ ] Web UI for ban management
- [ ] Docker/Podman images
- [ ] Kubernetes Helm chart
- [ ] Full IPv6 testing
- [ ] gRPC protocol option (alternative to binary TCP)

---

See [CHANGELOG.md](CHANGELOG.md) for version history.
