<div align="center">

# frp-ban

**Distributed IP banning for [frp](https://github.com/fatedier/frp) — stop attackers at the frps edge before they reach your tunnels.**

[![CI](https://github.com/799953468/frp-ban/actions/workflows/ci.yml/badge.svg)](https://github.com/799953468/frp-ban/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/799953468/frp-ban?sort=semver)](https://github.com/799953468/frp-ban/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-11-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
![Platforms](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey)

[Quick Start](#quick-start) ·
[Configuration](#configuration) ·
[Web UI](#web-ui) ·
[Protocol](#protocol) ·
[Changelog](CHANGELOG.md)

</div>

---

## Overview

When you expose services such as SSH through frp, attack traffic is logged on the
machine running **frpc**, but it enters through **frps**. Local tools like fail2ban
cannot block it at the source, because every connection appears to come from frpc.

**frp-ban** closes that gap:

- **`frp-ban-client`** runs next to your services, watches their logs (files or the
  systemd journal), and detects attacks using YAML rules.
- **`frp-ban`** (server) runs next to frps as an [HTTP server plugin](https://github.com/fatedier/frp/blob/dev/doc/server_plugin.md).
  It receives ban requests from clients over TLS and rejects banned IPs at the frps
  `Login` and `NewUserConn` stages.

```
   Client host                                       frps host
 ┌──────────────────────────────┐              ┌──────────────────────────────┐
 │ sshd / nginx / ...           │              │ frps (:7000)                 │
 │   │ logs                     │   frp tunnel │   │ Login / NewUserConn      │
 │   ▼                          │◄────────────►│   ▼                          │
 │ frp-ban-client               │              │ frp-ban                      │
 │   ├─ rules.d/*.yaml          │     TLS      │   ├─ POST /handler (:9000)   │
 │   ├─ file / journal monitors │─────────────►│   ├─ TLS listener (:9443)    │
 │   └─ retry queue + backoff   │  ban request │   ├─ in-memory ban list      │
 │                              │              │   └─ bans.json (persistent)  │
 └──────────────────────────────┘              └──────────────────────────────┘
```

1. frps calls `POST /handler` on frp-ban before every `Login` and `NewUserConn`.
2. frp-ban looks up the source IP in its in-memory ban list and rejects banned IPs.
3. frp-ban-client matches log lines against rules and sends a ban request over TLS when a threshold is reached.
4. The server persists the ban and blocks the IP on subsequent connections.

## Features

- 🛡️ **frps plugin integration** — Rejects banned IPs at `Login` and `NewUserConn`, before a tunnel or user connection is established.
- 🔐 **TLS-encrypted protocol** — Compact binary framing over TLS 1.2/1.3, token authentication, optional mutual TLS.
- 📜 **Rule engine** — YAML rules with regex or JSON matching and sliding-window thresholds, applied to log files or systemd journal units.
- 🌐 **IPv4 and IPv6** — Canonical address handling, CIDR exemptions, IPv4-mapped IPv6 support.
- 💾 **Durable bans** — Atomic persistence; temporary bans keep their original expiry across restarts.
- 🖥️ **Web UI** — Opt-in management page for searching, adding, and removing bans, with its own token.
- 🧱 **Hardened by default** — Bounded connections, queues, and frames; per-IP rate limits; handshake and idle deadlines.
- 📦 **Self-contained** — Ships with the .NET runtime. Packages for deb, rpm, Arch, Alpine, plus portable archives for Linux, Windows, and macOS.

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Server](#server)
  - [IP exemptions](#ip-exemptions)
  - [Web UI](#web-ui)
  - [Client](#client)
  - [Ban rules](#ban-rules)
  - [Systemd journal rules](#systemd-journal-rules)
- [Operations](#operations)
- [Security](#security)
- [Protocol](#protocol)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Quick Start

The following steps use the Linux packages and systemd. See [Installation](#installation) for other platforms.

**1. Install the server on the frps host**

Download a package from [Releases](https://github.com/799953468/frp-ban/releases), for example:

```bash
sudo apt install ./frp-ban-<version>-linux-x64.deb
```

**2. Create a TLS certificate and configure the server**

```bash
# Self-signed certificate (use your CA or Let's Encrypt in production)
openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -days 365 -nodes \
  -subj "/CN=frps.example.com" -addext "subjectAltName=DNS:frps.example.com"
openssl pkcs12 -export -out server.pfx -inkey server-key.pem -in server-cert.pem
sudo install -o root -g frp-ban -m 640 server.pfx /etc/frp-ban/certs/server.pfx

# Keep secrets in the service environment file
TOKEN="$(openssl rand -base64 32)"
echo "PluginSettings__Token=$TOKEN" | sudo tee /etc/frp-ban/env >/dev/null
echo "PluginSettings__Tls__CertificatePassword=<pfx-password>" | sudo tee -a /etc/frp-ban/env >/dev/null
sudo chmod 600 /etc/frp-ban/env

sudo systemctl enable --now frp-ban
```

**3. Register the plugin in `frps.toml`** and restart frps:

```toml
[[httpPlugins]]
name = "frp-ban"
addr = "127.0.0.1:9000"
path = "/handler"
ops  = ["Login", "NewUserConn"]
```

**4. Install the client on each frpc host**

```bash
sudo apt install ./frp-ban-client-<version>-linux-x64.deb
sudo nano /etc/frp-ban-client/appsettings.json   # ServerAddress and CaCertificatePath (copy server-cert.pem)
echo "ClientSettings__Token=<same token as server>" | sudo tee /etc/frp-ban-client/env >/dev/null
sudo chmod 600 /etc/frp-ban-client/env
sudo usermod -aG adm frp-ban-client               # if monitored logs are owned by adm
sudo systemctl enable --now frp-ban-client
```

**5. Verify**

```bash
journalctl -u frp-ban -f          # server: client connected, bans applied
journalctl -u frp-ban-client -f   # client: rules loaded, connected to server
```

The bundled rules ban an IP for one hour after 5 failed SSH logins within 5 minutes.

## Installation

### Release packages

Each [release](https://github.com/799953468/frp-ban/releases) provides the server (`frp-ban-…`) and client
(`frp-ban-client-…`) separately for x64 and ARM64, with `SHA256SUMS`:

| Platform            | Formats                                                          |
|---------------------|------------------------------------------------------------------|
| Linux (glibc)       | `.deb`, `.rpm`, Arch `.pkg.tar.zst`, portable `.tar.gz`          |
| Alpine Linux (musl) | `.apk`, portable `.tar.gz`                                       |
| Windows             | portable `.zip`                                                  |
| macOS               | portable `.tar.gz`                                               |

Every package includes the self-contained .NET runtime, configuration, license, and
[release notes](packaging/RELEASE_NOTES.md). Server packages include `frps.toml.example`;
client packages include `rules.d`.

**Linux packages** create a dedicated service account, configuration in `/etc/frp-ban`
or `/etc/frp-ban-client`, application files in `/opt`, a command launcher, and a
systemd or OpenRC service. Secrets can be placed in `/etc/frp-ban/env` and
`/etc/frp-ban-client/env`. Configuration and rules are preserved on upgrade.
Services are **not** enabled or started automatically.

**Portable archives** contain a versioned root folder with an `frp-ban[.cmd]` or
`frp-ban-client[.cmd]` launcher and local data/log paths. Extract the whole archive
and configure it before running the launcher. For a manual service installation, use
the templates in [`packaging/linux/`](packaging/linux) and [`packaging/linux/client/`](packaging/linux/client).

### Build from source

Requires the [.NET 11 SDK](https://dotnet.microsoft.com/download).

```bash
git clone https://github.com/799953468/frp-ban.git
cd frp-ban
dotnet publish src/FrpBan/FrpBan.csproj -c Release -r linux-x64 -p:PublishProfile=SelfContained -o publish/server
dotnet publish src/FrpBan.Client/FrpBan.Client.csproj -c Release -r linux-x64 -p:PublishProfile=SelfContained -o publish/client
```

Supported runtime identifiers: `linux-x64`, `linux-arm64`, `linux-musl-x64`,
`linux-musl-arm64`, `win-x64`, `win-arm64`, `osx-x64`, `osx-arm64`. Any Linux host can
publish every target; no native toolchain is required (Native AOT and ReadyToRun are
not enabled). Without `-r`, the profile publishes for the local runtime into
`publish/self-contained/<project>/<runtime>/`.

## Configuration

Both applications read `appsettings.json` from their working directory, then
environment variables (`Section__Key=value`). The client also accepts command-line
arguments (`--ClientSettings:ServerAddress=frps.example.com`). Use environment
variables for secrets.

### Server

`appsettings.json` (installed at `/etc/frp-ban/appsettings.json`):

```json
{
  "PluginSettings": {
    "Token": "CHANGE_ME_TO_A_LONG_RANDOM_SECRET",
    "BanFilePath": "/var/lib/frp-ban/bans.json",
    "AppLogPath": "/var/log/frp-ban/frp-ban-.log",
    "AllowedPluginAddresses": ["127.0.0.1", "::1"],
    "ExemptAddresses": [],
    "DefaultBanDurationSeconds": 3600,
    "Tls": {
      "Enabled": true,
      "TcpListenerEnabled": true,
      "ListenAddress": "::",
      "Port": 9443,
      "CertificatePath": "/etc/frp-ban/certs/server.pfx",
      "CertificatePassword": "your-cert-password",
      "RequireClientCertificate": false
    }
  },
  "urls": "http://127.0.0.1:9000"
}
```

| Key | Default | Description |
|-----|---------|-------------|
| `Token` | — | Shared secret for TLS clients. At least 32 characters; placeholders are rejected at startup. |
| `BanFilePath` | `/var/lib/frp-ban/bans.json` | Persistent ban storage. Use a stable absolute path; the parent directory must be writable. |
| `AppLogPath` | `/var/log/frp-ban/frp-ban-.log` | Log file (rotated daily). |
| `AllowedPluginAddresses` | loopback | IPs/CIDRs allowed to call `/handler`. Empty = allow all. Invalid entries or CIDRs with host bits set fail startup. |
| `ExemptAddresses` | `[]` | IPs/CIDRs that can never be banned. See [IP exemptions](#ip-exemptions). |
| `DefaultBanDurationSeconds` | `3600` | Duration used when a request omits it. `0` = permanent. |
| `MaxBanEntries` | `100000` | Maximum number of stored bans (1–1,000,000). |
| `WebUi.*` | disabled | See [Web UI](#web-ui). |
| `Tls.Enabled` | `true` | Enable TLS for the client listener. |
| `Tls.ListenAddress` | `::` | Dual-stack by default; falls back to `0.0.0.0` without IPv6. Set e.g. `10.0.0.1` to bind one interface. |
| `Tls.Port` | `9443` | TLS listener port. |
| `Tls.CertificatePath` / `CertificatePassword` | — | PKCS#12 server certificate. |
| `Tls.RequireClientCertificate` | `false` | Require mutual TLS. |
| `Tls.MaxConcurrentConnections` | `100` | Concurrent TLS connections. |
| `Tls.MaxConnectionsPerMinute` | `10` | New connections per IP per minute. |
| `Tls.MaxMessagesPerMinute` | `120` | Protocol messages per IP per minute. |
| `Tls.HandshakeTimeoutSeconds` | `10` | TLS + HELLO deadline. |
| `Tls.IdleTimeoutSeconds` | `90` | Idle session timeout. |
| `Tls.WriteTimeoutSeconds` | `10` | Write deadline. |
| `urls` | `http://127.0.0.1:9000` | HTTP listener for frps callbacks and the Web UI. |

The HTTP listener binds to loopback by default. If frps runs on another host, change
`urls` and list the frps address in `AllowedPluginAddresses`. Durations use `null` for
the configured default and `0` for a permanent ban.

```bash
# Production secrets (e.g. in /etc/frp-ban/env)
PluginSettings__Token=...
PluginSettings__Tls__CertificatePassword=...
```

### IP exemptions

`PluginSettings.ExemptAddresses` protects trusted addresses from all ban requests:

```json
"ExemptAddresses": ["192.0.2.10", "198.51.100.0/24", "2001:db8::/32"]
```

- Accepts IPv4/IPv6 addresses and CIDRs. CIDRs must use the network address (`198.51.100.0/24`, not `198.51.100.10/24`). Hostnames and ports are rejected; invalid entries fail startup.
- IPv4-mapped IPv6 matches the IPv4 equivalent (`::ffff:192.0.2.10` ≙ `192.0.2.10`). `0.0.0.0/0` covers IPv4 including mapped addresses; `::/0` covers native IPv6.
- An empty list exempts nothing, not even loopback. The list is compiled at startup; restart after changes.
- Exempt addresses are allowed at both `Login` and `NewUserConn`, cannot be banned, and do not consume capacity. Existing bans for them are dropped on startup and removed from the ban file; removing the exemption later does not restore them.
- Exemptions do not bypass `AllowedPluginAddresses`, TLS authentication, or rate limits. No client configuration is needed.
- Environment variables use indexed keys: `PluginSettings__ExemptAddresses__0=192.0.2.10`.

### Web UI

An optional management page is served at `http://127.0.0.1:9000/admin/`. It is
**disabled by default** and uses its own token, which must differ from `Token`:

```json
"WebUi": {
  "Enabled": true,
  "AllowedAddresses": ["127.0.0.1", "::1"]
}
```

```bash
PluginSettings__WebUi__Token=$(openssl rand -hex 32)   # 32–256 printable ASCII characters, no spaces
```

- Search by IP or reason, filter temporary/permanent bans, and page through results.
- Add IPv4/IPv6 bans with the default, a preset, a custom duration, or no expiry. Existing longer or permanent bans are kept.
- Remove bans after confirmation. Rules may ban the address again on new activity.
- The token is kept only in tab memory — never in cookies or storage. Reloading or **Lock session** clears it.
- Assets are embedded in the server; no Node.js, separate frontend, or CDN is needed.

`WebUi.AllowedAddresses` (default: loopback) checks the socket peer. Empty allows any
address with a valid token. For remote access, prefer an SSH tunnel:

```bash
ssh -L 19000:127.0.0.1:9000 user@your-server
# then open http://127.0.0.1:19000/admin/
```

Behind a reverse proxy, terminate HTTPS at the proxy, restrict direct backend access,
and keep the `/admin/` prefix. `AllowedAddresses` sees the proxy address, not
`X-Forwarded-For`, so enforce end-user restrictions at the proxy. The port 9443 TLS
settings do **not** apply to the HTTP listener. Restart after changing Web UI settings
or rotating the token.

<details>
<summary><b>Management API reference</b></summary>

All requests require `Authorization: Bearer <management-token>` (query-string tokens
are not accepted). Limited to 120 requests per socket IP per minute, including failed
authentication; bodies are limited to 64 KiB.

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/admin/api/bans` | Query: `search` (≤ 256 chars), `kind` (`all`, `temporary`, `permanent`), `page` (1-based), `pageSize` (1–100, default 25) |
| `POST` | `/admin/api/bans` | JSON: `ip`, `reason` (1–1024 chars), optional `durationSeconds` (`null` = default, `0` = permanent) |
| `DELETE` | `/admin/api/bans/{ip}` | Remove the URL-encoded IP; succeeds if already absent |

The list response contains `items`, `total`, `page`, `pageSize`, `activeCount`,
`permanentCount`, and `defaultBanDurationSeconds`. Items contain `ip`, `reason`,
`bannedAt`, `expiresAt`, and `isActive` (ISO 8601 times).

| Status | Meaning |
|--------|---------|
| `204` | POST/DELETE succeeded (change persisted) |
| `400` | Validation error |
| `401` | Missing or invalid token |
| `403` | Address not allowed |
| `404` | Web UI disabled |
| `409` | Exempt address or capacity reached |
| `413` / `415` | Body too large / unsupported content type |
| `429` | Rate limited (`Retry-After: 60`) |
| `503` | Persistence failed; change stays pending in memory — fix storage and retry |

</details>

### Client

`appsettings.json` (installed at `/etc/frp-ban-client/appsettings.json`):

```json
{
  "ClientSettings": {
    "ServerAddress": "frps.example.com",
    "ServerPort": 9443,
    "Token": "CHANGE_ME_TO_A_LONG_RANDOM_SECRET",
    "RulesPath": "rules.d",
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

| Key | Default | Description |
|-----|---------|-------------|
| `ServerAddress` / `ServerPort` | — / `9443` | frp-ban TLS listener. |
| `Token` | — | Must match the server `Token`. |
| `RulesPath` | `rules.d` | Directory of YAML rule files, relative to the working directory. |
| `Tls.CaCertificatePath` | system trust | CA (or self-signed certificate) used to validate the server. |
| `Tls.ClientCertificatePath` | — | Client certificate, required only if the server enables mTLS. |
| `Tls.ValidateServerCertificate` | `true` | Cannot be disabled in production. |
| `Reconnection.*` | see above | Exponential backoff; `MaxRetries: -1` = retry forever. |
| `ConnectionTimeoutSeconds` | `15` | Connect + handshake timeout. |
| `RequestTimeoutSeconds` | `10` | Ban request timeout. |
| `MaxPendingBans` | `1024` | In-memory queue size while disconnected. |

TLS is always used. Log monitors start immediately, even if the server is unreachable;
detected attacks are queued and delivered after reconnecting. The queue is in memory
only and is not persisted across restarts. Invalid settings, or rule sources with no
valid enabled rule, stop the client with exit code 1.

### Ban rules

Rules live in `rules.d/*.yaml`. Example (`01-ssh-bruteforce.yaml`, simplified):

```yaml
rules:
  - name: ssh-bruteforce
    enabled: true
    logSource:
      type: file                 # file | journal
      path: /var/log/auth.log
    matching:
      - type: regex
        pattern: 'sshd(?:-session|-auth)?(?:\[[0-9]+\])?: Failed password for [^\r\n]* from (?<ip>\S+) port [0-9]+ ssh2'
    action:
      type: threshold
      maxMatches: 5              # ban after 5 matches...
      windowSeconds: 300         # ...within 5 minutes
      banDurationSeconds: 3600   # 0 = permanent
      reason: SSH brute force attempt
    maxTrackedIps: 10000
```

| Option | Description |
|--------|-------------|
| `logSource.type: file` | Tail a file using an event-driven watcher (no polling). |
| `logSource.type: journal` | Follow a systemd unit (Linux only). See below. |
| `matching[].type: regex` | .NET regex; the named group `ip` captures the source address. Cached, 100 ms timeout. |
| `matching[].type: json` | Match JSON log lines with `jsonPath`, `jsonValue`, and `ipJsonPath`. |
| `action.type: threshold` | Ban after `maxMatches` within `windowSeconds`. |
| `maxTrackedIps` | Upper bound on IPs tracked per rule. |

The bundled rules (`01-ssh-bruteforce.yaml`, `02-ssh-invalid-user.yaml`) use stricter,
anchored expressions that accept plain `sshd` messages or syslog lines with RFC 3164 or
RFC 3339 timestamps, support IPv4 and IPv6, and never treat IP text inside a username
as the source address. Keep these boundaries when adapting rules to other formats.

Repeated ban requests can only extend an existing ban or make it permanent; a shorter
request keeps the stronger ban, including its reason and timestamp. A permanent ban
must be removed explicitly before a temporary one can replace it.

### Systemd journal rules

On systemd hosts, rules can follow a unit's journal instead of a log file. This
requires `journalctl` on `PATH` and read access to the unit's journal:

```yaml
rules:
  - name: ssh-journal-bruteforce
    enabled: true
    logSource:
      type: journal
      service: ssh.service       # or sshd.service, depending on the distribution
    matching:
      - type: regex
        pattern: '\AFailed password for [^\r\n]* from (?<ip>\S+) port [0-9]+ ssh2(?: \[preauth\])?\z'
    action:
      type: threshold
      maxMatches: 5
      windowSeconds: 300
      banDurationSeconds: 3600
      reason: SSH brute force attempt
```

```bash
sudo usermod -aG systemd-journal frp-ban-client
sudo -u frp-ban-client journalctl --system --unit=ssh.service --lines=5 --output=cat --no-pager
sudo systemctl restart frp-ban-client
```

- Journal rules match only the message body (`MESSAGE`) — no timestamp, hostname, or `sshd[pid]:` prefix. Changing `type` and `service` on a file rule is not enough; adapt the expression.
- JSON options (`type: json`) apply to the JSON message body, not journal metadata. Multiline messages are matched one line at a time.
- Only new messages are followed (`journalctl --follow --lines=0`); existing entries are not replayed and no cursor is stored.
- Lines over 64 Ki characters are discarded. If `journalctl` exits unexpectedly, the client fails so the service manager can restart it (`Restart=on-failure`).

## Operations

### Ban persistence

Bans are written to `BanFilePath` by a single coalescing writer using atomic
same-directory replacement. A successful ban/unban response means the change is on
disk. On startup, active bans are restored before traffic is accepted; temporary bans
keep their original expiry, and expired or exempt entries are dropped.

If a write fails, the Web UI API returns `503` and TLS clients receive
`StorageUnavailable`. The change stays in memory and is retried by the next request
and every 30 seconds. An invalid JSON file prevents startup instead of silently
resetting the ban list.

### Logging

| | |
|---|---|
| Path | `PluginSettings.AppLogPath` (default `/var/log/frp-ban/frp-ban-.log`) |
| Rotation | Daily, plus a 100 MB size limit |
| Retention | 30 days |
| Format | `YYYY-MM-DD HH:mm:ss.fff [LEVEL] Message` |
| Level | `Logging.LogLevel.Default` (`Debug`, `Information`, `Warning`, `Error`) |

```bash
sudo journalctl -u frp-ban -f
sudo tail -f /var/log/frp-ban/frp-ban-$(date +%Y%m%d).log
sudo grep -i error /var/log/frp-ban/frp-ban-*.log
```

## Security

- **Transport**: TLS 1.2/1.3 only; optional mutual TLS. Certificate validation cannot be disabled in production.
- **Authentication**: Clients authenticate with a token hash in `HELLO`; tokens shorter than 32 characters or left as placeholders are rejected at startup. The Web UI uses a separate token.
- **Access control**: `/handler` is limited to `AllowedPluginAddresses`; the Web UI to `WebUi.AllowedAddresses`. Both default to loopback.
- **Resource limits**: 100 concurrent TLS connections, 10 new connections and 120 messages per IP per minute, 64 KiB protocol/HTTP bodies, 64 Ki-character log lines, handshake/idle/write deadlines — all configurable.
- **Input validation**: Strict IP and CIDR parsing (prefix 0–32 for IPv4, 0–128 for IPv6).

**Reporting vulnerabilities**: please report security issues privately to the
maintainer instead of opening a public issue.

## Protocol

Clients and server communicate over TLS using length-prefixed frames:

```
[Type: 1 byte][Length: 4 bytes, big-endian][Body: UTF-8 JSON, ≤ 64 KiB]
```

| Type | Name | Direction | Purpose |
|------|------|-----------|---------|
| `0x01` | `HELLO` | client → server | Handshake with protocol version and token hash |
| `0x02` | `BAN_REQUEST` | client → server | Request a ban |
| `0x03` | `BAN_RESPONSE` | server → client | Result of a ban request |
| `0x04` | `PING` | client → server | Health check |
| `0x05` | `PONG` | server → client | Health check reply |
| `0x06` | `ERROR` | server → client | Error message |

Unknown message types and oversized frames close the session. The current protocol
version is **2.0**; the server rejects any other version, so upgrade clients and
server together when moving from 1.x.

`BAN_RESPONSE` carries `{"Status": "...", "Message": "..."}`:

| Status | Meaning | Client action |
|--------|---------|---------------|
| `Applied` | Ban added or extended and persisted | Done |
| `AlreadyBanned` | An equal or stronger ban already exists | Done |
| `Exempt` | Address is in `ExemptAddresses` | Drop |
| `Invalid` | Invalid IP, reason (1–1024 chars), or negative duration | Drop |
| `CapacityReached` | `MaxBanEntries` reached | Drop |
| `StorageUnavailable` | Active in memory but not yet persisted | Retry later |

## Troubleshooting

<details>
<summary><b>Client cannot connect</b></summary>

```bash
openssl s_client -connect frps.example.com:9443 -showcerts   # check certificate and reachability
journalctl -u frp-ban -n 50                                   # check server-side errors
journalctl -u frp-ban-client -n 50
```

- Make sure client and server use the same `Token` and the same protocol version.
- Check that port 9443 is open and `Tls.ListenAddress` covers the right interface.
</details>

<details>
<summary><b>TLS certificate errors</b></summary>

- For a self-signed or private-CA certificate, set `ClientSettings.Tls.CaCertificatePath`.
- The certificate's subject alternative name must match `ServerAddress`.
- Check expiry: `openssl x509 -in server-cert.pem -noout -dates`.
</details>

<details>
<summary><b>Bans are not triggered</b></summary>

- Confirm the client account can read the log file or journal unit.
- Test the rule regex against a real log line; journal rules see only the message body.
- Check that the attacker IP is not listed in `ExemptAddresses`.
</details>

<details>
<summary><b>High memory usage</b></summary>

- Inspect the ban count in `/var/lib/frp-ban/bans.json`.
- Review ban durations and `MaxBanEntries`; look for rules that match too broadly.
</details>

## Development

```bash
dotnet build FrpBan.slnx
dotnet test FrpBan.slnx
python3 -m unittest discover -s scripts/tests -v   # release packaging tests

# Run locally
dotnet run --project src/FrpBan
dotnet run --project src/FrpBan.Client
```

<details>
<summary><b>Project structure</b></summary>

```
src/
├── FrpBan.Protocol/   # Shared wire protocol: framing, messages, transport, TLS trust
├── FrpBan/            # Server: frps plugin endpoint, TLS listener, ban store, Web UI
│   ├── Endpoints/     #   HTTP routes and pre-body authorization
│   ├── Handlers/      #   frps plugin request handling
│   ├── Security/      #   address lists and rate limiting
│   ├── Services/      #   BanService, TcpServerService
│   └── WebUi/         #   embedded management page
└── FrpBan.Client/     # Client: log monitors, rule engine, TLS connection, retry queue
    ├── Services/
    └── rules.d/       #   bundled YAML rules
tests/FrpBan.Tests/    # Unit, security and loopback integration tests
packaging/             # Linux service templates, install scripts, release notes
scripts/release.py     # Release packaging (shared by GitHub and GitLab CI)
```
</details>

<details>
<summary><b>Releasing</b></summary>

GitHub Actions and GitLab CI each build both components for all eight targets on
Linux using `scripts/release.py`, which publishes self-contained builds, creates
portable archives and nFPM Linux packages, verifies all 32 assets, and writes
`SHA256SUMS`. To release, tag a commit as `vX.Y.Z` and push the tag to both remotes.
GitLab uploads assets to the project's generic package registry and uses
[`packaging/RELEASE_NOTES.md`](packaging/RELEASE_NOTES.md) for the release notes.
</details>

## Roadmap

- [x] Systemd journal monitoring
- [x] IP exemption list
- [x] Web UI for ban management
- [ ] Prometheus metrics endpoint
- [ ] Docker/Podman images
- [ ] Kubernetes Helm chart
- [ ] Full IPv6 test coverage
- [ ] gRPC protocol option

## Contributing

Contributions are welcome!

1. Fork the repository and create a branch: `git checkout -b feature/my-feature`
2. Make your changes and add tests where appropriate.
3. Run `dotnet test FrpBan.slnx` and make sure everything passes.
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/) (e.g. `feat(client): ...`, `fix: ...`).
5. Open a pull request and describe the change. Update [CHANGELOG.md](CHANGELOG.md) for user-visible changes.

## License

Distributed under the [MIT License](LICENSE).

## Acknowledgements

- [frp](https://github.com/fatedier/frp) — the fast reverse proxy this project extends.
- [fail2ban](https://github.com/fail2ban/fail2ban) — inspiration for log-based banning.
