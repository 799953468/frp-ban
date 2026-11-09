# frp-ban

A C# ASP.NET Core HTTP plugin for [frps](https://github.com/fatedier/frp) that blocks banned IP addresses from connecting through frp tunnels. Remote machines can push new bans via a token-protected REST API, and fail2ban on the server monitors the plugin's own access log to block brute-force attempts against the API itself.

---

## Architecture

```
 CLIENT MACHINE                    FRP SERVER
 ┌─────────────────────┐           ┌──────────────────────────────────┐
 │ frpc                │◄─tunnel──►│ frps (:7000)                     │
 │                     │           │   │ plugin callbacks              │
 │ fail2ban            │           │   ▼                               │
 │  detects SSH attack │           │ frp-ban (:9000)                   │
 │  → action script ──────────────►│   POST /handler  (Login/NewUser) │
 │    POST /api/bans   │           │   POST /api/bans  [token auth]    │
 └─────────────────────┘           │   DELETE /api/bans/{ip}           │
                                   │   GET  /api/bans                  │
                                   │                     │             │
                                   │              access.log           │
                                   │                     ▼             │
                                   │              fail2ban             │
                                   │          (guards the API port)    │
                                   └──────────────────────────────────┘
```

**Flow:**
1. frps calls `POST /handler` before each `Login` and `NewUserConn`.
2. frp-ban checks the offending IP against the ban list; rejected IPs never establish a tunnel.
3. A remote fail2ban action script calls `POST /api/bans` (with a Bearer token) to push a new ban.
4. The server-side fail2ban watches `/var/log/frp-ban/access.log` for bad-token attempts and bans those IPs via iptables.

---

## Configuration

Edit `src/FrpBan/appsettings.json`:

```json
{
  "PluginSettings": {
    "Token": "CHANGE_ME_TO_A_LONG_RANDOM_SECRET",
    "BanFilePath": "/var/lib/frp-ban/bans.json",
    "AccessLogPath": "/var/log/frp-ban/access.log",
    "AllowedPluginAddresses": ["127.0.0.1", "::1"],
    "DefaultBanDurationSeconds": 3600
  },
  "urls": "http://0.0.0.0:9000"
}
```

| Key | Description |
|-----|-------------|
| `Token` | Bearer token required for all `/api/*` calls |
| `BanFilePath` | JSON file used to persist bans across restarts |
| `AccessLogPath` | Log file monitored by fail2ban (one line per bad request) |
| `AllowedPluginAddresses` | IPs allowed to call `/handler` (frps itself); empty = allow all |
| `DefaultBanDurationSeconds` | Default ban duration; `0` = permanent |

---

## Running

```bash
# Build
dotnet build FrpBan.sln

# Run (production)
dotnet run --project src/FrpBan --configuration Release

# Or publish a self-contained binary
dotnet publish src/FrpBan -c Release -r linux-x64 --self-contained -o ./publish
./publish/frp-ban
```

---

## frps configuration

Add to `frps.toml`:

```toml
[[httpPlugins]]
name = "frp-ban"
addr = "127.0.0.1:9000"
path = "/handler"
ops  = ["Login", "NewUserConn"]
```

---

## fail2ban — server side (protect the API)

```bash
# Copy files
sudo cp fail2ban/filter.d/frp-ban-api.conf /etc/fail2ban/filter.d/
sudo cp fail2ban/jail.d/frp-ban.conf       /etc/fail2ban/jail.d/

# Reload
sudo fail2ban-client reload
```

The jail bans any IP that sends 5+ bad-token requests within 60 seconds.

---

## fail2ban — client side (push bans to the server)

Copy `scripts/fail2ban-action.sh` to the frpc client machine:

```bash
sudo cp scripts/fail2ban-action.sh /opt/frp-ban/fail2ban-action.sh
sudo chmod +x /opt/frp-ban/fail2ban-action.sh
```

Then add the action to your existing jail (e.g. sshd) in `/etc/fail2ban/jail.d/sshd.local`:

```ini
[sshd]
action = %(action_mw)s
         frp-ban[frp_ban_url="https://frps.example.com:9000",
                 frp_ban_token="CHANGE_ME_TO_A_LONG_RANDOM_SECRET"]
```

Install the action definition:

```bash
sudo cp fail2ban/filter.d/frp-ban-action.conf /etc/fail2ban/action.d/frp-ban.conf
sudo fail2ban-client reload
```

---

## systemd service (server)

Use the install script to deploy the compiled binary as a managed systemd service.

```bash
# 1. Build a self-contained binary
dotnet publish src/FrpBan -c Release -r linux-x64 --self-contained -o ./publish/linux-x64

# 2. Copy the repo to the server, then run
sudo ./deploy/install.sh
```

The script:
- creates a `frp-ban` system user (no login shell)
- installs the binary to `/opt/frp-ban/`
- creates `/var/lib/frp-ban/` (ban persistence) and `/var/log/frp-ban/` (access log)
- places an env file at `/etc/frp-ban/env` (mode `0640`) for secrets
- installs and enables `frp-ban.service`

### Configuring the token

Edit `/etc/frp-ban/env` (or `/opt/frp-ban/appsettings.json`) before starting:

```bash
# /etc/frp-ban/env
PluginSettings__Token=CHANGE_ME_TO_A_LONG_RANDOM_SECRET
```

Then:

```bash
sudo systemctl restart frp-ban
sudo systemctl status frp-ban
journalctl -u frp-ban -f          # follow logs
```

### Uninstall

```bash
sudo ./deploy/install.sh --uninstall
```

---

## API Reference

All `/api/*` endpoints require `Authorization: Bearer <token>` header. Query parameter authentication is not supported for security reasons (tokens would appear in server logs).

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `GET` | `/api/bans` | — | List active bans |
| `POST` | `/api/bans` | `{"ip":"1.2.3.4","reason":"...","durationSeconds":3600}` | Add a ban |
| `DELETE` | `/api/bans/{ip}` | — | Remove a ban |

`durationSeconds: 0` or omitting it creates a permanent ban.
