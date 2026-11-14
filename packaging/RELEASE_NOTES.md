# v1.2.0

## New Features

- **Ban-management Web UI:** View and search active bans, filter temporary and
  permanent entries, add bans with custom durations, and remove bans after
  confirmation at `/admin/`.
- **IP whitelist:** Protect trusted IPv4/IPv6 addresses and CIDR networks with
  `PluginSettings.ExemptAddresses`. Exempt addresses cannot be banned, and their
  existing bans are removed from validated storage when the server starts.
- **Systemd journal monitoring:** Linux clients can monitor a systemd unit with
  `logSource.type: journal` and `logSource.service`, using the same matching and
  threshold rules as file monitoring.

## Fixes

- Wait for ban-file persistence before confirming successful ban or unban
  requests, including duplicate requests. Report storage failures and retain
  pending changes for retry.
- Preserve ban expiry times across restarts, retain concurrent updates during
  persistence, and flush pending writes during shutdown.
- Prevent shorter bans from weakening longer or permanent bans. Prevent expiry
  cleanup from removing a ban that was refreshed concurrently.
- Harden bundled SSH patterns against misleading username text and unrelated
  messages. Support traditional and ISO timestamps, plus `sshd-session` and
  `sshd-auth` process names.

## Configuration Notes

- The Web UI is disabled by default. Enable `PluginSettings.WebUi.Enabled` and
  configure a separate `WebUi.Token` containing 32–256 printable ASCII characters
  without spaces. Access defaults to loopback; use an SSH tunnel or HTTPS reverse
  proxy for remote administration.
- Exemption changes require a server restart. Exemptions do not bypass TLS
  authentication or frps callback authorization.
- Journal monitoring requires Linux, `journalctl`, a valid systemd unit, and
  journal read permissions. Rules match message bodies without syslog prefixes;
  adapt file-based patterns accordingly. Only new entries are monitored, and
  no journal cursor is retained across client restarts.
- Keep the configured ban-file directory writable. Management requests return
  HTTP `503` if changes cannot be saved; fix storage and retry the request.
