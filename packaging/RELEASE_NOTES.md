# v1.2.0

This release adds an authenticated ban-management Web UI, IP/CIDR exemptions,
and Linux systemd journal monitoring. Server and client downloads include the
.NET runtime, and successful ban changes are acknowledged only after the ban
file has been updated.

## New Features

### Ban-management Web UI

- Enable the optional management page at `/admin/` to search active bans, filter
  temporary/permanent entries, page through results, add bans, and remove bans
  after confirmation.
- Management is disabled by default. Set `PluginSettings.WebUi.Enabled` and a
  separate `PluginSettings.WebUi.Token` containing 32–256 printable ASCII
  characters without spaces. It must differ from the TLS client token.
- Access defaults to loopback and is controlled by `WebUi.AllowedAddresses`.
  The API requires bearer authentication, applies request limits, and shares the
  server's ban store. Browser assets are embedded in the server assembly.
- The browser keeps the management token only in tab memory. Use an SSH tunnel
  or an HTTPS reverse proxy for remote access; the TLS client listener does not
  encrypt the management HTTP listener.

### IP whitelist and ban exemptions

- Configure `PluginSettings.ExemptAddresses` with individual IPv4/IPv6 addresses
  or CIDR networks. IPv4-mapped IPv6 addresses match their IPv4 equivalents.
- Exempt addresses cannot be banned by monitoring clients or the Web UI and do
  not consume ban capacity. Existing bans for exempt addresses are removed from
  validated storage during server startup.
- Changes require a server restart. Exemptions do not bypass TLS authentication,
  frps callback authorization, or rate limits.

### Systemd journal monitoring

- Linux clients can use `logSource.type: journal` with a required `service`
  unit, such as `ssh.service` or `sshd.service`.
- Journal rules use the existing regex/JSON matching and threshold engine on
  message bodies, without syslog timestamps or process prefixes. Adapt patterns
  when moving from file rules; changing the source type alone is insufficient.
- The monitor follows new messages only. It does not replay startup history or
  persist a cursor. Configure journal read permissions for the service account.
- Output buffering is bounded, diagnostics are drained concurrently, and the
  child process is cleaned up on shutdown. An unexpected `journalctl` exit fails
  the client so its service supervisor can restart it.

## Fixes and Reliability

- Ban and unban requests, including duplicate requests, wait for the coalesced
  atomic file replacement before reporting success. Storage failures are
  reported to callers; the management API returns HTTP `503`, and pending
  changes remain available for retry.
- Preserve original expiry times across restarts, retain updates made during
  concurrent writes, and drain pending persistence during shutdown.
- A new request can extend a ban but cannot shorten a longer ban or replace a
  permanent ban with a temporary one. Expiry cleanup no longer removes a ban
  that was refreshed concurrently.
- Harden bundled SSH rules against misleading text in usernames and unrelated
  log messages, with support for traditional/ISO timestamps and modern
  `sshd-session`/`sshd-auth` process names.

## Build and Release Changes

- Remove Native AOT compilation and publish both components directly with the
  shared `SelfContained` profiles. Downloads include managed assemblies and the
  target platform's .NET runtime; no separate runtime installation is needed.
- GitHub and GitLab independently build all eight targets on Linux. GitLab CI
  uses its existing Linux runner and automatically publishes its own archives,
  checksums, and release notes without copying GitHub build artifacts.
- Retain source-generated JSON serialization, configuration binding, and the
  explicit YAML rule parser. Protocol wire compatibility remains covered by
  regression tests.
- Build with the .NET 11 GA SDK and enable runtime async compilation. Update
  Microsoft.Extensions, YamlDotNet, and Serilog dependencies; the pinned Serilog
  versions include development builds, as listed in `Directory.Packages.props`.

## Downloads

This release provides **16 archives**: server and client builds for eight runtime
targets, plus **`SHA256SUMS`** covering every archive.

| Platform | Architectures | Server and Client Format |
| --- | --- | --- |
| Windows | x64, ARM64 | `.zip` |
| macOS | Intel x64, Apple Silicon ARM64 | `.tar.gz` |
| Linux (glibc) | x64, ARM64 | `.tar.gz` |
| Alpine Linux (musl) | x64, ARM64 | `.tar.gz` |

Server filenames start with `frp-ban-1.2.0-`; client filenames start with
`frp-ban-client-1.2.0-`. Each archive includes the executable, application DLLs,
.NET runtime, example configuration, and license. Client archives also include
`rules.d`.

## Upgrade Notes

1. Back up configuration, certificates, rules, and the ban file. Stop the old
   services before replacing their binaries, and upgrade server and client
   together where possible.
2. **Packaging has changed since v1.1.0:** `.deb`, `.rpm`, `.pkg.tar.zst`, and
   `.apk` installers are no longer published. Extract the matching archive into
   a new directory and copy your configuration explicitly. Archives do not
   create service accounts, install services, or preserve configuration
   automatically. Manual systemd/OpenRC templates remain in `packaging/linux/`.
3. Run `FrpBan` or `FrpBan.Client` directly (`.exe` on Windows). Update existing
   service launch paths and working directories; the old portable launchers are
   not part of these archives. Extract the entire archive, including its DLLs
   and runtime libraries. Linux deployments still need the native OS libraries
   required by .NET 11; use the musl build for Alpine.
4. Keep a stable, writable `PluginSettings.BanFilePath` and ensure its directory
   permits temporary-file creation and replacement. A storage error can leave
   an in-memory change pending even though the request failed; fix storage and
   retry. The client's pending request queue remains memory-only.
5. Review the bundled SSH rules against your host's log format. Journal
   monitoring is opt-in and requires Linux, `journalctl`, a valid unit, suitable
   permissions, and message-body patterns.
6. The Web UI and exemptions are opt-in. Keep management credentials separate
   from client credentials, restart after configuration changes, and verify all
   downloaded archives against `SHA256SUMS`.

See `README.md` in this tag for configuration examples and manual installation.

## Validation

- 334 unit and integration tests passed before release preparation, covering
  protocol compatibility, TLS, SSH rule matching, journal process handling,
  exemptions, management endpoints, and persistence/restart behavior.
- Four release-publisher regression tests cover complete uploads, checksums,
  missing archives, failed uploads, and repairing links when a publish job is retried.
- The release workflow runs the Release-configuration test suite before building
  both components for all eight targets and producing archive checksums.
