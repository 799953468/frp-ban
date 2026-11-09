# v1.1.0

This release adds standalone client packages alongside the server for Windows,
macOS and Linux on x64 and ARM64. It also includes the TLS, protocol validation,
ban persistence and log monitoring improvements made since v1.0.0.

## Release Packages

- GitHub and GitLab share the same release script and build each component for every runtime target.
- Each release provides 32 native packages or portable archives, plus a `SHA256SUMS` file covering all downloads.
- Server filenames start with `frp-ban-`; client filenames start with `frp-ban-client-`. Install either component independently or both on the same host.
- Every package includes the complete self-contained .NET runtime, example configuration and license. Client packages also include YAML rules in `rules.d`.
- Native Linux client packages include a dedicated service account, launcher and systemd/OpenRC services. Configuration and bundled rules are preserved on upgrade.

| Platform / Distribution | Architectures | Formats (Server and Client) |
| --- | --- | --- |
| Windows | x64, ARM64 | `.zip` |
| macOS | Intel x64, Apple Silicon ARM64 | `.tar.gz` |
| Debian / Ubuntu | x64, ARM64 | `.deb` |
| Fedora / RHEL / Rocky / AlmaLinux / openSUSE | x64, ARM64 | `.rpm` |
| Arch Linux / Arch Linux ARM | x64, ARM64 | `.pkg.tar.zst` |
| Alpine Linux (musl) | x64, ARM64 | `.apk` |
| Linux portable (glibc / musl) | x64, ARM64 | `.tar.gz` |

### Arch Linux Installation

Download the components you need. For x64:

```sh
sudo pacman -U ./frp-ban-1.1.0-linux-x64.pkg.tar.zst
sudo pacman -U ./frp-ban-client-1.1.0-linux-x64.pkg.tar.zst
```

For Arch Linux ARM, replace `linux-x64` with `linux-arm64` in the filenames.

- Server configuration: `/etc/frp-ban/appsettings.json`; service: `frp-ban`.
- Client configuration: `/etc/frp-ban-client/appsettings.json`; rules: `/etc/frp-ban-client/rules.d`; service: `frp-ban-client`.
- Packages do not enable or start services automatically. Configure the token, TLS certificates/trust and log rules first, then run `sudo systemctl enable --now frp-ban` or `sudo systemctl enable --now frp-ban-client` as needed.
- Grant the `frp-ban-client` account read access to monitored logs and search access to their parent directories. Preserve that access after log rotation.
- The bundled SSH rules use `/var/log/auth.log`; adjust them to your host's log paths. The `journal` log source is not implemented.

## Security Improvements

- Validate protocol frame lengths and required JSON fields, enforce input limits, and reject truncated, oversized or malformed messages.
- Enforce custom CA trust, peer names, certificate validity and mTLS client certificate purpose.
- Apply handshake/read/write deadlines, connection and message rate limits, and bounded per-IP state.
- Authorize frps HTTP callback sources before reading request bodies, bind callbacks to loopback by default, normalize IP addresses and reject invalid requests.
- Validate tokens and nested configuration at startup. Validate rule expressions during loading, cache regular expressions and enforce execution timeouts.

## Reliability and Performance

- Serialize client protocol exchanges and retain pending ban requests in a bounded queue during disconnections, retrying after reconnection.
- Coalesce ban persistence through a single writer and atomically replace the ban file. Corrupt stored ban data fails startup instead of being silently discarded.
- Serialize log reads, retain partial UTF-8 lines, and handle file rotation and oversized input.
- Bound and expire threshold state, and separate JSON matching conditions from IP extraction.
- Refactor the shared protocol, TLS validation, log monitors and test projects; centralize build properties and NuGet package versions.

## Upgrade Notes

- Upgrade the server and client together where possible. Back up configuration, certificates, rules and ban data first.
- Both components require the same non-placeholder token of at least 32 characters. The bundled example configuration is not ready to start unchanged.
- TLS checks are stricter: configure a trusted CA for private or self-signed certificates, ensure certificate names match the connection address, and provide a valid client certificate when the server requires mTLS.
- If frps runs on another host, explicitly configure the HTTP listener and trusted callback sources.
- The client's pending ban queue is held in memory only and is not persisted across process exits.
- On Windows and macOS, extract the entire archive, configure it, and use `frp-ban[.cmd]` or `frp-ban-client[.cmd]`. Native OS libraries are still required on Linux. Alpine packages are unsigned.
- See `docs/RELEASING.md` in this tag for complete installation, dependency and configuration instructions. Verify downloads against `SHA256SUMS`.

## Validation

- 115 .NET unit and integration tests pass.
- 15 release script tests pass, covering both components, eight runtime targets, Arch package configuration, archive contents, checksums and GitLab asset upload logic.
