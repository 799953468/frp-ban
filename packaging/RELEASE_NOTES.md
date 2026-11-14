# v1.1.0

Server and client builds use Native AOT for Windows, macOS and Linux on x64 and
ARM64. Configuration, protocol serialization, YAML rules and ban persistence
support native compilation without runtime code generation.

## Release Packages

- GitHub and GitLab invoke `dotnet publish` directly for each component and runtime target.
- Each release provides 16 archives, plus a `SHA256SUMS` file covering all downloads.
- Server filenames start with `frp-ban-`; client filenames start with `frp-ban-client-`. Install either component independently or both on the same host.
- Every package includes a Native AOT executable, example configuration and license. No separate .NET runtime installation is required. Client packages also include YAML rules in `rules.d`.
- Archives contain publish output and do not install services or preserve configuration automatically. Linux service templates remain in `packaging/linux/` for manual installation.

| Platform / Distribution | Architectures | Formats (Server and Client) |
| --- | --- | --- |
| Windows | x64, ARM64 | `.zip` |
| macOS | Intel x64, Apple Silicon ARM64 | `.tar.gz` |
| Linux (glibc) | x64, ARM64 | `.tar.gz` |
| Alpine Linux (musl) | x64, ARM64 | `.tar.gz` |

### Running the Applications

Extract the appropriate archive, configure `appsettings.json`, and run the
executable from the extracted directory:

```sh
./FrpBan
# On the client host:
./FrpBan.Client
```

On Windows, use `FrpBan.exe` or `FrpBan.Client.exe`.

- Set writable ban/log paths and valid TLS certificate paths before starting either application. The server defaults use system directories that may need to be created or changed.
- Configure the client rules path and monitored log paths for the host.
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
- Extract into a new directory when upgrading and copy your existing configuration, certificates and rules explicitly. Native OS libraries are still required on Linux; glibc artifacts are built on Ubuntu 24.04.
- See `README.md` for build and configuration instructions. Verify downloads against `SHA256SUMS`.

## Validation

- 135 .NET unit and integration tests pass, including protocol wire compatibility and YAML scalar handling.
- Server and client Native AOT publishing was verified on macOS ARM64, including TLS, rule-triggered bans, HTTP callbacks and persistence across restarts.
