# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support Linux systemd journal rules with `logSource.type: journal` and a required `service` unit.
- Follow new journal message bodies through the existing regex/JSON matching and ban delivery pipeline, with bounded line buffering, concurrent diagnostic draining, and child-process cleanup on shutdown.
- Document journal permissions, SSH message patterns, startup history behavior, and failure handling; add configuration and monitor regression tests.

## [1.1.0] - 2026-11-09

### Added

- Publish separate self-contained client packages alongside server packages on GitHub and GitLab.
- Provide both components for eight runtime identifiers on Windows, macOS and Linux (x64/ARM64).
- Include client configuration, YAML rules, portable launchers, Linux service accounts and systemd/OpenRC services.
- Provide Arch Linux and Arch Linux ARM `.pkg.tar.zst` packages for both components.
- Verify the complete set of 32 assets and publish SHA-256 checksums for every package.
- Preserve client configuration and bundled rules on native package upgrades; document installation and log permissions.
- Expand release regression coverage to validate the client payload, component isolation and full packaging matrix.

### Security

- Validate complete bounded protocol frames and strict required JSON fields.
- Enforce custom CA trust, peer names, certificate validity and mTLS client purpose.
- Add effective handshake/read/write deadlines, bounded per-IP state and message rate limits.
- Normalize IP representations and reject malformed protected frps callbacks.
- Authorize HTTP peers before body parsing; bind callbacks to loopback by default.
- Cache regexes with timeouts; fix the bundled SSH patterns and validate rules at load time.
- Reject placeholder secrets and invalid nested configuration at startup.

### Reliability and Performance

- Serialize client exchanges and queue pending bans across reconnects with bounded backpressure.
- Coalesce ban persistence through one worker and atomically replace the ban file.
- Preserve dirty updates, fail startup on corrupt ban storage, and drain service shutdown.
- Serialize log tailing, retain partial UTF-8 lines, and handle rotation and oversized input.
- Bound and expire threshold state; separate JSON conditions from the extracted IP field.

### Structure and Tests

- Centralize build properties and package versions; remove invalid version requests.
- Split transport messages, shared TLS validation, endpoint mapping and log monitor implementations.
- Move regression tests to `tests/FrpBan.Tests` and add real TLS/mTLS and HTTP coverage.
- Include client configuration and rules in build/publish output.
- Update configuration examples and deployment documentation.

## [1.0.0] - 2026-11-09

### Architecture Changes

- **BREAKING**: Removed HTTP REST API (kept only frps plugin interface)
- **BREAKING**: Removed fail2ban integration (client now has built-in ban capability)
- Extracted shared `FrpBan.Protocol` library
- Removed circular dependency between Client and Server projects
- Simplified logging configuration (hardcoded in code, only path and level configurable)

### Security Enhancements

- Added TLS connection rate limiting (10 requests/minute per IP)
- Fixed buffer overflow vulnerability (1MB max per connection)
- Reduced maximum message size from 10MB to 64KB
- Added CIDR prefix validation (0-32 for IPv4, 0-128 for IPv6)
- Enforced TLS certificate validation in production (cannot be disabled)
- Fixed JsonDocument resource leaks in message deserialization
- Removed plaintext token from HTTP headers (TLS-only authentication now)

### Performance Improvements

- Replaced `ReaderWriterLockSlim` with `ConcurrentDictionary` for lock-free reads
- Implemented `ArrayPool<byte>` for buffer management (reduced GC pressure)
- Replaced polling with `FileSystemWatcher` for log monitoring (reduced CPU usage)
- Fixed race conditions using atomic `Interlocked` operations
- Added connection pooling (max 100 concurrent connections)

### Changed

- Removed `AccessLogService` and associated fail2ban monitoring
- Removed `TokenAuthMiddleware` (HTTP API removed)
- Simplified `PluginSettings` configuration model
- Updated `appsettings.json` structure (removed Serilog section)

### Fixed

- JsonDocument disposal in Protocol message deserialization
- Race condition in `BanService._isDirty` flag management
- Buffer resize vulnerability in TCP protocol handler
- Missing CIDR range validation in IP allowlist

## [1.0.0] - 2026-11-05

### Added

- Initial release
- HTTP REST API for ban management
- TLS-secured TCP binary protocol
- Client-side log monitoring with rule engine
- frps plugin integration
- fail2ban integration (server & client)
- Serilog structured logging with auto-rotation
- Persistent ban storage (JSON)
- CIDR support for IP allowlists
- Auto-reconnect TLS client with exponential backoff
- Health check (ping/pong) protocol

[Unreleased]: https://github.com/799953468/frp-ban/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/799953468/frp-ban/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/799953468/frp-ban/releases/tag/v1.0.0
