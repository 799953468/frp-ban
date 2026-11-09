# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[2.0.0]: https://github.com/your-repo/frp-ban/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/your-repo/frp-ban/releases/tag/v1.0.0
