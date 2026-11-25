# v2.0.0

v2.0.0 introduces protocol 2.0 and makes the client more reliable when the
server is unreachable. **This is a breaking release: upgrade the server and all
clients together.**

## Breaking Changes

- **Protocol 2.0:** `BAN_RESPONSE` now carries a `Status` instead of `Success`:
  `Applied`, `AlreadyBanned`, `Exempt`, `Invalid`, `CapacityReached` or
  `StorageUnavailable`. A 2.0 server rejects 1.x clients at `HELLO`, and a 2.0
  client cannot talk to a 1.x server.
- **Stricter address lists:** `AllowedPluginAddresses` and
  `WebUi.AllowedAddresses` are validated like
  `ExemptAddresses`. Invalid entries and CIDRs with host bits set (for example
  `10.0.0.1/8`; use `10.0.0.0/8`) now fail startup, and the error names the
  setting.
- **Decimal rule integers:** Rule integers with a leading zero are decimal.
  `windowSeconds: 0600` now means 600 seconds instead of octal 384.
- **Client TLS is always on:** `ClientSettings.Tls.Enabled` is no longer read
  and can be removed from client configuration.

## New Features

- **IPv6 TLS listener:** The new `PluginSettings.Tls.ListenAddress` setting
  controls the server TLS listener address. The default `::` accepts both IPv6
  and IPv4 clients; previously the listener accepted IPv4 only.
- **Command-line configuration:** The client now runs on the .NET Generic Host
  and accepts configuration overrides as command-line arguments, for example
  `--ClientSettings:ServerAddress=frps.example.com`.

## Fixes

- Log monitors start immediately instead of waiting for the first successful
  connection, so attack lines written while the server is unreachable are
  queued instead of skipped.
- A ban that the server applied but could not persist (`StorageUnavailable`) is
  retried by the client instead of being dropped as rejected.
- An unauthenticated peer that sends an unknown frame type no longer produces
  an Error log entry.
- A management request received during shutdown no longer reports "Ban
  capacity reached".

## Other Changes

- Rules are validated and compiled once at load time, and each rule owns its
  threshold counters. Invalid rules and unreadable rule files are still logged
  and skipped.
- Startup validation errors are reported once, concisely. If a client
  component fails or reconnection is exhausted, the client exits with code 1 so
  the service manager can restart it.
- frps `/handler` callbacks are logged at Debug instead of two Information lines
  per user connection.
- Dependencies use stable releases: Serilog 4.4.0, Serilog.Sinks.File 7.0.0,
  Serilog.AspNetCore 11.0.0 and Serilog.Extensions.Logging 11.0.0.

## Upgrade Notes

1. Stop all clients, then upgrade and restart the server.
2. Before starting the server, check that every `AllowedPluginAddresses`,
   `WebUi.AllowedAddresses` and `ExemptAddresses` CIDR uses its network address.
3. If the TLS listener must remain IPv4-only, set `Tls.ListenAddress` to
   `0.0.0.0`.
4. Upgrade the clients, remove `ClientSettings.Tls.Enabled`, and check rules for
   integers with leading zeros.
5. Persisted ban files, rule files and the Web UI configuration are unchanged
   and need no migration.
