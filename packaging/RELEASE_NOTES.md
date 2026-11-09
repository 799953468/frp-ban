# FRP Ban

Self-contained server builds: the .NET runtime, configuration example and license
are included. Choose the package matching your operating system and CPU.

| Platform | Architectures | Downloads |
| --- | --- | --- |
| Windows | x64, ARM64 | Portable `.zip` |
| macOS | Intel x64, Apple Silicon ARM64 | Portable `.tar.gz` |
| Debian / Ubuntu | x64, ARM64 | `.deb` |
| Fedora / RHEL / Rocky / AlmaLinux / openSUSE | x64, ARM64 | `.rpm` |
| Arch Linux / Arch Linux ARM | x64, ARM64 | `.pkg.tar.zst` |
| Alpine Linux (musl) | x64, ARM64 | `.apk` |
| Linux portable (glibc or musl) | x64, ARM64 | `.tar.gz` |

See `docs/RELEASING.md` in this tag for installation commands, runtime library
requirements, configuration and CI runner setup. The client is not part of these
server packages.

Configure a private token and your own TLS certificate before starting the server.
Windows and macOS downloads are archives: extract, configure and run them.
Linux packages do not start the server automatically. Alpine packages are unsigned.
Verify downloads using the attached `SHA256SUMS`.
