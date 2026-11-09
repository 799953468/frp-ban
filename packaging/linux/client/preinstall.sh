#!/bin/sh
set -eu
if command -v useradd >/dev/null 2>&1; then
    getent group frp-ban-client >/dev/null 2>&1 || groupadd --system frp-ban-client
    if ! id -u frp-ban-client >/dev/null 2>&1; then
        useradd --system --gid frp-ban-client --home-dir / --no-create-home --shell /sbin/nologin frp-ban-client
    fi
else
    # Alpine's BusyBox account tools.
    grep -q '^frp-ban-client:' /etc/group || addgroup -S frp-ban-client
    if ! id -u frp-ban-client >/dev/null 2>&1; then
        adduser -S -D -H -h / -s /sbin/nologin -G frp-ban-client frp-ban-client
    fi
fi
