#!/bin/sh
set -eu
if command -v useradd >/dev/null 2>&1; then
    getent group frp-ban >/dev/null 2>&1 || groupadd --system frp-ban
    if ! id -u frp-ban >/dev/null 2>&1; then
        useradd --system --gid frp-ban --home-dir /var/lib/frp-ban --no-create-home --shell /sbin/nologin frp-ban
    fi
else
    # Alpine's BusyBox account tools.
    grep -q '^frp-ban:' /etc/group || addgroup -S frp-ban
    if ! id -u frp-ban >/dev/null 2>&1; then
        adduser -S -D -H -h /var/lib/frp-ban -s /sbin/nologin -G frp-ban frp-ban
    fi
fi
