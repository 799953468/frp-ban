#!/bin/sh
# Preserve a running service during package upgrades.
case "${1:-remove}" in
    remove|deconfigure|0|[0-9]*.*)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop frp-ban-client.service || true
            systemctl disable frp-ban-client.service || true
        elif command -v rc-service >/dev/null 2>&1; then
            rc-service frp-ban-client stop || true
            rc-update del frp-ban-client default || true
        fi
        ;;
esac
