#!/bin/sh
# RPM passes 0 on removal, 1 on upgrade; dpkg passes remove/upgrade.
# Arch/Alpine do not call preremove for upgrades. Preserve a running service then.
case "${1:-remove}" in
    remove|deconfigure|0|[0-9]*.*)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop frp-ban.service || true
            systemctl disable frp-ban.service || true
        elif command -v rc-service >/dev/null 2>&1; then
            rc-service frp-ban stop || true
            rc-update del frp-ban default || true
        fi
        ;;
esac
