#!/bin/sh
set -eu
mkdir -p /var/lib/frp-ban /var/log/frp-ban /etc/frp-ban/certs
chown frp-ban:frp-ban /var/lib/frp-ban /var/log/frp-ban
chmod 750 /var/lib/frp-ban /var/log/frp-ban
chown root:frp-ban /etc/frp-ban /etc/frp-ban/certs
chmod 750 /etc/frp-ban /etc/frp-ban/certs
chown root:frp-ban /etc/frp-ban/appsettings.json
chmod 640 /etc/frp-ban/appsettings.json
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
echo 'Configure /etc/frp-ban/appsettings.json and your TLS certificate before starting frp-ban.'
