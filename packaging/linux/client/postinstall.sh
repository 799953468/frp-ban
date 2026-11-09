#!/bin/sh
set -eu
mkdir -p /var/log/frp-ban-client /etc/frp-ban-client/certs /etc/frp-ban-client/rules.d
chown frp-ban-client:frp-ban-client /var/log/frp-ban-client
chmod 750 /var/log/frp-ban-client
chown root:frp-ban-client /etc/frp-ban-client /etc/frp-ban-client/certs /etc/frp-ban-client/rules.d
chmod 750 /etc/frp-ban-client /etc/frp-ban-client/certs /etc/frp-ban-client/rules.d
chown root:frp-ban-client /etc/frp-ban-client/appsettings.json
chmod 640 /etc/frp-ban-client/appsettings.json
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
echo 'Configure /etc/frp-ban-client/appsettings.json, TLS trust and rules.d; grant frp-ban-client read access to monitored logs before starting the service.'
