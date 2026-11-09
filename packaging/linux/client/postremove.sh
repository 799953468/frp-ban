#!/bin/sh
# Keep configuration, rules, TLS certificates, logs and the service account.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
