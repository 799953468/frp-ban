#!/bin/sh
# Keep configuration, TLS certificates, logs, ban data and the service account.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
