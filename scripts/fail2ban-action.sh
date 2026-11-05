#!/usr/bin/env bash
# fail2ban action script — runs on the frpc CLIENT machine.
#
# When fail2ban detects an intrusion attempt locally (e.g. SSH brute-force),
# it calls this script to push the offending IP to the frp-ban server so
# that IP is also blocked from connecting through the frp tunnel.
#
# Usage (called by fail2ban action definition):
#   ban:   ./fail2ban-action.sh ban   <offending-ip>
#   unban: ./fail2ban-action.sh unban <offending-ip>
#
# Required environment variables (set in /etc/fail2ban/action.d/frp-ban.local
# or pass directly):
#   FRP_BAN_URL   — base URL of the frp-ban server, e.g. https://frps.example.com:9000
#   FRP_BAN_TOKEN — bearer token configured in frp-ban appsettings.json

set -euo pipefail

ACTION="${1:?Usage: $0 ban|unban <ip>}"
TARGET_IP="${2:?Usage: $0 ban|unban <ip>}"

FRP_BAN_URL="${FRP_BAN_URL:?FRP_BAN_URL is not set}"
FRP_BAN_TOKEN="${FRP_BAN_TOKEN:?FRP_BAN_TOKEN is not set}"

case "$ACTION" in
  ban)
    curl -sf -X POST "${FRP_BAN_URL}/api/bans" \
      -H "Authorization: Bearer ${FRP_BAN_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"ip\":\"${TARGET_IP}\",\"reason\":\"fail2ban from $(hostname)\",\"durationSeconds\":3600}"
    echo "Banned ${TARGET_IP} on frp-ban server"
    ;;
  unban)
    curl -sf -X DELETE "${FRP_BAN_URL}/api/bans/${TARGET_IP}" \
      -H "Authorization: Bearer ${FRP_BAN_TOKEN}"
    echo "Unbanned ${TARGET_IP} on frp-ban server"
    ;;
  *)
    echo "Unknown action: ${ACTION}" >&2
    exit 1
    ;;
esac
