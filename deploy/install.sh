#!/usr/bin/env bash
# Install frp-ban as a systemd service on the FRP SERVER host.
#
# Usage:
#   sudo ./deploy/install.sh                # install service + dirs + user
#   sudo ./deploy/install.sh --uninstall    # reverse the install
#
# Assumes the self-contained binary has been published to ./publish/linux-x64
# (either built locally or downloaded from a CI release).
set -euo pipefail

INSTALL_DIR="/opt/frp-ban"
DATA_DIR="/var/lib/frp-ban"
LOG_DIR="/var/log/frp-ban"
ENV_FILE="/etc/frp-ban/env"
SERVICE_FILE="/etc/systemd/system/frp-ban.service"
USER_NAME="frp-ban"

# ── helpers ──────────────────────────────────────────────────────────────────
need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Must run as root: sudo $0 $*" >&2
    exit 1
  fi
}

user_exists() { id "$1" >/dev/null 2>&1; }

# ── install ──────────────────────────────────────────────────────────────────
do_install() {
  need_root

  local src_dir
  src_dir="$(cd "$(dirname "$0")/.." && pwd)"
  local publish_bin="${src_dir}/publish/linux-x64"
  if [[ ! -x "${publish_bin}/frp-ban" ]]; then
    echo "Binary not found at ${publish_bin}/frp-ban." >&2
    echo "Build it first:  dotnet publish src/FrpBan -c Release -r linux-x64 --self-contained -o ${publish_bin}" >&2
    exit 1
  fi

  # 1. system user
  if ! user_exists "${USER_NAME}"; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${USER_NAME}"
    echo "Created user ${USER_NAME}"
  fi

  # 2. directories
  install -d -o "${USER_NAME}" -g "${USER_NAME}" -m 0750 "${INSTALL_DIR}"
  install -d -o "${USER_NAME}" -g "${USER_NAME}" -m 0750 "${DATA_DIR}"
  install -d -o "${USER_NAME}" -g "${USER_NAME}" -m 0750 "${LOG_DIR}"
  install -d -o root -g "${USER_NAME}" -m 0750 "$(dirname "${ENV_FILE}")"

  # 3. binary + config
  install -o root -g "${USER_NAME}" -m 0755 "${publish_bin}/frp-ban" "${INSTALL_DIR}/frp-ban"
  # Ship the example config so the service starts; admin edits afterward.
  if [[ -f "${src_dir}/src/FrpBan/appsettings.json" ]]; then
    install -o "${USER_NAME}" -g "${USER_NAME}" -m 0640 "${src_dir}/src/FrpBan/appsettings.json" "${INSTALL_DIR}/appsettings.json"
  fi

  # 4. env file (secrets) — only create if missing
  if [[ ! -f "${ENV_FILE}" ]]; then
    cat > "${ENV_FILE}" <<'EOF'
# frp-ban runtime environment — owned by root:frp-ban, mode 0640
# Override appsettings.json values here. Example:
# ASPNETCORE_URLS=http://0.0.0.0:9000
# PluginSettings__Token=CHANGE_ME_TO_A_LONG_RANDOM_SECRET
EOF
    chown root:"${USER_NAME}" "${ENV_FILE}"
    chmod 0640 "${ENV_FILE}"
    echo "Created ${ENV_FILE} — edit it and set your token before starting the service."
  fi

  # 5. service unit
  install -m 0644 "${src_dir}/deploy/frp-ban.service" "${SERVICE_FILE}"

  systemctl daemon-reload
  systemctl enable --now frp-ban.service
  echo
  echo "Installed. Status:"
  systemctl --no-pager --full status frp-ban.service || true
  echo
  echo "Next: edit ${ENV_FILE} (or ${INSTALL_DIR}/appsettings.json) and:"
  echo "  sudo systemctl restart frp-ban"
}

# ── uninstall ──────────────────────────────────────────────────────────────────
do_uninstall() {
  need_root
  systemctl disable --now frp-ban.service 2>/dev/null || true
  rm -f "${SERVICE_FILE}"
  systemctl daemon-reload

  read -r -p "Remove ${INSTALL_DIR}, ${DATA_DIR}, ${LOG_DIR}, ${ENV_FILE}, and user ${USER_NAME}? [y/N] " ans
  if [[ "${ans,,}" == "y" ]]; then
    rm -rf "${INSTALL_DIR}" "${DATA_DIR}" "${LOG_DIR}"
    rm -rf "$(dirname "${ENV_FILE}")"
    if user_exists "${USER_NAME}"; then
      userdel "${USER_NAME}" 2>/dev/null || true
    fi
    echo "Removed."
  else
    echo "Kept data dirs and user; only the unit file was removed."
  fi
}

# ── entry ────────────────────────────────────────────────────────────────────
case "${1:-install}" in
  install)        do_install ;;
  --uninstall|uninstall) do_uninstall ;;
  *) echo "Usage: $0 [install|--uninstall]" >&2; exit 1 ;;
esac
