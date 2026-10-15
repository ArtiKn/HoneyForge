#!/usr/bin/env bash
# Install the Trap Agent as a neutral system service (requirement MASK-4).
#
# The service name, system user, process title and install directory all share
# the same inconspicuous name (`syslog-relay` by default). Override
# SERVICE_NAME, LEVEL=low|medium, or any *_DIR variable for a different layout.
set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SERVICE_NAME="${SERVICE_NAME:-syslog-relay}"
LEVEL="${LEVEL:-low}"
INSTALL_DIR="${INSTALL_DIR:-/usr/lib/${SERVICE_NAME}}"
STATE_DIR="${STATE_DIR:-/var/lib/${SERVICE_NAME}}"
CONFIG_DIR="${CONFIG_DIR:-/etc/${SERVICE_NAME}}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
AGENT_USER="${AGENT_USER:-${SERVICE_NAME}}"
AGENT_GROUP="${AGENT_GROUP:-${AGENT_USER}}"
PYTHON="${PYTHON:-/usr/bin/python3}"
SKIP_USER="${SKIP_USER:-0}"
SKIP_SYSTEMD="${SKIP_SYSTEMD:-0}"

case "${SERVICE_NAME,,}" in
  *honey* | *agent* | *trap* | *decoy* | *c2*)
    echo "refusing non-neutral SERVICE_NAME: ${SERVICE_NAME}" >&2
    exit 1
    ;;
esac

case "${LEVEL}" in
  low | medium) ;;
  *)
    echo "LEVEL must be low or medium, got: ${LEVEL}" >&2
    exit 1
    ;;
esac

common_source="${AGENT_DIR}/../honeyforge_common"
if [ ! -d "${common_source}" ]; then
  echo "honeyforge_common not found at ${common_source}" >&2
  exit 1
fi

echo "Installing ${LEVEL} Trap Agent as ${SERVICE_NAME} in ${INSTALL_DIR}"

install -d -m 0755 "${INSTALL_DIR}" "${CONFIG_DIR}"
install -d -m 0700 "${STATE_DIR}"

rm -rf "${INSTALL_DIR}/honeyforge_common"
cp -R "${common_source}" "${INSTALL_DIR}/honeyforge_common"
find "${INSTALL_DIR}/honeyforge_common" -name '__pycache__' -type d -prune -exec rm -rf {} +

if [ "${LEVEL}" = "low" ]; then
  install -m 0644 "${AGENT_DIR}/low/honeyforge_low.py" "${INSTALL_DIR}/honeyforge_low.py"
  install -m 0644 "${AGENT_DIR}/low/profile_runtime.py" "${INSTALL_DIR}/profile_runtime.py"
  install -m 0644 "${AGENT_DIR}/low/process_masking.py" "${INSTALL_DIR}/process_masking.py"
  # Neutral entry point: the file on disk is not called main.py.
  install -m 0644 "${AGENT_DIR}/low/main.py" "${INSTALL_DIR}/relay.py"
  exec_start="${PYTHON} ${INSTALL_DIR}/relay.py"
else
  install -d -m 0755 "${INSTALL_DIR}/agent/low" "${INSTALL_DIR}/agent/medium"
  install -m 0644 "${AGENT_DIR}/__init__.py" "${INSTALL_DIR}/agent/__init__.py"
  for module in honeyforge_low profile_runtime process_masking __init__; do
    install -m 0644 "${AGENT_DIR}/low/${module}.py" "${INSTALL_DIR}/agent/low/${module}.py"
  done
  install -m 0644 "${AGENT_DIR}/medium/main.py" "${INSTALL_DIR}/agent/medium/main.py"
  install -m 0644 "${AGENT_DIR}/medium/http_service.py" "${INSTALL_DIR}/agent/medium/http_service.py"
  exec_start="${PYTHON} -m agent.medium.main"
fi

if [ ! -f "${CONFIG_DIR}/relay.env" ]; then
  cat > "${CONFIG_DIR}/relay.env" <<EOF
# Runtime configuration for the ${SERVICE_NAME} service.
# Replace with the real Control Center endpoint, Trap Secret and CA bundle.
CENTER_URL=https://assets.cdn-static.example
TRAP_SECRET_FILE=${CONFIG_DIR}/trap_secret
CENTER_CA_FILE=${CONFIG_DIR}/center-ca.crt
EVENT_QUEUE_PATH=${STATE_DIR}/events.sqlite3
PROCESS_MASK_NAME=${SERVICE_NAME}
EOF
  chmod 0600 "${CONFIG_DIR}/relay.env"
fi

if [ "${SKIP_USER}" != "1" ]; then
  if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --home-dir "${STATE_DIR}" \
      --shell /usr/sbin/nologin "${AGENT_USER}"
  fi
  chown -R "${AGENT_USER}:${AGENT_GROUP}" "${INSTALL_DIR}" "${STATE_DIR}" "${CONFIG_DIR}"
fi

unit_source="${AGENT_DIR}/systemd/syslog-relay.service"
unit_target="${UNIT_DIR}/${SERVICE_NAME}.service"
install -d -m 0755 "${UNIT_DIR}"
sed \
  -e "s#@@SERVICE_USER@@#${AGENT_USER}#g" \
  -e "s#@@SERVICE_GROUP@@#${AGENT_GROUP}#g" \
  -e "s#@@CONFIG_DIR@@#${CONFIG_DIR}#g" \
  -e "s#@@INSTALL_DIR@@#${INSTALL_DIR}#g" \
  -e "s#@@STATE_DIR@@#${STATE_DIR}#g" \
  -e "s#@@EXEC_START@@#${exec_start}#g" \
  "${unit_source}" > "${unit_target}"
chmod 0644 "${unit_target}"

if [ "${SKIP_SYSTEMD}" != "1" ]; then
  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}.service"
fi

echo "Installed ${SERVICE_NAME}.service (${exec_start})"
