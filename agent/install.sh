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

for identity in "${SERVICE_NAME}" "${AGENT_USER}" "${AGENT_GROUP}"; do
  if [[ ! "${identity}" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]]; then
    echo "invalid service identity: ${identity}" >&2
    exit 1
  fi
  case "${identity,,}" in
    *honey* | *agent* | *trap* | *decoy* | *c2*)
      echo "refusing non-neutral service identity: ${identity}" >&2
      exit 1 ;;
  esac
done

case "${LEVEL}" in
  low | medium) ;;
  *)
    echo "LEVEL must be low or medium, got: ${LEVEL}" >&2
    exit 1
    ;;
esac

# Use the selected interpreter for both packaging and runtime compatibility.
# The bundle has neutral module paths and does not install the source tree.
"${PYTHON}" -c 'import zipapp'
echo "Installing ${SERVICE_NAME} in ${INSTALL_DIR}"
install -d -m 0755 "${INSTALL_DIR}" "${CONFIG_DIR}"
install -d -m 0700 "${STATE_DIR}"
"${PYTHON}" "${AGENT_DIR}/build_bundle.py" --level "${LEVEL}" --output "${INSTALL_DIR}/relay.pyz"
exec_start="${PYTHON} ${INSTALL_DIR}/relay.pyz"
# Remove only the source layout owned by previous versions of this installer.
# State and configuration live outside these directories and are preserved.
rm -rf "${INSTALL_DIR}/agent" "${INSTALL_DIR}/honeyforge_common" "${INSTALL_DIR}/__pycache__"
rm -f "${INSTALL_DIR}/honeyforge_low.py" "${INSTALL_DIR}/profile_runtime.py" \
  "${INSTALL_DIR}/process_masking.py" "${INSTALL_DIR}/relay.py"

# Preserve existing configuration and queue paths during an in-place upgrade.
if [ -f "${CONFIG_DIR}/relay.env" ]; then
  "${PYTHON}" - "${CONFIG_DIR}" <<'PYCONFIG'
import pathlib
import sys

config_dir = pathlib.Path(sys.argv[1])
env_file = config_dir / "relay.env"
content = env_file.read_text().replace("TRAP_SECRET_FILE=", "SERVICE_KEY_FILE=").replace("AGENT_VERSION=", "SERVICE_VERSION=")
old_key, new_key = config_dir / "trap_secret", config_dir / "relay.key"
old_setting = "SERVICE_KEY_FILE=" + str(old_key)
if old_setting in content.splitlines() and old_key.is_file() and not new_key.exists():
    old_key.rename(new_key)
    content = content.replace(old_setting, "SERVICE_KEY_FILE=" + str(new_key))
env_file.write_text(content)
PYCONFIG
fi
if [ ! -f "${CONFIG_DIR}/relay.env" ]; then
  cat > "${CONFIG_DIR}/relay.env" <<EOF
# Runtime configuration for the ${SERVICE_NAME} service.
# Replace with the real Control Center endpoint, Trap Secret and CA bundle.
CENTER_URL=https://assets.cdn-static.example
SERVICE_KEY_FILE=${CONFIG_DIR}/relay.key
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
  systemctl enable "${SERVICE_NAME}.service"
  systemctl restart "${SERVICE_NAME}.service"
fi

echo "Installed ${SERVICE_NAME}.service (${exec_start})"
