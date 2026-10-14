#!/usr/bin/env bash
# Generate self-signed TLS certificates for Nginx (task 6.5).
# Writes deploy/nginx/certs/center.crt and center.key; use --force to overwrite.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$(cd "${SCRIPT_DIR}/../nginx" && pwd)/certs"
CERT_FILE="${CERT_DIR}/center.crt"
KEY_FILE="${CERT_DIR}/center.key"

DAYS="${CERT_DAYS:-365}"
SUBJECT="${CERT_SUBJECT:-/CN=assets.cdn-static.example}"
SAN="${CERT_SAN:-DNS:localhost,DNS:assets.cdn-static.example,IP:127.0.0.1}"

FORCE=0
for arg in "$@"; do
  case "${arg}" in
    -f|--force) FORCE=1 ;;
    -h|--help)
      sed -n '2,3p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "[gen_certs] unknown option: ${arg}" >&2
      exit 2
      ;;
  esac
done

command -v openssl >/dev/null 2>&1 || {
  echo "[gen_certs] openssl not found in PATH" >&2
  exit 1
}

mkdir -p "${CERT_DIR}"

if [[ -f "${CERT_FILE}" && -f "${KEY_FILE}" && "${FORCE}" -eq 0 ]]; then
  echo "[gen_certs] certificates already exist, use --force to regenerate"
  exit 0
fi

openssl req -x509 -newkey rsa:4096 -nodes \
  -days "${DAYS}" \
  -keyout "${KEY_FILE}" \
  -out "${CERT_FILE}" \
  -subj "${SUBJECT}" \
  -addext "subjectAltName=${SAN}" \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

chmod 600 "${KEY_FILE}"
chmod 644 "${CERT_FILE}"

echo "[gen_certs] wrote ${CERT_FILE} and ${KEY_FILE}"
