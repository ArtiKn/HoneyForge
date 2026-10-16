#!/usr/bin/env bash
# Generate a local demo CA and a CA-signed TLS certificate for Nginx.
# Writes ca.crt/ca.key and center.crt/center.key; use --force to overwrite.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${CERT_DIR:-$(cd "${SCRIPT_DIR}/../nginx" && pwd)/certs}"
CA_CERT_FILE="${CERT_DIR}/ca.crt"
CA_KEY_FILE="${CERT_DIR}/ca.key"
CERT_FILE="${CERT_DIR}/center.crt"
KEY_FILE="${CERT_DIR}/center.key"

DAYS="${CERT_DAYS:-365}"
CA_DAYS="${CA_DAYS:-3650}"
# This CA is mounted onto every Trap host so the Agent can verify the Control
# Center, which means its subject line must not name the platform (MASK-4).
CA_SUBJECT="${CA_SUBJECT:-/CN=Local Demo CA}"
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

if [[ -f "${CA_CERT_FILE}" && -f "${CA_KEY_FILE}" \
      && -f "${CERT_FILE}" && -f "${KEY_FILE}" && "${FORCE}" -eq 0 ]]; then
  echo "[gen_certs] certificates already exist, use --force to regenerate"
  exit 0
fi

if [[ "${FORCE}" -eq 0 ]] && [[ -e "${CA_CERT_FILE}" || -e "${CA_KEY_FILE}" \
      || -e "${CERT_FILE}" || -e "${KEY_FILE}" ]]; then
  echo "[gen_certs] partial certificate bundle; use --force to rotate it explicitly" >&2
  exit 1
fi

openssl req -x509 -newkey rsa:4096 -nodes -sha256 \
  -days "${CA_DAYS}" \
  -keyout "${CA_KEY_FILE}" \
  -out "${CA_CERT_FILE}" \
  -subj "${CA_SUBJECT}" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

CSR_FILE="$(mktemp "${CERT_DIR}/center.XXXXXX.csr")"
EXT_FILE="$(mktemp "${CERT_DIR}/center.XXXXXX.ext")"
trap 'rm -f "${CSR_FILE}" "${EXT_FILE}"' EXIT

openssl req -new -newkey rsa:4096 -nodes -sha256 \
  -keyout "${KEY_FILE}" \
  -out "${CSR_FILE}" \
  -subj "${SUBJECT}"

printf '%s\n' \
  "basicConstraints=critical,CA:FALSE" \
  "subjectAltName=${SAN}" \
  "keyUsage=critical,digitalSignature,keyEncipherment" \
  "extendedKeyUsage=serverAuth" >"${EXT_FILE}"

openssl x509 -req -sha256 \
  -in "${CSR_FILE}" \
  -CA "${CA_CERT_FILE}" \
  -CAkey "${CA_KEY_FILE}" \
  -CAcreateserial \
  -days "${DAYS}" \
  -extfile "${EXT_FILE}" \
  -out "${CERT_FILE}"

chmod 600 "${CA_KEY_FILE}" "${KEY_FILE}"
chmod 644 "${CA_CERT_FILE}" "${CERT_FILE}"

echo "[gen_certs] wrote local CA and server certificate in ${CERT_DIR}"
