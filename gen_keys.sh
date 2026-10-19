#!/usr/bin/env bash
set -euo pipefail

# Generates RSA keys for my-oauth with sensible defaults.
# By default it reads conf.json:rsaPrivateKeyPath and writes there,
# so no extra server-side configuration is needed.
#
# Usage:
#   ./gen_rsa.sh
#   ./gen_rsa.sh /path/to/private.pem
#   RSA_BITS=4096 ./gen_rsa.sh
#   FORCE=1 ./gen_rsa.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BITS="${RSA_BITS:-4096}"
FORCE_WRITE="${FORCE:-0}"
CONF_FILE="conf.json"

extract_private_path_from_conf() {
  if [[ ! -f "$CONF_FILE" ]]; then
    return 1
  fi
  local line
  line="$(grep -E '"rsaPrivateKeyPath"[[:space:]]*:' "$CONF_FILE" || true)"
  if [[ -z "$line" ]]; then
    return 1
  fi
  echo "$line" | sed -E 's/.*"rsaPrivateKeyPath"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/'
}

PRIVATE_PATH="${1:-}"
if [[ -z "$PRIVATE_PATH" ]]; then
  PRIVATE_PATH="$(extract_private_path_from_conf || true)"
fi
if [[ -z "$PRIVATE_PATH" ]]; then
  PRIVATE_PATH="oauth.private.pem"
fi

if [[ "$PRIVATE_PATH" != /* ]]; then
  PRIVATE_PATH="$SCRIPT_DIR/$PRIVATE_PATH"
fi

PRIVATE_DIR="$(dirname "$PRIVATE_PATH")"
mkdir -p "$PRIVATE_DIR"

if [[ "$PRIVATE_PATH" == *.pem ]]; then
  PUBLIC_PATH="${PRIVATE_PATH%.pem}.public.pem"
else
  PUBLIC_PATH="${PRIVATE_PATH}.public.pem"
fi

if [[ -f "$PRIVATE_PATH" && "$FORCE_WRITE" != "1" ]]; then
  echo "Refusing to overwrite existing private key: $PRIVATE_PATH"
  echo "Set FORCE=1 to overwrite."
  exit 1
fi

openssl genpkey \
  -algorithm RSA \
  -pkeyopt "rsa_keygen_bits:${BITS}" \
  -out "$PRIVATE_PATH"

openssl pkey \
  -in "$PRIVATE_PATH" \
  -pubout \
  -out "$PUBLIC_PATH"

chmod 600 "$PRIVATE_PATH"
chmod 644 "$PUBLIC_PATH"

echo "Generated:"
echo "  Private key: $PRIVATE_PATH"
echo "  Public key : $PUBLIC_PATH"
echo
echo "For conf.json:"
echo "  \"rsaPrivateKeyPath\": \"${PRIVATE_PATH}\""
