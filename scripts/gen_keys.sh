#!/usr/bin/env bash
set -euo pipefail

# Generates RSA keys for my-oauth with sensible defaults.
# MyOAuth auto-generates the signing key on first boot, so this script is only
# for operators who prefer to manage the key explicitly. It defaults to
# oauth.private.pem and writes a matching public key alongside.
#
# Usage:
#   ./scripts/gen_keys.sh
#   ./scripts/gen_keys.sh /path/to/private.pem
#   RSA_BITS=4096 ./scripts/gen_keys.sh
#   FORCE=1 ./scripts/gen_keys.sh
#   MYOAUTH_RSA_PRIVATE_KEY_PATH=/data/oauth.private.pem ./scripts/gen_keys.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BITS="${RSA_BITS:-4096}"
FORCE_WRITE="${FORCE:-0}"

# Path resolution order: first argument, then MYOAUTH_RSA_PRIVATE_KEY_PATH,
# then the built-in default that matches Configuration.applyDefaults.
PRIVATE_PATH="${1:-${MYOAUTH_RSA_PRIVATE_KEY_PATH:-oauth.private.pem}}"

if [[ "$PRIVATE_PATH" != /* ]]; then
  PRIVATE_PATH="$REPO_ROOT/$PRIVATE_PATH"
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
echo "Point MyOAuth at it with:"
echo "  MYOAUTH_RSA_PRIVATE_KEY_PATH=${PRIVATE_PATH}"
