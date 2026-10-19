#!/usr/bin/env bash
set -euo pipefail

# Generates RSA keys for myoauth with sensible defaults.
# MyOAuth auto-generates the signing key on first boot, so this script is only
# for operators who prefer to manage the key explicitly. It defaults to
# oauth.private.pem and writes a matching public key alongside.
#
# Usage:
#   ./scripts/gen_keys.sh
#   ./scripts/gen_keys.sh /path/to/private.pem
#   RSA_BITS=4096 ./scripts/gen_keys.sh
#   FORCE=1 ./scripts/gen_keys.sh
#   MYOAUTH_RSA_PRIVATE_KEY_PATH=/path/to/private.pem ./scripts/gen_keys.sh
#
# All paths here are HOST paths. The value MyOAuth itself needs is the
# *container* path (see the final hint printed by this script).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BITS="${RSA_BITS:-4096}"
FORCE_WRITE="${FORCE:-0}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "error: 'openssl' is required to generate RSA keys but was not found on PATH." >&2
  echo "Install it (e.g. apt-get install openssl / apk add openssl) and retry." >&2
  exit 1
fi

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

# Create the key material unreadable to other users from the start; no
# separate chmod on the private key (which would race the write).
umask 077

openssl genpkey \
  -algorithm RSA \
  -pkeyopt "rsa_keygen_bits:${BITS}" \
  -out "$PRIVATE_PATH"

openssl pkey \
  -in "$PRIVATE_PATH" \
  -pubout \
  -out "$PUBLIC_PATH"

# The public key is not a secret; restore normal readability for convenience.
chmod 644 "$PUBLIC_PATH"

echo "Generated:"
echo "  Private key: $PRIVATE_PATH"
echo "  Public key : $PUBLIC_PATH"
echo
echo "Point MyOAuth at it with the CONTAINER path (not the host path above):"
echo "  1. copy the key into the directory mounted at /data, e.g.:"
echo "       cp '$PRIVATE_PATH' ./data/oauth.private.pem"
echo "       chown 100:101 ./data/oauth.private.pem   # container uid:gid"
echo "  2. set the container path in .env:"
echo "       MYOAUTH_RSA_PRIVATE_KEY_PATH=/data/oauth.private.pem"
echo "     (that is already the image default; only needed if you rename it)"
