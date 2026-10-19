#!/usr/bin/env bash
set -euo pipefail

# Generates the bcrypt hash for MYOAUTH_ADMIN_PASSWORD.
# MyOAuth verifies the admin password with bcrypt cost 12. This script uses the
# project's own util.BCryptPassword through `go run` so the format and cost
# match the server exactly; when no Go toolchain is installed it falls back to
# `htpasswd` (apache2-utils / httpd-tools), whose $2y$ output MyOAuth accepts.
#
# Usage:
#   ./scripts/gen_bcrypt.sh                        # prompt (hidden input)
#   printf '%s' 'YourStrongPassword' | ./scripts/gen_bcrypt.sh
#   ./scripts/gen_bcrypt.sh 'YourStrongPassword'   # visible in shell history
#                                                  # and the process list

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PASSWORD="${1:-}"
if [[ -z "$PASSWORD" ]]; then
  if [[ -t 0 ]]; then
    read -rsp "Admin password: " PASSWORD
    echo
    read -rsp "Confirm password: " CONFIRM
    echo
    if [[ "$PASSWORD" != "$CONFIRM" ]]; then
      echo "Passwords do not match." >&2
      exit 1
    fi
  else
    # `printf '%s' ... | script` sends no trailing newline, which makes `read`
    # return non-zero at EOF even though it captured the value.
    IFS= read -r PASSWORD || true
  fi
fi

if [[ -z "$PASSWORD" ]]; then
  echo "Refusing to hash an empty password." >&2
  exit 1
fi

if command -v go >/dev/null 2>&1; then
  # `go run` needs the package inside the module for the util import to resolve,
  # and the go tool ignores dot-prefixed directories, hence the visible name.
  TMP_DIR="$(mktemp -d "$REPO_ROOT/bcrypt_tmp.XXXXXX")"
  trap 'rm -rf "$TMP_DIR"' EXIT

  cat > "$TMP_DIR/main.go" <<'EOF'
package main

import (
	"fmt"
	"os"

	"github.com/undefinednil/myoauth/util"
)

func main() {
	hash, err := util.BCryptPassword(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Println(hash)
}
EOF

  cd "$REPO_ROOT"
  HASH="$(go run "./$(basename "$TMP_DIR")" "$PASSWORD")"
elif command -v htpasswd >/dev/null 2>&1; then
  HASH="$(htpasswd -bnBC 12 "" "$PASSWORD" | tr -d ':\r\n')"
else
  echo "error: neither 'go' nor 'htpasswd' is available." >&2
  echo "Install a Go toolchain (https://go.dev/dl/) or apache2-utils / httpd-tools, then retry." >&2
  exit 1
fi

echo
echo "Hash (paste into .env as MYOAUTH_ADMIN_PASSWORD):"
echo "  $HASH"
echo
echo "A bcrypt hash contains '\$' characters; if your Compose version warns about"
echo "interpolation, escape each '\$' as '\$\$' in .env (env_file values themselves"
echo "are passed through literally)."
