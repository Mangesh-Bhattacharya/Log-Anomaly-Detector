#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-/usr/local/bin/sentinel}"
install -m 0755 "$(dirname "$0")/../sentinel.sh" "$TARGET"
echo "Installed to ${TARGET}"
