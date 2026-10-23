#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ " $* " == *" --help "* ]]; then
  exec deno run --no-prompt --cached-only --no-config --no-lock --node-modules-dir=none "$script_dir/rotate-plc-key.ts" --help
fi

: "${PLC_URL:?Set PLC_URL to the trusted PLC directory URL}"
: "${DIDS:?Set DIDS to the absolute DID inventory path}"
: "${OLD:?Set OLD to the absolute old-key path}"
: "${NEW:?Set NEW to the absolute new-key path}"
REPORT_DIR="${REPORT_DIR:-./reports}"
host="${PLC_URL#*://}"
host="${host%%/*}"

exec deno run --no-prompt --cached-only --no-config --no-lock --node-modules-dir=none \
  --allow-sys=hostname,uid --allow-net="$host" \
  --allow-read="$DIDS,$OLD,$NEW,$REPORT_DIR" --allow-write="$REPORT_DIR" \
  --allow-env=LOG_SYSTEMS,LOG_ENABLED,LOG_LEVEL,LOG_DESTINATION,PLC_ROTATION_OLD_KEY_HEX,PLC_ROTATION_NEW_KEY_HEX \
  "$script_dir/rotate-plc-key.ts" --plc-url "$PLC_URL" \
  --did-file "$DIDS" --old-key-file "$OLD" --new-key-file "$NEW" \
  --report-dir "$REPORT_DIR" "$@"
