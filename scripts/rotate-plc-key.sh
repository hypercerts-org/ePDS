#!/usr/bin/env bash
set -euo pipefail

: "${PLC_URL:?Set PLC_URL to the trusted PLC directory URL}"
: "${DIDS:?Set DIDS to the absolute DID inventory path}"
: "${OLD:?Set OLD to the absolute old-key path}"
: "${NEW:?Set NEW to the absolute new-key path}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
report_dir=${REPORT_DIR:-"$PWD/reports"}
net_host=${PLC_URL#https://}
net_host=${net_host#http://}

umask 077
mkdir -p "$report_dir"
chmod 700 "$report_dir"
report_path=$(mktemp "$report_dir/rotation-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX.json")

if deno run --no-prompt --cached-only --no-config --no-lock --node-modules-dir=none \
  --allow-sys=hostname,uid --allow-net="$net_host" \
  --allow-read="$DIDS,$OLD,$NEW" \
  --allow-env=LOG_SYSTEMS,LOG_ENABLED,LOG_LEVEL,LOG_DESTINATION,PLC_ROTATION_OLD_KEY_HEX,PLC_ROTATION_NEW_KEY_HEX \
  "$script_dir/rotate-plc-key.ts" --plc-url "$PLC_URL" --did-file "$DIDS" \
  --old-key-file "$OLD" --new-key-file "$NEW" "$@" | tee "$report_path"; then
  status=0
else
  status=$?
fi

printf 'Saved report: %s\n' "$report_path" >&2
exit "$status"
