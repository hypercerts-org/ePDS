#!/usr/bin/env bash
set -euo pipefail

: "${PROJECT:?Set PROJECT to the Railway project ID}"
: "${ENVIRONMENT:?Set ENVIRONMENT to the Railway environment ID}"
: "${SERVICE:?Set SERVICE to the Railway PDS service ID}"
: "${DIDS:?Set DIDS to the absolute DID inventory path}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
report_dir=${REPORT_DIR:-"$PWD/reports"}
workdir=${WORKDIR:-/app/packages/pds-core}

umask 077
mkdir -p "$report_dir"
chmod 700 "$report_dir"
report_path=$(mktemp "$report_dir/identity-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX.json")

if deno run --no-prompt --no-config --no-lock --allow-read="$DIDS" --allow-run=railway \
  "$script_dir/publish-identity-railway.ts" --project "$PROJECT" \
  --environment "$ENVIRONMENT" --service "$SERVICE" --workdir "$workdir" \
  --did-file "$DIDS" "$@" | tee "$report_path"; then
  status=0
else
  status=$?
fi

printf 'Saved report: %s\n' "$report_path" >&2
exit "$status"
