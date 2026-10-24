#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
for arg in "$@"; do
  if [[ "$arg" == --help ]]; then
    exec deno run --no-prompt --no-config --no-lock "$script_dir/publish-identity-docker.ts" --help
  fi
done
args=()
[[ -z "${CONTAINER:-}" ]] || args+=(--container "$CONTAINER")
[[ -z "${DIDS:-}" ]] || args+=(--did-file "$DIDS")
[[ -z "${EXEC_USER:-}" ]] || args+=(--user "$EXEC_USER")
args+=(--workdir "${WORKDIR:-/app/packages/pds-core}" --report-dir "${REPORT_DIR:-$PWD/reports}" "$@")
read_path=${DIDS:-}
resume_path=''
report_dir=${REPORT_DIR:-$PWD/reports}
for ((i=0; i<${#args[@]}; i++)); do
  case "${args[i]}" in
    --did-file) read_path=${args[i+1]:-} ;;
    --did-file=*) read_path=${args[i]#--did-file=} ;;
    --resume-report) resume_path=${args[i+1]:-} ;;
    --resume-report=*) resume_path=${args[i]#--resume-report=} ;;
    --report-dir) report_dir=${args[i+1]:-} ;;
    --report-dir=*) report_dir=${args[i]#--report-dir=} ;;
    *) ;;
  esac
done
permissions=(--allow-read="$report_dir" --allow-write="$report_dir")
[[ -z "$read_path" ]] || permissions+=(--allow-read="$read_path")
[[ -z "$resume_path" ]] || permissions+=(--allow-read="$resume_path")
exec deno run --no-prompt --no-config --no-lock "${permissions[@]}" --allow-sys=uid --allow-run=docker "$script_dir/publish-identity-docker.ts" "${args[@]}"
