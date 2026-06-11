#!/usr/bin/env bash
# Capture Caddy diagnostics when the container approaches its memory limit.
#
# The script is read-only with respect to Docker services: it does not restart,
# reload, or reconfigure containers. Snapshots are private by default and avoid
# raw docker inspect output because inspect includes environment variables.

set -Eeuo pipefail
umask 077

CADDY_SERVICE="${CADDY_SERVICE:-caddy}"
CORE_SERVICE="${CORE_SERVICE:-core}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-/tmp/epds-caddy-snapshots}"
THRESHOLD_MIB="${THRESHOLD_MIB:-384}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-5}"
SNAPSHOT_COOLDOWN_SECONDS="${SNAPSHOT_COOLDOWN_SECONDS:-300}"
LOG_SINCE="${LOG_SINCE:-10m}"
COMMAND_TIMEOUT_SECONDS="${COMMAND_TIMEOUT_SECONDS:-12}"
POLL_TIMEOUT_SECONDS="${POLL_TIMEOUT_SECONDS:-4}"
ONCE=0

if [[ "${1:-}" == "--once" ]]; then
  ONCE=1
fi

usage() {
  cat <<USAGE
Usage: $0 [--once]

Environment variables:
  CADDY_SERVICE                 Compose service name for Caddy. Default: caddy
  CORE_SERVICE                  Compose service name for pds-core. Default: core
  SNAPSHOT_DIR                  Output directory. Default: /tmp/epds-caddy-snapshots
  THRESHOLD_MIB                 Capture when Caddy memory is at/above this MiB. Default: 384
  INTERVAL_SECONDS              Poll interval for watch mode. Default: 5
  SNAPSHOT_COOLDOWN_SECONDS     Minimum seconds between snapshots. Default: 300
  LOG_SINCE                     docker compose logs --since value. Default: 10m
  COMMAND_TIMEOUT_SECONDS       Timeout for snapshot commands. Default: 12
  POLL_TIMEOUT_SECONDS          Timeout for polling commands. Default: 4

The script reads Caddy's local admin API from inside the Caddy container and
captures /debug/vars, /metrics, heap, goroutines, docker stats, selected
container state, connection state, and recent compose/kernel logs.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "missing required command: $command_name" >&2
    exit 1
  fi
}

container_id() {
  local service="$1"
  timeout "$POLL_TIMEOUT_SECONDS" docker compose ps -q "$service" 2>/dev/null || true
}

memory_bytes() {
  local container="$1"
  timeout "$POLL_TIMEOUT_SECONDS" docker exec "$container" sh -lc 'cat /sys/fs/cgroup/memory.current 2>/dev/null || cat /sys/fs/cgroup/memory/memory.usage_in_bytes 2>/dev/null || echo -1' 2>/dev/null || echo -1
}

mib_from_bytes() {
  awk '{printf "%d", $1 / 1024 / 1024}'
}

safe_capture() {
  local output_file="$1"
  shift
  {
    timeout "$COMMAND_TIMEOUT_SECONDS" "$@"
  } >"$output_file" 2>&1 || true
}

safe_docker_exec_wget() {
  local container="$1"
  local url="$2"
  local output_file="$3"
  safe_capture "$output_file" docker exec "$container" wget -q -O - "$url"
}

capture_container_state() {
  local container="$1"
  local output_file="$2"
  safe_capture "$output_file" docker inspect "$container" --format '
name={{.Name}}
id={{.Id}}
image={{.Config.Image}}
restartCount={{.RestartCount}}
status={{.State.Status}}
running={{.State.Running}}
oomKilled={{.State.OOMKilled}}
exitCode={{.State.ExitCode}}
error={{.State.Error}}
startedAt={{.State.StartedAt}}
finishedAt={{.State.FinishedAt}}
memoryLimitBytes={{.HostConfig.Memory}}
memorySwapBytes={{.HostConfig.MemorySwap}}
pidsLimit={{.HostConfig.PidsLimit}}
restartPolicy={{.HostConfig.RestartPolicy.Name}}
'
}

capture_snapshot() {
  local caddy_id="$1"
  local core_id="$2"
  local memory_mib="$3"
  local now_epoch snapshot_path

  now_epoch="$(date +%s)"
  snapshot_path="$SNAPSHOT_DIR/snapshot-$now_epoch"
  mkdir -p "$snapshot_path"
  chmod 700 "$snapshot_path"

  {
    echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "caddy_service=$CADDY_SERVICE"
    echo "core_service=$CORE_SERVICE"
    echo "caddy_id=$caddy_id"
    echo "core_id=$core_id"
    echo "caddy_memory_mib=$memory_mib"
    echo "threshold_mib=$THRESHOLD_MIB"
  } >"$snapshot_path/metadata.env"

  safe_capture "$snapshot_path/docker-stats.txt" docker stats --no-stream "$caddy_id" "$core_id"
  capture_container_state "$caddy_id" "$snapshot_path/caddy-state.txt"
  capture_container_state "$core_id" "$snapshot_path/core-state.txt"
  safe_capture "$snapshot_path/ss.txt" ss -tanp
  safe_capture "$snapshot_path/kernel-recent.txt" journalctl -k --since "-$LOG_SINCE" --no-pager
  safe_capture "$snapshot_path/caddy-logs.txt" docker compose logs --timestamps --since "$LOG_SINCE" "$CADDY_SERVICE"
  safe_capture "$snapshot_path/core-logs.txt" docker compose logs --timestamps --since "$LOG_SINCE" "$CORE_SERVICE"

  safe_docker_exec_wget "$caddy_id" http://localhost:2019/debug/vars "$snapshot_path/caddy-debug-vars.json"
  safe_docker_exec_wget "$caddy_id" http://localhost:2019/metrics "$snapshot_path/caddy-metrics.txt"
  safe_docker_exec_wget "$caddy_id" 'http://localhost:2019/debug/pprof/goroutine?debug=2' "$snapshot_path/caddy-goroutines.txt"
  safe_docker_exec_wget "$caddy_id" 'http://localhost:2019/debug/pprof/heap?debug=1' "$snapshot_path/caddy-heap.txt"
  safe_docker_exec_wget "$caddy_id" 'http://localhost:2019/debug/pprof/heap' "$snapshot_path/caddy-heap.pb.gz"

  echo "captured Caddy diagnostic snapshot: $snapshot_path"
}

require_command docker
require_command awk
require_command date
require_command timeout
mkdir -p "$SNAPSHOT_DIR"
chmod 700 "$SNAPSHOT_DIR"

last_snapshot_epoch=0

while true; do
  caddy_id="$(container_id "$CADDY_SERVICE")"
  core_id="$(container_id "$CORE_SERVICE")"

  if [[ -z "$caddy_id" ]]; then
    echo "Caddy service '$CADDY_SERVICE' is not running or not found" >&2
    exit 1
  fi
  if [[ -z "$core_id" ]]; then
    echo "Core service '$CORE_SERVICE' is not running or not found" >&2
    exit 1
  fi

  caddy_memory_bytes="$(memory_bytes "$caddy_id")"
  if ! [[ "$caddy_memory_bytes" =~ ^[0-9]+$ ]]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) caddy_memory_unknown=1 raw_value=$caddy_memory_bytes" >&2
    if (( ONCE == 1 )); then
      exit 1
    fi
    sleep "$INTERVAL_SECONDS"
    continue
  fi

  caddy_memory_mib="$(printf '%s\n' "$caddy_memory_bytes" | mib_from_bytes)"
  now_epoch="$(date +%s)"

  if (( caddy_memory_mib >= THRESHOLD_MIB )); then
    if (( ONCE == 1 || now_epoch - last_snapshot_epoch >= SNAPSHOT_COOLDOWN_SECONDS )); then
      capture_snapshot "$caddy_id" "$core_id" "$caddy_memory_mib"
      last_snapshot_epoch="$now_epoch"
    else
      echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) caddy_memory_mib=$caddy_memory_mib threshold_mib=$THRESHOLD_MIB cooldown_active=1"
    fi
  else
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) caddy_memory_mib=$caddy_memory_mib threshold_mib=$THRESHOLD_MIB"
  fi

  if (( ONCE == 1 )); then
    exit 0
  fi
  sleep "$INTERVAL_SECONDS"
done
