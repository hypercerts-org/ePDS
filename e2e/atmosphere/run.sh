#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOURCE_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
PIN=${EPDS_AIB_PIN:-e3640ee15a97501a0d5d01fdfcd21dde73d46be9}
REPORT_ROOT="$SOURCE_ROOT/reports"
PROFILE=${EPDS_E2E_PROFILE:-both}
SCENARIO_NAME=${EPDS_E2E_SCENARIO_NAME:-}
case "$PROFILE" in
  both|default|session-reuse) ;;
  *) echo "EPDS_E2E_PROFILE must be both, default, or session-reuse." >&2; exit 2 ;;
esac
if [[ -n "$SCENARIO_NAME" && "$PROFILE" != session-reuse ]]; then
  echo "EPDS_E2E_SCENARIO_NAME is only supported with EPDS_E2E_PROFILE=session-reuse." >&2
  exit 2
fi
if [[ -n "${EPDS_E2E_REPORT_DIR:-}" ]]; then
  REPORT_ROOT=$EPDS_E2E_REPORT_DIR
fi
PROJECT=${EPDS_E2E_PROJECT:-"epds-e2e-${GITHUB_RUN_ID:-local}-$(date +%s)-$$"}
if [[ ! "$PROJECT" =~ ^epds-e2e-[a-z0-9][a-z0-9_-]*$ ]]; then
  echo "EPDS_E2E_PROJECT must start with epds-e2e- and use lowercase Compose-safe characters." >&2
  exit 2
fi
TEMP_ROOT=$(mktemp -d "${RUNNER_TEMP:-/tmp}/epds-aib-e2e.XXXXXX")
SANDBOX_ROOT="$TEMP_ROOT/atmosphereinabox"
SUBNET=''

mkdir -p "$REPORT_ROOT"
chmod 0755 "$REPORT_ROOT"
mkdir -m 0700 -p "$TEMP_ROOT/docker-config"
export DOCKER_CONFIG="$TEMP_ROOT/docker-config"
cat > "$REPORT_ROOT/e2e.junit.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="e2e" tests="0" failures="0" errors="0" time="0">
  <testsuite name="placeholder (overwritten by cucumber)" tests="0" failures="0" errors="0" skipped="0" time="0"/>
</testsuites>
EOF

copy_reports() {
  if [[ -d "$SANDBOX_ROOT/reports" ]]; then
    tar -C "$SANDBOX_ROOT/reports" --exclude='./private-plc-proof.json' \
      -cf - . | tar -C "$REPORT_ROOT" -xf -
  fi
}

cleanup() {
  local result=$?
  rm -f "$TEMP_ROOT/private-plc-proof.json"
  copy_reports
  if [[ -f "$SANDBOX_ROOT/compose.yaml" ]]; then
    if [[ "$result" -ne 0 ]]; then
      docker compose --project-name "$PROJECT" -f "$SANDBOX_ROOT/compose.yaml" \
        ps --all --format json >"$TEMP_ROOT/project-status.jsonl" 2>/dev/null || true
      python3 - "$TEMP_ROOT/project-status.jsonl" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding='utf-8', errors='replace'):
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue
    print('service status:', item.get('Service'), item.get('State'), item.get('Health', ''), item.get('ExitCode', ''))
PY
      docker compose --project-name "$PROJECT" -f "$SANDBOX_ROOT/compose.yaml" \
        logs --no-color --tail=100 dns gateway epds-lexicon-authority \
        epds-core epds-auth epds-demo epds-demo-untrusted \
        >"$TEMP_ROOT/service-errors.log" 2>&1 || true
      python3 - "$TEMP_ROOT/service-errors.log" <<'PY'
import re, sys
for line in open(sys.argv[1], encoding='utf-8', errors='replace'):
    if not re.search(r'error|failed|invalid|fatal|non-unicast|no files matching import glob', line, re.I):
        continue
    service = re.match(r'^\s*([A-Za-z0-9_.-]+)\s*\|', line)
    error = re.search(r'\b(EACCES|ENOENT|ECONNREFUSED|ETIMEDOUT|[A-Za-z][A-Za-z0-9]*(?:Error|Exception))\b', line)
    host = re.search(r'\b([A-Za-z0-9*-]+(?:\.[A-Za-z0-9*-]+)*\.(?:test|internal|org|app))\b', line)
    status = re.search(r'\b(?:HTTP|status|returned|response)\D{0,12}([1-5][0-9]{2})\b', line, re.I)
    category = error.group(1) if error else ('ImportGlobEmpty' if 'No files matching import glob' in line else 'ServiceFailure')
    print('diagnostic:',
          'service=' + (service.group(1) if service else 'compose'),
          'error_class=' + category,
          'route_host=' + (host.group(1) if host else 'none'),
          'response_code=' + (status.group(1) if status else 'none'))
PY
    fi
    if [[ "$result" -ne 0 && "${EPDS_E2E_KEEP_FAILED_STATE:-0}" == 1 ]]; then
      echo "Preserved diagnostic state for scoped project $PROJECT at $TEMP_ROOT"
    else
      docker compose --project-name "$PROJECT" -f "$SANDBOX_ROOT/compose.yaml" \
        down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
  fi
  if [[ "$result" -eq 0 || "${EPDS_E2E_KEEP_FAILED_STATE:-0}" != 1 ]]; then
    rm -rf "$TEMP_ROOT"
  fi
  exit "$result"
}
trap cleanup EXIT INT TERM

choose_subnet() {
  local occupied_routes occupied_networks
  occupied_networks=$(docker network ls -q | xargs -r docker network inspect \
    --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' | tr ' ' '\n' | sed '/^$/d')
  occupied_routes=$(ip -j route)
  python3 - "$occupied_networks" "$occupied_routes" <<'PY'
import ipaddress, json, sys
occupied = []
for value in sys.argv[1].splitlines():
    try:
        occupied.append(ipaddress.ip_network(value, strict=False))
    except ValueError:
        pass
for route in json.loads(sys.argv[2]):
    if route.get('dst') and '/' in route['dst']:
        try:
            occupied.append(ipaddress.ip_network(route['dst'], strict=False))
        except ValueError:
            pass
for second in range(16, 32):
    for third in range(0, 256):
        candidate = ipaddress.ip_network(f'172.{second}.{third}.0/24')
        if not any(candidate.overlaps(network) for network in occupied):
            print(candidate)
            raise SystemExit(0)
raise SystemExit('No unused RFC1918 /24 subnet is available for Atmosphere in a Box')
PY
}

now() { date +%s; }

clone_start=$(now)
git clone --quiet --filter=blob:none https://tangled.org/kandake.africa/atmosphereinabox.git "$SANDBOX_ROOT"
git -C "$SANDBOX_ROOT" checkout --quiet --detach "$PIN"
echo "Atmosphere clone seconds: $(( $(now) - clone_start ))"

SUBNET=$(choose_subnet)
install_start=$(now)
(cd "$SANDBOX_ROOT" && npm ci && deno task install && deno task sandbox test)
bash "$SCRIPT_DIR/install.sh" "$SANDBOX_ROOT" "$PROJECT" "$SUBNET"
node --input-type=module - "$SANDBOX_ROOT/job-manifest.json" "$PROJECT" "$SUBNET" \
  < "$SCRIPT_DIR/create-manifest.mjs.txt"
echo "Template install seconds: $(( $(now) - install_start ))"

cd "$SANDBOX_ROOT"
deno task sandbox create --manifest job-manifest.json
deno task sandbox check
  docker compose -f compose.yaml config --quiet
docker compose -f compose.yaml config --format json | python3 -c '
import json,sys
config=json.load(sys.stdin)
services=config["services"]
published=[name for name,service in services.items() if service.get("ports")]
if published:
    raise SystemExit("Unexpected host-published service ports")
if "epds-lexicon-authority" not in services:
    raise SystemExit("Local Lexicon authority service is missing")
if not config["networks"]["atmosinabox"].get("internal"):
    raise SystemExit("Sandbox application network must remain internal")
print("Compose boundary: no host ports; internal application network; local Lexicon authority present")
'

(cd "$SANDBOX_ROOT/e2e-source" && ./scripts/stamp-version.sh >/dev/null)

build_start=$(now)
docker compose --profile e2e build
echo "Image build seconds: $(( $(now) - build_start ))"
docker compose --profile e2e run --rm --no-deps epds-e2e-runner pnpm --version

start_start=$(now)
deno task sandbox up --wait-timeout 300
echo "Service startup seconds: $(( $(now) - start_start ))"

if [[ "${EPDS_E2E_DIAG_ONLY:-0}" == 1 ]]; then
  echo "Diagnostic-only start complete; e2e proof and profiles were skipped."
  exit 0
fi

docker compose --profile e2e run --rm --no-deps epds-e2e-runner node -e '
(async () => {
const auth = {Authorization: "Basic " + Buffer.from(`${process.env.E2E_MAILPIT_USER}:${process.env.E2E_MAILPIT_PASS}`).toString("base64")};
const checks = [
  ["PLC", `${process.env.E2E_PLC_URL}/_health`],
  ["PDS", `${process.env.E2E_PDS_URL}/health`],
  ["auth", `${process.env.E2E_AUTH_URL}/health`],
  ["Lexicon authority", `https://lexicons.atmosbox.test/.well-known/did.json`],
  ["trusted demo", process.env.E2E_DEMO_URL],
  ["untrusted demo", process.env.E2E_DEMO_UNTRUSTED_URL],
  ["Mailpit", `${process.env.E2E_MAILPIT_URL}/readyz`, auth],
];
for (const [name, url, headers] of checks) {
  const response = await fetch(url, headers ? {headers} : {});
  if (!response.ok) throw new Error(`${name} health returned ${response.status}`);
  console.log(`${name}: ${response.status}`);
}
})().catch((error) => { console.error(error.message); process.exit(1); });
'
docker compose exec -T epds-core sh -c '
  if [ "${PDS_DISABLE_SSRF_PROTECTION:-}" = true ]; then
    echo "Core test SSRF setting: enabled"
  else
    echo "Core test SSRF setting: missing"
    exit 1
  fi
'

docker compose --profile e2e run --rm --no-deps epds-e2e-runner node -e '
const fs = require("node:fs");
const path = "/app/reports/.write-check";
fs.writeFileSync(path, "ok");
fs.rmSync(path);
console.log("Runner report artifact mount: writable");
'

suite_start=$(now)
PROOF_CONTAINER="${PROJECT}-private-plc-proof"
docker compose --profile e2e run --name "$PROOF_CONTAINER" --no-deps epds-e2e-runner \
  node --import tsx/esm e2e/atmosphere/prove-private-plc.runtime.mts
docker cp "$PROOF_CONTAINER:/tmp/private-plc-proof.json" "$TEMP_ROOT/private-plc-proof.json" >/dev/null
docker rm "$PROOF_CONTAINER" >/dev/null
DID=$(node -e "process.stdout.write(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')).did)" "$TEMP_ROOT/private-plc-proof.json")
PUBLIC_STATUS=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  "https://plc.directory/$DID")
unset DID
if [[ "$PUBLIC_STATUS" != 404 ]]; then
  echo "Public PLC lookup for the ePDS proof DID returned $PUBLIC_STATUS (expected 404)." >&2
  exit 1
fi
rm -f "$TEMP_ROOT/private-plc-proof.json"
echo "Private PLC account creation and resolution: passed"
echo "Public PLC read-only DID absence: HTTP $PUBLIC_STATUS"

if [[ "${EPDS_E2E_PROOF_ONLY:-0}" == 1 ]]; then
  echo "Private PLC proof complete; profile suite skipped by EPDS_E2E_PROOF_ONLY."
  exit 0
fi

if [[ "$PROFILE" == both || "$PROFILE" == default ]]; then
  docker compose --profile e2e run --rm --no-deps epds-e2e-runner pnpm test:e2e:headless
fi
if [[ "$PROFILE" == both || "$PROFILE" == session-reuse ]]; then
  if [[ -n "$SCENARIO_NAME" ]]; then
    docker compose --profile e2e run --rm --no-deps epds-e2e-runner \
      pnpm test:e2e:headless -p session-reuse --name "$SCENARIO_NAME"
  else
    docker compose --profile e2e run --rm --no-deps epds-e2e-runner \
      pnpm test:e2e:headless -p session-reuse
  fi
fi
echo "E2E profile suite seconds: $(( $(now) - suite_start ))"
