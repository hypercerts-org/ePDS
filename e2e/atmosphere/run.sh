#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOURCE_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
PIN=${EPDS_AIB_PIN:-26cf1f60f81b491b065dfc830efd27aba8b89a54}
REPORT_ROOT=${EPDS_E2E_REPORT_DIR:-"$SOURCE_ROOT/reports"}
PROFILE=${EPDS_E2E_PROFILE:-both}
SCENARIO_NAME=${EPDS_E2E_SCENARIO_NAME:-}
PROJECT=${EPDS_E2E_PROJECT:-"epds-e2e-${GITHUB_RUN_ID:-local}-$(date +%s)-$$"}
SANDBOX_DOMAIN=atmosbox.test
E2E_RUNNER_UID=$(id -u)
E2E_RUNNER_GID=$(id -g)
export SANDBOX_DOMAIN E2E_RUNNER_UID E2E_RUNNER_GID

case "$PROFILE" in
  both|default|otp-expiry|session-reuse) ;;
  *) echo "EPDS_E2E_PROFILE must be both, default, otp-expiry, or session-reuse." >&2; exit 2 ;;
esac
if [[ -n "$SCENARIO_NAME" && "$PROFILE" != session-reuse ]]; then
  echo "EPDS_E2E_SCENARIO_NAME is only supported with EPDS_E2E_PROFILE=session-reuse." >&2
  exit 2
fi
if [[ ! "$PROJECT" =~ ^epds-e2e-[a-z0-9][a-z0-9_-]*$ ]]; then
  echo "EPDS_E2E_PROJECT must start with epds-e2e- and use lowercase Compose-safe characters." >&2
  exit 2
fi

TEMP_ROOT=$(mktemp -d "${RUNNER_TEMP:-/tmp}/epds-aib-e2e.XXXXXX")
SANDBOX_ROOT="$TEMP_ROOT/atmosphereinabox"
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
      docker compose --project-name "$PROJECT" -f "$SANDBOX_ROOT/compose.yaml" \
        logs --no-color --tail=100 dns gateway epds-lexicon-authority \
        epds-core epds-auth epds-demo epds-demo-untrusted \
        >"$TEMP_ROOT/service-errors.log" 2>&1 || true
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

python3 "$SCRIPT_DIR/test_validate_template.py"

git clone --quiet --filter=blob:none https://tangled.org/kandake.africa/atmosphereinabox.git "$SANDBOX_ROOT"
git -C "$SANDBOX_ROOT" checkout --quiet --detach "$PIN"
(cd "$SANDBOX_ROOT" && deno task install)
bash "$SCRIPT_DIR/install.sh" "$SANDBOX_ROOT"

cd "$SANDBOX_ROOT"
deno task sandbox create --pds 0 --users-per-pds 0 --project "$PROJECT" --subnet auto --app epds-e2e
deno task sandbox check
docker compose --project-name "$PROJECT" config --quiet
docker compose --project-name "$PROJECT" config --format json \
  | python3 "$SCRIPT_DIR/validate_template.py" \
      --definition "$SANDBOX_ROOT/stacks/epds-e2e.definition.json" --compose -

(cd "$SANDBOX_ROOT/e2e-source" && ./scripts/stamp-version.sh >/dev/null)
docker compose --project-name "$PROJECT" --profile e2e build
docker compose --project-name "$PROJECT" --profile e2e run --rm --no-deps epds-e2e-runner pnpm --version
deno task sandbox up --wait-timeout 300
deno task sandbox seed
deno task sandbox access --json > "$TEMP_ROOT/access.json"
node "$SCRIPT_DIR/validate-access.mjs" "$TEMP_ROOT/access.json" "$PROJECT"

if [[ "${EPDS_E2E_DIAG_ONLY:-0}" == 1 ]]; then
  echo "Diagnostic-only provisioning complete; e2e proof and profiles were skipped."
  exit 0
fi

docker compose --project-name "$PROJECT" --profile e2e run --rm --no-deps epds-e2e-runner node -e '
(async () => {
const checks = [
  ["PLC", `${process.env.E2E_PLC_URL}/_health`],
  ["PDS", `${process.env.E2E_PDS_URL}/health`],
  ["auth", `${process.env.E2E_AUTH_URL}/health`],
  ["Lexicon authority", `${process.env.E2E_LEXICON_AUTHORITY_URL}/xrpc/_health`],
  ["trusted demo", process.env.E2E_DEMO_URL],
  ["untrusted demo", process.env.E2E_DEMO_UNTRUSTED_URL],
  ["Mailpit", `${process.env.E2E_MAILPIT_URL}/readyz`],
];
for (const [name, url] of checks) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${name} health returned ${response.status}`);
  console.log(`${name}: ${response.status}`);
}
})().catch((error) => { console.error(error.message); process.exit(1); });
'

docker compose --project-name "$PROJECT" exec -T epds-core sh -c '
  test "${PDS_DISABLE_SSRF_PROTECTION:-}" = true
'

docker compose --project-name "$PROJECT" --profile e2e run --rm --no-deps epds-e2e-runner node -e '
const fs = require("node:fs");
const path = "/app/reports/.write-check";
fs.writeFileSync(path, "ok");
fs.rmSync(path);
'

PROOF_CONTAINER="${PROJECT}-private-plc-proof"
docker compose --project-name "$PROJECT" --profile e2e run --name "$PROOF_CONTAINER" --no-deps epds-e2e-runner \
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

if [[ "${EPDS_E2E_PROOF_ONLY:-0}" == 1 ]]; then
  echo "Private PLC proof complete; profile suite skipped by EPDS_E2E_PROOF_ONLY."
  exit 0
fi

if [[ "$PROFILE" == both || "$PROFILE" == default ]]; then
  docker compose --project-name "$PROJECT" --profile e2e run --rm --no-deps epds-e2e-runner pnpm test:e2e:headless
fi
if [[ "$PROFILE" == both || "$PROFILE" == otp-expiry ]]; then
  docker compose --project-name "$PROJECT" --profile e2e run --rm --no-deps epds-e2e-runner \
    pnpm test:e2e:headless --profile otp-expiry
fi
if [[ "$PROFILE" == both || "$PROFILE" == session-reuse ]]; then
  if [[ -n "$SCENARIO_NAME" ]]; then
    docker compose --project-name "$PROJECT" --profile e2e run --rm --no-deps epds-e2e-runner \
      pnpm test:e2e:headless -p session-reuse --name "$SCENARIO_NAME"
  else
    docker compose --project-name "$PROJECT" --profile e2e run --rm --no-deps epds-e2e-runner \
      pnpm test:e2e:headless -p session-reuse
  fi
fi
