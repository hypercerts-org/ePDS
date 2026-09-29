#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOURCE_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
PIN=${EPDS_AIB_PIN:-26cf1f60f81b491b065dfc830efd27aba8b89a54}
SANDBOX_ROOT=${1:?usage: install.sh <pinned-sandbox-clone>}

actual_pin=$(git -C "$SANDBOX_ROOT" rev-parse HEAD)
if [[ "$actual_pin" != "$PIN" ]]; then
  echo "Pinned Atmosphere in a Box revision mismatch: $actual_pin" >&2
  exit 1
fi

node --input-type=module - "$SANDBOX_ROOT/stacks/components.json" <<'EOF'
import { readFile, writeFile } from 'node:fs/promises'

const [registryPath] = process.argv.slice(2)
const entry = {
  id: 'epds-e2e',
  file: 'stacks/epds-e2e.yaml',
  application: 'epds-e2e',
  definition: 'stacks/epds-e2e.definition.json',
}
const registry = JSON.parse(await readFile(registryPath, 'utf8'))
const existing = registry.filter((item) => item?.id === entry.id)
if (existing.length > 1 || (existing.length === 1 && JSON.stringify(existing[0]) !== JSON.stringify(entry))) {
  throw new Error('Conflicting epds-e2e stack registration')
}
if (!existing.length) {
  registry.push(entry)
  await writeFile(registryPath, JSON.stringify(registry, null, 2) + '\n')
}
EOF

cp "$SCRIPT_DIR/stack.yaml" "$SANDBOX_ROOT/stacks/epds-e2e.yaml"
cp "$SCRIPT_DIR/stack.definition.json" "$SANDBOX_ROOT/stacks/epds-e2e.definition.json"
mkdir -p "$SANDBOX_ROOT/e2e-source" "$SANDBOX_ROOT/reports"
(
  umask 022
  tar -C "$SOURCE_ROOT" \
    --exclude='./.git' --exclude='./.aib-upstream' --exclude='./node_modules' \
    --exclude='./coverage' --exclude='./reports' --exclude='./.env' \
    --exclude='./plans' --exclude='./e2e/.env' --exclude='./.beads' \
    --exclude='./packages/shared/dist' --exclude='./packages/auth-service/dist' \
    --exclude='./packages/pds-core/dist' --exclude='./packages/demo/.next' \
    --exclude='./packages/shared/tsconfig.tsbuildinfo' \
    --exclude='./packages/auth-service/tsconfig.tsbuildinfo' \
    --exclude='./packages/pds-core/tsconfig.tsbuildinfo' \
    --exclude='*.sqlite*' \
    -cf - . | tar -C "$SANDBOX_ROOT/e2e-source" -xf -
)
chmod 0755 "$SANDBOX_ROOT/e2e-source" "$SANDBOX_ROOT/reports"

printf 'Installed ePDS stack into Atmosphere in a Box %s.\n' "$PIN"
