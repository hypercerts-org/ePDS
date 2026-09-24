#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOURCE_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
PIN=${EPDS_AIB_PIN:-e3640ee15a97501a0d5d01fdfcd21dde73d46be9}
SANDBOX_ROOT=${1:?usage: install.sh <pinned-sandbox-clone> <project> <subnet>}
PROJECT=${2:?usage: install.sh <pinned-sandbox-clone> <project> <subnet>}
SUBNET=${3:?usage: install.sh <pinned-sandbox-clone> <project> <subnet>}
DOMAIN=${SANDBOX_DOMAIN:-atmosbox.test}

actual_pin=$(git -C "$SANDBOX_ROOT" rev-parse HEAD)
if [[ "$actual_pin" != "$PIN" ]]; then
  echo "Pinned Atmosphere in a Box revision mismatch: $actual_pin" >&2
  exit 1
fi

read -r GATEWAY_IP DNS_IP < <(python3 - "$SUBNET" <<'PY'
import ipaddress, sys
network = ipaddress.ip_network(sys.argv[1], strict=True)
if network.version != 4 or network.prefixlen < 24 or network.prefixlen > 28:
    raise SystemExit('Sandbox subnet must be IPv4 /24 through /28')
print(network.network_address + 2, network.network_address + 3)
PY
)

python3 - "$SANDBOX_ROOT" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
registry = root / 'stacks/components.json'
items = json.loads(registry.read_text())
expected = [
    ('networking', 'compose/networking.yaml', None),
    ('plc', 'compose/plc.yaml', None),
    ('pds', 'compose/pds.yaml', None),
    ('runner', 'compose/runner.yaml', None),
    ('vanillajs-oauth-web-app', 'stacks/vanillajs-oauth-web-app.yaml', 'vanillajs-oauth-web-app'),
]
if len(items) < len(expected):
    raise SystemExit('Pinned sandbox registry is missing expected components')
for item, (component_id, file, app) in zip(items, expected):
    if item.get('id') != component_id or item.get('file') != file:
        raise SystemExit('Pinned sandbox registry schema/order changed')
    if app is None:
        if set(item) != {'id', 'file'}:
            raise SystemExit('Pinned sandbox built-in registry schema changed')
    elif item.get('application') != app or item.get('definition') != f'stacks/{app}.definition.json' or set(item) != {'id', 'file', 'application', 'definition'}:
        raise SystemExit('Pinned sandbox managed-app registry schema changed')

entry = {'id': 'epds-e2e', 'file': 'stacks/epds-e2e.yaml', 'application': 'epds-e2e', 'definition': 'stacks/epds-e2e.definition.json'}
matches = [item for item in items if item.get('id') == 'epds-e2e']
if matches and matches != [entry]:
    raise SystemExit('Existing epds-e2e registry entry does not match this template')
if not matches:
    items.append(entry)
registry.write_text(json.dumps(items, indent=2) + '\n')

networking = root / 'compose/networking.yaml'
source = networking.read_text()
dns_mount = '      - ./compose/e2e-handles-dns:/config/zones:ro,z\n'
caddy_mount = '      - ./compose/e2e-handles-caddy:/etc/caddy/routes:ro,z\n'
dns_anchor = '      - ./state/Corefile:/config/Corefile:ro,z\n'
caddy_anchor = '      - ./state/Caddyfile:/etc/caddy/Caddyfile:ro,z\n'
for anchor, mount, name in [(dns_anchor, dns_mount, 'CoreDNS'), (caddy_anchor, caddy_mount, 'Caddy')]:
    count = source.count(anchor)
    if count != 1:
        raise SystemExit(f'Pinned networking template changed: expected one {name} mount anchor')
    if mount not in source:
        source = source.replace(anchor, anchor + mount)
networking.write_text(source)
PY

cp "$SCRIPT_DIR/stack.yaml" "$SANDBOX_ROOT/stacks/epds-e2e.yaml"
cp "$SCRIPT_DIR/stack.definition.json" "$SANDBOX_ROOT/stacks/epds-e2e.definition.json"
mkdir -p "$SANDBOX_ROOT/compose/e2e-handles-dns" "$SANDBOX_ROOT/compose/e2e-handles-caddy"
chmod 0755 "$SANDBOX_ROOT/compose/e2e-handles-dns" "$SANDBOX_ROOT/compose/e2e-handles-caddy"
sed -e "s/@@SANDBOX_DOMAIN@@/$DOMAIN/g" -e "s/@@GATEWAY_IP@@/$GATEWAY_IP/g" \
  "$SCRIPT_DIR/handles.server" > "$SANDBOX_ROOT/compose/e2e-handles-dns/handles.server"
sed -e "s/@@SANDBOX_DOMAIN@@/$DOMAIN/g" \
  "$SCRIPT_DIR/handles.caddy" > "$SANDBOX_ROOT/compose/e2e-handles-caddy/handles.caddy"
chmod 0644 "$SANDBOX_ROOT/compose/e2e-handles-dns/handles.server" \
  "$SANDBOX_ROOT/compose/e2e-handles-caddy/handles.caddy"

mkdir -p "$SANDBOX_ROOT/e2e-source" "$SANDBOX_ROOT/reports"
(
  umask 022
  tar -C "$SOURCE_ROOT" \
    --exclude='./.git' --exclude='./.aib-upstream' --exclude='./node_modules' \
    --exclude='./coverage' --exclude='./reports' --exclude='./.env' \
    --exclude='./plans' \
    --exclude='./e2e/.env' --exclude='./.beads' --exclude='*.sqlite*' \
    -cf - . | tar -C "$SANDBOX_ROOT/e2e-source" -xf -
)
chmod 0755 "$SANDBOX_ROOT/e2e-source"
chmod 0755 "$SANDBOX_ROOT/reports"

trusted_jwk=$(node "$SOURCE_ROOT/scripts/generate-es256-jwk.cjs")
untrusted_jwk=$(node "$SOURCE_ROOT/scripts/generate-es256-jwk.cjs")
[[ "$trusted_jwk" != "$untrusted_jwk" ]]
mailpit_pass=$(openssl rand -hex 24)
e2e_runner_uid=$(id -u)
e2e_runner_gid=$(id -g)
cat > "$SANDBOX_ROOT/.env" <<EOF
SANDBOX_DOMAIN=$DOMAIN
TRUSTED_DEMO_JWK=$trusted_jwk
UNTRUSTED_DEMO_JWK=$untrusted_jwk
MAILPIT_USER=e2e
MAILPIT_PASS=$mailpit_pass
E2E_RUNNER_UID=$e2e_runner_uid
E2E_RUNNER_GID=$e2e_runner_gid
EOF
chmod 0600 "$SANDBOX_ROOT/.env"
unset trusted_jwk untrusted_jwk mailpit_pass e2e_runner_uid e2e_runner_gid

printf 'Installed ePDS template into pinned sandbox %s (project %s, DNS %s).\n' "$PIN" "$PROJECT" "$DNS_IP"
