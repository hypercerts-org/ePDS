#!/bin/bash
set -euo pipefail

# ── Utility functions ──

# Generate a hex secret
generate_secret() {
  openssl rand -hex 32
}

generate_es256_private_jwk() {
  "$(dirname "$0")/generate-es256-jwk.cjs"
}

# Portable sed in-place (works on macOS and Linux)
sed_inplace() {
  if sed --version 2>/dev/null | grep -q GNU; then
    sed -i "$1" "$2"
  else
    sed -i '' "$1" "$2"
  fi
}

# Read a var=value from a file, returning just the value.
# Returns empty string if not found or value is empty.
read_env_var() {
  local var="$1" file="$2"
  grep -E "^${var}=" "$file" 2>/dev/null | head -1 | cut -d'=' -f2-
}

# Set a var in a file. If an uncommented line exists, replace it.
# If only commented lines exist, leave them alone and append.
# If the var doesn't exist at all, append it.
set_env_var() {
  local var="$1" val="$2" file="$3"
  if grep -qE "^${var}=" "$file" 2>/dev/null; then
    sed_inplace "s|^${var}=.*|${var}=${val}|" "$file"
  else
    echo "${var}=${val}" >> "$file"
  fi
}

# Generate random values for vars that are currently set to bare "=".
# Usage: generate_secrets_in_file <file> VAR1 VAR2 ...
generate_secrets_in_file() {
  local file="$1"; shift
  for var in "$@"; do
    local secret
    secret=$(generate_secret)
    sed_inplace "s|^${var}=$|${var}=${secret}|" "$file"
    echo "  Generated $var"
  done
}

# Copy shared vars from the top-level .env into a per-package .env.
# Only sets vars that already have an uncommented line in the target file,
# so packages don't end up with vars they don't use.
inject_shared_vars() {
  local target="$1"
  local example="${target%.env}.env.example"
  for var in PDS_HOSTNAME PDS_PUBLIC_URL AUTH_HOSTNAME \
             EPDS_CALLBACK_SECRET EPDS_INTERNAL_SECRET PDS_ADMIN_PASSWORD \
             PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX \
             EPDS_INVITE_CODE PDS_INTERNAL_URL \
             SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS SMTP_FROM SMTP_FROM_NAME PDS_EMAIL_FROM_ADDRESS; do
    # Skip if the var isn't in the target AND isn't in the package's .env.example.
    # This avoids injecting vars a package doesn't use, while still handling
    # .env files created from an older .env.example that lacked the var.
    if ! grep -qE "^${var}=" "$target" 2>/dev/null \
       && ! grep -qE "^${var}=" "$example" 2>/dev/null; then
      continue
    fi
    local val
    val=$(read_env_var "$var" .env)
    if [ -n "$val" ]; then
      set_env_var "$var" "$val" "$target"
    fi
  done
}

# Inject derived vars that need computation (not just a plain copy from .env).
# Also checks .env.example so vars added after initial setup are still applied.
inject_derived_vars() {
  local target="$1"
  local example="${target%.env}.env.example"

  # Helper: true if var is in the target .env OR its .env.example
  var_belongs() {
    grep -qE "^${1}=" "$target" 2>/dev/null \
      || grep -qE "^${1}=" "$example" 2>/dev/null
  }

  local auth_hostname
  auth_hostname=$(read_env_var AUTH_HOSTNAME .env)

  if var_belongs EPDS_LINK_BASE_URL && [ -n "$auth_hostname" ]; then
    set_env_var EPDS_LINK_BASE_URL "https://${auth_hostname}/auth/verify" "$target"
  fi
  # PDS_EMAIL_SMTP_URL is pds-core-specific, constructed from SMTP components
  local smtp_url
  smtp_url=$(read_env_var PDS_EMAIL_SMTP_URL .env)
  if var_belongs PDS_EMAIL_SMTP_URL && [ -n "$smtp_url" ]; then
    set_env_var PDS_EMAIL_SMTP_URL "$smtp_url" "$target"
  fi

  # PORT — Railway uses this for healthchecks.  Derive from the service-
  # specific port variable in the top-level .env so the per-package .env
  # has the right value for Railway paste-in.
  if var_belongs PORT; then
    # pds-core uses PDS_PORT, auth-service uses AUTH_PORT
    local port_val=""
    if [[ "$target" == *pds-core* ]]; then
      port_val=$(read_env_var PDS_PORT .env)
    elif [[ "$target" == *auth-service* ]]; then
      port_val=$(read_env_var AUTH_PORT .env)
    fi
    if [ -n "$port_val" ]; then
      set_env_var PORT "$port_val" "$target"
    fi
  fi
}

# ── Interactive prompts ──

# Ask for the PDS hostname and derive all other hostnames/URLs from it.
prompt_hostname() {
  echo "Configure your ePDS instance"
  echo "──────────────────────────────"
  echo ""
  echo "Enter your PDS hostname. This is the domain your PDS will be"
  echo "reachable at. User handles will be <random>.<hostname>."
  echo ""
  echo "Examples:"
  echo "  pds.example.com          (production)"
  echo "  localhost                 (local dev without TLS)"
  echo ""

  local existing_hostname
  existing_hostname=$(read_env_var PDS_HOSTNAME .env)

  local pds_hostname
  read -rep "PDS hostname: " -i "${existing_hostname:-localhost}" pds_hostname

  local auth_hostname
  if [ "$pds_hostname" = "localhost" ]; then
    auth_hostname="localhost"
  else
    auth_hostname="auth.${pds_hostname}"
  fi

  echo ""
  echo "Auth hostname will be: ${auth_hostname}"
  echo ""

  local proto="https"
  if [ "$pds_hostname" = "localhost" ] || [[ "$pds_hostname" == *.localhost ]]; then
    proto="http"
  fi

  local pds_public_url="${proto}://${pds_hostname}"
  if [ "$pds_hostname" = "localhost" ]; then
    pds_public_url="http://localhost:3000"
  fi

  set_env_var PDS_HOSTNAME "$pds_hostname" .env
  set_env_var PDS_PUBLIC_URL "$pds_public_url" .env
  set_env_var AUTH_HOSTNAME "$auth_hostname" .env
  set_env_var EPDS_LINK_BASE_URL "${proto}://${auth_hostname}/auth/verify" .env

  # Set PDS_INTERNAL_URL for multi-service deployments (auth-service → pds-core).
  # Docker: http://core:3000; Railway: http://<service>.railway.internal:3000
  # Not needed for localhost (both services on same host).
  if [ "$pds_hostname" != "localhost" ] && [[ "$pds_hostname" != *.localhost ]]; then
    set_env_var PDS_INTERNAL_URL "http://core:3000" .env
    echo "  Set PDS_INTERNAL_URL=http://core:3000"
  fi

  echo "  Set PDS_HOSTNAME=${pds_hostname}"
  echo "  Set PDS_PUBLIC_URL=${pds_public_url}"
  echo "  Set AUTH_HOSTNAME=${auth_hostname}"
  echo "  Set EPDS_LINK_BASE_URL=${proto}://${auth_hostname}/auth/verify"
}

# Ask for SMTP credentials. Sets discrete vars in .env (for auth-service) and
# constructs PDS_EMAIL_SMTP_URL (for pds-core).
prompt_smtp() {
  echo ""
  echo "Configure SMTP (for sending emails)"
  echo "────────────────────────────────────"
  echo ""
  echo "ePDS needs an SMTP server for OTP codes, password resets, and"
  echo "email verification. Press Enter to accept defaults (local Mailpit)."
  echo ""

  # Read existing values for defaults
  local existing_host existing_port existing_user existing_pass existing_from existing_from_name
  existing_host=$(read_env_var SMTP_HOST .env)
  existing_port=$(read_env_var SMTP_PORT .env)
  existing_user=$(read_env_var SMTP_USER .env)
  existing_pass=$(read_env_var SMTP_PASS .env)
  existing_from=$(read_env_var SMTP_FROM .env)
  existing_from_name=$(read_env_var SMTP_FROM_NAME .env)

  local smtp_host smtp_port smtp_user smtp_pass

  read -rep "SMTP host: " -i "${existing_host:-localhost}" smtp_host

  local default_port="${existing_port:-587}"
  if [ -z "$existing_port" ] && [ "$smtp_host" = "localhost" ]; then
    default_port="1025"
  fi
  read -rep "SMTP port: " -i "$default_port" smtp_port

  read -rep "SMTP username (blank for none): " -i "$existing_user" smtp_user
  if [ -n "$smtp_user" ]; then
    local pass_prompt="SMTP password"
    if [[ -n "$existing_pass" ]]; then
      pass_prompt="SMTP password (press Enter to keep existing)"
    fi
    read -rsp "${pass_prompt}: " smtp_pass
    echo ""
    if [[ -z "$smtp_pass" ]] && [[ -n "$existing_pass" ]]; then
      smtp_pass="$existing_pass"
    fi
  else
    smtp_pass=""
  fi

  # From address and display name
  local pds_hostname smtp_from smtp_from_name
  pds_hostname=$(read_env_var PDS_HOSTNAME .env)
  local default_from="${existing_from:-noreply@${pds_hostname}}"

  read -rep "From address: " -i "$default_from" smtp_from

  read -rep "From name: " -i "${existing_from_name:-ePDS}" smtp_from_name

  set_env_var SMTP_HOST "$smtp_host" .env
  set_env_var SMTP_PORT "$smtp_port" .env
  set_env_var SMTP_USER "$smtp_user" .env
  set_env_var SMTP_PASS "$smtp_pass" .env
  set_env_var SMTP_FROM "$smtp_from" .env
  set_env_var SMTP_FROM_NAME "$smtp_from_name" .env
  set_env_var PDS_EMAIL_FROM_ADDRESS "$smtp_from" .env

  # Construct PDS_EMAIL_SMTP_URL: smtps for port 465, smtp otherwise
  local scheme="smtp"
  if [ "$smtp_port" = "465" ]; then
    scheme="smtps"
  fi

  local smtp_url
  if [ -n "$smtp_user" ]; then
    # URL-encode nothing here — SMTP credentials rarely contain special chars.
    # If they do, the user should edit .env manually.
    smtp_url="${scheme}://${smtp_user}:${smtp_pass}@${smtp_host}:${smtp_port}"
  else
    smtp_url="${scheme}://${smtp_host}:${smtp_port}"
  fi
  set_env_var PDS_EMAIL_SMTP_URL "$smtp_url" .env

  echo "  Set SMTP_HOST=${smtp_host}"
  echo "  Set SMTP_PORT=${smtp_port}"
  if [ -n "$smtp_user" ]; then
    echo "  Set SMTP_USER=${smtp_user}"
    echo "  Set SMTP_PASS=****"
    echo "  Set PDS_EMAIL_SMTP_URL=${scheme}://${smtp_user}:****@${smtp_host}:${smtp_port}"
  else
    echo "  Set PDS_EMAIL_SMTP_URL=${smtp_url}"
  fi
  echo "  Set SMTP_FROM=${smtp_from}"
  echo "  Set SMTP_FROM_NAME=${smtp_from_name}"
  echo "  Set PDS_EMAIL_FROM_ADDRESS=${smtp_from}"
}

prompt_demo() {
  echo ""
  echo "Configure the demo app"
  echo "──────────────────────"
  echo ""

  local pds_public_url auth_hostname proto
  pds_public_url=$(read_env_var PDS_PUBLIC_URL .env)
  auth_hostname=$(read_env_var AUTH_HOSTNAME .env)
  proto="https"
  if [[ "$pds_public_url" == http://* ]]; then
    proto="http"
  fi

  # PDS_URL and AUTH_ENDPOINT are derived — no need to prompt
  local auth_endpoint="${proto}://${auth_hostname}/oauth/authorize"
  if [ "$auth_hostname" = "localhost" ]; then
    auth_endpoint="http://localhost:3001/oauth/authorize"
  fi

  local existing_demo_url
  existing_demo_url=$(read_env_var PUBLIC_URL packages/demo/.env)

  local demo_url
  read -rep "Demo public URL: " -i "${existing_demo_url:-http://127.0.0.1:3002}" demo_url

  set_env_var PUBLIC_URL "$demo_url" packages/demo/.env
  set_env_var PDS_URL "$pds_public_url" packages/demo/.env
  set_env_var AUTH_ENDPOINT "$auth_endpoint" packages/demo/.env

  echo "  Set PUBLIC_URL=${demo_url}"
  echo "  Set PDS_URL=${pds_public_url}"
  echo "  Set AUTH_ENDPOINT=${auth_endpoint}"
}

# ── Setup stages ──

# Warn if any .env files already exist — secrets won't be regenerated,
# but prompts will run with existing values pre-filled for editing.
warn_existing_env_files() {
  local existing=()
  for f in .env packages/pds-core/.env packages/auth-service/.env packages/demo/.env; do
    if [ -f "$f" ]; then
      existing+=("$f")
    fi
  done

  if [ ${#existing[@]} -eq 0 ]; then
    return
  fi

  echo "NOTE: The following .env files already exist:"
  for f in "${existing[@]}"; do
    echo "  $f"
  done
  echo ""
  echo "Secrets will not be regenerated. Prompts will show current values"
  echo "for editing. Delete the files first if you want a completely fresh setup."
  echo ""

  local reply
  read -rp "Continue? [Y/n] " reply
  if [[ "$reply" =~ ^[Nn] ]]; then
    echo "Aborted."
    exit 0
  fi
  echo ""
}

check_prerequisites() {
  for cmd in pnpm openssl node; do
    if ! command -v "$cmd" &>/dev/null; then
      echo "ERROR: $cmd is required but not installed."
      exit 1
    fi
  done
  echo "Node version: $(node --version)"
  echo "pnpm version: $(pnpm --version)"
  echo ""
}

setup_toplevel_env() {
  if [ ! -f .env ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env

    generate_secrets_in_file .env \
      PDS_JWT_SECRET PDS_DPOP_SECRET AUTH_SESSION_SECRET AUTH_CSRF_SECRET \
      PDS_ADMIN_PASSWORD EPDS_CALLBACK_SECRET EPDS_INTERNAL_SECRET
  fi

  echo ""
  prompt_hostname
  prompt_smtp

  local rotation_key
  rotation_key=$(read_env_var PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX .env)
  if [ -z "$rotation_key" ]; then
    echo ""
    echo "Generating PLC rotation key..."
    rotation_key=$(openssl ecparam -name secp256k1 -genkey -noout \
      | openssl ec -text -noout 2>/dev/null \
      | grep priv -A 3 | tail -n +2 | tr -d '[:space:]:')
    set_env_var PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX "$rotation_key" .env
    echo "  Generated PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX"
  fi
}

# Create a per-package .env from its .env.example, inject shared/derived vars,
# and generate any package-specific secrets.
# Usage: setup_package_env <pkg_dir> [SECRET_VAR ...]
setup_package_env() {
  local pkg_dir="$1"; shift
  local env_file="${pkg_dir}/.env"

  if [ ! -f "$env_file" ]; then
    echo "Creating ${env_file}..."
    cp "${pkg_dir}/.env.example" "$env_file"
    if [ $# -gt 0 ]; then
      generate_secrets_in_file "$env_file" "$@"
    fi
  fi

  inject_shared_vars "$env_file"
  inject_derived_vars "$env_file"
}

setup_package_envs() {
  # Each package has its own .env.example. Per-package .env files are used by:
  #   - pnpm dev:demo (Next.js loads packages/demo/.env automatically)
  #   - Railway (each service reads only its own vars — copy-paste into raw editor)
  # For docker-compose and pnpm dev (core + auth), the top-level .env is sufficient.

  echo ""
  setup_package_env packages/pds-core PDS_JWT_SECRET PDS_DPOP_SECRET
  setup_package_env packages/auth-service AUTH_SESSION_SECRET AUTH_CSRF_SECRET

  # Demo needs special handling: SESSION_SECRET line is commented out by default
  if [ ! -f packages/demo/.env ]; then
    echo "Creating packages/demo/.env..."
    cp packages/demo/.env.example packages/demo/.env
    local secret
    secret=$(generate_secret)
    sed_inplace "s|^# SESSION_SECRET=.*|SESSION_SECRET=${secret}|" packages/demo/.env
    echo "  Generated SESSION_SECRET"
  fi

  # Generate an ES256 keypair for OAuth confidential-client authentication
  # (private_key_jwt). Declared in client-metadata.json and used to sign
  # client_assertion JWTs at the token endpoint. Without this, the upstream
  # @atproto/oauth-provider classifies the client as public and forcibly
  # re-prompts consent on every authorize request (see HYPER-270).
  local existing_jwk
  existing_jwk=$(read_env_var EPDS_CLIENT_PRIVATE_JWK packages/demo/.env)
  if [ -z "$existing_jwk" ]; then
    echo "Generating EPDS_CLIENT_PRIVATE_JWK (ES256 P-256 private JWK)..."
    local jwk
    jwk=$(generate_es256_private_jwk)
    set_env_var EPDS_CLIENT_PRIVATE_JWK "$jwk" packages/demo/.env
    echo "  Generated EPDS_CLIENT_PRIVATE_JWK"
  fi

  prompt_demo

  echo ""
  echo "See per-package .env.example files for full documentation:"
  echo "  packages/pds-core/.env.example"
  echo "  packages/auth-service/.env.example"
  echo "  packages/demo/.env.example"
}

print_next_steps() {
  echo ""
  echo "=== Setup complete ==="
  echo ""
  echo "Next steps:"
  echo "  1. Review .env files and adjust if needed"
  echo "  2. pnpm install && pnpm build"
  echo "  3. pnpm dev              - Start core + auth in dev mode"
  echo "  4. pnpm dev:demo         - Start the demo app (separate terminal)"
  echo "  5. docker compose up -d  - Or start with Docker instead"
  echo ""
  echo "  NOTE: The PDS requires invite codes by default. After the PDS is"
  echo "  running, generate one via the admin API and set EPDS_INVITE_CODE"
  echo "  in pds-core's environment. See docs/deployment.md for details."
  echo "  Alternatively, set PDS_INVITE_REQUIRED=false to disable this."
  echo ""
  echo "For Railway deployment, paste the output of these commands into"
  echo "each service's raw environment editor:"
  echo "  grep -v '^\s*#' packages/pds-core/.env | grep -v '^\s*$'"
  echo "  grep -v '^\s*#' packages/auth-service/.env | grep -v '^\s*$'"
  echo "  grep -v '^\s*#' packages/demo/.env | grep -v '^\s*$'"
  echo ""
  echo "  IMPORTANT: For Railway, change PDS_INTERNAL_URL in auth-service from"
  echo "  the Docker value (http://core:3000) to the Railway internal URL:"
  echo "    http://<pds-core-service>.railway.internal:3000"
  echo "  The auth service will fail to start without a correct PDS_INTERNAL_URL."
  echo ""
  echo "  IMPORTANT: EPDS_CLIENT_PRIVATE_JWK must be DIFFERENT per demo service."
  echo "  If you deploy more than one demo on Railway (e.g. a trusted demo and"
  echo "  an untrusted demo to exercise the e2e consent scenarios), each service"
  echo "  needs its own ES256 keypair — otherwise one demo could forge a client"
  echo "  assertion claiming to be the other. The packages/demo/.env value above"
  echo "  can be pasted into ONE demo service; generate a second keypair for"
  echo "  any additional demo services with:"
  echo ""
  echo "    scripts/generate-es256-jwk.cjs"
  echo ""
  echo "  Paste the output as EPDS_CLIENT_PRIVATE_JWK on the second demo service."
}

# ── Main ──

print_intro() {
  echo "=== ePDS Setup ==="
  echo ""
  echo "Run this once before first use. It creates .env files for all packages"
  echo "and auto-generates secrets."
  echo ""
  echo "docker-compose / pnpm dev:"
  echo "  The top-level .env is loaded by the core, auth, and caddy services."
  echo "  packages/demo/.env is loaded by the demo service (docker-compose)"
  echo "  and by Next.js when running pnpm dev:demo."
  echo ""
  echo "Railway:"
  echo "  Each service reads only its own per-package .env — the top-level .env"
  echo "  is not used. Run this script locally, then paste each per-package .env"
  echo "  into the service's raw environment editor in the Railway dashboard."
  echo ""
  echo "Re-running is safe — existing secrets are preserved and prompts show"
  echo "current values for editing."
  echo ""
}

main() {
  print_intro
  check_prerequisites
  warn_existing_env_files
  setup_toplevel_env
  setup_package_envs
  print_next_steps
}

main "$@"
