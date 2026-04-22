#!/bin/sh
# Stamp the ePDS version then run docker compose build.
# All arguments are forwarded, e.g.:
#   pnpm docker:build auth
#   pnpm docker:build --no-cache core
set -e
./scripts/stamp-version.sh
exec docker compose build "$@"
