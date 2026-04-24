#!/bin/sh
# Resolve the ePDS version and write it to .epds-version in the current
# directory. Used by all three Dockerfiles during image build.
#
# Sources (first non-empty wins):
#   1. RAILWAY_GIT_COMMIT_SHA env var (injected by Railway at build time)
#   2. EPDS_GIT_SHA env var / build arg (optional for non-Railway builds)
#   3. .epds-version file already present (written by stamp-version.sh)
#   4. version field from the root package.json
set -e

base_version() {
  node -p "require('./package.json').version"
}

short_sha() {
  printf '%s' "$1" | cut -c1-8
}

if [ -n "$RAILWAY_GIT_COMMIT_SHA" ]; then
  VERSION="$(base_version)+$(short_sha "$RAILWAY_GIT_COMMIT_SHA")"
elif [ -n "$EPDS_GIT_SHA" ]; then
  VERSION="$(base_version)+$(short_sha "$EPDS_GIT_SHA")"
elif [ -f .epds-version ] && [ -s .epds-version ]; then
  VERSION=$(cat .epds-version)
else
  VERSION=$(base_version)
fi

printf '%s\n' "$VERSION" > .epds-version
