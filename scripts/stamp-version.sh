#!/bin/sh
# Write .epds-version at the repo root for Docker builds to pick up.
# Called automatically by docker-compose.yml pre-build or manually.
# The Dockerfile copies this file if it exists; Railway uses
# RAILWAY_GIT_COMMIT_SHA instead.
set -e
VERSION=$(node -p "require('./package.json').version")
SHA=$(git rev-parse HEAD 2>/dev/null || echo "")
if [ -n "$SHA" ]; then
  VERSION="$VERSION+$(echo "$SHA" | cut -c1-8)"
fi
echo "$VERSION" > .epds-version
echo "$VERSION"
