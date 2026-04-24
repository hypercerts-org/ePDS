#!/bin/sh
# Write .epds-version at the repo root for Docker builds to pick up.
# Called by pnpm docker:build or manually when you want to stamp the
# current git SHA into the version ahead of the Docker build.
# Dockerfiles also fall back to package.json if this file is absent.
set -e
VERSION=$(node -p "require('./package.json').version")
SHA=$(git rev-parse HEAD 2>/dev/null || echo "")
if [ -n "$SHA" ]; then
  VERSION="$VERSION+$(echo "$SHA" | cut -c1-8)"
fi
echo "$VERSION" > .epds-version
echo "$VERSION"
