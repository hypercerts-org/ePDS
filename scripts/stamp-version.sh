#!/bin/sh
# Write .epds-version at the repo root for Docker builds to pick up.
# Called by pnpm docker:build or manually when you want local images to
# include the current git SHA. Dockerfiles fall back to package.json when
# this file is absent; Railway uses RAILWAY_GIT_COMMIT_SHA instead.
set -e
VERSION=$(node -p "require('./package.json').version")
SHA=$(git rev-parse HEAD 2>/dev/null || echo "")
if [ -n "$SHA" ]; then
  VERSION="$VERSION+$(echo "$SHA" | cut -c1-8)"
fi
echo "$VERSION" > .epds-version
echo "$VERSION"
