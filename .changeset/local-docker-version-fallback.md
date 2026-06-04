---
'ePDS': patch
---

Local Docker builds no longer fail when the stamped version file has not been generated first.

**Affects:** Operators

**Operators:** Dockerfiles now resolve the image version from `RAILWAY_GIT_COMMIT_SHA`, optional `EPDS_GIT_SHA`, an existing `.epds-version`, or finally the root `package.json` version. `pnpm docker:build` remains the preferred rebuild command when you want the local image version to include the current git SHA, but `docker compose up -d` and `docker compose build` can build missing images without first running `./scripts/stamp-version.sh`.
