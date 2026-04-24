---
'ePDS': patch
---

Docker builds now fall back to the repo version automatically when no pre-stamped version file is present.

**Affects:** Operators

**Operators:** `docker compose build` now works on hosts that only have Docker installed. During image builds, `scripts/resolve-version.sh` still prefers `RAILWAY_GIT_COMMIT_SHA` and an existing `.epds-version`, but now falls back to the root `package.json` version instead of failing with `ERROR: .epds-version not found`. Non-Railway builds can also pass `EPDS_GIT_SHA` to keep the `+<sha>` suffix, for example `EPDS_GIT_SHA=$(git rev-parse HEAD) docker compose build`.
