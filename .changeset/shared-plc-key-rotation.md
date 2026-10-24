---
'ePDS': minor
---

Add standalone shared PLC key rotation, active DID inventory, and Docker/Railway identity publishing tools with resumable private reports.

**Affects:** Operators

**Operators:** Use Deno 2.8.3 and follow `docs/plc-key-rotation.md`:

- Build an inventory with `scripts/list-active-dids.ts --pds-url https://HOST` using scoped network permission; active DIDs are printed one per line only after all pages succeed. Preview/add/remove keys with `scripts/rotate-plc-key.sh`. During outages, add only; after recovery, freeze writers, reconcile accounts, manually switch and verify every replica, then remove the old key. The tools do not change deployment secrets, redeploy services, or eliminate PLC's historical recovery window.
- Independently publish identity events with `scripts/publish-identity-docker.sh` (`CONTAINER`) or `scripts/publish-identity-railway.sh` (`PROJECT`, `ENVIRONMENT`, `SERVICE`), a reviewed `DIDS` file of up to 15,000 DIDs, and `--apply`; preview is offline. Both default to the ePDS workdir `/app/packages/pds-core`; set `WORKDIR=/app` for a reference PDS. Docker uses its configured user unless overridden by `EXEC_USER` / `--user USER[:GROUP]`; Railway uses its SSH login user, ignores `EXEC_USER`, and no longer accepts `--user`. Verify runtime/storage access before applying; `queued` confirms PDS storage, not relay receipt.
- Every rotation or publishing run requires terminal confirmation with `yes`. Select a compatible numbered report, `0` for a fresh run, or use `--no-resume` / `--resume-report PATH`; these do not bypass confirmation. Unique owner-only JSON and timestamped logs are saved directly in `REPORT_DIR` (default `./reports`) without changing existing directory permissions; stdout shows outcomes and report paths. Resume preserves successful provenance and retries unfinished work, never using preview successes to skip apply work. Railway reports ignore the obsolete expected-user field while retaining other target checks.
- Failures exit nonzero; Ctrl+C/SIGTERM saves the full inventory and exits 130. Inspect uncertain PLC heads or remote processes before retrying: local cancellation does not stop remote publishing, and duplicate notifications are possible. Check publisher JSON `error.stage` / `error.code` and private logs for runtime failures; raw logs may contain secrets and retain at most 1,000,000 bytes per output channel. Rotation wrappers accept PLC URLs with a trailing slash.
