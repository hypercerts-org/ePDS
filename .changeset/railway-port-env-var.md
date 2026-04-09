---
'epds': patch
---

Honour the generic `PORT` environment variable on both services, so
Railway's automatic healthcheck succeeds without per-service
configuration.

**Affects:** Operators

New port-resolution precedence (first set value wins):

- **auth service:** `AUTH_PORT` → `PORT` → `3001`
- **pds-core:** `PDS_PORT` → `PORT` → `3000` (pds-core reads
  `PDS_PORT`; when `PDS_PORT` is unset, `PORT` is copied into it
  before `@atproto/pds` reads its environment)

If you run ePDS on Docker Compose or another orchestrator where you
set `AUTH_PORT` / `PDS_PORT` explicitly: no change — your existing
settings take precedence over `PORT`.

If you run ePDS on Railway (or any platform that injects `PORT`
automatically): you can now remove service-specific `AUTH_PORT` /
`PDS_PORT` overrides from your Railway variables. Each service
will pick up Railway's injected `PORT` and healthchecks will bind
correctly. Previously these services bound to their hardcoded
defaults regardless of `PORT`, causing Railway healthchecks to
fail.
