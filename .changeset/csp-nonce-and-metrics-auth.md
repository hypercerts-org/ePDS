---
'ePDS': minor
---

Auth service tightens its Content-Security-Policy and locks down the metrics endpoint.

**Affects:** Operators

**Operators:** the auth service's `Content-Security-Policy` response header now uses a per-response nonce on the `script-src` directive instead of `'unsafe-inline'`. The resulting policy looks like `default-src 'self'; script-src 'self' 'nonce-<base64url>'; style-src 'self' 'unsafe-inline'; img-src 'self' data: [client-origin]; connect-src 'self'`. All inline `<script>` tags that ePDS ships are already stamped with the matching nonce, so there is nothing to do on upgrade — but any operator-supplied HTML overlay or injected script that the auth service happens to serve inline will now be blocked by the browser unless it is updated to read `res.locals.cspNonce` and stamp `<script nonce="...">`. External scripts loaded via `src=` are unaffected.

The `/metrics` endpoint on the auth service is now deny-by-default: if `PDS_ADMIN_PASSWORD` is unset, the endpoint returns `401 Unauthorized` instead of serving metrics unauthenticated. Previously, unset meant "no auth required", which leaked process uptime, RSS memory, and database counters to anyone who could reach the auth service's `/metrics` path. Operators who relied on the open endpoint must set `PDS_ADMIN_PASSWORD` and send HTTP Basic auth as `admin:<password>` to continue scraping.
