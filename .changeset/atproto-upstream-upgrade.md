---
'ePDS': minor
---

Signing in and managing your account now run on the latest AT Protocol server, which requires operators to upgrade to Node.js 22.19 or newer.

**Affects:** End users, Operators

**End users:** the account and sign-in screens now come from a newer version of the underlying AT Protocol software, which adds changing your handle and deactivating or deleting your account through the account-management interface. The passwordless email-code sign-in and email verification you already use through ePDS are unchanged.

**Operators:**

- ePDS now requires **Node.js 22.19.0 or newer** (previously 20). Deployments pinned to Node 20 must upgrade; the Docker images already use `node:22-alpine`. `engines.node` is now `>=22.19.0` (the floor is set by a transitive `undici@8` runtime dependency, which fails on Node 22.0–22.18).
- The bundled AT Protocol packages moved to their latest releases: `@atproto/pds` 0.5.23, `@atproto/oauth-provider` 0.21.1, `@atproto/oauth-provider-ui` 0.8.9.
- No configuration changes are required, but the native `better-sqlite3` module must be built for the Node 22 ABI — a clean `pnpm install` on Node 22 handles this; an in-place Node version switch needs `pnpm rebuild better-sqlite3`.
