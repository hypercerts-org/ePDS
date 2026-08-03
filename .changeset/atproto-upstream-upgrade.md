---
'ePDS': minor
---

Signing in and managing your account now run on the latest AT Protocol server, which requires operators to upgrade to Node.js 22.

**Affects:** End users, Operators

**End users:** the account and sign-in screens now come from a newer version of the underlying AT Protocol software, bringing email verification, changing your handle, and deactivating or deleting your account through the account-management interface. The passwordless email-code sign-in you already use is unchanged.

**Operators:**

- ePDS now requires **Node.js 22** (previously 20). Deployments pinned to Node 20 must upgrade; the Docker images already use `node:22-alpine`. `engines.node` is now `>=22`.
- The bundled AT Protocol packages moved to their latest releases: `@atproto/pds` 0.5.23, `@atproto/oauth-provider` 0.21.1, `@atproto/oauth-provider-ui` 0.8.9.
- No configuration changes are required, but the native `better-sqlite3` module must be built for the Node 22 ABI — a clean `pnpm install` on Node 22 handles this; an in-place Node version switch needs `pnpm rebuild better-sqlite3`.
