---
'ePDS': minor
---

Signing in and account creation now run on the latest AT Protocol server release.

**Affects:** Client app developers, Operators

**Client app developers:** The authorization endpoint now accepts only pushed authorization requests (`request_uri` from the PAR endpoint). Clients built on `@atproto/oauth-client-node` already do this; clients that send the parameters directly on the `/oauth/authorize` query string must switch to PAR.

**Operators:**

- Node.js must now satisfy `^22.22.3 || ^24.11.1 || >=25.1.0` (`engines` in the root and `pds-core` `package.json`; `.nvmrc` is 22.22.3). The Docker images use the floating `node:22-alpine` tag, which meets this.
- The upgrade runs migration `008-account-email-auth-factor` on `account.sqlite` at pds-core startup, and the previous image refuses the migrated database. Snapshot `account.sqlite` before cutover: stop pds-core first and copy `account.sqlite` together with any `-wal` and `-shm` files, or take the snapshot online with `sqlite3 account.sqlite ".backup 'account.snapshot.sqlite'"` (or `VACUUM INTO`). Rolling back means restoring that snapshot, which discards every account write made after it was taken, including writes between the snapshot and the cutover.
- Upgraded packages: `@atproto/pds` 0.5.66, `@atproto/oauth-provider` 0.27.3, `@atproto/oauth-provider-ui` 0.11.2, `@atproto-labs/fetch-node` 0.5.0 (patched undici).
- The upstream account page now offers users an email one-time-code toggle (`/oauth/api/enable-email-otp`, `/disable-email-otp`). ePDS does not hide or brand it; it does not affect ePDS sign-in, which does not use that factor.
