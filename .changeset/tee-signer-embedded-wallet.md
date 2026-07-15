---
'ePDS': minor
---

Optional secure-hardware key protection: accounts can have their data-signing key held in a locked-down secure enclave, and every user can get a built-in crypto wallet that only they can authorize — the server operator can never read or use the keys.

**Affects:** End users, Client app developers, Operators

**End users:** nothing changes in how you sign up or sign in. On instances that enable the wallet, your account comes with crypto wallet addresses (Ethereum-compatible and Solana) — no seed phrase to manage, and only requests approved on your device can spend from it.

**Client app developers:** three new routes on the PDS when the operator sets `EPDS_WALLET_ENABLED=1`, all fully separate from ATProto repo reads/writes:

- `POST /wallet/enroll` (OAuth/access token required) — register the user's request public key: body `{ "requestPublicKeyHex": "<compressed P-256, 66 hex chars>" }`. First key wins (trust-on-first-use); re-enrolling a different key returns `409`.
- `GET /wallet/info` (OAuth/access token required) — returns `{ did, enrolled, evm: { address, publicKeyHex }, sol: { address, publicKeyHex } }`.
- `POST /wallet/sign` — body `{ "payload": "<base64url JSON>", "sig": "<base64url compact P-256 signature over SHA-256(payload)>" }`. The payload carries `did`, `purpose` (`wallet/evm` with a 32-byte `digestHex`, or `wallet/sol` with `messageBase64`), a strictly increasing `nonce`, and an `iat` within a freshness window (default 120 s). No PDS token is required or accepted as authorization here — the user-signed envelope is the authorization. Bad envelopes return `403`, replayed nonces `409`.

**Operators:** all off by default; with no new env vars set, behaviour is unchanged.

- New workspace package `packages/signer` — a standalone signing service that holds a root seed and derives per-user keys. In production it must run on confidential-compute hardware (dstack in a TDX/SEV-SNP confidential VM — never Railway/plain Docker); `pnpm dev:signer` runs it locally. Configure via `SIGNER_PORT`, `SIGNER_DATA_DIR`, `SIGNER_INTERNAL_SECRET`, `SIGNER_ROOT_SEED_HEX`/`SIGNER_ROOT_SEED_FILE`, `SIGNER_ALLOW_DEV_SEED`, `SIGNER_WALLET_FRESHNESS_SEC`, `SIGNER_DSTACK_SOCK`.
- New pds-core env vars: `EPDS_SIGNER_URL` (master switch), `EPDS_SIGNER_SECRET` (must match `SIGNER_INTERNAL_SECRET`; startup fails with "EPDS_SIGNER_SECRET must be set when EPDS_SIGNER_URL is set" if missing), `EPDS_SIGNER_REQUIRE_ATTESTATION=1` (refuse unattested signers — set in any real deployment), `EPDS_TEE_REPO_SIGNING=1` (enclave-signed repo commits for adopted accounts + `POST /_internal/tee/adopt` migration endpoint), `EPDS_TEE_ADOPT_ON_SIGNUP=1`, `EPDS_WALLET_ENABLED=1`.
- See `docs/design/tee-signer.md` for the architecture, threat model, and migration/rollback procedure before enabling repo signing.
