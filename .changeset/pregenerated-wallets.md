---
'ePDS': minor
---

Wallet addresses can now be provisioned for any DID before its first login, so assets can be sent to a user — even one migrating from another PDS — ahead of onboarding.

**Affects:** Client app developers, Operators

**Client app developers:**

- `GET /wallet/info` (and `app.gainforest.wallet.getWallet`) gains a `pregen` field — the unclaimed pregenerated wallet's public material (`{did, evm, sol, createdAt}`), `null` when absent or after claiming.
- The first `POST /wallet/create` after enrollment claims a pregenerated wallet: it returns `status: 'claimed'` (instead of `'created'`) with the same addresses that were advertised pre-claim, plus the usual device/recovery share JWEs.
- Unclaimed wallets are receive-only: sign, export, and recover fail until the wallet is claimed.

**Operators:** new internal endpoint on pds-core — `POST /_internal/wallet/pregenerate {"did": "..."}`, gated by `x-internal-secret` and mounted only with `EPDS_WALLET_ENABLED=1`. It accepts any plausible `did:plc`/`did:web` (no local account required — the DID may live on another PDS and migrate in later), is idempotent, and returns the wallet addresses. Until claimed, the wallet's key entropy is held whole (encrypted) by the TEE signer instead of split 2-of-3, so pre-funded amounts sit under enclave custody — see docs/design/tee-signer.md ("Pregenerated wallets") for the custody caveats before pre-funding.
