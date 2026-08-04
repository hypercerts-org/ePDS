---
'ePDS': minor
---

Public wallet receive-address lookup by decentralized identifier.

**Affects:** Client app developers, Operators

**Client app developers:** Use the unauthenticated `GET /xrpc/app.gainforest.wallet.getPublicWallet?did=<did>` query or `GET /wallet/public-info?did=<did>` REST alias to retrieve a claimed or pregenerated wallet's receive addresses and public keys. The response contains `{ did, status, wallet }`, where `status` is `claimed` or `pregenerated`; it intentionally omits enrollment state and enclave encryption metadata. This enables handle-to-wallet transfers after resolving an AT Protocol handle to its DID.

**Operators:** Instances with `EPDS_WALLET_ENABLED=1` now expose this additive public read endpoint. Wallet DIDs are not enumerable through the endpoint, but known DIDs can be queried for public receiving information.
