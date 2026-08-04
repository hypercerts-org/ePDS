---
'ePDS': minor
---

Authenticated wallet users can prepare a receive-only wallet for someone who has not joined the ePDS yet.

**Affects:** End users, Client app developers, Operators

**End users:** A pregenerated wallet for an external account remains receive-only until that exact account migrates to this ePDS and claims it. Clients must ask for confirmation and explain this custody limitation before sending funds.

**Client app developers:** Call `POST /xrpc/app.gainforest.wallet.prepareRecipient` or `POST /wallet/prepare-recipient` with `{ "did": "did:plc:..." }` and the sender's OAuth token. The idempotent response is `{ did, status, wallet }`; `status` is `claimed` when a wallet already exists or `pregenerated` when the receive-only wallet exists or was created. Resolve an AT Protocol handle to a DID first, and require explicit sender confirmation before provisioning an external DID.

**Operators:** Instances with `EPDS_WALLET_ENABLED=1` expose this authenticated provisioning procedure. It can add signer storage records for target DIDs requested by authenticated users; monitor usage and apply gateway rate limits appropriate to the deployment.
