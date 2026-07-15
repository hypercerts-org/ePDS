# TEE signer — enclave-held repo signing keys and embedded wallets

Status: implemented (opt-in, off by default)

## What this is

An optional extension that gives each ePDS user, from their single
ATProto login, two things at once:

1. their normal ATProto repo identity (the key that signs their repo), and
2. a self-custodial crypto wallet (EVM + Solana),

where every private key is created and used inside a **TEE** (a
confidential VM the operator cannot look into). No seed phrase, and the
operator cannot extract the keys.

## The two flows stay separate — always

This is the load-bearing design rule. ePDS keeps **normal ATProto reads
and writes exactly as they are**; the wallet is purely **additive**. The
two flows share only the transport to the signer:

|                             | Repo flow (normal ATProto)                  | Wallet flow (additive)                                                    |
| --------------------------- | ------------------------------------------- | ------------------------------------------------------------------------- |
| Key purpose                 | `atproto/signing`                           | `wallet/evm`, `wallet/sol`                                                |
| Curve                       | secp256k1                                   | secp256k1 (EVM), ed25519 (Solana)                                         |
| Signer route                | `POST /v1/sign/repo`                        | `POST /v1/wallet/*`                                                       |
| PDS surface                 | actor-store seam (invisible)                | `/wallet/*` routes                                                        |
| Who can trigger a signature | the PDS (server-to-server, internal secret) | only the **user**, via an envelope signed with their enrolled request key |
| Enable flag                 | `EPDS_TEE_REPO_SIGNING=1`                   | `EPDS_WALLET_ENABLED=1`                                                   |

Keys are derived per `(did, purpose)` with the purpose baked into the
HKDF info string, so the repo key and the wallet keys are
cryptographically unrelated even where they share a curve. The signer's
repo route can only ever reach `atproto/signing` keys; the wallet route
only `wallet/*` keys. Neither flag requires the other.

## Architecture

```
ATProto client ──login──▶ pds-core ──"sign digest for did X"──▶ signer (in the TEE)
                          │            x-internal-secret          - holds the root seed
                          │                                       - derives per-(did,purpose) keys
                          │ never holds an enclave key            - wallet signs ONLY user-signed
                          ▼                                         envelopes
                    repo reads/writes                             - proves itself (attestation)
Wallet client ──user-signed envelope──▶ pds-core /wallet/sign ──▶ signer /v1/wallet/sign
```

- **pds-core** does all normal ATProto work. With `EPDS_TEE_REPO_SIGNING=1`
  it patches `actorStore.keypair(did)` so TEE-adopted accounts get a
  `TeeKeypair` whose `sign()` sends the SHA-256 digest to the signer.
  Non-adopted accounts keep the stock local-key path untouched.
- **`packages/signer`** is a separate service that holds the root seed and
  signs on request. It runs as a dstack workload in a confidential VM in
  production and as a plain process in dev.

### ATProto signing rules honoured

- The PDS hashes commit bytes with SHA-256 exactly once; the signer signs
  the raw digest (`prehash: false`) — no Ethereum prefix, no keccak.
- Signatures are low-S normalized, compact 64-byte `r || s`.
- The enclave public key is registered in the DID document `#atproto`
  entry as a did:key/Multikey via `@atproto/crypto`'s `formatDidKey`.
- PLC **rotation keys stay separate** from the signing key: adoption ops
  are signed by the PDS's existing PLC rotation key (or a KMS-backed
  one), which the signer never holds.

### Account adoption (repo flow)

Stock `@atproto/pds` creates the per-account signing key inline during
account creation, with no config hook. Rather than fork that code,
accounts are **adopted** into TEE signing after creation:

1. Signer derives the account's `atproto/signing` key, returns its did:key.
2. pds-core publishes a PLC op rotating `#atproto` to that did:key
   (signed by the PLC rotation key).
3. Only after PLC accepts, a `tee.json` marker is written into the
   actor's directory. From then on `actorStore.keypair(did)` returns the
   `TeeKeypair`.
4. An identity event is sequenced so relays pick up the new key.

Adoption is idempotent and triggered either automatically for new
accounts (`EPDS_TEE_ADOPT_ON_SIGNUP=1`) or per-account via
`POST /_internal/tee/adopt {"did": ...}` (internal-secret gated) for
migrating existing accounts. The old local key file is left in place so
rollback is "delete marker + rotate PLC back".

### The user check (wallet flow)

The single most important property: **the signer produces a wallet
signature only for a request the user signed.** A PDS-forwarded OAuth
token is deliberately not accepted — if it were, whoever compromises the
PDS host could drain wallets even though keys never leave the TEE.

- At enrollment (`POST /wallet/enroll`, OAuth-token authenticated), the
  client registers a compressed P-256 **request public key** — e.g. a
  WebCrypto non-extractable key or a passkey-wrapped key. Enrollment is
  trust-on-first-use; the signer refuses to overwrite an existing
  enrollment (rotation would require a request signed by the current key
  and is future work).
- Every `POST /wallet/sign` carries an envelope
  `{payload: b64url(JSON), sig: b64url(P-256 over SHA-256(payload))}`
  with `did`, `purpose`, the EVM digest / Solana message, a strictly
  increasing `nonce`, and an `iat` freshness timestamp. The signer
  verifies the signature against the enrolled key, the freshness window,
  and the monotonic nonce before signing. pds-core is a pure relay here.

### Honest limitation: OTP login and the enrollment bootstrap

ePDS users are passwordless (email OTP). The enrollment step is
therefore authorized by an OAuth token — which the operator's own
auth-service issues. A malicious operator could enroll their own request
key for a **new, not-yet-enrolled** account and control that wallet.
TOFU means they can never take over an already-enrolled wallet. Fully
closing the bootstrap gap requires binding enrollment to something the
operator can't mint (WebAuthn/passkey attestation) — documented future
work. Until then, the honest claim is: enrolled wallets are
self-custodial; enrollment itself trusts the operator once.

### Threat model (what an evil host can and cannot do)

Cannot: read the root seed or any derived key (memory encrypted, keys
never on the PDS host at all); swap the signer for a key-stealing build
without changing the attestation measurement; forge a wallet signature
for an enrolled wallet (no user envelope, no signature).

Can — design against it:

- **Feed the repo signer doctored commits.** Bounded: identity is
  recoverable via rotation keys the host doesn't control; did:plc's
  audit log lets you undo hostile changes.
- **Replay wallet envelopes after a disk rollback.** The nonce table is
  host-controlled disk; rolling it back re-opens a replay window for
  envelopes the user already signed (never new ones). Production should
  anchor freshness outside the host; the `iat` window limits exposure.
- **Take you offline.** TEEs protect secrecy/integrity, not uptime.
- **Side-channels** against TDX/SEV — low probability, real for a
  determined host.

Two things the PDS/signer host must never hold: the **PLC rotation
keys' authority** beyond what stock PDS already has (keep a recovery
rotation key offline; `PDS_RECOVERY_DID_KEY` upstream supports this) and
the **KMS / code-approval authority** for the TEE (run by a separate
party in production).

### Attestation

`GET /v1/attestation` on the signer returns
`{mode, reportData, quote, identityPublicKeyHex}` where `reportData` is
SHA-256 of the signer's derived identity public key. Inside a dstack CVM
the quote comes from the guest agent (`/var/run/dstack.sock`); outside,
`mode: 'dev'` with no quote. pds-core refuses to start against an
unattested signer when `EPDS_SIGNER_REQUIRE_ATTESTATION=1` — set it in
any split-host deployment. (Full attested-TLS channel binding — TLS key
inside the quote — is future work; until then run the PDS↔signer link
over a private network and require the quote at startup.)

### Failover

Derivation is pure `(rootSeed, did, purpose)` — no per-key state. A
replacement signer that passes attestation and receives the same root
seed from the dstack KMS derives identical keys. Only wallet
enrollments + nonces (a small sqlite file) need replication.

## Where things run

- **pds-core / auth-service**: unchanged — Docker, Railway, anywhere.
- **signer**: real confidential-compute hardware only — dstack on your
  own TDX/SEV-SNP box, a cloud confidential VM (GCP/Azure/Nitro), or
  Phala. **Never Railway or plain Docker in production** — there the
  platform is exactly the host the TEE is supposed to lock out. Dev mode
  (plain process, `SIGNER_ALLOW_DEV_SEED=1`) exists for local work only.

## Configuration

See [configuration.md](../configuration.md) (PDS Core → TEE signer &
wallet; Signer section) and `packages/signer/.env.example`.

## Code map

| Piece                        | Path                                                                                                            |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Signer service (TEE side)    | `packages/signer/src/` — `derive.ts`, `envelope.ts`, `service.ts`, `attestation.ts`, `store.ts`, `root-seed.ts` |
| Purpose separation           | `packages/signer/src/purposes.ts`                                                                               |
| PDS→signer client            | `packages/shared/src/signer-client.ts`                                                                          |
| Repo seam (`Keypair` impl)   | `packages/pds-core/src/tee/tee-keypair.ts`                                                                      |
| Actor-store patch + adoption | `packages/pds-core/src/tee/actor-store-tee.ts`                                                                  |
| Wallet routes                | `packages/pds-core/src/tee/wallet-router.ts`                                                                    |
| Wiring / env flags           | `packages/pds-core/src/tee/setup.ts`                                                                            |
