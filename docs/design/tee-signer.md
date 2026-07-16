# TEE signer — enclave-held repo signing keys and embedded wallets

Status: implemented (opt-in, off by default)

## What this is

An optional extension that gives each ePDS user, from their single
ATProto login, two things at once:

1. their normal ATProto repo identity (the key that signs their repo), and
2. a self-custodial crypto wallet (EVM + Solana),

where every private key is created and used inside a **TEE** (a
confidential VM the operator cannot look into). No seed phrase surfaced,
and the operator cannot extract the keys — nor trap them: wallets use a
Privy-style 2-of-3 Shamir share scheme in which the user independently
holds a share majority (device + recovery), so they can always recover
or leave without the operator.

## The two flows stay separate — always

This is the load-bearing design rule. ePDS keeps **normal ATProto reads
and writes exactly as they are**; the wallet is purely **additive**. The
two flows share only the transport to the signer:

|                             | Repo flow (normal ATProto)                  | Wallet flow (additive)                                                    |
| --------------------------- | ------------------------------------------- | ------------------------------------------------------------------------- |
| Key purpose                 | `atproto/signing`                           | `wallet/evm`, `wallet/sol`                                                |
| Curve                       | secp256k1                                   | secp256k1 (EVM), ed25519 (Solana)                                         |
| Key material                | derived from the enclave root seed          | independent per-wallet entropy, split 2-of-3 (Shamir)                     |
| If the key is lost          | re-derive, or mint + rotate `#atproto`      | reconstruct from any 2 of 3 shares                                        |
| Signer route                | `POST /v1/sign/repo`                        | `POST /v1/wallet/*`                                                       |
| PDS surface                 | actor-store seam (invisible)                | `/wallet/*` + `/xrpc/app.gainforest.wallet.*`                             |
| Who can trigger a signature | the PDS (server-to-server, internal secret) | only the **user**, via an envelope signed with their enrolled request key |
| Enable flag                 | `EPDS_TEE_REPO_SIGNING=1`                   | `EPDS_WALLET_ENABLED=1`                                                   |

The two key types deliberately have **different durability models**,
because they have different recovery properties. The repo signing key is
_disposable_: if it is ever lost, a fresh key is minted and the DID's
`#atproto` method rotated to it — so root-seed derivation (HKDF per
`(did, purpose)`) is exactly right, and a failover enclave re-derives
identical keys. A wallet key is _not_ disposable — the address IS the
account — so it is never derivable from the root: each wallet is an
independent 128-bit secret under a 2-of-3 share split (below). The
signer's repo route can only ever reach `atproto/signing` keys; the
wallet routes only wallet material. Neither flag requires the other.

## Architecture

```
ATProto client ──login──▶ pds-core ──"sign digest for did X"──▶ signer (in the TEE)
                          │            x-internal-secret          - holds the root seed
                          │                                       - derives per-DID repo keys
                          │ never holds an enclave key            - holds 1 of 3 wallet shares
                          ▼                                         (encrypted); reconstructs
                    repo reads/writes                               transiently for user-signed
                                                                    envelopes only
Wallet client ──user-signed envelope + device share (JWE)──▶      - proves itself (attestation)
                pds-core /wallet/* ──▶ signer /v1/wallet/*
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

(The wallet flow has an analogous internal endpoint —
`POST /_internal/wallet/pregenerate` — described under “Pregenerated
wallets” below.)

### Wallet keys: per-wallet entropy + 2-of-3 Shamir shares

On `POST /wallet/create` the enclave generates 128 bits of CSPRNG
entropy, derives a standard HD wallet from it (BIP-39 → BIP-32
`m/44'/60'/0'/0/0` for EVM, SLIP-10 `m/44'/501'/0'/0'` for Solana), and
splits the entropy 2-of-3 with Shamir's Secret Sharing ([Privy's
audited `shamir-secret-sharing`
library](https://github.com/privy-io/shamir-secret-sharing)):

- **Server share** — the only thing the signer persists, encrypted
  AES-256-GCM under a KEK derived from the root seed (the
  measurement-bound key: only an attested enclave that received the
  seed can use it — opaque to the operator and storage admins).
- **Device share** — returned to the user encrypted (JWE ECDH-ES) to
  their enrolled P-256 request key. Never persisted server-side.
- **Recovery share** — same delivery; the client must re-protect it
  under a user-controlled **recovery factor** (password or user-cloud
  backup). The operator can never read it.

Every wallet operation reconstructs the entropy **transiently inside
the enclave** from the server share plus a user share, verifies the
reconstructed key against the wallet's registered public keys, signs,
and wipes. The user share travels JWE-encrypted **to the enclave's own
encryption key** (published in `/v1/attestation` and `/wallet/info`),
so the relaying PDS never sees share plaintext.

The custody invariant (the reason this is self-custodial): **no single
party ever holds ≥ 2 shares, and the user independently controls ≥ 2**
(device + recovery). Consequences:

- _Machine burns down:_ a fresh attested enclave re-reads the encrypted
  server share (KEK re-derived from the KMS-released root seed) and
  combines it with the user's device share. No user action needed.
- _User loses device:_ `POST /wallet/recover` with the recovery share.
  The enclave verifies the share actually reconstructs this wallet
  (that possession — not the caller — is the authorization), re-splits
  with **fresh coefficients** (old/stolen shares become useless),
  optionally rotates the enrolled request key, and returns fresh
  device + recovery shares.
- _Operator disappears or turns hostile:_ the user holds device +
  recovery — a reconstructing majority — and `POST /wallet/export`
  (user-signed envelope, response encrypted to the user's request key)
  hands over the mnemonic/private keys. Credible exit either way; the
  operator can freeze, never trap.

### Pregenerated wallets (defer-split)

A wallet can be provisioned for a DID **before its first login**:
`POST /_internal/wallet/pregenerate {"did": ...}` on pds-core
(internal-secret gated, requires `EPDS_WALLET_ENABLED=1`), so airdrops
or migrated balances can be sent to an account ahead of onboarding.
Pregeneration is keyed by DID alone — **any plausible `did:plc` /
`did:web` is accepted, including one whose account still lives on
another PDS** and migrates here later. Claiming (not pregeneration) is
what requires a local authenticated account.

Instead of splitting, the enclave persists the wallet's **whole
entropy**, encrypted under the same measurement-bound KEK as server
shares but in a distinct AAD domain (a pregen blob can never be
presented as a server share, or vice versa). The addresses are
returned immediately and appear as `pregen` in `/wallet/info` until
claimed. The call is idempotent.

Custody honesty: until claimed, such a wallet is **enclave-custodial**
— the 2-of-3 invariant does not hold yet, exactly as a Privy
pregenerated wallet is Privy-custodial until first login. Two rules
bound that window:

- **Unclaimed wallets are receive-only.** sign/export/recover all
  require the wallet record that only claiming creates; the signer
  cannot produce a signature for an unclaimed wallet.
- **Claiming destroys the whole-entropy blob.** The user's first
  `POST /wallet/create` after enrollment decrypts the entropy,
  verifies it reproduces the advertised addresses, splits it 2-of-3,
  and deletes the blob in the same transaction. The response carries
  `status: 'claimed'` (instead of `'created'`) with the same
  addresses; from then on the wallet is indistinguishable from one
  created normally.

The enrollment-bootstrap caveat (below) applies with more force here:
whoever enrolls first for a DID claims any assets already sent to its
pregenerated addresses. Until enrollment is passkey-bound, do not
pre-fund wallets beyond what the TOFU trust note tolerates.

### Wallet Lexicon surface (`app.gainforest.wallet.*`)

The wallet is reachable on two equivalent PDS surfaces backed by the
same handlers — plain REST and an XRPC Lexicon namespace. All wallet
NSIDs (and any future wallet Lexicon schemas or sidecar record types)
live under **`app.gainforest.*`**. At startup, ePDS places this custom
XRPC router in a thin gateway before the stock `@atproto/pds` app; all
unmatched methods fall through unchanged. This ordering is required
because the upstream app owns a catch-all `/xrpc` handler and would
otherwise intercept custom NSIDs:

| XRPC method (NSID)                      | Type      | REST alias                | Auth                                |
| --------------------------------------- | --------- | ------------------------- | ----------------------------------- |
| `app.gainforest.wallet.enroll`          | procedure | POST `/wallet/enroll`     | OAuth token (TOFU bootstrap)        |
| `app.gainforest.wallet.create`          | procedure | POST `/wallet/create`     | OAuth token                         |
| `app.gainforest.wallet.getWallet`       | query     | GET `/wallet/info`        | OAuth token (own wallet material)   |
| `app.gainforest.wallet.getPublicWallet` | query     | GET `/wallet/public-info` | Public; receive info by DID         |
| `app.gainforest.wallet.sign`            | procedure | POST `/wallet/sign`       | user-signed envelope + device share |
| `app.gainforest.wallet.export`          | procedure | POST `/wallet/export`     | user-signed envelope + device share |
| `app.gainforest.wallet.recover`         | procedure | POST `/wallet/recover`    | possession of the recovery share    |

`getPublicWallet` returns only the claimed or pregenerated wallet's receive addresses and public keys. It deliberately omits enrollment state and enclave encryption metadata, allowing clients to resolve an ATProto handle to a DID and then find its receiving wallet without authenticating.

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
- Every `POST /wallet/sign` (and `/wallet/export`, with `op: 'export'`)
  carries an envelope
  `{payload: b64url(JSON), sig: b64url(P-256 over SHA-256(payload))}`
  with `did`, `purpose`, the EVM digest / Solana message, the
  `deviceShareJwe` (the user's device share, encrypted to the enclave),
  a strictly increasing `nonce`, and an `iat` freshness timestamp. The
  signer verifies the signature against the enrolled key, the freshness
  window, and the monotonic nonce — and can only even reconstruct the
  wallet key when the envelope carries a genuine share. pds-core is a
  pure relay here.
- Enrollment rotation happens only through `POST /wallet/recover`,
  where possession of the recovery share authorizes binding a new
  request key (device replacement).

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
never on the PDS host at all); read the wallet server share at rest
(encrypted under the measurement-bound KEK); reconstruct any wallet
unilaterally (the operator holds at most one share — the invariant the
2-of-3 split exists for); swap the signer for a key-stealing build
without changing the attestation measurement; forge a wallet signature
for an enrolled wallet (no user envelope carrying a real share, no
signature).

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

Repo-key derivation is pure `(rootSeed, did)` — no per-key state. A
replacement signer that passes attestation and receives the same root
seed from the dstack KMS derives identical repo keys, and can decrypt
the wallet server shares (the KEK derives from the same root seed).
The sqlite store — wallet records (encrypted server shares + public
material), enrollments, nonces — must be replicated; it contains no
plaintext secrets and at most **one** share per wallet, so replication
targets never gain spending power.

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

| Piece                        | Path                                                                                                                         |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Signer service (TEE side)    | `packages/signer/src/` — `derive.ts`, `wallet.ts`, `envelope.ts`, `service.ts`, `attestation.ts`, `store.ts`, `root-seed.ts` |
| Wallet share model (2-of-3)  | `packages/signer/src/wallet.ts`                                                                                              |
| Purpose separation           | `packages/signer/src/purposes.ts`                                                                                            |
| PDS→signer client            | `packages/shared/src/signer-client.ts`                                                                                       |
| Repo seam (`Keypair` impl)   | `packages/pds-core/src/tee/tee-keypair.ts`                                                                                   |
| Actor-store patch + adoption | `packages/pds-core/src/tee/actor-store-tee.ts`                                                                               |
| Wallet routes                | `packages/pds-core/src/tee/wallet-router.ts`                                                                                 |
| Wiring / env flags           | `packages/pds-core/src/tee/setup.ts`                                                                                         |
