# ePDS — extended Personal Data Server

ePDS lets your users sign in to [AT Protocol](https://atproto.com/) apps — like
[Bluesky](https://bsky.app/) — using familiar login methods: **email OTP**, **Google**,
**GitHub**, or any other provider [Better Auth](https://www.better-auth.com/) supports.

Under the hood, ePDS is a standard AT Protocol
[Personal Data Server (PDS)](https://atproto.com/guides/self-hosting) wrapped with a
pluggable authentication layer. Users don't need to know or care about
any of that — they just sign in with their email or social account and get a presence
in the AT Protocol universe (a DID, a handle, a data repository) automatically
provisioned for them.

```
  Your app             ePDS                               AT Protocol universe
  ────────             ──────────────────────────         ────────────────────
  [ Login ]  ───────►  [ Email OTP login        ]
             ◄───────  [ Google / GitHub        ]  ────►  Bluesky
  [ use app ]          [ Auto-creates account   ]         Other AT apps
                       [ Issues AT Protocol     ]         plc.directory
                       [   access tokens        ]
```

## What your users experience

1. Click "Login" (or enter their email) in your app
2. Receive a one-time code by email (or sign in with Google/GitHub)
3. Enter the code — done. They're logged in.

No passwords. No invite codes to distribute. No AT Protocol knowledge required.
New users get an account created automatically on their first login.

## What you get as a developer

- A fully spec-compliant AT Protocol PDS your app authenticates against
- Standard AT Protocol OAuth from your app's perspective — use any AT Protocol
  OAuth client library
- Two integration patterns depending on your UI needs — see [Login Flows](#login-flows)
- Social login support (Google, GitHub) — configured per deployment

## Login Flows

Two patterns are supported depending on whether your app collects the user's email:

- **Flow 1** — your app has its own email form: the user enters their email in your
  app, you pass it to ePDS, and the user lands directly on the OTP input. No ePDS
  email form shown.
- **Flow 2** — your app has a simple "Login" button: ePDS shows its own email input
  form and handles the whole login UI.

See [docs/tutorial.md](docs/tutorial.md) for the full integration guide including PAR
request format, authorization redirect, token exchange, and client metadata.

## Security

- OTP codes: 8-digit, single-use, short expiry
- Accounts are passwordless — login only via OTP or social providers, optionally
  set a password later
- CSRF protection, HttpOnly + SameSite cookies, HSTS, X-Frame-Options

## TEE Signing & Embedded Wallets (optional)

ePDS can optionally move all private-key material into a **TEE** (a
confidential VM the operator cannot look into), giving every user two
things from their single email login:

- **Enclave-held repo signing** — the key that signs each user's AT
  Protocol repository lives inside the enclave instead of on disk.
  Reads and writes stay fully standard; clients, relays, and AppViews
  notice nothing.
- **A self-custodial embedded wallet** (Ethereum-compatible + Solana) —
  no seed phrase surfaced, and only requests signed on the user's own
  device can spend from it. Wallet keys use a Privy-style **2-of-3
  Shamir share model** (device / server-in-TEE / recovery): the
  operator alone can never spend or trap funds, users survive device
  loss, and can always export their keys and leave.

The wallet surface is exposed as REST routes (`/wallet/*`) and as an
XRPC Lexicon namespace (`/xrpc/app.gainforest.wallet.*`): `enroll`,
`create`, `getWallet`, `sign`, `export`, `recover`.

Everything is off by default and additive — with no TEE configured,
ePDS behaves exactly as described above. See
[docs/design/tee-signer.md](docs/design/tee-signer.md) for the
architecture, threat model, and deployment requirements (the signer
must run on confidential-compute hardware, e.g.
[dstack](https://github.com/Dstack-TEE/dstack) on Intel TDX / AMD
SEV-SNP or a cloud confidential VM).

## AI Agent Skill

An [agent skill](https://github.com/vercel-labs/skills) is available for AI
coding agents (Claude Code, Cursor, Codex, etc.) to help implement login flows
against ePDS. Install it with:

```bash
npx skills add hypercerts-org/ePDS --skill epds-login
```

This installs the `epds-login` skill which covers PAR requests, DPoP proofs,
token exchange, client metadata, and both login flows.

## Further Reading

- [docs/tutorial.md](docs/tutorial.md) — login flows and integration tutorial
- [docs/architecture.md](docs/architecture.md) — internal design and package structure
- [docs/deployment.md](docs/deployment.md) — production deployment with Docker
- [docs/development.md](docs/development.md) — local development setup
- [docs/configuration.md](docs/configuration.md) — all environment variables
- [docs/design/tee-signer.md](docs/design/tee-signer.md) — TEE signer & embedded wallets (2-of-3 shares)

## License

MIT
