## Session-reuse bugs

Follow-up to [cross-client-session-reuse](./cross-client-session-reuse.md) (HYPER-268, PR #96).

### Symptom

After PR #96 shipped, at least one user (`lukas@maearth.com` on
`epds1.test.certified.app`) reported that the **second** sign-in via an OAuth
client (specifically `staging.app.maearth.dev`) did not land on the enriched
account picker. Instead it landed on upstream `@atproto/oauth-provider`'s
stock welcome page — "Authenticate / Create a new account / Sign in /
Cancel" — as if the device had no bound accounts at all.

The user could sign in normally again after clearing their browser cache.
Other users on the same client, and the same user on a different client
(`epds-demo.test.certified.app`), were unaffected at the time the report
came in.

### How PR #96 introduced the regression

Pre-#96, upstream's `dev-id` / `ses-id` cookies were **host-only** on the
pds-core origin. auth-service, running on a sibling subdomain, could not
read them. Every incoming `/oauth/authorize` request at auth-service
therefore had no visible device session and **always** fell through to the
email/OTP form. Stale or partial cookies on pds-core's origin existed in
this era too — users just never saw them, because auth-service never
looked at them.

PR #96 intentionally broadened the cookie scope to the shared parent
domain so auth-service could _see_ the upstream session and skip the
email form when one was present — the cross-client session-reuse fast
path. At the same time it added `shouldReuseSession()` in auth-service,
which checks for `dev-id` and, if present, 302-redirects the browser
into pds-core's `/oauth/authorize` instead of rendering the email form.

The regression is in the signal `shouldReuseSession` trusts. "A `dev-id`
cookie is present" does not reliably mean "the user has a usable
session on pds-core". It fires in every case described in the next
section — partial pairs, stale pairs, DB rows whose bindings have been
purged — and each of those resolves, server-side, to an empty device
that hydrates the stock welcome page. So the breakage isn't in the
email-form code path: it's that auth-service now **skips** the email
form based on a cookie signal that doesn't guarantee a usable session.

### Root cause

`auth-service`'s `shouldReuseSession` decides whether to redirect an
incoming `/oauth/authorize` request to `pds-core` based on the presence of
an upstream `dev-id` cookie. `dev-id` is scoped (post-#96) to the PDS's
parent domain, so both the auth-service and pds-core see it.

Upstream pds-core (`@atproto/oauth-provider`) parses the cookie pair in
`DeviceManager.getCookies()`:

- Requires **both** `dev-id` **and** `ses-id` to be parseable. If either is
  missing or fails schema validation, `getCookies` returns `null` and
  `load()` falls through to `create()` — a **brand new, empty device row**
  with a **new** dev-id/ses-id cookie pair.
- When the pair parses, `refresh()` reads the device row from SQLite. If
  the sessionId in the cookie does not match the sessionId in the database
  and the row's `lastSeenAt` is older than `SESSION_FIXATION_MAX_AGE` (5
  seconds), the code calls `deleteDevice(deviceId)` and then `create()` —
  again a brand new empty device.
- If the device row does not exist in the database at all (e.g. because
  another request already ran the fixation-deletion branch, or the row was
  manually purged), `readDevice` returns `null` and `load()` falls through
  to `create()`.

In all three cases — partial cookie pair, stale-but-matching pair against a
mismatched sessionId, and outright-missing DB row — the end state is the
same: a new device is created, bound to zero accounts. The chooser (whether
via `/oauth/authorize` or `/account`) hydrates from `window.__sessions = []`
and renders upstream's stock welcome page.

`auth-service`'s current check is too permissive — it only looks at
`dev-id` as a raw string — so any stale cookie on `dev-id` is enough to
trigger a redirect to pds-core, where the user then lands on the stock
welcome page.

### Reproduction

Confirmed in Chromium via `agent-browser`:

1. Inject two well-formed but server-unknown cookies on the PDS parent
   domain:
   ```
   dev-id=dev-0123456789abcdef0123456789abcdef;
     Domain=.<pds-host>; Path=/; Secure; HttpOnly; SameSite=Lax
   ses-id=ses-fedcba9876543210fedcba9876543210;
     Domain=.<pds-host>; Path=/; Secure; HttpOnly; SameSite=Lax
   ```
2. Navigate to the demo client's flow-2 sign-in button.
3. The browser is redirected through auth-service to pds-core's
   `/oauth/authorize` and renders the stock welcome page.

Repro variant: remove either `dev-id` or `ses-id` of a valid pair (leaving
only one of the two). The auth-service still redirects (because `dev-id` is
present), and pds-core falls through to `create()` because `parseCookie`
requires both cookies. Same end state.

### How users end up in this state

In declining order of likelihood:

- **Migration 005 TTL purge.** `@atproto/pds`'s migration 005 deletes
  `device_account` rows where `remember=0` and `authenticatedAt < now - 1h`.
  A user who signed in without "remember me" more than an hour ago has a
  valid `dev-id`/`ses-id` pair on the client but zero `account_device` rows
  in the database. Upstream's chooser renders empty.
- **Concurrent-request fixation race.** Two overlapping `/oauth/authorize`
  requests can cause one branch to rotate the sessionId while the other
  still carries the old one. If the older request arrives more than 5s
  after `lastSeenAt`, it hits the fixation-deletion branch
  (`device-manager.ts:164-168`) and deletes the device. The next request
  creates a fresh empty device.
- **Cookie-jar partial eviction.** Browsers can evict cookies
  asymmetrically (cookie-jar size limits, per-site quota, storage
  pressure). Even though upstream writes `dev-id` and `ses-id` with
  identical options, the jar can retain one and drop the other.
- **Scope transition at #96 deploy.** Pre-#96 cookies were host-only on the
  PDS host; post-#96 cookies are domain-scoped on the parent. Depending on
  the sequence of requests around the deploy, a browser could end up
  holding the old host-only variant of one cookie and the new
  domain-scoped variant of its partner. Browsers send both. RFC 6265
  merges by name only for the header line, so the server sees whichever
  appeared first — which may validate, fail to validate, or mismatch
  against the server's current DB state.

All four cases converge to the same server-side behavior: upstream
allocates a fresh empty device and renders the stock welcome page.

### Fix (layered)

#### Layer 1 — auth-service: require the full cookie pair

`hasDeviceSessionCookie` is tightened to return `true` only when **both**
`dev-id` and `ses-id` are present on the request. A partial pair is
treated as no session at all, so the request falls through to
auth-service's own email/OTP flow instead of being redirected into pds-core.

This catches the cookie-jar-eviction and scope-transition cases cheaply,
before any cross-service redirect.

It does NOT catch the stale-but-complete-pair cases (migration purge,
fixation race, deleted DB row). Those reach pds-core and need Layer 2.

When auth-service's `/oauth/authorize` handler detects a half-pair
(exactly one of `dev-id` / `ses-id` present) via `hasOrphanDeviceCookie`,
it also appends `Max-Age=0` `Set-Cookie` headers for **both** cookies in
**both** the host-only and shared-parent-domain scopes before rendering
the email form. Browsers treat host-only and domain-scoped variants as
distinct cookies, so clearing only one leaves the other behind and the
half-pair state survives into the next OAuth flow. Clearing both names
in both scopes unconditionally (not just the orphan half) is idempotent
and avoids branching — the caller has already confirmed we're in an
orphan state. The shared parent domain is derived with the same rule
pds-core's cookie-domain middleware uses (auth-service hostname ends
with `.<PDS_HOSTNAME>` → `PDS_HOSTNAME` is the parent; otherwise no
domain-scoped clear is needed).

#### Layer 2 — pds-core: pre-route check before upstream renders

The three-button stock welcome page ("Authenticate / Create new account /
Sign in / Cancel") is structurally unreachable from ePDS by design: every
user-facing entry point into pds-core either has bound sessions to show
or should be driven by auth-service's email/OTP flow. A pre-route Express
middleware, mounted early in pds-core's stack on `/oauth/authorize` and
`/account`, short-circuits the request before upstream's signin handler
runs:

1. Parse the `dev-id` + `ses-id` cookie pair side-effect-free using
   upstream's exported Zod schemas (not `deviceManager.load`, which
   has a side effect — it deletes the device row on a partial pair
   and would race the bounce-and-clear path below). A missing or
   malformed pair short-circuits straight to step 4.
2. Validate `ses-id` against the device row's active session id by
   calling `provider.deviceManager.store.readDevice(deviceId)`. The
   `store` field is TS-private on `DeviceManager` but accessible at
   runtime via a narrow structural cast — only the `sessionId` field
   is consulted, keeping the dependency surface tiny. This rejects a
   syntactically-valid cookie pair whose `ses-id` no longer matches
   the persisted row (logout/rotation race, restored backup, manual
   deletion of the device row, fixation reset, etc.) — exactly the
   case that would otherwise sail past step 3 and let upstream
   render its stock welcome page.
3. Count bound accounts on the device via
   `provider.accountManager.listDeviceAccounts(deviceId)`.
4. If either check fails (no/half/stale cookies, or zero bindings):
   respond with `303` + `Location:` pointing at auth-service's
   `/oauth/authorize` with the original query string plus
   `prompt=login`, and `Set-Cookie: dev-id=; Max-Age=0` (same for
   `ses-id`, plus their `:hash` sidecars, in both host-only and
   domain-scoped variants) to clear the stale pair.
5. Otherwise: call `next()` and let upstream's signin handler render
   the chooser as today. The existing chooser-enrichment middleware
   then injects branding and enrichment as today.

Using upstream's own exported APIs and schemas (rather than forking
`@atproto/oauth-provider` or monkey-patching internals) means this
tracks upstream's definition of "device" across future versions. The
stock welcome page is never rendered, so no response-body rewrite or
HTML inspection is needed.

This catches **all** known causes because the checks are on observable
invariants at decision time (cookie pair present and valid, ses-id
matches the persisted row, device has at least one binding) rather than
on any particular upstream state-transition.

#### Why both layers

Layer 1 alone misses stale-pair cases. Layer 2 alone would accept an
extra round-trip for the partial-pair case (redirect into pds-core just to
bounce straight back). Together they keep the common case fast and the
edge cases correct.

#### Layer 3 — route all non-reuse entry points through the email form

The stock welcome page is one of three ways a user could wind up somewhere
other than the enriched account picker or the email form. The other two
are surfaced by the chooser itself and by client apps:

- **"Another account" button on the chooser.** Upstream
  `@atproto/oauth-provider-ui` renders this as a `<div role="button"
aria-label="Login to account that is not listed">` inside its hydrated
  React SPA. A plain-anchor sibling with an `href=".../prompt=login"` is
  cosmetic — React's delegated root-level click listener fires first and
  swaps the chooser component for upstream's stock sign-in form before
  the browser's default navigation has a chance to run. The
  chooser-enrichment snippet therefore binds a capture-phase click handler
  directly to the upstream div, calls `preventDefault()` +
  `stopImmediatePropagation()` so React's listener never sees the event,
  and drives `window.location.href` to
  `auth.<host>/oauth/authorize?prompt=login&<orig params>`. auth-service's
  `isForceLoginPrompt` short-circuits `shouldReuseSession`, so the email
  form renders without ever touching pds-core. The rebind is idempotent
  via a `dataset.epdsRebound` marker so the MutationObserver driving
  re-enrichment doesn't double-bind. This preserves the multi-account
  device-binding model — one `dev-id` + one `ses-id` per browser, N
  bindings per device in `AccountManager` — so "Another account" _adds_ a
  new binding to the device rather than replacing the existing ones.
- **"Sign up" button on the chooser.** Upstream's chooser SPA itself
  renders a Sign-up affordance, separate from the stock welcome page
  eliminated by Layer 2. Clicking it in an ePDS deployment drops the user
  into upstream's signup route, which in turn crashes in the compiled
  React bundle because ePDS routes account creation through
  auth-service's OTP flow rather than upstream's signup surface. The
  chooser-enrichment snippet hides any `<button>`/`<a>` whose trimmed
  text is exactly "Sign up" via `display: none` + `aria-hidden="true"`,
  idempotent via a `dataset.epdsHidden` marker. No server-side response
  rewriting needed; the enrichment script runs post-hydration via the
  same MutationObserver that handles email enrichment, which is exactly
  when upstream's SPA has rendered the button.

Covered here so future contributors don't reintroduce either escape
hatch as a link back into pds-core's signin flow.

#### Layer 4 — hide the handle on the chooser when handleMode is random

When the current OAuth flow's resolved `handle_mode` is `random`, the
account rows the chooser renders are handles the user never chose and
almost certainly can't recognise (six base36 characters under the PDS's
handle domain). Showing them as the primary identifier is worse than
useless — it suggests the user should be able to pick the right one by
reading them.

The chooser-enrichment snippet already shows the user's email alongside
each handle. In random mode we invert that: hide the handle visually and
surface it as a `title` tooltip only. Email becomes the sole primary
identifier the user sees.

Handle-mode precedence matches the signup flow exactly. The resolver has
moved into the shared package (`packages/shared/src/handle.ts`
`resolveHandleMode`) and both services import it, so there is no risk of
pds-core and auth-service disagreeing about the effective mode for a given
flow: query param `epds_handle_mode` → client metadata's
`epds_handle_mode` → env var `EPDS_DEFAULT_HANDLE_MODE` →
`picker-with-random`. The chooser middleware resolves the mode per
request (client metadata comes from the same in-memory cache the
CSS-injection middleware uses, so the hot path is a single map read)
and injects a `<meta name="epds-handle-mode">` tag into `<head>` next to
the enrichment script. The static script reads that meta at runtime and
hides the handle when the mode is `random`. No new internal HTTP
endpoint and no database lookup on the pds-core side — the chooser
doesn't consult `auth_flow.handle_mode` directly because many chooser
requests are rendered for flows that never went through auth-service
(session-reuse redirect straight to pds-core's `/oauth/authorize`).

Per-row per-account answers would be more correct — accounts on this PDS
may have been created by different clients under different handle-mode
settings, so a user-chosen handle and a randomly-generated one can sit
side by side in the chooser. But recording handle mode per-account
requires a new column on `account` (upstream-owned) plus a backfill for
historical rows, which is out of scope here. The current-flow rule is a
pragmatic approximation: it matches signup's own interpretation of
handle mode and guarantees consistency between "what the user sees in
the chooser" and "how a fresh signup would present itself".

### Non-goals for the initial fix

- **Root-causing the cookie-jar diverge.** We can't control browser
  eviction heuristics. Layer 1 makes us robust to them.
- **Forcing `remember=1` on all sign-ins.** Would avoid the 1h migration
  purge but also violates the user's intent if they opt out. Separate
  decision, tracked elsewhere.
- **Instrumenting stale-session frequency.** Adding telemetry on how often
  the Layer 2 bounce fires would let us validate the fix in production.
  Considered for a follow-up PR; the fix itself is safe to ship without it.

### Related

- [cross-client-session-reuse.md](./cross-client-session-reuse.md) — the
  PR this regression came from
- `packages/auth-service/src/lib/session-reuse.ts` — Layer 1 fix site
- `packages/pds-core/src/index.ts` — Layer 2 fix site (new pre-route
  middleware mounted alongside the existing sec-fetch-site rewrite,
  cookie-domain, and chooser-enrichment middlewares)
- `packages/pds-core/src/chooser-enrichment.ts` — unchanged by Layer 2;
  continues to enrich non-empty-session renders
- `@atproto/oauth-provider` `DeviceManager.load()` / `getCookies()` /
  `refresh()` — upstream code paths that produce the empty-device state
- `@atproto/pds` migration 005 — 1h TTL purge on `remember=0` rows
