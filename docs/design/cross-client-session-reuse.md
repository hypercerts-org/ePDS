# Cross-client OAuth session reuse

Tracking issue: HYPER-268.

## Problem

After a user authenticates via one OAuth client, a subsequent
`/oauth/authorize` request from a different client in the same browser
re-triggers the email OTP flow instead of reusing the existing ePDS
authentication session. This differs from how every mainstream OAuth
provider behaves ("sign in once per browser session").

Root cause (from investigation in this PR):

- The auth-service owns `/oauth/authorize` (via an AS-metadata override
  in pds-core) and renders its own email/OTP login page
  unconditionally.
- It never checks whether a device session already exists on the
  ePDS authorization-server domain.
- Upstream `@atproto/oauth-provider` _does_ maintain device sessions
  (`dev-id` / `ses-id` cookies bound to accounts via
  `deviceManager`/`accountManager`) — but those cookies are scoped to
  `pds.foo.com` only, and the auth-service (on `auth.pds.foo.com`)
  cannot see them even though both are subdomains of the same parent.

## Target behavior

Branching depends on whether the client started OAuth with a
`login_hint` (flow 1 — demo collects email and forwards it) or without
(flow 2 — demo redirects straight to the authorization server).

| Flow | Prior state on this device                          | Expected outcome                                                                                                           |
| ---- | --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| 1    | Single bound account, matches                       | auto-skip OTP, auto-skip chooser (upstream does this via `login_hint`), land directly on consent → redirect back to client |
| 2    | Single bound account                                | auto-skip OTP, show chooser with the one account (so the user confirms "yes, use this identity"), then consent → redirect  |
| 2    | Single bound account, pre-approved untrusted client | chooser → confirm → auto-skip consent → redirect                                                                           |
| 2    | User wants a different account                      | chooser → "Another account" button (rebound) → redirect to auth-service email/OTP form for the new account                 |
| 1/2  | No prior session                                    | current email/OTP flow (unchanged)                                                                                         |

Non-goals for this PR:

- Multi-account chooser UX (more than one bound account — uses whatever
  upstream renders by default, which is already a picker).
- Tracking "random handle" vs "user-chosen handle" — the email-display
  fix makes this unnecessary for the UX problem it was going to solve.
- Option E: making pds-core the authorization_endpoint rather than
  auth-service. Cleaner architecturally; deferred as follow-up so this
  PR stays focused.

## Architecture

Stacked on PR #9 (`css-injection-trusted-clients`), which gives us a
response-rewrite middleware in pds-core for injecting content into
upstream authorization-page responses. We extend the same pattern.

### Pieces

1. **Cookie domain broadening (pds-core).** Make upstream's
   `DeviceManager` set `dev-id`/`ses-id` with `Domain=<parent>` so
   subdomains can read the cookies. Upstream's `DeviceManager` does
   not expose a cookie `domain` config option, so we wrap/intercept
   the cookie writer.
   - Auto-derived: if `AUTH_HOSTNAME` ends with `.<PDS_HOSTNAME>`,
     pds-core uses `PDS_HOSTNAME` as the cookie domain. Otherwise
     the middleware is skipped (no shared parent, e.g. Railway).
   - Implementation: Express middleware wraps `res.setHeader` and
     `res.appendHeader` to inject `Domain=` into outbound Set-Cookie
     headers for the four device cookies.

2. **Session detection (auth-service).** At the top of the
   `/oauth/authorize` route in auth-service, check the request for
   `dev-id` cookie. If present, redirect the browser to pds-core's
   upstream `/oauth/authorize` with the original query string
   untouched. If absent, render the email form exactly as today.
   - Only cost for new-user flows: a single `if` check and cookie
     lookup. No round-trip.
   - For session-holders: one 302 from
     `auth.pds.foo.com/oauth/authorize` to
     `pds.pds.foo.com/oauth/authorize`. pds-core's upstream middleware
     then runs `deviceManager.load()` and either auto-redirects
     (flow 1 + login_hint match) or renders the chooser (flow 2).

3. **Email-on-chooser rendering (pds-core).** Use PR #9's
   response-rewrite middleware. When intercepting the `/account` (and
   related) page responses, inject a small `<script>` that runs after
   upstream's React SPA hydrates and augments each account row with
   its email address. Email is already present in the
   `__deviceSessions` hydration data — the upstream SPA just doesn't
   render it.
   - If augmenting in-place is fragile (SPA overwrites our DOM edits),
     fall back to a `MutationObserver` that re-applies the patch on
     each render cycle.

4. **"Another account" rebind (pds-core).** Same response-rewrite
   mechanism, but instead of injecting a new anchor we rebind upstream's
   existing div (`role="button"`, `aria-label="Login to account that is not listed"`).
   Injected anchors inside upstream's hydrated React SPA are
   cosmetic — React's delegated root-level click listener intercepts
   first and swaps the chooser for upstream's stock sign-in form before
   the browser's default navigation has a chance to run. The enrichment
   snippet attaches a capture-phase click listener that calls
   `preventDefault()` + `stopImmediatePropagation()` so React's listener
   never sees the event, and then drives `window.location.href` to
   `https://auth.pds.foo.com/oauth/authorize?...&prompt=login`.
   auth-service's `isForceLoginPrompt` short-circuits
   `shouldReuseSession`, so the email form renders without ever touching
   pds-core. The rebind is idempotent via a `dataset.epdsRebound` marker
   on the div.

### Flow summaries

**Session-holder, flow 2, default (single account):**

```
browser → auth.pds.foo.com/oauth/authorize?...
         → 302 (auth-service sees dev-id cookie)
browser → pds.pds.foo.com/oauth/authorize?...
         → upstream middleware loads device session
         → renders /account (chooser)
browser → /account  (chooser with injected email display + rebound "Another account")
         → user clicks primary account
         → POST /sign-in + POST /consent via upstream API
         → 302 back to client
```

**Session-holder, flow 1 (login_hint matches):**

```
browser → auth.pds.foo.com/oauth/authorize?...&login_hint=foo@example.com
         → 302 (auth-service sees dev-id cookie)
browser → pds.pds.foo.com/oauth/authorize?...&login_hint=foo@example.com
         → upstream middleware loads device session + matches hint
         → auto-issues authorization code → 302 to client
```

**New user (no cookie):**

```
browser → auth.pds.foo.com/oauth/authorize?...
         → no dev-id cookie → render email form as today
         → email + OTP → /auth/complete → /oauth/epds-callback (internal)
         → pds-core creates account, sets device session
         → 302 to pds.pds.foo.com/oauth/authorize for consent
         → 302 to client
```

**Session-holder who wants a different account:**

```
browser → auth.pds.foo.com/oauth/authorize?...
         → 302 to pds-core chooser as above
browser → /account  (chooser)
         → user clicks "Another account" (rebound via capture-phase handler)
         → hard-navigate to auth.pds.foo.com/oauth/authorize?...&prompt=login
         → auth-service honors prompt=login, renders email form
         → email + OTP → new account bound to device
         → 302 to pds.pds.foo.com/oauth/authorize → consent → client
```

## Test scenarios

New Gherkin scenarios in `features/passwordless-authentication.feature`
under the HYPER-268 heading. Replaces the two speculative scenarios
currently on this branch.

1. **Flow 1, signed in, auto-skip**
   Trusted demo sign-in, then untrusted demo flow 1 (re-enters email).
   Assert: no new OTP email, no OTP form shown, no chooser shown,
   lands on consent → authorize → /welcome.

2. **Flow 2, signed in, chooser with one account**
   Trusted demo sign-in, then untrusted demo flow 2 (no email).
   Assert: no new OTP email, chooser shown, chooser contains test
   email text, user confirms account, lands on consent → authorize
   → /welcome.

3. **Flow 2, signed in + pre-approved untrusted, auto-authorize**
   Pre-approve untrusted, then trusted demo sign-in as returning user
   (not new sign-up — requires a new setup step), then untrusted flow 2.
   Assert: no new OTP email, chooser shown, user confirms, no consent
   screen, lands on /welcome.

4. **Flow 2, signed in, user picks "different account"**
   Trusted sign-in, then untrusted flow 2, chooser shown, user clicks
   "Another account" (upstream's rebound button), lands on auth-service
   email form for a fresh account.

All scenarios run with both demo clients wired as confidential
(`token_endpoint_auth_method=private_key_jwt`). The public-client
force-consent path in upstream's `request-manager.js` is not
exercised by this suite — public-client behaviour is covered by
upstream `@atproto/oauth-provider`'s own tests, and ePDS's
documented stance is that untrusted clients should run as
confidential. See the [coverage matrix](#coverage-matrix) gaps
section.

### New step definitions

- `When the untrusted demo client initiates an OAuth login via flow 2`
  (navigates to `${untrustedDemoUrl}/flow2` and clicks the sign-in
  button).
- `Then the account chooser is displayed`
  (URL is on pds-core host, not auth-service; `#root` div present).
- `Then the account chooser displays the test email`
  (body contains `world.testEmail`).
- `When the user confirms their account on the chooser`
  (clicks the upstream SPA's account row; selector TBD when we
  inspect the rendered DOM).
- `When the user clicks "Another account" on the chooser`
  (clicks upstream's rebound `role=button` div; capture-phase handler
  redirects to auth-service).
- `Then the browser is on the auth service email form`
  (URL host is auth-subdomain, `#email` input visible).

### New setup step

- `Given the user has a returning account signed in via the trusted demo client`
  Drives a sign-up via the trusted demo (account created + device
  session bound), preserving the browser context. Unlike
  `createAccountViaOAuth` + `resetBrowserContext`, this one leaves
  cookies intact — that's the whole point.

## Implementation order

1. Scenarios + step definitions (write first, watch them fail)
2. Cookie domain change in pds-core (make auth-service able to read the cookie)
3. Session detection in auth-service (wire the redirect)
4. Response-rewrite extensions in pds-core (email display + "different account" link)
5. Run e2e to confirm scenarios pass
6. Unit tests where practical (cookie domain, session detection)

## Open questions

- What form does the "prompt=login" bypass take? Plain OAuth
  `prompt=login` (standard OIDC, upstream understands it) seems
  cleanest, but need to verify upstream does the right thing —
  it should skip SSO and force a credential prompt, which maps
  naturally to "render the email form in auth-service".
- Cookie domain: now auto-derived from `AUTH_HOSTNAME` / `PDS_HOSTNAME`
  relationship. No extra env var. Resolved.
- Chooser customization: if the response-rewrite scripts turn out
  to be fragile against upstream SPA updates, consider an
  optional fallback path that skips the rewrite and accepts
  handle-only display.

## Coverage matrix

A grid of every active and pending session-reuse scenario across both
feature files (`features/passwordless-authentication.feature` and
`features/session-reuse-bugs.feature`), mapped onto the axes that
actually drive ePDS's branching. Used to spot duplicate coverage,
under-tested combinations, and scenarios whose name does not match
what they exercise.

### Axes

- **Prior-state**: what the device already has when the scenario
  starts. `none` (no cookies), `bound` (dev-id+ses-id valid + ≥1
  account binding via the trusted demo), `bound+approved-other`
  (also has a persistent grant for the second client),
  `bound-purged` (cookies + device row, zero bindings),
  `cookies-broken-X` (specific cookie failure mode).
- **Cross-client?**: does the scenario exercise client A→client B
  reuse, or stay on a single client. `single` / `cross`.
- **Flow**: `1` = client supplied `login_hint`; `2` = no hint.
  `n/a` = scenario is pre-OAuth (cookie-state coverage in the bugs
  feature) or cookie/recovery-only.
- **Trust**: trust class of the client driving the _current_ OAuth
  request (not the prior one). `T` trusted, `U` untrusted.
- **Confidentiality**: `pub` (public, no client auth) vs `conf`
  (private_key_jwt). Only matters where upstream's
  `request-manager.js` force-overrides `prompt=consent`.
- **Expected**: shorthand for what the user should see.
  `OTP` = email/OTP form, `chooser` = enriched chooser,
  `consent` = consent screen, `→RP` = silent redirect to RP,
  `→email` = bounce to auth-service email form,
  `clear` = stale cookies cleared on response.

### Active scenarios

| #   | Scenario (file:line)                                               | Prior-state              | Cross? | Flow | Trust | Conf | Expected                             |
| --- | ------------------------------------------------------------------ | ------------------------ | ------ | ---- | ----- | ---- | ------------------------------------ |
| 1   | New user OTP (passwordless:14)                                     | none                     | single | 2    | T     | conf | OTP → handle → consent → →RP         |
| 2   | Returning user OTP (passwordless:30)                               | none (cookies cleared)   | single | 1    | T     | conf | OTP → →RP                            |
| 3   | Returning user, already approved (passwordless:40)                 | bound+approved-other (T) | single | 1    | T     | conf | OTP → →RP (no consent)               |
| A   | OTP-skip via prior trusted sign-in, flow 1 (passwordless:83)       | bound (via T)            | cross  | 1    | U     | conf | chooser → consent → →RP              |
| B   | Chooser confirmation, flow 2 (passwordless:98)                     | bound (via T)            | cross  | 2    | U     | conf | chooser (with email) → consent → →RP |
| C   | Returning to pre-approved second client, flow 2 (passwordless:121) | bound+approved-other (U) | cross? | 2    | U     | conf | chooser → →RP (no consent)           |
| D   | "Another account" from chooser (passwordless:137)                  | bound (via T)            | cross  | 2    | U     | conf | chooser → click → →email             |
| E1  | Both cookies valid baseline (bugs:23)                              | bound                    | single | 2    | T     | conf | enriched chooser shown               |
| E2  | dev-id only / ses-id missing (bugs:28)                             | cookies-broken-half      | single | 2    | T     | conf | →email + clear                       |
| E3  | ses-id only / dev-id missing (bugs:39)                             | cookies-broken-half      | single | 2    | T     | conf | →email + clear                       |
| E4  | dev-id stale, ses-id valid (bugs:46)                               | cookies-broken-stale     | single | 2    | T     | conf | →email + clear                       |
| E5  | ses-id stale, dev-id valid (bugs:53)                               | cookies-broken-stale     | single | 2    | T     | conf | →email + clear                       |
| E6  | Both stale (bugs:60)                                               | cookies-broken-stale     | single | 2    | T     | conf | →email + clear                       |
| F1  | "Another account" → email form (bugs:67)                           | bound                    | single | 2    | T     | conf | chooser → click → →email             |
| F2  | Upstream Sign up affordance hidden (bugs:76)                       | bound                    | single | 2    | T     | conf | chooser without "Sign up"            |
| F3  | Chooser hides handle in random-handle mode (bugs:82)               | bound                    | single | 2    | T     | conf | chooser, handle hidden, email shown  |

### Pending scenarios (planned trusted-client auto-skip)

| #   | Scenario                                                            | Prior-state    | Cross? | Flow | Trust | Conf | Expected         |
| --- | ------------------------------------------------------------------- | -------------- | ------ | ---- | ----- | ---- | ---------------- |
| P1  | Trusted + opt-in + matching hint, single binding (passwordless:159) | bound (1 acct) | single | 1    | T+opt | conf | →RP (no chooser) |
| P2  | Trusted + opt-in + matching hint, multi-binding (passwordless:171)  | bound (N acct) | single | 1    | T+opt | conf | →RP (no chooser) |
| P3  | Trusted, no opt-in, matching hint (passwordless:183)                | bound          | single | 1    | T     | conf | chooser shown    |
| P4  | Untrusted + opt-in flag (must NOT take effect) (passwordless:192)   | bound          | cross  | 1    | U+opt | conf | chooser shown    |
| P5  | Trusted + opt-in + non-matching hint (passwordless:203)             | bound          | single | 1    | T+opt | conf | chooser shown    |
| P6  | Trusted + opt-in + flow 2 (no hint) (passwordless:213)              | bound          | single | 2    | T+opt | conf | chooser shown    |
| P7  | Pre-existing device with purged bindings (bugs:95)                  | bound-purged   | single | 2    | T     | conf | →email + clear   |

### What this exposes

**Genuine coverage:**

- Cookie-state coverage (E1–E6 + P7) is exhaustive across the
  `{dev-id, ses-id} × {present, missing, stale}` grid.
- Flow-1 vs flow-2 split is covered for the cross-client + bound
  case (A vs B) and for the trusted-auto-skip planned feature
  (P1, P3, P5, P6).
- Both chooser-affordance fixes (Sign up hide, Another account
  rebind) are tested in both their usage contexts: cross-client
  (D) and single-client returning (F1).

**Overlaps and what each contributes:**

- **C vs 3**: Scenario 3 (passwordless:40) covers "returning user
  with prior approval, single client, flow 1." Scenario C covers
  "device with prior U-approval, T sign-in establishes the live
  device session, return to U skips consent." The U→T leg in step 2
  of C is the genuine cross-client claim (a dev-id minted during
  U-approval is reused by T to skip OTP); the U-return in step 3 is
  the persistent-grant claim. Both legs are needed — neither
  scenario 3 nor any other active scenario exercises the U→T
  cross-client direction.
- **D vs F1**: same DOM affordance ("Another account"), tested both
  in cross-client (D) and single-client (F1) contexts. Worth keeping
  both: D guards the cross-client wiring, F1 guards the docker-stack
  chooser-rendering pipeline.

**Gaps that matter:**

- **T as the _current_ OAuth client receiving a U-minted session.**
  A and B are T-mints / U-current. The reverse direction
  (U-mints / T-current) has no active coverage. Today the auth
  branches are symmetric so the gap is mostly cosmetic, but if
  trusted-client auto-skip ever ships (P-series) the trust-class of
  the _current_ client will start mattering and this gap will
  become a real hole.
- **Public client coverage is zero.** Every scenario runs against
  confidential clients because that is what both demos are wired
  as. A regression that re-exposed upstream's force-consent path
  for an untrusted public client would not be caught here — only
  by upstream's own tests. ePDS's documented stance is "untrusted
  ⇒ confidential recommended" so this gap is intentional, but
  it should be named rather than implicit.
- **Multi-binding device** (more than one account bound to one
  dev-id) appears only in @pending P2. No active scenario exercises
  the chooser with two real rows; the SPA's row-rendering and
  enrichment loop are only exercised on the single-row case.
- **Zero-binding chooser render** (device row exists, bindings
  purged) is covered only by @pending P7, with the comment on
  bugs:90–94 explaining the white-box-access blocker. Unit tests
  fill the gap.

**Non-gaps (called out so they aren't re-investigated):**

- **Flow 1 + cross-client + pre-approved**: not separately tested
  (A is flow 1 + bound, no approval; C is flow 2 + bound + approval).
  The persistent-grant short-circuit is independent of `login_hint`,
  so a dedicated scenario would duplicate C's grant-claim with
  A's flow-1-claim — no new combinatorial coverage.

### Recommended actions

1. **Drop the cryptic `Scenario A —` / `B` / `C` / `D` lettering.**
   The scenario names already describe the behaviour; the letters
   duplicate the comment headings above each scenario and were
   flagged earlier as cryptic. Keep the comments — they document
   the _why_, which the names alone do not — but remove the letter
   prefixes.
2. **Document the public-client gap explicitly** in the
   `## Test scenarios` section: one sentence noting that all
   scenarios run with both demos wired as confidential clients,
   so the public-client force-consent path is covered by upstream
   tests rather than this suite. Cheaper than adding a second
   untrusted demo container.
3. **Open a follow-up for the U→T direction gap** if/when the
   trusted-client auto-skip feature (P-series) lands — the
   asymmetry only starts mattering then.
4. **Leave overlaps C vs 3 and D vs F1 alone.** Each pair tests
   distinct claims; the apparent overlap is actually two
   complementary coverage layers.

PR #103's e2e run exposed that the original target-behaviour table
(rows 1 and 3, "auto-skip chooser") encodes a behaviour that
`@atproto/oauth-provider` does not actually deliver. In the version
of the library ePDS ships against, upstream's chooser is rendered
unconditionally whenever the device has at least one binding —
single-binding plus a matching `login_hint` does NOT cause it to
auto-issue the authorization code. The user always sees the chooser
and must click "Continue" to proceed.

Scenario A (flow 1, no prior approval) was updated to expect the
chooser hop — auto-skipping the chooser on a verified `login_hint`
match is a separate opt-in feature, gated on per-client trust (see
predicate below).

Scenario C (flow 2, prior approval on a confidential client) keeps
the original "no consent screen on return" expectation. The chooser
is still shown for explicit confirmation, but after the user clicks
through it the persistent grant in `authorized_client` (keyed by
`(sub, clientId)`) fires upstream's `checkConsentRequired` short-
circuit and the flow auto-redirects to the RP. This only works when
the client runs as confidential
(`token_endpoint_auth_method=private_key_jwt`); upstream's
`request-manager.js` force-overrides `prompt=consent` for untrusted
public clients, so the grant lookup never gets a chance to fire.
Both demo containers are wired as confidential clients to exercise
this path — see the `EPDS_CLIENT_PRIVATE_JWK` /
`DEMO_UNTRUSTED_PRIVATE_JWK` env vars in `docker-compose.yml` and
`packages/demo/src/app/client-metadata.json/route.ts`.

### Security analysis: would auto-skipping the chooser be safe?

The chooser is the user's last-line consent surface for "this device's
identity → this RP". It runs on a PDS-controlled origin
(`auth.<pds>` or `<pds>`) so the user can verify the URL bar before
granting. Skipping it means the browser silently mints an OAuth grant
without any human-mediated affirmation, and the user never sees
PDS-controlled DOM during the reuse path.

|                                                       | Trusted client                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Untrusted client                                                                                                                                                                                                                                                                                                                                                                                                      |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Auto-skip chooser when `login_hint` matches a binding | Defensible: operator has already vouched for this `client_id` via `PDS_OAUTH_TRUSTED_CLIENTS`, and trusted clients can already auto-consent on signup (`epds_skip_consent_on_signup`). Auto-skipping the chooser is a small additional delegation. Should be opt-in per-client via metadata flag (e.g. `epds_skip_chooser_on_match`), default off, and documented as a residual-risk surface (CSRF-style cross-tab; `login_hint` spoofing; session-fixation post-recovery). | Should NOT skip. The whole point of "untrusted" is "no out-of-band signal that this client is benign". Anyone who can register a `client_id` and get the user to visit their page once would be able to mint OAuth grants against existing PDS sessions with no clicks. Drive-by binding via flow 2 (no `login_hint`) is even worse — upstream auto-pick would silently choose _some_ session for the third-party RP. |

The cross-domain split (auth subdomain rendering chooser, RP on a
separate origin) _increases_ the chooser's value as a security UX:
the alternative is the user never seeing PDS-controlled DOM at all
during reuse, eliminating their ability to spot a malicious client.

### Auto-skip predicate (when implemented)

The auto-skip predicate is, with all conditions required:

1. `client_id` is on `PDS_OAUTH_TRUSTED_CLIENTS`.
2. Client metadata advertises `epds_skip_chooser_on_match: true`
   (per-client opt-in; default off).
3. The auth-ui-guard's existing checks pass:
   - `dev-id`/`ses-id` cookies parse and ses-id matches the device
     row's active sessionId.
   - `accountManager.listDeviceAccounts(deviceId)` returns at least
     one binding.
4. The PAR's resolved `login_hint` (DID, after pds-core rewrites the
   client-supplied email→DID at `index.ts:486-499`) matches exactly
   one of the device's bindings.

Match by DID, not email: ePDS resolves `login_hint=email` server-side
into the DID and rewrites the stored PAR before redirecting to
upstream. The auto-skip predicate must use the resolved DID so it
isn't fooled by email-collision tricks or by clients that supply an
unresolved string.

Multi-binding is fine: the predicate is "the resolved `login_hint`
DID is bound to this device", not "this device has only one binding".
If the user has three accounts on this device and the trusted client
hints one of them, the hint already disambiguates; the chooser would
add no signal beyond confirming what the client just told ePDS. The
single-binding case is just the degenerate sub-case where the only
candidate trivially matches.
