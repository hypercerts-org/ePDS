# PAR Expiry, Heartbeats, and Clean Exits

Working design doc for the OTP / PAR / auth_flow timer interactions and the
"stuck in a loop" failure modes a slow user can trip during OAuth login.

This is a living document — keep it current as scope, decisions, or
findings change.

## Problem

A real user reported being stuck in a login loop:

1. They start an OAuth login (flow=email-first, `prompt=login`).
2. They receive the OTP email but wait >10 minutes before entering it.
3. The OTP-expired UI fires as expected.
4. They click "Resend" and receive a fresh OTP.
5. They enter the second OTP and see "Your sign-in took too long to
   complete and timed out. Please start sign-in again."
6. There is no working path forward — the page is a dead end.

We had landed several recent OTP-expiry fixes (PRs leading up to
`dacf1d2`, `0e62bd6`, etc.) and added e2e scenarios specifically for OTP
expiry, so the immediate question was: how did this slip through?

## The three timers

| Timer                   | Default        | Where                                                |
| ----------------------- | -------------- | ---------------------------------------------------- |
| OTP TTL                 | 10 min         | better-auth `verification` row (auth-service SQLite) |
| PAR (`request_uri`) TTL | 5 min, sliding | `@atproto/oauth-provider` request store (pds-core)   |
| auth_flow TTL           | 60 min         | auth-service SQLite + `epds_auth_flow` cookie        |

Each lives in a different layer because each layer owns a different
concept (better-auth: email-OTP only; oauth-provider: OAuth handshake
only; auth-service: glue ePDS adds to bridge them).

### What each one gates

- **OTP TTL** — the 8-char code in the email. Fixed at row creation.
  Resend creates a new row.
- **PAR TTL** — the `request_uri` handle that points to all the OAuth
  parameters (client_id, scope, code_challenge, redirect_uri, state)
  the client pushed at flow start. Without it the OAuth flow has no
  memory of the original request. **Sliding**: every successful
  `requestManager.get()` resets `expiresAt` to `now + 5 min`. There is
  no absolute ceiling — pinged often enough, the row lives indefinitely.
  When the timer fires, the row is deleted in the same call that
  throws.
- **auth_flow TTL** — auth-service's bridge that remembers which OAuth
  flow a user is in across page navigations. Without it, `/auth/complete`
  doesn't know which `request_uri` to redirect back to.

### How the bug fires

User sits on the OTP form for 6 minutes. During those 6 minutes:

- OTP (10 min) — alive.
- PAR (5 min sliding) — **dead at minute 5**, because nothing on the
  OTP form calls `requestManager.get()` while the user reads.
- auth_flow (60 min) — alive.

User submits OTP. Auth-service verifies it (OTP alive, auth_flow alive
— looks fine). It then bridges back to the OAuth flow via PAR → dead →
user lands on whichever error page is downstream of the failing `get()`
with no recovery path.

## Why the existing scenarios missed it

| Scenario                         | OTP expired | PAR expired | auth_flow expired | Resend in flow |
| -------------------------------- | ----------- | ----------- | ----------------- | -------------- |
| `@otp-expiry` (existing)         | Yes         | **No**      | No                | Yes            |
| `@par-callback-error` (existing) | No          | Yes         | No                | No             |
| `@otp-and-par-expiry` (new)      | Yes         | Yes         | No                | Yes            |
| `@multiple-resend` (new)         | No          | Yes         | No                | Yes (twice)    |
| `@prompt-login` (new)            | No          | Yes         | No                | No             |
| `@recovery` (new)                | No          | Yes         | No                | No             |

`@otp-expiry` only ages the OTP row and _deliberately keeps the PAR
alive_ to isolate the auth-service-side TTL fix from the PDS layer.
But PAR's hardcoded 5-min TTL is shorter than OTP's 10-min TTL, so in
production the PAR is already dead by the time OTP expiry ever fires.
The scenario passes because it artificially preserves a row that
wouldn't exist in real life.

`@par-callback-error` only covers the _response shape_ when PAR is
dead at callback (styled HTML vs raw JSON). It does not exercise
Resend at all and asserts nothing about user recovery.

The four new scenarios cover four real-user paths that were untested.

### Surfaces the bug presents on

The same root cause (PAR dead before final bridge) presents three
different error pages depending on which downstream call hits PAR
first:

- auth-service `/auth/choose-handle`: "Session expired, please start
  over" (basic + multiple-Resend scenarios)
- pds-core friendly redirect from `/oauth/epds-callback`'s catch
  block: "Your sign-in took too long to complete and timed out…"
  (recovery scenario)
- Browser stalls navigating to `/oauth/epds-callback` and never
  reaches `/welcome` (prompt=login scenario)

Each of these is a dead end for the user today.

## Strategy

Two layers, in priority order:

### 1. Clean exit — the contract

**Every error a slow user can trip must end with a working path back
to the OAuth client.** No stranded pages, no loops. This is the
non-negotiable outcome.

Audit every page that today says "Session expired" / "Authentication
failed" / "Your sign-in took too long" / similar, and confirm each
one offers either:

- an automatic redirect to the OAuth client's `redirect_uri` with an
  OAuth-spec error (`error=access_denied`, `error_description=…`,
  `state`, `iss`) so the client can show its own retry UI; or
- a "Start over" button that re-initiates the OAuth flow from scratch.

The four RED scenarios surface three different dead-end pages already
— that is the starting list for the audit.

### 2. Heartbeat — the UX polish

Keep the PAR alive while the user is genuinely on the page so the
common case (slow inbox / slow typist) doesn't hit the dead end at
all. PAR has a built-in refresh primitive (`pingParRequest`) which is
already wired into a few server-side handoff points but not from the
pages where humans actually wait.

Apply heartbeats only where it materially helps and doesn't weaken
security:

- OTP form (login) — main case
- Recovery form — same shape
- Skip handle picker (already has server-side ping at render time)
- Skip email-input form (user is fast, PAR is fresh)

Heartbeats are **opportunistic**. If they fail, security is unchanged
and the user falls through to the clean-exit path from layer 1.
Timeouts will happen regardless of heartbeats.

### Security guardrails for heartbeats

The heartbeat must not be a way to extend more than it should:

- Only refreshes PAR (timer 2). Doesn't touch OTP or auth_flow TTLs.
- Tied to a valid `epds_auth_flow` cookie — no flow → no ping.
- Bounded by auth_flow's 60-min ceiling — once auth_flow dies, the
  ping has nothing to look up and becomes a no-op. PAR cannot be kept
  alive past 60 min via heartbeat.
- Rate-limited per flow.
- Read-only on auth-service; only effect is sliding upstream's timer
  via an already-internal call.
- Not credential-bearing.

### What the strategy explicitly does NOT do

- Does not bump any of the three TTL defaults.
- Does not regenerate a fresh PAR mid-flow (PAR carries client-supplied
  params auth-service can't recreate without round-tripping to the
  OAuth client).
- Does not extend OTP or auth_flow TTLs.

## Tracked work

### RED scenarios (committed, currently failing)

In `features/passwordless-authentication.feature`, all tagged
`@otp-and-par-expiry`:

- `Expired OTP + expired PAR — Resend must still recover the flow`
- `Two Resend cycles after silent PAR death still complete the flow`
  (`@multiple-resend`)
- `prompt=login + expired PAR — flow must still complete`
  (`@prompt-login`)
- `Recovery via backup email + expired PAR — flow must still complete`
  (`@recovery`)

All four reproduce on `origin/main` (commit `ffc17bd`). All four are
preserved as worst-case "PAR is hard-dead" coverage even after the
heartbeat lands — they go GREEN only when clean-exit makes the dead
end usable.

### Dead-end pages → target UX

Each row is a `renderError(...)` call site that a slow user can reach
on the auth path. "Page" is the route showing the error. "Trigger" is
which TTL/state condition caused it. "Today" describes the current
DOM/redirect outcome — every entry that says "static page" is a dead
end (the shared `renderError` template has no retry link, no Start
Over button — see `packages/shared/src/render-error.ts`). "Target" is
the proposed clean-exit UX.

> **Note (post-resolution):** the table records the audit at decision
> time. Some Target cells speculate about a `/_internal/par-…`-style
> lookup or bare `/oauth/authorize` restart. The resolved approach
> (see "Resolved decisions" below) replaced both with a single shape:
> resolve the OAuth client's published metadata via
> `@certified-app/shared`'s `resolveClientMetadata()` to recover
> `redirect_uris[0]`, then issue the spec error redirect. No new
> pds-core internal endpoints; no bare authorize restart. The table
> is preserved as-written to keep the audit honest about the option
> space; the "Resolved decisions" section is the source of truth for
> what shipped.

| #   | Page                                                 | Trigger                                                                                                 | Today                                                                                                                                                                                                                                                     | Target                                                                                                                                                                             |
| --- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `/auth/complete` (no cookie)                         | `epds_auth_flow` cookie missing                                                                         | Static "Authentication session expired. Please try again."                                                                                                                                                                                                | Redirect back to OAuth client with `error=access_denied` if `redirect_uri` recoverable; else static page with Start Over link to fresh `/oauth/authorize` for the original client. |
| 2   | `/auth/complete` (no flow row)                       | auth_flow row missing/expired                                                                           | Static "Authentication session expired. Please try again."                                                                                                                                                                                                | Same as #1. The flow row carried `requestUri` + `clientId`; if it's gone we don't know `redirect_uri` and must fall back to Start Over.                                            |
| 3   | `/auth/complete` (better-auth session error)         | better-auth session lookup throws                                                                       | Static "Authentication failed. Please try again."                                                                                                                                                                                                         | Redirect to client with `error=server_error` if recoverable; otherwise Start Over.                                                                                                 |
| 4   | `/auth/choose-handle` (no cookie / no flow)          | same as #1/#2 but on handle picker                                                                      | Static "Session expired, please start over"                                                                                                                                                                                                               | Same as #1.                                                                                                                                                                        |
| 5   | `/auth/choose-handle` (better-auth session error)    | session lookup throws                                                                                   | Static "Authentication failed. Please try again."                                                                                                                                                                                                         | Same as #3.                                                                                                                                                                        |
| 6   | `/auth/choose-handle` (no session user)              | better-auth session has no user                                                                         | Static "Session expired, please start over"                                                                                                                                                                                                               | Same as #1.                                                                                                                                                                        |
| 7   | `/auth/choose-handle` (PAR ping fails on render)     | upstream PAR row dead before user even sees the picker                                                  | Static "Session expired, please start over"                                                                                                                                                                                                               | Redirect to client (we still hold `flow.clientId` here, can resolve `redirect_uri` via `/_internal/par-…`-style lookup OR we can defer — see open question below).                 |
| 8   | `/auth/choose-handle` (PAR ping fails on POST)       | PAR died while user was picking                                                                         | Static "Session expired, please start over"                                                                                                                                                                                                               | Same as #7.                                                                                                                                                                        |
| 9   | `/oauth/epds-callback` catch (PAR-expired branch)    | upstream `requestManager.get()` threw `expired`/`unknown request_uri`                                   | Already does the right thing IF `redirect_uri` was captured before the throw: redirects to client with `error=access_denied` + description. Falls back to a styled-but-static "Your sign-in took too long…" page when `redirect_uri` was not recoverable. | Keep redirect path. For the static-fallback case, add a Start Over link/button so the user can re-initiate.                                                                        |
| 10  | `/oauth/epds-callback` catch (server_error branch)   | any other throw                                                                                         | Static "Authentication failed."                                                                                                                                                                                                                           | Same shape: redirect when possible, Start Over fallback when not.                                                                                                                  |
| 11  | `/auth/recover` (missing request_uri)                | direct GET without query param                                                                          | Static "Missing request_uri parameter"                                                                                                                                                                                                                    | Out of scope — this isn't an expiry case, it's misuse. Leave as is.                                                                                                                |
| 12  | Recovery OTP verify success → `/auth/complete` chain | recovery flow hands back to `/auth/complete`; if PAR died during the recovery loop, falls into #1/#2/#9 | Inherits the surface of whichever route fires                                                                                                                                                                                                             | Inherits the fix.                                                                                                                                                                  |

### Failure clusters

The table collapses into three clusters:

- **A: redirect-when-possible** (#1, #2, #3, #4, #5, #6, #9, #10) —
  user reaches an error after a sign-in attempt; redirect them back
  to the OAuth client with the OAuth-spec error so the client's own
  UI handles retry. This is what the OAuth spec says to do anyway.

- **B: PAR-dead-on-handle-page** (#7, #8) — discovered before the
  callback hop. Fix is to feed the same redirect-when-possible logic
  with the `redirect_uri` we can pull from the (still-alive) auth_flow
  row before it's too late.

- **C: nothing recoverable** — when we have neither a live auth_flow
  nor a captured `redirect_uri`, the user must Start Over. Static
  pages that hit this case need a Start Over link/button. Today they
  are silent dead ends.

### Building blocks we already have

- `handleCallbackError()` in `packages/pds-core/src/lib/epds-callback-error.ts`
  already does the redirect-when-possible logic for `/oauth/epds-callback`.
  Lift it (or its shape) into a shared helper auth-service can call.
- `flow.clientId` is on every auth_flow row, so given a live flow we
  can always find the OAuth client's metadata (`redirect_uris`, etc.)
  to construct a redirect target.
- `renderError()` is the shared template; extending it to optionally
  render a Start Over button (with a `clientId` or fully-qualified
  authorize URL) is a one-place change.

### Resolved decisions

Guiding principle: **minimum friction for the end user** — fewest
steps to retry, no manual restart when an automatic bounce-back is
possible.

1. **Start Over destination = the OAuth client.** Always redirect to
   the client's registered `redirect_uri` with the OAuth-spec error
   query params. The client's own UI handles "try again", which is
   one click on familiar branding. This is also what RFC 6749 §4.1.2.1
   prescribes. We cannot synthesise a valid `/oauth/authorize` URL
   without the dead PAR's `state`/`code_challenge`/etc., so a "bare
   re-authorize" path isn't actually feasible. The Start Over page is
   only the last-resort fallback when no clientId is in scope at all.

2. **Cluster B (PAR-dead-on-handle-page) → redirect to the client.**
   We have `flow.clientId` on every auth*flow row and OAuth clients
   publish metadata independently of the PAR row, so
   `redirect_uris[0]` is resolvable. The original `state` is lost
   (it lived in the PAR). RFC 6749 §4.1.2.1 explicitly \_requires*
   `state` in the error response when it was present in the
   authorization request, so this is a pragmatic degradation — not
   a spec-permitted shortcut. We chose redirect-without-state over
   stranding the user because every spec-compliant OAuth client
   already has to handle the case where it cannot correlate an
   error response with an in-flight attempt (e.g. cross-device
   resumption, browser session loss), so an "anonymous error,
   restart" outcome is universally recoverable on the client side
   even if it is not the spec's preferred shape.

3. **Recovery flows must carry `clientId`.** The current `clientId:
null` on recovery's auth_flow row is a side-effect of the DB API,
   not a design choice. Thread the clientId from the login page into
   the recovery link (URL or cookie) so the recovery page can
   populate it on the auth_flow row at creation. This puts recovery
   flows on the same redirect-to-client path as everything else, no
   manual restart.

The shape of the implementation falls out of these:

- One shared helper `redirectToClientWithError(res, clientId, code,
description, state?)` that resolves client metadata and issues the
  RFC 6749 error redirect. Called from every cluster A and B site.
- Lift `handleCallbackError`'s redirect logic into that helper so
  pds-core and auth-service share one code path.
- `renderError` gains an optional Start Over href, used only by the
  cluster C fallback when no clientId is in scope.

### White-boxing budget

This work must avoid adding to the white-boxing surface catalogued in
`docs/design/pds-white-boxing.md`. Concretely:

- **Auth-service resolves client metadata itself.**
  `@certified-app/shared` already exposes `resolveClientMetadata(clientId)`
  which fetches the public client metadata document directly. This
  means cluster A/B redirects can be built in auth-service without
  any new pds-core internal endpoint and without any new
  `provider.<thing>` access. Zero new white-boxing.
- **Cluster A/B implementation lives entirely in auth-service.** The
  shared helper above is an `auth-service` lib (or a `shared`
  utility), not a pds-core route. Pds-core continues to have its own
  `handleCallbackError` for cluster A on `/oauth/epds-callback`
  because that path is already inside pds-core; the helper shape can
  be aligned across both services without forcing them to share a
  module.
- **Heartbeat reuses existing pds-core `/_internal/ping-request`.**
  No new pds-core endpoint. Auth-service adds a new public
  `/auth/ping` route that calls the existing internal one
  server-side; the public route is an auth-service-only concern.
- **No new `requestManager` calls.** Nothing in this work needs to
  read the dead PAR row. We use only the OAuth client metadata
  (which is auth-service-resolvable) and `flow.clientId` (which
  auth-service already stores).
- **Recovery flow's clientId** is threaded through query-string /
  cookie at link-render time, not by exposing expired PAR rows from
  pds-core. The login page already has the clientId in scope.

### Future open questions (defer)

- Heartbeat interval (3 min vs shorter) — pick during impl.
- `?no-heartbeat=1` test toggle — useful regression-testing primitive
  but tied to heartbeat rollout, not clean-exit.

## Decisions log

- **Clean exit > heartbeat in priority.** Heartbeats are polish;
  reliable recovery from dead ends is the contract.
- **Heartbeats only where reasonable.** OTP form + recovery form for
  now; not handle picker, not email-input form.
- **Don't change TTLs.** They are correct for what each layer owns.

## Out of scope (for now)

- Changes to upstream `@atproto/oauth-provider` constants.
- Re-architecting the auth_flow / PAR / OTP separation.
- Generic session-keepalive that crosses concerns.

## Bug found post-PR-154: Resend offers a code that cannot complete the flow

**What broke:** the user lands on the OTP form after the OTP has expired
(>10 min), clicks Resend, gets a fresh code, types it in — and is
bounced back to the OAuth client with an `error=access_denied` redirect.
The clean-exit contract is technically satisfied (user is recoverable,
not stranded inside ePDS), but the experience is a lie: we offered them
Resend as if it would complete the flow, accepted their fresh OTP, then
told them sign-in failed.

**Why it happens:** the heartbeat keeps the upstream PAR alive only
while the page is actively pinging. A user who waits >10 min for the
OTP has typically also let the PAR die at minute 5 (browser tab
backgrounded, laptop closed, network hiccup hit two pings in a row,
etc.). When they click Resend, better-auth happily issues a new OTP
because it doesn't know about the PAR. Auth-service then signs the
callback against the dead `request_uri` and pds-core's
`handleCallbackError` redirects the user back to the OAuth client
with `error=access_denied`.

**Resolved approach:** prevent the dishonest cycle in the first place.

- **Proactive notice (no redirect).** When the heartbeat's
  `/auth/ping` returns `par_expired`, the OTP form replaces its
  current state with a clear notice: "Your sign-in has timed out.
  The code we sent will no longer work. Start sign-in again from the
  app you came from." The notice carries a single "Start over"
  button. The OTP boxes, Resend button, and Verify button are all
  disabled — nothing the user types or clicks on the form will
  silently fail.

  No automatic redirect. The user makes the choice to click Start
  over (which navigates to `/auth/abort`). Clicking elsewhere on
  the page (e.g. the Powered by Certified link) still works as
  expected.

- **Reactive gates kept for defence in depth.** Even with the
  proactive notice, race conditions exist (heartbeat hasn't
  fired yet, user already mid-typing, etc.). Both the Resend click
  and the Verify submit ping `/auth/ping` first — if it returns
  `par_expired`, the handler navigates to `/auth/abort` instead of
  proceeding, so a user who beats the proactive notice still gets
  cleanly bounced rather than typing a code that won't work.

- **`GET /auth/abort` route.** Browser-driven server-side clean exit.
  Reads the auth_flow cookie, runs the same `cleanExit()` helper as
  the unrecoverable-error paths in /auth/complete and
  /auth/choose-handle: redirect to the OAuth client's `redirect_uri`
  with `error=access_denied` per RFC 6749 §4.1.2.1, or fall back to
  a styled "Return to sign in" page when the client is unknown.
  Cookie is cleared because the flow is being abandoned.

**Why a 3-minute heartbeat interval against a 5-minute window?**
PAR's sliding inactivity timer (5 min) is reset on every successful
`requestManager.get()` call upstream. 3 min is comfortably under 5
and tolerates one missed ping (network blip, suspended tab between
ticks). Tighter would be wasted requests; looser would risk the timer
expiring between pings.

**Why slide the timer indefinitely?** The upstream code in
`@atproto/oauth-provider`'s `request-manager.ts` resets `expiresAt`
on every successful read by design — sliding-on-touch is the
intended pattern, not a workaround. The 5-min figure was introduced
in the initial OAuth provider commit (June 2024) with no inline
rationale, no subsequent discussion in PR/commit history, and
nothing in the OAuth/PAR specs that mandates either the value or
the sliding behaviour. Practical bounds:

- The 60-min auth_flow TTL caps how long heartbeat-driven sliding
  can keep a PAR alive — once the auth_flow row dies, /auth/ping
  returns `flow_expired` and the browser stops pinging.
- The httpOnly `epds_auth_flow` cookie gates `/auth/ping`, so an
  attacker without the cookie cannot ping.
- PAR consumption is single-use — once the auth code is issued,
  the row is deleted.

## Status

- Reproduction scenarios: 4 RED scenarios committed on
  `fix/otp-resend-after-par-expiry` and now GREEN — they assert
  "browser lands back at the demo client with an auth error", which
  the demo translates to `?error=auth_failed`.
- Audit: complete. All 12 dead-end sites mapped to clusters A / B / C
  with resolved decisions.
- Heartbeat impl: landed on commit `b1fc940`. `/auth/ping` route +
  3-min `setInterval` on OTP form + recovery form. Covered by 15
  unit tests and one e2e (`@par-heartbeat`).
- Clean-exit impl: landed on commit `2e4d327`. Six auth-service
  dead-ends rewired to `cleanExit()`; pds-core's
  `handleCallbackError` extended with a `signedClientId` fallback
  (delivered via a new `client_id` field on the HMAC-signed
  callback). Covered by 7 new pds-core tests, 4 new shared crypto
  tests, and the four `@otp-and-par-expiry` e2e scenarios.
- Resend-honesty impl (post-PR-154 user report): `/auth/abort`
  route + proactive notice on the OTP form + reactive abort gates
  on Resend / Verify clicks. Resend no longer issues a fresh OTP
  that cannot complete the flow — instead the user goes straight
  to the OAuth client with the spec-compliant error redirect.
  Covered by 4 new auth-abort tests, 7 new login-page render-shape
  tests, and the new `@resend-after-par-dead` e2e scenario. The
  pre-existing `@otp-and-par-expiry` and `@multiple-resend`
  scenarios were updated to match the new contract (the user no
  longer sees the misleading "OTP expired → Resend → fresh OTP
  → fails" cycle).
