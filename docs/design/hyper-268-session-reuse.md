# HYPER-268 — Cross-client OAuth session reuse

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
| 2    | User wants a different account                      | chooser → "Use a different account" link → redirect to auth-service email/OTP form for the new account                     |
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

4. **"Use a different account" link (pds-core).** Same response-rewrite
   mechanism. Inject a visible link that points to
   `https://auth.pds.foo.com/oauth/authorize?...` with the original
   OAuth params plus a marker (e.g. `prompt=login` or a custom query
   flag) that tells auth-service "don't redirect me back — render the
   email form". Auth-service honors that flag by bypassing its session
   detection.

### Flow summaries

**Session-holder, flow 2, default (single account):**

```
browser → auth.pds.foo.com/oauth/authorize?...
         → 302 (auth-service sees dev-id cookie)
browser → pds.pds.foo.com/oauth/authorize?...
         → upstream middleware loads device session
         → renders /account (chooser)
browser → /account  (chooser with injected email display + "use different" link)
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
         → user clicks "Use a different account"
         → 302 to auth.pds.foo.com/oauth/authorize?...&prompt=login
         → auth-service honors prompt=login, renders email form
         → email + OTP → new account bound to device
         → 302 to pds.pds.foo.com/oauth/authorize → consent → client
```

## Test scenarios

New Gherkin scenarios in `features/passwordless-authentication.feature`
under the HYPER-268 heading. Replaces the two speculative scenarios
currently on this branch.

1. **A — Flow 1, signed in, auto-skip**
   Trusted demo sign-in, then untrusted demo flow 1 (re-enters email).
   Assert: no new OTP email, no OTP form shown, no chooser shown,
   lands on consent → authorize → /welcome.

2. **B — Flow 2, signed in, chooser with one account**
   Trusted demo sign-in, then untrusted demo flow 2 (no email).
   Assert: no new OTP email, chooser shown, chooser contains test
   email text, user confirms account, lands on consent → authorize
   → /welcome.

3. **C — Flow 2, signed in + pre-approved untrusted, auto-authorize**
   Pre-approve untrusted, then trusted demo sign-in as returning user
   (not new sign-up — requires a new setup step), then untrusted flow 2.
   Assert: no new OTP email, chooser shown, user confirms, no consent
   screen, lands on /welcome.

4. **D — Flow 2, signed in, user picks "different account"**
   Trusted sign-in, then untrusted flow 2, chooser shown, user clicks
   "Use a different account", lands on auth-service email form for a
   fresh account.

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
- `When the user clicks "Use a different account" on the chooser`
  (clicks the injected link).
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
