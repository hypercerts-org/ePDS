Feature: Passwordless authentication via email OTP
  ePDS replaces the vanilla PDS password-based login with a passwordless
  email OTP (One-Time Password) system. Users enter their email, receive
  a one-time code, and verify it to authenticate. No password is ever
  created or stored in a user-accessible way.

  Background:
    Given the ePDS test environment is running
    And the demo OAuth client's metadata is discoverable

  # --- Happy path ---

  @email
  Scenario: New user authenticates with email OTP
    When the demo client initiates an OAuth login
    Then the browser is redirected to the auth service login page
    And the login page displays an email input form
    When the user enters a unique test email and submits
    Then an OTP email arrives in the mail trap for the test email
    # Demo is a trusted client with its own branded email_subject_template
    # ("{{code}} — your {{app_name}} code"), so subject contains app name.
    And the email subject contains "ePDS Demo"
    And the login page shows an OTP verification form
    When the user enters the OTP code
    And the user picks a handle
    Then the browser is redirected back to the demo client
    And the demo client has a valid OAuth access token

  @email
  Scenario: Returning user authenticates with email OTP
    Given a returning user has a PDS account
    When the demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    And the email subject contains "ePDS Demo"
    When the user enters the OTP code
    Then the demo client's welcome page confirms the user is signed in

  @email
  Scenario: Returning user who has already approved skips consent
    Given a returning user has already approved the demo client
    When the demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    And the email subject contains "ePDS Demo"
    When the user enters the OTP code
    Then the demo client's welcome page confirms the user is signed in

  # --- Session reuse across OAuth clients (HYPER-268) ---
  #
  # After authenticating once via any OAuth client, ePDS should maintain
  # a device session on the authorization server. A subsequent
  # /oauth/authorize request from a *different* client in the same browser
  # must recognise that session and skip the email OTP step entirely.
  #
  # Behaviour depends on whether the client started the flow with a
  # login_hint (demo flow 1 — demo collects the email and forwards it)
  # or without (demo flow 2 — demo redirects straight to the authorization
  # server with no hint):
  #
  #   Flow 1 (login_hint supplied) + bound account matching the hint:
  #     → auto-skip OTP, account chooser is shown for confirmation
  #       (upstream @atproto/oauth-provider does not auto-skip the
  #       chooser on a single-binding/login_hint match — it always
  #       renders for explicit user confirmation), then consent
  #   Flow 2 (no login_hint) + bound account:
  #     → auto-skip OTP, account chooser is shown so the user can confirm
  #       or switch account, then consent
  #   Either flow + pre-approved client (same device):
  #     → consent screen is skipped on top of everything else above
  #
  # See docs/design/cross-client-session-reuse.md "Findings: upstream
  # chooser does not auto-skip on single binding" for the security
  # analysis behind treating the chooser as the user's last-line
  # consent surface, and for the trusted-client opt-in predicate that
  # would let a future feature skip it on a verified login_hint match.

  # Flow 1: a matching login_hint lets ePDS skip the email OTP step. The
  # account chooser is still shown for explicit user confirmation
  # (auto-skipping it on a verified login_hint match is a planned
  # trusted-client opt-in; see the @pending scenarios below).
  @email @session-reuse
  Scenario: Signed-in user is not re-prompted for OTP by a second client (flow 1)
    Given the user has just signed in via the trusted demo client in this browser
    When the untrusted demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then no new OTP email is sent to the test email
    And the account chooser is displayed
    When the user confirms their account on the chooser
    Then a consent screen is displayed
    When the user clicks "Authorize"
    Then the browser is redirected back to the untrusted demo client with a valid session

  # Flow 2: no login_hint means ePDS must show the account chooser so the
  # user can confirm which identity to reuse, even when there is only one
  # bound account. The OTP step must still be skipped.
  @email @session-reuse
  Scenario: Signed-in user confirms their identity via the account chooser (flow 2)
    Given the user has just signed in via the trusted demo client in this browser
    When the untrusted demo client initiates an OAuth login via flow 2
    Then no new OTP email is sent to the test email
    And the account chooser is displayed
    And the account chooser displays the test email
    When the user confirms their account on the chooser
    Then a consent screen is displayed
    When the user clicks "Authorize"
    Then the browser is redirected back to the untrusted demo client with a valid session

  # Flow 2 + pre-approved client: chooser is still shown so the user can
  # confirm, but after confirming the consent screen is skipped and the
  # flow auto-redirects, because the prior approval is still on file
  # (persistent grant keyed by (sub, clientId) in the authorized_client
  # table, and the dev-id cookie is preserved from the pre-approval
  # setup so upstream's session-reuse path engages).
  #
  # The trusted-client sign-in step in the middle is load-bearing: it
  # exercises the U→T cross-client direction (a dev-id minted during
  # the untrusted approval is reused by the trusted client to skip OTP).
  # Without it the test would only prove the (sub, clientId) grant
  # lookup works on a single-client flow.
  #
  # Requires the untrusted demo to run as a confidential client
  # (token_endpoint_auth_method=private_key_jwt). Public clients hit
  # upstream's force-consent rule (request-manager.js) and bypass the
  # remembered-grant path entirely — see docker-compose.yml for the
  # DEMO_UNTRUSTED_PRIVATE_JWK wiring.
  @email @session-reuse
  Scenario: Signed-in user returning to an already-approved second client auto-approves after confirming identity (flow 2)
    Given the user has already approved the untrusted demo client in a prior session
    And the user has a returning session on the trusted demo client in this browser
    When the untrusted demo client initiates an OAuth login via flow 2
    Then no new OTP email is sent to the test email
    And the account chooser is displayed
    When the user confirms their account on the chooser
    Then no consent screen was shown during the second login
    And the browser is redirected back to the untrusted demo client with a valid session

  # Flow 2 "Another account": from the chooser the user must be able to
  # opt out of session reuse and sign in as someone else. Upstream's
  # "Another account" button is a client-side component swap into
  # upstream's stock sign-in form; ePDS must intercept the click and
  # hard-navigate to the auth-service email/OTP form instead.
  @email @session-reuse
  Scenario: Signed-in user can sign in as a different account from the chooser
    Given the user has just signed in via the trusted demo client in this browser
    When the untrusted demo client initiates an OAuth login via flow 2
    Then the account chooser is displayed
    When the user clicks "Another account" on the chooser
    Then the browser is on the auth service email form

  # --- Future: trusted-client auto-skip chooser on login_hint match ---
  #
  # Sketches a planned opt-in feature where a *trusted* client whose
  # metadata advertises `epds_skip_chooser_on_match: true` can skip the
  # account chooser when its `login_hint` (resolved server-side from
  # email to DID) matches a binding on the current device. Untrusted
  # clients never auto-skip — see the security analysis in
  # docs/design/cross-client-session-reuse.md "Findings: upstream
  # chooser does not auto-skip on single binding". These are sketches
  # of the intended behaviour, kept @pending until the feature lands.

  # P1 — single binding, trusted client, login_hint matches: full
  # auto-skip path (no OTP, no chooser, straight to consent or onward).
  @email @session-reuse @pending
  Scenario: Trusted client with matching login_hint auto-skips the chooser (single binding)
    Given the user has just signed in via the trusted demo client in this browser
    And the trusted demo client opts in to chooser auto-skip on login_hint match
    When the trusted demo client initiates an OAuth login with the user's email as login_hint
    Then no new OTP email is sent to the test email
    And the account chooser is not displayed
    And the browser is redirected back to the trusted demo client with a valid session

  # P2 — multiple bindings, trusted client, login_hint matches one of
  # them: auto-skip is still safe because the resolved-DID match
  # uniquely disambiguates the chosen account.
  @email @session-reuse @pending
  Scenario: Trusted client with matching login_hint auto-skips the chooser (multiple bindings)
    Given the user has bound multiple accounts to this device via the trusted demo client
    And the trusted demo client opts in to chooser auto-skip on login_hint match
    When the trusted demo client initiates an OAuth login with one bound account's email as login_hint
    Then no new OTP email is sent to the test email
    And the account chooser is not displayed
    And the browser is redirected back to the trusted demo client signed in as the hinted account

  # P3 — opt-in is mandatory: a trusted client that does NOT advertise
  # the metadata flag must still see the chooser, even with a matching
  # login_hint.
  @email @session-reuse @pending
  Scenario: Trusted client without auto-skip metadata still sees the chooser
    Given the user has just signed in via the trusted demo client in this browser
    And the trusted demo client does not opt in to chooser auto-skip on login_hint match
    When the trusted demo client initiates an OAuth login with the user's email as login_hint
    Then the account chooser is displayed

  # P4 — trust gate is mandatory: an untrusted client must not be able
  # to opt in to auto-skip even by setting the metadata flag.
  @email @session-reuse @pending
  Scenario: Untrusted client cannot auto-skip the chooser even with the metadata flag
    Given the user has just signed in via the trusted demo client in this browser
    And the untrusted demo client advertises chooser auto-skip on login_hint match
    When the untrusted demo client initiates an OAuth login with the user's email as login_hint
    Then the account chooser is displayed

  # P5 — login_hint mismatch falls back to the chooser. The trusted
  # client supplies a hint, but the resolved DID is not bound to this
  # device; the user must pick a real binding from the chooser instead
  # of being silently re-bound to a new account.
  @email @session-reuse @pending
  Scenario: Trusted client with non-matching login_hint falls back to the chooser
    Given the user has just signed in via the trusted demo client in this browser
    And the trusted demo client opts in to chooser auto-skip on login_hint match
    When the trusted demo client initiates an OAuth login with an unbound email as login_hint
    Then the account chooser is displayed

  # P6 — flow 2 (no login_hint) never auto-skips, even for a trusted
  # opted-in client. Without a hint there is nothing to disambiguate
  # from, so picking silently would be drive-by binding.
  @email @session-reuse @pending
  Scenario: Trusted client without login_hint still sees the chooser (flow 2)
    Given the user has just signed in via the trusted demo client in this browser
    And the trusted demo client opts in to chooser auto-skip on login_hint match
    When the trusted demo client initiates an OAuth login via flow 2
    Then the account chooser is displayed

  # --- OTP configuration ---

  # @manual: This scenario requires the auth service to be running with
  # OTP_CHARSET=alphanumeric and OTP_LENGTH=8. These are Railway environment
  # variables that cannot be dynamically set from the test runner against a
  # remote deployment. To test manually: set OTP_CHARSET=alphanumeric and
  # OTP_LENGTH=8 before starting the auth service, then run the e2e suite locally.
  @manual
  Scenario: Alphanumeric OTP codes when configured
    Given OTP_FORMAT is set to "alphanumeric" and OTP_LENGTH is set to "8"
    When the user requests an OTP
    Then the OTP input field has inputmode="text" (not "numeric")
    And the OTP code in the mail trap is 8 characters of uppercase letters and digits

  # --- OTP expiry ---
  #
  # The OTP code expires 10 minutes after issue. The auth_flow row and the
  # epds_auth_flow cookie that thread the OAuth request_uri through the
  # flow have a longer lifetime (60 min — see lib/auth-flow.ts), so a
  # slow user who hits OTP expiry can click Resend and complete the flow
  # without losing the original OAuth ticket.
  #
  # Faking the wall-clock wait would make the suite painfully slow, so we
  # use a test-only auth-service hook (POST /_internal/test/expire-otp,
  # gated by EPDS_TEST_HOOKS=1 + EPDS_INTERNAL_SECRET) to backdate the
  # better-auth verification row only. We deliberately leave the
  # auth_flow row + cookie alive to mirror reality at the 10-minute mark.
  # After the OTP has been aged past expiry, submitting it must fail with
  # the helpful "OTP expired" message; resending must produce a fresh
  # code that completes the flow normally.
  #
  @email @otp-expiry
  Scenario: Expired OTP is rejected, resend recovers the flow
    When the demo client initiates an OAuth login
    Then the browser is redirected to the auth service login page
    And the login page displays an email input form
    When the user enters a unique test email and submits
    Then an OTP email arrives in the mail trap for the test email
    And the login page shows an OTP verification form
    When more than 10 minutes pass before the user enters the OTP
    And the user enters the OTP code
    Then the verification form shows an "OTP expired" error
    And the OTP entry boxes are visible and enabled
    When the user requests a new OTP via the resend button
    Then a fresh OTP email arrives in the mail trap for the test email
    When the user enters the OTP code
    And the user picks a handle
    Then the browser is redirected back to the demo client
    And the demo client has a valid OAuth access token

  # --- Hard-dead PAR clean-exit scenarios (@otp-and-par-expiry) ---
  #
  # These four scenarios reproduce the dead-end pages a real user used
  # to trip when the upstream PAR (request_uri) row died before the
  # OAuth flow could complete. Upstream's PAR has a 5-min sliding
  # inactivity timeout that we cannot bump (hardcoded in
  # @atproto/oauth-provider) and that, once tripped, deletes the row
  # in the same call that throws — so no in-flight recovery is
  # possible.
  #
  # The fix is twofold (see docs/design/par-expiry-and-clean-exits.md):
  #
  #   1. While the user is on the OTP / recovery form, a 3-min
  #      heartbeat to /auth/ping slides the PAR's inactivity timer so
  #      the row stays alive. This is exercised by @par-heartbeat.
  #
  #   2. When the PAR is *genuinely* dead (closed tab, walked away,
  #      explicit upstream cleanup), every dead-end auth-service page
  #      must redirect the user back to the OAuth client with the
  #      RFC 6749 §4.1.2.1 error parameters so the client's own UI
  #      handles retry — never strand them on a static page.
  #
  # These scenarios use /_internal/test/delete-par to simulate (2) —
  # the row is hard-deleted and cannot be revived. The contract they
  # assert is therefore "land back at the demo client with an auth
  # error" (the demo translates `error=access_denied` to
  # `?error=auth_failed` on its landing page), NOT "the OAuth flow
  # successfully completes". Layer 1 (heartbeat) is what prevents
  # the dead PAR; layer 2 (clean-exit) is what makes recovery
  # one-click when prevention fails.
  @email @otp-and-par-expiry
  Scenario: Expired OTP + expired PAR — clean exit back to the OAuth client
    # With the proactive notice + reactive abort gate (added after the
    # original PR-154 user report) the user no longer goes through the
    # "OTP expired → Resend → fresh OTP → fails anyway" cycle. The
    # Verify submit sees the dead PAR via /auth/ping and bails to
    # /auth/abort directly, so the contract this scenario asserts
    # is just "lands at the demo client with an auth error" — same
    # end state, fewer misleading UI steps.
    When the demo client initiates an OAuth login
    Then the browser is redirected to the auth service login page
    And the login page displays an email input form
    When the user enters a unique test email and submits
    Then an OTP email arrives in the mail trap for the test email
    And the login page shows an OTP verification form
    When more than 10 minutes pass before the user enters the OTP
    And the PAR request_uri has expired before the bridge fires
    And the user enters the OTP code
    Then the browser lands back at the demo client with an auth error

  @email @otp-and-par-expiry @multiple-resend
  Scenario: Two Resend cycles after silent PAR death — clean exit back to the OAuth client
    # First Resend cycle works (PAR is still alive). Second Resend
    # triggers after the PAR has died: the reactive abort gate sees
    # /auth/ping returns par_expired, so the resend handler bails
    # to /auth/abort instead of issuing a third OTP that the user
    # could never use. End state: user is back at the demo client
    # with the spec-compliant error redirect, NOT in a misleading
    # "fresh code that won't work" cycle.
    When the demo client initiates an OAuth login
    Then the browser is redirected to the auth service login page
    And the login page displays an email input form
    When the user enters a unique test email and submits
    Then an OTP email arrives in the mail trap for the test email
    And the login page shows an OTP verification form
    When the user requests a new OTP via the resend button
    Then a fresh OTP email arrives in the mail trap for the test email
    When the PAR request_uri has expired before the bridge fires
    And the user requests a new OTP via the resend button
    Then the browser lands back at the demo client with an auth error

  @email @otp-and-par-expiry @prompt-login
  Scenario: prompt=login + expired PAR — clean exit back to the OAuth client
    Given a returning user has a PDS account
    When the demo client starts a new OAuth flow with prompt=login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    And the login page shows an OTP verification form
    When the PAR request_uri has expired before the bridge fires
    And the user enters the OTP code
    Then the browser lands back at the demo client with an auth error

  @email @otp-and-par-expiry @recovery
  Scenario: Recovery via backup email + expired PAR — clean exit back to the OAuth client
    Given a returning user has a PDS account
    And the test user has a verified backup email
    And the demo client initiates OAuth with the test email as login_hint
    # /auth/recover is a plain URL with no request_uri query parameter,
    # so we must snapshot the request_uri while we're still on the
    # original /oauth/authorize page (the login_hint step lands here).
    And the PAR request_uri is captured for later expiry
    When the user navigates to the recovery page
    And the user enters the backup email on the recovery page
    Then an OTP email arrives in the mail trap for the backup email
    When the PAR request_uri has expired before the bridge fires
    And the user enters the recovery OTP
    Then the browser lands back at the demo client with an auth error

  # --- PAR heartbeat (live PAR, no delete) ---
  #
  # Proves the in-page heartbeat reaches /auth/ping and that
  # /auth/ping forwards to pds-core's /_internal/ping-request,
  # i.e. the wiring works end-to-end through Caddy. This is
  # heartbeat liveness, not heartbeat efficacy — the unit tests in
  # heartbeat.test.ts cover routing logic. We don't wall-clock-wait
  # 5 min for the timer to lapse; instead the browser fires the
  # heartbeat fetch synchronously from the OTP form's page context
  # and we assert the response shape.
  @email @par-heartbeat
  Scenario: OTP form's heartbeat reaches /auth/ping with ok:true
    When the demo client initiates an OAuth login
    Then the browser is redirected to the auth service login page
    When the user enters a unique test email and submits
    Then an OTP email arrives in the mail trap for the test email
    And the login page shows an OTP verification form
    Then a heartbeat fetched from the OTP form returns ok:true

  # --- Resend after PAR death ---
  #
  # If the user lands on the OTP form with the upstream PAR already
  # dead (>5 min wait, missed heartbeat, suspended tab, etc.), they
  # should NOT be allowed to click Resend, get a fresh code, type it
  # in, and only then be told sign-in failed. Offering Resend in
  # that state is misleading: better-auth would happily issue a new
  # OTP that pds-core's /oauth/epds-callback would then bounce back
  # to the OAuth client with error=access_denied because the PAR is
  # gone and cannot be revived.
  #
  # The Resend click handler now pings /auth/ping first. If the
  # response is `par_expired` (or `flow_expired` / `no_cookie`), the
  # browser navigates to /auth/abort instead of issuing the new OTP.
  # /auth/abort runs the same cleanExit() as the unrecoverable-error
  # paths, so the user lands at the OAuth client with the standard
  # RFC 6749 §4.1.2.1 error params. No fresh OTP gets issued, no
  # OTP-typing UX cycle.
  @email @resend-after-par-dead
  Scenario: Clicking Resend after the PAR has died bails to the OAuth client without issuing a new OTP
    When the demo client initiates an OAuth login
    Then the browser is redirected to the auth service login page
    When the user enters a unique test email and submits
    Then an OTP email arrives in the mail trap for the test email
    And the login page shows an OTP verification form
    When the PAR request_uri has expired before the bridge fires
    # The Resend step wipes the inbox before clicking the button, so
    # the "no new OTP email" assertion below measures the resend
    # click in isolation rather than the OTP that already arrived.
    And the user requests a new OTP via the resend button
    Then the browser lands back at the demo client with an auth error
    And no new OTP email is sent to the test email

  # --- PAR (request_uri) expiry ---
  #
  # The PAR ("Pushed Authorization Request") record lives in pds-core's
  # @atproto/oauth-provider store. Upstream hardcodes:
  #   * PAR_EXPIRES_IN = 5 minutes (initial TTL on PAR creation), and
  #   * AUTHORIZATION_INACTIVITY_TIMEOUT = 5 minutes (sliding window
  #     reset on every requestManager.get()).
  # If the user takes >5 minutes between requesting an OTP and
  # submitting it (slow inbox, switching tabs, fishing the code out
  # of spam, multiple Resend cycles), the PAR row is gone by the time
  # auth-service's /auth/complete redirects to /oauth/epds-callback.
  # PAR expiry is genuine: once expired, the row cannot be revived —
  # @atproto/oauth-provider's RequestManager.get() throws
  # AccessDeniedError AND deletes the row in the same call.
  #
  # The bug a real user hit: the resulting AccessDeniedError was
  # caught inside /oauth/epds-callback and surfaced as a raw JSON
  # response body of {"error": "Authentication failed"} on the PDS
  # host, with no client redirect and no styled page. The fix is to
  # honour RFC 6749 §4.1.2.1: redirect the user back to the OAuth
  # client's redirect_uri with error=access_denied,
  # error_description, iss, and state query parameters, so the
  # client can offer "Sign-in expired, try again". When no
  # redirect_uri is recoverable from the dead PAR row, fall back to
  # a styled HTML page on the PDS host instead of raw JSON.
  #
  # access_denied is the same error code @atproto/oauth-provider uses
  # for PAR expiry on its own paths (e.g. when a user is bounced
  # through /oauth/authorize with an expired request_uri). We follow
  # that precedent for consistency, even though "denied" is mildly
  # misleading — the error_description carries the real user-friendly
  # explanation.
  #
  # Wall-clock waiting 5 minutes is unacceptable for an e2e scenario,
  # so a test-only pds-core hook (POST /_internal/test/delete-par,
  # gated by EPDS_TEST_HOOKS=1 + EPDS_INTERNAL_SECRET, and refused
  # under NODE_ENV=production) deletes the PAR row directly. The
  # auth_flow row, OTP, and cookie are all left alive so the failure
  # isolates to the PAR layer — exactly what a slow user trips in
  # production.

  # The test deletes the PAR row before the callback fires, mirroring
  # the production failure where /oauth/epds-callback's first
  # requestManager.get() (Step 2 in the handler) throws
  # InvalidRequestError("Unknown request_uri"). The signed callback
  # URL now carries `client_id` (per the clean-exit work in this PR),
  # so even though the PAR is dead the catch block can resolve the
  # client's metadata and redirect the user back to the OAuth client
  # with the standard RFC 6749 §4.1.2.1 error parameters. The demo
  # client translates `error=access_denied` into `?error=auth_failed`
  # on its landing page; that's the contract this scenario asserts.
  #
  # The static HTML fallback inside pds-core's catch block only fires
  # in the worst case where neither the captured PAR data nor the
  # signed `client_id` resolves to a usable redirect URI — much
  # harder to reach now and not exercised here.
  @email @par-callback-error
  Scenario: Expired PAR redirects back to the OAuth client instead of stranding the user
    Given a returning user has a PDS account
    When the demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    And the login page shows an OTP verification form
    When the PAR request_uri has expired before the bridge fires
    And the user enters the OTP code
    Then the browser lands back at the demo client with an auth error

  # Regression boundary for the auth_flow lifetime. The auth_flow row +
  # epds_auth_flow cookie are explicitly NOT tied to the OTP TTL — they
  # live for 60 minutes (lib/auth-flow.ts) so a slow user who hits OTP
  # expiry and clicks Resend can still complete on the original ticket.
  # If someone shortens AUTH_FLOW_TTL_MS back to the OTP TTL we want to
  # catch it here: past the 60-minute mark, even a freshly verified OTP
  # must NOT recover the flow.
  #
  # Post-PR-154 the OTP form's reactive abort gate pings /auth/ping
  # before submitting; with the auth_flow row backdated /auth/ping
  # answers `flow_expired` and the gate navigates to /auth/abort.
  # /auth/abort then reads AUTH_FLOW_COOKIE to recover the OAuth
  # client_id for a redirect back — and because the same row is dead
  # that lookup also fails, so cleanExit serves its Tier-2 styled
  # "Sign-in session expired" fallback page on the auth-service host.
  # We assert both signals: the ping reason (proving auth_flow
  # specifically tripped, not PAR) and the abort fallback page.
  @email @otp-expiry
  Scenario: OAuth flow expires after the auth_flow TTL elapses
    When the demo client initiates an OAuth login
    Then the browser is redirected to the auth service login page
    And the login page displays an email input form
    When the user enters a unique test email and submits
    Then an OTP email arrives in the mail trap for the test email
    And the login page shows an OTP verification form
    When more than 60 minutes pass before the user submits the OTP
    And the user enters the OTP code
    Then the OAuth flow aborts because auth_flow expired

  # --- Brute force protection ---

  Scenario: OTP verification rejects wrong code
    When the user requests an OTP for a unique test email
    And enters an incorrect OTP code
    Then the verification form shows an error message
    And the OTP entry boxes are visible and enabled

  Scenario: Too many failed OTP attempts locks out the token
    When the user requests an OTP for a unique test email
    And enters an incorrect OTP code 5 times
    Then further attempts are rejected
    And the user must request a new OTP

  # --- Idempotent login page ---

  Scenario: Refreshing the login page does not break the flow
    When the demo client redirects to the auth service login page
    And the user refreshes the page (duplicate GET /oauth/authorize)
    Then the login page renders normally
    And the OTP flow still works to completion
