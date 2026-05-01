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
    And the user can try again
    When the user requests a new OTP via the resend button
    Then a fresh OTP email arrives in the mail trap for the test email
    When the user enters the OTP code
    And the user picks a handle
    Then the browser is redirected back to the demo client
    And the demo client has a valid OAuth access token

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
  # InvalidRequestError("Unknown request_uri"). With no live PAR row
  # there is no redirect_uri to recover, so the user must land on a
  # styled HTML page on the PDS host — not the previous raw JSON
  # body — explaining that the sign-in timed out.
  #
  # The redirect-back-to-client path (driven by the redirect_uri /
  # state captured during a successful Step 2) is exercised by the
  # other paths inside the same handler that throw later in the
  # flow; we don't have an easy e2e harness to inject a mid-flow
  # failure today.
  @email @par-callback-error
  Scenario: Expired PAR shows a styled HTML page instead of leaking JSON
    Given a returning user has a PDS account
    When the demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    And the login page shows an OTP verification form
    When the PAR request_uri has expired before the bridge fires
    And the user enters the OTP code
    Then the response body is not raw JSON
    And the response body explains that sign-in timed out

  # --- Brute force protection ---

  Scenario: OTP verification rejects wrong code
    When the user requests an OTP for a unique test email
    And enters an incorrect OTP code
    Then the verification form shows an error message
    And the user can try again

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
