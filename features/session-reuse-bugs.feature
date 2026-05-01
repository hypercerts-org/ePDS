@session-reuse @docker-only @email
Feature: Welcome-page guard suppresses upstream's authentication UI
  Upstream @atproto/oauth-provider has two authentication UIs that ePDS
  must never render: its stock welcome page ("Authenticate / Create new
  account / Sign in / Cancel") and its sign-in-view (handle + password
  form). Both are unreachable by design — ePDS accounts are passwordless
  and authentication goes through auth-service's OTP flow.

  The pre-route guard in pds-core (welcome-page-guard.ts) intercepts
  every guarded GET and bounces to auth-service whenever upstream would
  otherwise render either UI. ePDS must recover gracefully from every
  variety of cookie/server divergence — and from every PAR-parameter
  combination that would otherwise force upstream into its sign-in
  form — by falling back to the auth-service email/OTP form and
  clearing stale cookies so the next visit starts clean.

  See docs/design/session-reuse-bugs.md for the full failure-mode
  taxonomy. This feature covers the externally-reproducible cases.

  Background:
    Given the ePDS test environment is running
    And a returning user has a PDS account
    And the user has completed one OAuth sign-in from the demo client
    And the browser holds a valid dev-id and ses-id cookie pair

  Scenario: Both cookies valid — baseline session reuse still works
    When the demo client starts a new OAuth flow
    Then the browser lands on the ePDS enriched account picker

  Scenario: Only dev-id is present (ses-id missing)
    Given the ses-id cookie has been evicted from the browser
    When the demo client starts a new OAuth flow
    Then the browser lands on the auth-service email-and-OTP form
    # Both cookies (and their parent-domain variants) must clear on any
    # half-pair bounce — auth-service's contract is that a half-pair
    # never survives into the next flow. Asserting only the orphan half
    # would let a regression that clears only one cookie sneak through.
    And the response clears the dev-id and ses-id cookies

  Scenario: Only ses-id is present (dev-id missing)
    Given the dev-id cookie has been evicted from the browser
    When the demo client starts a new OAuth flow
    Then the browser lands on the auth-service email-and-OTP form
    And the response clears the dev-id and ses-id cookies

  Scenario: dev-id is stale, ses-id is valid
    Given the dev-id cookie has been replaced with a well-formed but server-unknown value
    When the demo client starts a new OAuth flow
    Then the browser lands on the auth-service email-and-OTP form
    And the response clears the dev-id and ses-id cookies

  Scenario: ses-id is stale, dev-id is valid
    Given the ses-id cookie has been replaced with a well-formed but server-unknown value
    When the demo client starts a new OAuth flow
    Then the browser lands on the auth-service email-and-OTP form
    And the response clears the dev-id and ses-id cookies

  Scenario: Both cookies are stale (server-unknown pair)
    Given the dev-id and ses-id cookies have been replaced with well-formed but server-unknown values
    When the demo client starts a new OAuth flow
    Then the browser lands on the auth-service email-and-OTP form
    And the response clears the dev-id and ses-id cookies

  Scenario: "Another account" on the chooser goes to the email form
    Given the browser holds cookies for a device with at least one bound account
    When the demo client starts a new OAuth flow
    Then the browser lands on the ePDS enriched account picker
    When the user clicks "Another account" on the enriched account picker
    Then the browser lands on the auth-service email-and-OTP form

  Scenario: Upstream "Sign up" affordance is hidden on the enriched chooser
    Given the browser holds cookies for a device with at least one bound account
    When the demo client starts a new OAuth flow
    Then the browser lands on the ePDS enriched account picker
    And no upstream "Sign up" affordance is visible on the chooser

  Scenario: Chooser hides handles when the flow resolves to random handle mode
    Given the browser holds cookies for a device with at least one bound account
    When the demo client starts a new OAuth flow with random handle mode
    Then the browser lands on the ePDS enriched account picker
    And the enriched account picker renders without the handle visible
    And each row exposes the handle only via a title tooltip
    And the email remains visible as the primary identifier

  @pending
  # The purged-bindings repro needs server-side white-box access to delete
  # device_account rows out of band, which the e2e suite intentionally avoids
  # (see features/README.md). Left pending so the invariant remains visible
  # as a living spec; unit tests cover the guard's zero-bindings branch.
  Scenario: Pre-existing device whose bindings have been purged
    # Reproduces the migration-005 1h TTL purge for remember=0 rows:
    # cookies are valid and parse successfully, device row exists, but
    # the device_account row was purged so the device has zero bound
    # accounts at chooser render time.
    Given the user has a valid dev-id and ses-id pair
    And the device row exists but has zero bound accounts
    When the demo client starts a new OAuth flow
    Then the browser lands on the auth-service email-and-OTP form
    And the response clears the dev-id and ses-id cookies

  # ---------------------------------------------------------------------------
  # Pre-PR-#103 host-only cookies shadow the freshly-set Domain-scoped pair.
  # Reproduces GitHub issue #116. A user whose browser jar holds a host-only
  # dev-id/ses-id pair from before cookie-domain broadening shipped — when
  # the cookie parser keeps the first occurrence per name and per RFC 6265
  # §5.4 the host-only stale entry comes first — the welcome-page-guard
  # validates the wrong values, bounces to auth-service with prompt=login,
  # and the user loops on the OTP form. The scenario's Given clears the
  # jar (overriding what the Background's OAuth sign-in deposited) and
  # plants only the stale host-only pair, matching the actual state of
  # an affected user's browser.
  # ---------------------------------------------------------------------------

  Scenario: Stale host-only cookies don't trap the user in an OTP loop
    # The Background's account-creation step recorded the trusted demo as
    # an authorised client (PDS_SIGNUP_ALLOW_CONSENT_SKIP), so a returning
    # login skips consent and lands on /welcome. Pre-fix the user never
    # gets there — every post-callback /oauth/authorize hop bounces
    # because the host-only stale pair shadows the freshly-set
    # Domain-scoped pair.
    Given the browser jar holds only a stale host-only dev-id and ses-id pair
    When the demo client starts a new OAuth flow
    And the user enters the test email on the login page
    Then the login page shows an OTP verification form
    And an OTP email arrives in the mail trap
    When the user enters the OTP code
    Then the browser is redirected back to the demo client

  # ---------------------------------------------------------------------------
  # Flow 1 hint-vs-bindings gate: when login_hint resolves to an email that
  # is not bound to the current device, auth-service must skip session reuse
  # and surface the email/OTP form so the hinted user can sign in fresh.
  # See packages/auth-service/src/lib/session-reuse.ts shouldReuseSession
  # and packages/pds-core/src/lib/device-accounts.ts.
  # ---------------------------------------------------------------------------

  Scenario: Login hint matches a bound account — chooser still wins
    When the demo client starts a new OAuth flow with the test user's handle as login_hint
    Then the browser lands on the ePDS enriched account picker

  # GitHub issue #138: when the OAuth flow that reached the chooser carried
  # a login_hint, the "Another account" rebind preserves it on the
  # auth-service URL and adds prompt=login. shouldReuseSession honours
  # prompt=login and falls through to the login page, but the initialStep
  # selector at routes/login-page.ts only looks at hint presence — so the
  # resolved email forces initialStep='otp' and the user lands on the OTP
  # form for the *previous* account instead of the email entry form. The
  # email form is the only correct outcome: prompt=login is the user's
  # explicit "start over" signal.
  Scenario: "Another account" with login_hint must reach the email form
    When the demo client starts a new OAuth flow with the test user's handle as login_hint
    Then the browser lands on the ePDS enriched account picker
    When the user clicks "Another account" on the enriched account picker
    Then the browser is on the auth service email form
    And the email input is empty
    And the OTP verification step is not active

  Scenario: Login hint resolves to an unbound account — skip chooser
    Given another user has a separate PDS account
    When the demo client starts a new OAuth flow with the other user's handle as login_hint
    Then the login page renders directly at the OTP verification step
    And the OTP form will submit the other user's email

  # ---------------------------------------------------------------------------
  # Sign-in-view leaks. Distinct from the welcome-page leaks above: here
  # cookies and bindings are valid, but every binding upstream would consider
  # has `loginRequired: true`, so upstream's only remaining path is to render
  # its sign-in-view (handle + password form). The chooser may render first
  # as an intermediate step, but every account on it leads to sign-in-view on
  # click — equally a leak. ePDS accounts are passwordless, so any path into
  # that form is unusable. The guard must bounce these to auth-service for a
  # fresh OTP round.
  #
  # Three independent triggers force every binding into loginRequired:
  #   - the stored PAR contains `prompt=login` (forced re-authentication);
  #   - every binding's `account_device.updated_at` is older than
  #     upstream's authenticationMaxAge (7 days);
  #   - `login_hint` resolves to a binding that's individually stale even
  #     though other bindings on the device are fresh, and upstream
  #     pre-selects the hinted account so clicking lands on sign-in-view.
  # ---------------------------------------------------------------------------

  Scenario: Forced re-authentication via prompt=login
    # The demo's "Force re-authentication" checkbox sets prompt=login on
    # both the auth-service redirect query AND the PAR body. Auth-service's
    # `shouldReuseSession` honours the query and serves the OTP form rather
    # than redirecting to pds-core (session-reuse.ts:158, isForceLoginPrompt).
    # The user completes OTP, and pds-core's epds-callback redirects to
    # pds-core's own /oauth/authorize?request_uri=... with the now-fresh
    # device cookies. At THAT hop the auth-ui-guard fires:
    #   - cookie pair is valid (just set by the callback)
    #   - the device has one binding (the user just authenticated)
    #   - the stored PAR `parameters.prompt` is still 'login' (the demo also
    #     set it in the PAR body)
    # Without the fix the guard would pass through; upstream's authorize()
    # reads the stored PAR, marks the only session loginRequired, and the
    # frontend renders sign-in-view. The guard bounces back to auth-service
    # and the epds-callback hop strips the `login` token from the stored
    # PAR so the next /oauth/authorize hop can complete normally.
    When the demo client starts a new OAuth flow with prompt=login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    When the user enters the OTP code
    # The end-to-end recovery: after the (single) OTP cycle the user lands
    # on /welcome. Earlier iterations of the fix re-bounced the post-OTP
    # /oauth/authorize hop because the stored PAR still carried
    # prompt=login, looping forever. The epds-callback hop strips that
    # token after a successful OTP, so there is exactly one OTP cycle,
    # one bounce-suppression, then /welcome.
    Then the demo client's welcome page confirms the user is signed in

  # Reproducing the all-bindings-stale case needs server-side white-box
  # access to backdate `account_device.updated_at` past upstream's
  # authenticationMaxAge (7 days). A pds-core
  # /_internal/test/expire-device-account hook provides this, gated on
  # EPDS_TEST_HOOKS=1 && NODE_ENV !== 'production' (mirroring auth-service's
  # expire-otp / expire-auth-flow hooks).
  Scenario: Every binding's auth age exceeds 7 days
    Given the device's account_device row has been backdated past 7 days
    When the demo client starts a new OAuth flow
    # End-to-end recovery: the auth-ui-guard bounces the initial
    # /oauth/authorize hop to auth-service, the user completes a fresh OTP
    # cycle, and lands on /welcome.
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    When the user enters the OTP code
    Then the demo client's welcome page confirms the user is signed in

  # The hint-narrowed case needs two bindings on the same device — one
  # stale, one fresh — plus a login_hint that resolves to the stale one.
  # Built on the same /_internal/test/expire-device-account hook used by
  # the all-stale scenario above, plus a second OAuth sign-in driven within
  # the SAME browser context (so the second account's upsertDeviceAccount
  # binds to the existing dev-id rather than creating a fresh device).
  Scenario: login_hint narrows to a stale binding on a multi-account device
    Given the device has two bound accounts
    And the test user's account_device row has been backdated past 7 days
    And the other user's account_device row is fresh
    When the demo client starts a new OAuth flow with the test user's handle as a PAR-body login_hint
    # End-to-end recovery: the auth-ui-guard bounces to auth-service
    # with the email already resolved from the PAR-body login_hint, so
    # auth-service serves the OTP step directly (no email entry). After
    # the OTP cycle the user lands on /welcome.
    Then an OTP email arrives in the mail trap
    When the user enters the OTP code
    Then the demo client's welcome page confirms the user is signed in
