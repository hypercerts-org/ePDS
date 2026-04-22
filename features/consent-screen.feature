@untrusted-client
Feature: OAuth consent screen
  When a user logs into a new OAuth client for the first time, ePDS shows
  a consent screen asking for approval. Consent decisions are remembered
  per client. Sign-up consent can be skipped when all three conditions
  hold: PDS_SIGNUP_ALLOW_CONSENT_SKIP is enabled on the PDS, the client
  is listed in PDS_OAUTH_TRUSTED_CLIENTS, and the client's metadata opts
  in via "epds_skip_consent_on_signup": true. The e2e environment is
  configured with the PDS flag on and both demo clients opted in via
  metadata, so the trusted/untrusted distinction is what's exercised here.

  Background:
    Given the ePDS test environment is running
    And the trusted demo OAuth client's metadata is discoverable
    And the untrusted demo OAuth client's metadata is discoverable

  # These scenarios sign up via the trusted demo client (which skips the
  # consent screen at sign-up as part of the trusted-client flow) and then
  # log in to the *untrusted* demo client — a genuinely new client for the
  # user. That's the only way to exercise the "first login to a new client
  # shows consent" path now that sign-up auto-authorises trusted clients.

  Scenario: Existing user sees consent screen for a new client
    Given a returning user has a PDS account
    When the untrusted demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    When the user enters the OTP code
    Then a consent screen is displayed
    And it identifies the untrusted demo client by its URL host
    When the user clicks "Authorize"
    Then the browser is redirected back to the untrusted demo client with a valid session

  Scenario: User denies consent
    Given a returning user has a PDS account
    When the untrusted demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    When the user enters the OTP code
    Then a consent screen is displayed
    When the user clicks "Deny access"
    Then the browser is redirected back to the untrusted demo client with an auth error

  # HYPER-270: Tests the real "click Authorize → record grant → return
  # login skips consent" path. Uses the untrusted demo deliberately —
  # the trusted demo would auto-authorize during sign-up via the
  # PDS_SIGNUP_ALLOW_CONSENT_SKIP path (setAuthorizedClient in
  # pds-core/src/index.ts step 5) and silently paper over any bug in
  # the explicit-click-Authorize grant-recording path.
  Scenario: Returning user skips consent for a previously-approved untrusted client
    Given a returning user has already approved the untrusted demo client
    When the untrusted demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    When the user enters the OTP code
    Then no consent screen is shown
    And the browser is redirected back to the untrusted demo client with a valid session

  Scenario: New user skips consent when signing up via a trusted client
    When a new user signs up via the trusted demo client
    Then no consent screen is shown
    And the browser is redirected back to the trusted demo client with a valid session

  Scenario: New user still sees consent when signing up via an untrusted client
    When a new user starts signing up via the untrusted demo client
    Then a consent screen is displayed
    When the user clicks "Authorize"
    Then the browser is redirected back to the untrusted demo client with a valid session

  Scenario: Sign-up consent skip does not carry over to a second client
    Given a returning user signed up via the trusted demo client with consent skipped
    When the user later initiates an OAuth login via the untrusted demo client
    Then a consent screen is displayed

  # TODO: automate once custom CSS injection is merged into the consent route
  # (renderConsent() needs to accept and apply clientBrandingCss from client metadata)
  @manual
  Scenario: Consent page shows client branding for trusted clients
    Given the demo client is listed in PDS_OAUTH_TRUSTED_CLIENTS
    And the demo client's metadata includes custom CSS
    When the consent screen is displayed
    Then the client's custom CSS is applied to the page
