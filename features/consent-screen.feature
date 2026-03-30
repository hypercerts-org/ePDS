Feature: OAuth consent screen
  When an existing user logs into a new OAuth client for the first time,
  ePDS shows a consent screen asking for approval. New accounts skip
  consent (account creation implies consent). Consent decisions are
  remembered per client.

  Background:
    Given the ePDS test environment is running
    And a demo OAuth client is registered

  Scenario: Existing user sees consent screen for a new client
    Given a returning user has a PDS account
    When the demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    When the user enters the OTP code
    Then a consent screen is displayed
    And it shows the demo client's name
    When the user clicks "Approve"
    Then the browser is redirected back to the demo client with a valid session

  Scenario: User denies consent
    Given a returning user has a PDS account
    When the demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    When the user enters the OTP code
    Then a consent screen is displayed
    When the user clicks "Deny"
    Then the browser is redirected to the PDS with an access_denied error

  Scenario: Returning user skips consent for a previously-approved client
    Given a returning user has already approved the demo client
    When the demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    When the user enters the OTP code
    Then no consent screen is shown
    And the browser is redirected back to the demo client with a valid session

  Scenario: New user skips consent entirely
    Given a new user has registered via the demo client
    Then no consent screen is shown
    And the browser is redirected back to the demo client with a valid session

  # TODO: automate once custom CSS injection is merged into the consent route
  # (renderConsent() needs to accept and apply clientBrandingCss from client metadata)
  @manual
  Scenario: Consent page shows client branding for trusted clients
    Given the demo client is listed in PDS_OAUTH_TRUSTED_CLIENTS
    And the demo client's metadata includes custom CSS
    When the consent screen is displayed
    Then the client's custom CSS is applied to the page
