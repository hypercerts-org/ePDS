Feature: Login hint resolution
  ePDS resolves OAuth login_hint parameters so the auth service can skip
  the email form and go straight to OTP verification. Hints can be emails,
  AT Protocol handles, or DIDs.

  The parsing and internal API call logic is unit-tested in
  resolve-login-hint.test.ts. These E2E scenarios test the observable
  user-facing behavior.

  Background:
    Given the ePDS test environment is running
    And a returning user has a PDS account

  Scenario: Email login hint skips the email form
    When the demo client initiates OAuth with the test email as login_hint
    Then the login page renders directly at the OTP verification step
    And an OTP email is auto-sent to the test email

  Scenario: Handle login hint is resolved and skips the email form
    When the demo client initiates OAuth with the test handle as login_hint
    Then the login page renders directly at the OTP verification step
    And an OTP email is auto-sent to the test email

  Scenario: DID login hint is resolved and skips the email form
    When the demo client initiates OAuth with the test DID as login_hint
    Then the login page renders directly at the OTP verification step
    And an OTP email is auto-sent to the test email

  Scenario: Login hint from PAR body is used when not on query string
    When the demo client submits the test handle as login_hint in the PAR body only
    Then the login page renders directly at the OTP verification step
    And an OTP email is auto-sent to the test email

  Scenario: Unknown login hint falls back to email form
    When the demo client initiates OAuth with an unknown handle as login_hint
    Then the login page shows the email input form
