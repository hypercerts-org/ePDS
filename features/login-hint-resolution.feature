Feature: Login hint resolution
  ePDS resolves email OAuth login_hint parameters so the auth service can
  skip the email form and go straight to code verification. AT Protocol
  handle or DID hints in the PAR body are handed to the stock PDS
  handle/password login page for this fork.

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

  Scenario: Handle login hint in the PAR body opens the PDS password page
    When the demo client submits the test handle as login_hint in the PAR body only
    Then the browser is on the PDS authorize page

  Scenario: DID login hint in the PAR body opens the PDS password page
    When the demo client submits the test DID as login_hint in the PAR body only
    Then the browser is on the PDS authorize page

  Scenario: Unknown login hint falls back to email form
    When the demo client initiates OAuth with an unknown handle as login_hint
    Then the login page shows the email input form
