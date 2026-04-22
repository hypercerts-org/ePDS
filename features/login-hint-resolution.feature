@pending
Feature: Login hint resolution
  ePDS resolves OAuth login_hint parameters so the auth service can skip
  the email form and go straight to OTP verification. Hints can be emails,
  AT Protocol handles, or DIDs.

  The parsing and internal API call logic is unit-tested in
  resolve-login-hint.test.ts. These E2E scenarios test the observable
  user-facing behavior.

  Background:
    Given the ePDS test environment is running
    And "alice@example.com" has a PDS account with handle "alice.pds.test"

  Scenario: Email login hint skips the email form
    When the demo client initiates OAuth with login_hint="alice@example.com"
    Then the login page renders directly at the OTP verification step
    And an OTP email is auto-sent to "alice@example.com"

  Scenario: Handle login hint is resolved and skips the email form
    When the demo client initiates OAuth with login_hint="alice.pds.test"
    Then the login page renders directly at the OTP verification step
    And an OTP email is auto-sent to "alice@example.com"

  Scenario: DID login hint is resolved and skips the email form
    Given alice's DID is "did:plc:alice123"
    When the demo client initiates OAuth with login_hint="did:plc:alice123"
    Then the login page renders directly at the OTP verification step
    And an OTP email is auto-sent to "alice@example.com"

  Scenario: Login hint from PAR body is used when not on query string
    When the demo client submits login_hint in the PAR request body (not the redirect URL)
    Then the auth service retrieves the hint from the stored PAR request
    And the login page renders at the OTP step with the hint resolved

  Scenario: Unknown login hint falls back to email form
    When the demo client initiates OAuth with login_hint="unknown.pds.test"
    Then the login page shows the email input form (hint could not be resolved)
