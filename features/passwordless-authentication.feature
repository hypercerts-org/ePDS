Feature: Passwordless authentication via email OTP
  ePDS replaces the vanilla PDS password-based login with a passwordless
  email OTP (One-Time Password) system. Users enter their email, receive
  a one-time code, and verify it to authenticate. No password is ever
  created or stored in a user-accessible way.

  Background:
    Given the ePDS test environment is running
    And a demo OAuth client is registered

  # --- Happy path ---

  Scenario: New user authenticates with email OTP
    When the demo client initiates an OAuth login
    Then the browser is redirected to the auth service login page
    And the login page displays an email input form
    When the user enters "alice@example.com" and submits
    Then an OTP email arrives in the mail trap for "alice@example.com"
    And the email subject contains "Welcome" (new user)
    And the login page shows an OTP verification form
    When the user enters the OTP code from the email
    Then the browser is redirected back to the demo client
    And the demo client has a valid OAuth access token

  Scenario: Returning user authenticates with email OTP
    Given "bob@example.com" already has a PDS account
    When the demo client initiates an OAuth login
    And the user enters "bob@example.com" on the login page
    Then an OTP email arrives in the mail trap
    And the email subject contains "Sign-in" (returning user)
    When the user enters the OTP code
    Then the browser is redirected back to the demo client with a valid session

  # --- OTP configuration ---

  Scenario: Alphanumeric OTP codes when configured
    Given OTP_FORMAT is set to "alphanumeric" and OTP_LENGTH is set to "8"
    When the user requests an OTP
    Then the OTP input field has inputmode="text" (not "numeric")
    And the OTP code in the mail trap is 8 characters of uppercase letters and digits

  # --- Brute force protection ---

  Scenario: OTP verification rejects wrong code
    When the user requests an OTP for "alice@example.com"
    And enters an incorrect OTP code
    Then the verification form shows an error message
    And the user can try again

  Scenario: Too many failed OTP attempts locks out the token
    When the user requests an OTP for "alice@example.com"
    And enters an incorrect OTP code 5 times
    Then further attempts are rejected
    And the user must request a new OTP

  # --- Terms of Service acceptance ---

  Scenario: New user must accept Terms of Service before completing OTP verification
    Given no PDS account exists for the user
    When the user authenticates via OTP through the demo client
    Then the OTP step shows a Terms of Service and Privacy Policy acceptance checkbox
    And the checkbox must be checked before OTP verification can be submitted
    When the user checks the checkbox and enters the OTP code
    Then the browser is redirected back to the demo client with a valid session

  Scenario: Returning user is not shown the Terms of Service checkbox
    Given a user already has a PDS account
    When the user authenticates via OTP through the demo client
    Then the OTP step does not show a Terms of Service checkbox

  # --- Idempotent login page ---

  Scenario: Refreshing the login page does not break the flow
    When the demo client redirects to the auth service login page
    And the user refreshes the page (duplicate GET /oauth/authorize)
    Then the login page renders normally
    And the OTP flow still works to completion
