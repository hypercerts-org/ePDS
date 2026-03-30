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
    When the user enters a unique test email and submits
    Then an OTP email arrives in the mail trap for the test email
    # "Welcome" for new users, "Sign-in" for returning users
    And the email subject contains "Welcome"
    And the login page shows an OTP verification form
    When the user enters the OTP code
    Then the browser is redirected back to the demo client
    And the demo client has a valid OAuth access token

  Scenario: Returning user authenticates with email OTP
    Given a returning user has a PDS account
    When the demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    And the email subject contains "Sign-in"
    When the user enters the OTP code
    And the user approves the consent screen
    Then the browser is redirected back to the demo client with a valid session

  Scenario: Returning user who has already approved skips consent
    Given a returning user has already approved the demo client
    When the demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    And the email subject contains "Sign-in"
    When the user enters the OTP code
    Then the browser is redirected back to the demo client with a valid session

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
