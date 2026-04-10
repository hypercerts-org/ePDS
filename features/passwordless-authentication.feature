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
    # "Welcome" for new users, "Sign-in" for returning users
    And the email subject contains "Welcome"
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
    And the email subject contains "Sign-in"
    When the user enters the OTP code
    Then the browser is redirected back to the demo client with a valid session

  @email
  Scenario: Returning user who has already approved skips consent
    Given a returning user has already approved the demo client
    When the demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then an OTP email arrives in the mail trap
    And the email subject contains "Sign-in"
    When the user enters the OTP code
    Then the browser is redirected back to the demo client with a valid session

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
  #   Flow 1 + single bound account matching the hint:
  #     → auto-skip OTP, auto-skip account chooser, auto-redirect to consent
  #   Flow 2 + single bound account:
  #     → auto-skip OTP, account chooser is shown so the user can confirm
  #       or switch account, then consent
  #   Either flow + pre-approved client:
  #     → consent screen is skipped on top of everything else above

  # Scenario A — Flow 1: a matching login_hint lets ePDS skip both the
  # email OTP step and the account chooser (upstream oauth-provider
  # auto-selects the matching session).
  @email @session-reuse
  Scenario: Signed-in user is not re-prompted for OTP by a second client (flow 1)
    Given the user has just signed in via the trusted demo client in this browser
    When the untrusted demo client initiates an OAuth login
    And the user enters the test email on the login page
    Then no new OTP email is sent to the test email
    And the account chooser is not displayed
    And a consent screen is displayed
    When the user clicks "Authorize"
    Then the browser is redirected back to the untrusted demo client with a valid session

  # Scenario B — Flow 2: no login_hint means ePDS must show the account
  # chooser so the user can confirm which identity to reuse, even when
  # there is only one bound account. The OTP step must still be skipped.
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

  # Scenario C — Flow 2 + pre-approved client: chooser is still shown so
  # the user can confirm, but after confirming the consent screen is
  # skipped and the flow auto-redirects.
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

  # Scenario D — Flow 2 "use a different account": from the chooser the
  # user must be able to opt out of session reuse and sign in as someone
  # else. That should drop them back on the auth service email form.
  @email @session-reuse
  Scenario: Signed-in user can sign in as a different account from the chooser
    Given the user has just signed in via the trusted demo client in this browser
    When the untrusted demo client initiates an OAuth login via flow 2
    Then the account chooser is displayed
    When the user clicks "Use a different account" on the chooser
    Then the browser is on the auth service email form

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
