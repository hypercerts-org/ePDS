Feature: Account settings dashboard
  ePDS provides a self-service web dashboard at /account where authenticated
  users can manage their account: view their identity, change handle, manage
  backup emails, view/revoke sessions, and delete their account.

Background:
  Given the ePDS test environment is running

  # --- Authentication for settings ---

Scenario: Unauthenticated user is redirected to login
  When a user navigates to /account without a session
  Then the browser is redirected to /account/login

@email
Scenario: Account settings login uses standalone OTP
  Given a returning user has a PDS account
  When the user navigates to /account/login
  Then a login form is displayed (separate from the OAuth flow)
  When the user enters their email and verifies the OTP
  Then the browser is redirected to /account
  And the account settings dashboard is displayed

  # --- Account information ---

Scenario: User views their account information
  Given the user is logged into account settings
  When they view the /account page
  Then the page displays their DID
  And the page displays their primary email
  # And the page displays their current handle

  # --- Handle management ---

# Known gap: handle update on /account is not implemented yet.
@pending
Scenario: User changes their handle
  Given the user is logged into account settings
  And their current handle is a random subdomain of the PDS domain
  When the user submits a valid new handle
  Then the user's handle is updated
  And the settings page reflects the updated handle
  And the updated handle resolves to the user's DID via the PDS

  # --- Session management ---

Scenario: User views and revokes a session
  Given the user is logged into account settings
  And the user has at least one other active session
  When the user views the sessions section
  Then active sessions are listed
  When the user revokes another session
  Then that session is no longer listed

  # --- Account deletion ---

Scenario: User deletes their account
  Given the user is logged into account settings
  When the user initiates account deletion and confirms
  Then the account deleted confirmation page is shown
  And visiting /account redirects to /account/login
  And the user's PDS account no longer exists
