@fake-google
Feature: Google sign-in
  A client that lists "google" in its epds_social_providers metadata gets a
  "Sign in with Google" button on the login page. After Google, the user
  flows through the same auth bridge as email OTP and lands on the PDS
  account that owns the address, but only when Google can vouch for it.

  Google itself is faked: the browser's trip to accounts.google.com is
  intercepted and sent straight back to the auth service with the identity
  the scenario chooses, and the auth service (EPDS_TEST_FAKE_GOOGLE=1)
  answers its token request with an ID token for that identity.

  Background:
    Given the ePDS test environment is running
    And the demo OAuth client's metadata is discoverable

  Scenario: An account created with Google is the same account for email sign-in
    When a new user signs in with Google using a Gmail address
    And the user picks a handle
    Then the browser is redirected back to the demo client
    When the user later signs in with a code sent to that address
    Then the demo client is signed in to the same PDS account

  Scenario: User can sign in with an email code after Google sign-in is rejected
    Given a returning user has a PDS account
    And Google reports a verified email for the test user
    But Google's ID token has the "hd" claim "other.example"
    When the user signs in with Google
    Then the browser returns to the login page
    And the login page asks the user to sign in with an email code instead
    And no authenticated session is created
    When the user signs in with a code sent to that address
    Then the demo client is signed in to the same PDS account

  Scenario: Cancelling at Google returns to the login page
    When the user signs in with Google but cancels at Google
    Then the browser returns to the login page
    And the login page says that sign-in was cancelled
    And no authenticated session is created
