@pending
Feature: Social login (Google, GitHub)
  ePDS supports Google and GitHub as optional OAuth social login providers.
  When configured, social login buttons appear on the login page. After
  authenticating with the social provider, the user flows through the same
  auth bridge as email OTP and ends up with a valid OAuth session.

  Background:
    Given the ePDS test environment is running
    And the demo OAuth client's metadata is discoverable

  # --- Login page rendering ---

  Scenario: Social login buttons appear when providers are configured
    Given Google and GitHub social login are configured
    When the demo client initiates an OAuth login
    Then the login page displays a "Sign in with Google" button
    And the login page displays a "Sign in with GitHub" button

  Scenario: No social login buttons when providers are not configured
    Given no social login providers are configured
    When the demo client initiates an OAuth login
    Then the login page displays only the email OTP form
    And no social login buttons are visible

  # --- Full social login flow ---

  Scenario: User authenticates via Google
    Given Google social login is configured
    When the user clicks "Sign in with Google" on the login page
    Then the browser is redirected to Google's OAuth consent screen
    When Google returns with an authenticated identity
    Then the browser is redirected back to the demo client
    And the demo client has a valid OAuth access token

  Scenario: User authenticates via GitHub
    Given GitHub social login is configured
    When the user clicks "Sign in with GitHub" on the login page
    Then the browser is redirected to GitHub's OAuth consent screen
    When GitHub returns with an authenticated identity
    Then the browser is redirected back to the demo client
    And the demo client has a valid OAuth access token

  # --- Account linking ---

  Scenario: Same email via social login uses existing PDS account
    Given "alice@example.com" has a PDS account (created via email OTP)
    When "alice@example.com" signs in via Google
    Then the same PDS account is used (not a new one)

  Scenario: Different email via social login creates a separate account
    Given "alice@example.com" has a PDS account
    When the user signs in via Google with "alice@gmail.com"
    Then a new PDS account is created for "alice@gmail.com"
