@pending
Feature: Account recovery via backup emails
  Users can register backup email addresses. If they lose access to their
  primary email, they can use a backup email to recover their account via
  the same OTP flow.

  Background:
    Given the ePDS test environment is running
    And "alice@example.com" has a PDS account

  # --- Backup email setup (via account settings) ---

  @email
  Scenario: User adds and verifies a backup email
    Given "alice@example.com" is logged into account settings
    When the user adds "backup@example.com" as a backup email
    Then a verification email is sent to "backup@example.com"
    When the user clicks the verification link in that email
    Then the backup email is marked as verified in the settings page

  # --- Recovery flow ---

  @email
  Scenario: User recovers account via verified backup email
    Given "backup@example.com" is a verified backup email for alice's account
    And an OAuth client has initiated a login flow
    When the user navigates to the recovery page
    And enters "backup@example.com"
    Then an OTP code is sent to "backup@example.com"
    When the user enters the correct OTP code
    Then the browser is redirected back to the OAuth client with a valid session
    And the session is for alice's PDS account

  @email
  Scenario: Recovery with non-existent email shows same UI (anti-enumeration)
    Given an OAuth client has initiated a login flow
    When the user navigates to the recovery page
    And enters "nonexistent@example.com"
    Then the OTP form is displayed (same as if the email was found)
    But no email arrives in the mail trap

  # --- Backup email management ---

  Scenario: User removes a backup email
    Given "alice@example.com" has a verified backup email "old@example.com"
    When the user removes "old@example.com" from account settings
    Then "old@example.com" no longer appears in the backup emails list
    And recovery via "old@example.com" no longer works
