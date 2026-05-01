Feature: Account recovery via backup emails
  Users can register backup email addresses. If they lose access to their
  primary email, they can use a backup email to recover their account via
  the same OTP flow.

  Test accounts and backup-email addresses are created dynamically per
  scenario so multiple runs against the same shared environment do not
  collide.

  Background:
    Given the ePDS test environment is running
    And a returning user has a PDS account

  # --- Backup email setup (via account settings) ---

  Scenario: User adds and verifies a backup email
    Given the user is logged into account settings
    When the user adds a unique backup email
    Then a verification email arrives in the mail trap for the backup email
    And the email contains a verification link
    When the user clicks the verification link in that email
    Then the backup email is marked as verified on the account settings page

  # --- Recovery flow ---

  Scenario: User recovers account via verified backup email
    Given the test user has a verified backup email
    And the demo client initiates OAuth with the test email as login_hint
    When the user navigates to the recovery page
    And the user enters the backup email on the recovery page
    Then an OTP email arrives in the mail trap for the backup email
    When the user enters the recovery OTP
    Then the demo client's welcome page confirms the user is signed in

  Scenario: Recovery with non-existent email shows same UI (anti-enumeration)
    Given the demo client initiates OAuth with the test email as login_hint
    When the user navigates to the recovery page
    And the user enters a random non-existent email on the recovery page
    Then the recovery OTP form is displayed
    And no email arrives for that non-existent address

  # --- Backup email management ---

  Scenario: User removes a backup email
    Given the test user has a verified backup email
    When the user removes the backup email from account settings
    Then the backup email no longer appears on the account settings page
    And recovery via the removed backup email no longer works
