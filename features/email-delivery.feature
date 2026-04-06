@email
Feature: Email delivery
  ePDS sends OTP codes and verification links via email. The test
  environment uses a mail trap (e.g. MailHog) to capture emails.

  Background:
    Given the ePDS test environment is running
    And a mail trap is capturing outbound emails

  Scenario: New user receives a welcome OTP email
    Given no PDS account exists for "alice@example.com"
    When the user requests an OTP for "alice@example.com"
    Then an email arrives in the mail trap addressed to "alice@example.com"
    And the email subject contains "Welcome"
    And the email body contains a numeric OTP code

  Scenario: Returning user receives a sign-in OTP email
    Given "bob@example.com" has an existing PDS account
    When the user requests an OTP for "bob@example.com"
    Then an email arrives in the mail trap addressed to "bob@example.com"
    And the email subject contains "Sign-in"

  Scenario: Backup email verification link is delivered
    Given "alice@example.com" is logged into account settings
    When the user adds "backup@example.com" as a backup email
    Then a verification email arrives in the mail trap for "backup@example.com"
    And the email contains a verification link
