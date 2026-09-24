Feature: Email-domain typo suggestions
  A mistyped email domain prevents a user from receiving their sign-in code.
  Before sending a code, ePDS should suggest an obvious correction while
  still allowing the user to dismiss the suggestion and keep their address.

  Background:
    Given the ePDS test environment is running
    And the demo OAuth client's metadata is discoverable

  @email @email-typo-guard
  Scenario: OAuth login uses the suggested correction
    When the demo client initiates an OAuth login via flow 2
    Then the browser is redirected to the auth service login page
    When the user enters an email at "gmial.com" that should be "gmail.com"
    Then the corrected-address suggestion appears before any code request
    And the form cannot continue until the user resolves the suggestion
    When the user accepts the corrected email suggestion
    Then the corrected address replaces the email and Continue is re-enabled
    When the user continues from the email form
    Then one code request targets the corrected email address
    And the email code form is shown

  @email @email-typo-guard
  Scenario: OAuth login can dismiss the suggestion and keep the original address
    When the demo client initiates an OAuth login via flow 2
    Then the browser is redirected to the auth service login page
    When the user enters an email at "gnail.com" that should be "gmail.com"
    Then the corrected-address suggestion appears before any code request
    And the form cannot continue until the user resolves the suggestion
    When the user dismisses the email correction suggestion
    Then the original address remains and Continue is re-enabled
    When the user continues from the email form
    Then one code request targets the original email address
    And the email code form is shown

  @account-settings @email-typo-guard
  Scenario: Account settings login uses the suggested correction
    When the user opens the account settings email sign-in page
    And the user enters an email at "hotmal.com" that should be "hotmail.com"
    Then the corrected-address suggestion appears before any code request
    And the form cannot continue until the user resolves the suggestion
    When the user accepts the corrected email suggestion
    Then the corrected address replaces the email and Continue is re-enabled
    When the user continues from the email form
    Then one code request targets the corrected email address
    And the email code form is shown
