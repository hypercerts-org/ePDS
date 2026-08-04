Feature: OTP character filtering
  Every OTP form — the segmented sign-in grid, account-login, and recovery —
  must apply the configured OTP character policy while the user types.

  Background:
    Given the ePDS test environment is running

  Scenario Outline: Recovery OTP input applies the configured character policy
    When the recovery OTP preview uses the "<charset>" character policy
    And the user types "<typed>" into the recovery OTP input
    Then the recovery OTP input contains "<expected>"

    Examples:
      | charset      | typed | expected |
      | numeric      | a1-!  | 1        |
      | alphanumeric | a1-!  | A1       |
