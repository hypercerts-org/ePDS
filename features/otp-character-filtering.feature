Feature: OTP character filtering
  The segmented sign-in grid and the recovery form must apply the configured
  OTP character policy while the user types or pastes. The account-login form
  applies the same policy, but has no preview route to drive it from a
  browser, so it is not covered here.

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

  Scenario Outline: Sign-in OTP grid applies the configured character policy
    When the sign-in OTP preview uses the "<charset>" character policy
    And the user types "<typed>" into the first sign-in OTP box
    Then the sign-in OTP boxes spell "<expected>"

    Examples:
      | charset      | typed | expected |
      | numeric      | a     |          |
      | numeric      | 7     | 7        |
      | alphanumeric | -     |          |
      | alphanumeric | b     | B        |

  # The grid's paste handler both filters and distributes across boxes. A
  # unit test asserting on rendered HTML can observe neither, so this is the
  # only coverage that would catch a regression in the spreading.
  Scenario Outline: Pasting into the sign-in OTP grid spreads the kept characters
    When the sign-in OTP preview uses the "<charset>" character policy
    And the user pastes "<pasted>" into the first sign-in OTP box
    Then the sign-in OTP boxes spell "<expected>"

    Examples:
      | charset      | pasted | expected |
      | numeric      | 1-2 3a | 123      |
      | alphanumeric | 1-b 3! | 1B3      |
