Feature: Handle availability feedback
  The picker must not claim that every unavailable handle is already taken,
  because policy and validation failures can produce the same unavailable
  response.

  Background:
    Given the ePDS test environment is running

  Scenario: Generic unavailable response uses truthful copy
    When the handle picker preview reports that "alreadyused" is unavailable
    Then the handle picker shows "Not available."
    And the handle picker does not show "Already taken."
