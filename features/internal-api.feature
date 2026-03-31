Feature: Internal service-to-service API
  ePDS splits the PDS into two services that communicate via internal
  HTTP endpoints protected by a shared secret. The client-side calling
  logic is unit-tested. These E2E scenarios test the server-side endpoints
  directly.

  Background:
    Given the ePDS test environment is running
    And the internal API secret is configured

  Scenario: Account lookup by email returns the account's DID
    Given a new user has registered via the demo client
    When the internal API is queried for the account by email
    Then the response contains the account's DID

  Scenario: Account lookup by email returns null for an unknown email
    When the internal API is queried for account-by-email with an unknown address
    Then the response status is 200
    And the response body has a null DID

  Scenario: Handle resolution returns the account's email
    Given a new user has registered via the demo client
    When the internal API is queried for the account by handle
    Then the response contains the account's email

  Scenario: Check-handle returns true for an existing handle
    Given a new user has registered via the demo client
    When the internal API is queried to check if the handle exists
    Then the response indicates the handle exists

  # @manual: requires a real PKCE PAR request — implement when PAR submission
  # steps exist (also needed for login-hint-resolution.feature)
  @manual
  Scenario: PAR login hint retrieval
    Given a new user has registered via the demo client
    When the demo client submits a PAR request with the user's handle as login_hint
    And the internal API is queried for the PAR login hint
    Then the response contains the user's handle as the login hint

  Scenario: Missing internal secret returns 401
    When an internal endpoint is called without the secret header
    Then the response status is 401
    And the response body contains an auth error

  Scenario: Wrong internal secret returns 401
    When an internal endpoint is called with an incorrect secret
    Then the response status is 401
    And the response body contains an auth error

  # check-handle returns 403 (not 401) on bad secret — server-side inconsistency
  Scenario: Wrong internal secret on check-handle returns 403
    When the check-handle endpoint is called with an incorrect secret
    Then the response status is 403
    And the response body contains an auth error
