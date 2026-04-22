Feature: Standard PDS behaviors at risk of disruption
  These scenarios test standard AT Protocol PDS functionality that could
  be broken by ePDS modifications. The ePDS injects middleware into the
  Express stack, overrides metadata endpoints, and intercepts the OAuth
  flow — any of these could accidentally break standard operations.

  Background:
    Given the ePDS test environment is running
    And a user account has been auto-created via the ePDS OAuth flow

  @risk-of-disruption
  Scenario: describeServer returns valid PDS metadata
    When a client calls GET /xrpc/com.atproto.server.describeServer
    Then the response includes availableUserDomains and links

  @risk-of-disruption
  Scenario: Full OAuth flow produces a working access token
    When a user authenticates through the ePDS OAuth flow
    And the demo client exchanges the authorization code for tokens
    Then the access token can be used to call authenticated XRPC endpoints

  @risk-of-disruption
  Scenario: PAR endpoint works correctly
    When an OAuth client sends a PAR request to POST /oauth/par
    Then a valid request_uri is returned
    And the request_uri can be used in the authorization flow

  @risk-of-disruption
  Scenario: Repo operations work on ePDS-created accounts
    Given the user has a valid access token
    When the user creates a record via com.atproto.repo.createRecord
    Then the record is created successfully
    When the user reads the record via com.atproto.repo.getRecord
    Then the record is returned
    When the user deletes the record via com.atproto.repo.deleteRecord
    Then the deletion succeeds

  @risk-of-disruption
  Scenario: DID document resolves correctly for ePDS accounts
    Given the user's account was auto-created with a PLC DID
    When the DID document is resolved
    Then it contains a service entry pointing to the PDS
    And the handle can be verified

  @risk-of-disruption
  Scenario: Handle resolution via .well-known works
    Given the user has handle "alice.pds.test"
    When a client fetches https://alice.pds.test/.well-known/atproto-did
    Then the correct DID is returned

  @risk-of-disruption
  Scenario: Repo sync endpoint works
    Given the user has created some records
    When a client calls com.atproto.sync.getRepo for the user's DID
    Then the repo CAR file is returned successfully

  @risk-of-disruption
  Scenario: Password-based createSession is not possible
    When someone calls com.atproto.server.createSession with a guessed password
    Then the request fails with an authentication error
