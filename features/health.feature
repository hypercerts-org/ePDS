Feature: Health endpoints
  Both ePDS services expose /health with the ePDS version. The PDS also
  exposes /xrpc/_health which reports the upstream @atproto/pds version.

  Background:
    Given the ePDS test environment is running

  Scenario: PDS /health reports the ePDS version
    When the PDS /health endpoint is queried
    Then the response contains an ePDS version string

  Scenario: Auth service /health reports the ePDS version
    When the auth service /health endpoint is queried
    Then the response contains an ePDS version string

  Scenario: /xrpc/_health reports the upstream PDS version
    When the PDS /xrpc/_health endpoint is queried
    Then the response contains an upstream PDS version string
