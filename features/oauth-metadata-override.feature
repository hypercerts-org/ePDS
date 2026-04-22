Feature: OAuth authorization server metadata override
  ePDS overrides the stock PDS's /.well-known/oauth-authorization-server
  metadata to point the authorization_endpoint to the external auth service.
  This is what causes OAuth clients to send users to the ePDS auth service
  rather than the vanilla PDS login form.

  Background:
    Given the ePDS test environment is running

  @risk-of-disruption
  Scenario: Authorization endpoint points to external auth service
    When GET /.well-known/oauth-authorization-server is fetched from the PDS
    Then the response JSON includes authorization_endpoint pointing to the auth service
    And all other standard OAuth metadata fields are present (issuer, token_endpoint, etc.)
    And the response has Cache-Control: public, max-age=300

  @risk-of-disruption
  Scenario: Standard OAuth fields are preserved
    When GET /.well-known/oauth-authorization-server is fetched
    Then the response includes token_endpoint pointing to the PDS's /oauth/token
    And the response includes pushed_authorization_request_endpoint pointing to /oauth/par
    And response_types_supported, grant_types_supported, and dpop_signing_alg_values_supported are present

  @risk-of-disruption
  Scenario: OAuth clients discover and use the auth service automatically
    Given a standard AT Protocol OAuth client
    When the client discovers the authorization server via /.well-known/oauth-authorization-server
    And the client initiates a PAR request
    And the client redirects the user to the authorization_endpoint
    Then the user arrives at the ePDS auth service (not the stock PDS login)
