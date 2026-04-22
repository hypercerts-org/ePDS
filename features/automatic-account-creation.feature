Feature: Automatic account creation on first login
  When a user authenticates for the first time (no existing PDS account
  for their email), ePDS automatically creates a PDS account as a
  side-effect of the OAuth flow — the user does not visit a separate
  sign-up form, they just pick a handle during the login flow and the
  account is provisioned for them. No password is ever created.

  Handle generation and crypto primitives are unit-tested. These scenarios
  test the observable end-to-end behavior.

  Background:
    Given the ePDS test environment is running
    And the demo OAuth client's metadata is discoverable

  Scenario: First-time user gets an auto-created PDS account
    Given a new user has registered via the demo client
    Then the browser is redirected back to the demo client
    And the demo client has a valid OAuth access token
    And the welcome page shows the user's DID and handle
    And the handle resolves to the correct DID via the PDS

  # @docker-only: handle subdomain HTTPS requires Caddy on-demand TLS, not available on Railway
  @docker-only
  Scenario: Auto-created handle is a random subdomain
    Given a new user has registered via the demo client
    Then the handle is a short alphanumeric subdomain of the PDS domain
    And the handle resolves to the correct DID via the PDS
    And the handle subdomain resolves via HTTPS

  @manual
  Scenario: Auto-created account has a working AT Protocol repo
    Given a new user has registered via the demo client
    When the user creates a record via com.atproto.repo.createRecord
    Then the record is created successfully
    And it can be retrieved via com.atproto.repo.getRecord

  Scenario: Password-based login does not work for auto-created accounts
    Given a new user has registered via the demo client
    When someone attempts createSession with any password
    Then the createSession request fails with an auth error
    # Password-based login is the only alternative — rejected above
