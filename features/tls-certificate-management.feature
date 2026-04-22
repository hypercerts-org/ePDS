@pending
Feature: TLS certificate management via Caddy on-demand TLS
  Caddy reverse proxy provisions TLS certificates on-demand for the PDS
  hostname, auth subdomain, and all user handle subdomains. The /tls-check
  endpoint validates which domains should get certificates.

  Background:
    Given the ePDS test environment is running with Caddy

  Scenario: PDS hostname is accessible via HTTPS
    When a client connects to https://pds.test
    Then the TLS handshake succeeds
    And the response is from pds-core

  Scenario: Auth subdomain is accessible via HTTPS
    When a client connects to https://auth.pds.test
    Then the TLS handshake succeeds
    And the response is from the auth service

  Scenario: User handle subdomain gets a TLS certificate
    Given a PDS account exists with handle "alice.pds.test"
    When a client connects to https://alice.pds.test
    Then the TLS handshake succeeds
    And /.well-known/atproto-did returns alice's DID

  Scenario: Unknown subdomain is rejected by tls-check
    When GET /tls-check?domain=nonexistent.pds.test is called on pds-core
    Then the response is non-200 (domain not recognized)

  Scenario: Caddy routes auth subdomain to auth service
    When a request arrives at https://auth.pds.test/health
    Then the response is { "status": "ok", "service": "auth" }

  Scenario: Caddy routes PDS hostname to pds-core
    When a request arrives at https://pds.test/health
    Then the response is { "status": "ok", "service": "epds" }

  Scenario: Security headers are set by Caddy
    When any HTTPS response passes through Caddy
    Then the response includes Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers
