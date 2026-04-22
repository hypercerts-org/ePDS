Feature: Security measures
  ePDS implements multiple layers of security. Unit tests cover the
  primitives (timing-safe comparison, HTML escaping, email masking).
  These E2E scenarios test the security behaviors observable via HTTP.

  Background:
    Given the ePDS test environment is running

  # --- CSRF protection ---

  @pending
  Scenario: Forms include CSRF protection
    When the login page is loaded
    Then the response sets a CSRF cookie
    And the HTML form contains a hidden CSRF token field

  @pending
  Scenario: POST without CSRF token is rejected
    When a POST request is sent to the OTP verification endpoint without a CSRF token
    Then the response status is 403

  # --- Rate limiting ---

  @pending
  Scenario: Excessive requests from one IP are rate-limited
    When more than 60 requests are sent from the same IP within one minute
    Then subsequent requests receive a 429 Too Many Requests response
    And the response includes a Retry-After header

  @pending
  Scenario: Excessive OTP requests for one email are throttled
    When OTP codes are requested for the same email many times in quick succession
    Then the rate limiter throttles further OTP sends for that email

  # --- Security headers ---

  @pending
  Scenario: Auth service responses include security headers
    When any page is loaded from the auth service via Caddy
    Then the response includes:
      | header                    | value            |
      | Strict-Transport-Security | max-age=31536000 |
      | X-Frame-Options           | DENY             |
      | X-Content-Type-Options    | nosniff          |
      | Referrer-Policy           | no-referrer      |

  @pending
  Scenario: Content-Security-Policy restricts inline content
    When the login page is loaded
    Then the Content-Security-Policy header is present
    And it does not allow unsafe-inline scripts

  # --- Monitoring ---

  @pending
  Scenario: Health check endpoints are available
    When GET /health is called on the auth service
    Then it returns status 200 with { "status": "ok" }
    When GET /health is called on the PDS core
    Then it returns status 200 with { "status": "ok" }

  @pending
  Scenario: Metrics endpoint requires authentication
    When GET /metrics is called on the auth service without credentials
    Then the response status is 401
    When GET /metrics is called with valid Basic auth credentials
    Then the response includes uptime and memory usage metrics

  # --- Same-site deployment topology (sec-fetch-site) ---
  #
  # Background: ePDS splits the OAuth authorization server onto a subdomain
  # (e.g. auth.epds1.certified.app) while the PDS stays on the parent domain
  # (epds1.certified.app). In stock atproto, the PDS serves its own login UI,
  # so this split never occurs.
  #
  # After OTP verification, the auth service redirects the browser through a
  # 303 chain: auth-service/auth/complete → pds-core/oauth/epds-callback →
  # pds-core/oauth/authorize. Browsers compute sec-fetch-site from the full
  # redirect chain — since the chain crosses from the auth subdomain to the
  # PDS, the browser sends sec-fetch-site: same-site on the final request.
  #
  # The upstream @atproto/oauth-provider validates sec-fetch-site on
  # GET /oauth/authorize and allows same-origin, cross-site, and none — but
  # rejects same-site. This is reasonable for stock atproto (where same-site
  # would be unexpected) but breaks ePDS's subdomain architecture.
  #
  # Why CI doesn't catch this naturally: Railway PR preview environments use
  # *.up.railway.app domains. Because up.railway.app is on the Public Suffix
  # List (https://publicsuffix.org), each Railway subdomain is its own "site",
  # making cross-service requests cross-site rather than same-site. The
  # atproto validation accepts cross-site, so the bug is invisible on Railway.
  #
  # This scenario catches it by sending sec-fetch-site: same-site directly
  # via HTTP, simulating what a real browser sends on *.certified.app.

  Scenario: PDS /oauth/authorize accepts sec-fetch-site: same-site
    When a GET request is sent to the PDS /oauth/authorize with sec-fetch-site "same-site"
    Then the response is not a 400 error about forbidden sec-fetch-site header

  # --- Email privacy ---

  @pending
  Scenario: Displayed emails are masked on error/status pages
    When an email address is displayed on a server-rendered page
    Then it appears masked (e.g. "j***n@example.com")
    And the full email is not visible in the page source
