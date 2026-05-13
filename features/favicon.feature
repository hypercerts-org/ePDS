Feature: Favicon on rendered pages
  ePDS ships a Certified favicon (light + dark SVG variants) on every
  HTML page it serves or rewrites. This includes auth-service pages
  (login, recovery, choose-handle, error) as well as upstream
  oauth-provider pages (the /account* SPA, the /oauth authorize
  flow) that pds-core rewrites on the response path to
  prepend favicon <link> tags. The SVG assets live under /static on
  each service, plus a /favicon.ico alias covers non-HTML responses
  where browsers auto-fetch the legacy path.

  Background:
    Given the ePDS test environment is running

  # --- Auth-service-rendered pages -----------------------------------

  Scenario: Auth-service login page references both favicon variants
    When the auth-service login page is fetched directly
    Then the HTML contains both the light and dark favicon links

  # --- Pds-core upstream-rewritten pages -----------------------------

  Scenario: Upstream /account/sign-in gets favicon injected
    When the pds-core "/account/sign-in" page is fetched directly
    Then the HTML contains both the light and dark favicon links

  Scenario: Upstream /oauth/authorize gets favicon injected
    When the pds-core "/oauth/authorize" page is fetched directly
    Then the HTML contains both the light and dark favicon links

  # --- Static assets + /favicon.ico alias ----------------------------

  Scenario Outline: Favicon SVG assets are served on both services
    When "<path>" is fetched from the "<service>" service
    Then the response status is 200
    And the response Content-Type starts with "image/svg+xml"

    Examples:
      | service       | path                      |
      | pds-core      | /static/favicon.svg       |
      | pds-core      | /static/favicon-dark.svg  |
      | auth-service  | /static/favicon.svg       |
      | auth-service  | /static/favicon-dark.svg  |

  Scenario Outline: /favicon.ico alias serves an SVG on both services
    When "/favicon.ico" is fetched from the "<service>" service
    Then the response status is 200
    And the response Content-Type starts with "image/svg+xml"

    Examples:
      | service       |
      | pds-core      |
      | auth-service  |
