Feature: Client branding — CSS injection and custom email templates
  ePDS allows trusted OAuth clients to customize the appearance of login
  and consent pages via CSS injection, and to provide custom email templates
  for OTP emails. This enables white-label experiences for approved apps.

  Background:
    Given the ePDS test environment is running
    And the trusted demo OAuth client's metadata is discoverable

  # --- CSS injection ---

  Scenario: Trusted client's CSS is applied to the login page
    When the demo client initiates an OAuth login
    Then the login page HTML contains the trusted client's custom CSS

  @untrusted-client
  Scenario: Trusted and untrusted demo clients render visibly differently
    When the trusted demo client initiates an OAuth login
    And the login page body background color is captured as "trusted"
    And the browser session is reset
    And the untrusted demo client initiates an OAuth login
    And the login page body background color is captured as "untrusted"
    Then the captured "trusted" and "untrusted" background colors differ

  @untrusted-client
  Scenario: Untrusted client does not get CSS injection
    When the untrusted demo client initiates an OAuth login
    Then the login page HTML does not contain the trusted client's custom CSS
    And the login page body uses the default background color

  @manual
  Scenario: Trusted client's CSS is applied to the upstream OAuth consent page
    # Exercises the pds-core CSS-injection middleware on /oauth/authorize.
    # Requires a returning user re-authorizing through the upstream consent UI
    # (trusted clients skip consent on initial sign-up, so this path only
    # fires on reauth). Manual until we have a reauth fixture.
    Given the demo client is listed in PDS_OAUTH_TRUSTED_CLIENTS
    When an existing user reaches the upstream consent screen via the demo client
    Then the consent page HTML contains the trusted client's custom CSS
    And the Content-Security-Policy style-src directive includes the CSS SHA-256 hash

  # --- Custom email templates ---

  @email @not-implemented
  Scenario: Client-branded OTP email uses custom template
    Given the demo client's metadata includes an "email_template_uri"
    And the template contains "{{code}}" and "{{app_name}}" placeholders
    When the user requests an OTP via the demo client
    Then the OTP email in the mail trap uses the custom template
    And the OTP code and app name are rendered into the template

  @email @not-implemented
  Scenario: Custom email template with conditional new-user section
    Given the demo client provides a template with "{{#is_new_user}}" section
    When a new user requests an OTP via the demo client
    Then the email includes the new-user section content
    When a returning user requests an OTP via the demo client
    Then the email excludes the new-user section content

  @email @not-implemented
  Scenario: Invalid email template falls back to default
    Given the demo client's email_template_uri points to a template without "{{code}}"
    When the user requests an OTP
    Then the default PDS email template is used (invalid template rejected)

  @email @not-implemented
  Scenario: Custom email subject line
    Given the demo client's metadata includes email_subject_template "Your {{app_name}} code"
    When the user requests an OTP
    Then the OTP email subject matches the custom template

  @email @not-implemented
  Scenario: Non-HTTPS email template URI is rejected
    Given the demo client's email_template_uri uses HTTP (not HTTPS)
    When the user requests an OTP
    Then the default email template is used (HTTP rejected)

  @email @not-implemented
  Scenario: OTP email uses default template when no client context
    Given the user is logging into account settings (no OAuth client context)
    When the user requests an OTP
    Then the default PDS email template is used
