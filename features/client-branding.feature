Feature: Client branding — CSS injection and custom email templates
  ePDS allows trusted OAuth clients to customize the appearance of login
  and consent pages via CSS injection, and to provide custom email templates
  for OTP emails. This enables white-label experiences for approved apps.

  Background:
    Given the ePDS test environment is running

  # --- CSS injection ---

  Scenario: Trusted client's CSS is applied to the login page
    Given the demo client is listed in PDS_OAUTH_TRUSTED_CLIENTS
    And the demo client's metadata includes a "branding.css" URL
    When the demo client initiates an OAuth login
    Then the login page includes the client's custom CSS in a <style> tag
    And the Content-Security-Policy header includes the CSS hash in style-src

  Scenario: Trusted client's CSS is applied to the consent page
    Given the demo client is listed in PDS_OAUTH_TRUSTED_CLIENTS
    When an existing user reaches the consent screen via the demo client
    Then the consent page includes the client's custom CSS

  Scenario: Untrusted client does not get CSS injection
    Given "https://untrusted.example.com" is NOT in PDS_OAUTH_TRUSTED_CLIENTS
    When a login flow is initiated by the untrusted client
    Then the login page uses the default styling (no injected CSS)

  # --- Custom email templates ---

  @email
  Scenario: Client-branded OTP email uses custom template
    Given the demo client's metadata includes an "email_template_uri"
    And the template contains "{{code}}" and "{{app_name}}" placeholders
    When the user requests an OTP via the demo client
    Then the OTP email in the mail trap uses the custom template
    And the OTP code and app name are rendered into the template

  @email
  Scenario: Custom email template with conditional new-user section
    Given the demo client provides a template with "{{#is_new_user}}" section
    When a new user requests an OTP via the demo client
    Then the email includes the new-user section content
    When a returning user requests an OTP via the demo client
    Then the email excludes the new-user section content

  @email
  Scenario: Invalid email template falls back to default
    Given the demo client's email_template_uri points to a template without "{{code}}"
    When the user requests an OTP
    Then the default PDS email template is used (invalid template rejected)

  @email
  Scenario: Custom email subject line
    Given the demo client's metadata includes email_subject_template "Your {{app_name}} code"
    When the user requests an OTP
    Then the OTP email subject matches the custom template

  @email
  Scenario: Non-HTTPS email template URI is rejected
    Given the demo client's email_template_uri uses HTTP (not HTTPS)
    When the user requests an OTP
    Then the default email template is used (HTTP rejected)

  @email
  Scenario: OTP email uses default template when no client context
    Given the user is logging into account settings (no OAuth client context)
    When the user requests an OTP
    Then the default PDS email template is used
