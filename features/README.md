# ePDS Feature Specifications

Gherkin feature files describing the functionality that ePDS adds on top of
a vanilla AT Protocol PDS.

## Purpose

These `.feature` files serve two roles:

1. **Living documentation** of ePDS-specific behavior.
2. **E2E integration test specifications** intended to be automated against a
   full test environment.

## Test philosophy

These features are designed to **augment, not duplicate** the existing unit and
functional tests in `packages/*/src/__tests__/`.

### Black-box, outside-in testing

Scenarios should test through the **browser and HTTP requests** against a
running ePDS deployment (auth-service, pds-core, demo client, Caddy/TLS),
not by poking at internal databases or calling library functions directly.

- **Preferred**: Navigate to a URL, fill a form, click a button, observe the
  redirect / response / email.
- **Acceptable**: Make HTTP requests directly to API endpoints and assert on
  status codes, headers, and JSON bodies.
- **Avoid**: Directly querying SQLite tables, calling internal functions, or
  asserting on in-memory state. The unit tests already cover those paths.

### When white-box assertions are acceptable

Pragmatically, some behaviors are only observable inside the box:

- Verifying that an email was sent (check the mail trap).
- Confirming a TLS certificate was provisioned (check Caddy logs or a real
  HTTPS request).
- Checking that a cookie was set (inspect HTTP response headers).

These are fine as supporting assertions within an otherwise black-box scenario.

### What NOT to duplicate

The existing unit tests (`packages/*/src/__tests__/`) already cover:

- Database CRUD operations (auth_flow, backup_email, verification_token, etc.)
- Cryptographic primitives (HMAC signing, token hashing, timing-safe equality)
- Input validation (HTML escaping, email masking, OTP generation)
- Login hint resolution (email vs handle vs DID parsing)
- Social provider configuration detection

Do not re-test these at the integration level. Instead, test the **end-to-end
flows** that exercise these components together through the real service
boundaries.

## Test environment

The E2E tests assume an ephemeral test environment with:

- **pds-core** — running with a test PDS database
- **auth-service** — running with a test auth database
- **demo client** — the Next.js demo app (optional, for OAuth flow tests)
- **Caddy** — TLS-terminating reverse proxy with on-demand certificates
- **Mail trap** — captures outbound emails (e.g. MailHog on port 8025)
- **DNS** — configured so that `*.pds.test` resolves to the test environment

## File organization

Each `.feature` file covers one major feature area:

| File                                  | Area                                     |
| ------------------------------------- | ---------------------------------------- |
| `passwordless-authentication.feature` | Email OTP login flows                    |
| `automatic-account-creation.feature`  | Auto-provisioning on first login         |
| `social-login.feature`                | Google / GitHub OAuth login              |
| `consent-screen.feature`              | First-time client consent                |
| `account-recovery.feature`            | Recovery via backup emails               |
| `account-settings.feature`            | Self-service account management          |
| `epds-callback.feature`               | The HMAC-signed auth bridge              |
| `client-branding.feature`             | CSS injection and custom email templates |
| `login-hint-resolution.feature`       | Pre-filling login from hints             |
| `oauth-metadata-override.feature`     | AS metadata rewriting                    |
| `internal-api.feature`                | Service-to-service endpoints             |
| `tls-certificate-management.feature`  | Caddy on-demand TLS and routing          |
| `security.feature`                    | CSRF, rate limiting, headers, monitoring |
| `email-delivery.feature`              | OTP and verification email delivery      |
| `pds-behavior-at-risk.feature`        | Vanilla PDS behaviors at risk            |

## Tags

- `@risk-of-disruption` — Scenarios testing standard PDS functionality that
  could be broken by ePDS modifications. These are regression guards.
