# E2E Test Framework — Implementation Plan

> HYPER-184 · Playwright + cucumber-js · Docker-local + Railway previews

## Overview

This plan delivers an end-to-end BDD test framework for the ePDS, automating
the 86 Gherkin scenarios across the 15 existing `.feature` files. The same test
suite runs against two environments:

1. **Docker-local** — ephemeral Docker Compose stack with local DNS, for CI and
   local development
2. **Railway preview** — ephemeral Railway deployment per PR with CloudFlare
   DNS, for production-like validation

Both environments also support **manual testing** via browser access to the
running services.

## Decisions

| Decision              | Choice                       | Rationale                                                                                      |
| --------------------- | ---------------------------- | ---------------------------------------------------------------------------------------------- |
| Browser automation    | Playwright                   | Deterministic, fast, free, no LLM costs. Stagehand can layer on later (Playwright-compatible). |
| BDD framework         | cucumber-js                  | Gherkin step definitions, good Playwright integration, widely used.                            |
| Social login E2E      | Deferred (`@manual`)         | Requires mocking Google/GitHub OAuth; unit tests cover the integration code for now.           |
| Local DNS (Docker)    | dnsmasq in a sidecar         | Resolves `*.pds.test` to container IPs. Simple, no host-level config needed.                   |
| Preview DNS (Railway) | CloudFlare DNS API           | Ephemeral wildcard DNS records for preview environments. See safety guardrails below.          |
| TLS in Docker         | Caddy internal CA            | Self-signed certs for `*.pds.test`; Playwright accepts via `--ignore-https-errors`.            |
| Email trap            | MailHog (already in compose) | HTTP API on port 8025 for OTP retrieval in tests and manual inspection.                        |

## Architecture

```
features/                              # Already exists (15 .feature files)
features/IMPLEMENTATION-PLAN.md        # This file
features/README.md                     # Already exists
features/support/
  world.ts                             # Cucumber World: browser, page, env config, helpers
  hooks.ts                             # Before/After: browser lifecycle, DB seeding, cleanup
  env.ts                               # Test environment config (URLs, secrets, target)
features/step-definitions/
  common.steps.ts                      # Shared: "Given the ePDS test environment is running"
  auth.steps.ts                        # OTP login, consent, account creation flows
  email.steps.ts                       # MailHog API assertions (OTP retrieval, subjects, etc.)
  api.steps.ts                         # Internal API + HTTP-only scenarios
  account.steps.ts                     # Account settings, recovery, backup email
  branding.steps.ts                    # CSS injection, custom email templates
  security.steps.ts                    # CSRF, rate limiting, security headers
  tls.steps.ts                         # TLS/Caddy routing assertions
  pds.steps.ts                         # Vanilla PDS behavior (atproto operations)
e2e/
  docker-compose.test.yml             # Compose override for test environment
  Caddyfile.test                       # Caddy config using internal CA for *.pds.test
  dnsmasq.conf                         # DNS config: *.pds.test -> container
  wait-for-healthy.sh                  # Health-check poller (waits for all services)
  seed.ts                              # Test data seeding script (creates accounts, etc.)
  teardown.ts                          # Cleanup script (reset DBs between scenarios)
  cloudflare-dns.sh                    # CloudFlare DNS record management for Railway previews
cucumber.mjs                           # Cucumber runner configuration
playwright.config.ts                   # Playwright browser/context defaults
```

## Phases

### Phase 1: Docker-local test environment

**Goal:** `docker compose -f docker-compose.yml -f e2e/docker-compose.test.yml up`
boots a fully functional ePDS with local DNS, self-signed TLS, and MailHog —
usable for both automated E2E tests and manual browser testing.

#### 1a. DNS sidecar

Add a `dns` service to `docker-compose.test.yml` using `dnsmasq` (or
`coredns/coredns`) that resolves:

- `pds.test` -> Caddy container
- `auth.pds.test` -> Caddy container
- `*.pds.test` -> Caddy container (handle subdomains)
- `demo.test` -> demo container (optional convenience alias)

All other services use this DNS container via `dns:` directive in the compose
override.

#### 1b. Caddy internal CA

Create `e2e/Caddyfile.test` that replaces ACME with Caddy's built-in internal
issuer:

```caddyfile
{
    local_certs              # Use Caddy's internal CA (self-signed)
    on_demand_tls {
        ask http://core:3000/tls-check
    }
}
```

This gives us real TLS for `*.pds.test` without needing public DNS or ACME.
Browsers see a self-signed cert — fine for Playwright
(`ignoreHTTPSErrors: true`) and acceptable for manual testing (click through
the warning once, or install Caddy's root CA).

#### 1c. Compose test overlay

`e2e/docker-compose.test.yml` overrides:

- **Adds** `dns` service (dnsmasq)
- **Promotes** `mailhog` from `profiles: [dev]` to always-on
- **Overrides** Caddy to mount `Caddyfile.test` instead of production Caddyfile
- **Sets** `PDS_HOSTNAME=pds.test` and related env vars
- **Sets** DNS resolution for all services to use the `dns` container
- **Exposes** MailHog web UI (8025) for manual email inspection
- **Uses** named test volumes (separate from dev volumes) to avoid data
  collision

#### 1d. Health-check wait script

`e2e/wait-for-healthy.sh` polls the health endpoints of core, auth, and demo
until all return 200, with a configurable timeout (default 60s). Used by both
CI and the `pnpm test:e2e` script.

#### 1e. Manual testing support (Docker)

When the test environment is running, a developer can:

- Open `https://pds.test` in a browser (after accepting the self-signed cert,
  or after installing Caddy's root CA locally)
- Open `https://auth.pds.test` for the auth service
- Open `http://localhost:3002` (or `http://demo.test:3002`) for the demo app
- Open `http://localhost:8025` for the MailHog web UI to see captured emails
- Run the full Gherkin suite, a single feature, or a single scenario

This requires the DNS sidecar's resolver to be reachable from the host. Options:

1. Add entries to `/etc/hosts` (simplest, manual)
2. Use the DNS container as the system resolver temporarily
3. Provide a `pnpm test:e2e:setup` script that prints instructions or offers to
   configure this automatically

### Phase 2: Test framework wiring

**Goal:** `pnpm test:e2e` runs cucumber-js with Playwright against the running
test environment.

#### 2a. Dependencies

Add to root `devDependencies`:

```
@cucumber/cucumber
playwright
ts-node
```

Run `npx playwright install --with-deps chromium` in CI setup.

#### 2b. Cucumber configuration (`cucumber.mjs`)

```js
export default {
  paths: ['features/**/*.feature'],
  require: ['features/step-definitions/**/*.ts', 'features/support/**/*.ts'],
  requireModule: ['ts-node/register'],
  format: ['progress-bar', 'html:reports/e2e.html'],
  publishQuiet: true,
  tags: 'not @manual',
}
```

#### 2c. Playwright configuration (`playwright.config.ts`)

Minimal config — Playwright is used as a library (not as a test runner), so
this is primarily for `playwright install` and browser defaults:

```ts
export default {
  use: {
    ignoreHTTPSErrors: true,
    headless: true, // override to false for manual observation
    viewport: { width: 1280, height: 720 },
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
}
```

#### 2d. Cucumber World (`features/support/world.ts`)

The World class holds:

- `browser`: Playwright `Browser` instance (shared across scenarios via hooks)
- `page`: Playwright `Page` instance (fresh per scenario)
- `env`: Test environment config (base URLs, secrets, MailHog API URL)
- Helper methods: `login(email)`, `getOtpFromMailhog(email)`,
  `makeInternalRequest(path, headers)`, etc.

#### 2e. Environment config (`features/support/env.ts`)

Reads from environment variables with sensible defaults for Docker-local:

```ts
export const testEnv = {
  target: process.env.E2E_TARGET || 'docker', // 'docker' | 'railway'
  pdsUrl: process.env.E2E_PDS_URL || 'https://pds.test',
  authUrl: process.env.E2E_AUTH_URL || 'https://auth.pds.test',
  demoUrl: process.env.E2E_DEMO_URL || 'http://localhost:3002',
  mailhogUrl: process.env.E2E_MAILHOG_URL || 'http://localhost:8025',
  internalSecret: process.env.EPDS_INTERNAL_SECRET || 'test-secret',
  callbackSecret: process.env.EPDS_CALLBACK_SECRET || 'test-callback-secret',
  headless: process.env.E2E_HEADLESS !== 'false', // default headless
}
```

For Railway previews, these env vars are set by the CI job based on the
preview deployment URLs.

#### 2f. Hooks (`features/support/hooks.ts`)

- **BeforeAll**: Launch Playwright browser
- **Before (each scenario)**: Create new browser context + page; optionally
  seed test data
- **After (each scenario)**: Capture screenshot on failure; close page/context;
  clean up test data (purge MailHog, reset test accounts)
- **AfterAll**: Close browser

#### 2g. npm scripts

```json
{
  "test:e2e": "cucumber-js",
  "test:e2e:docker:up": "docker compose -f docker-compose.yml -f e2e/docker-compose.test.yml up -d && ./e2e/wait-for-healthy.sh",
  "test:e2e:docker:down": "docker compose -f docker-compose.yml -f e2e/docker-compose.test.yml down -v",
  "test:e2e:ci": "pnpm test:e2e:docker:up && pnpm test:e2e; EXIT=$?; pnpm test:e2e:docker:down; exit $EXIT"
}
```

### Phase 3: Step definitions (incremental)

Implement step definitions one feature file at a time, ordered by difficulty
(easiest first). Each batch should be a separate PR that adds working,
green scenarios.

#### Batch 1 — HTTP-only scenarios (no browser needed)

| Feature file                      | Scenarios | Notes                                                 |
| --------------------------------- | --------- | ----------------------------------------------------- |
| `internal-api.feature`            | 6         | Pure HTTP with `x-internal-secret` header             |
| `oauth-metadata-override.feature` | ~4        | HTTP GET + JSON assertions on `.well-known` endpoints |
| `email-delivery.feature`          | ~4        | Trigger OTP via HTTP, assert via MailHog API          |

These use `fetch()` or Playwright's `request` API, no browser context needed.

#### Batch 2 — Core auth flows (browser + MailHog)

| Feature file                          | Scenarios | Notes                                         |
| ------------------------------------- | --------- | --------------------------------------------- |
| `passwordless-authentication.feature` | 6         | Full browser flow + MailHog OTP retrieval     |
| `automatic-account-creation.feature`  | ~4        | Subset of auth flow, assert account exists    |
| `login-hint-resolution.feature`       | ~4        | Browser redirect assertions with query params |

These are the most important scenarios — they exercise the core login loop.
The World helper `getOtpFromMailhog(email)` calls the MailHog API
(`GET /api/v2/search?kind=to&query=<email>`) and parses the OTP from the
email body.

#### Batch 3 — Consent and account management (browser)

| Feature file               | Scenarios | Notes                                                  |
| -------------------------- | --------- | ------------------------------------------------------ |
| `consent-screen.feature`   | 5         | Two-pass login (first time -> consent, second -> skip) |
| `account-recovery.feature` | ~5        | Backup email setup + recovery flow                     |
| `account-settings.feature` | ~6        | Authenticated settings page interactions               |
| `epds-callback.feature`    | ~5        | HMAC-signed redirect chain verification                |

#### Batch 4 — Branding, security, TLS (mixed)

| Feature file                         | Scenarios | Notes                                            |
| ------------------------------------ | --------- | ------------------------------------------------ |
| `client-branding.feature`            | ~6        | CSS injection verification via computed styles   |
| `security.feature`                   | ~7        | HTTP headers, rate limiting, CSRF                |
| `tls-certificate-management.feature` | 7         | TLS handshake + routing assertions (Docker only) |
| `pds-behavior-at-risk.feature`       | ~6        | Standard ATProto ops via `@atproto/api` client   |

#### Deferred — Social login

| Feature file           | Scenarios | Notes                                   |
| ---------------------- | --------- | --------------------------------------- |
| `social-login.feature` | 6         | Tagged `@manual`, skipped in automation |

Social login scenarios require interacting with real Google/GitHub OAuth
screens. These are deferred from automated testing. The feature file remains
as living documentation and can be run manually against a real environment. If
automated testing becomes necessary, a mock OAuth provider container can be
added later.

### Phase 4: Railway preview environment

**Goal:** Each PR automatically gets an ephemeral ePDS deployment on Railway
with real DNS, and the E2E suite runs against it.

#### 4a. Railway preview deployments

Railway already supports PR environments. The three services (core, auth, demo)
each have `railway.toml` configs. Enable PR environments in the Railway
project settings so that each PR gets isolated service instances.

Railway preview services get auto-generated URLs like
`epds-core-pr-42.up.railway.app`. However, ePDS needs wildcard subdomains
(`auth.<hostname>`, `<handle>.<hostname>`), which Railway's default URLs don't
provide.

#### 4b. CloudFlare DNS automation

`e2e/cloudflare-dns.sh` manages ephemeral DNS records for Railway preview
environments.

**On PR open/update**, create DNS records:

- `pr-<number>.epds-test.example.com` -> Railway core service
- `auth.pr-<number>.epds-test.example.com` -> Railway auth service
- `*.pr-<number>.epds-test.example.com` -> Railway core service (handles)

**On PR close/merge**, delete these DNS records.

##### CloudFlare DNS safety guardrails

Accidental modification of unrelated DNS records is a serious risk. The
following guardrails **must all** be implemented:

1. **Dedicated zone**: Use a dedicated domain exclusively for ephemeral test
   environments (e.g. `epds-test.example.com`). This domain must have NO
   production records. Ideally register a cheap throwaway domain (e.g.
   `epds-e2e-tests.dev`) specifically for this purpose so there is zero overlap
   with any production infrastructure.

2. **Scoped API token**: Create a CloudFlare API token with permissions
   restricted to **DNS Edit on the single test zone only**. Do not use a
   Global API Key or a token with broader zone permissions. Verify the token
   scope in the CloudFlare dashboard before use.

3. **Name prefix enforcement**: The script must hard-code a required prefix
   pattern (e.g. `pr-<number>.epds-test.example.com`) and refuse to
   create/modify/delete any record that doesn't match this pattern. This is a
   defence-in-depth measure in case the token scope is misconfigured.

4. **Record-type restriction**: The script must only create `CNAME` /
   `A` records and possibly `TXT`. E.g. It must never touch `NS`,
   `SOA`, or other record types. `MX` _might_ be needed at some point
   if we want ephemeral email test environments.

5. **Dry-run mode**: The script must support a `--dry-run` flag that prints
   what it would do without making any API calls. CI should log the dry-run
   output before the actual run for auditability.

6. **Cleanup verification**: The PR-close cleanup job must list all records
   matching the PR prefix, delete only those, and then verify the deletion
   succeeded. Log the before/after record list.

7. **Stale record sweep**: A scheduled GitHub Actions job (e.g. weekly) scans
   the test zone for records whose corresponding PR is closed/merged, and
   deletes them. This catches any cleanup failures.

8. **Script-level safeguards**:

   ```bash
   # Hard-coded zone — never parameterised from user input
   ZONE_NAME="epds-e2e-tests.dev"

   # Validate PR number is numeric
   [[ "$PR_NUMBER" =~ ^[0-9]+$ ]] || { echo "Invalid PR number"; exit 1; }

   # Only operate on records matching the expected pattern
   RECORD_PATTERN="^(\\*\\.)?pr-${PR_NUMBER}\\.${ZONE_NAME}$"
   # ... reject any record name not matching RECORD_PATTERN
   ```

These guardrails ensure that even if multiple things go wrong simultaneously
(wrong env var, script bug, token misconfiguration), the blast radius is
confined to a throwaway test domain with no production records.

#### 4c. GitHub Actions workflow (`e2e-railway.yml`)

New workflow triggered on PR events:

```yaml
name: E2E (Railway Preview)
on:
  pull_request:
    types: [opened, synchronize, reopened, closed]

jobs:
  setup-dns:
    if: github.event.action != 'closed'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Create DNS records (dry-run)
        run: ./e2e/cloudflare-dns.sh create --dry-run
        env:
          PR_NUMBER: ${{ github.event.number }}
          CF_API_TOKEN: ${{ secrets.CF_E2E_DNS_TOKEN }}
      - name: Create DNS records
        run: ./e2e/cloudflare-dns.sh create
        env:
          PR_NUMBER: ${{ github.event.number }}
          CF_API_TOKEN: ${{ secrets.CF_E2E_DNS_TOKEN }}

  e2e-railway:
    needs: setup-dns
    if: github.event.action != 'closed'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: pnpm
      - run: pnpm install --frozen-lockfile
      - run: npx playwright install --with-deps chromium

      - name: Wait for Railway preview
        run: ./e2e/wait-for-healthy.sh
        env:
          E2E_PDS_URL: https://pr-${{ github.event.number }}.epds-e2e-tests.dev
          E2E_AUTH_URL: https://auth.pr-${{ github.event.number }}.epds-e2e-tests.dev

      - name: Run E2E tests
        run: pnpm test:e2e --tags 'not @manual and not @docker-only'
        env:
          E2E_TARGET: railway
          E2E_PDS_URL: https://pr-${{ github.event.number }}.epds-e2e-tests.dev
          E2E_AUTH_URL: https://auth.pr-${{ github.event.number }}.epds-e2e-tests.dev
          E2E_DEMO_URL: https://demo-pr-${{ github.event.number }}.up.railway.app
          E2E_MAILHOG_URL: ''

      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: e2e-traces
          path: reports/

  cleanup-dns:
    if: github.event.action == 'closed'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Delete DNS records
        run: ./e2e/cloudflare-dns.sh delete
        env:
          PR_NUMBER: ${{ github.event.number }}
          CF_API_TOKEN: ${{ secrets.CF_E2E_DNS_TOKEN }}
```

#### 4d. Railway preview manual testing

When a Railway preview is deployed, developers/reviewers can:

- Open `https://pr-<number>.epds-e2e-tests.dev` in a browser (real TLS via
  ACME)
- Open `https://auth.pr-<number>.epds-e2e-tests.dev` for the auth service
- Test with real ATProto clients (since the domain is publicly accessible)
- Test with the deployed demo app
- Share the URL with reviewers who don't have the repo checked out

This is a significant advantage over Docker-local: Railway previews can be
tested with real public ATProto apps.

#### 4e. Email testing on Railway

MailHog is not available on Railway. Options:

1. **Skip email-dependent scenarios** on Railway (tag with `@docker-only`)
2. **Use a real email provider** with a test inbox service (e.g. Mailosaur) —
   adds cost and complexity
3. **Deploy MailHog as a Railway service** — possible but wastes resources

Recommend option 1 for now: email scenarios are tagged `@docker-only` and
skipped when `E2E_TARGET=railway`. The Docker-local CI job covers them.

### Phase 5: CI integration

#### 5a. Docker-local E2E in CI (`e2e-docker.yml`)

New GitHub Actions workflow:

```yaml
name: E2E (Docker)
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  e2e-docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: pnpm
      - run: pnpm install --frozen-lockfile
      - run: npx playwright install --with-deps chromium

      - name: Start test environment
        run: pnpm test:e2e:docker:up

      - name: Run E2E tests
        run: pnpm test:e2e

      - name: Stop test environment
        if: always()
        run: pnpm test:e2e:docker:down

      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: e2e-traces
          path: reports/
```

#### 5b. Test reporting

- Cucumber HTML report -> `reports/e2e.html` (uploaded as CI artifact)
- Playwright traces -> `reports/` (uploaded on failure)
- Screenshots on failure -> embedded in Cucumber report

## Tag Strategy

| Tag                   | Meaning                                                 | Docker CI | Railway |
| --------------------- | ------------------------------------------------------- | --------- | ------- |
| (no tag)              | Standard scenario                                       | Yes       | Yes     |
| `@email`              | Requires a mail trap (Mailpit) to assert email delivery | Yes       | No      |
| `@manual`             | Requires human interaction (social login)               | No        | No      |
| `@docker-only`        | Needs Docker-specific infra (MailHog, internal API)     | Yes       | No      |
| `@risk-of-disruption` | Regression guard for vanilla PDS behavior (existing)    | Yes       | Yes     |
| `@slow`               | Takes >30s (rate limiting, lockout scenarios)           | Yes       | Yes     |

Cucumber config excludes `@manual` by default. Railway CI additionally
excludes `@docker-only`. Scenarios tagged `@email` require Mailpit to be
running; they are skipped gracefully when `E2E_MAILPIT_PASS` is unset.

## Test Data Strategy

### Seeding

Each scenario starts with a clean state. The `Before` hook:

1. Purges MailHog inbox (`DELETE /api/v1/messages`)
2. Creates test accounts as needed (via the ePDS itself — navigate login page,
   enter email, complete OTP, receive account)

For efficiency, a `@seed` tagged `Background` can pre-create accounts via the
internal API or direct DB seeding (for Docker-local only).

### Isolation

- Each scenario gets a fresh Playwright browser context (separate cookies,
  storage)
- Test emails use scenario-unique addresses (e.g.
  `test-<uuid>@example.com`) to avoid collisions in parallel runs
- On Docker, volumes are destroyed between full suite runs
  (`docker compose down -v`)

### Account creation helper

The World class provides a `createTestAccount(email)` helper that:

1. Initiates OAuth login via the demo client
2. Enters the email on the login page
3. Retrieves OTP from MailHog API
4. Completes verification
5. Returns the authenticated page

This is reused across scenarios that have a `Given "X" has a PDS account`
precondition.

## Effort Estimates

| Phase                                     | Effort          | Dependencies |
| ----------------------------------------- | --------------- | ------------ |
| Phase 1: Docker-local test environment    | 2-3 days        | None         |
| Phase 2: Test framework wiring            | 1-2 days        | Phase 1      |
| Phase 3, Batch 1: HTTP-only scenarios     | 1-2 days        | Phase 2      |
| Phase 3, Batch 2: Core auth flows         | 3-4 days        | Phase 2      |
| Phase 3, Batch 3: Consent & account mgmt  | 2-3 days        | Batch 2      |
| Phase 3, Batch 4: Branding, security, TLS | 2-3 days        | Batch 2      |
| Phase 4: Railway preview environment      | 3-4 days        | Phase 2      |
| Phase 5: CI integration                   | 1-2 days        | Phases 1-2   |
| **Total**                                 | **~15-23 days** |              |

Phases 4 and 5 can be worked on in parallel with Phase 3 batches.

## Open Risks

1. **Caddy internal CA in Docker** — Needs testing to confirm Caddy's
   `local_certs` directive works with on-demand TLS for arbitrary subdomains.
   If not, fall back to HTTP-only testing in Docker (skip TLS scenarios).

2. **Railway preview URL routing** — Railway's networking may not support
   wildcard subdomain routing to a single service. May need a Railway-side
   Caddy or nginx service, or a custom domain with Railway's CNAME setup.

3. **Test speed** — 86 scenarios with browser interactions could take 10-20
   minutes. Parallel execution (cucumber-js `--parallel`) and context reuse
   can help, but the MailHog-dependent scenarios are inherently sequential
   per email address.

4. **CloudFlare DNS propagation** — DNS changes may take seconds to minutes
   to propagate. The wait script needs to account for this when testing
   Railway previews.

5. **Account cleanup between scenarios** — There's no "delete account" API
   in the ePDS currently. Scenarios that create accounts need unique emails
   to avoid leaking state. For Docker, nuking volumes between runs is fine;
   for Railway, we need a cleanup strategy or unique emails per run.
