# E2E Tests

End-to-end tests for the full ePDS stack (PDS core, auth service, demo
frontend) using [Cucumber.js](https://cucumber.io/) with
[Playwright](https://playwright.dev/) for browser automation.

The `.feature` files live in `features/` at the repo root. Step definitions
and support files live here in `e2e/`.

## Prerequisites

- Node.js >= 20 and pnpm 9+
- A running ePDS stack to test against (see [Setup](#setup))
- Chromium browser (installed separately — see below)

## Setup

### 1. Install the Playwright browser

```bash
npx playwright install chromium
```

### 2. Configure environment variables

```bash
cp e2e/.env.example e2e/.env
```

Open `e2e/.env` and fill in the three required service URLs. See
[Environment variables](#environment-variables) for the full reference.

### 3. Point the tests at a stack

The tests run against an already-running ePDS deployment — they do not start
services themselves. Two options:

**Option A — Live environment**
Point the tests at any deployed ePDS instance by setting the service URLs in
`e2e/.env`.

**Option B — Local stack**
Run the services locally with `pnpm dev` (see
[docs/development.md](../docs/development.md)), then set:

```dotenv
E2E_PDS_URL=http://localhost:3000
E2E_AUTH_URL=http://localhost:3001
E2E_DEMO_URL=http://localhost:3002
```

For OTP scenarios you also need a local Mailpit instance (see
[Mailpit](#mailpit)).

## Environment variables

| Variable           | Required | Default   | Description                                                          |
| ------------------ | -------- | --------- | -------------------------------------------------------------------- |
| `E2E_PDS_URL`      | Yes      | —         | PDS core base URL                                                    |
| `E2E_AUTH_URL`     | Yes      | —         | Auth service base URL                                                |
| `E2E_DEMO_URL`     | Yes      | —         | Demo frontend base URL                                               |
| `E2E_MAILPIT_URL`  | No       | —         | Mailpit base URL. Required for OTP scenarios.                        |
| `E2E_MAILPIT_USER` | No       | `karma`   | Mailpit HTTP basic auth username                                     |
| `E2E_MAILPIT_PASS` | No       | _(empty)_ | Mailpit HTTP basic auth password. Leave empty to skip OTP scenarios. |
| `E2E_HEADLESS`     | No       | `false`   | Set to `true` to run without a visible browser window                |

## Running the tests

```bash
# Headed mode — browser window visible (good for local debugging)
pnpm test:e2e

# Headless mode — same as above but forces E2E_HEADLESS=true
pnpm test:e2e:headless
```

### What to expect

- **OTP / email scenarios** are automatically marked `pending` (not failed)
  when `E2E_MAILPIT_PASS` is not set. This lets you run the non-email subset
  of scenarios without a mail server.
- **Failure screenshots** are saved to `reports/screenshots/<scenario-name>.png`.
- **HTML report** is written to `reports/e2e.html` after each run.
- Step timeout is 60 seconds to accommodate cold-start latency on remote environments.

## Mailpit

[Mailpit](https://mailpit.axllent.org/) is an SMTP trap with a web UI and
REST API. The e2e suite uses it to capture outbound OTP emails and extract
the verification code without a real mail server.

### How the suite uses Mailpit

- **Scenario hygiene** — the global setup clears any leftover inbox state at
  suite start, and per-scenario cleanup deletes messages for the scenario's
  test recipient to avoid cross-scenario bleed.
- **OTP retrieval** — before triggering OTP send for a recipient, tests clear
  `to:<email>` via Mailpit search delete. After submit, they poll
  `GET /api/v1/search?query=to:<email>` every 500 ms until an OTP email
  arrives.
- **Why clear before send** — this prevents stale OTP reuse when multiple OTP
  emails are sent to the same recipient in one scenario (for example composed
  setup + login, secondary-session login, retries, and resend flows).
- **Code extraction** — once an email is found, tests fetch
  `/view/<id>.txt` and extract the OTP with a regex.
- **Auth** — requests use HTTP Basic auth (`E2E_MAILPIT_USER` /
  `E2E_MAILPIT_PASS`) encoded as an `Authorization: Basic ...` header.

### Running Mailpit locally

```bash
docker run -d \
  --name mailpit \
  -p 1025:1025 \
  -p 8025:8025 \
  axllent/mailpit
```

Then set in `e2e/.env`:

```dotenv
E2E_MAILPIT_URL=http://localhost:8025
E2E_MAILPIT_USER=admin
E2E_MAILPIT_PASS=     # leave empty if you didn't enable auth
```

The web UI is available at <http://localhost:8025>.
