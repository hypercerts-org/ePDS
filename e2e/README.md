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

Open `e2e/.env` and fill in the required service URLs. See
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
# Optional — only needed for scenarios that exercise the trusted vs.
# untrusted client distinction. See "Two demo clients" below.
# E2E_DEMO_UNTRUSTED_URL=http://localhost:3003
```

For OTP scenarios you also need a local Mailpit instance (see
[Mailpit](#mailpit)).

## Environment variables

| Variable                 | Required | Default   | Description                                                                                                                                             |
| ------------------------ | -------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `E2E_PDS_URL`            | Yes      | —         | PDS core base URL                                                                                                                                       |
| `E2E_AUTH_URL`           | Yes      | —         | Auth service base URL                                                                                                                                   |
| `E2E_DEMO_URL`           | Yes      | —         | Trusted demo client base URL (its `client_id` URL, i.e. `<base>/client-metadata.json`, is listed in `pds-core`'s `PDS_OAUTH_TRUSTED_CLIENTS`)           |
| `E2E_DEMO_UNTRUSTED_URL` | No       | —         | Untrusted demo client base URL. When unset, scenarios tagged `@untrusted-client` are automatically excluded. See [Two demo clients](#two-demo-clients). |
| `E2E_MAILPIT_URL`        | No       | —         | Mailpit base URL. Required for OTP scenarios.                                                                                                           |
| `E2E_MAILPIT_USER`       | No       | `karma`   | Mailpit HTTP basic auth username                                                                                                                        |
| `E2E_MAILPIT_PASS`       | No       | _(empty)_ | Mailpit HTTP basic auth password. Leave empty to skip OTP scenarios.                                                                                    |
| `E2E_HEADLESS`           | No       | `false`   | Set to `true` to run without a visible browser window                                                                                                   |

## Two demo clients

The e2e suite uses **two** demo OAuth clients deployed as separate Railway
services in the `ePDS` project:

| Service name                    | Role          | Listed in `PDS_OAUTH_TRUSTED_CLIENTS` |
| ------------------------------- | ------------- | ------------------------------------- |
| `@certified-app/demo`           | **Trusted**   | Yes                                   |
| `@certified-app/demo untrusted` | **Untrusted** | No                                    |

Both demos are deployed from the same source — the only meaningful
differences are (a) different OAuth client identities (separate private
JWKs and `client-metadata.json` URLs, hence different `client_id` values)
and (b) only the trusted demo's `client-metadata.json` URL is listed in
the `PDS_OAUTH_TRUSTED_CLIENTS` env var on `pds-core`. **The trust check
happens on `pds-core`, not on the demos themselves** — so flipping a demo
between trusted and untrusted is a config change on `pds-core`, not a
code change on the demo.

### Where the untrusted demo exists

The untrusted demo lives in **`pr-base`** and every PR preview environment
forked from it (`ePDS-pr-<N>` / `pr-<hash>-<N>`). It does **not** exist in
the `test`, `production`, or `dev` Railway environments. If you want a
local untrusted demo for development, you need to start a second instance
of the demo app yourself with a different `client_id` and point
`E2E_DEMO_UNTRUSTED_URL` at it.

### Why two clients

Two distinct categories of e2e scenarios need an untrusted client:

1. **Negative trust tests** — proving that features which require trust
   do not function for untrusted clients. Examples: consent-skip on
   sign-up (only the trusted demo skips consent automatically), custom
   client display name in the consent screen (untrusted clients show
   their URL host instead), CSS branding injection (only injected for
   trusted clients).
2. **Multi-client scenarios** — anything that needs two distinct OAuth
   clients in the same browser session. The canonical example is
   cross-client SSO / session reuse (HYPER-268), where the test
   fundamentally cannot be expressed with a single client.

### How to use it from a step definition

The trusted demo URL is exposed as `testEnv.demoTrustedUrl` (also
available under the back-compat alias `testEnv.demoUrl`); the untrusted
demo URL is exposed as `testEnv.demoUntrustedUrl`.

The shared sign-up helpers in [`e2e/support/flows.ts`](support/flows.ts)
take an explicit `demoUrl` parameter:

```ts
import {
  createAccountViaOAuth,
  startSignUpAwaitingConsent,
} from '../support/flows.js'

// Default trusted-demo sign-up:
await createAccountViaOAuth(world, email)

// Drive the untrusted demo (e.g. negative consent-skip test):
await createAccountViaOAuth(world, email, testEnv.demoUntrustedUrl)

// Sign up but stop on the consent screen — only meaningful for the
// untrusted demo, since trusted clients skip consent on sign-up:
await startSignUpAwaitingConsent(world, email, testEnv.demoUntrustedUrl)
```

`testEnv.demoUntrustedUrl` is typed as `string | undefined`. Any step
that reads it must guard against the unset case with an early
`if (!testEnv.demoUntrustedUrl) return 'pending'` at the top of the
step body — the same pattern as the `E2E_MAILPIT_PASS` check in
mailpit-dependent steps. See `e2e/step-definitions/consent.steps.ts`
for examples.

### Skipping untrusted-client scenarios when the var is unset

Scenarios (or whole features) that depend on the untrusted demo are
tagged `@untrusted-client`. When `E2E_DEMO_UNTRUSTED_URL` is unset,
`e2e/cucumber.mjs` automatically adds `not @untrusted-client` to the
tag exclusion expression, so the affected scenarios are skipped
cleanly at discovery time rather than failing at run time.

The step-level `return 'pending'` guards described above are
defence-in-depth for `cucumber-js --name "..."` invocations, which
bypass tag exclusions entirely — if you run a single scenario by
name against an environment without an untrusted demo, its steps
will return `'pending'` one by one and cucumber will mark the
scenario as pending.

### Existing consumers

For prior art when adding new untrusted-client scenarios, see:

- [`e2e/step-definitions/consent.steps.ts`](step-definitions/consent.steps.ts)
  — sign-up consent-skip scenarios that compare trusted vs. untrusted
  client behaviour and assert the consent screen displays the URL host
  for untrusted clients.
- [`e2e/support/flows.ts`](support/flows.ts) — `startSignUpAwaitingConsent`
  is documented as intended for untrusted clients specifically.

## Running the tests

```bash
# Headed mode — browser window visible (good for local debugging)
pnpm test:e2e

# Headless mode — same as above but forces E2E_HEADLESS=true
pnpm test:e2e:headless
```

### Run a single feature

`pnpm test:e2e` and `pnpm test:e2e:headless` use `e2e/cucumber.mjs`, which
defines a `paths` list. If you pass a feature path on the CLI, the current
`cucumber-js` version merges that path with configured `paths`, so it can run
multiple features.

To run only one feature, invoke `cucumber-js` directly:

```bash
E2E_HEADLESS=true TSX_TSCONFIG_PATH=e2e/tsconfig.e2e.json \
node --import tsx/esm ./node_modules/@cucumber/cucumber/bin/cucumber-js \
  --import 'e2e/step-definitions/**/*.ts' \
  --import 'e2e/support/**/*.ts' \
  --format pretty \
  --format html:reports/e2e.html \
  --tags 'not @manual and not @docker-only and not @pending' \
  --strict \
  features/account-settings.feature
```

### Run a single scenario by name

Use `--name` with a scenario title (and keep the feature path scoped to reduce
search time):

```bash
pnpm run test:e2e:headless --name "User deletes their account"
```

You cannot run a step definition file directly (for example
`e2e/step-definitions/account-settings.steps.ts`). Cucumber runs feature files
or scenarios and loads step definitions via `--import`.

### What to expect

- **OTP / email scenarios** are automatically marked `pending` (not failed)
  when `E2E_MAILPIT_PASS` is not set. This lets you run the non-email subset
  of scenarios without a mail server.
- **Failure screenshots** are saved to `reports/screenshots/<scenario-name>.png`.
- **HTML report** is written to `reports/e2e.html` after each run.
- Step timeout is 60 seconds to accommodate cold-start latency on remote environments.

## Running the CI e2e job against a Railway environment

The `E2E tests` GitHub Actions workflow (`.github/workflows/e2e-tests.yml`) normally
runs itself: whenever Railway successfully deploys a PR preview environment, it
posts a `deployment_status` webhook that triggers the workflow against the
environment it just deployed. For everyday PR work you don't need to do anything.

You do need to trigger it manually in two situations:

1. You made an e2e-only change (feature files, step definitions, workflow YAML)
   that does not cause a Railway rebuild — so no `deployment_status` event fires.
2. You want to re-run e2e against an existing Railway environment without
   pushing a new commit (for example, after flakiness or after fixing a
   misconfigured env var).

Use `gh workflow run` with **both** `--ref` and `-f env_name`:

```bash
gh workflow run e2e-tests.yml \
  --ref <your-branch> \
  -f env_name="ePDS / <railway-env-name>"
```

- `--ref <your-branch>` controls **which version of the workflow file, feature
  files, and step definitions** get checked out and executed. Without it,
  `gh workflow run` defaults to the repository's default branch (`main`),
  so your local changes won't be exercised — the workflow will run against
  old test code and produce confusing results.
- `-f env_name="..."` is the display name shown in the Railway PR comment.
  Use the exact string you see there. Accepted formats:
  - `ePDS / ePDS-pr-<N>` — standard PR environment name.
  - `ePDS / pr-<hash>-<N>` — Railway's collision-avoidance fallback, seen
    after a close/reopen or force-push inside the env-cleanup window.
    See [Railway discussion](https://station.railway.com/questions/pr-environment-name-format-change-causin-9aaa904f).
  - `ePDS / pr-base` — the persistent post-merge backstop environment.

Example:

```bash
gh workflow run e2e-tests.yml \
  --ref fix/consent-use-upstream-oauth-ui \
  -f env_name="ePDS / ePDS-pr-21"
```

After dispatching, watch the run:

```bash
gh run list --workflow=e2e-tests.yml --event=workflow_dispatch --limit 1
gh run watch <run-id>
```

### How service URLs are derived

The workflow derives service URLs from the env name using Railway's standard
slug rule: strip the `@<scope>/` prefix, replace spaces with `-`, lowercase.
For an env named `ePDS-pr-21` it expects:

- `certified-apppds-core-epds-pr-21.up.railway.app`
- `certified-appauth-service-epds-pr-21.up.railway.app`
- `certified-appdemo-epds-pr-21.up.railway.app`
- `certified-appdemo-untrusted-epds-pr-21.up.railway.app` (see [Two demo clients](#two-demo-clients))
- `mailpit-epds-pr-21.up.railway.app`

If any of these return a 404 "Application not found", the service probably
has no public domain attached in Railway. Generate one in the Railway UI
(Settings → Networking → Generate Domain) and re-run.

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
