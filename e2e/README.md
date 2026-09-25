# E2E Tests

End-to-end tests for the full ePDS stack (PDS core, auth service, demo
frontend) using [Cucumber.js](https://cucumber.io/) with
[Playwright](https://playwright.dev/) for browser automation.

The `.feature` files live in `features/` at the repo root. Step definitions
and support files live here in `e2e/`.

## Prerequisites

- Node.js >= 22.19 and pnpm 9+
- A running ePDS stack to test against (see [Setup](#setup))
- Chromium browser (installed separately — see below)

## Setup

### Run the private integration stack

For the full local CI-like environment, use the repository-owned
[Atmosphere in a Box template](atmosphere/README.md). It starts ePDS core,
auth, trusted and untrusted demos, Mailpit, a private PLC, the local OAuth
permission-set lexicon authority, and the Playwright runner on a private
network with trusted HTTPS:

```bash
EPDS_E2E_PROJECT=epds-e2e-local pnpm test:e2e:atmosphere
```

Prerequisites are Docker Compose v2, Node.js 24, npm, Deno 2.8.3, Python 3,
and the ePDS pnpm dependencies. The runner performs both profiles by default,
checks that the created DID resolves only through the job-local PLC, retains
HTML/JUnit reports under `reports/`, and cleans up the named project.

### Railway release validation

The `E2E tests` workflow also validates Railway release branches. A push to
`dev` follows the `main` → `dev` promotion and targets `ePDS / dev`; a push to
`production` follows the `dev` → `production` promotion and targets `ePDS /
production`. The job waits for Railway to report a successful deployment of the
pushed SHA, then runs the suite against that environment. This does not use
AiaB or provision a separate stack.

### Run against another stack

The suite can also target an already-running deployment. Copy
`e2e/.env.example` to `e2e/.env` and set the service URLs described below.
For local application development, start services with `pnpm dev` (see
[docs/development.md](../docs/development.md)) and use `http://localhost`
URLs. External stacks may omit Mailpit or the untrusted demo; the corresponding
scenarios are excluded at discovery time when their configuration is absent.

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
| `E2E_PARALLEL`           | No       | `3`       | Number of Cucumber worker processes for the default profile. Lower this on constrained local machines; use `0` or `1` for serial debugging.             |
| `CUCUMBER_RETRY`         | No       | `0`       | Number of times Cucumber retries a failed scenario after the first attempt. `1` means up to two total attempts.                                         |

## Two demo clients

The e2e suite uses **two** separately configured demo OAuth clients in the
private test stack (or equivalent external deployment):

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

The managed private test stack starts the untrusted demo automatically. Other
environments must provide a second demo instance with a different
`client_id` and set `E2E_DEMO_UNTRUSTED_URL`.

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

## Running the CI e2e job

The `E2E tests` workflow runs on relevant pull requests, pushes to `main`,
and manual dispatch. It checks out the PR head SHA, clones the pinned
Atmosphere in a Box commit, builds the checked-out ePDS source into a fresh
private stack, and runs the default profile against that stack. It does not
discover Railway previews or require public service URLs, Railway credentials,
or writes to public PLC.

Each provisioning and verification operation is a named workflow step: template
validation, clone and registration, topology creation, image build, service
startup, fixture seeding, access projection validation, private-service probes,
private-PLC proof, Cucumber, report copying, failure logs, and scoped cleanup.
This keeps the GitHub Actions log useful when a specific infrastructure stage
fails. `e2e/atmosphere/run.sh` remains the local equivalent.

To run the same workflow manually, select **E2E tests** in GitHub Actions and
choose **Run workflow**. There are no environment-name inputs. Locally, run
`pnpm test:e2e:atmosphere`; see its README for prerequisites, network and TLS
boundaries, reports, and cleanup behavior.

The default profile intentionally excludes `@session-reuse`. The session-reuse
profile is run separately against the compatible hostname layout. Its last
verified run passed 19 of 20 scenarios and had one baseline failure:
“Signed-in user returning to an already-approved second client auto-approves
after confirming identity” remained on the untrusted client's consent page
instead of returning to `/welcome`. The default profile passed 83 scenarios. The failure is recorded in the
session-reuse JUnit report from that verification; session-reuse is not a
required CI job while it fails.

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
