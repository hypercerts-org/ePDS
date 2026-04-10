# AGENTS.md — ePDS (extended Personal Data Server)

AI agent instructions for the ePDS repository.

## Repository Structure

Pnpm monorepo with three packages:

| Package                       | Path                     | Description                                      |
| ----------------------------- | ------------------------ | ------------------------------------------------ |
| `@certified-app/shared`       | `packages/shared/`       | SQLite DB, crypto utils, logger, types           |
| `@certified-app/auth-service` | `packages/auth-service/` | Login UI, OTP, social login, account settings    |
| `@certified-app/pds-core`     | `packages/pds-core/`     | Wraps `@atproto/pds` with epds-callback endpoint |

## Build / Dev Commands

```bash
pnpm install               # install all dependencies
pnpm build                 # build all packages (tsc --build)
pnpm typecheck             # type-check without emitting
pnpm dev                   # run all packages in dev/watch mode
pnpm dev:auth              # auth-service only (tsx watch)
pnpm dev:pds               # pds-core only (tsx watch)
pnpm dev:demo              # demo frontend only (Next.js, port 3002)
pnpm format                # format all files with Prettier
pnpm format:check          # check formatting (CI)
pnpm lint                  # lint all files with ESLint
pnpm lint:fix              # lint and auto-fix where possible
```

## Test Commands

```bash
pnpm test                          # run all tests (vitest run)
pnpm test:watch                    # vitest in watch mode

# Run a single test file
pnpm vitest run packages/auth-service/src/__tests__/login-page.test.ts

# Run tests matching a pattern
pnpm vitest run --reporter=verbose -t "creates an auth_flow"

# Run tests for one package
pnpm vitest run packages/shared
```

Tests live in `packages/<name>/src/__tests__/`. There is no per-package test
script — all tests are run from the root via vitest.

### End-to-end tests in CI

The e2e suite lives in `e2e/` and its feature files in `features/`. Normally
the `E2E tests` workflow (`.github/workflows/e2e-pr.yml`) runs itself off
Railway's `deployment_status` webhook — no action needed on an ordinary PR.

To manually trigger it against a Railway environment (for e2e-only changes
that don't cause a rebuild, or to re-run without a new commit), **always
pass both `--ref` and `-f env_name`**:

```bash
gh workflow run e2e-pr.yml \
  --ref <your-branch> \
  -f env_name="ePDS / ePDS-pr-<N>"
```

`--ref` controls which version of the feature files, step definitions, and
workflow YAML get checked out. Without it, `gh workflow run` defaults to
`main` and you'll silently test old code against the right environment.
See [`e2e/README.md`](e2e/README.md#running-the-ci-e2e-job-against-a-railway-environment)
for details (env-name formats, URL derivation, how to handle missing Railway
domains).

#### Two demo clients

The e2e suite uses **two** demo OAuth clients deployed as separate Railway
services: `@certified-app/demo` (trusted) and `@certified-app/demo untrusted`
(untrusted, note the space in the service name). Only the trusted demo's
`client-metadata.json` URL is listed in `pds-core`'s `PDS_OAUTH_TRUSTED_CLIENTS`
env var — that's where the trust check lives, not on the demos themselves.

Any e2e scenario that needs to exercise trust-gated behaviour (consent-skip
on sign-up, custom CSS branding, trusted client display name in the consent
screen) or that needs two distinct OAuth clients in the same browser session
(cross-client SSO / session reuse) must drive the untrusted demo via
`testEnv.demoUntrustedUrl`. The untrusted demo only exists in `pr-base` and
PR preview environments — not in `test`, `production`, or `dev`.

`E2E_DEMO_UNTRUSTED_URL` is typed as optional, but there is currently no
tag-based opt-out for scenarios that touch the untrusted demo — they will
throw from `requireUntrustedDemoUrl()` if the env var is unset. When
writing a new scenario that requires it, follow the guard pattern in
[`e2e/step-definitions/consent.steps.ts`](e2e/step-definitions/consent.steps.ts)
(`requireUntrustedDemoUrl()` helper) so the failure message names the env
var. See [`e2e/README.md#two-demo-clients`](e2e/README.md#two-demo-clients)
for the full reference.

### Writing Tests

Before designing or writing new tests, read
[`docs/design/testing-gaps.md`](docs/design/testing-gaps.md). It documents:

- Current coverage per package/area and known hard-to-test zones.
- Which areas are unit-testable vs. require integration/e2e tests.
- Recommended strategies for covering route handlers, pds-core, and
  better-auth wiring.
- Remaining low-hanging fruit for coverage improvement.

Follow these guidelines when adding tests:

- **Prefer unit tests for pure logic** — crypto, validation, DB operations,
  middleware. Use mock req/res objects (see `csrf.test.ts`, `rate-limit.test.ts`).
- **Use `globalThis.fetch` mocking** for code that calls external services
  (see `client-metadata.test.ts`, `email-template.test.ts`). Return
  `Promise.resolve(...)` instead of `async () => ...` to avoid
  `@typescript-eslint/require-await` lint errors.
- **Use in-memory SQLite** for DB tests — create a temp file in
  `os.tmpdir()`, clean up in `afterEach` (see `db.test.ts`).
- **Do not test route handlers with unit tests** — they are integration-level
  glue. Cover them via `supertest` integration tests or e2e tests instead.
- **Keep `testing-gaps.md` up to date** — when you add tests that close a
  documented gap, or discover new gaps, update the coverage summary table
  and relevant sections.
- **Ratchet thresholds** — after improving coverage, bump the thresholds in
  `vitest.config.ts` so coverage cannot regress.

### Coverage Ratcheting Policy

Coverage thresholds in `vitest.config.ts` must **only ever increase**.
When a PR increases coverage above the current thresholds, the thresholds
must be ratcheted up to the new floor (rounded down to the nearest integer)
as part of the same PR. This ensures coverage can never regress.

```bash
pnpm test:coverage   # check current coverage vs thresholds
```

After confirming coverage exceeds thresholds, update `vitest.config.ts`:

```ts
thresholds: {
  statements: <new floor>,
  branches: <new floor>,
  functions: <new floor>,
  lines: <new floor>,
},
```

**Never lower thresholds.** If a change removes tested code (e.g. deleting
a feature), add tests for other code to compensate.

## Docker

```bash
# Build images (always use --no-cache — cache busting is broken)
# IMPORTANT: Only rebuild the services that changed. Check the diff to
# determine which packages are affected, then pass service names:
sudo -g docker bash -c "cd /data/projects/ePDS && docker compose build --no-cache auth"
sudo -g docker bash -c "cd /data/projects/ePDS && docker compose build --no-cache core"
sudo -g docker bash -c "cd /data/projects/ePDS && docker compose build --no-cache demo"
# Only use bare 'docker compose build --no-cache' (all services) when
# shared/ changed or you genuinely need to rebuild everything.

# Run the full stack
sudo -g docker bash -c "cd /data/projects/ePDS && docker compose up -d"
sudo -g docker bash -c "cd /data/projects/ePDS && docker compose logs -f"

# Always use 'up -d' (not 'restart') to pick up .env changes
sudo -g docker bash -c "cd /data/projects/ePDS && docker compose up -d"
```

Service-to-image mapping (use this to decide what to rebuild):

| Docker service | Image       | Rebuilds when these packages change |
| -------------- | ----------- | ----------------------------------- |
| `core`         | `epds-core` | `shared/`, `pds-core/`              |
| `auth`         | `epds-auth` | `shared/`, `auth-service/`          |
| `demo`         | `epds-demo` | `shared/`, `demo/`                  |
| `caddy`        | (upstream)  | Only `Caddyfile` — no build needed  |

Container names: `epds-core` (PDS, port 3000), `epds-auth` (auth service, port 3001),
and `epds-demo` (demo frontend, port 3002).

## Code Style

### TypeScript

- **Strict mode** — `strict: true` in all tsconfigs. No implicit `any`.
- **Target** — ES2022, module Node16, moduleResolution Node16.
- **ESM** — all packages use `"type": "module"`. Use `.js` extensions in
  imports even for `.ts` source files (Node16 resolution requires this).
- **Type imports** — use `import type` for type-only imports:
  ```ts
  import type { Request, Response } from 'express'
  import { Router } from 'express'
  ```
- **`as any` casts** — permitted only when working with untyped internals of
  `@atproto/oauth-provider` branded types. Comment why.

### Imports

Order (no enforced linter, but follow this convention):

1. Node built-ins (`node:crypto`, `node:path`, etc.) — always use the `node:`
   prefix
2. External packages
3. Internal workspace packages (`@certified-app/shared`)
4. Local relative imports (with `.js` extension)

```ts
import * as crypto from 'node:crypto'
import express from 'express'
import { createLogger } from '@certified-app/shared'
import { AuthServiceContext } from './context.js'
```

### Naming

- **Files** — `kebab-case.ts`
- **Classes** — `PascalCase`
- **Interfaces / types** — `PascalCase`, prefix with `I` only if needed to
  avoid collision with a class of the same name
- **Functions / variables** — `camelCase`
- **Constants** — `SCREAMING_SNAKE_CASE` for module-level magic values,
  `camelCase` for const variables
- **DB column names** — `camelCase` in TypeScript interfaces, `snake_case` in
  raw SQL
- **Route factories** — named `create<Name>Router(ctx)` returning `Router`

### Functions and Modules

- Prefer small, focused functions. Route handlers delegate to helpers.
- Route files export a single `create*Router(ctx)` factory function.
- No default exports — use named exports throughout.
- Async `main()` pattern for service entry points.

### Error Handling

- Use `logger.error({ err }, 'description')` (pino structured logging).
- Return HTTP error responses with `res.status(N).json({ error: '...' })` or
  `res.status(N).type('html').send(renderError(...))` for HTML pages.
- Never swallow errors silently — log at minimum `debug` level.
- Debug/trace logging at `logger.debug(...)`, not `logger.info(...)`.

### Comments

- File-level JSDoc block at the top of route files explaining the route's
  purpose, flow steps, and any non-obvious behaviour.
- Inline comments explain _why_, not _what_.
- Do not add comments that merely restate what the code does.

### HTML / Templates

- Server-rendered HTML uses template literal functions (e.g. `renderLoginPage()`).
- Always escape user input with `escapeHtml()` from `@certified-app/shared`.
- CSS classes control visibility (`hidden`, `active`) — avoid inline `display`
  style except for dynamic values set at render time.

## Database

- SQLite via `better-sqlite3`. All DB access goes through `EpdsDb`
  (`packages/shared/src/db.ts`).
- Schema changes use versioned migrations in `runMigrations()`.
- **Never drop tables or columns in migrations.** Destructive schema changes
  break emergency rollbacks — rolled-back code still references the dropped
  schema and crashes. Leave unused tables/columns in place; they're harmless.
- Do **not** directly read or modify `@atproto/pds` database tables — use
  `pds.ctx.accountManager.*` methods.

## Security

- All epds-callback redirects must be HMAC-SHA256 signed using
  `signCallback()` / `verifyCallback()` from `@certified-app/shared`.
- Use `timingSafeEqual()` for all secret/token comparisons.
- OTP codes: configurable length (4–12, default 8, via `OTP_LENGTH`) and charset
  (`numeric` or `alphanumeric`, default `numeric`, via `OTP_CHARSET`), single-use,
  managed by better-auth. Expiry is hardcoded at 600 s with 5 allowed attempts.
- Internal service-to-service calls use `x-internal-secret` header.

## Task Tracking

- Use `bd` (beads) for all task tracking — **not** TodoWrite or markdown files.
- `bd ready` — show available work; `bd create` — new issue; `bd close` — done.
- `bd export -o .beads/issues.jsonl` to export issues (commit this file).
- Do **not** use `bd sync` (obsolete).

## Releases & Changesets

ePDS uses [Changesets](https://github.com/changesets/changesets) for versioning
and release notes. The repo is treated as a **single release unit** even though
the source is split across `packages/*`, via a `"workspaces": ["."]` field in
the root `package.json` that scopes Changesets to the root `ePDS` package only.
One `CHANGELOG.md` at the repo root, one `v<version>` git tag per release, one
GitHub Release per release.

- **When to add a changeset:** any user-facing or operator-facing change to the
  three in-scope packages (`pds-core`, `auth-service`, `shared`). Skip for
  internal refactors, tests-only, CI-only, docs-only, and the internal trust
  boundary between `auth-service` and `pds-core` (HMAC callback signature,
  `/_internal/` routes). If in doubt, add one.
- **How to add a changeset:** `pnpm changeset` then rename the generated file
  to something descriptive. Commit it in the same PR as the code change.
- **Required format:** every changeset must have a `**Affects:**` line listing
  audiences (End users, Client app developers, Operators — in that order). The
  release workflow **fails hard** if any changeset in a release is missing
  this line, because `scripts/changelog-audience-summary.mjs` can't generate
  the "Who should read this release" block without it.
- **Summary line:** the first non-frontmatter line is read by _every_ listed
  audience (it appears in the aggregate summary block at the top of the
  release section). If End users is one of the audiences, write the summary
  in plain language — no OTP/DID/PAR/OAuth jargon, no field names, no
  implementation concepts. Technical naming belongs in the per-audience
  sections below.
- **No H2/H3 headings** inside changeset bodies. `@changesets/changelog-github`
  renders each changeset as a single indented bullet, and indented headings
  break out of the list on GitHub's renderer. Use **bold inline labels**
  (`**End users:**`, `**Operators:**`) instead.
- **Full format reference:** `.agents/skills/writing-changesets/SKILL.md`
  (also reachable via the `.claude/skills/writing-changesets/SKILL.md`
  symlink). Contains the audience list, body structure rules, examples of
  good and bad summaries, and the plain-language rule in detail.
- **Cutting a release:** `docs/PUBLISHING.md` documents the release workflow
  for maintainers — the two-phase "Version Packages PR" → "tag + GitHub
  Release" flow via `.github/workflows/release.yml`.

## Key Gotchas

- `docker compose restart` does **not** pick up `.env` changes — use
  `docker compose up -d`.
- `docker compose build --no-cache` required (cache busting is broken for both images).
- better-auth does **not** auto-migrate — `runBetterAuthMigrations()` must be
  called explicitly on startup.
- New PDS accounts need a real password passed to `createAccount()` (use
  `randomBytes(32).toString('hex')`) — passing `undefined` skips
  `registerAccount()` and leaves the `account` table empty, breaking
  `upsertDeviceAccount()` FK constraints.
- Auth service must use `PDS_INTERNAL_URL` to reach pds-core over the internal
  network (Docker: `http://core:3000`, Railway:
  `http://<service>.railway.internal:<PDS_PORT>` substituting whichever port
  pds-core is actually configured to listen on). The URL must include the
  `http://` or `https://` scheme — `requireInternalEnv()` rejects bare hostnames
  at startup. Without `PDS_INTERNAL_URL`, internal API calls (par-login-hint,
  account-by-email) fall back to the public URL which is unreachable from
  containers (no hairpin NAT).
- Caddy's on-demand TLS `ask` URL and reverse proxy upstreams must use the
  Docker Compose service name (`core`, `auth`) — if you rename services, update
  `Caddyfile` defaults too or Caddy will refuse all TLS connections.
