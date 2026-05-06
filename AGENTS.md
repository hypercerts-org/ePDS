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

## Before Pushing

**Run every check CI runs — locally — before every push.** CI failures
that prettier / eslint / tsc would have caught locally waste review
cycles. The full set CI runs is:

```bash
pnpm format:check          # prettier — CI fails if any file is unformatted
pnpm lint                  # eslint
pnpm typecheck             # tsc --noEmit
pnpm test                  # vitest run
pnpm test:coverage         # v8 thresholds in vitest.config.ts
```

These are cheap. Run them all before `git push` — not just the ones you
think are relevant to the change. In particular, `pnpm format:check`
catches prettier drift that `pnpm format` fixes in-place.

## Documentation

**Always update documentation when your changes would render existing docs
inaccurate or incomplete.** This includes but is not limited to:

- Adding, removing, or renaming environment variables → update
  `docs/configuration.md`, relevant `.env.example` files, and
  `scripts/setup.sh` (if the variable needs prompting or injection).
- Changing build steps, Docker workflows, or CLI commands → update
  `docs/deployment.md`, the Docker section below, and
  `scripts/setup.sh` next-steps output if it references the changed
  commands.
- Adding new scripts or changing existing ones → update the Build / Dev
  Commands section above.
- Changing API endpoints, health responses, or OAuth flows → update
  `docs/tutorial.md` or the relevant design doc.
- Changing agent-facing workflows → update this file (`AGENTS.md`).

Do not treat docs as a separate follow-up task. Update them in the same
commit or PR as the code change.

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

### SonarCloud

SonarCloud runs on every PR. Check results and fix issues before
merging. See [`.agents/reference/SonarCloud.md`](.agents/reference/SonarCloud.md)
for API commands and quality gate thresholds.

### PR review comments

Check for and address unresolved review comments after every push.
See [`.agents/reference/github-pr-comments.md`](.agents/reference/github-pr-comments.md)
for API commands.

### End-to-end tests in CI

The e2e suite lives in `e2e/` and its feature files in `features/`. Normally
the `E2E tests` workflow (`.github/workflows/e2e-tests.yml`) runs itself off
Railway's `deployment_status` webhook — no action needed on an ordinary PR.

To manually trigger it against a Railway environment (for e2e-only changes
that don't cause a rebuild, or to re-run without a new commit), **always
pass both `--ref` and `-f env_name`**:

```bash
# Against a PR environment:
gh workflow run e2e-tests.yml \
  --ref <your-branch> \
  -f env_name="ePDS / ePDS-pr-<N>"

# Against the persistent pr-base environment (post-merge backstop):
gh workflow run e2e-tests.yml \
  --ref main \
  -f env_name="ePDS / pr-base"
```

`--ref` controls which version of the feature files, step definitions, and
workflow YAML get checked out. Without it, `gh workflow run` defaults to
`main` and you'll silently test old code against the right environment.
See [`e2e/README.md`](e2e/README.md#running-the-ci-e2e-job-against-a-railway-environment)
for details (env-name formats, URL derivation, how to handle missing Railway
domains).

The e2e suite uses two demo OAuth clients (trusted and untrusted) for
trust-gated scenarios. See [`e2e/README.md`](e2e/README.md#two-demo-clients)
for the full setup, tagging conventions, and step-definition patterns.

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
# Build images — use pnpm docker:build to auto-stamp the version.
# IMPORTANT: Only rebuild the services that changed. Check the diff to
# determine which packages are affected, then pass service names:
sudo -g docker bash -c "cd /data/projects/ePDS && pnpm docker:build auth"
sudo -g docker bash -c "cd /data/projects/ePDS && pnpm docker:build core"
sudo -g docker bash -c "cd /data/projects/ePDS && pnpm docker:build demo"
# Only use bare 'pnpm docker:build' (all services) when shared/ changed
# or you genuinely need to rebuild everything.

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

## Railway

ePDS deploys to Railway. When checking the live config, follow these rules
to avoid wasting time on `--help` / wrong commands and to avoid leaking
secrets into your context.

### Discovery commands

```bash
railway status --json          # current project, service IDs, linked env
railway environment list       # all environments in the project
```

### Use -s and -e, not `railway link`

For any command that targets a specific service or environment, pass
`-s <SERVICE>` and `-e <ENVIRONMENT>` directly. Do **not** run
`railway environment link …` or `railway service link …` to "switch
context" first — those mutate local CLI state and are only needed when
`-s` / `-e` genuinely don't work for a given subcommand.

```bash
railway variable list -s demo-untrusted -e pr-base --kv | cut -d= -f1
railway logs -s pds-core -e pr-base --deployment
```

### NEVER extract sensitive variable values

This is non-negotiable. Variable values on Railway include API keys,
JWT secrets, database passwords, signing keys, and similar credentials.
Anything pulled into your context is effectively logged.

- **Allowed:** listing variable _names_ to check for presence /
  absence (e.g. "is `EPDS_CLIENT_PRIVATE_JWK` set on this service?").
- **Disallowed without explicit user permission:** the actual value of
  any variable that is not obviously non-sensitive (a hostname, a
  public URL, a log level, a feature flag boolean). When in doubt,
  treat it as sensitive.
- This applies to every command that can return values, including
  `railway variable list` (without filtering), `railway environment
config --json` (dumps all variables across all services with values),
  and `railway run …` (injects them into a subprocess).

To check presence without seeing values, list names only:

```bash
# Names only — pipe through cut to drop values
railway variable list -s demo-untrusted -e pr-base --kv | cut -d= -f1 | sort

# Or via the JSON API, extracting keys only
railway variable list -s demo-untrusted -e pr-base --json \
  | python3 -c 'import json,sys; print("\n".join(sorted(json.load(sys.stdin))))'
```

If a value genuinely needs inspection (e.g. debugging a misconfigured
URL), ask the user first.

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

- **Never hand-roll security code.** Use upstream or established libraries
  for SSRF protection, crypto, auth, input sanitization, etc. If a library
  integration has issues (e.g. test incompatibility), fix the integration —
  do not reimplement the security logic. If the integration truly can't
  work, stop and ask before proceeding with any alternative.
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
and release notes. `CHANGELOG.md` is **prepend-only** — the tooling adds new
sections at the top and never modifies old ones. See
[`.agents/reference/release-notes.md`](.agents/reference/release-notes.md) for
how the release workflow operates and how to fix attribution on Version Packages
PRs.

The repo is treated as a **single release unit** even though the source is split
across `packages/*`, via a `"workspaces": ["."]` field in the root
`package.json` that scopes Changesets to the root `ePDS` package only. One
`CHANGELOG.md` at the repo root, one `v<version>` git tag per release, one
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
  Release" flow via `.github/workflows/release.yml`. Phase 1 is triggered
  manually (`workflow_dispatch`); phase 2 fires automatically when the
  Release PR (head branch `changeset-release/main`) is merged into `main`.

## Key Gotchas

- `docker compose restart` does **not** pick up `.env` changes — use
  `docker compose up -d`.
- Use `pnpm docker:build` instead of bare `docker compose build` — it
  stamps the ePDS version before building.
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
