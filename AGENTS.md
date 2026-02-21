# AGENTS.md — ePDS

AI agent instructions for the ePDS repository.

## Repository Structure

Pnpm monorepo with three packages:

| Package                       | Path                     | Description                                       |
| ----------------------------- | ------------------------ | ------------------------------------------------- |
| `@certified-app/shared`       | `packages/shared/`       | SQLite DB, crypto utils, logger, types            |
| `@certified-app/auth-service` | `packages/auth-service/` | Login UI, OTP, social login, account settings     |
| `@certified-app/pds-core`     | `packages/pds-core/`     | Wraps `@atproto/pds` with magic-callback endpoint |

## Build / Dev Commands

```bash
pnpm install               # install all dependencies
pnpm build                 # build all packages (tsc --build)
pnpm typecheck             # type-check without emitting
pnpm dev                   # run all packages in dev/watch mode
pnpm dev:auth              # auth-service only (tsx watch)
pnpm dev:pds               # pds-core only (tsx watch)
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

## Docker

```bash
# Build images (use --no-cache for pds-core — cache busting is broken)
docker build --no-cache -f Dockerfile.pds -t epds .
docker build -f Dockerfile.auth -t magic-auth .

# Run the full stack
sudo -g docker bash -c "cd /data/projects/ePDS && docker compose up -d"
sudo -g docker bash -c "cd /data/projects/ePDS && docker compose logs -f"

# Always use 'up -d' (not 'restart') to pick up .env changes
sudo -g docker bash -c "cd /data/projects/ePDS && docker compose up -d"
```

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
- Do **not** directly read or modify `@atproto/pds` database tables — use
  `pds.ctx.accountManager.*` methods.

## Security

- All magic-callback redirects must be HMAC-SHA256 signed using
  `signCallback()` / `verifyCallback()` from `@certified-app/shared`.
- Use `timingSafeEqual()` for all secret/token comparisons.
- OTP codes: 8-digit, single-use, managed by better-auth.
- Internal service-to-service calls use `x-internal-secret` header.

## Task Tracking

- Use `bd` (beads) for all task tracking — **not** TodoWrite or markdown files.
- `bd ready` — show available work; `bd create` — new issue; `bd close` — done.
- `bd export -o .beads/issues.jsonl` to export issues (commit this file).
- Do **not** use `bd sync` (obsolete).

## Key Gotchas

- `docker compose restart` does **not** pick up `.env` changes — use
  `docker compose up -d`.
- `docker build --no-cache` required for PDS image (cache busting broken).
- better-auth does **not** auto-migrate — `runBetterAuthMigrations()` must be
  called explicitly on startup.
- New PDS accounts need a real password passed to `createAccount()` (use
  `randomBytes(32).toString('hex')`) — passing `undefined` skips
  `registerAccount()` and leaves the `account` table empty, breaking
  `upsertDeviceAccount()` FK constraints.
- Auth service must use `PDS_INTERNAL_URL=http://pds:3000` in Docker to reach
  PDS over the internal network.
