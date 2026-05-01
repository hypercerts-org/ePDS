/**
 * Route-level coverage for the "Another account" rebind branch of
 * GET /oauth/authorize.
 *
 * GitHub issue #138: pds-core's "Another account" rebind navigates back
 * to auth-service with `prompt=login` AND `epds_skip_par_hint=1`
 * appended (and any URL `login_hint` stripped). `epds_skip_par_hint=1`
 * tells auth-service to ignore any login_hint stored in the PAR — the
 * user clicked an opt-out, so the RP's hint must not influence rendering.
 * With no hint resolving, `resolvedEmail` is null and the email step
 * falls out from the standard rendering decision.
 *
 * `prompt=login` ALONE (without the skip flag) must NOT suppress hint
 * resolution — pds-core's auth-ui-guard sign-in-view bounce appends
 * prompt=login while still expecting the hint to be honoured (the user
 * wants that account; upstream's password sign-in form is just
 * unreachable in a passwordless deployment). The third test below pins
 * this so a future "simplification" that conflates the two signals is
 * caught.
 *
 * Lives in its own file because the `vi.mock` calls below replace the
 * shared resolver modules wholesale, and we don't want that bleed into
 * the existing unit tests in login-page.test.ts.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import express from 'express'
import cookieParser from 'cookie-parser'
import { randomBytes } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import type { AddressInfo } from 'node:net'
import { _seedClientMetadataCacheForTest } from '@certified-app/shared'
import { csrfProtection } from '../middleware/csrf.js'
import { createLoginPageRouter } from '../routes/login-page.js'
import { AuthServiceContext, type AuthServiceConfig } from '../context.js'

// Hoisted spies — `vi.mock` runs before module imports, so the mock factory
// must capture them via `vi.hoisted` rather than referencing top-level
// `const`s that haven't been initialised yet.
const mocks = vi.hoisted(() => ({
  fetchParLoginHint: vi.fn(),
  resolveLoginHint: vi.fn(),
  fetchDeviceAccountEmails: vi.fn(),
}))

vi.mock('../lib/resolve-login-hint.js', () => ({
  fetchParLoginHint: mocks.fetchParLoginHint,
  resolveLoginHint: mocks.resolveLoginHint,
}))

vi.mock('../lib/fetch-device-accounts.js', () => ({
  fetchDeviceAccountEmails: mocks.fetchDeviceAccountEmails,
}))

function makeConfig(dbPath: string): AuthServiceConfig {
  return {
    hostname: 'auth.test.local',
    port: 0,
    sessionSecret: 'test-session-secret',
    csrfSecret: 'test-csrf-secret',
    epdsCallbackSecret: 'test-callback-secret',
    pdsHostname: 'test.local',
    pdsPublicUrl: 'https://test.local',
    email: {
      provider: 'smtp',
      smtpHost: 'localhost',
      smtpPort: 1025,
      from: 'noreply@test.local',
      fromName: 'ePDS Test',
    },
    dbLocation: dbPath,
    otpLength: 6,
    otpCharset: 'numeric',
    trustedClients: [],
  }
}

async function startApp(ctx: AuthServiceContext): Promise<{
  baseUrl: string
  close: () => Promise<void>
}> {
  const app = express()
  // Silence sonar's "framework version disclosure" hotspot that fires
  // on any vanilla express() instance. This is an in-process test
  // server bound to 127.0.0.1 on an ephemeral port — the header is
  // only visible to the test runner — but disabling it keeps the
  // signal clean.
  app.disable('x-powered-by')
  app.use(cookieParser())
  app.use(csrfProtection(ctx.config.csrfSecret))
  app.use(createLoginPageRouter(ctx))
  const server = app.listen(0)
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.once('listening', () => {
      resolve()
    })
  })
  server.unref()
  const port = (server.address() as AddressInfo).port
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => {
          resolve()
        })
      }),
  }
}

describe('GET /oauth/authorize prompt=login handling (issue #138)', () => {
  let dbPath: string
  let ctx: AuthServiceContext
  let app: { baseUrl: string; close: () => Promise<void> }

  beforeEach(async () => {
    dbPath = path.join(
      os.tmpdir(),
      `prompt-login-${Date.now()}-${randomBytes(4).toString('hex')}.db`,
    )
    // Avoid an outbound fetch when the handler resolves client metadata.
    _seedClientMetadataCacheForTest('https://app.example.com', {
      client_name: 'Test App',
    })
    // AuthServiceContext opens its own EpdsDb against config.dbLocation;
    // we use ctx.db throughout (rather than constructing a parallel
    // instance and overwriting) so there's exactly one open SQLite handle
    // per test — `ctx.destroy()` in afterEach closes it cleanly and
    // releases the WAL/SHM companion files for the unlink to remove.
    ctx = new AuthServiceContext(makeConfig(dbPath))
    app = await startApp(ctx)
    mocks.fetchParLoginHint.mockReset()
    mocks.resolveLoginHint.mockReset()
    mocks.fetchDeviceAccountEmails.mockReset()
  })

  afterEach(async () => {
    await app.close()
    ctx.destroy()
    // Best-effort cleanup of the temp DB and its WAL/SHM companions.
    // SQLite in WAL mode writes alongside the main file; rmSync(force)
    // tolerates the missing companions when WAL was checkpointed before
    // close, and avoids the empty try/catch antipattern.
    for (const suffix of ['', '-wal', '-shm']) {
      fs.rmSync(dbPath + suffix, { force: true })
    }
  })

  it('renders the email step on the "Another account" rebind path', async () => {
    // pds-core's "Another account" rebind sets epds_skip_par_hint=1
    // and strips URL login_hint. Mock fetchParLoginHint to return a
    // value anyway so a regression that ignored the skip flag would
    // visibly pre-fill the email box with the previous user.
    mocks.fetchParLoginHint.mockResolvedValue('previous@example.com')
    mocks.resolveLoginHint.mockResolvedValue('previous@example.com')

    const url =
      app.baseUrl +
      '/oauth/authorize?request_uri=urn:ietf:params:oauth:request_uri:rebind' +
      '&client_id=' +
      encodeURIComponent('https://app.example.com') +
      '&prompt=login' +
      '&epds_skip_par_hint=1'
    const res = await fetch(url)
    expect(res.status).toBe(200)
    const html = await res.text()

    // PAR hint resolution is skipped: fetchParLoginHint must NOT be called.
    expect(mocks.fetchParLoginHint).not.toHaveBeenCalled()
    // Email step rendered, OTP step not active, input empty.
    expect(html).toMatch(/<div id="step-email" class="step-email">/)
    expect(html).not.toMatch(/class="step-otp active"/)
    expect(html).toMatch(/<input type="email" id="email"[^>]*value=""[^>]*>/)
  })

  it('honours PAR login_hint when prompt=login arrives without the skip flag', async () => {
    // pds-core's auth-ui-guard sign-in-view bounce appends prompt=login
    // (no epds_skip_par_hint) and expects auth-service to resolve any
    // PAR login_hint and serve the OTP step. A regression that
    // conflated prompt=login with the rebind semantics would re-break
    // the @session-reuse e2e scenario "login_hint narrows to a stale
    // binding on a multi-account device".
    mocks.fetchParLoginHint.mockResolvedValue('hinted@example.com')
    mocks.resolveLoginHint.mockResolvedValue('hinted@example.com')

    const url =
      app.baseUrl +
      '/oauth/authorize?request_uri=urn:ietf:params:oauth:request_uri:guardbounce' +
      '&prompt=login'
    const res = await fetch(url)
    expect(res.status).toBe(200)
    const html = await res.text()

    expect(mocks.fetchParLoginHint).toHaveBeenCalled()
    expect(mocks.resolveLoginHint).toHaveBeenCalled()
    expect(html).toMatch(/class="step-otp active"/)
  })

  it('still resolves login_hint when prompt=login is absent (regression guard)', async () => {
    // Without prompt=login at all, the hint must resolve normally and
    // the OTP step pre-fills with the email.
    mocks.resolveLoginHint.mockResolvedValue('user@example.com')

    const url =
      app.baseUrl +
      '/oauth/authorize?request_uri=urn:ietf:params:oauth:request_uri:nopromptlogin' +
      '&login_hint=user%40example.com'
    const res = await fetch(url)
    expect(res.status).toBe(200)
    const html = await res.text()

    expect(mocks.resolveLoginHint).toHaveBeenCalledWith(
      'user@example.com',
      expect.any(String),
      expect.any(String),
    )
    // OTP step is the active step (hasLoginHint true).
    expect(html).toMatch(/class="step-otp active"/)
  })
})
