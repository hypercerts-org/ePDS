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
 * The second describe covers the privacy rule for resolved hints: a
 * handle/DID `login_hint` resolves to the account's private email, which
 * must stay on the auth_flow row and never reach the rendered page.
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
  app.use(csrfProtection())
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

describe('GET /oauth/authorize never renders an email resolved from a handle/DID hint', () => {
  const REQUEST_URI = 'urn:ietf:params:oauth:request_uri:private-hint'
  const CLIENT_ID = 'https://app.example.com'
  let dbPath: string
  let ctx: AuthServiceContext
  let app: { baseUrl: string; close: () => Promise<void> }

  beforeEach(async () => {
    dbPath = path.join(
      os.tmpdir(),
      `private-hint-${Date.now()}-${randomBytes(4).toString('hex')}.db`,
    )
    _seedClientMetadataCacheForTest(CLIENT_ID, { client_name: 'Test App' })
    ctx = new AuthServiceContext(makeConfig(dbPath))
    app = await startApp(ctx)
    mocks.fetchParLoginHint.mockReset()
    mocks.resolveLoginHint.mockReset()
    mocks.fetchDeviceAccountEmails.mockReset()
  })

  afterEach(async () => {
    vi.restoreAllMocks()
    await app.close()
    ctx.destroy()
    for (const suffix of ['', '-wal', '-shm']) {
      fs.rmSync(dbPath + suffix, { force: true })
    }
  })

  function authorize(
    params: Record<string, string> = {},
    cookie?: string,
  ): Promise<Response> {
    const query = new URLSearchParams({
      request_uri: REQUEST_URI,
      client_id: CLIENT_ID,
      ...params,
    })
    return fetch(`${app.baseUrl}/oauth/authorize?${query.toString()}`, {
      headers: cookie ? { cookie } : {},
    })
  }

  /** The `epds_auth_flow=<id>` pair the page set, as a request cookie. */
  function flowCookie(res: Response): string {
    const match = /epds_auth_flow=[^;]+/.exec(
      res.headers.get('set-cookie') ?? '',
    )
    if (!match) throw new Error('response set no epds_auth_flow cookie')
    return match[0]
  }

  const flowIdOf = (cookie: string): string => cookie.split('=')[1]

  const privateAddresses = [
    ['alice.private@example.com', 'al***@example.com'],
    // A short local part is fully hidden: with the domain visible, any
    // visible prefix would reconstruct the address.
    ['a@mail.private.test', '***@mail.private.test'],
  ]

  const hintSources: Array<[string, () => Record<string, string>]> = [
    ['a handle in the URL', () => ({ login_hint: 'alice.test.local' })],
    ['a DID in the URL', () => ({ login_hint: 'did:plc:abc123' })],
    [
      'a handle only in the stored PAR request',
      () => {
        mocks.fetchParLoginHint.mockResolvedValue('alice.test.local')
        return {}
      },
    ],
  ]

  describe.each(privateAddresses)('account email %s', (email, masked) => {
    it.each(hintSources)(
      'is absent from the page for %s, and held on the flow row instead',
      async (_name, hint) => {
        mocks.resolveLoginHint.mockResolvedValue(email)

        const res = await authorize(hint())
        const html = await res.text()

        expect(res.status).toBe(200)
        expect(html.toLowerCase()).not.toContain(email)
        // OTP step is shown, driven by the server-held address.
        expect(html).toMatch(/class="step-otp active"/)
        expect(html).toContain('var useFlowEmail = true;')
        expect(html).toMatch(/<input type="email" id="email"[^>]*value=""/)
        expect(html).toMatch(
          /<input type="hidden" id="otp-email"[^>]*value="">/,
        )
        expect(html).toContain(
          `var flowEmailMasked = ${JSON.stringify(masked)};`,
        )
        expect(
          ctx.db.getAuthFlowLoginHintEmail(flowIdOf(flowCookie(res))),
        ).toBe(email)
      },
    )

    it('shows only the masked label on a duplicate load of the same flow', async () => {
      mocks.resolveLoginHint.mockResolvedValue(email)
      const first = await authorize({ login_hint: 'alice.test.local' })

      const second = await authorize(
        { login_hint: 'alice.test.local' },
        flowCookie(first),
      )
      const html = await second.text()

      expect(html).toContain(`Code already sent to ${masked}`)
      expect(html.toLowerCase()).not.toContain(email)
    })
  })

  it('still pre-fills an email hint, which the caller already knows', async () => {
    mocks.resolveLoginHint.mockResolvedValue('bob@example.com')

    const res = await authorize({ login_hint: 'bob@example.com' })
    const html = await res.text()

    expect(html).toMatch(
      /<input type="email" id="email"[^>]*value="bob@example\.com">/,
    )
    expect(html).toMatch(
      /<input type="hidden" id="otp-email"[^>]*value="bob@example\.com">/,
    )
    expect(html).toContain('var loginHint = "bob@example.com";')
    expect(html).toContain('var useFlowEmail = false;')
    expect(
      ctx.db.getAuthFlowLoginHintEmail(flowIdOf(flowCookie(res))),
    ).toBeNull()
  })

  it('uses the URL email hint over a handle in the stored PAR request', async () => {
    // Each hint resolves to a different account email, so the page and the
    // flow row show which hint won.
    mocks.fetchParLoginHint.mockResolvedValue('alice.test.local')
    mocks.resolveLoginHint.mockImplementation((hint: string) =>
      Promise.resolve(
        hint === 'alice.test.local' ? 'alice.private@example.com' : hint,
      ),
    )

    const res = await authorize({ login_hint: 'bob@example.com' })
    const html = await res.text()

    expect(html).toMatch(
      /<input type="email" id="email"[^>]*value="bob@example\.com">/,
    )
    expect(html).toContain('var useFlowEmail = false;')
    expect(html.toLowerCase()).not.toContain('alice.private@example.com')
    expect(
      ctx.db.getAuthFlowLoginHintEmail(flowIdOf(flowCookie(res))),
    ).toBeNull()
  })

  it('drops the stored email when the same flow is reopened without a hint', async () => {
    // "Another account" rebind: the user opted out of the RP's hint.
    mocks.resolveLoginHint.mockResolvedValue('alice.private@example.com')
    const first = await authorize({ login_hint: 'alice.test.local' })
    const cookie = flowCookie(first)
    expect(ctx.db.getAuthFlowLoginHintEmail(flowIdOf(cookie))).not.toBeNull()

    const second = await authorize(
      { prompt: 'login', epds_skip_par_hint: '1' },
      cookie,
    )
    const html = await second.text()

    expect(ctx.db.getAuthFlowLoginHintEmail(flowIdOf(cookie))).toBeNull()
    expect(html).toContain('var useFlowEmail = false;')
    expect(html).toMatch(/<div id="step-email" class="step-email">/)
  })

  it('fails closed when the stored email cannot be updated on a reused flow', async () => {
    mocks.resolveLoginHint.mockResolvedValue('alice.private@example.com')
    const first = await authorize({ login_hint: 'alice.test.local' })
    vi.spyOn(ctx.db, 'setAuthFlowLoginHintEmail').mockImplementation(() => {
      throw new Error('disk full')
    })

    const second = await authorize(
      { login_hint: 'alice.test.local' },
      flowCookie(first),
    )
    const html = await second.text()

    expect(second.status).toBe(500)
    expect(html).not.toContain('useFlowEmail')
    expect(html.toLowerCase()).not.toContain('alice.private@example.com')
  })
})
