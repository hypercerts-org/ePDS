/**
 * The flow-email hook through better-auth's real HTTP router.
 *
 * flow-email-plugin.test.ts proves what the hook does to a Request; this file
 * proves the pieces that only exist once better-auth is in the loop:
 *
 * - the production instance (`createBetterAuth`) has the plugin registered,
 *   so a page that sends `useFlowEmail` gets an OTP mailed to the address
 *   stored on its auth_flow row and can sign in with it, session cookie
 *   included;
 * - the hook runs before better-auth's rate limiter, and the rewritten
 *   request is still rate limited per IP and path.
 *
 * Both go through `toNodeHandler` on an Express app, exactly as index.ts
 * mounts better-auth.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import express from 'express'
import Database from 'better-sqlite3'
import { betterAuth } from 'better-auth'
import { emailOTP } from 'better-auth/plugins'
import { toNodeHandler } from 'better-auth/node'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { randomBytes } from 'node:crypto'
import type { AddressInfo } from 'node:net'
import { EpdsDb } from '@certified-app/shared'
import { createBetterAuth, runBetterAuthMigrations } from '../better-auth.js'
import { flowEmailPlugin } from '../lib/flow-email-plugin.js'
import type { EmailSender } from '../email/sender.js'

// sendVerificationOTP asks pds-core whether the address belongs to an
// existing account; there is no pds-core here, so every address is new.
vi.mock('../lib/get-did-by-email.js', () => ({
  getDidByEmail: vi.fn().mockResolvedValue(null),
}))

const AUTH_HOSTNAME = 'auth.test.local'
const ORIGIN = `https://${AUTH_HOSTNAME}`
const FLOW_EMAIL = 'alice.private@example.com'
const FLOW_ID = 'flow-router-test'

interface TestServer {
  url: string
  close: () => Promise<void>
}

async function serve(
  auth: Parameters<typeof toNodeHandler>[0],
): Promise<TestServer> {
  const app = express()
  app.disable('x-powered-by')
  app.all('/api/auth/*', toNodeHandler(auth))
  const server = app.listen(0)
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.once('listening', () => {
      resolve()
    })
  })
  server.unref()
  const { port } = server.address() as AddressInfo
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => {
          resolve()
        })
      }),
  }
}

/** POST JSON as the login page's fetch() would: same-origin, with the flow cookie. */
function postJson(
  server: TestServer,
  routePath: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<Response> {
  return fetch(`${server.url}/api/auth${routePath}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: ORIGIN,
      cookie: `epds_auth_flow=${FLOW_ID}`,
      ...headers,
    },
    body: JSON.stringify(body),
  })
}

describe('flow-email hook inside better-auth', () => {
  let dbPath: string
  let db: EpdsDb
  let server: TestServer | undefined
  const sendOtpCode = vi.fn()

  beforeEach(async () => {
    dbPath = path.join(
      os.tmpdir(),
      `flow-email-router-${Date.now()}-${randomBytes(4).toString('hex')}.db`,
    )
    vi.stubEnv('DB_LOCATION', dbPath)
    vi.stubEnv('AUTH_HOSTNAME', AUTH_HOSTNAME)
    vi.stubEnv('AUTH_SESSION_SECRET', 'router-test-session-secret-0123456789')
    sendOtpCode.mockReset().mockResolvedValue(undefined)

    db = new EpdsDb(dbPath)
    await runBetterAuthMigrations(dbPath, AUTH_HOSTNAME, 6)
    db.createAuthFlow({
      flowId: FLOW_ID,
      requestUri: 'urn:ietf:params:oauth:request_uri:router-test',
      clientId: null,
      loginHintEmail: FLOW_EMAIL,
      expiresAt: Date.now() + 600_000,
    })
  })

  afterEach(async () => {
    await server?.close()
    server = undefined
    db.close()
    vi.unstubAllEnvs()
    for (const suffix of ['', '-wal', '-shm']) {
      fs.rmSync(dbPath + suffix, { force: true })
    }
  })

  describe('production instance (createBetterAuth)', () => {
    beforeEach(async () => {
      const auth = createBetterAuth(
        { sendOtpCode } as unknown as EmailSender,
        db,
        6,
      )
      server = await serve(auth)
    })

    it('mails the OTP to the flow email, and the same code signs the user in', async () => {
      const sent = await postJson(server!, '/email-otp/send-verification-otp', {
        useFlowEmail: true,
        type: 'sign-in',
      })
      expect(sent.status).toBe(200)
      expect(sendOtpCode).toHaveBeenCalledTimes(1)
      const { to, code } = sendOtpCode.mock.calls[0][0] as {
        to: string
        code: string
      }
      expect(to).toBe(FLOW_EMAIL)

      const verified = await postJson(server!, '/sign-in/email-otp', {
        useFlowEmail: true,
        otp: code,
      })
      expect(verified.status).toBe(200)
      // Reaching better-auth's own handler means its Set-Cookie still applies.
      expect(verified.headers.get('set-cookie')).toMatch(/session_token=/)
      const session = (await verified.json()) as { user: { email: string } }
      expect(session.user.email).toBe(FLOW_EMAIL)
    })

    it('never overrides an email the browser sends', async () => {
      const sent = await postJson(server!, '/email-otp/send-verification-otp', {
        useFlowEmail: true,
        email: 'typed@example.com',
        type: 'sign-in',
      })
      expect(sent.status).toBe(200)
      expect((sendOtpCode.mock.calls[0][0] as { to: string }).to).toBe(
        'typed@example.com',
      )
    })

    it('answers 400 with a message the page can show when the flow has no email', async () => {
      const res = await postJson(
        server!,
        '/email-otp/send-verification-otp',
        { useFlowEmail: true, type: 'sign-in' },
        { cookie: 'epds_auth_flow=some-other-flow' },
      )
      expect(res.status).toBe(400)
      const body = (await res.json()) as { code: string; message: string }
      expect(body.code).toBe('EPDS_FLOW_EMAIL_UNAVAILABLE')
      expect(body.message).toMatch(/enter your email/i)
      expect(sendOtpCode).not.toHaveBeenCalled()
    })

    it('hands better-auth an intact body when the hook declined to buffer it', async () => {
      // Over the hook's read cap: it stops reading its clone, and the real
      // Node request stream behind the original must still be fully readable.
      const sent = await postJson(server!, '/email-otp/send-verification-otp', {
        email: 'typed@example.com',
        type: 'sign-in',
        padding: 'x'.repeat(6000),
      })
      expect(sent.status).toBe(200)
      expect((sendOtpCode.mock.calls[0][0] as { to: string }).to).toBe(
        'typed@example.com',
      )
    })

    it('leaves ordinary typed-email requests alone', async () => {
      const sent = await postJson(server!, '/email-otp/send-verification-otp', {
        email: 'typed@example.com',
        type: 'sign-in',
      })
      expect(sent.status).toBe(200)
      expect((sendOtpCode.mock.calls[0][0] as { to: string }).to).toBe(
        'typed@example.com',
      )
    })
  })

  describe('with better-auth rate limiting enabled', () => {
    // createBetterAuth leaves rate limiting at better-auth's default
    // (production only), so build an instance with the same plugin and the
    // limiter forced on.
    beforeEach(async () => {
      const auth = betterAuth({
        secret: process.env.AUTH_SESSION_SECRET,
        // TS4058 workaround, as in better-auth.ts: the better-sqlite3 type
        // must not leak into the inferred instance type.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        database: new Database(dbPath) as any,
        baseURL: ORIGIN,
        basePath: '/api/auth',
        rateLimit: { enabled: true, storage: 'memory' },
        plugins: [
          flowEmailPlugin(db),
          emailOTP({
            otpLength: 6,
            async sendVerificationOTP() {},
          }),
        ],
      })
      server = await serve(auth)
    })

    it('still rate limits requests whose email the hook injected', async () => {
      // better-auth allows 3 sign-in requests per 10s per IP and path. A
      // unique forwarded IP keeps this key out of other tests' buckets.
      const headers = { 'x-forwarded-for': '203.0.113.77' }
      const statuses: number[] = []
      const messages: string[] = []
      for (let i = 0; i < 4; i++) {
        const res = await postJson(
          server!,
          '/sign-in/email-otp',
          { useFlowEmail: true, otp: '000000' },
          headers,
        )
        statuses.push(res.status)
        messages.push(((await res.json()) as { message: string }).message)
      }

      // The first three reached the OTP endpoint with the injected email
      // (better-auth's own wrong-code error, not the hook's 400 / "enter
      // your email" message); the fourth was stopped by the limiter.
      expect(statuses).toEqual([400, 400, 400, 429])
      expect(messages.slice(0, 3)).toEqual([
        'Invalid OTP',
        'Invalid OTP',
        'Invalid OTP',
      ])
      expect(messages[3]).toMatch(/too many requests/i)
    })
  })
})
