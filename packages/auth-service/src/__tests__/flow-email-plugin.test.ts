/**
 * Unit tests for the `onRequest` hook that substitutes an auth_flow's stored
 * email into the OTP endpoints' request body (lib/flow-email-plugin.ts).
 *
 * These drive the hook directly with real Request objects and a real
 * SQLite-backed EpdsDb. That the hook actually runs inside better-auth's
 * router, ahead of its rate limiter, is covered separately in
 * flow-email-router.test.ts.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { randomBytes } from 'node:crypto'
import { EpdsDb } from '@certified-app/shared'
import {
  FLOW_EMAIL_UNAVAILABLE_CODE,
  createFlowEmailHook,
} from '../lib/flow-email-plugin.js'

const BASE_URL = 'https://auth.test.local/api/auth'
const CTX = { baseURL: BASE_URL }
const SEND_PATH = '/email-otp/send-verification-otp'
const VERIFY_PATH = '/sign-in/email-otp'
const FLOW_EMAIL = 'alice.private@example.com'

function post(
  routePath: string,
  body: unknown,
  headers: Record<string, string> = {},
): Request {
  const raw = typeof body === 'string' ? body : JSON.stringify(body)
  return new Request(BASE_URL + routePath, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(raw)),
      ...headers,
    },
    body: raw,
  })
}

describe('flow-email onRequest hook', () => {
  let db: EpdsDb
  let dbPath: string
  let hook: ReturnType<typeof createFlowEmailHook>

  function seedFlow(
    flowId: string,
    opts: { email?: string | null; expiresAt?: number } = {},
  ): void {
    db.createAuthFlow({
      flowId,
      requestUri: `urn:ietf:params:oauth:request_uri:${flowId}`,
      clientId: null,
      loginHintEmail: opts.email === undefined ? FLOW_EMAIL : opts.email,
      expiresAt: opts.expiresAt ?? Date.now() + 600_000,
    })
  }

  beforeEach(() => {
    dbPath = path.join(
      os.tmpdir(),
      `flow-email-plugin-${Date.now()}-${randomBytes(4).toString('hex')}.db`,
    )
    db = new EpdsDb(dbPath)
    hook = createFlowEmailHook(db)
  })

  afterEach(() => {
    db.close()
    for (const suffix of ['', '-wal', '-shm']) {
      fs.rmSync(dbPath + suffix, { force: true })
    }
  })

  describe('substituting the stored email', () => {
    it.each([SEND_PATH, VERIFY_PATH])(
      'injects the flow email into %s and drops the flag',
      async (routePath) => {
        seedFlow('flow-1')
        const original = post(
          routePath,
          { useFlowEmail: true, type: 'sign-in', otp: '123456' },
          { cookie: 'a=b; epds_auth_flow=flow-1; c=d', origin: 'https://x.y' },
        )

        const result = await hook(original, CTX)

        expect(result).toBeDefined()
        const rewritten = (result as { request: Request }).request
        expect(await rewritten.json()).toEqual({
          type: 'sign-in',
          otp: '123456',
          email: FLOW_EMAIL,
        })
        // Everything better-auth's later stages look at is carried over.
        expect(rewritten.method).toBe('POST')
        expect(rewritten.url).toBe(original.url)
        expect(rewritten.headers.get('cookie')).toBe(
          'a=b; epds_auth_flow=flow-1; c=d',
        )
        expect(rewritten.headers.get('origin')).toBe('https://x.y')
        expect(rewritten.headers.get('content-type')).toBe('application/json')
        // The body length changed, so the stale length must not survive.
        expect(rewritten.headers.get('content-length')).toBeNull()
      },
    )

    it('does not depend on a content-length header', async () => {
      // A proxy may drop it, and the page's bodies are tiny either way.
      seedFlow('flow-chunked')
      const request = post(
        SEND_PATH,
        { useFlowEmail: true, type: 'sign-in' },
        { cookie: 'epds_auth_flow=flow-chunked' },
      )
      request.headers.delete('content-length')

      const result = await hook(request, CTX)

      expect(await (result as { request: Request }).request.json()).toEqual({
        type: 'sign-in',
        email: FLOW_EMAIL,
      })
    })

    it('accepts the JSON content type in any case, with parameters', async () => {
      seedFlow('flow-ct')
      const result = await hook(
        post(
          SEND_PATH,
          { useFlowEmail: true },
          {
            cookie: 'epds_auth_flow=flow-ct',
            'content-type': 'Application/JSON; charset=UTF-8',
          },
        ),
        CTX,
      )
      expect(result).toHaveProperty('request')
    })
  })

  describe('when the server holds no email for the sign-in', () => {
    async function expectUnavailable(request: Request): Promise<void> {
      const result = await hook(request, CTX)
      expect(result).toHaveProperty('response')
      const response = (result as { response: Response }).response
      expect(response.status).toBe(400)
      expect(response.headers.get('content-type')).toContain('application/json')
      const body = (await response.json()) as { code: string; message: string }
      expect(body.code).toBe(FLOW_EMAIL_UNAVAILABLE_CODE)
      // The page shows `message` as-is, so it has to tell the user what to do.
      expect(body.message).toMatch(/enter your email/i)
      expect(JSON.stringify(body)).not.toContain(FLOW_EMAIL)
    }

    it('rejects a request with no cookie header', async () => {
      seedFlow('flow-1')
      await expectUnavailable(post(SEND_PATH, { useFlowEmail: true }))
    })

    it('rejects a request whose cookie is not the auth_flow cookie', async () => {
      seedFlow('flow-1')
      await expectUnavailable(
        post(SEND_PATH, { useFlowEmail: true }, { cookie: 'session=flow-1' }),
      )
    })

    it('rejects an unknown flow id', async () => {
      seedFlow('flow-1')
      await expectUnavailable(
        post(
          VERIFY_PATH,
          { useFlowEmail: true },
          { cookie: 'epds_auth_flow=nope' },
        ),
      )
    })

    it('rejects an expired flow even though the row still holds an email', async () => {
      seedFlow('flow-old', { expiresAt: Date.now() - 1000 })
      await expectUnavailable(
        post(
          SEND_PATH,
          { useFlowEmail: true },
          { cookie: 'epds_auth_flow=flow-old' },
        ),
      )
    })

    it('rejects a duplicated flow cookie rather than guessing which one counts', async () => {
      // better-auth's parser would take the last value, cookie-parser (which
      // /auth/complete uses) the first. Both flows are valid here, so
      // picking either would act on a flow the rest of the app disagrees on.
      seedFlow('flow-1', { email: 'one@example.com' })
      seedFlow('flow-2', { email: 'two@example.com' })
      await expectUnavailable(
        post(
          SEND_PATH,
          { useFlowEmail: true },
          { cookie: 'epds_auth_flow=flow-1; epds_auth_flow=flow-2' },
        ),
      )
    })

    it('counts a duplicate whose cookie name has stray whitespace, as cookie-parser does', async () => {
      // cookie-parser trims names, so `epds_auth_flow =flow-1` is the same
      // cookie to /auth/complete; the hook must see two, not one.
      seedFlow('flow-1', { email: 'one@example.com' })
      seedFlow('flow-2', { email: 'two@example.com' })
      await expectUnavailable(
        post(
          SEND_PATH,
          { useFlowEmail: true },
          { cookie: 'epds_auth_flow =flow-1; epds_auth_flow=flow-2' },
        ),
      )
    })

    it('rejects a live flow that has no stored email', async () => {
      seedFlow('flow-bare', { email: null })
      await expectUnavailable(
        post(
          SEND_PATH,
          { useFlowEmail: true },
          { cookie: 'epds_auth_flow=flow-bare' },
        ),
      )
    })
  })

  it('answers 500 itself when the flow lookup throws, since better-auth would not catch it', async () => {
    const failing = createFlowEmailHook({
      getAuthFlowLoginHintEmail: () => {
        throw new Error('database is locked')
      },
    })

    const result = await failing(
      post(
        SEND_PATH,
        { useFlowEmail: true },
        { cookie: 'epds_auth_flow=flow-1' },
      ),
      CTX,
    )

    expect((result as { response: Response }).response.status).toBe(500)
  })

  describe('requests it must leave alone', () => {
    const cookie = { cookie: 'epds_auth_flow=flow-1' }

    beforeEach(() => {
      seedFlow('flow-1')
    })

    /** The hook declined, and the body is still intact for better-auth. */
    async function expectPassThrough(
      request: Request,
      expectedBody: string,
    ): Promise<void> {
      expect(await hook(request, CTX)).toBeUndefined()
      expect(await request.text()).toBe(expectedBody)
    }

    it('never overrides an email the browser supplied', async () => {
      const raw = JSON.stringify({
        useFlowEmail: true,
        email: 'typed@example.com',
        type: 'sign-in',
      })
      await expectPassThrough(post(SEND_PATH, raw, cookie), raw)
    })

    it('does not treat an empty email as absent', async () => {
      const raw = JSON.stringify({ useFlowEmail: true, email: '' })
      await expectPassThrough(post(VERIFY_PATH, raw, cookie), raw)
    })

    it('ignores bodies without useFlowEmail: true', async () => {
      for (const body of [
        { email: 'typed@example.com', type: 'sign-in' },
        { type: 'sign-in' },
        { useFlowEmail: false },
        { useFlowEmail: 'true' },
      ]) {
        const raw = JSON.stringify(body)
        await expectPassThrough(post(SEND_PATH, raw, cookie), raw)
      }
    })

    it('ignores other better-auth endpoints', async () => {
      const raw = JSON.stringify({ useFlowEmail: true })
      await expectPassThrough(
        post('/email-otp/check-verification-otp', raw, cookie),
        raw,
      )
      await expectPassThrough(post('/sign-in/social', raw, cookie), raw)
    })

    it('matches the endpoint paths exactly, which better-auth also does', async () => {
      const raw = JSON.stringify({ useFlowEmail: true })
      await expectPassThrough(post(VERIFY_PATH + '/', raw, cookie), raw)
    })

    it('ignores paths outside the better-auth base path', async () => {
      const raw = JSON.stringify({ useFlowEmail: true })
      const request = new Request(
        'https://auth.test.local/elsewhere' + VERIFY_PATH,
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'content-length': String(raw.length),
            ...cookie,
          },
          body: raw,
        },
      )
      await expectPassThrough(request, raw)
    })

    it('ignores non-POST methods', async () => {
      const request = new Request(BASE_URL + SEND_PATH, {
        method: 'GET',
        headers: cookie,
      })
      expect(await hook(request, CTX)).toBeUndefined()
    })

    const useFlowEmailBody = JSON.stringify({ useFlowEmail: true })

    it('ignores a non-JSON content type', async () => {
      const request = post(SEND_PATH, useFlowEmailBody, {
        ...cookie,
        'content-type': 'text/plain',
      })
      await expectPassThrough(request, useFlowEmailBody)
    })

    it('ignores a body over the size cap, leaving it fully readable', async () => {
      // The hook runs before the rate limiter, so it must not buffer a
      // large body from an unauthenticated caller. Declining must not
      // disturb the body better-auth is about to read.
      const raw = JSON.stringify({ useFlowEmail: true, pad: 'x'.repeat(5000) })
      await expectPassThrough(post(SEND_PATH, raw, cookie), raw)
    })

    it.each(['not json', '[1,2]', 'null', '"str"'])(
      'ignores a body that is not a JSON object (%s)',
      async (raw) => {
        await expectPassThrough(post(SEND_PATH, raw, cookie), raw)
      },
    )
  })
})
