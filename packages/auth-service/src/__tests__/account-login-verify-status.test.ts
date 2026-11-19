/**
 * POST /account/verify-otp maps the status of better-auth's refusal to the
 * message: only 400/401/403 mean the user's code was wrong, expired or used
 * up; a rate limit or server error must not be reported as a bad code.
 */
import type { AddressInfo } from 'node:net'
import cookieParser from 'cookie-parser'
import express from 'express'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { BetterAuthInstance } from '../better-auth.js'
import type { AuthServiceContext } from '../context.js'
import { csrfProtection } from '../middleware/csrf.js'
import { createAccountLoginRouter } from '../routes/account-login.js'

const ctx = {
  config: { otpLength: 6, otpCharset: 'numeric' },
} as unknown as AuthServiceContext

let close: (() => Promise<void>) | undefined

afterEach(async () => {
  await close?.()
  close = undefined
})

async function verifyWithStatus(
  status: number,
): Promise<{ status: number; html: string; location: string | null }> {
  const auth = {
    api: {
      signInEmailOTP: vi.fn(() =>
        Promise.resolve(
          status < 400
            ? new Response('{}', { status, headers: { 'set-cookie': 'a=b' } })
            : Response.json({ message: 'x' }, { status }),
        ),
      ),
    },
  } as unknown as BetterAuthInstance
  const app = express()
  app.disable('x-powered-by')
  app.use(cookieParser())
  app.use(express.urlencoded({ extended: false }))
  app.use(csrfProtection())
  app.use(createAccountLoginRouter(auth, ctx))
  const server = app.listen(0, '127.0.0.1')
  await new Promise<void>((resolve) => {
    server.once('listening', () => {
      resolve()
    })
  })
  server.unref()
  close = () =>
    new Promise<void>((resolve) => {
      server.close(() => {
        resolve()
      })
    })
  const csrf = 'c'.repeat(64)
  const res = await fetch(
    `http://127.0.0.1:${(server.address() as AddressInfo).port}/account/verify-otp`,
    {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: `epds_csrf=${csrf}`,
      },
      body: new URLSearchParams({
        email: 'alice@example.com',
        otp: '123456',
        csrf,
      }),
    },
  )
  return {
    status: res.status,
    html: await res.text(),
    location: res.headers.get('location'),
  }
}

describe('POST /account/verify-otp refusal messages', () => {
  it.each([400, 401, 403])('says the code is invalid for %i', async (s) => {
    const r = await verifyWithStatus(s)
    expect(r.status).toBe(200)
    expect(r.html).toContain('Invalid or expired code')
  })

  it.each([429, 500])('does not blame the code for %i', async (s) => {
    const r = await verifyWithStatus(s)
    expect(r.status).toBe(200)
    expect(r.html).toContain('Verification failed')
    expect(r.html).not.toContain('Invalid or expired code')
  })

  it('redirects to /account on success', async () => {
    const r = await verifyWithStatus(200)
    expect(r.status).toBe(303)
    expect(r.location).toBe('/account')
  })
})
