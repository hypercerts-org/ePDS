/**
 * Account settings act on the PDS account that owns the session's email,
 * so a better-auth session whose email is not verified (a social sign-in
 * the provider did not vouch for) must count as signed out there.
 */
import type { AddressInfo } from 'node:net'
import cookieParser from 'cookie-parser'
import express from 'express'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { BetterAuthInstance } from '../better-auth.js'
import type { AuthServiceContext } from '../context.js'
import { csrfProtection } from '../middleware/csrf.js'
import { createAccountLoginRouter } from '../routes/account-login.js'
import { createAccountSettingsRouter } from '../routes/account-settings.js'

const mocks = vi.hoisted(() => ({ getDidByEmail: vi.fn() }))

vi.mock('../lib/get-did-by-email.js', () => ({
  getDidByEmail: mocks.getDidByEmail,
}))

const ctx = {
  config: {
    pdsPublicUrl: 'https://pds.example',
    pdsHostname: 'pds.example',
    otpLength: 6,
    otpCharset: 'numeric',
  },
} as unknown as AuthServiceContext

function makeAuth(user: Record<string, unknown>) {
  return {
    api: {
      getSession: vi.fn(() =>
        Promise.resolve({ user, session: { token: 'session-token' } }),
      ),
      listSessions: vi.fn(() => Promise.resolve([])),
    },
  }
}

let close: (() => Promise<void>) | undefined

afterEach(async () => {
  await close?.()
  close = undefined
  mocks.getDidByEmail.mockReset()
})

async function get(
  auth: ReturnType<typeof makeAuth>,
  path: string,
): Promise<globalThis.Response> {
  const app = express()
  app.disable('x-powered-by')
  app.use(cookieParser())
  app.use(csrfProtection())
  app.use(createAccountLoginRouter(auth as unknown as BetterAuthInstance, ctx))
  app.use(createAccountSettingsRouter(ctx, auth))
  const server = app.listen(0)
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
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
  const port = (server.address() as AddressInfo).port
  return fetch(`http://127.0.0.1:${port}${path}`, { redirect: 'manual' })
}

describe('account settings with an unverified session', () => {
  const unverified = { email: 'alice@example.com', emailVerified: false }

  it('GET /account sends it to /account/login', async () => {
    const res = await get(makeAuth(unverified), '/account')
    expect(res.status).toBe(303)
    expect(res.headers.get('location')).toBe('/account/login')
    expect(mocks.getDidByEmail).not.toHaveBeenCalled()
  })

  it('GET /account/login shows the sign-in form instead of looping', async () => {
    const res = await get(makeAuth(unverified), '/account/login')
    expect(res.status).toBe(200)
  })

  it('GET /account/login still forwards a verified session', async () => {
    const res = await get(
      makeAuth({ email: 'alice@example.com', emailVerified: true }),
      '/account/login',
    )
    expect(res.status).toBe(303)
    expect(res.headers.get('location')).toBe('/account')
  })
})
