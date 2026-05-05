import { randomBytes } from 'node:crypto'
import type { AddressInfo } from 'node:net'
import express from 'express'
import cookieParser from 'cookie-parser'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { HandleMode } from '@certified-app/shared'
import type { AuthServiceContext } from '../context.js'
import { createChooseHandleRouter } from '../routes/choose-handle.js'
import { createCompleteRouter } from '../routes/complete.js'

const mocks = vi.hoisted(() => ({
  getDidByEmail: vi.fn(),
  pingParRequest: vi.fn(),
  resolveRecoveryEmail: vi.fn(),
  resolveClientBranding: vi.fn(),
}))

vi.mock('../lib/get-did-by-email.js', () => ({
  getDidByEmail: mocks.getDidByEmail,
}))

vi.mock('../lib/ping-par-request.js', () => ({
  pingParRequest: mocks.pingParRequest,
}))

vi.mock('../lib/resolve-recovery-email.js', () => ({
  resolveRecoveryEmail: mocks.resolveRecoveryEmail,
}))

vi.mock('../lib/client-metadata.js', () => ({
  resolveClientBranding: mocks.resolveClientBranding,
}))

const AUTH_FLOW_COOKIE = 'epds_auth_flow'
const realFetch = globalThis.fetch.bind(globalThis)

function makeCtx(handleMode: HandleMode | null): AuthServiceContext {
  return {
    config: {
      pdsPublicUrl: 'https://pds.example',
      pdsHostname: 'pds.example',
      epdsCallbackSecret: 'test-callback-secret',
      trustedClients: [],
    },
    db: {
      getAuthFlow: vi.fn(() => ({
        flowId: 'flow-1',
        requestUri: 'urn:ietf:params:oauth:request_uri:req-123',
        clientId: 'https://app.example/client.json',
        handleMode,
      })),
      deleteAuthFlow: vi.fn(),
    },
  } as unknown as AuthServiceContext
}

function makeAuth() {
  return {
    api: {
      getSession: vi.fn(() =>
        Promise.resolve({ user: { email: 'Alice@example.com' } }),
      ),
    },
  }
}

async function startApp(
  ctx: AuthServiceContext,
  auth: ReturnType<typeof makeAuth>,
): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  const app = express()
  app.disable('x-powered-by')
  app.use(cookieParser())
  app.use(express.urlencoded({ extended: false }))
  app.use(createCompleteRouter(ctx, auth))
  app.use(createChooseHandleRouter(ctx, auth))

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

function parseRedirect(res: globalThis.Response): URL {
  const location = res.headers.get('location')
  if (!location) throw new Error('Missing redirect location')
  return new URL(location)
}

function normalizeFetchUrl(input: Parameters<typeof fetch>[0]): URL {
  if (input instanceof URL) return input
  if (typeof input === 'string') return new URL(input)
  return new URL(input.url)
}

describe('auth-service epds-callback handle mode threading', () => {
  let priorEnv: { pdsInternalUrl?: string; internalSecret?: string }

  beforeEach(() => {
    priorEnv = {
      pdsInternalUrl: process.env.PDS_INTERNAL_URL,
      internalSecret: process.env.EPDS_INTERNAL_SECRET,
    }
    process.env.PDS_INTERNAL_URL = 'http://pds.internal' // NOSONAR test-only internal mocked URL
    process.env.EPDS_INTERNAL_SECRET = 'test-internal-secret'
    mocks.getDidByEmail.mockReset()
    mocks.pingParRequest.mockReset()
    mocks.resolveRecoveryEmail.mockReset()
    mocks.resolveClientBranding.mockReset()
    mocks.pingParRequest.mockResolvedValue({ ok: true })
    mocks.resolveRecoveryEmail.mockResolvedValue(null)
    mocks.resolveClientBranding.mockResolvedValue({
      customCss: null,
      customFaviconUrl: null,
      customFaviconUrlDark: null,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
        const url = normalizeFetchUrl(input)
        if (url.hostname === '127.0.0.1') return realFetch(input, init)
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ exists: false }),
        })
      }),
    )
  })

  afterEach(() => {
    if (priorEnv.pdsInternalUrl === undefined)
      delete process.env.PDS_INTERNAL_URL
    else process.env.PDS_INTERNAL_URL = priorEnv.pdsInternalUrl
    if (priorEnv.internalSecret === undefined)
      delete process.env.EPDS_INTERNAL_SECRET
    else process.env.EPDS_INTERNAL_SECRET = priorEnv.internalSecret
    vi.unstubAllGlobals()
  })

  it('includes the stored canonical handle mode for random-mode new users', async () => {
    mocks.getDidByEmail.mockResolvedValue(null)
    const app = await startApp(makeCtx('random'), makeAuth())
    try {
      const res = await fetch(`${app.baseUrl}/auth/complete`, {
        redirect: 'manual',
        headers: { cookie: `${AUTH_FLOW_COOKIE}=flow-1` },
      })

      expect(res.status).toBe(303)
      const url = parseRedirect(res)
      expect(url.pathname).toBe('/oauth/epds-callback')
      expect(url.searchParams.get('epds_handle_mode')).toBe('random')
      expect(url.searchParams.has('handle')).toBe(false)
    } finally {
      await app.close()
    }
  })

  it('includes the stored canonical handle mode for existing users', async () => {
    mocks.getDidByEmail.mockResolvedValue(randomBytes(16).toString('hex'))
    const app = await startApp(makeCtx('picker-with-random'), makeAuth())
    try {
      const res = await fetch(`${app.baseUrl}/auth/complete`, {
        redirect: 'manual',
        headers: { cookie: `${AUTH_FLOW_COOKIE}=flow-1` },
      })

      expect(res.status).toBe(303)
      const url = parseRedirect(res)
      expect(url.pathname).toBe('/oauth/epds-callback')
      expect(url.searchParams.get('epds_handle_mode')).toBe(
        'picker-with-random',
      )
    } finally {
      await app.close()
    }
  })

  it('includes the stored canonical handle mode for chosen-handle callbacks', async () => {
    mocks.getDidByEmail.mockResolvedValue(null)
    const app = await startApp(makeCtx('picker'), makeAuth())
    try {
      const res = await fetch(`${app.baseUrl}/auth/choose-handle`, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          cookie: `${AUTH_FLOW_COOKIE}=flow-1`,
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ handle: 'Alice1' }),
      })

      expect(res.status).toBe(303)
      const url = parseRedirect(res)
      expect(url.pathname).toBe('/oauth/epds-callback')
      expect(url.searchParams.get('epds_handle_mode')).toBe('picker')
      expect(url.searchParams.get('handle')).toBe('alice1')
    } finally {
      await app.close()
    }
  })
})
