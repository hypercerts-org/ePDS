/**
 * The OpenStreetMap section of account settings, through the real router
 * on an ephemeral Express server with better-auth's API mocked: the
 * section only shows when OpenStreetMap is configured, Connect hands the
 * browser to OpenStreetMap with better-auth's state cookie, and
 * Disconnect unlinks the account row.
 */
import type { AddressInfo } from 'node:net'
import cookieParser from 'cookie-parser'
import express from 'express'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { genericOAuthProviders } from '../better-auth.js'
import type { AuthServiceContext } from '../context.js'
import { csrfProtection } from '../middleware/csrf.js'
import { createAccountSettingsRouter } from '../routes/account-settings.js'

vi.mock('../lib/get-did-by-email.js', () => ({
  getDidByEmail: vi.fn(() => Promise.resolve(null)),
}))

const ctx = {
  config: { pdsPublicUrl: 'https://pds.example', pdsHostname: 'pds.example' },
} as unknown as AuthServiceContext

const OSM_URL = 'https://www.openstreetmap.org/oauth2/authorize?state=s'
const CSRF = 'a'.repeat(64)

function makeAuth(accounts: unknown[] = []) {
  return {
    api: {
      getSession: vi.fn(() =>
        Promise.resolve({
          user: { id: 'u1', email: 'alice@example.com', emailVerified: true },
          session: { token: 'session-token' },
        }),
      ),
      listSessions: vi.fn(() => Promise.resolve([])),
      listUserAccounts: vi.fn(() => Promise.resolve(accounts)),
      linkSocialAccount: vi.fn(() =>
        Promise.resolve({
          headers: new Headers([
            ['set-cookie', 'better-auth.state=st; Path=/; HttpOnly'],
          ]),
          response: { url: OSM_URL, redirect: false },
        }),
      ),
      unlinkAccount: vi.fn(() => Promise.resolve({ status: true })),
    },
  }
}

const LINKED = [
  {
    id: 'row-1',
    providerId: 'openstreetmap',
    accountId: 'www.openstreetmap.org:1001',
  },
  { id: 'row-2', providerId: 'google', accountId: 'g' },
]

let close: (() => Promise<void>) | undefined

beforeEach(() => {
  genericOAuthProviders.openstreetmap = {
    providerId: 'openstreetmap',
    clientId: 'osm-id',
  }
})

afterEach(async () => {
  await close?.()
  close = undefined
  delete genericOAuthProviders.openstreetmap
})

async function request(
  auth: ReturnType<typeof makeAuth>,
  path: string,
  method: 'GET' | 'POST' = 'GET',
): Promise<globalThis.Response> {
  const app = express()
  app.disable('x-powered-by')
  app.use(cookieParser())
  app.use(express.urlencoded({ extended: false }))
  app.use(csrfProtection())
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
  return fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    redirect: 'manual',
    headers: { cookie: `epds_csrf=${CSRF}`, 'x-csrf-token': CSRF },
  })
}

describe('GET /account OpenStreetMap section', () => {
  it('is absent when OpenStreetMap is not configured', async () => {
    delete genericOAuthProviders.openstreetmap
    const html = await (await request(makeAuth(), '/account')).text()
    expect(html).not.toContain('<h2>OpenStreetMap</h2>')
  })

  it('offers Connect when no identity is linked', async () => {
    const html = await (await request(makeAuth(), '/account')).text()
    expect(html).toContain('<h2>OpenStreetMap</h2>')
    expect(html).toContain('action="/account/openstreetmap/connect"')
    expect(html).not.toContain('Disconnect')
  })

  it('shows the linked OpenStreetMap user and offers Disconnect', async () => {
    const html = await (await request(makeAuth(LINKED), '/account')).text()
    expect(html).toContain(
      'Connected as OpenStreetMap user <code>1001</code> on www.openstreetmap.org',
    )
    expect(html).toContain('action="/account/openstreetmap/disconnect"')
  })

  it('shows a fixed notice for a known ?osm= and reflects nothing else', async () => {
    const ok = await (
      await request(makeAuth(), '/account?osm=connected')
    ).text()
    expect(ok).toContain('<p class="success">OpenStreetMap connected.</p>')
    const junk = await (
      await request(makeAuth(), '/account?osm=%3Cscript%3Ex%3C/script%3E')
    ).text()
    expect(junk).not.toContain('<script>x')
    expect(junk).not.toContain('class="success"')
  })
})

describe('POST /account/openstreetmap/connect', () => {
  it('starts a link and sends the browser to OpenStreetMap with the state cookie', async () => {
    const auth = makeAuth()
    const res = await request(auth, '/account/openstreetmap/connect', 'POST')
    expect(res.status).toBe(303)
    expect(res.headers.get('location')).toBe(OSM_URL)
    expect(res.headers.getSetCookie().join('\n')).toContain(
      'better-auth.state=st',
    )
    expect(auth.api.linkSocialAccount).toHaveBeenCalledWith(
      expect.objectContaining({
        body: {
          provider: 'openstreetmap',
          callbackURL: '/account?osm=connected',
          errorCallbackURL: '/account?osm=connect_failed',
          disableRedirect: true,
        },
        returnHeaders: true,
      }),
    )
  })

  it('refuses to follow a URL that is not OpenStreetMap’s', async () => {
    const auth = makeAuth()
    auth.api.linkSocialAccount.mockResolvedValueOnce({
      headers: new Headers(),
      response: {
        url: 'https://evil.example/oauth2/authorize',
        redirect: false,
      },
    })
    const res = await request(auth, '/account/openstreetmap/connect', 'POST')
    expect(res.headers.get('location')).toBe('/account?osm=connect_failed')
  })

  it('reports a failed start', async () => {
    const auth = makeAuth()
    auth.api.linkSocialAccount.mockRejectedValueOnce(new Error('down'))
    const res = await request(auth, '/account/openstreetmap/connect', 'POST')
    expect(res.headers.get('location')).toBe('/account?osm=connect_failed')
  })

  it('does nothing when OpenStreetMap is not configured', async () => {
    delete genericOAuthProviders.openstreetmap
    const auth = makeAuth()
    const res = await request(auth, '/account/openstreetmap/connect', 'POST')
    expect(res.headers.get('location')).toBe('/account')
    expect(auth.api.linkSocialAccount).not.toHaveBeenCalled()
  })
})

describe('POST /account/openstreetmap/disconnect', () => {
  it('unlinks the OpenStreetMap account row', async () => {
    const auth = makeAuth(LINKED)
    const res = await request(auth, '/account/openstreetmap/disconnect', 'POST')
    expect(res.headers.get('location')).toBe('/account?osm=disconnected')
    expect(auth.api.unlinkAccount).toHaveBeenCalledWith(
      expect.objectContaining({ body: { accountId: 'row-1' } }),
    )
  })

  it('reports a failed unlink', async () => {
    const auth = makeAuth(LINKED)
    auth.api.unlinkAccount.mockRejectedValueOnce(new Error('stale session'))
    const res = await request(auth, '/account/openstreetmap/disconnect', 'POST')
    expect(res.headers.get('location')).toBe('/account?osm=disconnect_failed')
  })

  it('does nothing when no OpenStreetMap identity is linked', async () => {
    const auth = makeAuth()
    const res = await request(auth, '/account/openstreetmap/disconnect', 'POST')
    expect(res.headers.get('location')).toBe('/account')
    expect(auth.api.unlinkAccount).not.toHaveBeenCalled()
  })

  it('treats a failed account listing as not linked', async () => {
    const auth = makeAuth()
    auth.api.listUserAccounts.mockRejectedValueOnce(new Error('db'))
    const res = await request(auth, '/account/openstreetmap/disconnect', 'POST')
    expect(res.headers.get('location')).toBe('/account')
  })
})
