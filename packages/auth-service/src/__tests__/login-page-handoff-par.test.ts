/**
 * GET /oauth/authorize with the real PAR lookup: only the HTTP call to
 * pds-core's /_internal/par-login-hint is stubbed. Proves, through the
 * router, that one request makes one lookup for the stored flow's client
 * (not the query string's), that the hand-off `state` and `iss` come from
 * that response (the issuer differs from the public URL), that the page is
 * not cached, and that a PAR pushed by another client yields neither.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { _seedClientMetadataCacheForTest } from '@certified-app/shared'
import {
  startLoginPageApp,
  type LoginPageApp,
} from './__helpers__/login-page-app.js'

const REQUEST_URI = 'urn:ietf:params:oauth:request_uri:handoff-par'
const PLAIN_CLIENT_ID = 'https://app.example.com'
const HANDOFF_CLIENT_ID = 'https://handoff-par.example.com'
const PDS_INTERNAL = 'http://core.test:3000'
const ISSUER = 'http://pds.localhost:3000'

describe('GET /oauth/authorize PAR lookup for the Atmosphere hand-off', () => {
  let app: LoginPageApp
  let parFetches: string[]
  let parBody: object
  const realFetch = globalThis.fetch

  beforeEach(async () => {
    vi.stubEnv('PDS_INTERNAL_URL', PDS_INTERNAL)
    vi.stubEnv('EPDS_INTERNAL_SECRET', 'test-secret')
    app = await startLoginPageApp('handoff-par')
    _seedClientMetadataCacheForTest(HANDOFF_CLIENT_ID, {
      client_name: 'Hand-off App',
      epds_handle_login_url: `${HANDOFF_CLIENT_ID}/api/oauth/handoff`,
    })
    app.ctx.db.createAuthFlow({
      flowId: 'flow-handoff-par',
      requestUri: REQUEST_URI,
      clientId: HANDOFF_CLIENT_ID,
      expiresAt: Date.now() + 60_000,
    })
    parFetches = []
    parBody = {
      login_hint: null,
      state: 'st-par-1',
      client_id: HANDOFF_CLIENT_ID,
      issuer: ISSUER,
    }
    // The test server is reached through the same global fetch, so only
    // pds-core's endpoint is intercepted.
    vi.stubGlobal(
      'fetch',
      (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
        const url = input instanceof Request ? input.url : String(input)
        if (!url.startsWith(`${PDS_INTERNAL}/_internal/par-login-hint`)) {
          return realFetch(input, init)
        }
        parFetches.push(url)
        return Promise.resolve(Response.json(parBody))
      },
    )
  })

  afterEach(async () => {
    vi.unstubAllGlobals()
    vi.unstubAllEnvs()
    await app.close()
  })

  function authorize(clientId: string): Promise<Response> {
    const query = new URLSearchParams({
      request_uri: REQUEST_URI,
      client_id: clientId,
    })
    return realFetch(`${app.baseUrl}/oauth/authorize?${query.toString()}`)
  }

  it("inlines the PAR state and the PDS issuer for the flow's client after a single lookup, uncached", async () => {
    // The stored flow wins over the query string's client_id, which a
    // browser can set to anything.
    const res = await authorize(PLAIN_CLIENT_ID)
    const html = await res.text()

    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(html).toContain('var handoffState = "st-par-1";')
    expect(html).toContain(`var handoffIss = "${ISSUER}";`)
    expect(html).not.toContain('var handoffIss = "https://test.local"')
    expect(parFetches).toHaveLength(1)
  })

  it('inlines neither state nor issuer when the PAR belongs to another client', async () => {
    parBody = {
      login_hint: null,
      state: 'st-par-1',
      client_id: 'https://other.example.com',
      issuer: ISSUER,
    }

    const html = await (await authorize(HANDOFF_CLIENT_ID)).text()

    expect(html).toContain('var handoffState = "";')
    expect(html).toContain('var handoffIss = "";')
  })
})
