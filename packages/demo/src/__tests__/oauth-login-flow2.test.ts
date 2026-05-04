/**
 * Tests for the OAuth login route handler — Flow 2 (no email/handle params).
 *
 * Mocks global.fetch to simulate PAR endpoint responses and verifies the
 * route produces correct redirects and session cookies.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// Mock next/server before importing the route
vi.mock('next/server', () => {
  class MockHeaders {
    private _h = new Map<string, string>()
    set(k: string, v: string) {
      this._h.set(k.toLowerCase(), v)
    }
    get(k: string) {
      return this._h.get(k.toLowerCase()) ?? null
    }
    has(k: string) {
      return this._h.has(k.toLowerCase())
    }
  }

  class MockCookies {
    private _c = new Map<string, { value: string; options: unknown }>()
    set(name: string, value: string, options?: unknown) {
      this._c.set(name, { value, options })
    }
    get(name: string) {
      return this._c.get(name)
    }
    entries() {
      return this._c.entries()
    }
  }

  class MockNextResponse {
    status: number
    headers: MockHeaders
    cookies: MockCookies
    _url: string

    constructor(
      body: string | null,
      init?: { status?: number; headers?: Record<string, string> },
    ) {
      this.status = init?.status ?? 200
      this.headers = new MockHeaders()
      this.cookies = new MockCookies()
      this._url = ''
      if (init?.headers) {
        for (const [k, v] of Object.entries(init.headers)) {
          this.headers.set(k, v)
        }
      }
    }

    static redirect(url: string | URL) {
      const resp = new MockNextResponse(null, { status: 307 })
      resp._url = typeof url === 'string' ? url : url.toString()
      return resp
    }
  }

  return { NextResponse: MockNextResponse }
})

import { GET } from '../app/api/oauth/login/route'
import { getOAuthSessionFromCookie, OAUTH_COOKIE } from '../lib/session'

const MOCK_PAR_RESPONSE = {
  request_uri: 'urn:ietf:params:oauth:request_uri:test-123',
}

function makeRequest(queryString = '') {
  const url = `http://localhost:3002/api/oauth/login${queryString ? '?' + queryString : ''}`
  return new Request(url, {
    headers: { 'x-real-ip': '127.0.0.1' },
  })
}

describe('OAuth login route (Flow 2)', () => {
  let originalFetch: typeof global.fetch

  beforeEach(() => {
    originalFetch = global.fetch
  })

  afterEach(() => {
    global.fetch = originalFetch
    vi.restoreAllMocks()
  })

  it('redirects to auth endpoint with no login_hint when no email/handle', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_PAR_RESPONSE),
      headers: new Headers(),
    })

    const resp = (await GET(makeRequest())) as unknown as {
      status: number
      _url: string
      cookies: { entries(): Iterable<[string, { value: string }]> }
    }

    expect(resp.status).toBe(307)
    expect(resp._url).toContain('request_uri=')
    // Flow 2: no login_hint in the redirect URL
    expect(resp._url).not.toContain('login_hint')

    // Verify oauth session cookie was set
    let cookieSet = false
    for (const [name] of resp.cookies.entries()) {
      if (name === OAUTH_COOKIE) cookieSet = true
    }
    expect(cookieSet).toBe(true)
  })

  it('PAR body has no login_hint in Flow 2', async () => {
    let capturedBody = ''
    global.fetch = vi
      .fn()
      .mockImplementation((_url: string, init?: RequestInit) => {
        if (init?.body) capturedBody = init.body as string
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_PAR_RESPONSE),
          headers: new Headers(),
        })
      })

    await GET(makeRequest())

    // PAR body should not include login_hint
    const params = new URLSearchParams(capturedBody)
    expect(params.has('login_hint')).toBe(false)
  })

  it('handles DPoP nonce retry (400 → dpop-nonce header → retry succeeds)', async () => {
    let callCount = 0
    global.fetch = vi.fn().mockImplementation(() => {
      callCount++
      if (callCount === 1) {
        // First call: 400 with dpop-nonce
        const headers = new Headers()
        headers.set('dpop-nonce', 'server-nonce-abc')
        return Promise.resolve({
          ok: false,
          status: 400,
          headers,
          text: () => Promise.resolve('use_dpop_nonce'),
        })
      }
      // Second call: success
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve(MOCK_PAR_RESPONSE),
        headers: new Headers(),
      })
    })

    const resp = (await GET(makeRequest())) as unknown as {
      status: number
      _url: string
    }

    // Should have made 2 fetch calls (original + retry)
    expect(callCount).toBe(2)
    // Should redirect successfully after retry
    expect(resp.status).toBe(307)
    expect(resp._url).toContain('request_uri=')
  })

  it('session cookie round-trips the stored OAuth data', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_PAR_RESPONSE),
      headers: new Headers(),
    })

    const resp = (await GET(makeRequest())) as unknown as {
      cookies: {
        get(name: string): { value: string; options: unknown } | undefined
      }
    }

    const cookie = resp.cookies.get(OAUTH_COOKIE)
    expect(cookie).toBeDefined()

    // Verify the cookie value can be decoded back to a valid session
    const store = {
      get(name: string) {
        return name === OAUTH_COOKIE ? { value: cookie!.value } : undefined
      },
    }
    const session = getOAuthSessionFromCookie(store)
    expect(session).not.toBeNull()
    expect(session!.state).toBeTypeOf('string')
    expect(session!.codeVerifier).toBeTypeOf('string')
    expect(session!.tokenEndpoint).toContain('/oauth/token')
    // Flow 2: no email
    expect(session!.email).toBeUndefined()
  })
})
