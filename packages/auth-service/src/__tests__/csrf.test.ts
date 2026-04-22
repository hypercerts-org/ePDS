/**
 * Tests for the CSRF protection middleware.
 *
 * Exercises GET (cookie setting) and POST (validation) flows using
 * minimal mock req/res objects.
 */
import { describe, it, expect } from 'vitest'
import { csrfProtection, getCsrfToken } from '../middleware/csrf.js'

/** Build a minimal mock request. */
function makeReq(overrides: {
  method: string
  cookies?: Record<string, string>
  headers?: Record<string, string>
  body?: Record<string, string>
}) {
  return {
    method: overrides.method,
    cookies: overrides.cookies || {},
    headers: overrides.headers || {},
    body: overrides.body || {},
  }
}

/** Build a minimal mock response with tracking for status, json, cookie. */
function makeRes() {
  const res = {
    _status: 200,
    _json: null as unknown,
    _cookies: [] as Array<{ name: string; value: string; options: unknown }>,
    locals: {} as Record<string, unknown>,
    status(code: number) {
      res._status = code
      return res
    },
    json(body: unknown) {
      res._json = body
      return res
    },
    cookie(name: string, value: string, options: unknown) {
      res._cookies.push({ name, value, options })
      return res
    },
  }
  return res
}

describe('csrfProtection middleware', () => {
  const middleware = csrfProtection('test-secret')

  describe('GET requests', () => {
    it('sets a CSRF cookie when none exists', () => {
      const req = makeReq({ method: 'GET' })
      const res = makeRes()
      let nextCalled = false

      middleware(req as never, res as never, () => {
        nextCalled = true
      })

      expect(nextCalled).toBe(true)
      expect(res._cookies).toHaveLength(1)
      expect(res._cookies[0].name).toBe('epds_csrf')
      expect(res._cookies[0].value).toHaveLength(64) // 32 bytes hex
      expect(res.locals.csrfToken).toBe(res._cookies[0].value)
    })

    it('reuses existing CSRF cookie', () => {
      const req = makeReq({
        method: 'GET',
        cookies: { epds_csrf: 'existing-token' },
      })
      const res = makeRes()
      let nextCalled = false

      middleware(req as never, res as never, () => {
        nextCalled = true
      })

      expect(nextCalled).toBe(true)
      expect(res._cookies).toHaveLength(0) // no new cookie set
      expect(res.locals.csrfToken).toBe('existing-token')
    })
  })

  describe('POST requests', () => {
    it('validates matching CSRF tokens from header', () => {
      const token = 'a'.repeat(64) // 64-char hex token
      const req = makeReq({
        method: 'POST',
        cookies: { epds_csrf: token },
        headers: { 'x-csrf-token': token },
      })
      const res = makeRes()
      let nextCalled = false

      middleware(req as never, res as never, () => {
        nextCalled = true
      })

      expect(nextCalled).toBe(true)
      expect(res.locals.csrfToken).toBe(token)
    })

    it('validates matching CSRF tokens from body', () => {
      const token = 'b'.repeat(64)
      const req = makeReq({
        method: 'POST',
        cookies: { epds_csrf: token },
        body: { csrf: token },
      })
      const res = makeRes()
      let nextCalled = false

      middleware(req as never, res as never, () => {
        nextCalled = true
      })

      expect(nextCalled).toBe(true)
    })

    it('rejects when cookie is missing', () => {
      const req = makeReq({
        method: 'POST',
        headers: { 'x-csrf-token': 'some-token' },
      })
      const res = makeRes()
      let nextCalled = false

      middleware(req as never, res as never, () => {
        nextCalled = true
      })

      expect(nextCalled).toBe(false)
      expect(res._status).toBe(403)
      expect(res._json).toEqual({ error: 'CSRF validation failed' })
    })

    it('rejects when submitted token is missing', () => {
      const req = makeReq({
        method: 'POST',
        cookies: { epds_csrf: 'cookie-token' },
      })
      const res = makeRes()
      let nextCalled = false

      middleware(req as never, res as never, () => {
        nextCalled = true
      })

      expect(nextCalled).toBe(false)
      expect(res._status).toBe(403)
    })

    it('rejects when tokens have different lengths', () => {
      const req = makeReq({
        method: 'POST',
        cookies: { epds_csrf: 'short' },
        headers: { 'x-csrf-token': 'much-longer-token' },
      })
      const res = makeRes()
      let nextCalled = false

      middleware(req as never, res as never, () => {
        nextCalled = true
      })

      expect(nextCalled).toBe(false)
      expect(res._status).toBe(403)
    })

    it('rejects when tokens do not match (same length)', () => {
      const req = makeReq({
        method: 'POST',
        cookies: { epds_csrf: 'a'.repeat(64) },
        headers: { 'x-csrf-token': 'b'.repeat(64) },
      })
      const res = makeRes()
      let nextCalled = false

      middleware(req as never, res as never, () => {
        nextCalled = true
      })

      expect(nextCalled).toBe(false)
      expect(res._status).toBe(403)
    })

    it('prefers header token over body token', () => {
      const cookie = 'c'.repeat(64)
      const req = makeReq({
        method: 'POST',
        cookies: { epds_csrf: cookie },
        headers: { 'x-csrf-token': cookie },
        body: { csrf: 'd'.repeat(64) },
      })
      const res = makeRes()
      let nextCalled = false

      middleware(req as never, res as never, () => {
        nextCalled = true
      })

      // Header matches cookie, so it should pass
      expect(nextCalled).toBe(true)
    })
  })

  describe('other HTTP methods', () => {
    it('calls next() for non-GET/POST methods (e.g., PUT)', () => {
      const req = makeReq({ method: 'PUT' })
      const res = makeRes()
      let nextCalled = false

      middleware(req as never, res as never, () => {
        nextCalled = true
      })

      expect(nextCalled).toBe(true)
    })
  })
})

describe('getCsrfToken', () => {
  it('reads csrfToken from res.locals', () => {
    const res = makeRes()
    res.locals.csrfToken = 'my-token'
    expect(getCsrfToken(res as never)).toBe('my-token')
  })
})
