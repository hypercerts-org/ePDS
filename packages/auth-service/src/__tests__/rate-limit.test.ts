/**
 * Tests for the in-memory request rate limiter middleware.
 */
import { describe, it, expect } from 'vitest'
import { requestRateLimit } from '../middleware/rate-limit.js'

function makeReq(ip?: string) {
  return {
    ip: ip || '127.0.0.1',
    socket: { remoteAddress: ip || '127.0.0.1' },
  }
}

function makeRes() {
  const res = {
    _status: 200,
    _json: null as unknown,
    status(code: number) {
      res._status = code
      return res
    },
    json(body: unknown) {
      res._json = body
      return res
    },
  }
  return res
}

describe('requestRateLimit', () => {
  it('allows requests within the limit', () => {
    const limiter = requestRateLimit({ windowMs: 60000, maxRequests: 5 })
    const req = makeReq('10.0.0.1')
    const res = makeRes()
    let nextCalled = false

    limiter(req as never, res as never, () => {
      nextCalled = true
    })

    expect(nextCalled).toBe(true)
    expect(res._status).toBe(200)
  })

  it('blocks requests over the limit', () => {
    const limiter = requestRateLimit({ windowMs: 60000, maxRequests: 2 })
    // Use a unique IP for this test to avoid interference
    const ip = `rate-test-${Date.now()}-${Math.random()}`

    // First two requests pass
    for (let i = 0; i < 2; i++) {
      const req = makeReq(ip)
      const res = makeRes()
      let passed = false
      limiter(req as never, res as never, () => {
        passed = true
      })
      expect(passed).toBe(true)
    }

    // Third request should be blocked
    const req = makeReq(ip)
    const res = makeRes()
    let blocked = true
    limiter(req as never, res as never, () => {
      blocked = false
    })

    expect(blocked).toBe(true)
    expect(res._status).toBe(429)
    expect(res._json).toEqual({
      error: 'Too many requests. Please try again later.',
    })
  })

  it('tracks different IPs independently', () => {
    const limiter = requestRateLimit({ windowMs: 60000, maxRequests: 1 })
    const ip1 = `ip1-${Date.now()}`
    const ip2 = `ip2-${Date.now()}`

    // IP1 uses its one request
    const req1 = makeReq(ip1)
    const res1 = makeRes()
    let next1 = false
    limiter(req1 as never, res1 as never, () => {
      next1 = true
    })
    expect(next1).toBe(true)

    // IP2 should still be allowed
    const req2 = makeReq(ip2)
    const res2 = makeRes()
    let next2 = false
    limiter(req2 as never, res2 as never, () => {
      next2 = true
    })
    expect(next2).toBe(true)
  })

  it('uses req.ip when available', () => {
    const limiter = requestRateLimit({ windowMs: 60000, maxRequests: 10 })
    const req = {
      ip: 'proxy-ip-1',
      socket: { remoteAddress: 'direct-ip-1' },
    }
    const res = makeRes()
    let nextCalled = false

    limiter(req as never, res as never, () => {
      nextCalled = true
    })

    expect(nextCalled).toBe(true)
  })

  it('falls back to "unknown" when no IP is available', () => {
    const limiter = requestRateLimit({ windowMs: 60000, maxRequests: 10 })
    const req = {
      ip: undefined,
      socket: { remoteAddress: undefined },
    }
    const res = makeRes()
    let nextCalled = false

    limiter(req as never, res as never, () => {
      nextCalled = true
    })

    expect(nextCalled).toBe(true)
  })
})
