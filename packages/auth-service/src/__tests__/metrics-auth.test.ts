import { describe, it, expect } from 'vitest'
import { checkMetricsAuth } from '../lib/metrics-auth.js'

function basic(user: string, password: string): string {
  return 'Basic ' + Buffer.from(`${user}:${password}`).toString('base64')
}

describe('checkMetricsAuth', () => {
  describe('deny-by-default (no admin password configured)', () => {
    it('returns 401 when adminPassword is undefined, even with a header', () => {
      const r = checkMetricsAuth(basic('admin', 'whatever'), undefined)
      expect(r.ok).toBe(false)
      if (!r.ok) {
        expect(r.status).toBe(401)
        expect(r.headers['WWW-Authenticate']).toBe('Basic realm="metrics"')
        expect(r.body).toEqual({ error: 'Unauthorized' })
      }
    })

    it('returns 401 when adminPassword is an empty string', () => {
      const r = checkMetricsAuth(basic('admin', 'whatever'), '')
      expect(r.ok).toBe(false)
    })

    it('returns 401 when both adminPassword and header are missing', () => {
      const r = checkMetricsAuth(undefined, undefined)
      expect(r.ok).toBe(false)
    })
  })

  describe('password configured', () => {
    const adminPassword = 'supersecret'

    it('returns 401 when Authorization header is missing', () => {
      const r = checkMetricsAuth(undefined, adminPassword)
      expect(r.ok).toBe(false)
      if (!r.ok) {
        expect(r.headers['WWW-Authenticate']).toBe('Basic realm="metrics"')
      }
    })

    it('returns 401 when Authorization header is the empty string', () => {
      const r = checkMetricsAuth('', adminPassword)
      expect(r.ok).toBe(false)
    })

    it('returns 401 when the password is wrong', () => {
      const r = checkMetricsAuth(basic('admin', 'wrong'), adminPassword)
      expect(r.ok).toBe(false)
    })

    it('returns 401 when the username is not "admin"', () => {
      const r = checkMetricsAuth(basic('root', adminPassword), adminPassword)
      expect(r.ok).toBe(false)
    })

    it('returns 401 when the header uses a different scheme (Bearer)', () => {
      const r = checkMetricsAuth(`Bearer ${adminPassword}`, adminPassword)
      expect(r.ok).toBe(false)
    })

    it('accepts a correctly formed Basic header with matching password', () => {
      const r = checkMetricsAuth(basic('admin', adminPassword), adminPassword)
      expect(r.ok).toBe(true)
    })

    it('rejects a header whose length happens to match the expected value', () => {
      // Guard against a regression that would short-circuit timingSafeEqual
      // when lengths differ. Use a same-length but different payload.
      const expected = basic('admin', adminPassword)
      const samelengthWrong = 'X'.repeat(expected.length)
      const r = checkMetricsAuth(samelengthWrong, adminPassword)
      expect(r.ok).toBe(false)
    })
  })
})
