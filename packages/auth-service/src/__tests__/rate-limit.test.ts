import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MagicPdsDb } from '@magic-pds/shared'
import { RateLimiter } from '../magic-link/rate-limit.js'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'

let db: MagicPdsDb
let dbPath: string

beforeEach(() => {
  dbPath = path.join(os.tmpdir(), `rate-limit-test-${Date.now()}-${Math.random().toString(36).slice(2)}.sqlite`)
  db = new MagicPdsDb(dbPath)
})

afterEach(() => {
  db.close()
  try { fs.unlinkSync(dbPath) } catch {}
  try { fs.unlinkSync(dbPath + '-wal') } catch {}
  try { fs.unlinkSync(dbPath + '-shm') } catch {}
})

describe('RateLimiter', () => {
  it('allows requests under the limit', () => {
    const limiter = new RateLimiter(db, { emailPer15Min: 3, emailPerHour: 5, ipPer15Min: 10 })
    expect(limiter.check('test@example.com', '127.0.0.1')).toBeNull()
  })

  it('blocks after email per-15-min limit', () => {
    const limiter = new RateLimiter(db, { emailPer15Min: 2, emailPerHour: 10, ipPer15Min: 10 })

    limiter.record('test@example.com', '127.0.0.1')
    limiter.record('test@example.com', '127.0.0.1')

    const result = limiter.check('test@example.com', '127.0.0.1')
    expect(result).not.toBeNull()
    expect(result).toContain('Too many requests')
  })

  it('blocks after email per-hour limit', () => {
    const limiter = new RateLimiter(db, { emailPer15Min: 10, emailPerHour: 2, ipPer15Min: 10 })

    limiter.record('test@example.com', '127.0.0.1')
    limiter.record('test@example.com', '127.0.0.1')

    const result = limiter.check('test@example.com', '127.0.0.1')
    expect(result).not.toBeNull()
    expect(result).toContain('Too many requests')
  })

  it('blocks after IP limit', () => {
    const limiter = new RateLimiter(db, { emailPer15Min: 10, emailPerHour: 10, ipPer15Min: 2 })

    limiter.record('a@example.com', '127.0.0.1')
    limiter.record('b@example.com', '127.0.0.1')

    const result = limiter.check('c@example.com', '127.0.0.1')
    expect(result).not.toBeNull()
    expect(result).toContain('Too many requests')
  })

  it('does not cross-contaminate between emails', () => {
    const limiter = new RateLimiter(db, { emailPer15Min: 2, emailPerHour: 10, ipPer15Min: 10 })

    limiter.record('a@example.com', '127.0.0.1')
    limiter.record('a@example.com', '127.0.0.1')

    // Different email should still be allowed
    expect(limiter.check('b@example.com', '127.0.0.1')).toBeNull()
  })

  it('does not cross-contaminate between IPs', () => {
    const limiter = new RateLimiter(db, { emailPer15Min: 10, emailPerHour: 10, ipPer15Min: 2 })

    limiter.record('a@example.com', '1.2.3.4')
    limiter.record('b@example.com', '1.2.3.4')

    // Different IP should still be allowed
    expect(limiter.check('c@example.com', '5.6.7.8')).toBeNull()
  })

  it('allows null IP address', () => {
    const limiter = new RateLimiter(db, { emailPer15Min: 3, emailPerHour: 5, ipPer15Min: 1 })

    limiter.record('test@example.com', null)
    // Should not hit IP limit with null IP
    expect(limiter.check('test@example.com', null)).toBeNull()
  })

  it('uses default limits when none provided', () => {
    const limiter = new RateLimiter(db)
    // Should work with defaults (3 per 15 min)
    expect(limiter.check('test@example.com', '127.0.0.1')).toBeNull()
  })

  it('is case-insensitive for email', () => {
    const limiter = new RateLimiter(db, { emailPer15Min: 1, emailPerHour: 10, ipPer15Min: 10 })

    limiter.record('Test@Example.com', '127.0.0.1')

    const result = limiter.check('test@example.com', '127.0.0.1')
    expect(result).not.toBeNull()
  })
})
