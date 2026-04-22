/**
 * Extended DB tests covering methods not exercised by the base db.test.ts:
 * getMetrics, OTP failure tracking, getAuthFlowByRequestUri, deleteAccountData,
 * and edge cases for existing operations.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { EpdsDb } from '../db.js'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'

let db: EpdsDb
let dbPath: string

beforeEach(() => {
  dbPath = path.join(
    os.tmpdir(),
    `epds-ext-test-${Date.now()}-${Math.random().toString(36).slice(2)}.sqlite`,
  )
  db = new EpdsDb(dbPath)
})

afterEach(() => {
  db.close()
  try {
    fs.unlinkSync(dbPath)
    // eslint-disable-next-line no-empty
  } catch {}
  try {
    fs.unlinkSync(dbPath + '-wal')
    // eslint-disable-next-line no-empty
  } catch {}
  try {
    fs.unlinkSync(dbPath + '-shm')
    // eslint-disable-next-line no-empty
  } catch {}
})

describe('getMetrics', () => {
  it('returns zero counts for an empty database', () => {
    const metrics = db.getMetrics()
    expect(metrics.pendingTokens).toBe(0)
    expect(metrics.backupEmails).toBe(0)
    expect(metrics.rateLimitEntries).toBe(0)
  })

  it('counts pending (unused, non-expired) tokens', () => {
    db.createVerificationToken({
      tokenHash: 'active-token',
      email: 'a@b.com',
      expiresAt: Date.now() + 60000,
      authRequestId: 'req-1',
      clientId: null,
      deviceInfo: null,
      csrfToken: 'csrf-1',
    })
    db.createVerificationToken({
      tokenHash: 'used-token',
      email: 'a@b.com',
      expiresAt: Date.now() + 60000,
      authRequestId: 'req-2',
      clientId: null,
      deviceInfo: null,
      csrfToken: 'csrf-2',
    })
    db.markVerificationTokenUsed('used-token')

    db.createVerificationToken({
      tokenHash: 'expired-token',
      email: 'a@b.com',
      expiresAt: Date.now() - 1000,
      authRequestId: 'req-3',
      clientId: null,
      deviceInfo: null,
      csrfToken: 'csrf-3',
    })

    const metrics = db.getMetrics()
    expect(metrics.pendingTokens).toBe(1) // only active-token
  })

  it('counts verified backup emails', () => {
    db.addBackupEmail('did:plc:1', 'verified@test.com', 'h1')
    db.verifyBackupEmail('h1')
    db.addBackupEmail('did:plc:2', 'unverified@test.com', 'h2')

    const metrics = db.getMetrics()
    expect(metrics.backupEmails).toBe(1) // only verified
  })

  it('counts rate limit entries', () => {
    db.recordEmailSend('a@b.com', '1.2.3.4')
    db.recordEmailSend('c@d.com', '5.6.7.8')

    const metrics = db.getMetrics()
    expect(metrics.rateLimitEntries).toBe(2)
  })
})

describe('OTP failure tracking', () => {
  it('records and counts OTP failures', () => {
    db.recordOtpFailure('fail@test.com')
    db.recordOtpFailure('fail@test.com')
    db.recordOtpFailure('fail@test.com')

    const count = db.getOtpFailureCount('fail@test.com', 60000)
    expect(count).toBe(3)
  })

  it('is case-insensitive for email', () => {
    db.recordOtpFailure('Fail@TEST.com')
    const count = db.getOtpFailureCount('fail@test.com', 60000)
    expect(count).toBe(1)
  })

  it('does not count failures outside the time window', () => {
    db.recordOtpFailure('old@test.com')
    // Window of 0ms means nothing is within range
    const count = db.getOtpFailureCount('old@test.com', 0)
    expect(count).toBe(0)
  })

  it('does not count failures for different emails', () => {
    db.recordOtpFailure('alice@test.com')
    const count = db.getOtpFailureCount('bob@test.com', 60000)
    expect(count).toBe(0)
  })

  it('cleans up old OTP failures without error', () => {
    db.recordOtpFailure('cleanup@test.com')
    const cleaned = db.cleanupOldOtpFailures()
    // Recent entries won't be cleaned, so 0 is expected
    expect(cleaned).toBeGreaterThanOrEqual(0)
  })
})

describe('getAuthFlowByRequestUri', () => {
  it('finds a flow by request_uri', () => {
    db.createAuthFlow({
      flowId: 'flow-by-uri',
      requestUri: 'urn:ietf:params:oauth:request_uri:unique123',
      clientId: 'https://app.example.com',
      expiresAt: Date.now() + 600_000,
    })

    const flow = db.getAuthFlowByRequestUri(
      'urn:ietf:params:oauth:request_uri:unique123',
    )
    expect(flow).toBeDefined()
    expect(flow!.flowId).toBe('flow-by-uri')
    expect(flow!.clientId).toBe('https://app.example.com')
  })

  it('returns undefined for non-existent request_uri', () => {
    expect(db.getAuthFlowByRequestUri('urn:nonexistent')).toBeUndefined()
  })

  it('returns undefined for expired flow', () => {
    db.createAuthFlow({
      flowId: 'flow-expired-uri',
      requestUri: 'urn:ietf:params:oauth:request_uri:expired',
      clientId: null,
      expiresAt: Date.now() - 1000,
    })

    expect(
      db.getAuthFlowByRequestUri('urn:ietf:params:oauth:request_uri:expired'),
    ).toBeUndefined()
  })
})

describe('deleteAccountData', () => {
  it('deletes backup emails for a DID', () => {
    db.addBackupEmail('did:plc:delete-me', 'a@test.com', 'h1')
    db.addBackupEmail('did:plc:delete-me', 'b@test.com', 'h2')
    db.addBackupEmail('did:plc:keep', 'c@test.com', 'h3')

    db.deleteAccountData('did:plc:delete-me')

    expect(db.getBackupEmails('did:plc:delete-me')).toHaveLength(0)
    expect(db.getBackupEmails('did:plc:keep')).toHaveLength(1)
  })
})

describe('Verification token with codeHash', () => {
  it('creates token with codeHash for OTP', () => {
    db.createVerificationToken({
      tokenHash: 'otp-token',
      email: 'otp@test.com',
      expiresAt: Date.now() + 60000,
      authRequestId: 'req-otp',
      clientId: 'https://client.example',
      deviceInfo: 'Firefox',
      csrfToken: 'csrf-otp',
      codeHash: 'sha256-of-otp-code',
    })

    const row = db.getVerificationToken('otp-token')
    expect(row).toBeDefined()
    expect(row!.codeHash).toBe('sha256-of-otp-code')
    expect(row!.clientId).toBe('https://client.example')
    expect(row!.deviceInfo).toBe('Firefox')
  })

  it('stores null codeHash when not provided', () => {
    db.createVerificationToken({
      tokenHash: 'no-code-token',
      email: 'nocode@test.com',
      expiresAt: Date.now() + 60000,
      authRequestId: 'req-nc',
      clientId: null,
      deviceInfo: null,
      csrfToken: 'csrf-nc',
    })

    const row = db.getVerificationToken('no-code-token')
    expect(row!.codeHash).toBeNull()
  })
})

describe('incrementTokenAttempts edge cases', () => {
  it('returns 0 for non-existent token', () => {
    const count = db.incrementTokenAttempts('nonexistent')
    expect(count).toBe(0)
  })
})

describe('verifyBackupEmail edge cases', () => {
  it('returns false when verifying non-existent token hash', () => {
    expect(db.verifyBackupEmail('nonexistent-hash')).toBe(false)
  })

  it('returns false when verifying already-verified email', () => {
    db.addBackupEmail('did:plc:1', 'test@test.com', 'once-hash')
    expect(db.verifyBackupEmail('once-hash')).toBe(true)
    // Second verification should fail (already verified = 1)
    expect(db.verifyBackupEmail('once-hash')).toBe(false)
  })
})

describe('getVerificationTokenByCsrf edge cases', () => {
  it('returns undefined for non-existent CSRF token', () => {
    expect(db.getVerificationTokenByCsrf('nonexistent')).toBeUndefined()
  })
})

describe('Database initialization', () => {
  it('creates db directory if it does not exist', () => {
    const nestedPath = path.join(
      os.tmpdir(),
      `epds-nested-${Date.now()}`,
      'subdir',
      'test.sqlite',
    )
    const nestedDb = new EpdsDb(nestedPath)
    // Should not throw — directory created automatically
    expect(nestedDb).toBeDefined()
    nestedDb.close()
    // Cleanup
    try {
      fs.rmSync(path.dirname(path.dirname(nestedPath)), {
        recursive: true,
      })
      // eslint-disable-next-line no-empty
    } catch {}
  })

  it('runs migrations idempotently on second open', () => {
    // Close and reopen the same db path
    db.close()
    const db2 = new EpdsDb(dbPath)
    // Should not throw on second open
    expect(db2).toBeDefined()
    // Replace the module-level db so afterEach cleanup works
    db = db2
  })
})
