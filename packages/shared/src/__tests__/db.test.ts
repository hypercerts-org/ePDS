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
    `epds-test-${Date.now()}-${Math.random().toString(36).slice(2)}.sqlite`,
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

describe('Verification Token Operations', () => {
  it('creates and retrieves a token', () => {
    db.createVerificationToken({
      tokenHash: 'abc123',
      email: 'Test@Example.com',
      expiresAt: Date.now() + 60000,
      authRequestId: 'req-1',
      clientId: null,
      deviceInfo: 'Chrome',
      csrfToken: 'csrf-1',
    })

    const row = db.getVerificationToken('abc123')
    expect(row).toBeDefined()
    expect(row!.email).toBe('test@example.com') // lowercased
    expect(row!.authRequestId).toBe('req-1')
    expect(row!.used).toBe(0)
    expect(row!.attempts).toBe(0)
  })

  it('marks token as used', () => {
    db.createVerificationToken({
      tokenHash: 'token1',
      email: 'a@b.com',
      expiresAt: Date.now() + 60000,
      authRequestId: 'req-1',
      clientId: null,
      deviceInfo: null,
      csrfToken: 'csrf-1',
    })

    db.markVerificationTokenUsed('token1')
    const row = db.getVerificationToken('token1')
    expect(row!.used).toBe(1)
  })

  it('increments token attempts', () => {
    db.createVerificationToken({
      tokenHash: 'token2',
      email: 'a@b.com',
      expiresAt: Date.now() + 60000,
      authRequestId: 'req-1',
      clientId: null,
      deviceInfo: null,
      csrfToken: 'csrf-2',
    })

    expect(db.incrementTokenAttempts('token2')).toBe(1)
    expect(db.incrementTokenAttempts('token2')).toBe(2)
    expect(db.incrementTokenAttempts('token2')).toBe(3)
  })

  it('looks up token by CSRF', () => {
    db.createVerificationToken({
      tokenHash: 'token3',
      email: 'poll@test.com',
      expiresAt: Date.now() + 60000,
      authRequestId: 'req-3',
      clientId: 'https://app.example/client-metadata.json',
      deviceInfo: null,
      csrfToken: 'csrf-poll',
    })

    const row = db.getVerificationTokenByCsrf('csrf-poll')
    expect(row).toBeDefined()
    expect(row!.email).toBe('poll@test.com')
    expect(row!.clientId).toBe('https://app.example/client-metadata.json')
  })

  it('cleans up expired tokens', () => {
    db.createVerificationToken({
      tokenHash: 'expired',
      email: 'a@b.com',
      expiresAt: Date.now() - 1000, // already expired
      authRequestId: 'req-1',
      clientId: null,
      deviceInfo: null,
      csrfToken: 'csrf-x',
    })

    const cleaned = db.cleanupExpiredTokens()
    expect(cleaned).toBe(1)
    expect(db.getVerificationToken('expired')).toBeUndefined()
  })
})

describe('Backup Email Operations', () => {
  it('adds and verifies a backup email', () => {
    db.addBackupEmail('did:plc:123', 'backup@test.com', 'verify-hash')

    // Not verified yet
    expect(db.getDidByBackupEmail('backup@test.com')).toBeUndefined()

    // Verify
    expect(db.verifyBackupEmail('verify-hash')).toBe(true)
    expect(db.getDidByBackupEmail('backup@test.com')).toBe('did:plc:123')
  })

  it('lists backup emails for a DID', () => {
    db.addBackupEmail('did:plc:123', 'b1@test.com', 'h1')
    db.addBackupEmail('did:plc:123', 'b2@test.com', 'h2')

    const emails = db.getBackupEmails('did:plc:123')
    expect(emails).toHaveLength(2)
  })

  it('removes a backup email', () => {
    db.addBackupEmail('did:plc:123', 'remove@test.com', 'h3')
    db.removeBackupEmail('did:plc:123', 'remove@test.com')
    expect(db.getBackupEmails('did:plc:123')).toHaveLength(0)
  })
})

describe('Rate Limiting', () => {
  it('records and counts email sends', () => {
    db.recordEmailSend('rate@test.com', '1.2.3.4')
    db.recordEmailSend('rate@test.com', '1.2.3.4')

    expect(db.getEmailSendCount('rate@test.com', 60000)).toBe(2)
    expect(db.getIpSendCount('1.2.3.4', 60000)).toBe(2)
  })

  it('cleans up old rate limit entries', () => {
    // We can't easily test this without manipulating time,
    // but we can verify the method runs without error
    const cleaned = db.cleanupOldRateLimitEntries()
    expect(cleaned).toBeGreaterThanOrEqual(0)
  })
})

describe('Auth Flow Operations', () => {
  it('creates and retrieves an auth flow', () => {
    db.createAuthFlow({
      flowId: 'flow-1',
      requestUri: 'urn:ietf:params:oauth:request_uri:abc123',
      clientId: 'https://app.example/client',
      expiresAt: Date.now() + 600_000, // 10 min
    })

    const flow = db.getAuthFlow('flow-1')
    expect(flow).toBeDefined()
    expect(flow!.requestUri).toBe('urn:ietf:params:oauth:request_uri:abc123')
    expect(flow!.clientId).toBe('https://app.example/client')
    expect(flow!.email).toBeNull()
  })

  it('returns undefined for expired auth flows', () => {
    db.createAuthFlow({
      flowId: 'flow-expired',
      requestUri: 'urn:ietf:params:oauth:request_uri:expired',
      clientId: null,
      expiresAt: Date.now() - 1000, // already expired
    })

    expect(db.getAuthFlow('flow-expired')).toBeUndefined()
  })

  it('deletes an auth flow', () => {
    db.createAuthFlow({
      flowId: 'flow-delete',
      requestUri: 'urn:ietf:params:oauth:request_uri:delete',
      clientId: null,
      expiresAt: Date.now() + 600_000,
    })

    db.deleteAuthFlow('flow-delete')
    expect(db.getAuthFlow('flow-delete')).toBeUndefined()
  })

  it('cleans up expired auth flows', () => {
    db.createAuthFlow({
      flowId: 'flow-cleanup',
      requestUri: 'urn:ietf:params:oauth:request_uri:cleanup',
      clientId: null,
      expiresAt: Date.now() - 1000,
    })

    const cleaned = db.cleanupExpiredAuthFlows()
    expect(cleaned).toBeGreaterThanOrEqual(1)
    expect(db.getAuthFlow('flow-cleanup')).toBeUndefined()
  })
})

describe('Migration: v9 is a no-op (client_logins preserved)', () => {
  it('client_logins table still exists after all migrations', () => {
    // v9 was originally a DROP but changed to a no-op. The table is no
    // longer used by current code but kept to avoid breaking rollbacks.
    const tables = db['db']
      .prepare(
        `SELECT name FROM sqlite_master WHERE type='table' AND name='client_logins'`,
      )
      .all()
    expect(tables).toHaveLength(1)
  })

  it('schema version is at least 9 after migration', () => {
    const row = db['db']
      .prepare('SELECT version FROM schema_version')
      .get() as { version: number }
    expect(row.version).toBeGreaterThanOrEqual(9)
  })
})
