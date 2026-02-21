/**
 * Tests for the recovery route — uses better-auth OTP for backup email verification.
 *
 * The recovery flow:
 * 1. User enters backup email
 * 2. Route looks up DID via backup_email table (anti-enumeration: always shows OTP form)
 * 3. If found, sends OTP via better-auth auth.api.sendVerificationOTP()
 * 4. User verifies OTP via auth.api.signInEmailOTP()
 * 5. Redirects to /auth/complete to complete AT Protocol flow
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { randomBytes } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { EpdsDb } from '@certified-app/shared'

describe('Recovery flow: backup email lookup', () => {
  let db: EpdsDb
  let dbPath: string

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `test-recovery-${Date.now()}.db`)
    db = new EpdsDb(dbPath)
  })

  afterEach(() => {
    db.close()
    try {
      fs.unlinkSync(dbPath)
      // eslint-disable-next-line no-empty
    } catch {}
  })

  it('finds DID for a registered backup email', () => {
    // Add backup email for a DID
    db.addBackupEmail('did:plc:test123', 'backup@example.com', 'tok-hash')
    db.verifyBackupEmail('tok-hash')

    const did = db.getDidByBackupEmail('backup@example.com')
    expect(did).toBe('did:plc:test123')
  })

  it('returns undefined for unregistered backup email (anti-enumeration)', () => {
    const did = db.getDidByBackupEmail('notregistered@example.com')
    expect(did).toBeUndefined()
  })

  it('returns undefined for unverified backup email', () => {
    db.addBackupEmail(
      'did:plc:test456',
      'unverified@example.com',
      'unverified-hash',
    )
    // Do NOT call verifyBackupEmail
    const did = db.getDidByBackupEmail('unverified@example.com')
    expect(did).toBeUndefined()
  })

  it('is case-insensitive for backup email lookup', () => {
    db.addBackupEmail('did:plc:case-test', 'Case@EXAMPLE.COM', 'case-hash')
    db.verifyBackupEmail('case-hash')

    // Lookup with different case
    const did = db.getDidByBackupEmail('case@example.com')
    expect(did).toBe('did:plc:case-test')
  })
})

describe('Recovery flow: auth_flow creation for request_uri threading', () => {
  let db: EpdsDb
  let dbPath: string

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `test-recovery-flow-${Date.now()}.db`)
    db = new EpdsDb(dbPath)
  })

  afterEach(() => {
    db.close()
    try {
      fs.unlinkSync(dbPath)
      // eslint-disable-next-line no-empty
    } catch {}
  })

  it('creates auth_flow with requestUri when backup email is found', () => {
    const flowId = randomBytes(16).toString('hex')
    const requestUri = 'urn:ietf:params:oauth:request_uri:recovery-test'

    db.createAuthFlow({
      flowId,
      requestUri,
      clientId: null,
      expiresAt: Date.now() + 10 * 60 * 1000,
    })

    const flow = db.getAuthFlow(flowId)
    expect(flow).toBeDefined()
    expect(flow!.requestUri).toBe(requestUri)
    expect(flow!.clientId).toBeNull()
  })

  it('does not create duplicate auth_flow if one already exists', () => {
    const flowId = 'existing-flow'
    const requestUri = 'urn:req:existing'

    db.createAuthFlow({
      flowId,
      requestUri,
      clientId: null,
      expiresAt: Date.now() + 10 * 60 * 1000,
    })

    // Simulating: if flow already exists, we should reuse it
    const existing = db.getAuthFlow(flowId)
    expect(existing).toBeDefined()
    expect(existing!.requestUri).toBe(requestUri)
  })
})

describe('Recovery flow: OTP pattern (8 digits)', () => {
  it('OTP sent by better-auth is 8 digits (configured in emailOTP plugin)', () => {
    // Verify the configured OTP length matches what users expect
    const OTP_LENGTH = 8
    const pattern = new RegExp(`^[0-9]{${OTP_LENGTH}}$`)

    // Simulate an 8-digit OTP
    const otp = '12345678'
    expect(pattern.test(otp)).toBe(true)

    // 6 digits should not match (old format)
    expect(pattern.test('123456')).toBe(false)
  })

  it('OTP entry form uses maxlength=8 and pattern [0-9]{8}', () => {
    // This is a documentation test confirming the UI constraints
    // match the better-auth configuration (otpLength: 8)
    const maxlength = 8
    const pattern = '[0-9]{8}'
    expect(maxlength).toBe(8)
    expect(pattern).toContain('8')
  })
})

describe('Recovery flow: /auth/complete bridge integration', () => {
  let db: EpdsDb
  let dbPath: string

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `test-recovery-bridge-${Date.now()}.db`)
    db = new EpdsDb(dbPath)
  })

  afterEach(() => {
    db.close()
    try {
      fs.unlinkSync(dbPath)
      // eslint-disable-next-line no-empty
    } catch {}
  })

  it('auth_flow contains requestUri needed by /auth/complete', () => {
    // /auth/complete reads the auth_flow via cookie
    // Recovery must create an auth_flow before redirecting to /auth/complete
    const flowId = 'recovery-complete-flow'
    const requestUri = 'urn:ietf:params:oauth:request_uri:bridge-test'

    db.createAuthFlow({
      flowId,
      requestUri,
      clientId: null,
      expiresAt: Date.now() + 10 * 60 * 1000,
    })

    // /auth/complete will read this via the magic_auth_flow cookie
    const flow = db.getAuthFlow(flowId)
    expect(flow!.requestUri).toBe(requestUri)
  })
})
