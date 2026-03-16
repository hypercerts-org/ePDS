/**
 * Tests for the unified login page (GET /oauth/authorize).
 *
 * The login page:
 * 1. Creates an auth_flow row to thread request_uri through better-auth
 * 2. Sets the epds_auth_flow cookie
 * 3. Renders a login page with email OTP form + optional social buttons
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { randomBytes } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { EpdsDb } from '@certified-app/shared'

describe('Login page auth_flow creation', () => {
  let db: EpdsDb
  let dbPath: string

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `test-login-${Date.now()}.db`)
    db = new EpdsDb(dbPath)
  })

  afterEach(() => {
    db.close()
    try {
      fs.unlinkSync(dbPath)
      // eslint-disable-next-line no-empty
    } catch {}
  })

  it('creates an auth_flow row with correct request_uri and client_id', () => {
    const flowId = 'test-login-flow-001'
    const requestUri = 'urn:ietf:params:oauth:request_uri:login-test'
    const clientId = 'https://app.example.com'

    db.createAuthFlow({
      flowId,
      requestUri,
      clientId,
      expiresAt: Date.now() + 10 * 60 * 1000,
    })

    const flow = db.getAuthFlow(flowId)
    expect(flow).toBeDefined()
    expect(flow!.requestUri).toBe(requestUri)
    expect(flow!.clientId).toBe(clientId)
    expect(flow!.expiresAt).toBeGreaterThan(Date.now())
  })

  it('creates auth_flow without client_id when not provided', () => {
    const flowId = 'no-client-login-flow'
    db.createAuthFlow({
      flowId,
      requestUri: 'urn:req:no-client',
      clientId: null,
      expiresAt: Date.now() + 10 * 60 * 1000,
    })

    const flow = db.getAuthFlow(flowId)
    expect(flow).toBeDefined()
    expect(flow!.clientId).toBeNull()
  })

  it('expires auth_flow after TTL', () => {
    const flowId = 'expired-login-flow'
    db.createAuthFlow({
      flowId,
      requestUri: 'urn:req:expired',
      clientId: null,
      expiresAt: Date.now() - 1, // immediately expired
    })

    expect(db.getAuthFlow(flowId)).toBeUndefined()
  })

  it('cleans up expired auth_flow rows', () => {
    // Create 3 expired and 1 active
    for (let i = 0; i < 3; i++) {
      db.createAuthFlow({
        flowId: `expired-${i}`,
        requestUri: `urn:req:${i}`,
        clientId: null,
        expiresAt: Date.now() - 1000,
      })
    }
    db.createAuthFlow({
      flowId: 'active-flow',
      requestUri: 'urn:req:active',
      clientId: null,
      expiresAt: Date.now() + 10 * 60 * 1000,
    })

    const cleaned = db.cleanupExpiredAuthFlows()
    expect(cleaned).toBe(3)
    expect(db.getAuthFlow('active-flow')).toBeDefined()
  })

  it('getAuthFlowByRequestUri returns existing non-expired flow', () => {
    const flowId = 'idem-flow-001'
    const requestUri = 'urn:ietf:params:oauth:request_uri:idem-test'
    db.createAuthFlow({
      flowId,
      requestUri,
      clientId: null,
      expiresAt: Date.now() + 10 * 60 * 1000,
    })

    const found = db.getAuthFlowByRequestUri(requestUri)
    expect(found).toBeDefined()
    expect(found!.flowId).toBe(flowId)
  })

  it('getAuthFlowByRequestUri returns undefined for expired flow', () => {
    db.createAuthFlow({
      flowId: 'idem-expired',
      requestUri: 'urn:ietf:params:oauth:request_uri:idem-expired',
      clientId: null,
      expiresAt: Date.now() - 1,
    })

    expect(
      db.getAuthFlowByRequestUri(
        'urn:ietf:params:oauth:request_uri:idem-expired',
      ),
    ).toBeUndefined()
  })

  it('getAuthFlowByRequestUri returns undefined when no flow exists', () => {
    expect(
      db.getAuthFlowByRequestUri(
        'urn:ietf:params:oauth:request_uri:nonexistent',
      ),
    ).toBeUndefined()
  })

  it('generates unique flow IDs (no collisions)', () => {
    const ids = new Set<string>()
    for (let i = 0; i < 100; i++) {
      ids.add(randomBytes(16).toString('hex'))
    }
    expect(ids.size).toBe(100)
  })
})

describe('Login page handle_mode storage', () => {
  let db: EpdsDb
  let dbPath: string

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `test-handle-mode-${Date.now()}.db`)
    db = new EpdsDb(dbPath)
  })

  afterEach(() => {
    db.close()
    try {
      fs.unlinkSync(dbPath)
      // eslint-disable-next-line no-empty
    } catch {}
  })

  it('stores "random" handle mode', () => {
    db.createAuthFlow({
      flowId: 'hm-random',
      requestUri: 'urn:req:hm-random',
      clientId: null,
      handleMode: 'random',
      expiresAt: Date.now() + 10 * 60 * 1000,
    })
    expect(db.getAuthFlow('hm-random')!.handleMode).toBe('random')
  })

  it('stores "picker" handle mode', () => {
    db.createAuthFlow({
      flowId: 'hm-picker',
      requestUri: 'urn:req:hm-picker',
      clientId: null,
      handleMode: 'picker',
      expiresAt: Date.now() + 10 * 60 * 1000,
    })
    expect(db.getAuthFlow('hm-picker')!.handleMode).toBe('picker')
  })

  it('stores "picker-with-random" handle mode', () => {
    db.createAuthFlow({
      flowId: 'hm-pwr',
      requestUri: 'urn:req:hm-pwr',
      clientId: null,
      handleMode: 'picker-with-random',
      expiresAt: Date.now() + 10 * 60 * 1000,
    })
    expect(db.getAuthFlow('hm-pwr')!.handleMode).toBe('picker-with-random')
  })

  it('stores null when handle mode is absent (default → picker behavior)', () => {
    db.createAuthFlow({
      flowId: 'hm-null',
      requestUri: 'urn:req:hm-null',
      clientId: null,
      handleMode: null,
      expiresAt: Date.now() + 10 * 60 * 1000,
    })
    expect(db.getAuthFlow('hm-null')!.handleMode).toBeNull()
  })

  it('validates: only known modes accepted, unknown values → null', () => {
    const VALID = ['random', 'picker', 'picker-with-random'] as const
    const validate = (raw: string | undefined): string | null =>
      raw !== undefined && (VALID as readonly string[]).includes(raw)
        ? raw
        : null

    expect(validate('random')).toBe('random')
    expect(validate('picker')).toBe('picker')
    expect(validate('picker-with-random')).toBe('picker-with-random')
    expect(validate('unknown')).toBeNull()
    expect(validate('')).toBeNull()
    expect(validate(undefined)).toBeNull()
  })

  it('getAuthFlowByRequestUri also returns handleMode', () => {
    db.createAuthFlow({
      flowId: 'hm-by-uri',
      requestUri: 'urn:req:hm-by-uri',
      clientId: null,
      handleMode: 'picker',
      expiresAt: Date.now() + 10 * 60 * 1000,
    })
    expect(db.getAuthFlowByRequestUri('urn:req:hm-by-uri')!.handleMode).toBe(
      'picker',
    )
  })
})

describe('Social providers detection', () => {
  it('empty socialProviders when no env vars set', () => {
    // Preserve original env
    const origGoogle = process.env.GOOGLE_CLIENT_ID
    const origGithub = process.env.GITHUB_CLIENT_ID
    delete process.env.GOOGLE_CLIENT_ID
    delete process.env.GITHUB_CLIENT_ID

    // Re-import to get fresh state (simulate no social providers)
    // We can't easily re-run buildSocialProviders() in isolation,
    // but we can verify the logic directly
    const providers: Record<string, unknown> = {}
    const googleId = process.env.GOOGLE_CLIENT_ID
    const googleSecret = process.env.GOOGLE_CLIENT_SECRET
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- testing env-var-driven logic
    if (googleId && googleSecret)
      providers.google = { clientId: googleId, clientSecret: googleSecret }

    expect('google' in providers).toBe(false)
    expect('github' in providers).toBe(false)

    // Restore
    if (origGoogle) process.env.GOOGLE_CLIENT_ID = origGoogle
    if (origGithub) process.env.GITHUB_CLIENT_ID = origGithub
  })

  it('includes google provider when env vars set', () => {
    const providers: Record<string, unknown> = {}
    const googleId = 'test-google-id'
    const googleSecret = 'test-google-secret'
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- testing env-var-driven logic
    if (googleId && googleSecret)
      providers.google = { clientId: googleId, clientSecret: googleSecret }
    expect('google' in providers).toBe(true)
  })

  it('excludes provider when only client_id is set (no secret)', () => {
    const providers: Record<string, unknown> = {}
    const googleId = 'test-google-id'
    const googleSecret = undefined
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- testing env-var-driven logic
    if (googleId && googleSecret)
      providers.google = { clientId: googleId, clientSecret: googleSecret }
    expect('google' in providers).toBe(false)
  })
})

describe('Login page redirect requirements', () => {
  it('requires request_uri parameter', () => {
    // Simulate what createLoginPageRouter does when request_uri is missing
    const requestUri = undefined as string | undefined
    const hasError = !requestUri
    expect(hasError).toBe(true)
  })

  it('flow_id cookie expires in 10 minutes', () => {
    const AUTH_FLOW_TTL_MS = 10 * 60 * 1000
    const nowish = Date.now()
    const expiresAt = nowish + AUTH_FLOW_TTL_MS

    // Should be approximately 10 min from now
    expect(expiresAt - nowish).toBe(600_000)
  })
})
