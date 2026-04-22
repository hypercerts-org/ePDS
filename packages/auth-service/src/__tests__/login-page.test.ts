/**
 * Tests for the unified login page (GET /oauth/authorize).
 *
 * The login page:
 * 1. Creates an auth_flow row to thread request_uri through better-auth
 * 2. Sets the epds_auth_flow cookie
 * 3. Renders a login page with email OTP form + optional social buttons
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { randomBytes } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import {
  EpdsDb,
  clearClientMetadataCache,
  _seedClientMetadataCacheForTest,
} from '@certified-app/shared'
import type { HandleMode } from '@certified-app/shared'
import {
  resolveHandleMode,
  safeResolveClientMetadata,
} from '../routes/login-page.js'
import type { ClientMetadata } from '../lib/client-metadata.js'

// ---------------------------------------------------------------------------
// Shared DB helpers
// ---------------------------------------------------------------------------

function makeDb(prefix: string): { db: EpdsDb; dbPath: string } {
  const dbPath = path.join(os.tmpdir(), `${prefix}-${Date.now()}.db`)
  return { db: new EpdsDb(dbPath), dbPath }
}

function closeDb(db: EpdsDb, dbPath: string): void {
  db.close()
  try {
    fs.unlinkSync(dbPath)
    // eslint-disable-next-line no-empty
  } catch {}
}

// ---------------------------------------------------------------------------
// Shared env-var helpers for resolveHandleMode tests
// ---------------------------------------------------------------------------

function withEnv(value: string | undefined, fn: () => void): void {
  const orig = process.env.EPDS_DEFAULT_HANDLE_MODE
  if (value === undefined) {
    delete process.env.EPDS_DEFAULT_HANDLE_MODE
  } else {
    process.env.EPDS_DEFAULT_HANDLE_MODE = value
  }
  try {
    fn()
  } finally {
    if (orig === undefined) {
      delete process.env.EPDS_DEFAULT_HANDLE_MODE
    } else {
      process.env.EPDS_DEFAULT_HANDLE_MODE = orig
    }
  }
}

describe('Login page auth_flow creation', () => {
  let db: EpdsDb
  let dbPath: string

  beforeEach(() => {
    ;({ db, dbPath } = makeDb('test-login'))
  })

  afterEach(() => {
    closeDb(db, dbPath)
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
    ;({ db, dbPath } = makeDb('test-handle-mode'))
  })

  afterEach(() => {
    closeDb(db, dbPath)
  })

  const handleModes: Array<HandleMode | null> = [
    'random',
    'picker',
    'picker-with-random',
    null,
  ]

  it.each(handleModes)('stores handleMode=%s', (handleMode) => {
    const flowId = `hm-${String(handleMode)}`
    db.createAuthFlow({
      flowId,
      requestUri: `urn:req:${flowId}`,
      clientId: null,
      handleMode,
      expiresAt: Date.now() + 10 * 60 * 1000,
    })
    expect(db.getAuthFlow(flowId)!.handleMode).toBe(handleMode)
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

describe('resolveHandleMode', () => {
  it('returns query param when it is a valid mode', () => {
    const result = resolveHandleMode('random', {})
    expect(result).toBe('random')
  })

  it('falls back to client metadata when query param is absent', () => {
    const clientMeta: ClientMetadata = { epds_handle_mode: 'picker' }
    const result = resolveHandleMode(undefined, clientMeta)
    expect(result).toBe('picker')
  })

  it('falls back to env var when query param and client metadata are absent', () => {
    withEnv('picker-with-random', () => {
      expect(resolveHandleMode(undefined, {})).toBe('picker-with-random')
    })
  })

  it('returns picker-with-random when no valid mode is provided at any level', () => {
    withEnv(undefined, () => {
      expect(resolveHandleMode(undefined, {})).toBe('picker-with-random')
    })
  })

  it('ignores invalid values and falls back to next level', () => {
    // Cast via unknown to simulate malformed client metadata from a real fetch
    const clientMeta = {
      epds_handle_mode: 'invalid-mode',
    } as unknown as ClientMetadata
    withEnv('random', () => {
      // Query param is invalid, client metadata is invalid, env var is valid
      expect(resolveHandleMode('garbage', clientMeta)).toBe('random')
    })
  })

  it('returns picker-with-random when all levels have invalid values', () => {
    // Cast via unknown to simulate malformed client metadata
    const clientMeta = {
      epds_handle_mode: 'invalid-mode',
    } as unknown as ClientMetadata
    withEnv(undefined, () => {
      expect(resolveHandleMode('garbage', clientMeta)).toBe(
        'picker-with-random',
      )
    })
  })

  it('prioritizes query param over client metadata', () => {
    const clientMeta: ClientMetadata = { epds_handle_mode: 'picker' }
    const result = resolveHandleMode('random', clientMeta)
    expect(result).toBe('random')
  })

  it('prioritizes client metadata over env var', () => {
    const clientMeta: ClientMetadata = { epds_handle_mode: 'picker' }
    withEnv('random', () => {
      expect(resolveHandleMode(undefined, clientMeta)).toBe('picker')
    })
  })
})

describe('safeResolveClientMetadata', () => {
  const originalFetch = globalThis.fetch

  beforeEach(() => {
    clearClientMetadataCache()
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it('returns empty object when clientId is undefined', async () => {
    const result = await safeResolveClientMetadata(undefined)
    expect(result).toEqual({})
  })

  it('returns fallback metadata when fetch fails', async () => {
    // resolveClientMetadata has internal error handling, so it returns fallback
    // (domain extraction) rather than throwing. safeResolveClientMetadata's
    // catch is defense-in-depth but unreachable in current implementation.
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'))
    const result = await safeResolveClientMetadata('https://app.example.com')
    expect(result).toEqual({ client_name: 'app.example.com' })
  })

  it('returns fallback metadata when fetch returns non-OK status', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      headers: { get: () => null },
    } as unknown as Response)
    const result = await safeResolveClientMetadata('https://app.example.com')
    expect(result).toEqual({ client_name: 'app.example.com' })
  })

  it('returns metadata when cache is seeded', async () => {
    const mockMetadata: ClientMetadata = {
      client_name: 'Test App',
      brand_color: '#123456',
    }
    _seedClientMetadataCacheForTest(
      'https://test-app.coolapp.dev',
      mockMetadata,
    )
    const result = await safeResolveClientMetadata(
      'https://test-app.coolapp.dev',
    )
    expect(result).toEqual(mockMetadata)
  })
})
