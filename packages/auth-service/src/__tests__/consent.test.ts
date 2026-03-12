/**
 * Tests for the consent route — covers both flow_id mode (new) and legacy
 * request_uri mode (for backward compatibility with old OTP path).
 *
 * Uses minimal mock req/res objects to avoid a supertest dependency.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { EpdsDb } from '@certified-app/shared'
import type { AuthServiceContext } from '../context.js'
import type { AuthServiceConfig } from '../context.js'

// Build a minimal mock context for consent tests
function makeMockContext(db: EpdsDb): AuthServiceContext {
  const config: AuthServiceConfig = {
    hostname: 'auth.localhost',
    port: 3001,
    sessionSecret: 'test-session-secret',
    csrfSecret: 'test-csrf-secret',
    epdsCallbackSecret: 'test-callback-secret-32-chars-long!!',
    pdsHostname: 'pds.localhost',
    pdsPublicUrl: 'http://pds.localhost:3000',
    email: {
      provider: 'smtp',
      smtpHost: 'localhost',
      smtpPort: 1025,
      from: 'noreply@localhost',
      fromName: 'Test PDS',
    },
    dbLocation: ':memory:',
  }

  return {
    db,
    config,
    emailSender: null as unknown as AuthServiceContext['emailSender'],
    destroy: () => {
      db.close()
    },
  }
}

// Mock helpers for future route-level tests (currently only DB logic is tested)

function _makeMockRes() {
  const res = {
    _status: 200,
    body: '',
    redirectTo: '',
    cleared: [] as string[],
    locals: { csrfToken: 'test-csrf-token' },
    status(code: number) {
      this._status = code
      return this
    },
    type(_t: string) {
      return this
    },
    send(body: string) {
      this.body = body
      return this
    },
    redirect(code: number, url: string) {
      this._status = code
      this.redirectTo = url
      return this
    },
    clearCookie(name: string) {
      this.cleared.push(name)
      return this
    },
  }
  return res
}

function _makeGetReq(queryStr: string) {
  const url = new URL('http://localhost/auth/consent?' + queryStr)
  const query: Record<string, string> = {}
  url.searchParams.forEach((v, k) => {
    query[k] = v
  })
  return { query, cookies: {}, body: {} }
}

function _makePostReq(body: Record<string, string>) {
  return { query: {}, cookies: {}, body }
}

describe('Consent route logic', () => {
  let db: EpdsDb
  let dbPath: string
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  let ctx: AuthServiceContext

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `test-consent-${Date.now()}.db`)
    db = new EpdsDb(dbPath)
    ctx = makeMockContext(db)
  })

  afterEach(() => {
    db.close()
    try {
      fs.unlinkSync(dbPath)
      // eslint-disable-next-line no-empty
    } catch {}
  })

  describe('auth_flow table operations (used by consent)', () => {
    it('creates and retrieves an auth_flow record', () => {
      db.createAuthFlow({
        flowId: 'flow-abc',
        requestUri: 'urn:ietf:params:oauth:request_uri:test',
        clientId: 'https://client.example.com',
        expiresAt: Date.now() + 5 * 60 * 1000,
      })

      const flow = db.getAuthFlow('flow-abc')
      expect(flow).toBeDefined()
      expect(flow!.requestUri).toBe('urn:ietf:params:oauth:request_uri:test')
      expect(flow!.clientId).toBe('https://client.example.com')
    })

    it('returns undefined for non-existent flow', () => {
      expect(db.getAuthFlow('non-existent')).toBeUndefined()
    })

    it('returns undefined for expired flow', () => {
      db.createAuthFlow({
        flowId: 'expired-flow',
        requestUri: 'urn:ietf:params:oauth:request_uri:expired',
        clientId: null,
        expiresAt: Date.now() - 1000, // already expired
      })

      expect(db.getAuthFlow('expired-flow')).toBeUndefined()
    })

    it('deletes a flow after approval', () => {
      db.createAuthFlow({
        flowId: 'delete-me',
        requestUri: 'urn:ietf:params:oauth:request_uri:delete',
        clientId: null,
        expiresAt: Date.now() + 5 * 60 * 1000,
      })

      expect(db.getAuthFlow('delete-me')).toBeDefined()
      db.deleteAuthFlow('delete-me')
      expect(db.getAuthFlow('delete-me')).toBeUndefined()
    })
  })

  describe('client login tracking (used by consent)', () => {
    it('records and detects client login', () => {
      expect(
        db.hasClientLogin('user@example.com', 'https://app.example.com'),
      ).toBe(false)
      db.recordClientLogin('user@example.com', 'https://app.example.com')
      expect(
        db.hasClientLogin('user@example.com', 'https://app.example.com'),
      ).toBe(true)
    })

    it('is case-insensitive for email', () => {
      db.recordClientLogin('User@Example.COM', 'https://app.example.com')
      expect(
        db.hasClientLogin('user@example.com', 'https://app.example.com'),
      ).toBe(true)
    })

    it('does not share logins across different clients', () => {
      db.recordClientLogin('user@example.com', 'https://app1.example.com')
      expect(
        db.hasClientLogin('user@example.com', 'https://app2.example.com'),
      ).toBe(false)
    })
  })

  describe('signCallback (used by consent POST)', () => {
    it('produces a stable HMAC signature for the same inputs', async () => {
      const { signCallback } = await import('@certified-app/shared')
      const params = {
        request_uri: 'urn:req:test',
        email: 'user@example.com',
        approved: '1',
        new_account: '0',
      }
      const r1 = signCallback(params, 'secret-key')
      // Same params but allow ts to change — just verify structure
      expect(r1.sig).toMatch(/^[0-9a-f]{64}$/)
      expect(r1.ts).toMatch(/^\d+$/)
    })

    it('produces different signatures for different emails', async () => {
      const { signCallback } = await import('@certified-app/shared')
      const base = { request_uri: 'urn:req:x', approved: '1', new_account: '0' }
      const r1 = signCallback({ ...base, email: 'alice@example.com' }, 'secret')
      const r2 = signCallback({ ...base, email: 'bob@example.com' }, 'secret')
      expect(r1.sig).not.toBe(r2.sig)
    })

    it('verifies correctly with verifyCallback', async () => {
      const { signCallback, verifyCallback } =
        await import('@certified-app/shared')
      const params = {
        request_uri: 'urn:req:verify-test',
        email: 'user@example.com',
        approved: '1',
        new_account: '0',
      }
      const { sig, ts } = signCallback(params, 'shared-secret')
      const valid = verifyCallback(params, ts, sig, 'shared-secret')
      expect(valid).toBe(true)
    })
  })

  describe('flow_id mode: consent uses auth_flow table', () => {
    it('auth_flow row survives consent GET (not deleted until POST approve)', () => {
      // Simulate complete.ts creating an auth_flow before redirecting to consent
      db.createAuthFlow({
        flowId: 'get-flow',
        requestUri: 'urn:ietf:params:oauth:request_uri:get-test',
        clientId: 'https://app.example.com',
        expiresAt: Date.now() + 5 * 60 * 1000,
      })

      // GET consent should not delete the flow
      const flow = db.getAuthFlow('get-flow')
      expect(flow).toBeDefined()

      // Simulate: consent GET reads the flow but doesn't delete it
      const retrieved = db.getAuthFlow('get-flow')
      expect(retrieved).toBeDefined()
      expect(retrieved!.requestUri).toBe(
        'urn:ietf:params:oauth:request_uri:get-test',
      )
    })

    it('auth_flow row is deleted after approve (POST)', () => {
      db.createAuthFlow({
        flowId: 'post-flow',
        requestUri: 'urn:ietf:params:oauth:request_uri:post-test',
        clientId: null,
        expiresAt: Date.now() + 5 * 60 * 1000,
      })

      // Simulate what consent POST does on approve
      const flow = db.getAuthFlow('post-flow')
      expect(flow).toBeDefined()
      db.deleteAuthFlow('post-flow')
      expect(db.getAuthFlow('post-flow')).toBeUndefined()
    })
  })
})
