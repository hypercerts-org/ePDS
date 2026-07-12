import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import express from 'express'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { randomUUID } from 'node:crypto'
import Database from 'better-sqlite3'
import { postHook } from '@certified-app/shared'
import { createTestHooksRouter } from '../routes/test-hooks.js'

function readExpiresAt(dbPath: string, identifier: string): string | undefined {
  const db = new Database(dbPath)
  try {
    const row = db
      .prepare('SELECT expiresAt FROM verification WHERE identifier = ?')
      .get(identifier) as { expiresAt: string } | undefined
    return row?.expiresAt
  } finally {
    db.close()
  }
}

function seedVerification(
  dbPath: string,
  identifier: string,
  expiresAt: string,
): void {
  const db = new Database(dbPath)
  try {
    db.exec(
      'CREATE TABLE IF NOT EXISTS verification (id TEXT PRIMARY KEY, identifier TEXT NOT NULL, value TEXT NOT NULL, expiresAt TEXT NOT NULL, createdAt TEXT, updatedAt TEXT)',
    )
    db.prepare(
      'INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)',
    ).run(
      `id-${randomUUID()}`,
      identifier,
      'hashed-otp:0',
      expiresAt,
      new Date().toISOString(),
      new Date().toISOString(),
    )
  } finally {
    db.close()
  }
}

async function postExpire(
  app: express.Express,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<{ status: number; json: Record<string, unknown> }> {
  return postHook(app, '/_internal/test/expire-otp', body, headers)
}

async function postExpireAuthFlow(
  app: express.Express,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<{ status: number; json: Record<string, unknown> }> {
  return postHook(app, '/_internal/test/expire-auth-flow', body, headers)
}

function seedAuthFlow(dbPath: string, flowId: string, expiresAt: number): void {
  const db = new Database(dbPath)
  try {
    db.exec(
      `CREATE TABLE IF NOT EXISTS auth_flow (
         flow_id TEXT PRIMARY KEY,
         request_uri TEXT NOT NULL,
         client_id TEXT,
         email TEXT,
         created_at INTEGER NOT NULL,
         expires_at INTEGER NOT NULL,
         handle_mode TEXT
       )`,
    )
    db.prepare(
      `INSERT INTO auth_flow
         (flow_id, request_uri, client_id, email, created_at, expires_at, handle_mode)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      flowId,
      `urn:ietf:params:oauth:request_uri:${flowId}`,
      'demo-client',
      null,
      Date.now(),
      expiresAt,
      null,
    )
  } finally {
    db.close()
  }
}

function readAuthFlowExpiresAt(
  dbPath: string,
  flowId: string,
): number | undefined {
  const db = new Database(dbPath)
  try {
    const row = db
      .prepare('SELECT expires_at FROM auth_flow WHERE flow_id = ?')
      .get(flowId) as { expires_at: number } | undefined
    return row?.expires_at
  } finally {
    db.close()
  }
}

/**
 * Shared per-test fixture for both endpoint suites: snapshots and
 * restores the env vars the router consults, mints a unique sqlite
 * path per test, and wires up the EPDS_INTERNAL_SECRET that the test
 * helpers send. Returns a getter so the dbPath stays bound to the
 * current test even after re-assignment in beforeEach.
 */
function useTestHooksFixture(label: string): { dbPath: () => string } {
  let dbPath = ''
  let priorEnv: { hooks?: string; secret?: string; node?: string } = {}

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `${label}-${Date.now()}-${randomUUID()}.db`)
    priorEnv = {
      hooks: process.env.EPDS_TEST_HOOKS,
      secret: process.env.EPDS_INTERNAL_SECRET,
      node: process.env.NODE_ENV,
    }
    delete process.env.NODE_ENV
    process.env.EPDS_INTERNAL_SECRET = 'test-secret-1234'
  })

  afterEach(() => {
    if (priorEnv.hooks === undefined) delete process.env.EPDS_TEST_HOOKS
    else process.env.EPDS_TEST_HOOKS = priorEnv.hooks
    if (priorEnv.secret === undefined) delete process.env.EPDS_INTERNAL_SECRET
    else process.env.EPDS_INTERNAL_SECRET = priorEnv.secret
    if (priorEnv.node === undefined) delete process.env.NODE_ENV
    else process.env.NODE_ENV = priorEnv.node
    try {
      fs.unlinkSync(dbPath)
    } catch (err) {
      // Tests that throw before seeding the DB never create the file —
      // ignore ENOENT, but surface anything else so genuine teardown
      // failures aren't hidden.
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err
    }
  })

  return { dbPath: () => dbPath }
}

describe('test-hooks router — expire-otp', () => {
  const { dbPath } = useTestHooksFixture('test-hooks-otp')

  it('refuses to mount when NODE_ENV=production', () => {
    process.env.NODE_ENV = 'production'
    expect(() => createTestHooksRouter(dbPath())).toThrow(/production/i)
  })

  it('rejects requests without the internal secret', async () => {
    seedVerification(
      dbPath(),
      'sign-in-otp-alice@example.com',
      new Date(Date.now() + 600_000).toISOString(),
    )
    const app = express()
    app.use(express.json())
    app.use(createTestHooksRouter(dbPath()))

    const res = await postExpire(app, { email: 'alice@example.com' })
    expect(res.status).toBe(401)
  })

  it('rejects requests with the wrong secret', async () => {
    const app = express()
    app.use(express.json())
    app.use(createTestHooksRouter(dbPath()))

    const res = await postExpire(
      app,
      { email: 'alice@example.com' },
      { 'x-internal-secret': 'wrong-secret' },
    )
    expect(res.status).toBe(401)
  })

  it('rejects unknown OTP types', async () => {
    const app = express()
    app.use(express.json())
    app.use(createTestHooksRouter(dbPath()))

    const res = await postExpire(
      app,
      { email: 'alice@example.com', type: 'password-reset' },
      { 'x-internal-secret': 'test-secret-1234' },
    )
    expect(res.status).toBe(400)
    expect(String(res.json.error)).toMatch(/Unknown type/)
  })

  it('rejects requests missing the email field', async () => {
    const app = express()
    app.use(express.json())
    app.use(createTestHooksRouter(dbPath()))

    const res = await postExpire(
      app,
      {},
      { 'x-internal-secret': 'test-secret-1234' },
    )
    expect(res.status).toBe(400)
  })

  it('backdates the verification row for a sign-in OTP', async () => {
    const future = new Date(Date.now() + 600_000).toISOString()
    seedVerification(dbPath(), 'sign-in-otp-alice@example.com', future)

    const app = express()
    app.use(express.json())
    app.use(createTestHooksRouter(dbPath()))

    const res = await postExpire(
      app,
      { email: 'alice@example.com' },
      { 'x-internal-secret': 'test-secret-1234' },
    )

    expect(res.status).toBe(200)
    expect(res.json.updated).toBe(1)

    const newExpiresAt = readExpiresAt(
      dbPath(),
      'sign-in-otp-alice@example.com',
    )
    expect(newExpiresAt).toBeDefined()
    expect(new Date(newExpiresAt!).getTime()).toBeLessThan(Date.now())
  })

  it('returns updated=0 when no row matches the identifier', async () => {
    const app = express()
    app.use(express.json())
    app.use(createTestHooksRouter(dbPath()))
    // Seed a verification table but for a different email so the WHERE
    // clause doesn't match.
    seedVerification(
      dbPath(),
      'sign-in-otp-bob@example.com',
      new Date(Date.now() + 600_000).toISOString(),
    )

    const res = await postExpire(
      app,
      { email: 'alice@example.com' },
      { 'x-internal-secret': 'test-secret-1234' },
    )

    expect(res.status).toBe(200)
    expect(res.json.updated).toBe(0)
  })

  it('lowercases the email when constructing the identifier', async () => {
    seedVerification(
      dbPath(),
      'sign-in-otp-alice@example.com',
      new Date(Date.now() + 600_000).toISOString(),
    )
    const app = express()
    app.use(express.json())
    app.use(createTestHooksRouter(dbPath()))

    const res = await postExpire(
      app,
      { email: 'Alice@Example.COM' },
      { 'x-internal-secret': 'test-secret-1234' },
    )

    expect(res.status).toBe(200)
    expect(res.json.updated).toBe(1)
  })
})

describe('test-hooks router — expire-auth-flow', () => {
  const { dbPath } = useTestHooksFixture('test-hooks-af')

  it('refuses to mount when NODE_ENV=production', () => {
    process.env.NODE_ENV = 'production'
    expect(() => createTestHooksRouter(dbPath())).toThrow(/production/i)
  })

  it('rejects requests without the internal secret', async () => {
    seedAuthFlow(dbPath(), 'flow-1', Date.now() + 600_000)
    const app = express()
    app.use(express.json())
    app.use(createTestHooksRouter(dbPath()))

    const res = await postExpireAuthFlow(app, { email: 'alice@example.com' })
    expect(res.status).toBe(401)
  })

  it('rejects requests with the wrong secret', async () => {
    const app = express()
    app.use(express.json())
    app.use(createTestHooksRouter(dbPath()))

    const res = await postExpireAuthFlow(
      app,
      { email: 'alice@example.com' },
      { 'x-internal-secret': 'wrong-secret' },
    )
    expect(res.status).toBe(401)
  })

  it('rejects requests missing the email field', async () => {
    seedAuthFlow(dbPath(), 'flow-1', Date.now() + 600_000)
    const app = express()
    app.use(express.json())
    app.use(createTestHooksRouter(dbPath()))

    const res = await postExpireAuthFlow(
      app,
      {},
      { 'x-internal-secret': 'test-secret-1234' },
    )
    expect(res.status).toBe(400)
    expect(String(res.json.error)).toMatch(/email/i)
  })

  it('backdates a single live auth_flow row', async () => {
    const future = Date.now() + 600_000
    seedAuthFlow(dbPath(), 'flow-1', future)

    const app = express()
    app.use(express.json())
    app.use(createTestHooksRouter(dbPath()))

    const res = await postExpireAuthFlow(
      app,
      { email: 'alice@example.com' },
      { 'x-internal-secret': 'test-secret-1234' },
    )

    expect(res.status).toBe(200)
    expect(res.json.updated).toBe(1)

    const newExpiresAt = readAuthFlowExpiresAt(dbPath(), 'flow-1')
    expect(newExpiresAt).toBeDefined()
    expect(newExpiresAt!).toBeLessThan(Date.now())
  })

  it('backdates only the matching auth_flow when request_uri is supplied', async () => {
    const future = Date.now() + 600_000
    seedAuthFlow(dbPath(), 'flow-a', future)
    seedAuthFlow(dbPath(), 'flow-b', future + 1_000)

    const app = express()
    app.use(express.json())
    app.use(createTestHooksRouter(dbPath()))

    const res = await postExpireAuthFlow(
      app,
      {
        email: 'alice@example.com',
        request_uri: 'urn:ietf:params:oauth:request_uri:flow-b',
      },
      { 'x-internal-secret': 'test-secret-1234' },
    )

    expect(res.status).toBe(200)
    expect(res.json.updated).toBe(1)

    expect(readAuthFlowExpiresAt(dbPath(), 'flow-a')!).toBeGreaterThan(
      Date.now(),
    )
    expect(readAuthFlowExpiresAt(dbPath(), 'flow-b')!).toBeLessThan(Date.now())
  })

  it('returns updated=0 when there are no live auth_flow rows', async () => {
    // Schema exists (seeded by another flow that is already expired) but
    // no rows match the WHERE clause expires_at > now.
    seedAuthFlow(dbPath(), 'flow-old', Date.now() - 60_000)

    const app = express()
    app.use(express.json())
    app.use(createTestHooksRouter(dbPath()))

    const res = await postExpireAuthFlow(
      app,
      { email: 'alice@example.com' },
      { 'x-internal-secret': 'test-secret-1234' },
    )

    expect(res.status).toBe(200)
    expect(res.json.updated).toBe(0)

    // Already-expired rows are left untouched (we only backdate live flows).
    const oldExpiresAt = readAuthFlowExpiresAt(dbPath(), 'flow-old')
    expect(oldExpiresAt).toBeDefined()
    expect(oldExpiresAt!).toBeGreaterThan(Date.now() - 120_000)
  })

  it('backdates ALL live auth_flow rows when request_uri is omitted (legacy fallback)', async () => {
    // The fallback deliberately backdates every live flow, not just "the
    // one for this email", because the auth_flow.email column is rarely
    // populated in practice. E2E callers should pass request_uri so
    // parallel workers do not interfere with each other.
    const future = Date.now() + 600_000
    seedAuthFlow(dbPath(), 'flow-a', future)
    seedAuthFlow(dbPath(), 'flow-b', future + 1_000)
    seedAuthFlow(dbPath(), 'flow-c-expired', Date.now() - 10_000)

    const app = express()
    app.use(express.json())
    app.use(createTestHooksRouter(dbPath()))

    const res = await postExpireAuthFlow(
      app,
      { email: 'alice@example.com' },
      { 'x-internal-secret': 'test-secret-1234' },
    )

    expect(res.status).toBe(200)
    expect(res.json.updated).toBe(2)

    expect(readAuthFlowExpiresAt(dbPath(), 'flow-a')!).toBeLessThan(Date.now())
    expect(readAuthFlowExpiresAt(dbPath(), 'flow-b')!).toBeLessThan(Date.now())
  })
})
