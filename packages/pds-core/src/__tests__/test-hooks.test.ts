import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import express from 'express'
import { postHook } from '@certified-app/shared'
import { installTestHooks } from '../lib/test-hooks.js'

// Minimal Kysely-like update query mock: chains `.set().where()*.executeTakeFirst()`
// and records what was called for assertions. Enough for the hook —
// `installTestHooks` only ever calls these four chain methods.
function makeFakeUpdate() {
  const wheres: Array<[string, string, unknown]> = []
  let setVals: Record<string, unknown> = {}
  let result: { numUpdatedRows: number | bigint } = { numUpdatedRows: 0 }
  const chain = {
    set(vals: Record<string, unknown>) {
      setVals = vals
      return chain
    },
    where(col: string, op: string, val: unknown) {
      wheres.push([col, op, val])
      return chain
    },
    executeTakeFirst() {
      return Promise.resolve(result)
    },
  }
  return {
    chain,
    setUpdatedRows(n: number | bigint) {
      result = { numUpdatedRows: n }
    },
    inspect() {
      return { setVals, wheres }
    },
  }
}

// Sibling shape for the delete-par chain: `.where().executeTakeFirst()`,
// returning {numDeletedRows}. Same recording style.
function makeFakeDelete() {
  const wheres: Array<[string, string, unknown]> = []
  let result: { numDeletedRows: number | bigint } = { numDeletedRows: 0 }
  const chain = {
    where(col: string, op: string, val: unknown) {
      wheres.push([col, op, val])
      return chain
    },
    executeTakeFirst() {
      return Promise.resolve(result)
    },
  }
  return {
    chain,
    setDeletedRows(n: number | bigint) {
      result = { numDeletedRows: n }
    },
    inspect() {
      return { wheres }
    },
  }
}

function makeFakePds(opts: {
  fakeUpdate?: ReturnType<typeof makeFakeUpdate>
  fakeDelete?: ReturnType<typeof makeFakeDelete>
  failOnExecute?: boolean
  failOnDelete?: boolean
}) {
  return {
    ctx: {
      accountManager: {
        db: {
          db: {
            updateTable: (table: string) => {
              expect(table).toBe('account_device')
              if (opts.failOnExecute) {
                return {
                  set: () => ({
                    where: () => ({
                      executeTakeFirst: () =>
                        Promise.reject(new Error('db down')),
                    }),
                  }),
                }
              }
              return opts.fakeUpdate?.chain
            },
            deleteFrom: (table: string) => {
              expect(table).toBe('authorization_request')
              if (opts.failOnDelete) {
                return {
                  where: () => ({
                    executeTakeFirst: () =>
                      Promise.reject(new Error('db down')),
                  }),
                }
              }
              return opts.fakeDelete?.chain
            },
          },
        },
      },
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any
}

/** Build an express app with installTestHooks applied to a default
 *  fake-pds + fake-update + fake-delete fixture. Tests that need to
 *  inspect the underlying update/delete or override the failure mode
 *  pass extra options here. */
function setupApp(opts?: {
  failOnExecute?: boolean
  updatedRows?: number | bigint
  failOnDelete?: boolean
  deletedRows?: number | bigint
}): {
  app: express.Express
  fakeUpdate: ReturnType<typeof makeFakeUpdate>
  fakeDelete: ReturnType<typeof makeFakeDelete>
  logger: { warn: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> }
} {
  const fakeUpdate = makeFakeUpdate()
  const fakeDelete = makeFakeDelete()
  if (opts?.updatedRows !== undefined)
    fakeUpdate.setUpdatedRows(opts.updatedRows)
  if (opts?.deletedRows !== undefined)
    fakeDelete.setDeletedRows(opts.deletedRows)
  const logger = { warn: vi.fn(), error: vi.fn() }
  const app = express()
  installTestHooks({
    pds: makeFakePds({
      fakeUpdate,
      fakeDelete,
      failOnExecute: opts?.failOnExecute,
      failOnDelete: opts?.failOnDelete,
    }),
    app,
    logger,
  })
  return { app, fakeUpdate, fakeDelete, logger }
}

const SECRET = 'test-secret-1234'
const AUTH_HEADER = { 'x-internal-secret': SECRET }

const EXPIRE_PATH = '/_internal/test/expire-device-account'
const DELETE_PAR_PATH = '/_internal/test/delete-par'

const VALID_REQUEST_URI = 'urn:ietf:params:oauth:request_uri:req-deadbeef'

function useEnvFixture(): void {
  let priorEnv: { hooks?: string; secret?: string; node?: string } = {}
  beforeEach(() => {
    priorEnv = {
      hooks: process.env.EPDS_TEST_HOOKS,
      secret: process.env.EPDS_INTERNAL_SECRET,
      node: process.env.NODE_ENV,
    }
    delete process.env.NODE_ENV
    process.env.EPDS_INTERNAL_SECRET = SECRET
    process.env.EPDS_TEST_HOOKS = '1'
  })
  afterEach(() => {
    if (priorEnv.hooks === undefined) delete process.env.EPDS_TEST_HOOKS
    else process.env.EPDS_TEST_HOOKS = priorEnv.hooks
    if (priorEnv.secret === undefined) delete process.env.EPDS_INTERNAL_SECRET
    else process.env.EPDS_INTERNAL_SECRET = priorEnv.secret
    if (priorEnv.node === undefined) delete process.env.NODE_ENV
    else process.env.NODE_ENV = priorEnv.node
  })
}

describe('installTestHooks — expire-device-account', () => {
  useEnvFixture()

  it('does nothing when EPDS_TEST_HOOKS is unset', async () => {
    delete process.env.EPDS_TEST_HOOKS
    const { app } = setupApp()
    // Route was never mounted, so the request 404s before any auth check.
    const res = await postHook(
      app,
      EXPIRE_PATH,
      { did: 'did:plc:a' },
      AUTH_HEADER,
    )
    expect(res.status).toBe(404)
  })

  it('refuses to install when NODE_ENV=production', () => {
    process.env.NODE_ENV = 'production'
    expect(() => {
      setupApp()
    }).toThrow(/production/i)
  })

  it('rejects requests without the internal secret', async () => {
    const { app } = setupApp()
    const res = await postHook(app, EXPIRE_PATH, { did: 'did:plc:a' })
    expect(res.status).toBe(401)
  })

  it('rejects requests with the wrong secret', async () => {
    const { app } = setupApp()
    const res = await postHook(
      app,
      EXPIRE_PATH,
      { did: 'did:plc:a' },
      { 'x-internal-secret': 'wrong' },
    )
    expect(res.status).toBe(401)
  })

  it('rejects requests missing the did', async () => {
    const { app } = setupApp()
    const res = await postHook(app, EXPIRE_PATH, {}, AUTH_HEADER)
    expect(res.status).toBe(400)
    expect(String(res.json.error)).toMatch(/did/i)
  })

  it.each([
    { label: 'number', value: 42 },
    { label: 'object', value: { sub: 'did:plc:a' } },
    { label: 'array', value: ['did:plc:a'] },
    { label: 'null', value: null },
  ])(
    'returns 400 (not 500) when did is a non-string $label',
    async ({ value }) => {
      const { app } = setupApp()
      const res = await postHook(app, EXPIRE_PATH, { did: value }, AUTH_HEADER)
      // Pre-fix this would crash inside .trim() and yield 500. The
      // type-guard now treats non-string values as "missing did".
      expect(res.status).toBe(400)
      expect(String(res.json.error)).toMatch(/did/i)
    },
  )

  it('backdates every device row for the did when no deviceId is given', async () => {
    const { app, fakeUpdate } = setupApp({ updatedRows: 2 })
    const res = await postHook(
      app,
      EXPIRE_PATH,
      { did: 'did:plc:a' },
      AUTH_HEADER,
    )

    expect(res.status).toBe(200)
    expect(res.json.updated).toBe(2)
    const { setVals, wheres } = fakeUpdate.inspect()
    // updatedAt is set to an ISO string ~8 days in the past.
    const updatedAt = setVals.updatedAt as string
    const past = new Date(updatedAt).getTime()
    const eightDaysAgo = Date.now() - 8 * 24 * 60 * 60 * 1000
    expect(Math.abs(past - eightDaysAgo)).toBeLessThan(60_000)
    // Only one WHERE clause: did. No deviceId narrowing.
    expect(wheres).toEqual([['did', '=', 'did:plc:a']])
  })

  it('narrows by deviceId when both keys are provided', async () => {
    const { app, fakeUpdate } = setupApp({ updatedRows: 1 })
    const res = await postHook(
      app,
      EXPIRE_PATH,
      { did: 'did:plc:a', deviceId: 'dev-deadbeef' },
      AUTH_HEADER,
    )

    expect(res.status).toBe(200)
    expect(res.json.updated).toBe(1)
    expect(fakeUpdate.inspect().wheres).toEqual([
      ['did', '=', 'did:plc:a'],
      ['deviceId', '=', 'dev-deadbeef'],
    ])
  })

  it('returns 500 and logs when the underlying update throws', async () => {
    const { app, logger } = setupApp({ failOnExecute: true })
    const res = await postHook(
      app,
      EXPIRE_PATH,
      { did: 'did:plc:a' },
      AUTH_HEADER,
    )

    expect(res.status).toBe(500)
    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ did: 'did:plc:a' }),
      expect.stringContaining('Failed to backdate'),
    )
  })

  it('coerces bigint numUpdatedRows to a regular Number', async () => {
    // Kysely's actual return type is `bigint` on better-sqlite3 driver.
    const { app } = setupApp({ updatedRows: BigInt(3) })
    const res = await postHook(
      app,
      EXPIRE_PATH,
      { did: 'did:plc:a' },
      AUTH_HEADER,
    )

    expect(res.status).toBe(200)
    expect(res.json.updated).toBe(3)
    expect(typeof res.json.updated).toBe('number')
  })
})

describe('installTestHooks — delete-par', () => {
  useEnvFixture()

  it('does nothing when EPDS_TEST_HOOKS is unset', async () => {
    delete process.env.EPDS_TEST_HOOKS
    const { app } = setupApp()
    const res = await postHook(
      app,
      DELETE_PAR_PATH,
      { request_uri: VALID_REQUEST_URI },
      AUTH_HEADER,
    )
    expect(res.status).toBe(404)
  })

  it('rejects requests without the internal secret', async () => {
    const { app } = setupApp()
    const res = await postHook(app, DELETE_PAR_PATH, {
      request_uri: VALID_REQUEST_URI,
    })
    expect(res.status).toBe(401)
  })

  it('rejects requests with the wrong secret', async () => {
    const { app } = setupApp()
    const res = await postHook(
      app,
      DELETE_PAR_PATH,
      { request_uri: VALID_REQUEST_URI },
      { 'x-internal-secret': 'wrong' },
    )
    expect(res.status).toBe(401)
  })

  it('rejects requests missing the request_uri', async () => {
    const { app } = setupApp()
    const res = await postHook(app, DELETE_PAR_PATH, {}, AUTH_HEADER)
    expect(res.status).toBe(400)
    expect(String(res.json.error)).toMatch(/request_uri/i)
  })

  it('rejects malformed request_uri values', async () => {
    const { app } = setupApp()
    const res = await postHook(
      app,
      DELETE_PAR_PATH,
      { request_uri: 'not-a-par-uri' },
      AUTH_HEADER,
    )
    expect(res.status).toBe(400)
  })

  it.each([
    'urn:ietf:params:oauth:request_uri:req-%',
    'urn:ietf:params:oauth:request_uri:req-%E0%A4%A',
    'urn:ietf:params:oauth:request_uri:req-foo%',
  ])(
    'returns 400 (not 500) for request_uri with bad percent-encoding: %s',
    async (badUri) => {
      const { app } = setupApp()
      const res = await postHook(
        app,
        DELETE_PAR_PATH,
        { request_uri: badUri },
        AUTH_HEADER,
      )
      // Pre-fix decodeURIComponent would throw URIError inside the
      // try block and surface as 500. The decode-and-validate helper
      // now catches URIError and surfaces malformed-encoding inputs
      // as 400 the same way as a malformed prefix.
      expect(res.status).toBe(400)
      expect(String(res.json.error)).toMatch(/request_uri/i)
    },
  )

  it.each([
    { label: 'number', value: 42 },
    { label: 'object', value: { uri: VALID_REQUEST_URI } },
    { label: 'array', value: [VALID_REQUEST_URI] },
    { label: 'null', value: null },
  ])(
    'returns 400 (not 500) when request_uri is a non-string $label',
    async ({ value }) => {
      const { app } = setupApp()
      const res = await postHook(
        app,
        DELETE_PAR_PATH,
        { request_uri: value },
        AUTH_HEADER,
      )
      // Pre-fix this would crash inside .trim() and yield 500. The
      // type-guard now treats non-string values as malformed input.
      expect(res.status).toBe(400)
      expect(String(res.json.error)).toMatch(/request_uri/i)
    },
  )

  it('deletes the matching authorization_request row', async () => {
    const { app, fakeDelete } = setupApp({ deletedRows: 1 })
    const res = await postHook(
      app,
      DELETE_PAR_PATH,
      { request_uri: VALID_REQUEST_URI },
      AUTH_HEADER,
    )

    expect(res.status).toBe(200)
    expect(res.json.deleted).toBe(1)
    // The hook keys exclusively on id (the request_uri tail, decoded).
    expect(fakeDelete.inspect().wheres).toEqual([['id', '=', 'req-deadbeef']])
  })

  it('returns deleted=0 when no row matches', async () => {
    const { app } = setupApp({ deletedRows: 0 })
    const res = await postHook(
      app,
      DELETE_PAR_PATH,
      { request_uri: VALID_REQUEST_URI },
      AUTH_HEADER,
    )

    expect(res.status).toBe(200)
    expect(res.json.deleted).toBe(0)
  })

  it('decodes percent-encoded request_uri tails before lookup', async () => {
    // Real PAR request_uris come from upstream as `req-${hex}` so they
    // don't actually need decoding, but the hook calls
    // decodeURIComponent() on the tail — verify the decode path works
    // by feeding a tail with an encoded character.
    const { app, fakeDelete } = setupApp({ deletedRows: 1 })
    const res = await postHook(
      app,
      DELETE_PAR_PATH,
      { request_uri: 'urn:ietf:params:oauth:request_uri:req-foo%20bar' },
      AUTH_HEADER,
    )

    expect(res.status).toBe(200)
    expect(fakeDelete.inspect().wheres).toEqual([['id', '=', 'req-foo bar']])
  })

  it('returns 500 and logs when the underlying delete throws', async () => {
    const { app, logger } = setupApp({ failOnDelete: true })
    const res = await postHook(
      app,
      DELETE_PAR_PATH,
      { request_uri: VALID_REQUEST_URI },
      AUTH_HEADER,
    )

    expect(res.status).toBe(500)
    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ requestUri: VALID_REQUEST_URI }),
      expect.stringContaining('Failed to delete'),
    )
  })

  it('coerces bigint numDeletedRows to a regular Number', async () => {
    const { app } = setupApp({ deletedRows: BigInt(1) })
    const res = await postHook(
      app,
      DELETE_PAR_PATH,
      { request_uri: VALID_REQUEST_URI },
      AUTH_HEADER,
    )

    expect(res.status).toBe(200)
    expect(res.json.deleted).toBe(1)
    expect(typeof res.json.deleted).toBe('number')
  })
})
