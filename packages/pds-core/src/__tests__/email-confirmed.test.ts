import { describe, expect, it, vi } from 'vitest'

import {
  backfillEmailConfirmedAt,
  formatBackfillReport,
  markEmailConfirmed,
  parseDryRun,
  setEmailConfirmedAt,
} from '../lib/email-confirmed.js'

/** Records the single-account UPDATE that setEmailConfirmedAt builds:
 *  which table, which values, which where-clause, and whether it was
 *  handed to executeWithRetry. */
function makeFakeDb(opts: { failOnExecute?: boolean } = {}) {
  const calls: {
    table?: string
    values?: { emailConfirmedAt: string }
    where?: [string, string, string]
    executed: number
  } = { executed: 0 }

  const db = {
    executeWithRetry: (query: { execute: () => Promise<unknown> }) => {
      calls.executed++
      // Must receive the fully built statement — guards against a
      // chain that hands executeWithRetry something unexecutable.
      expect(query.execute).toBeTypeOf('function')
      if (opts.failOnExecute) return Promise.reject(new Error('db down'))
      return Promise.resolve(undefined)
    },
    db: {
      updateTable: (table: string) => {
        calls.table = table
        return {
          set: (values: { emailConfirmedAt: string }) => {
            calls.values = values
            return {
              where: (column: string, op: string, value: string) => {
                calls.where = [column, op, value]
                return { execute: () => Promise.resolve(undefined) }
              },
            }
          },
        }
      },
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- structural fake standing in for AccountDb
  } as any

  return { db, calls }
}

const DID = 'did:plc:7iza6de2dwap2sbkpav7c6c6'

describe('setEmailConfirmedAt', () => {
  it('updates the account row for the given DID via executeWithRetry', async () => {
    const { db, calls } = makeFakeDb()

    await setEmailConfirmedAt(db, DID, '2026-08-04T10:00:00.000Z')

    expect(calls.table).toBe('account')
    expect(calls.values).toEqual({
      emailConfirmedAt: '2026-08-04T10:00:00.000Z',
    })
    expect(calls.where).toEqual(['did', '=', DID])
    expect(calls.executed).toBe(1)
  })

  it('defaults emailConfirmedAt to an ISO timestamp of now', async () => {
    const { db, calls } = makeFakeDb()
    const before = Date.now()

    await setEmailConfirmedAt(db, DID)

    const written = calls.values?.emailConfirmedAt as string
    expect(written).toMatch(/^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/)
    const writtenMs = Date.parse(written)
    expect(writtenMs).toBeGreaterThanOrEqual(before)
    expect(writtenMs).toBeLessThanOrEqual(Date.now())
  })

  it('propagates db failures to the caller', async () => {
    const { db } = makeFakeDb({ failOnExecute: true })

    await expect(setEmailConfirmedAt(db, DID)).rejects.toThrow('db down')
  })
})

describe('markEmailConfirmed', () => {
  it('stamps the account and stays silent on success', async () => {
    const { db, calls } = makeFakeDb()
    const logger = { warn: vi.fn() }

    await markEmailConfirmed({ db, did: DID, logger })

    expect(calls.where).toEqual(['did', '=', DID])
    expect(logger.warn).not.toHaveBeenCalled()
  })

  it('swallows db failures so sign-in is never blocked, logging at warn', async () => {
    const { db } = makeFakeDb({ failOnExecute: true })
    const logger = { warn: vi.fn() }

    // Must resolve, not reject — the user has already proven ownership
    // of the address, so bookkeeping failure must not fail their sign-in.
    await expect(
      markEmailConfirmed({ db, did: DID, logger }),
    ).resolves.toBeUndefined()

    expect(logger.warn).toHaveBeenCalledTimes(1)
    const [context, message] = logger.warn.mock.calls[0]
    expect(context).toMatchObject({ did: DID })
    expect((context as { err: Error }).err.message).toBe('db down')
    expect(message).toMatch(/emailConfirmedAt/)
  })
})

/** Records the backfill's SELECT/UPDATE filters so the tests can
 *  assert the criteria, not just the row count. */
function makeBackfillDb(opts: { candidates: string[] }) {
  const selectWheres: [string, string, unknown][] = []
  const updateWheres: [string, string, unknown][] = []
  let updateValues: { emailConfirmedAt: string } | undefined
  let updateExecuted = 0

  const chain = (
    sink: [string, string, unknown][],
    onExecute: () => Promise<unknown>,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- self-referential fluent fake
  ): any => ({
    select: () => chain(sink, onExecute),
    where: (column: string, op: string, value: unknown) => {
      sink.push([column, op, value])
      return chain(sink, onExecute)
    },
    execute: onExecute,
  })

  const db = {
    db: {
      selectFrom: (table: string) => {
        expect(table).toBe('account')
        return chain(selectWheres, () =>
          Promise.resolve(opts.candidates.map((did) => ({ did }))),
        )
      },
      updateTable: (table: string) => {
        expect(table).toBe('account')
        return {
          set: (values: { emailConfirmedAt: string }) => {
            updateValues = values
            return chain(updateWheres, () => {
              updateExecuted++
              return Promise.resolve(undefined)
            })
          },
        }
      },
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- structural fake standing in for AccountDb
  } as any

  return {
    db,
    inspect: () => ({
      selectWheres,
      updateWheres,
      updateValues,
      updateExecuted,
    }),
  }
}

describe('backfillEmailConfirmedAt', () => {
  it('stamps every unconfirmed account that has an email', async () => {
    const { db, inspect } = makeBackfillDb({
      candidates: ['did:plc:aaa', 'did:plc:bbb'],
    })

    const result = await backfillEmailConfirmedAt({
      db,
      emailConfirmedAt: '2026-08-04T10:00:00.000Z',
    })

    expect(result).toEqual({ candidates: 2, updated: 2, dryRun: false })
    const { updateValues, updateExecuted } = inspect()
    expect(updateValues).toEqual({
      emailConfirmedAt: '2026-08-04T10:00:00.000Z',
    })
    expect(updateExecuted).toBe(1)
  })

  it('only targets rows with a null emailConfirmedAt and a real email', async () => {
    const { db, inspect } = makeBackfillDb({ candidates: ['did:plc:aaa'] })

    await backfillEmailConfirmedAt({ db })

    // Accounts with no address have nothing to confirm, and already
    // stamped rows must be excluded so re-running is a no-op.
    const expected = [
      ['emailConfirmedAt', 'is', null],
      ['email', 'is not', null],
      ['email', '!=', ''],
    ]
    expect(inspect().selectWheres).toEqual(expected)
    expect(inspect().updateWheres).toEqual(expected)
  })

  it('reports candidates without writing when dryRun is set', async () => {
    const { db, inspect } = makeBackfillDb({
      candidates: ['did:plc:aaa', 'did:plc:bbb', 'did:plc:ccc'],
    })

    const result = await backfillEmailConfirmedAt({ db, dryRun: true })

    expect(result).toEqual({ candidates: 3, updated: 0, dryRun: true })
    expect(inspect().updateExecuted).toBe(0)
  })

  it('skips the UPDATE entirely when nothing needs backfilling', async () => {
    const { db, inspect } = makeBackfillDb({ candidates: [] })

    const result = await backfillEmailConfirmedAt({ db })

    expect(result).toEqual({ candidates: 0, updated: 0, dryRun: false })
    expect(inspect().updateExecuted).toBe(0)
  })
})

describe('parseDryRun', () => {
  it('is off unless --dry-run is passed', () => {
    expect(parseDryRun(['node', 'backfill.ts'])).toBe(false)
    // A near-miss must not be treated as the flag: writing when the
    // operator meant to preview is the one unrecoverable mistake here.
    expect(parseDryRun(['node', 'backfill.ts', '--dry'])).toBe(false)
    expect(parseDryRun(['node', 'backfill.ts', 'dry-run'])).toBe(false)
  })

  it('is on when --dry-run is passed, in any position', () => {
    expect(parseDryRun(['node', 'backfill.ts', '--dry-run'])).toBe(true)
    expect(parseDryRun(['--dry-run', 'node', 'backfill.ts'])).toBe(true)
  })
})

describe('formatBackfillReport', () => {
  const LOCATION = '/data/account.sqlite'

  it('reports the candidate count and names the db on a dry run', () => {
    const line = formatBackfillReport(
      { candidates: 3, updated: 0, dryRun: true },
      LOCATION,
    )

    expect(line).toBe(
      `[dry run] 3 account(s) in ${LOCATION} would be marked email-confirmed.`,
    )
  })

  it('reports what was actually written on a real run', () => {
    const line = formatBackfillReport(
      { candidates: 3, updated: 3, dryRun: false },
      LOCATION,
    )

    expect(line).toBe(`Marked 3 account(s) in ${LOCATION} as email-confirmed.`)
  })

  it('makes a no-op run unambiguous rather than silent', () => {
    expect(
      formatBackfillReport(
        { candidates: 0, updated: 0, dryRun: false },
        LOCATION,
      ),
    ).toContain('0 account(s)')
  })
})
