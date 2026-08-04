import { describe, expect, it, vi } from 'vitest'

import {
  backfillEmailConfirmedAt,
  confirmAccountEmail,
  formatBackfillReport,
  markEmailConfirmed,
  matchesEmailFilter,
  needsEmailConfirmation,
  parseDryRun,
  parseEmailFilter,
  type EmailConfirmingAccountManager,
} from '../lib/email-confirmed.js'

const DID = 'did:plc:7iza6de2dwap2sbkpav7c6c6'

/**
 * Fake AccountManager recording the mint/redeem pair. Typed against
 * the real interface — no casts needed, so a signature change in
 * `EmailConfirmingAccountManager` breaks these tests rather than
 * silently passing.
 */
function makeAccountManager(
  opts: { failOn?: 'createEmailToken' | 'confirmEmail' } = {},
) {
  const calls: {
    minted: { did: string; purpose: string }[]
    redeemed: { did: string; token: string }[]
  } = { minted: [], redeemed: [] }

  let counter = 0

  const accountManager: EmailConfirmingAccountManager = {
    createEmailToken: (did, purpose) => {
      if (opts.failOn === 'createEmailToken') {
        return Promise.reject(new Error('db down'))
      }
      calls.minted.push({ did, purpose })
      return Promise.resolve(`TOKEN-${++counter}`)
    },
    confirmEmail: ({ did, token }) => {
      if (opts.failOn === 'confirmEmail') {
        return Promise.reject(new Error('token rejected'))
      }
      calls.redeemed.push({ did, token })
      return Promise.resolve()
    },
  }

  return { accountManager, calls }
}

describe('confirmAccountEmail', () => {
  it('redeems the token it just minted, for the same DID', async () => {
    const { accountManager, calls } = makeAccountManager()

    await confirmAccountEmail(accountManager, DID)

    expect(calls.minted).toEqual([{ did: DID, purpose: 'confirm_email' }])
    // The token must be the minted one — redeeming anything else
    // would leave the freshly created token row behind.
    expect(calls.redeemed).toEqual([{ did: DID, token: 'TOKEN-1' }])
  })

  it('propagates a minting failure without attempting to redeem', async () => {
    const { accountManager, calls } = makeAccountManager({
      failOn: 'createEmailToken',
    })

    await expect(confirmAccountEmail(accountManager, DID)).rejects.toThrow(
      'db down',
    )
    expect(calls.redeemed).toEqual([])
  })

  it('propagates a redemption failure', async () => {
    const { accountManager } = makeAccountManager({ failOn: 'confirmEmail' })

    await expect(confirmAccountEmail(accountManager, DID)).rejects.toThrow(
      'token rejected',
    )
  })
})

describe('markEmailConfirmed', () => {
  it('confirms the account and stays silent on success', async () => {
    const { accountManager, calls } = makeAccountManager()
    const logger = { error: vi.fn() }

    await markEmailConfirmed({ accountManager, did: DID, logger })

    expect(calls.redeemed).toEqual([{ did: DID, token: 'TOKEN-1' }])
    expect(logger.error).not.toHaveBeenCalled()
  })

  it('swallows failures so sign-in is never blocked, logging at error', async () => {
    const { accountManager } = makeAccountManager({ failOn: 'confirmEmail' })
    const logger = { error: vi.fn() }

    // Must resolve, not reject — the user has already proven ownership
    // of the address, so bookkeeping failure must not fail their sign-in.
    await expect(
      markEmailConfirmed({ accountManager, did: DID, logger }),
    ).resolves.toBeUndefined()

    expect(logger.error).toHaveBeenCalledTimes(1)
    const [context] = logger.error.mock.calls[0]
    expect(context).toMatchObject({ did: DID })
    expect((context as { err: Error }).err.message).toBe('token rejected')
  })
})

describe('needsEmailConfirmation', () => {
  it('is true for an account with an address and no confirmation', () => {
    expect(
      needsEmailConfirmation({ email: 'a@x.test', emailConfirmedAt: null }),
    ).toBe(true)
  })

  it('is false once confirmed, so re-runs and sign-ins skip the work', () => {
    expect(
      needsEmailConfirmation({
        email: 'a@x.test',
        emailConfirmedAt: '2026-08-04T10:00:00.000Z',
      }),
    ).toBe(false)
  })

  it('is false when there is no address to confirm', () => {
    // The column is NOT NULL in the PDS schema, so "no address"
    // arrives as the empty string; null is covered as insurance
    // against that constraint being relaxed upstream.
    expect(needsEmailConfirmation({ email: '', emailConfirmedAt: null })).toBe(
      false,
    )
    expect(
      needsEmailConfirmation({ email: null, emailConfirmedAt: null }),
    ).toBe(false)
  })

  it('is false for a missing account', () => {
    expect(needsEmailConfirmation(null)).toBe(false)
  })
})

describe('backfillEmailConfirmedAt', () => {
  const UNCONFIRMED = [
    { did: 'did:plc:aaa', email: 'a@x.test', emailConfirmedAt: null },
    { did: 'did:plc:bbb', email: 'b@x.test', emailConfirmedAt: null },
  ]
  const CONFIRMED = {
    did: 'did:plc:ccc',
    email: 'c@x.test',
    emailConfirmedAt: '2026-08-04T10:00:00.000Z',
  }
  const NO_EMAIL = { did: 'did:plc:ddd', email: '', emailConfirmedAt: null }

  it('confirms only the accounts that need it', async () => {
    const { accountManager, calls } = makeAccountManager()

    const result = await backfillEmailConfirmedAt({
      accountManager,
      accounts: [...UNCONFIRMED, CONFIRMED, NO_EMAIL],
    })

    expect(result).toMatchObject({ candidates: 2, updated: 2, failed: 0 })
    expect(calls.redeemed.map((r) => r.did)).toEqual([
      'did:plc:aaa',
      'did:plc:bbb',
    ])
  })

  it('confirms only accounts matching the email filter', async () => {
    const { accountManager, calls } = makeAccountManager()

    const result = await backfillEmailConfirmedAt({
      accountManager,
      accounts: [
        { did: 'did:plc:aaa', email: 'a@gmail.com', emailConfirmedAt: null },
        { did: 'did:plc:bbb', email: 'b@yahoo.com', emailConfirmedAt: null },
      ],
      emailFilter: '@gmail.com',
    })

    expect(result).toMatchObject({ candidates: 1, updated: 1, failed: 0 })
    expect(calls.redeemed.map((r) => r.did)).toEqual(['did:plc:aaa'])
  })

  it('reports candidates without writing when dryRun is set', async () => {
    const { accountManager, calls } = makeAccountManager()

    const result = await backfillEmailConfirmedAt({
      accountManager,
      accounts: [...UNCONFIRMED, CONFIRMED],
      dryRun: true,
    })

    expect(result).toEqual({
      candidates: 2,
      updated: 0,
      failed: 0,
      failures: [],
      dryRun: true,
    })
    expect(calls.minted).toEqual([])
  })

  it('is a no-op when every account is already confirmed', async () => {
    const { accountManager, calls } = makeAccountManager()

    const result = await backfillEmailConfirmedAt({
      accountManager,
      accounts: [CONFIRMED],
    })

    expect(result).toMatchObject({ candidates: 0, updated: 0, failed: 0 })
    expect(calls.minted).toEqual([])
  })

  it('keeps going after a failure and reports which accounts failed', async () => {
    // One unconfirmable account must not strand the rest of the run,
    // and the operator needs the DIDs to chase them up.
    let attempt = 0
    const accountManager: EmailConfirmingAccountManager = {
      createEmailToken: () => Promise.resolve('TOKEN'),
      confirmEmail: () => {
        attempt++
        return attempt === 1
          ? Promise.reject(new Error('account deactivated'))
          : Promise.resolve()
      },
    }

    const result = await backfillEmailConfirmedAt({
      accountManager,
      accounts: UNCONFIRMED,
    })

    expect(result).toMatchObject({ candidates: 2, updated: 1, failed: 1 })
    expect(result.failures).toEqual([
      { did: 'did:plc:aaa', error: 'account deactivated' },
    ])
  })
})

describe('matchesEmailFilter', () => {
  it('matches everything when no filter is given', () => {
    // "no filter" must mean all accounts, never none — otherwise a
    // mistyped invocation would do nothing and look like a clean run.
    expect(matchesEmailFilter('a@x.test', undefined)).toBe(true)
    expect(matchesEmailFilter('a@x.test', '')).toBe(true)
  })

  it('matches on a domain substring, case-insensitively', () => {
    expect(matchesEmailFilter('someone@gmail.com', '@gmail.com')).toBe(true)
    expect(matchesEmailFilter('Someone@GMAIL.com', '@gmail.com')).toBe(true)
    expect(matchesEmailFilter('someone@yahoo.com', '@gmail.com')).toBe(false)
  })

  it('matches a single full address', () => {
    expect(
      matchesEmailFilter('my.account@yahoo.com', 'my.account@yahoo.com'),
    ).toBe(true)
    expect(
      matchesEmailFilter('other.account@yahoo.com', 'my.account@yahoo.com'),
    ).toBe(false)
  })

  it('never matches an account with no address once a filter is set', () => {
    expect(matchesEmailFilter('', '@gmail.com')).toBe(false)
    expect(matchesEmailFilter(null, '@gmail.com')).toBe(false)
  })
})

describe('parseEmailFilter', () => {
  it('is undefined when only flags are passed', () => {
    expect(parseEmailFilter(['node', 'backfill.ts'])).toBeUndefined()
    expect(
      parseEmailFilter(['node', 'backfill.ts', '--dry-run']),
    ).toBeUndefined()
  })

  it('takes the first non-flag argument, in any position', () => {
    expect(parseEmailFilter(['node', 'backfill.ts', '@gmail.com'])).toBe(
      '@gmail.com',
    )
    expect(
      parseEmailFilter(['node', 'backfill.ts', '--dry-run', '@gmail.com']),
    ).toBe('@gmail.com')
    expect(
      parseEmailFilter(['node', 'backfill.ts', '@gmail.com', '--dry-run']),
    ).toBe('@gmail.com')
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
  const base = { failed: 0, failures: [], dryRun: false }

  it('reports the candidate count and names the db on a dry run', () => {
    const line = formatBackfillReport(
      { ...base, candidates: 3, updated: 0, dryRun: true },
      LOCATION,
    )

    expect(line).toBe(
      `[dry run] 3 account(s) in ${LOCATION} would be marked email-confirmed.`,
    )
  })

  it('reports what was actually written on a real run', () => {
    const line = formatBackfillReport(
      { ...base, candidates: 3, updated: 3 },
      LOCATION,
    )

    expect(line).toBe(`Marked 3 account(s) in ${LOCATION} as email-confirmed.`)
  })

  it('makes a no-op run unambiguous rather than silent', () => {
    expect(
      formatBackfillReport({ ...base, candidates: 0, updated: 0 }, LOCATION),
    ).toContain('0 account(s)')
  })

  it('names the filter so a scoped run is distinguishable from a full one', () => {
    // "0 account(s)" is ambiguous otherwise: nothing left to do, or a
    // filter that matched nothing?
    expect(
      formatBackfillReport(
        { ...base, candidates: 0, updated: 0, dryRun: true },
        LOCATION,
        '@gmail.com',
      ),
    ).toContain('matching "@gmail.com"')
    expect(
      formatBackfillReport({ ...base, candidates: 2, updated: 2 }, LOCATION),
    ).not.toContain('matching')
  })

  it('names the accounts that failed so the operator can chase them', () => {
    const line = formatBackfillReport(
      {
        candidates: 2,
        updated: 1,
        failed: 1,
        failures: [{ did: 'did:plc:aaa', error: 'account deactivated' }],
        dryRun: false,
      },
      LOCATION,
    )

    expect(line).toContain('Marked 1 account(s)')
    expect(line).toContain('1 account(s) could not be confirmed')
    expect(line).toContain('did:plc:aaa: account deactivated')
  })
})
