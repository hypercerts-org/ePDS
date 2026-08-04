/**
 * Marks ePDS accounts as email-confirmed.
 *
 * Every ePDS account is created by /oauth/epds-callback, which only
 * runs after auth-service has verified a one-time code sent to that
 * address. The email is therefore *already* verified by the time the
 * account row exists — but the PDS `account` table's
 * `emailConfirmedAt` column stays null, because upstream only ever
 * populates it from `confirmEmail()`, which demands a
 * `confirm_email` token the OTP flow never issues.
 *
 * Leaving it null has two observable consequences:
 *   1. `email_verified` is false in every OIDC/token claim, because
 *      upstream's oauth-store derives it as `emailConfirmedAt != null`.
 *      Relying parties see a verified address reported as unverified.
 *   2. Upstream's `requestEmailUpdate` only demands a confirmation
 *      token when `emailConfirmedAt` is set, so a null value skips
 *      the verification gate on email change entirely.
 *
 * Lives in its own module so the write can be unit-tested against a
 * fake db without booting a real PDS, matching the extraction
 * pattern used by the other lib/ modules.
 *
 * ## Why write via Kysely rather than upstream's helper
 *
 * `@atproto/pds` does not re-export `setEmailConfirmedAt` from its
 * package root, and its package.json declares no `exports` map — so
 * the only way to call it directly is a deep import into `dist/`,
 * which nothing guarantees across upgrades. `AccountManager.db` is
 * public and typed (`readonly db: AccountDb`), so we issue the same
 * statement upstream's helper issues, through a supported surface.
 * Kept deliberately identical to upstream's implementation
 * (`account-manager/helpers/account.ts`) so behaviour matches.
 */
import type { Logger } from 'pino'

/**
 * The slice of `AccountDb` we depend on: `executeWithRetry` (SQLite
 * busy-retry wrapper) plus the Kysely instance. Structural typing
 * against the real `AccountDb` keeps the fake in tests honest
 * without importing PDS internals.
 */
export interface EmailConfirmedDb {
  /** SQLite busy-retry wrapper; takes any executable Kysely statement. */
  executeWithRetry: <T>(query: { execute: () => Promise<T> }) => Promise<T>
  db: {
    updateTable: (table: 'account') => {
      set: (values: { emailConfirmedAt: string }) => {
        where: (
          column: 'did',
          op: '=',
          value: string,
        ) => { execute: () => Promise<unknown> }
      }
    }
  }
}

/**
 * Set `emailConfirmedAt` on a single account.
 *
 * Mirrors upstream `setEmailConfirmedAt(db, did, emailConfirmedAt)`.
 * `emailConfirmedAt` defaults to now, which is the honest value for
 * the OTP flow: the code was verified moments ago.
 */
export async function setEmailConfirmedAt(
  db: EmailConfirmedDb,
  did: string,
  emailConfirmedAt: string = new Date().toISOString(),
): Promise<void> {
  await db.executeWithRetry(
    db.db
      .updateTable('account')
      .set({ emailConfirmedAt })
      .where('did', '=', did),
  )
}

/**
 * The db slice the backfill needs: a Kysely instance able to run the
 * bulk UPDATE and count the rows it would touch.
 */
export interface BackfillDb {
  db: {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- structural slice of Kysely's fluent builder; the real types come from AccountDb at the call site
    selectFrom: (table: 'account') => any
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- ditto
    updateTable: (table: 'account') => any
  }
}

export interface BackfillResult {
  /** Rows matching the backfill criteria before the update ran. */
  candidates: number
  /** Rows actually updated; 0 when `dryRun` is set. */
  updated: number
  /** True when no write was attempted. */
  dryRun: boolean
}

/**
 * One-off backfill for accounts created before this fix landed, whose
 * `emailConfirmedAt` is still null.
 *
 * Deliberately NOT run automatically at startup. Whether a null
 * `emailConfirmedAt` means "verified via OTP but never recorded" or
 * "genuinely never verified" depends on how a given deployment was
 * operated — ePDS does not block upstream's
 * `com.atproto.server.createAccount` XRPC route, so an operator who
 * provisioned accounts by other means must not have those addresses
 * silently promoted to verified. Only the operator knows which case
 * applies, so this is exposed as a script they choose to run.
 *
 * Restricted to rows with a real email address: an account with no
 * address has nothing to confirm, and upstream reports
 * `email_verified` as undefined rather than false for those. The
 * column is `NOT NULL` in the PDS schema, so "no address" shows up
 * as the empty string; the null check is kept alongside it as
 * cheap insurance against that constraint being relaxed upstream.
 *
 * Idempotent — rows already stamped are excluded, so re-running is a
 * no-op. Use `dryRun` to report the candidate count without writing.
 */
export async function backfillEmailConfirmedAt(opts: {
  db: BackfillDb
  emailConfirmedAt?: string
  dryRun?: boolean
}): Promise<BackfillResult> {
  const dryRun = opts.dryRun ?? false
  const emailConfirmedAt = opts.emailConfirmedAt ?? new Date().toISOString()

  const rows = await opts.db.db
    .selectFrom('account')
    .select('did')
    .where('emailConfirmedAt', 'is', null)
    .where('email', 'is not', null)
    .where('email', '!=', '')
    .execute()
  const candidates = rows.length

  if (dryRun || candidates === 0) {
    return { candidates, updated: 0, dryRun }
  }

  await opts.db.db
    .updateTable('account')
    .set({ emailConfirmedAt })
    .where('emailConfirmedAt', 'is', null)
    .where('email', 'is not', null)
    .where('email', '!=', '')
    .execute()

  return { candidates, updated: candidates, dryRun }
}

/** True when the operator asked to preview rather than write. */
export function parseDryRun(argv: readonly string[]): boolean {
  return argv.includes('--dry-run')
}

/**
 * The line the backfill script prints on completion. Split out from
 * the script so the wording is covered by tests — the script itself
 * is an entry point and never imported by one.
 */
export function formatBackfillReport(
  result: BackfillResult,
  location: string,
): string {
  return result.dryRun
    ? `[dry run] ${result.candidates} account(s) in ${location} would be marked email-confirmed.`
    : `Marked ${result.updated} account(s) in ${location} as email-confirmed.`
}

/**
 * Best-effort variant used on the sign-in hot path.
 *
 * The email genuinely *is* verified at this point, so recording that
 * fact is correct — but it is bookkeeping, not part of the sign-in
 * contract. If the write fails (SQLite busy, disk error) the user
 * has still proven ownership of the address, so failing their
 * sign-in over it would be a strictly worse outcome than a stale
 * `email_verified: false` claim that the next sign-in re-attempts.
 * The error is logged at `warn` so it stays visible without tripping
 * error-level alerting.
 */
export async function markEmailConfirmed(opts: {
  db: EmailConfirmedDb
  did: string
  logger: Pick<Logger, 'warn'>
}): Promise<void> {
  try {
    await setEmailConfirmedAt(opts.db, opts.did)
  } catch (err) {
    opts.logger.warn(
      { err, did: opts.did },
      'Failed to set emailConfirmedAt after OTP-verified account creation',
    )
  }
}
