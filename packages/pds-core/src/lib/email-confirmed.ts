/**
 * Marks ePDS accounts as email-confirmed.
 *
 * Every ePDS account is created by /oauth/epds-callback, which only
 * runs after auth-service has verified a one-time code sent to that
 * address. The email is therefore *already* verified by the time the
 * account row exists — but the PDS `account` table's
 * `emailConfirmedAt` column stays null, because upstream only ever
 * populates it from `confirmEmail()`, which consumes a
 * `confirm_email` token that the OTP flow never mints.
 *
 * Leaving it null has two observable consequences:
 *   1. `email_verified` is false in every OIDC/token claim, because
 *      upstream's oauth-store derives it as `emailConfirmedAt != null`.
 *      Relying parties see a verified address reported as unverified.
 *   2. Upstream's `requestEmailUpdate` only demands a confirmation
 *      token when `emailConfirmedAt` is set, so a null value skips
 *      the verification gate on email change entirely.
 *
 * ## Why mint-then-redeem rather than writing the column
 *
 * AGENTS.md: "Do not directly read or modify `@atproto/pds` database
 * tables — use `pds.ctx.accountManager.*` methods." `createEmailToken`
 * and `confirmEmail` are both public `AccountManager` methods, and
 * together they are exactly the supported route to a confirmed email:
 * `confirmEmail` validates the token, deletes it, and sets
 * `emailConfirmedAt` in a single transaction, so no token row is left
 * behind.
 *
 * `createEmailToken` only inserts the row and returns the token —
 * upstream's XRPC handlers do the mailing separately, so nothing is
 * sent to the user here. That matters: the user already proved
 * ownership of this address via the OTP, and a second unexpected mail
 * would be worse than the bug being fixed.
 *
 * Lives in its own module so the flow can be unit-tested against a
 * fake account manager without booting a real PDS, matching the
 * extraction pattern used by the other lib/ modules.
 */
import type { Logger } from 'pino'

/**
 * The slice of `AccountManager` this module needs. Structurally
 * compatible with the real class, so the call sites pass
 * `pds.ctx.accountManager` directly and the fakes in tests stay
 * honest without importing PDS internals.
 */
export interface EmailConfirmingAccountManager {
  createEmailToken: (did: string, purpose: 'confirm_email') => Promise<string>
  confirmEmail: (opts: { did: string; token: string }) => Promise<void>
}

/**
 * Confirm a single account's email address.
 *
 * Mints a `confirm_email` token and immediately redeems it. Both
 * halves are public `AccountManager` operations; the token never
 * leaves this function and is deleted by `confirmEmail` as part of
 * the same transaction that records the confirmation.
 */
export async function confirmAccountEmail(
  accountManager: EmailConfirmingAccountManager,
  did: string,
): Promise<void> {
  const token = await accountManager.createEmailToken(did, 'confirm_email')
  await accountManager.confirmEmail({ did, token })
}

/**
 * Best-effort variant used on the sign-in hot path.
 *
 * The email genuinely *is* verified at this point, so recording that
 * fact is correct — but it is bookkeeping, not part of the sign-in
 * contract. If it fails (SQLite busy, disk error) the user has still
 * proven ownership of the address, so failing their sign-in over it
 * would be a strictly worse outcome than a stale
 * `email_verified: false` claim. The error is logged at `warn` so it
 * stays visible without tripping error-level alerting, and the next
 * sign-in retries — callers skip already-confirmed accounts, not
 * already-*seen* ones, so a failure here is self-healing.
 */
export async function markEmailConfirmed(opts: {
  accountManager: EmailConfirmingAccountManager
  did: string
  logger: Pick<Logger, 'warn'>
}): Promise<void> {
  try {
    await confirmAccountEmail(opts.accountManager, opts.did)
  } catch (err) {
    opts.logger.warn(
      { err, did: opts.did },
      'Failed to record email confirmation after OTP-verified sign-in',
    )
  }
}

/** An account as far as the backfill is concerned. */
export interface BackfillCandidate {
  did: string
  email?: string | null
  emailConfirmedAt?: string | null
}

/** True when this account has a real address that is not yet confirmed. */
export function needsEmailConfirmation(
  account: Pick<BackfillCandidate, 'email' | 'emailConfirmedAt'> | null,
): boolean {
  if (!account) return false
  // An account with no address has nothing to confirm — upstream
  // reports `email_verified` as undefined rather than false for those.
  if (!account.email) return false
  return !account.emailConfirmedAt
}

export interface BackfillResult {
  /** Accounts found needing confirmation. */
  candidates: number
  /** Accounts confirmed successfully. */
  updated: number
  /** Accounts that failed to confirm; see `failures`. */
  failed: number
  /** DIDs that failed, with the reason, for the operator to chase. */
  failures: { did: string; error: string }[]
  /** True when no write was attempted. */
  dryRun: boolean
}

/**
 * One-off backfill for accounts created before this fix landed, whose
 * email was verified by OTP but never recorded as confirmed.
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
 * Confirms one account at a time via the public API rather than a
 * single set-based UPDATE. That is more round-trips, but it keeps to
 * the account-manager boundary and lets one bad row be reported
 * without abandoning the rest of the run.
 *
 * Idempotent — already-confirmed accounts are skipped, so re-running
 * is a no-op. Use `dryRun` to report the candidate count without
 * writing.
 */
export async function backfillEmailConfirmedAt(opts: {
  accountManager: EmailConfirmingAccountManager
  /** Every account to consider, typically the full account list. */
  accounts: readonly BackfillCandidate[]
  dryRun?: boolean
}): Promise<BackfillResult> {
  const dryRun = opts.dryRun ?? false
  const candidates = opts.accounts.filter((a) => needsEmailConfirmation(a))

  if (dryRun || candidates.length === 0) {
    return {
      candidates: candidates.length,
      updated: 0,
      failed: 0,
      failures: [],
      dryRun,
    }
  }

  let updated = 0
  const failures: { did: string; error: string }[] = []
  for (const account of candidates) {
    try {
      await confirmAccountEmail(opts.accountManager, account.did)
      updated++
    } catch (err) {
      // One unconfirmable account must not strand the rest of the
      // run; collect and report instead.
      failures.push({
        did: account.did,
        error: err instanceof Error ? err.message : String(err),
      })
    }
  }

  return {
    candidates: candidates.length,
    updated,
    failed: failures.length,
    failures,
    dryRun,
  }
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
  if (result.dryRun) {
    return `[dry run] ${result.candidates} account(s) in ${location} would be marked email-confirmed.`
  }
  const base = `Marked ${result.updated} account(s) in ${location} as email-confirmed.`
  if (result.failed === 0) return base
  const detail = result.failures.map((f) => `  ${f.did}: ${f.error}`).join('\n')
  return `${base}\n${result.failed} account(s) could not be confirmed:\n${detail}`
}
