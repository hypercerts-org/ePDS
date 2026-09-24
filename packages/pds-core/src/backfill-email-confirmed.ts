/**
 * One-off operator script: record email confirmation for ePDS
 * accounts created before that was done at sign-up.
 *
 * Run it against a deployment's account database, with the same
 * environment the server runs with:
 *
 *   pnpm --filter @certified-app/pds-core backfill:email-confirmed --dry-run
 *   pnpm --filter @certified-app/pds-core backfill:email-confirmed
 *
 * A trailing argument scopes the run to addresses containing it
 * (case-insensitive), so an operator can work through a deployment in
 * batches or fix up a single account:
 *
 *   pnpm --filter @certified-app/pds-core backfill:email-confirmed --dry-run @gmail.com
 *   pnpm --filter @certified-app/pds-core backfill:email-confirmed my.account@yahoo.com
 *
 * Not wired into startup on purpose — see the rationale on
 * `backfillEmailConfirmedAt`.
 *
 * Builds the PDS via the same `PDS.create()` the server uses so the
 * database location, migrations and connection settings come from the
 * deployment's own config. `create()` wires up the context without
 * binding a port; `start()` is never called, so nothing is served.
 *
 * Confirmation itself goes through `accountManager.createEmailToken` /
 * `confirmEmail`, per AGENTS.md's account-manager boundary. Enumerating
 * the accounts to consider is the one read this script does directly,
 * under the documented exception to that rule — see "Database" in
 * AGENTS.md, and item 19 of docs/design/pds-white-boxing.md for what
 * breaks it on an upstream bump.
 */
import { PDS, envToCfg, envToSecrets, readEnv } from '@atproto/pds'
import { createLogger } from '@certified-app/shared'
import {
  backfillEmailConfirmedAt,
  formatBackfillReport,
  parseDryRun,
  parseEmailFilter,
  type BackfillCandidate,
} from './lib/email-confirmed.js'

const logger = createLogger('pds-core:backfill-email-confirmed')

async function main(): Promise<void> {
  const dryRun = parseDryRun(process.argv)
  const emailFilter = parseEmailFilter(process.argv)

  const env = readEnv()
  const cfg = envToCfg(env)
  const secrets = envToSecrets(env)

  const pds = await PDS.create(cfg, secrets)
  try {
    const accounts: BackfillCandidate[] = await pds.ctx.accountManager.db.db
      .selectFrom('account')
      .select(['did', 'email', 'emailConfirmedAt'])
      .execute()

    const result = await backfillEmailConfirmedAt({
      accountManager: pds.ctx.accountManager,
      accounts,
      emailFilter,
      dryRun,
    })
    process.stdout.write(
      formatBackfillReport(result, cfg.db.accountDbLoc, emailFilter) + '\n',
    )
    // Surface partial failure to the shell so a scripted run does not
    // report success when some accounts could not be confirmed.
    if (result.failed > 0) process.exitCode = 1
  } finally {
    await pds.destroy()
  }
}

main().catch((err: unknown) => {
  logger.error({ err }, 'Email-confirmation backfill failed')
  process.exit(1)
})
