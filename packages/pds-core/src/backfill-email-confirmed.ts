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
 * Not wired into startup on purpose — see the rationale on
 * `backfillEmailConfirmedAt`.
 *
 * Builds the PDS via the same `PDS.create()` the server uses so the
 * database location, migrations and connection settings come from the
 * deployment's own config. `create()` wires up the context without
 * binding a port; `start()` is never called, so nothing is served.
 *
 * Confirmation itself goes through `accountManager.createEmailToken` /
 * `confirmEmail`, per AGENTS.md's account-manager boundary. Listing
 * the accounts to consider is the one read this script does directly:
 * `AccountManager` exposes `getAccounts(dids)` but no "every account"
 * query, and a backfill cannot know the DIDs in advance. The read is
 * confined to this operator-invoked script — pds-core's request path
 * never does it.
 */
import { PDS, envToCfg, envToSecrets, readEnv } from '@atproto/pds'
import {
  backfillEmailConfirmedAt,
  formatBackfillReport,
  parseDryRun,
  type BackfillCandidate,
} from './lib/email-confirmed.js'

async function main(): Promise<void> {
  const dryRun = parseDryRun(process.argv)

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
      dryRun,
    })
    process.stdout.write(
      formatBackfillReport(result, cfg.db.accountDbLoc) + '\n',
    )
    // Surface partial failure to the shell so a scripted run does not
    // report success when some accounts could not be confirmed.
    if (result.failed > 0) process.exitCode = 1
  } finally {
    await pds.destroy()
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`Backfill failed: ${String(err)}\n`)
  process.exit(1)
})
