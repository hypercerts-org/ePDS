/**
 * One-off operator script: stamp `emailConfirmedAt` on ePDS accounts
 * created before that field was recorded at sign-up.
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
 * Builds the PDS via the same `PDS.create()` the server uses (rather
 * than opening account.sqlite directly) so the database location,
 * migrations and connection settings come from the deployment's own
 * config, and so we stay on `@atproto/pds`'s public entry point —
 * its account-db helpers are not exported from the package root.
 * `create()` wires up the context without binding a port; `start()`
 * is never called, so nothing is served.
 */
import { PDS, envToCfg, envToSecrets, readEnv } from '@atproto/pds'
import {
  backfillEmailConfirmedAt,
  formatBackfillReport,
  parseDryRun,
} from './lib/email-confirmed.js'

async function main(): Promise<void> {
  const dryRun = parseDryRun(process.argv)

  const env = readEnv()
  const cfg = envToCfg(env)
  const secrets = envToSecrets(env)

  const pds = await PDS.create(cfg, secrets)
  try {
    const result = await backfillEmailConfirmedAt({
      db: pds.ctx.accountManager.db,
      dryRun,
    })
    process.stdout.write(
      formatBackfillReport(result, cfg.db.accountDbLoc) + '\n',
    )
  } finally {
    await pds.destroy()
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`Backfill failed: ${String(err)}\n`)
  process.exit(1)
})
