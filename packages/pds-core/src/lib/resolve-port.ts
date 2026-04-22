/**
 * Applies Railway PORT fallback for @atproto/pds.
 *
 * @atproto/pds reads PDS_PORT, not PORT. Railway injects PORT and uses it
 * to probe healthchecks, so we copy PORT → PDS_PORT when PDS_PORT is not
 * explicitly set. This must be called before readEnv().
 *
 * Accepts an env object so the behaviour can be tested without mutating
 * process.env directly.
 */
export function applyPdsPortFallback(
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (!env.PDS_PORT && env.PORT) {
    env.PDS_PORT = env.PORT
  }
}
