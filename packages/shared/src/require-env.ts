/**
 * Read an environment variable that has no safe default, throwing if it is
 * missing or empty.
 *
 * Secrets must never fall back to a hardcoded development value: a
 * deployment that forgot to set one would boot successfully while signing
 * cookies and callback URLs with a value published in the source tree.
 * Callers invoke this at startup so the process dies immediately with an
 * actionable message rather than running in a silently insecure state.
 */
export function requireEnv(name: string): string {
  const value = process.env[name]
  if (!value) {
    throw new Error(
      `Missing required environment variable: ${name}. ` +
        `Generate a value with: openssl rand -hex 32`,
    )
  }
  return value
}
