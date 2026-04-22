/**
 * Resolves the port the auth-service should listen on.
 *
 * Priority: AUTH_PORT > PORT > default (3001).
 * PORT is the variable Railway injects for healthcheck probing.
 */
export function resolveAuthPort(env: NodeJS.ProcessEnv = process.env): number {
  return parseInt(env.AUTH_PORT || env.PORT || '3001', 10)
}
