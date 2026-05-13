import type { Server } from 'node:http'

/**
 * Anything with `listen(0)` returning a Node `http.Server` (or
 * something Server-shaped: `address()`, `unref()`, `close()`). Both
 * Express's `app.listen` and the raw `node:http` `createServer`
 * satisfy this. Typed structurally so this module doesn't pull
 * `@types/express` (or `express` as a runtime dep) into
 * `@certified-app/shared`.
 */
type Listenable = {
  listen(port: number): Server
}

export interface PostHookResult {
  status: number
  json: Record<string, unknown>
}

/**
 * Spin up a server-like on an ephemeral port, POST a JSON body to a
 * path on it, tear the server down. Used by both auth-service's and
 * pds-core's test-hooks suites so each drives its installer through a
 * real HTTP roundtrip without standing up the full service.
 */
export async function postHook(
  app: Listenable,
  hookPath: string,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<PostHookResult> {
  const server = app.listen(0)
  // Single try/finally covering BOTH the port-resolution step and the
  // fetch step. If `'listening'` fires with an unexpected address shape
  // (or the server emits `'error'` before listening), the inner promise
  // rejects and we still hit `closeServer` rather than leaking the
  // listener and hanging the test runner.
  try {
    server.unref()
    const port = await new Promise<number>((resolve, reject) => {
      server.once('error', reject)
      server.once('listening', () => {
        const addr = server.address()
        if (typeof addr === 'object' && addr) {
          resolve(addr.port)
        } else {
          reject(new Error('Failed to resolve ephemeral port'))
        }
      })
    })
    const res = await fetch(`http://127.0.0.1:${port}${hookPath}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
    })
    const json = (await res.json().catch(() => ({}))) as Record<string, unknown>
    return { status: res.status, json }
  } finally {
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve()
      })
    })
  }
}
