/**
 * Shared test harness for the heartbeat router (which now hosts both
 * GET /auth/ping and GET /auth/abort). Lifted out of the per-route
 * test files to keep them readable and to keep Sonar's
 * duplicated-lines gate happy — both files would otherwise carry
 * the same boilerplate verbatim.
 */
import express from 'express'
import cookieParser from 'cookie-parser'
import type { AuthServiceContext } from '../../context.js'

export interface FakeFlow {
  requestUri: string
  clientId: string | null
  handleMode: null
}

/**
 * Build an Express app with cookie-parser + the heartbeat router
 * mounted, backed by an in-memory Map of fake auth_flow rows. The
 * caller passes the `createHeartbeatRouter` factory directly so a
 * test using `vi.mock` to replace transitive dependencies (e.g.
 * cleanExit, pingParRequest) doesn't have to import the router
 * before its mocks are in scope.
 */
export function buildHeartbeatApp(
  createHeartbeatRouter: (ctx: AuthServiceContext) => express.Router,
  flows: Map<string, FakeFlow>,
): express.Express {
  const ctx = {
    db: {
      getAuthFlow(flowId: string): FakeFlow | undefined {
        return flows.get(flowId)
      },
    },
  } as unknown as AuthServiceContext
  const app = express()
  app.use(cookieParser())
  app.use(createHeartbeatRouter(ctx))
  return app
}

export interface HarnessResponse {
  status: number
  setCookie: string[]
  location: string | null
  cacheControl: string | null
  body: unknown
}

/**
 * Spin up the harness on an ephemeral port, GET the supplied path,
 * tear the server down. The /auth/ping caller wants the JSON body;
 * the /auth/abort caller wants the redirect Location and Set-Cookie
 * headers; expose all of them and let each test pick what it cares
 * about.
 */
export async function harnessGet(
  app: express.Express,
  path: string,
  cookie?: string,
): Promise<HarnessResponse> {
  const server = app.listen(0)
  try {
    server.unref()
    const port = await new Promise<number>((resolve, reject) => {
      server.once('error', reject)
      server.once('listening', () => {
        const addr = server.address()
        if (typeof addr === 'object' && addr) resolve(addr.port)
        else reject(new Error('Failed to resolve ephemeral port'))
      })
    })
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method: 'GET',
      headers: cookie ? { Cookie: cookie } : {},
      redirect: 'manual',
    })
    // Body parsing: /auth/ping returns JSON; /auth/abort returns a
    // redirect with no body. Try JSON; on failure, fall back to
    // null. Caller decides which result they care about.
    let body: unknown = null
    try {
      body = await res.json()
    } catch {
      body = null
    }
    return {
      status: res.status,
      setCookie: res.headers.getSetCookie(),
      location: res.headers.get('location'),
      cacheControl: res.headers.get('cache-control'),
      body,
    }
  } finally {
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve()
      })
    })
  }
}
