/**
 * Tests for the /auth/abort browser-driven clean-exit route.
 *
 * The route exists so the OTP / recovery forms can bail to the
 * OAuth client when they detect the flow can no longer complete
 * (PAR or auth_flow gone). Asserts:
 *   - cookie is cleared (the flow is being abandoned)
 *   - cleanExit is called with the right opts (clientId from the
 *     flow row, access_denied code, "took too long" description)
 *   - works whether or not a flow row exists (cookie present but
 *     row gone, vs no cookie at all)
 */
import {
  describe,
  it,
  expect,
  vi,
  beforeEach,
  beforeAll,
  afterAll,
} from 'vitest'
import {
  buildHeartbeatApp,
  harnessGet,
  type FakeFlow,
} from './__helpers__/heartbeat-router-harness.js'
import type express from 'express'

const PDS_URL = 'https://core:3000'
const SECRET = 'test-secret'
const CLIENT_ID = 'https://demo.example/client-metadata.json'

const ORIGINAL_PDS_URL = process.env.PDS_INTERNAL_URL
const ORIGINAL_SECRET = process.env.EPDS_INTERNAL_SECRET

beforeAll(() => {
  process.env.PDS_INTERNAL_URL = PDS_URL
  process.env.EPDS_INTERNAL_SECRET = SECRET
})

afterAll(() => {
  if (ORIGINAL_PDS_URL === undefined) delete process.env.PDS_INTERNAL_URL
  else process.env.PDS_INTERNAL_URL = ORIGINAL_PDS_URL
  if (ORIGINAL_SECRET === undefined) delete process.env.EPDS_INTERNAL_SECRET
  else process.env.EPDS_INTERNAL_SECRET = ORIGINAL_SECRET
})

// Mock cleanExit at the module boundary so we can assert what /auth/abort
// passes without standing up the full redirect/metadata machinery.
const cleanExitMock = vi.hoisted(() => vi.fn())
vi.mock('../lib/clean-exit.js', () => ({
  cleanExit: cleanExitMock,
}))

// Stub pingParRequest too — same reason as in heartbeat.test.ts.
const pingMock = vi.hoisted(() => vi.fn())
vi.mock('../lib/ping-par-request.js', () => ({
  pingParRequest: pingMock,
}))

beforeEach(() => {
  cleanExitMock.mockReset()
  cleanExitMock.mockImplementation(({ res }: { res: express.Response }) => {
    // Simulate a response so the route doesn't hang the test
    // client. Returns a resolved promise so the route's
    // `await cleanExit(...)` proceeds normally.
    res
      .status(303)
      .setHeader('Location', 'https://demo.example/?error=auth_failed')
      .end()
    return Promise.resolve()
  })
  pingMock.mockReset()
})

const { createHeartbeatRouter } = await import('../routes/heartbeat.js')

function buildApp(flows: Map<string, FakeFlow>): express.Express {
  return buildHeartbeatApp(createHeartbeatRouter, flows)
}

async function getAbort(
  app: express.Express,
  cookie?: string,
): Promise<{ status: number; setCookie: string[]; location: string | null }> {
  const r = await harnessGet(app, '/auth/abort', cookie)
  return { status: r.status, setCookie: r.setCookie, location: r.location }
}

describe('GET /auth/abort', () => {
  it('calls cleanExit with the flow.clientId when the cookie + flow row are alive', async () => {
    const flows = new Map<string, FakeFlow>([
      [
        'flow-1',
        {
          requestUri: 'urn:ietf:params:oauth:request_uri:req-abc',
          clientId: CLIENT_ID,
          handleMode: null,
        },
      ],
    ])
    const app = buildApp(flows)

    await getAbort(app, 'epds_auth_flow=flow-1')

    expect(cleanExitMock).toHaveBeenCalledWith(
      expect.objectContaining({
        clientId: CLIENT_ID,
        pdsUrl: PDS_URL,
        code: 'access_denied',
        description: expect.stringMatching(/took too long/i),
      }),
    )
  })

  it('clears the auth_flow cookie regardless of whether a flow row exists', async () => {
    const app = buildApp(new Map())
    const got = await getAbort(app, 'epds_auth_flow=stale-flow-id')
    // Express sets a cookie with `Max-Age=0` (or `Expires` in the past) to clear it.
    const cleared = got.setCookie.some((c) =>
      /epds_auth_flow=;.*Expires=Thu, 01 Jan 1970/.test(c),
    )
    expect(cleared).toBe(true)
  })

  it('passes clientId: null when no cookie is present', async () => {
    const app = buildApp(new Map())
    await getAbort(app)
    expect(cleanExitMock).toHaveBeenCalledWith(
      expect.objectContaining({ clientId: null }),
    )
  })

  it('passes clientId: null when the cookie points to a non-existent flow', async () => {
    const app = buildApp(new Map())
    await getAbort(app, 'epds_auth_flow=missing-flow')
    expect(cleanExitMock).toHaveBeenCalledWith(
      expect.objectContaining({ clientId: null }),
    )
  })
})
