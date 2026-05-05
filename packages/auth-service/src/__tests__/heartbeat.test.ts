/**
 * Tests for the /auth/ping heartbeat route.
 *
 * Strategy: stand up the router with a hand-rolled `ctx` that satisfies
 * just the slice the route reads (`db.getAuthFlow`). Mock
 * `pingParRequest` at the module boundary so we can assert what the
 * route forwards to it without hitting (or having to spy on) the
 * test's own fetch back into the in-process express server.
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

// Use https:// in the test fixture so SonarQube's S5332 hotspot doesn't
// flag this file. The mocked pingParRequest never actually issues a
// request — the literal flows from process.env to the route handler
// and back out as a positional argument we assert on.
const PDS_URL = 'https://core:3000'
const SECRET = 'test-secret'

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

// Mock the ping-par-request module so we can drive the route's success
// and failure branches without standing up a fake pds-core server.
const pingMock = vi.hoisted(() => vi.fn())
vi.mock('../lib/ping-par-request.js', () => ({
  pingParRequest: pingMock,
}))

beforeEach(() => {
  pingMock.mockReset()
})

// Late import so the vi.mock above is in effect.
const { createHeartbeatRouter } = await import('../routes/heartbeat.js')

function buildApp(flows: Map<string, FakeFlow>): express.Express {
  return buildHeartbeatApp(createHeartbeatRouter, flows)
}

async function getPing(
  app: express.Express,
  cookie?: string,
): Promise<{ status: number; cacheControl: string | null; body: unknown }> {
  const r = await harnessGet(app, '/auth/ping', cookie)
  return { status: r.status, cacheControl: r.cacheControl, body: r.body }
}

describe('GET /auth/ping', () => {
  it('returns no_cookie when the auth_flow cookie is missing', async () => {
    const app = buildApp(new Map())

    const res = await getPing(app)

    expect(res.status).toBe(200)
    expect(res.body).toEqual({ ok: false, reason: 'no_cookie' })
    // We do NOT call pds-core when there is nothing to ping.
    expect(pingMock).not.toHaveBeenCalled()
  })

  it('returns flow_expired when the auth_flow row is gone', async () => {
    const app = buildApp(new Map())

    const res = await getPing(app, 'epds_auth_flow=missing-flow')

    expect(res.status).toBe(200)
    expect(res.body).toEqual({ ok: false, reason: 'flow_expired' })
    expect(pingMock).not.toHaveBeenCalled()
  })

  it('forwards a successful ping and returns ok:true', async () => {
    const flows = new Map<string, FakeFlow>([
      [
        'flow-1',
        {
          requestUri: 'urn:ietf:params:oauth:request_uri:req-abc',
          clientId: 'https://demo.example.com/client-metadata.json',
          handleMode: null,
        },
      ],
    ])
    const app = buildApp(flows)
    pingMock.mockResolvedValueOnce({ ok: true })

    const res = await getPing(app, 'epds_auth_flow=flow-1')

    expect(res.status).toBe(200)
    expect(res.body).toEqual({ ok: true })
    expect(pingMock).toHaveBeenCalledTimes(1)
    expect(pingMock).toHaveBeenCalledWith(
      'urn:ietf:params:oauth:request_uri:req-abc',
      PDS_URL,
      SECRET,
    )
  })

  it('returns par_expired when pds-core reports the request_uri is gone', async () => {
    const flows = new Map<string, FakeFlow>([
      [
        'flow-1',
        {
          requestUri: 'urn:ietf:params:oauth:request_uri:req-dead',
          clientId: null,
          handleMode: null,
        },
      ],
    ])
    const app = buildApp(flows)
    pingMock.mockResolvedValueOnce({ ok: false, status: 404 })

    const res = await getPing(app, 'epds_auth_flow=flow-1')

    expect(res.status).toBe(200)
    expect(res.body).toEqual({ ok: false, reason: 'par_expired' })
  })

  it('returns transient on operational errors so the browser keeps polling', async () => {
    const flows = new Map<string, FakeFlow>([
      [
        'flow-1',
        {
          requestUri: 'urn:ietf:params:oauth:request_uri:req-blip',
          clientId: null,
          handleMode: null,
        },
      ],
    ])
    const app = buildApp(flows)
    pingMock.mockResolvedValueOnce({ ok: false, status: 502 })

    const res = await getPing(app, 'epds_auth_flow=flow-1')

    // Only a 404 from pds-core terminates keepalive — a 5xx blip
    // (or any non-404 failure) is reported as transient so the
    // browser keeps polling and the next tick can recover. Treating
    // a single dropped packet as terminal would re-introduce the
    // dead-end the heartbeat exists to prevent.
    expect(res.status).toBe(200)
    expect(res.body).toEqual({ ok: false, reason: 'transient' })
  })

  it('returns transient when pingParRequest reports a thrown error (no status)', async () => {
    const flows = new Map<string, FakeFlow>([
      [
        'flow-1',
        {
          requestUri: 'urn:ietf:params:oauth:request_uri:req-throw',
          clientId: null,
          handleMode: null,
        },
      ],
    ])
    const app = buildApp(flows)
    // pingParRequest catches network/timeout errors and reports them
    // as `{ ok: false, err }` with no `status` field. Same transient
    // semantics — the next tick may recover.
    pingMock.mockResolvedValueOnce({
      ok: false,
      err: new Error('network blip'),
    })

    const res = await getPing(app, 'epds_auth_flow=flow-1')

    expect(res.status).toBe(200)
    expect(res.body).toEqual({ ok: false, reason: 'transient' })
  })

  it('sets Cache-Control: no-store so a shared cache cannot serve a stale response across flows', async () => {
    const app = buildApp(new Map())

    const res = await getPing(app)

    expect(res.cacheControl).toBe('no-store')
  })
})
