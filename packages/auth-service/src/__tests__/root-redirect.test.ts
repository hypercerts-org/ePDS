/**
 * Integration test for the root (`/`) redirect. Brings up a minimal
 * express app with just the root router mounted, listens on an
 * ephemeral port, and fetches `/` with `redirect: 'manual'` so the
 * 303 is observable instead of being transparently followed.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import express, { type Express } from 'express'
import { createRootRouter } from '../routes/root.js'
import { listenOnLoopback, type TestServer } from './__helpers__/listen.js'

let server: TestServer
let app: Express

beforeAll(async () => {
  app = express()
  app.use(createRootRouter())
  server = await listenOnLoopback(app)
})

afterAll(async () => {
  await server.close()
})

describe('root router', () => {
  it('redirects GET / to /account with 303 See Other', async () => {
    const res = await fetch(`${server.baseUrl}/`, { redirect: 'manual' })
    expect(res.status).toBe(303)
    expect(res.headers.get('location')).toBe('/account')
  })
})
