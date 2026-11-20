/**
 * Repeated `request_uri` query params parse to an array; the route must
 * answer 400 instead of calling string methods on it.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import express from 'express'
import { createRecoveryRouter } from '../routes/recovery.js'
import type { AuthServiceContext } from '../context.js'
import { listenOnLoopback, type TestServer } from './__helpers__/listen.js'

let server: TestServer
let baseUrl: string

beforeAll(async () => {
  // The 400 path never touches the DB or better-auth.
  const ctx = {
    config: { otpLength: 8, otpCharset: 'numeric', trustedClients: [] },
  } as unknown as AuthServiceContext
  const app = express()
  app.use(createRecoveryRouter(ctx, {}))
  server = await listenOnLoopback(app)
  baseUrl = server.baseUrl
})

afterAll(() => server.close())

describe('GET /auth/recover request_uri validation', () => {
  it.each([
    ['a repeated', '?request_uri=a&request_uri=b'],
    ['a missing', ''],
  ])('returns 400 for %s request_uri', async (_l, query) => {
    expect((await fetch(`${baseUrl}/auth/recover${query}`)).status).toBe(400)
  })
})
