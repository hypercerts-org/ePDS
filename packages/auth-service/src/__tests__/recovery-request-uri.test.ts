/**
 * Repeated `request_uri` query params parse to an array; the route must
 * answer 400 instead of calling string methods on it.
 */
import type { Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import express from 'express'
import { createRecoveryRouter } from '../routes/recovery.js'
import type { AuthServiceContext } from '../context.js'

let server: Server
let baseUrl: string

beforeAll(async () => {
  // The 400 path never touches the DB or better-auth.
  const ctx = {
    config: { otpLength: 8, otpCharset: 'numeric', trustedClients: [] },
  } as unknown as AuthServiceContext
  const app = express()
  app.use(createRecoveryRouter(ctx, {}))
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      resolve()
    })
  })
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
})

afterAll(async () => {
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve()
    })
  })
})

describe('GET /auth/recover request_uri validation', () => {
  it('returns 400 for a repeated request_uri', async () => {
    const res = await fetch(
      `${baseUrl}/auth/recover?request_uri=a&request_uri=b`,
    )
    expect(res.status).toBe(400)
  })

  it('returns 400 for a missing request_uri', async () => {
    expect((await fetch(`${baseUrl}/auth/recover`)).status).toBe(400)
  })
})
