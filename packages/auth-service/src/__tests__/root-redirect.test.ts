/**
 * Integration test for the root (`/`) redirect. Brings up a minimal
 * express app with just the root router mounted, listens on an
 * ephemeral port, and fetches `/` with `redirect: 'manual'` so the
 * 303 is observable instead of being transparently followed.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import express, { type Express } from 'express'
import type { AddressInfo } from 'node:net'
import type { Server } from 'node:http'
import { createRootRouter } from '../routes/root.js'

let server: Server
let baseUrl: string
let app: Express

beforeAll(async () => {
  app = express()
  app.use(createRootRouter())
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      resolve()
    })
  })
  const addr = server.address() as AddressInfo
  baseUrl = `http://127.0.0.1:${addr.port}`
})

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => {
      if (err) reject(err)
      else resolve()
    })
  })
})

describe('root router', () => {
  it('redirects GET / to /account with 303 See Other', async () => {
    const res = await fetch(`${baseUrl}/`, { redirect: 'manual' })
    expect(res.status).toBe(303)
    expect(res.headers.get('location')).toBe('/account')
  })
})
