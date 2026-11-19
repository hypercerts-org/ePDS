/**
 * An async handler that throws must produce a 500 via errorHandler (Express 4
 * would otherwise leave an unhandled rejection that kills the process), and
 * the server must keep serving afterwards.
 */
import type { Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import express, { type RequestHandler } from 'express'
import { createAsyncRouter, forwardAsyncErrors } from '../lib/async-router.js'
import { errorHandler } from '../lib/error-middleware.js'

let server: Server
let baseUrl: string

beforeAll(async () => {
  const app = express()
  const router = createAsyncRouter()
  router.get('/ok', (_req, res) => {
    res.json({ ok: true })
  })
  router.get('/async-throw', async (req) => {
    await Promise.resolve()
    // Same failure shape as a repeated query param reaching a string method.
    ;(req.query.x as string).trim()
  })
  router.get('/sync-throw', () => {
    throw new Error('sync boom')
  })
  const passThrough: RequestHandler = (_req, _res, next) => {
    next()
  }
  router.post('/with-middleware', [
    passThrough,
    async () => {
      await Promise.reject(new Error('rejected'))
    },
  ])
  router.get('/next-err', (_req, _res, next) => {
    next(new Error('forwarded'))
  })
  router.get('/skip', (_req, _res, next) => {
    next('route')
  })
  router.get('/skip', (_req, res) => {
    res.json({ skipped: true })
  })
  app.use(router)
  app.use(errorHandler)

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

describe('createAsyncRouter', () => {
  it('turns a rejected async handler into a 500 and keeps serving', async () => {
    const bad = await fetch(`${baseUrl}/async-throw?x=a&x=b`)
    expect(bad.status).toBe(500)
    expect(await bad.json()).toEqual({ error: 'internal_error' })

    const good = await fetch(`${baseUrl}/ok`)
    expect(good.status).toBe(200)
  })

  it('turns a synchronous throw into a 500', async () => {
    expect((await fetch(`${baseUrl}/sync-throw`)).status).toBe(500)
  })

  it('wraps handlers passed as arrays', async () => {
    const res = await fetch(`${baseUrl}/with-middleware`, { method: 'POST' })
    expect(res.status).toBe(500)
  })

  it('passes next(err) to the error handler', async () => {
    expect((await fetch(`${baseUrl}/next-err`)).status).toBe(500)
  })

  it("honours next('route')", async () => {
    const res = await fetch(`${baseUrl}/skip`)
    expect(await res.json()).toEqual({ skipped: true })
  })

  it('wraps a standalone async handler such as the better-auth mount', async () => {
    const app = express()
    app.all(
      '/api/auth/*',
      forwardAsyncErrors(async () => {
        await Promise.reject(new Error('auth handler failed'))
      }),
    )
    app.use(errorHandler)
    const s = await new Promise<Server>((resolve) => {
      const srv = app.listen(0, '127.0.0.1', () => {
        resolve(srv)
      })
    })
    try {
      const port = (s.address() as AddressInfo).port
      const res = await fetch(`http://127.0.0.1:${port}/api/auth/anything`)
      expect(res.status).toBe(500)
    } finally {
      await new Promise<void>((resolve) => {
        s.close(() => {
          resolve()
        })
      })
    }
  })
})
