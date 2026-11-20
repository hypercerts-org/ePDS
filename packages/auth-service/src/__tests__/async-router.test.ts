/**
 * An async handler that throws must produce a 500 via errorHandler (Express 4
 * would otherwise leave an unhandled rejection that kills the process), and
 * the server must keep serving afterwards.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import express, { type RequestHandler } from 'express'
import { createAsyncRouter, forwardAsyncErrors } from '../lib/async-router.js'
import { errorHandler } from '../lib/error-middleware.js'
import { listenOnLoopback, type TestServer } from './__helpers__/listen.js'

let server: TestServer
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
  app.use(router)
  app.use(errorHandler)

  server = await listenOnLoopback(app)
  baseUrl = server.baseUrl
})

afterAll(() => server.close())

describe('createAsyncRouter', () => {
  it('turns a rejected async handler into a 500 and keeps serving', async () => {
    const bad = await fetch(`${baseUrl}/async-throw?x=a&x=b`)
    expect(bad.status).toBe(500)
    expect(await bad.json()).toEqual({ error: 'internal_error' })

    const good = await fetch(`${baseUrl}/ok`)
    expect(good.status).toBe(200)
  })

  it.each([
    ['a synchronous throw', 'GET', '/sync-throw'],
    ['a handler passed in an array', 'POST', '/with-middleware'],
    ['next(err)', 'GET', '/next-err'],
  ])('routes %s to the error handler as a 500', async (_l, method, path) => {
    expect((await fetch(`${baseUrl}${path}`, { method })).status).toBe(500)
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
    const s = await listenOnLoopback(app)
    try {
      const res = await fetch(`${s.baseUrl}/api/auth/anything`)
      expect(res.status).toBe(500)
    } finally {
      await s.close()
    }
  })
})
