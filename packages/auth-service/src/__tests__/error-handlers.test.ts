/**
 * Integration tests for the trailing 404 + 500 middleware that
 * createAuthService mounts. Imports the real handlers and exercises
 * content negotiation (JSON for Accept: * / *, HTML for browser Accept)
 * plus the headersSent guard that delegates to Express's default handler.
 */
import type { Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import express, { type Express } from 'express'
import { errorHandler, notFoundHandler } from '../lib/error-middleware.js'

let server: Server
let baseUrl: string

beforeAll(async () => {
  const app: Express = express()
  app.disable('x-powered-by')

  app.get('/ok', (_req, res) => {
    res.json({ ok: true })
  })
  app.get('/boom', (_req, _res, next) => {
    next(new Error('kaboom'))
  })
  app.get('/double', (_req, res, next) => {
    res.status(200).json({ partial: true })
    next(new Error('after-send'))
  })

  app.use(notFoundHandler)
  app.use(errorHandler)

  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      resolve()
    })
  })
  const addr = server.address() as AddressInfo
  baseUrl = `http://127.0.0.1:${addr.port}`
})

afterAll(async () => {
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve()
    })
  })
})

describe('notFoundHandler', () => {
  it('returns JSON for Accept: */* (fetch/curl default)', async () => {
    const res = await fetch(`${baseUrl}/nope`)
    expect(res.status).toBe(404)
    expect(res.headers.get('content-type')).toMatch(/application\/json/)
    expect(res.headers.get('vary')).toMatch(/\bAccept\b/i)
    expect(await res.json()).toEqual({ error: 'not_found' })
  })

  it('returns JSON for explicit Accept: application/json', async () => {
    const res = await fetch(`${baseUrl}/nope`, {
      headers: { Accept: 'application/json' },
    })
    expect(res.status).toBe(404)
    expect(await res.json()).toEqual({ error: 'not_found' })
  })

  it('returns styled HTML for browser Accept header', async () => {
    const res = await fetch(`${baseUrl}/nope`, {
      headers: {
        Accept:
          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
    })
    expect(res.status).toBe(404)
    expect(res.headers.get('content-type')).toMatch(/text\/html/)
    expect(res.headers.get('vary')).toMatch(/\bAccept\b/i)
    const body = await res.text()
    expect(body).toContain('<title>Page not found</title>')
    expect(body).toContain("doesn't exist")
  })
})

describe('errorHandler', () => {
  it('returns JSON for Accept: */*', async () => {
    const res = await fetch(`${baseUrl}/boom`)
    expect(res.status).toBe(500)
    expect(res.headers.get('vary')).toMatch(/\bAccept\b/i)
    expect(await res.json()).toEqual({ error: 'internal_error' })
  })

  it('returns styled HTML for browser Accept header', async () => {
    const res = await fetch(`${baseUrl}/boom`, {
      headers: { Accept: 'text/html' },
    })
    expect(res.status).toBe(500)
    expect(res.headers.get('content-type')).toMatch(/text\/html/)
    expect(res.headers.get('vary')).toMatch(/\bAccept\b/i)
    const body = await res.text()
    expect(body).toContain('<title>Error</title>')
    expect(body).toContain('Something went wrong')
  })

  it('delegates to Express default handler when headers already sent', async () => {
    const res = await fetch(`${baseUrl}/double`)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ partial: true })
  })
})
