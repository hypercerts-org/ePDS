import { describe, expect, it, vi } from 'vitest'
import {
  createUpstreamFaviconMiddleware,
  injectFaviconIntoHead,
  isUpstreamHtmlRequest,
} from '../upstream-favicon.js'

describe('isUpstreamHtmlRequest', () => {
  it('matches GET /account', () => {
    expect(isUpstreamHtmlRequest({ method: 'GET', path: '/account' })).toBe(
      true,
    )
  })

  it('matches GET /account/sign-in and nested subpaths', () => {
    expect(
      isUpstreamHtmlRequest({ method: 'GET', path: '/account/sign-in' }),
    ).toBe(true)
    expect(
      isUpstreamHtmlRequest({ method: 'GET', path: '/account/a/b/c' }),
    ).toBe(true)
  })

  it('matches GET /oauth/authorize, /oauth/authorize/redirect, and siblings', () => {
    expect(
      isUpstreamHtmlRequest({ method: 'GET', path: '/oauth/authorize' }),
    ).toBe(true)
    expect(
      isUpstreamHtmlRequest({
        method: 'GET',
        path: '/oauth/authorize/redirect',
      }),
    ).toBe(true)
    expect(isUpstreamHtmlRequest({ method: 'GET', path: '/oauth/jwks' })).toBe(
      true,
    )
  })

  it('rejects non-GET methods', () => {
    expect(isUpstreamHtmlRequest({ method: 'POST', path: '/account' })).toBe(
      false,
    )
    expect(
      isUpstreamHtmlRequest({ method: 'POST', path: '/oauth/authorize' }),
    ).toBe(false)
  })

  it('rejects unrelated paths', () => {
    expect(isUpstreamHtmlRequest({ method: 'GET', path: '/' })).toBe(false)
    expect(isUpstreamHtmlRequest({ method: 'GET', path: '/health' })).toBe(
      false,
    )
    expect(isUpstreamHtmlRequest({ method: 'GET', path: '/accounts' })).toBe(
      false,
    )
    expect(
      isUpstreamHtmlRequest({ method: 'GET', path: '/xrpc/_health' }),
    ).toBe(false)
  })
})

describe('injectFaviconIntoHead', () => {
  it('prepends both light and dark variants at the start of <head>', () => {
    const html = '<!DOCTYPE html><html><head><title>X</title></head></html>'
    const { body, injected } = injectFaviconIntoHead(html)
    expect(injected).toBe(true)
    expect(body).toMatch(
      /<head><link rel="icon" href="\/static\/favicon\.svg" media="\(prefers-color-scheme: light\)"/,
    )
    expect(body).toMatch(
      /<link rel="icon" href="\/static\/favicon-dark\.svg" media="\(prefers-color-scheme: dark\)"/,
    )
    // <title> must still be present after the injection.
    expect(body).toContain('<title>X</title>')
  })

  it('returns injected=false when no <head> is present', () => {
    const html = '<html><body>no head here</body></html>'
    const { body, injected } = injectFaviconIntoHead(html)
    expect(injected).toBe(false)
    expect(body).toBe(html)
  })

  it('is idempotent when the light-variant favicon already appears', () => {
    // Simulates a body that was already rewritten once (e.g. by a prior
    // pass, or by another middleware in the same chain). We must not
    // add another pair of <link> tags.
    const html =
      '<html><head><link rel="icon" href="/static/favicon.svg"></head></html>'
    const { body, injected } = injectFaviconIntoHead(html)
    expect(injected).toBe(false)
    expect(body).toBe(html)
  })

  it('only rewrites the first <head> occurrence', () => {
    const html =
      '<html><head><title>A</title></head><body>text mentioning <head> literally</body></html>'
    const { body, injected } = injectFaviconIntoHead(html)
    expect(injected).toBe(true)
    // Our tags appear exactly once.
    const count = body.split('/static/favicon.svg').length - 1
    expect(count).toBe(1)
  })
})

describe('createUpstreamFaviconMiddleware', () => {
  function makeRes({ headersSent = false }: { headersSent?: boolean } = {}) {
    const calls = {
      removedHeaders: [] as string[],
      end: [] as unknown[][],
    }
    const res = {
      headersSent,
      removeHeader: vi.fn((name: string) => {
        if (res.headersSent) {
          throw new Error(
            'Cannot remove headers after they are sent to the client',
          )
        }
        calls.removedHeaders.push(name)
      }),
      end: vi.fn((...args: unknown[]) => {
        calls.end.push(args)
      }),
    }
    return { res, calls }
  }

  it('passes non-matching requests through untouched', () => {
    const mw = createUpstreamFaviconMiddleware()
    const { res, calls } = makeRes()
    const next = vi.fn()
    mw({ method: 'GET', path: '/xrpc/_health' }, res, next)
    expect(next).toHaveBeenCalledTimes(1)
    // res.end must be the raw spy; string passed through unchanged.
    res.end('<html><head></head></html>')
    expect(calls.end[0][0]).toBe('<html><head></head></html>')
    expect(calls.removedHeaders).toEqual([])
  })

  it('passes non-GET requests through untouched', () => {
    const mw = createUpstreamFaviconMiddleware()
    const { res, calls } = makeRes()
    mw({ method: 'POST', path: '/oauth/authorize' }, res, () => {})
    res.end('<html><head></head></html>')
    expect(calls.end[0][0]).toBe('<html><head></head></html>')
  })

  it('injects favicon tags into HTML responses for /account', () => {
    const mw = createUpstreamFaviconMiddleware()
    const { res, calls } = makeRes()
    mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('<html><head><title>X</title></head></html>')
    const written = calls.end[0][0] as string
    expect(written).toContain('rel="icon"')
    expect(written).toContain('/static/favicon.svg')
    expect(written).toContain('/static/favicon-dark.svg')
  })

  it('injects favicon tags for /oauth/authorize and /oauth/authorize/redirect', () => {
    const mw = createUpstreamFaviconMiddleware()
    for (const path of ['/oauth/authorize', '/oauth/authorize/redirect']) {
      const { res, calls } = makeRes()
      mw({ method: 'GET', path }, res, () => {})
      res.end('<html><head></head></html>')
      const written = calls.end[0][0] as string
      expect(written).toContain('/static/favicon.svg')
      expect(written).toContain('/static/favicon-dark.svg')
    }
  })

  it('strips Content-Length / ETag after rewriting', () => {
    const mw = createUpstreamFaviconMiddleware()
    const { res, calls } = makeRes()
    mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('<html><head></head></html>')
    expect(calls.removedHeaders).toEqual(['Content-Length', 'ETag'])
  })

  it('does not strip Content-Length when body has no <head>', () => {
    const mw = createUpstreamFaviconMiddleware()
    const { res, calls } = makeRes()
    mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('not html')
    expect(calls.removedHeaders).toEqual([])
    expect(calls.end[0][0]).toBe('not html')
  })

  it('rewrites Buffer bodies containing <head>', () => {
    const mw = createUpstreamFaviconMiddleware()
    const { res, calls } = makeRes()
    mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end(Buffer.from('<html><head></head></html>'))
    const written = calls.end[0][0] as string
    expect(typeof written).toBe('string')
    expect(written).toContain('/static/favicon.svg')
    expect(calls.removedHeaders).toContain('Content-Length')
  })

  it('passes Buffer bodies without <head> through untouched', () => {
    const mw = createUpstreamFaviconMiddleware()
    const { res, calls } = makeRes()
    mw({ method: 'GET', path: '/account' }, res, () => {})
    const buf = Buffer.from('<not html>')
    res.end(buf)
    expect(calls.end[0][0]).toBe(buf)
    expect(calls.removedHeaders).toEqual([])
  })

  it('does not throw when headers are already sent', () => {
    const mw = createUpstreamFaviconMiddleware()
    const { res } = makeRes({ headersSent: true })
    mw({ method: 'GET', path: '/account' }, res, () => {})
    expect(() => {
      res.end('<html><head></head></html>')
    }).not.toThrow()
  })

  it('skips Content-Length rewrite once headers have been flushed', () => {
    const mw = createUpstreamFaviconMiddleware()
    const { res, calls } = makeRes({ headersSent: true })
    mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('<html><head></head></html>')
    expect(calls.removedHeaders).toEqual([])
    expect(calls.end.length).toBe(1)
  })

  it('still rewrites the body when headers are flushed — only the length-strip is skipped', () => {
    const mw = createUpstreamFaviconMiddleware()
    const { res, calls } = makeRes({ headersSent: true })
    mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('<html><head></head></html>')
    const written = calls.end[0][0] as string
    expect(written).toContain('/static/favicon.svg')
  })
})
