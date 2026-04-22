import { describe, it, expect, vi } from 'vitest'

import {
  appendStyleHashToCsp,
  createClientCssInjectionMiddleware,
  findInsertionIndex,
  injectStyleTagIntoHtml,
  shouldInjectClientCss,
} from '../lib/client-css-injection.js'

function mockLogger() {
  return { info: vi.fn(), warn: vi.fn(), debug: vi.fn() }
}

describe('shouldInjectClientCss', () => {
  const trustedClients = ['https://trusted.app/client-metadata.json']

  it('returns true for GET /oauth/authorize with trusted client id', () => {
    expect(
      shouldInjectClientCss(
        'GET',
        '/oauth/authorize',
        trustedClients[0],
        trustedClients,
      ),
    ).toBe(true)
  })

  it('returns false for non-GET methods', () => {
    expect(
      shouldInjectClientCss(
        'POST',
        '/oauth/authorize',
        trustedClients[0],
        trustedClients,
      ),
    ).toBe(false)
  })

  it('returns false for non-authorize paths', () => {
    expect(
      shouldInjectClientCss(
        'GET',
        '/oauth/token',
        trustedClients[0],
        trustedClients,
      ),
    ).toBe(false)
  })

  it('returns false when client id is missing', () => {
    expect(
      shouldInjectClientCss(
        'GET',
        '/oauth/authorize',
        undefined,
        trustedClients,
      ),
    ).toBe(false)
  })

  it('returns false for untrusted clients', () => {
    expect(
      shouldInjectClientCss(
        'GET',
        '/oauth/authorize',
        'https://untrusted.app/client-metadata.json',
        trustedClients,
      ),
    ).toBe(false)
  })
})

describe('appendStyleHashToCsp', () => {
  it('appends the hash to an existing style-src directive', () => {
    const csp =
      "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'"
    const result = appendStyleHashToCsp(csp, 'abc123')
    expect(result).toContain("style-src 'self' 'unsafe-inline' 'sha256-abc123'")
  })

  it('leaves csp unchanged when style-src is missing', () => {
    const csp = "default-src 'self'; img-src 'self'"
    expect(appendStyleHashToCsp(csp, 'abc123')).toBe(csp)
  })
})

describe('injectStyleTagIntoHtml', () => {
  it('injects style tag before </head> in string chunks', () => {
    const input = '<html><head><title>X</title></head><body>OK</body></html>'
    const styleTag = '<style>body{color:red}</style>'
    const result = injectStyleTagIntoHtml(input, styleTag)
    expect(result.rewritten).toBe(true)
    expect(result.chunk).toContain(`${styleTag}</head>`)
  })

  it('injects style tag before </head> in buffer chunks', () => {
    const input = Buffer.from(
      '<html><head><title>X</title></head><body>OK</body></html>',
      'utf-8',
    )
    const styleTag = '<style>body{color:red}</style>'
    const result = injectStyleTagIntoHtml(input, styleTag)
    expect(result.rewritten).toBe(true)
    expect(result.chunk).toBeTypeOf('string')
    expect(result.chunk).toContain(`${styleTag}</head>`)
  })

  it('returns unchanged chunk when </head> is missing', () => {
    const input = '<html><body>OK</body></html>'
    const styleTag = '<style>body{color:red}</style>'
    const result = injectStyleTagIntoHtml(input, styleTag)
    expect(result.rewritten).toBe(false)
    expect(result.chunk).toBe(input)
  })
})

describe('createClientCssInjectionMiddleware', () => {
  const trustedClient = 'https://trusted.app/client-metadata.json'

  function createResponseDouble() {
    const setHeaderSpy = vi.fn()
    const endSpy = vi.fn()
    const removeHeaderSpy = vi.fn()
    return {
      res: {
        setHeader: setHeaderSpy,
        end: endSpy,
        removeHeader: removeHeaderSpy,
      },
      setHeaderSpy,
      endSpy,
      removeHeaderSpy,
    }
  }

  it('calls next immediately when request does not match injection criteria', async () => {
    const middleware = createClientCssInjectionMiddleware({
      trustedClients: [trustedClient],
      resolveClientMetadata: vi.fn(),
      getClientCss: vi.fn(),
      logger: mockLogger(),
    })
    const req = { method: 'POST', path: '/oauth/authorize', query: {} }
    const { res } = createResponseDouble()
    const next = vi.fn()

    await middleware(req, res, next)
    expect(next).toHaveBeenCalledOnce()
  })

  it('calls next when trusted client has no css', async () => {
    const resolveClientMetadata = vi.fn().mockResolvedValue({})
    const getClientCss = vi.fn().mockReturnValue(null)
    const middleware = createClientCssInjectionMiddleware({
      trustedClients: [trustedClient],
      resolveClientMetadata,
      getClientCss,
      logger: mockLogger(),
    })
    const req = {
      method: 'GET',
      path: '/oauth/authorize',
      query: { client_id: trustedClient },
    }
    const { res } = createResponseDouble()
    const next = vi.fn()

    await middleware(req, res, next)
    expect(next).toHaveBeenCalledOnce()
    expect(resolveClientMetadata).toHaveBeenCalledWith(trustedClient)
    expect(getClientCss).toHaveBeenCalledOnce()
  })

  it('rewrites CSP header and response body when css is present', async () => {
    const middleware = createClientCssInjectionMiddleware({
      trustedClients: [trustedClient],
      resolveClientMetadata: vi.fn().mockResolvedValue({}),
      getClientCss: vi.fn().mockReturnValue('body { color: red; }'),
      logger: mockLogger(),
    })
    const req = {
      method: 'GET',
      path: '/oauth/authorize',
      query: { client_id: trustedClient },
    }
    const { res, setHeaderSpy, endSpy, removeHeaderSpy } =
      createResponseDouble()
    const next = vi.fn()

    await middleware(req, res, next)
    expect(next).toHaveBeenCalledOnce()

    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; style-src 'self'; img-src 'self'",
    )
    expect(setHeaderSpy).toHaveBeenCalledWith(
      'Content-Security-Policy',
      expect.stringContaining("style-src 'self' 'sha256-"),
    )

    const html = '<html><head><title>X</title></head><body>ok</body></html>'
    res.end(html)
    expect(endSpy).toHaveBeenCalledWith(
      expect.stringContaining('<style>body { color: red; }</style></head>'),
    )
    expect(removeHeaderSpy).toHaveBeenCalledWith('Content-Length')
    expect(removeHeaderSpy).toHaveBeenCalledWith('ETag')
  })

  it('does not remove headers when response is not rewritten', async () => {
    const middleware = createClientCssInjectionMiddleware({
      trustedClients: [trustedClient],
      resolveClientMetadata: vi.fn().mockResolvedValue({}),
      getClientCss: vi.fn().mockReturnValue('body { color: red; }'),
      logger: mockLogger(),
    })
    const req = {
      method: 'GET',
      path: '/oauth/authorize',
      query: { client_id: trustedClient },
    }
    const { res, removeHeaderSpy } = createResponseDouble()
    const next = vi.fn()

    await middleware(req, res, next)
    res.end('<html><body>ok</body></html>')
    expect(removeHeaderSpy).not.toHaveBeenCalled()
  })

  it('logs warning and continues when metadata resolution fails', async () => {
    const logger = mockLogger()
    const middleware = createClientCssInjectionMiddleware({
      trustedClients: [trustedClient],
      resolveClientMetadata: vi.fn().mockRejectedValue(new Error('boom')),
      getClientCss: vi.fn(),
      logger,
    })
    const req = {
      method: 'GET',
      path: '/oauth/authorize',
      query: { client_id: trustedClient },
    }
    const { res } = createResponseDouble()
    const next = vi.fn()

    await middleware(req, res, next)
    expect(logger.warn).toHaveBeenCalledOnce()
    expect(next).toHaveBeenCalledOnce()
  })
})

describe('findInsertionIndex', () => {
  it('returns index after compression when present', () => {
    const stack = [
      { name: 'query' },
      { name: 'expressInit' },
      { name: 'compression' },
      { name: 'router' },
    ]
    expect(findInsertionIndex(stack)).toBe(3)
  })

  it('falls back to after expressInit when compression is absent', () => {
    const stack = [
      { name: 'query' },
      { name: 'expressInit' },
      { name: 'router' },
    ]
    expect(findInsertionIndex(stack)).toBe(2)
  })

  it('returns 0 when neither compression nor expressInit is found', () => {
    const stack = [{ name: 'router' }, { name: 'other' }]
    expect(findInsertionIndex(stack)).toBe(0)
  })

  it('accepts custom preferAfter and fallbackAfter names', () => {
    const stack = [{ name: 'a' }, { name: 'myMiddleware' }, { name: 'b' }]
    expect(findInsertionIndex(stack, 'myMiddleware', 'a')).toBe(2)
  })
})
