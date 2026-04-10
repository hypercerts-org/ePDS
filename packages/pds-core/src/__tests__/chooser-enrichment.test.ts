import { describe, expect, it, vi } from 'vitest'
import {
  appendScriptHashToCsp,
  buildChooserEnrichmentScript,
  createChooserEnrichmentMiddleware,
  injectScriptIntoHead,
  isChooserRequest,
  sha256Base64,
} from '../chooser-enrichment.js'

describe('buildChooserEnrichmentScript (HYPER-268)', () => {
  it('bakes in the auth hostname for the "use a different account" link', () => {
    const script = buildChooserEnrichmentScript('auth.pds.example')
    expect(script).toContain('https://auth.pds.example/oauth/authorize')
  })

  it('captures __deviceSessions via an accessor so the SPA still sees them', () => {
    const script = buildChooserEnrichmentScript('auth.example')
    // The script must define a setter on window.__deviceSessions that
    // forwards to a plain data property before re-defining the prop.
    expect(script).toContain("Object.defineProperty(window, '__deviceSessions'")
    expect(script).toContain(
      'configurable: true, enumerable: true, writable: true',
    )
  })

  it('includes the sign-in-as-different-account label text', () => {
    const script = buildChooserEnrichmentScript('auth.example')
    expect(script).toContain('Use a different account')
  })

  it('is deterministic for a given hostname', () => {
    const a = buildChooserEnrichmentScript('auth.pds.example')
    const b = buildChooserEnrichmentScript('auth.pds.example')
    expect(a).toBe(b)
  })

  it('produces different scripts for different hostnames', () => {
    const a = buildChooserEnrichmentScript('auth.pds.example')
    const b = buildChooserEnrichmentScript('auth.other.example')
    expect(a).not.toBe(b)
  })

  it('sets prompt=login on the fallback URL too', () => {
    // Second instance of prompt=login is the catch-block fallback.
    const script = buildChooserEnrichmentScript('auth.example')
    const matches = script.match(/prompt.*login/g) ?? []
    expect(matches.length).toBeGreaterThanOrEqual(2)
  })
})

describe('sha256Base64', () => {
  it('produces a stable SHA256 base64 hash', () => {
    // Known value for the empty string.
    expect(sha256Base64('')).toBe(
      '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=',
    )
  })

  it('returns a different hash for different inputs', () => {
    expect(sha256Base64('foo')).not.toBe(sha256Base64('bar'))
  })
})

describe('appendScriptHashToCsp (HYPER-268)', () => {
  const hash = 'abc123=='

  it('appends the hash to an existing script-src directive', () => {
    const csp =
      "default-src 'none'; script-src 'self' 'sha256-xyz='; style-src 'self'"
    const result = appendScriptHashToCsp(csp, hash)
    expect(result).toBe(
      "default-src 'none'; script-src 'self' 'sha256-xyz=' 'sha256-abc123=='; style-src 'self'",
    )
  })

  it('leaves other directives untouched', () => {
    const csp = "default-src 'none'; script-src 'self'; style-src 'self'"
    const result = appendScriptHashToCsp(csp, hash)
    expect(result).toContain("default-src 'none'")
    expect(result).toContain("style-src 'self'")
  })

  it('adds a fresh script-src clause when none exists', () => {
    const csp = "default-src 'none'"
    const result = appendScriptHashToCsp(csp, hash)
    expect(result).toBe("default-src 'none'; script-src 'sha256-abc123=='")
  })

  it('handles a CSP that already ends with a semicolon', () => {
    const csp = "default-src 'none';"
    const result = appendScriptHashToCsp(csp, hash)
    expect(result).toBe("default-src 'none'; script-src 'sha256-abc123=='")
  })

  it('is idempotent on the no-script-src branch when called twice', () => {
    // First call adds a script-src, second call should append to it
    // rather than add another fresh clause.
    const csp = "default-src 'none'"
    const once = appendScriptHashToCsp(csp, hash)
    const twice = appendScriptHashToCsp(once, 'def456==')
    expect(twice).toBe(
      "default-src 'none'; script-src 'sha256-abc123==' 'sha256-def456=='",
    )
  })
})

describe('isChooserRequest (HYPER-268)', () => {
  it('matches GET /account', () => {
    expect(isChooserRequest({ method: 'GET', path: '/account' })).toBe(true)
  })

  it('matches GET /account/foo', () => {
    expect(isChooserRequest({ method: 'GET', path: '/account/foo' })).toBe(true)
  })

  it('matches GET /account/deep/path', () => {
    expect(
      isChooserRequest({ method: 'GET', path: '/account/deep/path' }),
    ).toBe(true)
  })

  it('rejects non-GET methods', () => {
    expect(isChooserRequest({ method: 'POST', path: '/account' })).toBe(false)
    expect(isChooserRequest({ method: 'PUT', path: '/account' })).toBe(false)
  })

  it('rejects unrelated paths', () => {
    expect(isChooserRequest({ method: 'GET', path: '/oauth/authorize' })).toBe(
      false,
    )
    expect(isChooserRequest({ method: 'GET', path: '/' })).toBe(false)
    expect(
      isChooserRequest({ method: 'GET', path: '/accounts' }), // plural
    ).toBe(false)
  })
})

describe('injectScriptIntoHead (HYPER-268)', () => {
  const tag = '<script>window.__foo=1</script>'

  it('inserts the script tag immediately after <head>', () => {
    const html =
      '<!DOCTYPE html><html><head><title>X</title></head><body></body></html>'
    const result = injectScriptIntoHead(html, tag)
    expect(result.injected).toBe(true)
    expect(result.body).toBe(
      '<!DOCTYPE html><html><head><script>window.__foo=1</script><title>X</title></head><body></body></html>',
    )
  })

  it('returns injected=false when no <head> is present', () => {
    const html = '<html><body>no head here</body></html>'
    const result = injectScriptIntoHead(html, tag)
    expect(result.injected).toBe(false)
    expect(result.body).toBe(html)
  })

  it('only rewrites the first <head> occurrence', () => {
    const html =
      '<html><head><title>A</title></head><body>text mentioning <head> literally</body></html>'
    const result = injectScriptIntoHead(html, tag)
    expect(result.injected).toBe(true)
    // The first <head> gets the script; the literal string in the body stays.
    const firstHeadIdx = result.body.indexOf('<head>')
    const secondHeadIdx = result.body.indexOf('<head>', firstHeadIdx + 6)
    expect(secondHeadIdx).toBeGreaterThan(0)
    // The script is only inserted once.
    expect(result.body.split(tag).length - 1).toBe(1)
  })
})

describe('createChooserEnrichmentMiddleware (HYPER-268)', () => {
  // Build a fake response object that records every header / body
  // operation so each test can assert on what the middleware did.
  function makeRes() {
    const calls = {
      setHeader: [] as Array<[string, unknown]>,
      removedHeaders: [] as string[],
      end: [] as unknown[][],
    }
    const res = {
      setHeader: vi.fn((name: string, value: unknown) => {
        calls.setHeader.push([name, value])
      }),
      removeHeader: vi.fn((name: string) => {
        calls.removedHeaders.push(name)
      }),
      end: vi.fn((...args: unknown[]) => {
        calls.end.push(args)
      }),
    }
    return { res, calls }
  }

  it('passes non-chooser requests through untouched', () => {
    const mw = createChooserEnrichmentMiddleware('auth.pds.example')
    const { res, calls } = makeRes()
    const next = vi.fn()
    mw({ method: 'GET', path: '/oauth/authorize' }, res, next)
    expect(next).toHaveBeenCalledTimes(1)
    // setHeader should not be wrapped — calling it should record the
    // raw call without any rewriting.
    res.setHeader('Content-Security-Policy', "default-src 'none'")
    expect(calls.setHeader[0]).toEqual([
      'Content-Security-Policy',
      "default-src 'none'",
    ])
  })

  it('passes non-GET requests through untouched', () => {
    const mw = createChooserEnrichmentMiddleware('auth.pds.example')
    const { res } = makeRes()
    const next = vi.fn()
    mw({ method: 'POST', path: '/account' }, res, next)
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('appends the script hash to CSP script-src on chooser requests', () => {
    const mw = createChooserEnrichmentMiddleware('auth.pds.example')
    const { res, calls } = makeRes()
    mw({ method: 'GET', path: '/account' }, res, () => {})
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; script-src 'self'",
    )
    expect(calls.setHeader[0][0]).toBe('Content-Security-Policy')
    const newCsp = calls.setHeader[0][1] as string
    expect(newCsp).toMatch(/script-src 'self' 'sha256-[A-Za-z0-9+/=]+='/)
  })

  it('leaves non-CSP headers untouched on chooser requests', () => {
    const mw = createChooserEnrichmentMiddleware('auth.pds.example')
    const { res, calls } = makeRes()
    mw({ method: 'GET', path: '/account' }, res, () => {})
    res.setHeader('Content-Type', 'text/html')
    expect(calls.setHeader[0]).toEqual(['Content-Type', 'text/html'])
  })

  it('injects the enrichment script into the <head> of an HTML body', () => {
    const mw = createChooserEnrichmentMiddleware('auth.pds.example')
    const { res, calls } = makeRes()
    mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('<html><head><title>X</title></head><body></body></html>')
    const written = calls.end[0][0] as string
    expect(written).toContain('https://auth.pds.example/oauth/authorize')
    // Script tag must come immediately after the opening <head>.
    expect(written).toMatch(/<head><script>/)
  })

  it('strips Content-Length / ETag after rewriting the body', () => {
    const mw = createChooserEnrichmentMiddleware('auth.pds.example')
    const { res, calls } = makeRes()
    mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('<html><head></head></html>')
    expect(calls.removedHeaders).toContain('Content-Length')
    expect(calls.removedHeaders).toContain('ETag')
  })

  it('does not strip Content-Length when no <head> is present', () => {
    const mw = createChooserEnrichmentMiddleware('auth.pds.example')
    const { res, calls } = makeRes()
    mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('not html, no head here')
    expect(calls.removedHeaders).not.toContain('Content-Length')
    expect(calls.end[0][0]).toBe('not html, no head here')
  })

  it('rewrites a Buffer body that contains <head>', () => {
    const mw = createChooserEnrichmentMiddleware('auth.pds.example')
    const { res, calls } = makeRes()
    mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end(Buffer.from('<html><head></head></html>'))
    const written = calls.end[0][0] as string
    expect(typeof written).toBe('string')
    expect(written).toContain('<head><script>')
    expect(calls.removedHeaders).toContain('Content-Length')
  })

  it('passes Buffer bodies without <head> through untouched', () => {
    const mw = createChooserEnrichmentMiddleware('auth.pds.example')
    const { res, calls } = makeRes()
    mw({ method: 'GET', path: '/account' }, res, () => {})
    const buf = Buffer.from('<not html>')
    res.end(buf)
    // Original buffer is preserved (the wrapped end is called with
    // the original chunk reference, untouched).
    expect(calls.end[0][0]).toBe(buf)
    expect(calls.removedHeaders).not.toContain('Content-Length')
  })

  it('matches /account/foo and /account subpaths', () => {
    const mw = createChooserEnrichmentMiddleware('auth.pds.example')
    const { res, calls } = makeRes()
    mw({ method: 'GET', path: '/account/foo' }, res, () => {})
    res.end('<html><head></head></html>')
    expect(calls.end[0][0]).toMatch(/<head><script>/)
  })

  it('reuses the same script (and hash) across all instances built with the same hostname', () => {
    // Since the script is deterministic, two middleware instances
    // built with the same hostname should produce identical script
    // tags and identical CSP hashes — verifies the factory caches the
    // script correctly without leaking per-call state.
    const mw1 = createChooserEnrichmentMiddleware('auth.example')
    const mw2 = createChooserEnrichmentMiddleware('auth.example')
    const r1 = makeRes()
    const r2 = makeRes()
    mw1({ method: 'GET', path: '/account' }, r1.res, () => {})
    mw2({ method: 'GET', path: '/account' }, r2.res, () => {})
    r1.res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; script-src 'self'",
    )
    r2.res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; script-src 'self'",
    )
    expect(r1.calls.setHeader[0][1]).toEqual(r2.calls.setHeader[0][1])
  })
})
