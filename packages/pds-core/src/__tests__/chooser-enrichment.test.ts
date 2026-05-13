import { describe, expect, it, vi } from 'vitest'
import {
  appendScriptHashToCsp,
  buildChooserEnrichmentScript,
  createChooserEnrichmentMiddleware,
  injectHandleModeMeta,
  injectScriptIntoHead,
  isChooserRequest,
  sha256Base64,
} from '../chooser-enrichment.js'

describe('buildChooserEnrichmentScript (HYPER-268)', () => {
  it('captures both hydration globals (__sessions, __deviceSessions) via accessors', () => {
    const script = buildChooserEnrichmentScript()
    // Upstream uses __sessions on /oauth/authorize (inline chooser) and
    // __deviceSessions on /account (standalone account SPA). The script
    // must intercept BOTH with defineProperty setters so neither path
    // slips through untouched — missing this is how early iterations of
    // HYPER-268 rendered a plain handle-only chooser in browsers.
    expect(script).toContain("interceptGlobal('__deviceSessions')")
    expect(script).toContain("interceptGlobal('__sessions')")
    expect(script).toContain('Object.defineProperty(window, name')
    expect(script).toContain(
      'configurable: true, enumerable: true, writable: true',
    )
  })

  it('is deterministic', () => {
    expect(buildChooserEnrichmentScript()).toBe(buildChooserEnrichmentScript())
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

  it('matches GET /oauth/authorize — upstream renders the chooser inline there', () => {
    expect(isChooserRequest({ method: 'GET', path: '/oauth/authorize' })).toBe(
      true,
    )
  })

  it('rejects unrelated paths', () => {
    expect(isChooserRequest({ method: 'GET', path: '/' })).toBe(false)
    expect(
      isChooserRequest({ method: 'GET', path: '/accounts' }), // plural
    ).toBe(false)
    expect(
      isChooserRequest({ method: 'GET', path: '/oauth/authorize/accept' }),
    ).toBe(false)
    expect(isChooserRequest({ method: 'POST', path: '/oauth/authorize' })).toBe(
      false,
    )
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

// Fake response object used across every middleware describe below.
// Records every header / body operation so tests can assert on what
// the middleware did.
function makeRes({ headersSent = false }: { headersSent?: boolean } = {}) {
  const calls = {
    setHeader: [] as Array<[string, unknown]>,
    removedHeaders: [] as string[],
    end: [] as unknown[][],
  }
  const res = {
    headersSent,
    setHeader: vi.fn((name: string, value: unknown) => {
      calls.setHeader.push([name, value])
    }),
    removeHeader: vi.fn((name: string) => {
      if (res.headersSent) {
        // Mirror Node's real behaviour: removeHeader() throws once
        // the response has been flushed. Tests rely on this shape so
        // the middleware's headersSent guard is exercised.
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

// Drive the middleware against a chooser request and return the
// HTML body that upstream would have received (i.e. what was passed
// to the wrapped res.end). Collapses the boilerplate of
// `createChooserEnrichmentMiddleware + makeRes + await mw + res.end +
// read calls.end[0][0]` that otherwise repeats across every
// meta-tag / rewrite test.
async function captureWrittenHtml(
  opts: Parameters<typeof createChooserEnrichmentMiddleware>[0],
  query: Record<string, string> = {},
  body = '<html><head></head></html>',
): Promise<string> {
  const mw = createChooserEnrichmentMiddleware(opts)
  const { res, calls } = makeRes()
  await mw({ method: 'GET', path: '/account', query }, res, () => {})
  res.end(body)
  return calls.end[0][0] as string
}

describe('createChooserEnrichmentMiddleware (HYPER-268)', () => {
  it('passes non-chooser requests through untouched', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    const next = vi.fn()
    await mw({ method: 'GET', path: '/oauth/token' }, res, next)
    expect(next).toHaveBeenCalledTimes(1)
    // setHeader should not be wrapped — calling it should record the
    // raw call without any rewriting.
    res.setHeader('Content-Security-Policy', "default-src 'none'")
    expect(calls.setHeader[0]).toEqual([
      'Content-Security-Policy',
      "default-src 'none'",
    ])
  })

  it('passes non-GET requests through untouched', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res } = makeRes()
    const next = vi.fn()
    await mw({ method: 'POST', path: '/account' }, res, next)
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('appends the script hash to CSP script-src on chooser requests', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; script-src 'self'",
    )
    expect(calls.setHeader[0][0]).toBe('Content-Security-Policy')
    const newCsp = calls.setHeader[0][1] as string
    expect(newCsp).toMatch(/script-src 'self' 'sha256-[A-Za-z0-9+/=]+='/)
  })

  it('leaves non-CSP headers untouched on chooser requests', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.setHeader('Content-Type', 'text/html')
    expect(calls.setHeader[0]).toEqual(['Content-Type', 'text/html'])
  })

  it('injects the enrichment script into the <head> of an HTML body', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('<html><head><title>X</title></head><body></body></html>')
    const written = calls.end[0][0] as string
    // Head rewrite must start with the handle-mode meta (so the script
    // can read it synchronously on DOMContentLoaded), followed by the
    // enrichment <script>. The meta is always present — handleMode
    // resolves to `picker-with-random` when no query / metadata
    // overrides it.
    expect(written).toMatch(
      /<head><meta name="epds-handle-mode" content="[a-z-]+"><meta name="epds-auth-origin" content="[^"]*"><script>/,
    )
  })

  it('strips Content-Length / ETag after rewriting the body', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('<html><head></head></html>')
    expect(calls.removedHeaders).toContain('Content-Length')
    expect(calls.removedHeaders).toContain('ETag')
  })

  it('does not strip Content-Length when no <head> is present', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('not html, no head here')
    expect(calls.removedHeaders).not.toContain('Content-Length')
    expect(calls.end[0][0]).toBe('not html, no head here')
  })

  it('rewrites a Buffer body that contains <head>', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end(Buffer.from('<html><head></head></html>'))
    const written = calls.end[0][0] as string
    expect(typeof written).toBe('string')
    expect(written).toMatch(
      /<head><meta name="epds-handle-mode" content="[a-z-]+"><meta name="epds-auth-origin" content="[^"]*"><script>/,
    )
    expect(calls.removedHeaders).toContain('Content-Length')
  })

  it('passes Buffer bodies without <head> through untouched', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    const buf = Buffer.from('<not html>')
    res.end(buf)
    // Original buffer is preserved (the wrapped end is called with
    // the original chunk reference, untouched).
    expect(calls.end[0][0]).toBe(buf)
    expect(calls.removedHeaders).not.toContain('Content-Length')
  })

  it('matches /account/foo and /account subpaths', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes()
    await mw({ method: 'GET', path: '/account/foo' }, res, () => {})
    res.end('<html><head></head></html>')
    expect(calls.end[0][0]).toMatch(
      /<head><meta name="epds-handle-mode" content="[a-z-]+"><meta name="epds-auth-origin" content="[^"]*"><script>/,
    )
  })

  it('reuses the same script (and hash) across instances', async () => {
    // Since the script is deterministic, two middleware instances
    // should produce identical script tags and identical CSP hashes —
    // verifies the factory doesn't leak per-call state.
    const mw1 = createChooserEnrichmentMiddleware()
    const mw2 = createChooserEnrichmentMiddleware()
    const r1 = makeRes()
    const r2 = makeRes()
    await mw1({ method: 'GET', path: '/account' }, r1.res, () => {})
    await mw2({ method: 'GET', path: '/account' }, r2.res, () => {})
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

  // ─── Regression: ERR_HTTP_HEADERS_SENT crash ─────────────────────────
  //
  // @atproto/oauth-provider's account-chooser route flushes its headers
  // before calling res.end(). Before this guard, our wrapped end() called
  // removeHeader('Content-Length') afterwards, which throws
  // ERR_HTTP_HEADERS_SENT at Node's HTTP layer. The throw escapes the
  // Express error pipeline (it's raised from a method replacement on
  // `res`, not from middleware body) and lands as an uncaught exception,
  // crashing pds-core. See the comment in chooser-enrichment.ts end()
  // wrapper for details.
  it('does not throw when upstream flushes headers before end()', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res } = makeRes({ headersSent: true })
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    expect(() => {
      res.end('<!DOCTYPE html><html><head></head><body></body></html>')
    }).not.toThrow()
  })

  it('skips Content-Length rewrite once headers have been flushed', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes({ headersSent: true })
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('<!DOCTYPE html><html><head></head><body></body></html>')
    expect(calls.removedHeaders).toEqual([])
    expect(calls.end.length).toBe(1)
  })

  it('still rewrites Content-Length when headers have not been flushed', async () => {
    const mw = createChooserEnrichmentMiddleware()
    const { res, calls } = makeRes({ headersSent: false })
    await mw({ method: 'GET', path: '/account' }, res, () => {})
    res.end('<!DOCTYPE html><html><head></head><body></body></html>')
    expect(calls.removedHeaders).toEqual(['Content-Length', 'ETag'])
  })
})

describe('buildChooserEnrichmentScript handle-mode hiding (HYPER-268 Layer 4)', () => {
  it('reads the epds-handle-mode meta tag at runtime', () => {
    const script = buildChooserEnrichmentScript()
    expect(script).toContain('querySelector(\'meta[name="epds-handle-mode"]\')')
  })

  it("hides the handle span and sets a title tooltip when mode is 'random'", () => {
    const script = buildChooserEnrichmentScript()
    // Hiding strategy: display:none on the handle element + title
    // attribute on the email label carrying the original handle text.
    expect(script).toContain("hideHandle = handleMode === 'random'")
    expect(script).toContain("m.el.style.display = 'none'")
    expect(script).toContain('label.title = ownText')
  })

  it('leaves the handle visible for picker / picker-with-random', () => {
    // The hideHandle branch is the only path that manipulates the
    // handle element; non-random modes fall through untouched.
    const script = buildChooserEnrichmentScript()
    expect(script).toMatch(/if \(hideHandle\)/)
  })
})

describe('injectHandleModeMeta (HYPER-268 Layer 4)', () => {
  it('inserts a meta tag carrying the handle mode into <head>', () => {
    const html =
      '<!DOCTYPE html><html><head><title>X</title></head><body></body></html>'
    const result = injectHandleModeMeta(html, 'random')
    expect(result.injected).toBe(true)
    expect(result.body).toContain(
      '<meta name="epds-handle-mode" content="random">',
    )
  })

  it('returns injected=false when no <head> is present', () => {
    const html = '<html><body>no head</body></html>'
    const result = injectHandleModeMeta(html, 'picker-with-random')
    expect(result.injected).toBe(false)
    expect(result.body).toBe(html)
  })
})

describe('createChooserEnrichmentMiddleware handle-mode meta (HYPER-268 Layer 4)', () => {
  it('falls back to picker-with-random when no query / metadata provides a mode', async () => {
    const written = await captureWrittenHtml({
      resolveClientMetadata: () => Promise.resolve({}),
    })
    expect(written).toContain(
      '<meta name="epds-handle-mode" content="picker-with-random">',
    )
  })

  it('honours the epds_handle_mode query override', async () => {
    const written = await captureWrittenHtml(
      { resolveClientMetadata: () => Promise.resolve({}) },
      { epds_handle_mode: 'random' },
    )
    expect(written).toContain('<meta name="epds-handle-mode" content="random">')
  })

  it('falls through to client metadata when query has no override', async () => {
    // The middleware awaits the metadata resolver before calling
    // next(), so the resolved value is always incorporated into the
    // meta tag — no races with upstream's synchronous res.end.
    const written = await captureWrittenHtml(
      {
        resolveClientMetadata: () =>
          Promise.resolve({ epds_handle_mode: 'random' as const }),
      },
      { client_id: 'https://demo.example/client' },
    )
    expect(written).toContain('<meta name="epds-handle-mode" content="random">')
  })

  it('ignores invalid handle modes from metadata (fall through to fallback)', async () => {
    const written = await captureWrittenHtml(
      {
        resolveClientMetadata: () =>
          // Value shape is intentional: an invalid string should be
          // ignored by the resolver, not propagated into the meta tag.
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- deliberate bad value
          Promise.resolve({ epds_handle_mode: 'garbage' as any }),
      },
      { client_id: 'https://demo.example/client' },
    )
    expect(written).toContain(
      '<meta name="epds-handle-mode" content="picker-with-random">',
    )
  })

  it('degrades silently when the metadata resolver rejects', async () => {
    const written = await captureWrittenHtml(
      {
        resolveClientMetadata: () => Promise.reject(new Error('network error')),
      },
      { client_id: 'https://demo.example/client' },
    )
    // Falls back to the default — no network means no upgrade.
    expect(written).toContain(
      '<meta name="epds-handle-mode" content="picker-with-random">',
    )
  })
})

describe('buildChooserEnrichmentScript sign-up hide + another-account rebind', () => {
  it('reads the epds-auth-origin meta tag at runtime', () => {
    const script = buildChooserEnrichmentScript()
    expect(script).toContain('querySelector(\'meta[name="epds-auth-origin"]\')')
  })

  it('hides upstream\'s "Sign up" button and marks it to stay idempotent', () => {
    const script = buildChooserEnrichmentScript()
    // Matches by trimmed text content — idempotent via dataset.epdsHidden
    // so the MutationObserver doesn't re-hide on every tick.
    expect(script).toContain("text === 'Sign up'")
    expect(script).toContain("el.style.display = 'none'")
    expect(script).toContain("el.setAttribute('aria-hidden', 'true'")
    expect(script).toContain("el.dataset.epdsHidden = '1'")
  })

  it('rebinds the "Another account" button via capture-phase listener', () => {
    const script = buildChooserEnrichmentScript()
    // Capture-phase is essential — React's delegated root-level click
    // listener fires in bubble phase, so a bubble listener on the button
    // would run AFTER React swaps to upstream's stock sign-in component.
    expect(script).toContain(
      '\'[role="button"][aria-label="Login to account that is not listed"]\'',
    )
    expect(script).toContain('e.preventDefault()')
    expect(script).toContain('e.stopImmediatePropagation()')
    expect(script).toContain('window.location.href')
    // The `true` third arg to addEventListener switches to capture phase.
    expect(script).toMatch(/addEventListener\([\s\S]*?true,?\s*\);/)
    expect(script).toContain("btn.dataset.epdsRebound = '1'")
  })

  it('forces prompt=login on the Another-account redirect URL', () => {
    const script = buildChooserEnrichmentScript()
    // OIDC's force-reauth signal; auth-service's shouldReuseSession
    // honours it and falls through to the email form instead of
    // redirecting back to pds-core's chooser.
    expect(script).toContain("params.set('prompt', 'login')")
  })
})

describe('createChooserEnrichmentMiddleware auth-origin meta (Another-account rebind)', () => {
  it('injects the auth-origin meta tag when authOrigin is provided', async () => {
    const written = await captureWrittenHtml({
      resolveClientMetadata: () => Promise.resolve({}),
      authOrigin: 'https://auth.example',
    })
    expect(written).toContain(
      '<meta name="epds-auth-origin" content="https://auth.example">',
    )
  })

  it('injects an empty auth-origin meta tag when authOrigin is omitted', async () => {
    // Empty value signals the script to skip the rebind — fails-open to
    // upstream's default behaviour rather than throwing on a missing meta.
    const written = await captureWrittenHtml({
      resolveClientMetadata: () => Promise.resolve({}),
    })
    expect(written).toContain('<meta name="epds-auth-origin" content="">')
  })

  it('HTML-escapes authOrigin so a misconfigured value cannot break attribute quoting', async () => {
    // authOrigin is operator-configured, not user-controlled, but a
    // malformed value with a stray `"` or `<` would otherwise escape the
    // attribute and break the injected head. Cheap defense-in-depth.
    const written = await captureWrittenHtml({
      resolveClientMetadata: () => Promise.resolve({}),
      authOrigin: 'https://auth.example/"><script>alert(1)</script>',
    })
    expect(written).toContain(
      '<meta name="epds-auth-origin" content="https://auth.example/&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;">',
    )
    // The raw attacker payload must not appear unescaped.
    expect(written).not.toContain('"><script>alert(1)</script>')
  })

  it('emits both meta tags before the script tag in head', async () => {
    // Order matters for the script's synchronous read on DOMContentLoaded.
    const written = await captureWrittenHtml({
      resolveClientMetadata: () => Promise.resolve({}),
      authOrigin: 'https://auth.example',
    })
    const handleModeIdx = written.indexOf('epds-handle-mode')
    const authOriginIdx = written.indexOf('epds-auth-origin')
    const scriptIdx = written.indexOf('<script>')
    expect(handleModeIdx).toBeGreaterThan(-1)
    expect(authOriginIdx).toBeGreaterThan(handleModeIdx)
    expect(scriptIdx).toBeGreaterThan(authOriginIdx)
  })
})
