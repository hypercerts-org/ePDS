import { createServer } from 'node:http'
import express from 'express'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  createPreviewConsentHandler,
  renderPreviewIndex,
} from '../lib/preview-consent.js'
import { createPreviewChooserHandler } from '../lib/preview-chooser.js'
import { installPreviewRoutes } from '../preview-routes.js'
import { mockLogger, mockRes } from './preview-test-helpers.js'

describe('createPreviewConsentHandler', () => {
  // Snapshot + restore per-test so a mid-test throw cannot leak env state
  // between tests (process.env is process-global, unlike Vitest's module
  // isolation).
  let originalEnv: string | undefined

  beforeEach(() => {
    originalEnv = process.env.PDS_PREVIEW_ROUTES
    delete process.env.PDS_PREVIEW_ROUTES
  })

  afterEach(() => {
    if (originalEnv === undefined) delete process.env.PDS_PREVIEW_ROUTES
    else process.env.PDS_PREVIEW_ROUTES = originalEnv
    vi.restoreAllMocks()
  })

  it('returns null when PDS_PREVIEW_ROUTES is unset', () => {
    // beforeEach already deleted it; explicit here is redundant but harmless
    const handler = createPreviewConsentHandler({
      trustedClients: [],
      resolveClientMetadata: () => Promise.resolve({}),
      getClientCss: () => null,
      logger: mockLogger(),
    })
    expect(handler).toBeNull()
  })

  it('returns null when PDS_PREVIEW_ROUTES is not "1"', () => {
    process.env.PDS_PREVIEW_ROUTES = '0'
    const handler = createPreviewConsentHandler({
      trustedClients: [],
      resolveClientMetadata: () => Promise.resolve({}),
      getClientCss: () => null,
      logger: mockLogger(),
    })
    expect(handler).toBeNull()
  })

  describe('when enabled', () => {
    beforeEach(() => {
      process.env.PDS_PREVIEW_ROUTES = '1'
    })

    it('renders fixture consent HTML through the registered route', async () => {
      const deps = {
        trustedClients: [],
        resolveClientMetadata: () => Promise.resolve({}),
        getClientCss: () => null,
        logger: mockLogger(),
      }
      const app = express()
      installPreviewRoutes(app, {
        previewConsentHandler: createPreviewConsentHandler(deps)!,
        previewChooserHandler: createPreviewChooserHandler({
          ...deps,
          authOrigin: 'http://auth.localhost',
        })!,
        authHostname: 'auth.localhost',
        pdsPublicUrl: 'http://pds.localhost',
        trustedClients: [],
        logger: deps.logger,
      })
      const server = createServer(app)
      const serverReady = new Promise<void>((resolve, reject) => {
        server.once('listening', resolve)
        server.once('error', reject)
      })
      server.listen(0)

      try {
        await serverReady
        const address = server.address()
        if (!address || typeof address === 'string') {
          throw new Error('Expected the preview test server to have a port')
        }
        const response = await fetch(
          `http://127.0.0.1:${address.port}/preview/consent`,
        )
        const body = await response.text()

        expect(response.status).toBe(200)
        expect(response.headers.get('content-type')).toBe(
          'text/html; charset=utf-8',
        )
        expect(response.headers.get('cache-control')).toBe('no-store')
        expect(response.headers.get('content-security-policy')).toContain(
          "script-src 'self' 'unsafe-inline'",
        )
        expect(body).toContain('preview.example/client-metadata.json')
        // Drives provider UI 0.10.3 straight to consent. The session account
        // uses the provider API's `did` field, and AuthorizeData selects it via
        // `selectedDid`; the removed `account.sub` / `session.selected` fixture
        // shape silently opens the account chooser instead.
        // Hydration is JSON-stringified twice, so names appear escaped.
        expect(body).toContain(
          String.raw`\"selectedDid\":\"did:web:preview.example\"`,
        )
        expect(body).toContain(String.raw`\"did\":\"did:web:preview.example\"`)
        expect(body).not.toContain(String.raw`\"sub\"`)
        expect(body).not.toContain(String.raw`\"selected\"`)
        // No loginHint — it would force account authentication.
        expect(body).not.toContain(String.raw`\"loginHint\"`)
        // Hydration script + entry bundle present:
        expect(body).toMatch(/<script>window\["__authorizeData"\]=JSON\.parse/)
        expect(body).toContain('/@atproto/oauth-provider/~assets/')
      } finally {
        await new Promise<void>((resolve, reject) => {
          server.close((error) => {
            if (error) {
              reject(error)
              return
            }
            resolve()
          })
        })
      }
    })

    it('resolves client metadata and injects CSS for custom client_id', async () => {
      const trusted = 'https://trusted.example/client-metadata.json'
      const resolveClientMetadata = vi.fn(() =>
        Promise.resolve({ client_name: 'Trusted App' }),
      )
      const getClientCss = vi.fn(() => 'body { color: red; }')
      const logger = mockLogger()

      const handler = createPreviewConsentHandler({
        trustedClients: [trusted],
        resolveClientMetadata,
        getClientCss,
        logger,
      })!
      const res = mockRes()
      await handler({ query: { client_id: trusted } }, res)

      expect(resolveClientMetadata).toHaveBeenCalledWith(trusted, {
        noCache: true,
      })
      expect(getClientCss).toHaveBeenCalledWith(
        trusted,
        { client_name: 'Trusted App' },
        [trusted],
      )
      expect(res.body).toContain('<style>body { color: red; }</style>')
      expect(res.body).toContain(String.raw`\"clientTrusted\":true`)
      expect(res.body).toContain('trusted.example')
    })

    it('marks clientTrusted=false when client_id is not in trustedClients', async () => {
      const handler = createPreviewConsentHandler({
        trustedClients: ['https://other.example/client-metadata.json'],
        resolveClientMetadata: () => Promise.resolve({}),
        getClientCss: () => null,
        logger: mockLogger(),
      })!
      const res = mockRes()
      await handler(
        {
          query: {
            client_id: 'https://untrusted.example/client-metadata.json',
          },
        },
        res,
      )
      expect(res.body).toContain(String.raw`\"clientTrusted\":false`)
    })

    it('logs a warning and still renders when metadata resolution fails', async () => {
      const logger = mockLogger()
      const handler = createPreviewConsentHandler({
        trustedClients: [],
        resolveClientMetadata: () => Promise.reject(new Error('fetch failed')),
        getClientCss: () => null,
        logger,
      })!
      const res = mockRes()
      await handler(
        { query: { client_id: 'https://broken.example/client-metadata.json' } },
        res,
      )
      expect(logger.warn).toHaveBeenCalledOnce()
      const [ctx, msg] = logger.warn.mock.calls[0]
      expect(msg).toMatch(/Preview consent/i)
      expect(ctx).toMatchObject({
        clientId: 'https://broken.example/client-metadata.json',
      })
      // Still responds with valid HTML shell:
      expect(res.body).toMatch(/<!doctype html>/i)
    })

    it('ignores non-string client_id and falls back to fixture default', async () => {
      const resolveClientMetadata = vi.fn(() => Promise.resolve({}))
      const handler = createPreviewConsentHandler({
        trustedClients: [],
        resolveClientMetadata,
        getClientCss: () => null,
        logger: mockLogger(),
      })!
      const res = mockRes()
      await handler({ query: { client_id: ['array', 'value'] } }, res)
      // Default fixture client: no resolution attempted
      expect(resolveClientMetadata).not.toHaveBeenCalled()
      expect(res.body).toContain('preview.example/client-metadata.json')
    })

    it('escapes `</script>` in attacker-controlled clientId so it cannot break out of the hydration <script>', async () => {
      const handler = createPreviewConsentHandler({
        trustedClients: [],
        resolveClientMetadata: () => Promise.resolve({}),
        getClientCss: () => null,
        logger: mockLogger(),
      })!
      const res = mockRes()
      await handler(
        {
          query: {
            client_id:
              'https://x.example/</script><img src=x onerror=alert(1)>',
          },
        },
        res,
      )
      // Pull out the hydration script and assert the breakout payload is escaped.
      // The browser only terminates <script> on a literal `</script>`; as long as
      // the unescaped sequence never appears inside the script block we're safe.
      const body = res.body!
      const scriptMatch =
        /<script>(window\["__authorizeData"\][\s\S]*?document\.currentScript\.remove\(\);)<\/script>/.exec(
          body,
        )
      expect(scriptMatch).not.toBeNull()
      const scriptBody = scriptMatch![1]
      expect(scriptBody).not.toMatch(/<\/script/i)
      // serialize-javascript escapes `<` → `\u003C` (uppercase C)
      expect(scriptBody).toContain(String.raw`\u003C\u002Fscript`)
    })

    it('always bypasses the metadata cache (preview routes never serve stale branding)', async () => {
      const resolveClientMetadata = vi.fn(() => Promise.resolve({}))
      const handler = createPreviewConsentHandler({
        trustedClients: [],
        resolveClientMetadata,
        getClientCss: () => null,
        logger: mockLogger(),
      })!
      const res = mockRes()
      await handler(
        { query: { client_id: 'https://x.example/client-metadata.json' } },
        res,
      )
      expect(resolveClientMetadata).toHaveBeenCalledWith(
        'https://x.example/client-metadata.json',
        { noCache: true },
      )
    })

    it('HTML-escapes the client id in the <title>', async () => {
      const handler = createPreviewConsentHandler({
        trustedClients: [],
        resolveClientMetadata: () => Promise.resolve({}),
        getClientCss: () => null,
        logger: mockLogger(),
      })!
      const res = mockRes()
      await handler(
        {
          query: { client_id: 'https://x.example/<dangerous>tag</dangerous>' },
        },
        res,
      )
      // Title is HTML-escaped:
      expect(res.body).toContain(
        '<title>Consent preview — https://x.example/&lt;dangerous&gt;tag&lt;/dangerous&gt;</title>',
      )
      // Raw tag must not appear in the title context. It does appear
      // unescaped inside the JSON hydration string literal — that's fine
      // because the browser parses it as a JS string, not HTML — so we
      // only assert the title remains escaped, by checking no unescaped
      // `<dangerous>` precedes the hydration <script> block.
      const titleEnd = res.body!.indexOf('</title>')
      expect(res.body!.slice(0, titleEnd)).not.toContain('<dangerous>')
    })
  })
})

describe('renderPreviewIndex', () => {
  const urls = {
    authPublicUrl: 'https://auth.pds.example',
    pdsPublicUrl: 'https://pds.example',
  }

  it('returns an HTML page listing the consent preview route', () => {
    const html = renderPreviewIndex(urls)
    expect(html).toMatch(/<!DOCTYPE html>/i)
    expect(html).toContain('pds-core preview routes')
    expect(html).toContain('href="/preview/consent"')
    expect(html).toContain('PDS_OAUTH_TRUSTED_CLIENTS')
  })

  it('includes the persisted client_id input with data-preview-link anchors', () => {
    const html = renderPreviewIndex(urls)
    expect(html).toContain('id="client-id-input"')
    expect(html).toContain('data-preview-link')
    // Inline script wires input → links and persists via localStorage:
    expect(html).toContain("'epds:preview:client_id'")
    expect(html).toContain('localStorage.getItem')
  })

  it('includes the live metadata-cache status block', () => {
    const html = renderPreviewIndex(urls)
    expect(html).toContain('id="cache-status-body"')
    expect(html).toContain('/preview/cache-status')
  })

  it('lists auth-service routes as absolute cross-origin links', () => {
    const html = renderPreviewIndex(urls)
    expect(html).toContain('href="https://auth.pds.example/preview/login"')
    expect(html).toContain(
      'href="https://auth.pds.example/preview/recovery-otp"',
    )
    // /preview/choose-handle no longer enumerates ?error= variants;
    // the dropdown bound to the `error` param replaces them. Assert
    // both the link and the bound control instead.
    expect(html).toContain(
      'href="https://auth.pds.example/preview/choose-handle"',
    )
    expect(html).toContain('data-preview-param="error"')
  })

  it('seeds the client_id input from ?client_id= on the page URL', () => {
    const html = renderPreviewIndex(urls)
    // The inline script reads window.location for an initial value so
    // /preview?client_id=<url> landings pre-fill the input.
    expect(html).toContain("searchParams.get('client_id')")
  })
})
