import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { createPreviewChooserHandler } from '../lib/preview-chooser.js'
import { mockLogger, mockRes } from './preview-test-helpers.js'

const AUTH_ORIGIN = 'https://auth.example'

function makeDeps(
  overrides: Partial<Parameters<typeof createPreviewChooserHandler>[0]> = {},
) {
  return {
    trustedClients: [],
    resolveClientMetadata: () => Promise.resolve({}),
    getClientCss: () => null,
    authOrigin: AUTH_ORIGIN,
    logger: mockLogger(),
    ...overrides,
  }
}

describe('createPreviewChooserHandler', () => {
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
    expect(createPreviewChooserHandler(makeDeps())).toBeNull()
  })

  it('returns null when PDS_PREVIEW_ROUTES is not "1"', () => {
    process.env.PDS_PREVIEW_ROUTES = '0'
    expect(createPreviewChooserHandler(makeDeps())).toBeNull()
  })

  describe('when enabled', () => {
    beforeEach(() => {
      process.env.PDS_PREVIEW_ROUTES = '1'
    })

    it('renders the chooser view with one fixture session by default', async () => {
      const handler = createPreviewChooserHandler(makeDeps())!
      const res = mockRes()
      await handler({ query: {} }, res)
      expect(res.headers['Content-Type']).toBe('text/html; charset=utf-8')
      expect(res.body).toContain('preview.example/client-metadata.json')
      // Provider UI 0.10.3 chooser sessions contain only the current
      // Account fields plus loginRequired.
      expect(res.body).toContain(
        String.raw`\"did\":\"did:web:preview-0.example\"`,
      )
      expect(res.body).toContain(
        String.raw`\"pds\":\"did:web:preview-0.example\"`,
      )
      expect(res.body).toContain(String.raw`\"deactivated\":false`)
      expect(res.body).toContain(
        String.raw`\"handle\":\"alice.preview.example\"`,
      )
      expect(res.body).toContain(String.raw`\"name\":\"Alice Preview\"`)
      expect(res.body).toContain(
        String.raw`\"email\":\"alice@preview.example\"`,
      )
      expect(res.body).toContain(String.raw`\"loginRequired\":false`)
      expect(res.body).not.toContain(String.raw`\"sub\":`)
      expect(res.body).not.toContain(String.raw`\"aud\":`)
      expect(res.body).not.toContain(String.raw`\"preferred_username\":`)
      expect(res.body).not.toContain(String.raw`\"selected\":`)
      expect(res.body).not.toContain(String.raw`\"consentRequired\":`)
    })

    it('respects ?numAccounts to grow / shrink the fixture', async () => {
      const handler = createPreviewChooserHandler(makeDeps())!
      const res = mockRes()
      await handler({ query: { numAccounts: '3' } }, res)
      expect(res.body).toContain(
        String.raw`\"handle\":\"alice.preview.example\"`,
      )
      expect(res.body).toContain(String.raw`\"handle\":\"bob.preview.example\"`)
      expect(res.body).toContain(
        String.raw`\"handle\":\"carol.preview.example\"`,
      )
      expect(res.body).not.toContain(
        String.raw`\"handle\":\"dave.preview.example\"`,
      )
    })

    it('clamps ?numAccounts to [1, 10]', async () => {
      const handler = createPreviewChooserHandler(makeDeps())!
      const overflow = mockRes()
      await handler({ query: { numAccounts: '99' } }, overflow)
      expect(overflow.body).toContain(
        String.raw`\"handle\":\"jack.preview.example\"`,
      )

      // Zero/negative clamp up to 1 — never to an empty session list, which
      // would let upstream's no-session welcome view leak through this route.
      for (const value of ['0', '-5']) {
        const res = mockRes()
        await handler({ query: { numAccounts: value } }, res)
        expect(res.body).toContain(
          String.raw`\"handle\":\"alice.preview.example\"`,
        )
        expect(res.body).not.toContain(
          String.raw`\"handle\":\"bob.preview.example\"`,
        )
      }
    })

    it('emits the same <head> injection real chooser middleware does', async () => {
      const handler = createPreviewChooserHandler(makeDeps())!
      const res = mockRes()
      await handler({ query: {} }, res)
      expect(res.body).toContain(
        '<meta name="epds-handle-mode" content="picker-with-random">',
      )
      expect(res.body).toContain(
        `<meta name="epds-auth-origin" content="${AUTH_ORIGIN}">`,
      )
      // Enrichment script is the same one the real middleware injects,
      // so its presence by signature string proves the wire-up.
      expect(res.body).toContain(`function readHandleMode()`)
    })

    it('reads the override from ?epds_handle_mode (production param name)', async () => {
      const handler = createPreviewChooserHandler(makeDeps())!
      const res = mockRes()
      await handler({ query: { epds_handle_mode: 'random' } }, res)
      expect(res.body).toContain(
        '<meta name="epds-handle-mode" content="random">',
      )
    })

    it('falls back to client metadata when no query override is present', async () => {
      const handler = createPreviewChooserHandler(
        makeDeps({
          resolveClientMetadata: () =>
            Promise.resolve({ epds_handle_mode: 'picker' }),
        }),
      )!
      const res = mockRes()
      await handler(
        { query: { client_id: 'https://x.example/client-metadata.json' } },
        res,
      )
      expect(res.body).toContain(
        '<meta name="epds-handle-mode" content="picker">',
      )
    })

    it('query override beats client metadata (production resolver order)', async () => {
      const handler = createPreviewChooserHandler(
        makeDeps({
          resolveClientMetadata: () =>
            Promise.resolve({ epds_handle_mode: 'picker' }),
        }),
      )!
      const res = mockRes()
      await handler(
        {
          query: {
            client_id: 'https://x.example/client-metadata.json',
            epds_handle_mode: 'random',
          },
        },
        res,
      )
      expect(res.body).toContain(
        '<meta name="epds-handle-mode" content="random">',
      )
    })

    it('still renders when client metadata resolution fails', async () => {
      const logger = mockLogger()
      const handler = createPreviewChooserHandler(
        makeDeps({
          resolveClientMetadata: () =>
            Promise.reject(new Error('fetch failed')),
          logger,
        }),
      )!
      const res = mockRes()
      await handler(
        { query: { client_id: 'https://broken.example/client-metadata.json' } },
        res,
      )
      expect(logger.warn).toHaveBeenCalledOnce()
      expect(res.body).toMatch(/<!doctype html>/i)
    })
  })
})
