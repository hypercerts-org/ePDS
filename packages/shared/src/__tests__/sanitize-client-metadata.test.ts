import { describe, expect, it } from 'vitest'
import { sanitizeClientMetadata } from '../client-metadata.js'

describe('sanitizeClientMetadata', () => {
  it('drops wrong-typed values instead of passing them to string code', () => {
    const out = sanitizeClientMetadata({
      client_name: ['a'],
      logo_uri: { x: 1 },
      brand_color: 5,
      epds_handle_mode: null,
      epds_skip_consent_on_signup: 'yes',
      branding: { css: 1, favicon_url: 'https://a.example/f.ico' },
      redirect_uris: ['https://a.example/cb', 3],
    })
    expect(out).toEqual({
      branding: { favicon_url: 'https://a.example/f.ico' },
      redirect_uris: ['https://a.example/cb'],
    })
  })

  it('ignores a non-object branding value', () => {
    expect(sanitizeClientMetadata({ branding: null })).toEqual({})
    expect(sanitizeClientMetadata({ branding: 'x' })).toEqual({})
  })

  it('keeps well-typed values', () => {
    const meta = {
      client_name: 'App',
      logo_uri: 'https://a.example/l.png',
      epds_handle_mode: 'random' as const,
      epds_skip_consent_on_signup: true,
      epds_social_providers: ['google'],
    }
    expect(sanitizeClientMetadata(meta)).toEqual(meta)
  })
})
