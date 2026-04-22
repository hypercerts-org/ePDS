import { describe, it, expect } from 'vitest'
import { shouldRewriteSecFetchSite } from '../lib/sec-fetch-site-rewrite.js'

const BASE = {
  method: 'GET',
  path: '/oauth/authorize',
  secFetchSite: 'same-site' as string | undefined,
  referer: undefined as string | undefined,
  authOrigin: 'https://auth.pds.example',
  pdsOrigin: 'https://pds.example',
}

describe('shouldRewriteSecFetchSite', () => {
  it('rewrites when referer is the auth subdomain', () => {
    expect(
      shouldRewriteSecFetchSite({
        ...BASE,
        referer: 'https://auth.pds.example/oauth/authorize?foo=bar',
      }),
    ).toBe(true)
  })

  it('rewrites when referer is absent (no referer)', () => {
    expect(shouldRewriteSecFetchSite({ ...BASE, referer: undefined })).toBe(
      true,
    )
  })

  it('rewrites when referer is the PDS itself', () => {
    expect(
      shouldRewriteSecFetchSite({
        ...BASE,
        referer: 'https://pds.example/oauth/authorize',
      }),
    ).toBe(true)
  })

  it('does NOT rewrite for an unknown same-site origin', () => {
    expect(
      shouldRewriteSecFetchSite({
        ...BASE,
        referer: 'https://evil.example/page',
      }),
    ).toBe(false)
  })

  it('does NOT rewrite when sec-fetch-site is cross-site', () => {
    expect(
      shouldRewriteSecFetchSite({ ...BASE, secFetchSite: 'cross-site' }),
    ).toBe(false)
  })

  it('does NOT rewrite when sec-fetch-site is same-origin', () => {
    expect(
      shouldRewriteSecFetchSite({ ...BASE, secFetchSite: 'same-origin' }),
    ).toBe(false)
  })

  it('does NOT rewrite when sec-fetch-site is none', () => {
    expect(shouldRewriteSecFetchSite({ ...BASE, secFetchSite: 'none' })).toBe(
      false,
    )
  })

  it('does NOT rewrite for a different path', () => {
    expect(shouldRewriteSecFetchSite({ ...BASE, path: '/oauth/token' })).toBe(
      false,
    )
  })

  it('does NOT rewrite for POST /oauth/authorize', () => {
    expect(shouldRewriteSecFetchSite({ ...BASE, method: 'POST' })).toBe(false)
  })
})
