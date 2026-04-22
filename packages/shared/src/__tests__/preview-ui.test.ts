import { describe, expect, it } from 'vitest'

import {
  AUTH_PREVIEW_ROUTES,
  PDS_PREVIEW_ROUTES,
  renderPreviewIndexPage,
  renderPreviewLinksSections,
} from '../preview-ui.js'

const AUTH_URL = 'https://auth.example'
const PDS_URL = 'https://pds.example'

describe('renderPreviewLinksSections', () => {
  it('renders same-origin links as path-relative when on the current service', () => {
    const html = renderPreviewLinksSections({
      currentService: 'auth',
      authPublicUrl: AUTH_URL,
      pdsPublicUrl: PDS_URL,
    })
    // First auth route is /preview/login — must appear as a relative href.
    expect(html).toContain('href="/preview/login"')
    // Sibling service's routes must be absolute on the other origin.
    expect(html).toContain(`href="${PDS_URL}/preview/consent"`)
  })

  it('swaps relative/absolute when rendered for the other service', () => {
    const html = renderPreviewLinksSections({
      currentService: 'pds',
      authPublicUrl: AUTH_URL,
      pdsPublicUrl: PDS_URL,
    })
    expect(html).toContain(`href="${AUTH_URL}/preview/login"`)
    expect(html).toContain('href="/preview/consent"')
  })

  it("marks the sibling service's heading as a link to its /preview index", () => {
    const authHtml = renderPreviewLinksSections({
      currentService: 'auth',
      authPublicUrl: AUTH_URL,
      pdsPublicUrl: PDS_URL,
    })
    // The sibling heading carries data-preview-link so the wire-up
    // script carries the current client_id across to the other service.
    expect(authHtml).toContain(
      `<a href="${PDS_URL}/preview" data-preview-link>pds-core</a>`,
    )
    expect(authHtml).toContain('<h2>auth-service</h2>')

    const pdsHtml = renderPreviewLinksSections({
      currentService: 'pds',
      authPublicUrl: AUTH_URL,
      pdsPublicUrl: PDS_URL,
    })
    expect(pdsHtml).toContain(
      `<a href="${AUTH_URL}/preview" data-preview-link>auth-service</a>`,
    )
    expect(pdsHtml).toContain('<h2>pds-core</h2>')
  })

  it('appends ?query=... to routes that declare one', () => {
    const html = renderPreviewLinksSections({
      currentService: 'auth',
      authPublicUrl: AUTH_URL,
      pdsPublicUrl: PDS_URL,
    })
    expect(html).toContain(
      'href="/preview/choose-handle?error=Handle+already+taken"',
    )
  })

  it('tags every link with data-preview-link so the wire-up script finds it', () => {
    const html = renderPreviewLinksSections({
      currentService: 'auth',
      authPublicUrl: AUTH_URL,
      pdsPublicUrl: PDS_URL,
    })
    const count = (html.match(/data-preview-link/g) || []).length
    // One per route, plus one for the sibling service's heading link.
    expect(count).toBe(
      AUTH_PREVIEW_ROUTES.length + PDS_PREVIEW_ROUTES.length + 1,
    )
  })
})

describe('renderPreviewIndexPage', () => {
  it('uses the service-specific title, heading, and sibling blurb', () => {
    const authHtml = renderPreviewIndexPage({
      currentService: 'auth',
      authPublicUrl: AUTH_URL,
      pdsPublicUrl: PDS_URL,
    })
    expect(authHtml).toContain('<title>auth-service previews</title>')
    expect(authHtml).toContain('<h1>auth-service preview routes</h1>')
    expect(authHtml).toContain('<em>pds-core</em>')

    const pdsHtml = renderPreviewIndexPage({
      currentService: 'pds',
      authPublicUrl: AUTH_URL,
      pdsPublicUrl: PDS_URL,
    })
    expect(pdsHtml).toContain('<title>pds-core previews</title>')
    expect(pdsHtml).toContain('<h1>pds-core preview routes</h1>')
    expect(pdsHtml).toContain('<em>auth-service</em>')
  })

  it('embeds the client_id input, cache-status block, and wire-up script', () => {
    const html = renderPreviewIndexPage({
      currentService: 'auth',
      authPublicUrl: AUTH_URL,
      pdsPublicUrl: PDS_URL,
    })
    expect(html).toContain('id="client-id-input"')
    expect(html).toContain('id="cache-status"')
    expect(html).toContain("var STORAGE_KEY = 'epds:preview:client_id';")
  })

  it('nests the shared links section inside the page', () => {
    const html = renderPreviewIndexPage({
      currentService: 'pds',
      authPublicUrl: AUTH_URL,
      pdsPublicUrl: PDS_URL,
    })
    // Relative pds-core link and absolute auth-service link should both
    // appear, proving the links section is wired in.
    expect(html).toContain('href="/preview/consent"')
    expect(html).toContain(`href="${AUTH_URL}/preview/login"`)
  })
})
