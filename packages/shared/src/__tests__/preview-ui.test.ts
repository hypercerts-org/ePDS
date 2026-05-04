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

  it('renders inline form controls for routes that declare them', () => {
    // /preview/choose-handle and /preview/chooser collapsed their
    // enumerated variants behind dropdowns/checkboxes that bind to
    // query params on the link's href via the wire-up script.
    const html = renderPreviewLinksSections({
      currentService: 'auth',
      authPublicUrl: AUTH_URL,
      pdsPublicUrl: PDS_URL,
    })
    // Choose-handle now renders a select bound to ?epds_handle_mode=:
    expect(html).toContain('data-preview-param="epds_handle_mode"')
    // …and a select for the error variant that used to be a separate
    // enumerated route entry:
    expect(html).toContain('data-preview-param="error"')
    expect(html).toContain('<option value="Handle already taken">')
    // pds-core's /preview/chooser declares its controls cross-origin:
    expect(html).toContain(`href="${PDS_URL}/preview/chooser"`)
    expect(html).toContain('data-preview-param="numAccounts"')
    // numAccounts must not allow 0 — the server-side handler clamps it
    // up, but the UI form should agree (otherwise users see 0 as a
    // legal value and submit something the server quietly rewrites).
    expect(html).toMatch(
      /<input[^>]*min="1"[^>]*data-preview-param="numAccounts"/,
    )
  })

  it('emits the per-service list classes so styling can be scoped to one section', () => {
    const html = renderPreviewLinksSections({
      currentService: 'auth',
      authPublicUrl: AUTH_URL,
      pdsPublicUrl: PDS_URL,
    })
    expect(html).toContain('class="preview-routes preview-routes-auth"')
    expect(html).toContain('class="preview-routes preview-routes-pds"')
  })

  it('lays each row out as a flex container so link + controls share a line', () => {
    // Locks the row layout: each <li> is a flex row whose children
    // (link, controls) sit on the same baseline. Catches regressions
    // that put controls on a separate visual line under the link.
    const html = renderPreviewIndexPage({
      currentService: 'auth',
      authPublicUrl: AUTH_URL,
      pdsPublicUrl: PDS_URL,
    })
    expect(html).toMatch(/\.preview-routes li \{[^}]*display:\s*flex/)
    expect(html).toMatch(/\.preview-routes li \{[^}]*align-items:\s*baseline/)
  })

  it('tags every link with data-preview-link so the wire-up script finds it', () => {
    const html = renderPreviewLinksSections({
      currentService: 'auth',
      authPublicUrl: AUTH_URL,
      pdsPublicUrl: PDS_URL,
    })
    // Match the bare attribute on anchors only; the controls render
    // a `data-preview-link-id` attribute that we want to exclude here.
    const count = (html.match(/data-preview-link(?!-)/g) || []).length
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
