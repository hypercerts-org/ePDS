/**
 * The Atmosphere hand-off sends the browser to the client's
 * epds_handle_login_url with the handle, our issuer and the client's own
 * PAR state, so the client can check the hand-off belongs to a sign-in it
 * started in this browser.
 *
 * Runs the page's real inline script and inspects where it navigates.
 */
import { describe, it, expect, vi } from 'vitest'
import {
  LOGIN_PAGE_OPTIONS,
  runPageScript,
} from './__helpers__/login-page-script.js'

vi.mock('../better-auth.js', () => ({ socialProviders: {} }))

const { renderLoginPage } = await import('../routes/login-page.js')

// Deliberately unlike LOGIN_PAGE_OPTIONS.pdsPublicUrl: iss must come from
// the issuer pds-core reports, never from the public URL.
const ISSUER = 'http://pds.localhost:3000'

async function handOff(
  handleLoginUrl: string,
  handoffState: string | null,
  handoffIssuer: string | null = ISSUER,
) {
  const page = runPageScript(
    renderLoginPage({
      ...LOGIN_PAGE_OPTIONS,
      handoffState,
      handoffIssuer,
      branding: { epds_handle_login_url: handleLoginUrl },
    }),
    () => {
      throw new Error('the hand-off must not fetch')
    },
  )
  await page.elements.atprotoButton.click()
  page.elements.emailInput.value = 'alice.bsky.social'
  await page.elements.sendOtpForm.submit()
  expect(page.navigations).toHaveLength(1)
  return new URL(page.navigations[0])
}

describe('Atmosphere hand-off URL', () => {
  it('omits state when none is available, even if the client URL has one', async () => {
    const url = await handOff(
      'https://app.example.com/api/oauth/login?state=from-metadata',
      null,
    )
    expect(url.searchParams.has('state')).toBe(false)
    expect(url.searchParams.get('iss')).toBe(ISSUER)
  })

  it('omits iss instead of falling back to the public URL when no issuer is known', async () => {
    const url = await handOff(
      'https://app.example.com/api/oauth/login?iss=from-metadata',
      'st-123',
      null,
    )
    expect(url.searchParams.has('iss')).toBe(false)
  })
})
