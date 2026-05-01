/**
 * Step definitions for features/session-reuse-bugs.feature — the
 * auth-ui-guard scenarios. See docs/design/session-reuse-bugs.md for the
 * full failure-mode taxonomy.
 *
 * These steps exercise the pre-route guard in pds-core that intercepts
 * /oauth/authorize and /account* before upstream's signin handler can
 * render its authentication UIs (stock welcome page or sign-in-view).
 * The guard bounces to auth-service when:
 *   - the dev-id/ses-id cookie pair is missing or malformed
 *   - the cookie pair resolves to a device with zero bound accounts
 *   - the stored PAR forces re-authentication (prompt contains 'login')
 *   - every relevant binding's auth age exceeds 7 days
 *
 * All scenarios require a docker-compose topology where auth-service is a
 * sibling subdomain of pds-core so device-session cookies are domain-scoped
 * on the shared parent. Tagged @docker-only for this reason.
 */

import { Given, Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import type { EpdsWorld } from '../support/world.js'
import { testEnv } from '../support/env.js'
import { getPage } from '../support/utils.js'
import { createAccountViaOAuth, pickHandle } from '../support/flows.js'
import { sharedBrowser } from '../support/hooks.js'
import { clearMailpit, extractOtp, waitForEmail } from '../support/mailpit.js'
import { fillOtp } from '../support/otp.js'

// ---------------------------------------------------------------------------
// Background: returning user completes an OAuth sign-in, leaving valid
// dev-id + ses-id cookies on the browser.
// ---------------------------------------------------------------------------

/**
 * After "a returning user has a PDS account" the account exists in the DB
 * but the browser context has been reset — dev-id/ses-id cookies are gone.
 * Drive a returning-user sign-in so upstream sets a fresh device-session
 * cookie pair on the jar without any other side effects. Mirrors the
 * pattern used by session-reuse.steps.ts's returning-session Given.
 */
Given(
  'the user has completed one OAuth sign-in from the demo client',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.testEmail) {
      const email = `reuse-${Date.now()}@example.com`
      await createAccountViaOAuth(this, email)
      return
    }
    const page = getPage(this)
    const email = this.testEmail
    await clearMailpit(email)
    await page.goto(testEnv.demoTrustedUrl)
    await page.fill('#email', email)
    await page.click('button[type=submit]')
    await expect(page.locator('#step-otp.active')).toBeVisible({
      timeout: 30_000,
    })
    const message = await waitForEmail(`to:${email}`)
    const otp = await extractOtp(message.ID)
    await fillOtp(page, otp)
    await page.waitForURL('**/welcome', { timeout: 30_000 })
    await clearMailpit(email)
  },
)

Given(
  'the browser holds a valid dev-id and ses-id cookie pair',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    const cookies = await page.context().cookies()
    const devId = cookies.find((c) => c.name === 'dev-id')
    const sesId = cookies.find((c) => c.name === 'ses-id')
    expect(
      devId?.value,
      'dev-id cookie missing after OAuth sign-in — background set-up did not leave a device session on the jar',
    ).toBeTruthy()
    expect(
      sesId?.value,
      'ses-id cookie missing after OAuth sign-in — background set-up did not leave a device session on the jar',
    ).toBeTruthy()
  },
)

// ---------------------------------------------------------------------------
// Cookie-manipulation steps: eviction and substitution
// ---------------------------------------------------------------------------

async function evictCookie(world: EpdsWorld, name: string): Promise<void> {
  const page = getPage(world)
  const ctx = page.context()
  const all = await ctx.cookies()
  const keep = all.filter((c) => c.name !== name)
  await ctx.clearCookies()
  await ctx.addCookies(keep)
}

Given(
  'the ses-id cookie has been evicted from the browser',
  async function (this: EpdsWorld) {
    await evictCookie(this, 'ses-id')
  },
)

Given(
  'the dev-id cookie has been evicted from the browser',
  async function (this: EpdsWorld) {
    await evictCookie(this, 'dev-id')
  },
)

/** A well-formed but server-unknown cookie value: right prefix, right hex
 *  length per upstream's Zod schema, but never issued by this pds-core. */
const UNKNOWN_DEV_ID = 'dev-0123456789abcdef0123456789abcdef'
const UNKNOWN_SES_ID = 'ses-fedcba9876543210fedcba9876543210'

async function replaceCookie(
  world: EpdsWorld,
  name: string,
  value: string,
): Promise<void> {
  const page = getPage(world)
  const ctx = page.context()
  const all = await ctx.cookies()
  const target = all.find((c) => c.name === name)
  if (!target) {
    throw new Error(
      `Cannot replace cookie ${name} — it is not present on the browser jar. ` +
        'A prior Given should have established a valid cookie pair first.',
    )
  }
  const kept = all.filter((c) => c.name !== name)
  await ctx.clearCookies()
  await ctx.addCookies([...kept, { ...target, value }])
}

Given(
  'the dev-id cookie has been replaced with a well-formed but server-unknown value',
  async function (this: EpdsWorld) {
    await replaceCookie(this, 'dev-id', UNKNOWN_DEV_ID)
  },
)

Given(
  'the ses-id cookie has been replaced with a well-formed but server-unknown value',
  async function (this: EpdsWorld) {
    await replaceCookie(this, 'ses-id', UNKNOWN_SES_ID)
  },
)

Given(
  'the dev-id and ses-id cookies have been replaced with well-formed but server-unknown values',
  async function (this: EpdsWorld) {
    await replaceCookie(this, 'dev-id', UNKNOWN_DEV_ID)
    await replaceCookie(this, 'ses-id', UNKNOWN_SES_ID)
  },
)

// ---------------------------------------------------------------------------
// Trigger: start a fresh OAuth flow
// ---------------------------------------------------------------------------

When(
  'the demo client starts a new OAuth flow',
  async function (this: EpdsWorld) {
    // flow2 is the chooser-eligible variant: no login_hint, just a plain
    // "Sign in" button that posts to /api/oauth/login -> /oauth/authorize.
    // This is the flow that would have rendered the stock welcome page
    // pre-fix for every empty-device case.
    const page = getPage(this)
    const base = testEnv.demoTrustedUrl.replace(/\/$/, '')
    await page.goto(`${base}/flow2`)
    await page.click('button[type=submit]')
  },
)

When(
  "the demo client starts a new OAuth flow with the test user's handle as login_hint",
  async function (this: EpdsWorld) {
    if (!this.userHandle) {
      throw new Error(
        'world.userHandle missing — Background step must run first',
      )
    }
    // Hits /api/oauth/login directly (the demo home form swallows query
    // params). login_hint=<handle> exercises the Flow 1 hint-vs-bindings
    // gate on the matching path: the resolved email IS in the device's
    // bound list, so session reuse stays enabled and the chooser wins.
    // Cookies are preserved (no resetBrowserContext) because the whole
    // point is to test the existing device session.
    const page = getPage(this)
    const url = new URL('/api/oauth/login', testEnv.demoUrl)
    url.searchParams.set('login_hint', this.userHandle)
    await page.goto(url.toString())
  },
)

When(
  "the demo client starts a new OAuth flow with the test user's handle as a PAR-body login_hint",
  async function (this: EpdsWorld) {
    if (!this.userHandle) {
      throw new Error(
        'world.userHandle missing — Background step must run first',
      )
    }
    // login_hint_location=body puts the hint in the PAR body rather than the
    // /oauth/authorize redirect URL — this matches the third-party
    // OAuth-client pattern that drives upstream's matchesHint logic against
    // `parameters.login_hint` from the stored PAR. Without this, upstream's
    // request-manager-loaded parameters carry no hint and the guard's
    // hint-narrowed bounce condition can never fire — filterCandidateBindings
    // would see every binding as a candidate, not just the stale one.
    const page = getPage(this)
    const url = new URL('/api/oauth/login', testEnv.demoUrl)
    url.searchParams.set('login_hint', this.userHandle)
    url.searchParams.set('login_hint_location', 'body')
    await page.goto(url.toString())
  },
)

Given(
  'another user has a separate PDS account',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!sharedBrowser) throw new Error('sharedBrowser is not initialised')

    // Create the second account in an isolated browser context so the
    // primary user's dev-id/ses-id cookies (set by the Background's
    // returning-user sign-in) survive untouched. Closing the context at
    // the end discards the second account's cookies, so the upcoming
    // hint-mismatch step navigates with ONLY the primary user bound to
    // the device — exactly the state the Flow 1 hint-vs-bindings gate
    // is meant to detect.
    const otherEmail = `flow1-other-${Date.now()}@example.com`
    const isolated = await sharedBrowser.newContext({
      userAgent: `e2e-other-user-${Date.now()}`,
    })
    const isolatedPage = await isolated.newPage()
    isolatedPage.setDefaultNavigationTimeout(30_000)
    isolatedPage.setDefaultTimeout(15_000)

    // createAccountViaOAuth reads/writes world.page and world.testEmail /
    // userDid / userHandle. Save and restore those so the primary user's
    // identity stays canonical on the world.
    const savedPage = this.page
    const savedContext = this.context
    const savedEmail = this.testEmail
    const savedDid = this.userDid
    const savedHandle = this.userHandle
    this.page = isolatedPage
    this.context = isolated
    try {
      const { did, handle } = await createAccountViaOAuth(this, otherEmail)
      this.otherUserEmail = otherEmail
      this.otherUserDid = did
      this.otherUserHandle = handle
      if (!handle) {
        throw new Error(
          'createAccountViaOAuth did not yield a handle for the second user',
        )
      }
    } finally {
      this.page = savedPage
      this.context = savedContext
      this.testEmail = savedEmail
      this.userDid = savedDid
      this.userHandle = savedHandle
      await isolated.close()
    }
  },
)

When(
  "the demo client starts a new OAuth flow with the other user's handle as login_hint",
  async function (this: EpdsWorld) {
    if (!this.otherUserHandle) {
      throw new Error(
        'world.otherUserHandle missing — "another user has a separate PDS account" step must run first',
      )
    }
    // Hits /api/oauth/login on the primary context. The primary device's
    // dev-id/ses-id cookies are still set (from the Background sign-in),
    // but login_hint resolves to the OTHER user's email — the gate must
    // skip session reuse and surface the email/OTP form.
    const page = getPage(this)
    const url = new URL('/api/oauth/login', testEnv.demoUrl)
    url.searchParams.set('login_hint', this.otherUserHandle)
    await page.goto(url.toString())
  },
)

Then(
  "the OTP form will submit the other user's email",
  async function (this: EpdsWorld) {
    if (!this.otherUserEmail) {
      throw new Error(
        'world.otherUserEmail missing — "another user has a separate PDS account" step must run first',
      )
    }
    // #otp-email is a hidden input — the resolved email rides along on
    // the OTP submit so the verify endpoint matches the right account.
    // Asserting on it (rather than the auth-host alone) proves the
    // auth-service skipped the chooser AND resolved the hinted handle
    // to the right account before rendering OTP.
    const page = getPage(this)
    const value = await page.locator('#otp-email').getAttribute('value')
    expect(value).toBe(this.otherUserEmail)
    const url = new URL(page.url())
    const authHost = new URL(testEnv.authUrl).host
    expect(url.host).toBe(authHost)
  },
)

When(
  'the demo client starts a new OAuth flow with random handle mode',
  async function (this: EpdsWorld) {
    // flow3 forwards handle_mode=random through to auth-service, which
    // carries epds_handle_mode=random in the /oauth/authorize query that
    // pds-core's chooser middleware reads to inject
    // <meta name="epds-handle-mode" content="random"> into the chooser's
    // <head>. The enrichment script reads that meta and hides the handle
    // span (display:none on .epds-handle-label, title= on
    // .epds-email-label) without touching the DB or the account's actual
    // stored handle.
    const page = getPage(this)
    const base = testEnv.demoTrustedUrl.replace(/\/$/, '')
    await page.goto(`${base}/flow3`)
    await page.click('button[type=submit]')
  },
)

// ---------------------------------------------------------------------------
// Assertions on landing page
// ---------------------------------------------------------------------------

Then(
  'the browser lands on the ePDS enriched account picker',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await page.waitForLoadState('networkidle', { timeout: 30_000 })
    const url = new URL(page.url())
    const pdsHost = new URL(testEnv.pdsUrl).host
    expect(
      url.host,
      `Enriched chooser should be served from ${pdsHost} but browser is on ${url.host}. URL: ${page.url()}`,
    ).toBe(pdsHost)
    await expect(page.locator('#root')).toBeAttached({ timeout: 10_000 })
    const html = await page.content()
    expect(
      html.includes('__deviceSessions') || html.includes('__sessions'),
      `Expected chooser hydration data on ${page.url()} but did not find it.`,
    ).toBe(true)
  },
)

Then(
  'the browser lands on the auth-service email-and-OTP form',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    // Wait for one of the auth-service login-page steps to be visible.
    // initialStep is 'email' on no-hint flows and 'otp' when a login_hint
    // resolves to an email — both land on the same login-page route, just
    // with a different step displayed initially. Either is a valid "lands
    // on the login page" outcome; the assertion is "we're on auth-service,
    // not pds-core".
    await expect(
      page.locator('#step-email:not(.hidden), #step-otp.active'),
    ).toBeVisible({ timeout: 30_000 })
    const url = new URL(page.url())
    const authHost = new URL(testEnv.authUrl).host
    expect(
      url.host,
      `Expected auth-service host ${authHost} but got ${url.host}`,
    ).toBe(authHost)
  },
)

Then(
  'no upstream "Sign up" affordance is visible on the chooser',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    // ePDS has not wired upstream's signup flow (account creation goes
    // through auth-service's OTP path), so upstream's chooser-rendered
    // "Sign up" button must be hidden by chooser-enrichment.
    await expect(
      page.getByRole('button', { name: 'Sign up', exact: true }),
    ).toHaveCount(0)
    await expect(
      page.getByRole('link', { name: 'Sign up', exact: true }),
    ).toHaveCount(0)
  },
)

// ---------------------------------------------------------------------------
// Random-handle-mode assertions on the enriched chooser (Layer 4 coverage)
// ---------------------------------------------------------------------------

Then(
  'the enriched account picker renders without the handle visible',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    // The enrichment script marks the original handle span with
    // .epds-handle-label and, when the flow resolves to random mode,
    // sets display:none on it. Wait for at least one row's email label
    // to appear (a signal that the script has run) before asserting the
    // handle is hidden — otherwise we race the MutationObserver.
    await expect(page.locator('.epds-email-label').first()).toBeVisible({
      timeout: 10_000,
    })
    const handleLabels = page.locator('.epds-handle-label')
    await expect(handleLabels.first()).toBeAttached()
    const count = await handleLabels.count()
    for (let i = 0; i < count; i++) {
      await expect(handleLabels.nth(i)).not.toBeVisible()
    }
  },
)

Then(
  'each row exposes the handle only via a title tooltip',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    // The script copies the hidden handle span's text into a title=
    // attribute on the adjacent .epds-email-label so power-users can
    // still inspect which account maps to which DID without the
    // gibberish random handle cluttering the visual hierarchy.
    const emailLabels = page.locator('.epds-email-label')
    const count = await emailLabels.count()
    expect(count).toBeGreaterThan(0)
    for (let i = 0; i < count; i++) {
      const title = await emailLabels.nth(i).getAttribute('title')
      const titleRepr = title === null ? 'null' : `"${title}"`
      expect(
        title,
        `Row ${i}: expected .epds-email-label to carry the hidden handle as title=, got ${titleRepr}`,
      ).toBeTruthy()
      expect(title!.trim().length).toBeGreaterThan(0)
    }
  },
)

Then(
  'the email remains visible as the primary identifier',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    if (!this.testEmail) {
      throw new Error(
        'world.testEmail missing — Background step must have set it via createAccountViaOAuth',
      )
    }
    // Assert at least one row's email label renders the test email as
    // visible text. Random mode hides the handle; the email must remain
    // the user-facing identifier on each row.
    const emailLabel = page
      .locator('.epds-email-label')
      .filter({ hasText: this.testEmail })
    await expect(emailLabel.first()).toBeVisible({ timeout: 5_000 })
  },
)

// ---------------------------------------------------------------------------
// Post-bounce cookie-clearing assertions
// ---------------------------------------------------------------------------

async function assertCookieCleared(
  world: EpdsWorld,
  name: string,
): Promise<void> {
  const page = getPage(world)
  const cookies = await page.context().cookies()
  const match = cookies.find((c) => c.name === name)
  expect(
    match,
    `Expected ${name} cookie to be cleared after the bounce but it is still present with value=${match?.value}`,
  ).toBeUndefined()
}

Then(
  'the response clears the dev-id and ses-id cookies',
  async function (this: EpdsWorld) {
    await assertCookieCleared(this, 'dev-id')
    await assertCookieCleared(this, 'ses-id')
  },
)

// ---------------------------------------------------------------------------
// "Another account" escape hatch from the enriched chooser (Layer 3 coverage)
// ---------------------------------------------------------------------------

Given(
  'the browser holds cookies for a device with at least one bound account',
  async function (this: EpdsWorld) {
    // Equivalent to "valid dev-id/ses-id pair" — the background already
    // establishes this via createAccountViaOAuth which leaves a bound
    // account in the DB. Delegate to the existing assertion.
    const page = getPage(this)
    const cookies = await page.context().cookies()
    const devId = cookies.find((c) => c.name === 'dev-id')
    const sesId = cookies.find((c) => c.name === 'ses-id')
    expect(devId?.value).toBeTruthy()
    expect(sesId?.value).toBeTruthy()
  },
)

When(
  'the user clicks "Another account" on the enriched account picker',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await page
      .getByRole('button', { name: 'Login to account that is not listed' })
      .click()
  },
)

// ---------------------------------------------------------------------------
// Stale host-only cookies surviving from sessions predating PR #103
// (GitHub issue #116).
//
// Pre-PR-#103 sign-ins set dev-id/ses-id host-only on the pds-core host.
// A long-time user's jar still holds those entries indefinitely — and
// post-PR-#103, the host-only stale pair shadows everything because the
// `cookie` package's parse() keeps the first occurrence per name and
// per RFC 6265 host-only comes first in the Cookie header.
//
// These helpers establish the affected-user starting state directly:
// only the host-only stale pair exists, no Domain-scoped pair, no live
// device session in the DB. We unconditionally clear the cookie jar
// first so the step works whether the preceding Background left it
// empty (e.g. "a returning user has a PDS account" resets the context)
// or populated (e.g. "the user has completed one OAuth sign-in" left
// a fresh Domain-scoped pair). The post-plant assertions then prove
// only the host-only entries we placed are present.
// ---------------------------------------------------------------------------

const STALE_HOST_ONLY_DEV_ID = 'dev-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
const STALE_HOST_ONLY_SES_ID = 'ses-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'

Given(
  'the browser jar holds only a stale host-only dev-id and ses-id pair',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    const ctx = page.context()
    const pdsHost = new URL(testEnv.pdsUrl).host

    // Wipe any cookies a preceding Background step deposited. The
    // affected-user starting state has nothing on the jar except the
    // stale host-only pair; if the Background ran "the user has
    // completed one OAuth sign-in" first, there'd be a fresh
    // Domain-scoped pair to remove.
    await ctx.clearCookies()

    // Playwright's cookie API treats `domain` without a leading dot as
    // host-only — exactly the scope an upstream-set cookie used pre-PR-#103.
    await ctx.addCookies([
      {
        name: 'dev-id',
        value: STALE_HOST_ONLY_DEV_ID,
        domain: pdsHost,
        path: '/',
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
      },
      {
        name: 'ses-id',
        value: STALE_HOST_ONLY_SES_ID,
        domain: pdsHost,
        path: '/',
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
      },
    ])

    // Sanity-check: the jar should now hold exactly one dev-id and one
    // ses-id, both host-only. If something else is there (a leftover
    // Domain-scoped pair from a previous scenario, etc.) we want a clear
    // failure here rather than a confusing assertion downstream.
    const all = await ctx.cookies()
    const devEntries = all.filter((c) => c.name === 'dev-id')
    const sesEntries = all.filter((c) => c.name === 'ses-id')
    expect(
      devEntries.length,
      `Expected exactly 1 dev-id entry (host-only stale) after planting, got ${devEntries.length}: ${JSON.stringify(devEntries)}`,
    ).toBe(1)
    expect(
      sesEntries.length,
      `Expected exactly 1 ses-id entry (host-only stale) after planting, got ${sesEntries.length}: ${JSON.stringify(sesEntries)}`,
    ).toBe(1)
    expect(
      devEntries[0].domain,
      `dev-id should be host-only on ${pdsHost} but Playwright reports domain=${devEntries[0].domain}`,
    ).toBe(pdsHost)
    expect(
      sesEntries[0].domain,
      `ses-id should be host-only on ${pdsHost} but Playwright reports domain=${sesEntries[0].domain}`,
    ).toBe(pdsHost)
  },
)

// ---------------------------------------------------------------------------
// Sign-in-view leaks. Distinct from the welcome-page leaks above: cookies
// and bindings are valid, but every binding upstream would consider has
// `loginRequired: true`, so upstream falls through to its sign-in-view
// (handle + password form). ePDS accounts are passwordless, so any path
// into that form is unusable. The guard must bounce these to auth-service
// for a fresh OTP round.
// ---------------------------------------------------------------------------

When(
  'the demo client starts a new OAuth flow with prompt=login',
  async function (this: EpdsWorld) {
    // /api/oauth/login on the demo accepts ?prompt=login and propagates
    // it to BOTH the PAR body AND the authorize-URL query string
    // (packages/demo/src/app/api/oauth/login/route.ts:146,162).
    // Cookies are preserved (the device must already be bound from the
    // Background) so once the auth-service-side OTP completes and the
    // pds-core epds-callback redirects back to /oauth/authorize, the
    // stored PAR still carries `prompt=login` — the trigger this scenario
    // exercises.
    const page = getPage(this)
    const url = new URL('/api/oauth/login', testEnv.demoUrl)
    url.searchParams.set('prompt', 'login')
    await page.goto(url.toString())
  },
)

// Backdate `account_device.updated_at` past upstream's authenticationMaxAge
// (7d) via a pds-core /_internal/test hook gated on EPDS_TEST_HOOKS=1. The
// hook accepts a target DID and optional deviceId; omitting deviceId
// backdates every device row for that DID (sufficient when the device has
// only one binding; the multi-account-device scenario passes both did and
// deviceId for surgical targeting).
async function expireDeviceAccount(opts: {
  did: string
  deviceId?: string
}): Promise<void> {
  if (!testEnv.internalSecret) {
    throw new Error(
      'E2E_INTERNAL_SECRET is unset — cannot call /_internal/test/expire-device-account',
    )
  }
  const url = new URL('/_internal/test/expire-device-account', testEnv.pdsUrl)
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-internal-secret': testEnv.internalSecret,
    },
    body: JSON.stringify(opts),
  })
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`expire-device-account hook failed: ${res.status} ${body}`)
  }
}

Given(
  "the device's account_device row has been backdated past 7 days",
  async function (this: EpdsWorld) {
    if (!this.userDid) {
      throw new Error('world.userDid missing — Background step must run first')
    }
    await expireDeviceAccount({ did: this.userDid })
  },
)

Given('the device has two bound accounts', async function (this: EpdsWorld) {
  if (!testEnv.mailpitPass) return 'pending'
  if (!this.userDid) {
    throw new Error('world.userDid missing — Background step must run first')
  }
  // Drive a second OAuth sign-in within the SAME browser context (no
  // resetBrowserContext — the dev-id/ses-id cookies from the Background
  // sign-in must survive). accountManager.upsertDeviceAccount(deviceId, sub)
  // on the existing dev-id then binds the new account to the same device
  // row, leaving the first binding intact.
  //
  // Identity extraction matches createAccountViaOAuth's regex pattern
  // (e2e/support/flows.ts:165-173) — kept inline rather than reusing
  // that helper because it writes to world.userDid/userHandle/testEmail
  // which we explicitly do NOT want to clobber here.
  const page = getPage(this)
  const otherEmail = `row9-other-${Date.now()}@example.com`
  await page.goto(testEnv.demoTrustedUrl)
  await page.fill('#email', otherEmail)
  await page.click('button[type=submit]')
  await expect(page.locator('#step-otp.active')).toBeVisible({
    timeout: 30_000,
  })
  const message = await waitForEmail(`to:${otherEmail}`)
  const otp = await extractOtp(message.ID)
  await fillOtp(page, otp)
  await pickHandle(this)
  await page.waitForURL('**/welcome', { timeout: 30_000 })

  const bodyText = await page.locator('body').innerText()
  const didMatch = /did:[a-z0-9:]+/i.exec(bodyText)
  if (!didMatch) {
    throw new Error('Could not find DID on welcome page for second user')
  }
  const handleMatch = /@([\w.-]+)/.exec(bodyText)
  this.otherUserEmail = otherEmail
  this.otherUserDid = didMatch[0]
  this.otherUserHandle = handleMatch ? handleMatch[1] : undefined
})

Given(
  "the test user's account_device row has been backdated past 7 days",
  async function (this: EpdsWorld) {
    if (!this.userDid) {
      throw new Error('world.userDid missing — Background step must run first')
    }
    await expireDeviceAccount({ did: this.userDid })
  },
)

Given(
  "the other user's account_device row is fresh",
  function (this: EpdsWorld) {
    // No-op: the second sign-in driven by "the device has two bound
    // accounts" leaves the other user's updatedAt at "now". This step
    // exists to make the precondition explicit in the feature file.
    if (!this.otherUserDid) {
      throw new Error(
        'world.otherUserDid missing — "the device has two bound accounts" step must run first',
      )
    }
  },
)
