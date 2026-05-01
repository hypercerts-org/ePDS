import { Given, Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import { testEnv } from '../support/env.js'
import type { EpdsWorld } from '../support/world.js'
import {
  getPage,
  resetBrowserContext,
  assertDemoClientSession,
} from '../support/utils.js'
import { createAccountViaOAuth, pickHandle } from '../support/flows.js'
import { sharedBrowser } from '../support/hooks.js'
import { clearMailpit, extractOtp, waitForEmail } from '../support/mailpit.js'
import { fillOtp } from '../support/otp.js'

function getOtpAlphabet(otpCharset: 'numeric' | 'alphanumeric'): string {
  return otpCharset === 'alphanumeric'
    ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    : '0123456789'
}

function mutateOtpCode(
  otpCode: string,
  otpCharset: 'numeric' | 'alphanumeric',
): string {
  const alphabet = getOtpAlphabet(otpCharset)

  for (let i = 0; i < otpCode.length; i++) {
    const currentChar = otpCode[i].toUpperCase()
    const replacement = alphabet.split('').find((char) => char !== currentChar)
    if (!replacement) continue

    return `${otpCode.slice(0, i)}${replacement}${otpCode.slice(i + 1)}`
  }

  throw new Error('Could not derive an incorrect OTP from the current code')
}

async function buildIncorrectOtpCode(world: EpdsWorld): Promise<string> {
  if (world.otpCode) {
    const otpCharset = /^[0-9]+$/.test(world.otpCode)
      ? 'numeric'
      : 'alphanumeric'
    return mutateOtpCode(world.otpCode, otpCharset)
  }

  // When world.otpCode is not set (e.g. the OTP email step was skipped),
  // we cannot read OTP_LENGTH / OTP_CHARSET from env directly because the
  // test runner has no access to the deployed service's environment on
  // Railway. Instead, infer the config from the segmented OTP boxes that
  // the auth service renders. Length comes from the box count; charset is
  // inferred from the per-box inputmode attribute (the old hidden-input
  // path's `pattern` attribute is no longer rendered).
  const page = getPage(world)
  const boxes = page.locator('.otp-box')
  const otpLength = (await boxes.count()) || testEnv.otpLength
  const inputModeAttr = await boxes.first().getAttribute('inputmode')
  const otpCharset: 'numeric' | 'alphanumeric' =
    inputModeAttr === 'numeric' ? 'numeric' : testEnv.otpCharset

  return mutateOtpCode('0'.repeat(otpLength), otpCharset)
}

// ---------------------------------------------------------------------------
// Scenario setup — compound Givens that create accounts as test preconditions
// ---------------------------------------------------------------------------

/**
 * Creates a fresh PDS account for returning-user scenarios.
 *
 * Drives the browser through the full new-user sign-up flow via the trusted
 * demo client, then resets the browser context so the returning-user login
 * starts with a clean session (no cookies from the sign-up). The generated
 * email is stored on world.testEmail for use by subsequent steps.
 *
 * Note: because sign-up via the trusted demo goes through the
 * PDS_SIGNUP_ALLOW_CONSENT_SKIP path, setAuthorizedClient is called during
 * sign-up — so the returning login will skip the consent screen entirely
 * and land directly on /welcome. Scenarios built on top of this Given must
 * not include "the user approves the consent screen" as a step.
 */
Given('a returning user has a PDS account', async function (this: EpdsWorld) {
  if (!testEnv.mailpitPass) return 'pending'

  const email = `returning-${Date.now()}@example.com`
  await createAccountViaOAuth(this, email)

  // Reset browser context to eliminate session cookies from the sign-up
  // flow — the returning-user login must start as a fresh OAuth session
  await resetBrowserContext(this, sharedBrowser)
})

/**
 * Creates a PDS account via the trusted demo client, which records the
 * client as authorized via setAuthorizedClient as part of the sign-up
 * consent-skip flow (see packages/pds-core/src/index.ts step 5). Resets
 * the browser context afterwards so the actual test login starts fresh.
 *
 * After this step, the next login for world.testEmail will skip consent
 * entirely and land directly on /welcome — not because of any browser
 * state, but because the PDS recorded the client as authorized during
 * sign-up.
 */
Given(
  'a returning user has already approved the demo client',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'

    const email = `approved-${Date.now()}@example.com`
    await createAccountViaOAuth(this, email)
    await resetBrowserContext(this, sharedBrowser)
  },
)

// ---------------------------------------------------------------------------
// Navigation and login page assertions
// ---------------------------------------------------------------------------

When(
  'the demo client initiates an OAuth login',
  async function (this: EpdsWorld) {
    await this.page?.goto(testEnv.demoUrl)
  },
)

Then(
  'the browser is redirected to the auth service login page',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(page.locator('#email')).toBeVisible({ timeout: 10_000 })
  },
)

Then(
  'the login page displays an email input form',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(page.locator('#email')).toBeVisible()
  },
)

When(
  'the user enters {string} and submits',
  async function (this: EpdsWorld, email: string) {
    if (testEnv.mailpitPass) {
      await clearMailpit(email)
    }
    await this.page?.fill('#email', email)
    await this.page?.click('button[type=submit]')
    await this.page?.waitForLoadState('networkidle')
  },
)

When(
  'the user enters a unique test email and submits',
  async function (this: EpdsWorld) {
    this.testEmail = `test-${Date.now()}@example.com`
    if (testEnv.mailpitPass) {
      await clearMailpit(this.testEmail)
    }
    await this.page?.fill('#email', this.testEmail)
    await this.page?.click('button[type=submit]')
    await this.page?.waitForLoadState('networkidle')
  },
)

When(
  'the user enters the test email on the login page',
  async function (this: EpdsWorld) {
    if (!this.testEmail) {
      throw new Error(
        'No test email set — "a returning user has a PDS account" step must run first',
      )
    }
    if (testEnv.mailpitPass) {
      await clearMailpit(this.testEmail)
    }
    await this.page?.fill('#email', this.testEmail)
    await this.page?.click('button[type=submit]')
    await this.page?.waitForLoadState('networkidle')
  },
)

When('the user approves the consent screen', async function (this: EpdsWorld) {
  const page = getPage(this)
  await expect(page.getByRole('button', { name: 'Authorize' })).toBeVisible({
    timeout: 30_000,
  })
  await page.getByRole('button', { name: 'Authorize' }).click()
})

// ---------------------------------------------------------------------------
// OTP form
// ---------------------------------------------------------------------------

Then(
  'the login page shows an OTP verification form',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(page.locator('#step-otp.active')).toBeVisible({
      timeout: 30_000,
    })
  },
)

When('the user enters the OTP code', async function (this: EpdsWorld) {
  if (!testEnv.mailpitPass) return 'pending'
  if (!this.otpCode)
    throw new Error('No OTP code available — email step must run first')
  const page = getPage(this)
  await fillOtp(page, this.otpCode)
})

/**
 * Drives the /auth/choose-handle page shown to new users after OTP
 * verification when the auth service is running in picker mode (the default).
 * In random-handle mode (@handle-random) the user is redirected past this
 * page and this step is not used.
 */
When('the user picks a handle', async function (this: EpdsWorld) {
  if (!testEnv.mailpitPass) return 'pending'
  await pickHandle(this)
})

// ---------------------------------------------------------------------------
// Post-login assertions
// ---------------------------------------------------------------------------

Then(
  'the browser is redirected back to the demo client',
  async function (this: EpdsWorld) {
    await this.page?.waitForURL('**/welcome', { timeout: 30_000 })
  },
)

Then(
  "the demo client's welcome page confirms the user is signed in",
  async function (this: EpdsWorld) {
    await assertDemoClientSession(this)
  },
)

Then(
  'the demo client has a valid OAuth access token',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(page.locator('body')).toContainText('did:')
  },
)

// ---------------------------------------------------------------------------
// OTP brute-force / error scenarios
// ---------------------------------------------------------------------------

When(
  'the user requests an OTP for {string}',
  async function (this: EpdsWorld, email: string) {
    if (!testEnv.mailpitPass) return 'pending'
    const page = getPage(this)
    await page.goto(testEnv.demoUrl)
    await page.fill('#email', email)
    await clearMailpit(email)
    await page.click('button[type=submit]')
    await page.waitForLoadState('networkidle')
    await expect(page.locator('#step-otp.active')).toBeVisible({
      timeout: 30_000,
    })
  },
)

When(
  'the user requests an OTP for the test email',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.testEmail) {
      throw new Error(
        'No test email set — "a returning user has a PDS account" step must run first',
      )
    }
    const page = getPage(this)
    await page.goto(testEnv.demoUrl)
    await page.fill('#email', this.testEmail)
    // Clear messages from any prior welcome/sign-in email for this recipient
    // so the next waitForEmail consumes the fresh OTP from this request.
    await clearMailpit(this.testEmail)
    await page.click('button[type=submit]')
    await page.waitForLoadState('networkidle')
    await expect(page.locator('#step-otp.active')).toBeVisible({
      timeout: 30_000,
    })
  },
)

When(
  'the user requests an OTP for a unique test email',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    const page = getPage(this)
    this.testEmail = `test-${Date.now()}@example.com`
    await page.goto(testEnv.demoUrl)
    await page.fill('#email', this.testEmail)
    await clearMailpit(this.testEmail)
    await page.click('button[type=submit]')
    await page.waitForLoadState('networkidle')
    await expect(page.locator('#step-otp.active')).toBeVisible({
      timeout: 30_000,
    })
  },
)

When('enters an incorrect OTP code', async function (this: EpdsWorld) {
  const page = getPage(this)
  const wrongOtp = await buildIncorrectOtpCode(this)

  await fillOtp(page, wrongOtp)
})

When(
  'enters an incorrect OTP code {int} times',
  async function (this: EpdsWorld, times: number) {
    const page = getPage(this)
    const wrongOtp = await buildIncorrectOtpCode(this)

    for (let i = 0; i < times; i++) {
      // Register the response listener BEFORE filling: the page auto-submits
      // on the 6th digit, so the request fires from inside fillOtp.
      const responsePromise = page.waitForResponse(
        (response) =>
          response.request().method() === 'POST' &&
          response.url().includes('/sign-in/email-otp'),
        { timeout: 10_000 },
      )
      await fillOtp(page, wrongOtp)
      await responsePromise
      // Wait for the failed state after each submit so the flow remains stable
      // and we do not race into the next attempt.
      await expect(page.locator('#error-msg')).toBeVisible({ timeout: 10_000 })
    }
  },
)

Then(
  'the verification form shows an error message',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(page.locator('#error-msg')).toBeVisible()
  },
)

Then('the user can try again', async function (this: EpdsWorld) {
  const page = getPage(this)
  await expect(page.locator('.otp-box').first()).toBeEnabled()
})

Then('further attempts are rejected', async function (this: EpdsWorld) {
  const page = getPage(this)
  await expect(page.locator('#error-msg')).toBeVisible()
})

Then('the user must request a new OTP', async function (this: EpdsWorld) {
  const page = getPage(this)
  await expect(page.locator('#btn-resend')).toBeVisible()
})

// ---------------------------------------------------------------------------
// OTP expiry scenario
// ---------------------------------------------------------------------------
//
// Simulates the user taking longer than 10 minutes between requesting
// the OTP and entering it. To reproduce the real-world failure mode
// faithfully (auth-service issue: even after Resend, /auth/complete
// returns "Authentication session expired") we have to age out THREE
// things in lockstep, all of which expire after 10 minutes in
// production:
//
//   1. The better-auth verification row (the OTP itself) — backdated
//      via POST /_internal/test/expire-otp.
//   2. The auth_flow row in the auth-service SQLite — backdated via
//      POST /_internal/test/expire-auth-flow.
//   3. The epds_auth_flow cookie in the browser — Playwright doesn't
//      let us forge an expiry timestamp on an existing cookie, so we
//      delete it outright. Functionally equivalent for the bug we're
//      reproducing: the browser presents no auth_flow cookie to
//      /auth/complete.
//
// Both /_internal/test/* hooks are gated by EPDS_TEST_HOOKS=1 on the
// server and authenticated with EPDS_INTERNAL_SECRET on the client.

async function callExpiryHook(
  hookPath: string,
  email: string,
  body: Record<string, unknown>,
): Promise<{ updated: number }> {
  const url = `${testEnv.authUrl}${hookPath}`
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-internal-secret': testEnv.internalSecret,
    },
    body: JSON.stringify({ email, ...body }),
    signal: AbortSignal.timeout(10_000),
  })
  if (!res.ok) {
    const errBody = await res.text().catch(() => '')
    throw new Error(
      `${hookPath} hook failed: ${res.status} ${res.statusText}: ${errBody}`,
    )
  }
  const data = (await res.json().catch(() => ({}))) as { updated?: number }
  return { updated: data.updated ?? 0 }
}

When(
  'more than 10 minutes pass before the user enters the OTP',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!testEnv.internalSecret) return 'pending'
    if (!this.testEmail) {
      throw new Error(
        'No test email set — the email-submit step must run first',
      )
    }

    // Expire only the better-auth OTP row. The auth_flow row + cookie
    // both have a 60-minute TTL (see lib/auth-flow.ts) and so MUST still
    // be alive at the 10-minute mark — that is the fix this scenario is
    // regression-testing. Aging them out here would falsify the
    // post-fix scenario: after Resend the new OTP completes, and
    // /auth/complete must still find the original auth_flow.
    const otpResult = await callExpiryHook(
      '/_internal/test/expire-otp',
      this.testEmail,
      { type: 'sign-in' },
    )
    if (otpResult.updated < 1) {
      throw new Error(
        `expire-otp hook reported no rows updated for ${this.testEmail} — was an OTP actually sent first?`,
      )
    }
  },
)

Then(
  'the verification form shows an {string} error',
  async function (this: EpdsWorld, expected: string) {
    const page = getPage(this)
    await expect(page.locator('#error-msg')).toBeVisible({ timeout: 10_000 })
    await expect(page.locator('#error-msg')).toHaveText(expected, {
      timeout: 10_000,
    })
  },
)

When(
  'the user requests a new OTP via the resend button',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.testEmail) {
      throw new Error(
        'No test email set — the email-submit step must run first',
      )
    }
    const page = getPage(this)
    // Clear the inbox so the next "OTP arrived" wait pulls the fresh
    // resend rather than the original (now-expired) message.
    await clearMailpit(this.testEmail)
    // Forget the stale code so a misuse before the new email arrives
    // surfaces as a clear "no OTP available" error rather than
    // re-submitting the expired one.
    this.otpCode = undefined
    await page.click('#btn-resend')
  },
)

Then(
  'a fresh OTP email arrives in the mail trap for the test email',
  async function (this: EpdsWorld) {
    // Distinct phrasing from the existing "an OTP email arrives ..."
    // step in email.steps.ts so cucumber doesn't see a duplicate
    // definition. The wait itself is the same — pull the next OTP
    // from mailpit and stash it on the world for later submission.
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.testEmail) {
      throw new Error(
        'No test email set — the email-submit step must run first',
      )
    }
    const message = await waitForEmail(`to:${this.testEmail}`)
    this.lastEmailSubject = message.Subject
    this.otpCode = await extractOtp(message.ID)
  },
)

// ---------------------------------------------------------------------------
// Refresh / idempotency scenario
// ---------------------------------------------------------------------------

When(
  'the demo client redirects to the auth service login page',
  async function (this: EpdsWorld) {
    await this.page?.goto(testEnv.demoUrl)
  },
)

When(
  'the user refreshes the page \\(duplicate GET \\/oauth\\/authorize\\)',
  async function (this: EpdsWorld) {
    await this.page?.reload()
  },
)

Then('the login page renders normally', async function (this: EpdsWorld) {
  const page = getPage(this)
  await expect(page.locator('#email')).toBeVisible()
})

Then('the OTP flow still works to completion', function (this: EpdsWorld) {
  return this.skipIfNoMailpit()
})

// ---------------------------------------------------------------------------
// PAR (request_uri) expiry scenario
// ---------------------------------------------------------------------------
//
// The PAR record lives in pds-core's @atproto/oauth-provider store
// (authorization_request table) and is independent of the auth-service
// auth_flow row. Upstream hardcodes PAR_EXPIRES_IN = 5 min, so a user
// who takes >5 min between requesting and submitting the OTP (slow
// inbox, switching tabs, multiple Resend cycles) trips
// "AccessDeniedError: This request has expired" inside
// /oauth/epds-callback even though all auth-service-side state is
// healthy. PAR expiry is genuine: once expired, the row cannot be
// revived — RequestManager.get() throws AND deletes the row in the
// same call, so any "ping" mechanism is too late.
//
// The fix is to honour RFC 6749 §4.1.2.1 and surface the failure as
// a redirect back to the client's redirect_uri with error,
// error_description, iss, and state query params. To reproduce
// without a 5-minute wall-clock wait, a pds-core test-only hook
// (mounted iff EPDS_TEST_HOOKS=1, double-gated by
// EPDS_INTERNAL_SECRET and a NODE_ENV=production refusal) deletes
// the PAR row directly:
//
//   POST /_internal/test/delete-par   { request_uri }

async function callPdsExpiryHook(
  hookPath: string,
  requestUri: string,
): Promise<void> {
  const url = `${testEnv.pdsUrl}${hookPath}`
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-internal-secret': testEnv.internalSecret,
    },
    body: JSON.stringify({ request_uri: requestUri }),
    signal: AbortSignal.timeout(10_000),
  })
  if (!res.ok) {
    const errBody = await res.text().catch(() => '')
    throw new Error(
      `${hookPath} hook failed: ${res.status} ${res.statusText}: ${errBody}`,
    )
  }
}

/**
 * Read the PAR request_uri from the current auth-service login page
 * URL and stash it on the world for subsequent expiry hooks. The URL
 * is `https://<auth>/oauth/authorize?request_uri=urn:...&...` while the
 * user is on the login/OTP form. Throws if the URL doesn't carry it,
 * which means the surrounding scenario is mis-ordered (the page must
 * be on the auth-service side before this step runs).
 */
function captureRequestUriFromPage(world: EpdsWorld): string {
  const page = getPage(world)
  const requestUri = new URL(page.url()).searchParams.get('request_uri')
  if (!requestUri) {
    throw new Error(
      `Expected request_uri in page URL but found none: ${page.url()}`,
    )
  }
  world.lastRequestUri = requestUri
  return requestUri
}

When(
  'the PAR request_uri has expired before the bridge fires',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!testEnv.internalSecret) return 'pending'
    const requestUri = captureRequestUriFromPage(this)
    await callPdsExpiryHook('/_internal/test/delete-par', requestUri)
  },
)

Then('the response body is not raw JSON', async function (this: EpdsWorld) {
  const page = getPage(this)
  // The OTP form's submit is JS-driven and async, and Playwright's
  // fill() returns before the bridge redirects. Wait for the
  // browser to actually leave the auth-service host and arrive at
  // pds-core's epds-callback (where, in this scenario, the
  // catch-block renders the error page). Without this wait we'd
  // read the still-rendering OTP form's body.
  const pdsHost = new URL(testEnv.pdsUrl).host
  await page.waitForURL(
    (url) => url.host === pdsHost && url.pathname.includes('epds-callback'),
    { timeout: 30_000 },
  )
  const body = await page.locator('body').innerText()
  // The pre-fix behaviour returned a body that started with
  // {"error": "Authentication failed"}. A graceful HTML page won't —
  // its <h1>/<p> text isn't valid JSON. The regex catches any
  // {"error": ...} shape so a future leak of a different JSON
  // payload is still caught.
  if (/^\s*\{\s*"error"/.test(body)) {
    throw new Error(
      `pds-core leaked raw JSON to the browser: ${body.slice(0, 200)}`,
    )
  }
})

Then(
  'the response body explains that sign-in timed out',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    const body = await page.locator('body').innerText()
    // Don't pin exact wording — just require something that mentions
    // the timeout / expiry so a human reading it understands why
    // their sign-in failed.
    if (!/expir|timed? ?out|too long/i.test(body)) {
      throw new Error(
        `Error page should mention the timeout but said: "${body.slice(0, 500)}"`,
      )
    }
  },
)
