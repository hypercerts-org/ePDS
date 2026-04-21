/**
 * Step definitions for security.feature. These scenarios run direct HTTP
 * requests (no browser) because they assert on response headers, status
 * codes, and raw HTML — not user interaction.
 */

import { When, Then } from '@cucumber/cucumber'
import type { DataTable } from '@cucumber/cucumber'
import type { EpdsWorld } from '../support/world.js'
import { testEnv } from '../support/env.js'

/** Response captured by the most recent direct-fetch step. */
interface CapturedResponse {
  status: number
  headers: Headers
  body: string
}

const capturedBySymbol = new WeakMap<EpdsWorld, CapturedResponse>()

function setCapturedResponse(
  world: EpdsWorld,
  response: CapturedResponse,
): void {
  capturedBySymbol.set(world, response)
  world.lastHttpStatus = response.status
}

function getCapturedResponse(world: EpdsWorld): CapturedResponse {
  const captured = capturedBySymbol.get(world)
  if (!captured) {
    throw new Error('No response has been captured by a prior step')
  }
  return captured
}

async function captureGet(
  world: EpdsWorld,
  url: string,
  init?: RequestInit,
): Promise<void> {
  const res = await fetch(url, { redirect: 'manual', ...init })
  const body = await res.text()
  setCapturedResponse(world, { status: res.status, headers: res.headers, body })
}

// ---------------------------------------------------------------------------
// CSRF scenarios
// ---------------------------------------------------------------------------

When('the recovery page is loaded', async function (this: EpdsWorld) {
  const recoveryUrl = `${testEnv.authUrl}/auth/recover?request_uri=urn:ietf:params:oauth:request_uri:req-security-probe`
  await captureGet(this, recoveryUrl)
})

Then('the response sets a CSRF cookie', function (this: EpdsWorld) {
  const { headers } = getCapturedResponse(this)
  // `headers.get('set-cookie')` collapses multiple Set-Cookie values
  // into a single comma-separated string in the Fetch API, which is
  // ambiguous because cookie values may themselves contain commas
  // (e.g. Expires=Thu, 01 Jan …). Use Headers.getSetCookie() (Node
  // >=18) to get each cookie as its own entry.
  const setCookies = headers.getSetCookie()
  if (!setCookies.some((cookie) => /^epds_csrf=/.test(cookie))) {
    throw new Error(
      `Expected Set-Cookie to include epds_csrf=..., got: ${setCookies.join(', ') || '(none)'}`,
    )
  }
})

Then(
  'the HTML form contains a hidden CSRF token field',
  function (this: EpdsWorld) {
    const { body } = getCapturedResponse(this)
    if (!/<input[^>]*type="hidden"[^>]*name="csrf"[^>]*>/.test(body)) {
      throw new Error('HTML response has no hidden CSRF input field')
    }
  },
)

When(
  'a POST request is sent to the recovery endpoint without a CSRF token',
  async function (this: EpdsWorld) {
    const res = await fetch(`${testEnv.authUrl}/auth/recover`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        request_uri: 'urn:ietf:params:oauth:request_uri:req-security-probe',
        email: 'noone@example.com',
      }).toString(),
      redirect: 'manual',
    })
    const body = await res.text()
    setCapturedResponse(this, {
      status: res.status,
      headers: res.headers,
      body,
    })
  },
)

Then('the response status is {int}', function (this: EpdsWorld, code: number) {
  const { status } = getCapturedResponse(this)
  if (status !== code) {
    throw new Error(`Expected status ${code}, got ${status}`)
  }
})

// ---------------------------------------------------------------------------
// Security headers scenario
// ---------------------------------------------------------------------------

When(
  'any page is loaded from the auth service',
  async function (this: EpdsWorld) {
    await captureGet(this, `${testEnv.authUrl}/health`)
  },
)

Then(
  'the response includes the following security headers:',
  function (this: EpdsWorld, table: DataTable) {
    const { headers } = getCapturedResponse(this)
    const missing: string[] = []
    for (const row of table.hashes()) {
      const expected = row.value
      const actual = headers.get(row.header)
      if (actual !== expected) {
        missing.push(
          `${row.header}: expected "${expected}", got "${actual ?? '(missing)'}"`,
        )
      }
    }
    if (missing.length) {
      throw new Error(`Security header mismatch:\n  ${missing.join('\n  ')}`)
    }
  },
)

// ---------------------------------------------------------------------------
// CSP scenario
// ---------------------------------------------------------------------------

When('the login page is loaded', async function (this: EpdsWorld) {
  // /oauth/authorize on the PDS renders the auth-service login page via
  // the epds-callback redirect chain, but hitting it without a valid
  // request_uri triggers an error response before headers are set the
  // way we want. The auth service exposes a preview route that renders
  // the same login template, guarded by AUTH_PREVIEW_ROUTES. If preview
  // is off, fall back to a probe of any auth-service page — the CSP
  // header is applied globally by the security-headers middleware, so
  // an auth-service /health response carries the same header.
  const previewUrl = `${testEnv.authUrl}/preview/login`
  let res = await fetch(previewUrl, { redirect: 'manual' })
  if (res.status === 404) {
    res = await fetch(`${testEnv.authUrl}/health`, { redirect: 'manual' })
  }
  const body = await res.text()
  setCapturedResponse(this, { status: res.status, headers: res.headers, body })
})

Then(
  'the Content-Security-Policy header is present',
  function (this: EpdsWorld) {
    const { headers } = getCapturedResponse(this)
    if (!headers.get('content-security-policy')) {
      throw new Error('Content-Security-Policy header is not set')
    }
  },
)

function getScriptSrcDirective(csp: string): string {
  const match = /(?:^|;\s*)script-src\s+([^;]+)/.exec(csp)
  if (!match) {
    throw new Error(`CSP is missing a script-src directive: "${csp}"`)
  }
  return match[1].trim()
}

Then(
  'the script-src directive does not allow unsafe-inline',
  function (this: EpdsWorld) {
    const { headers } = getCapturedResponse(this)
    const csp = headers.get('content-security-policy') ?? ''
    const scriptSrc = getScriptSrcDirective(csp)
    if (/'unsafe-inline'/.test(scriptSrc)) {
      throw new Error(
        `script-src directive allows 'unsafe-inline': "${scriptSrc}"`,
      )
    }
  },
)

function extractScriptSrcNonce(csp: string): string {
  const scriptSrc = getScriptSrcDirective(csp)
  const match = /'nonce-([A-Za-z0-9_-]+)'/.exec(scriptSrc)
  if (!match) {
    throw new Error(`script-src directive has no 'nonce-...': "${scriptSrc}"`)
  }
  return match[1]
}

Then(
  'the script-src directive carries a per-response nonce',
  async function (this: EpdsWorld) {
    // Assert two things: (a) the current response has a nonce-shaped
    // token in script-src, and (b) the nonce is freshly generated per
    // response — otherwise a hardcoded constant would pass (a) but
    // defeat the whole point of a CSP nonce. Hit the same endpoint a
    // second time and compare.
    const { headers } = getCapturedResponse(this)
    const firstCsp = headers.get('content-security-policy') ?? ''
    const firstNonce = extractScriptSrcNonce(firstCsp)

    const previewUrl = `${testEnv.authUrl}/preview/login`
    let second = await fetch(previewUrl, { redirect: 'manual' })
    if (second.status === 404) {
      second = await fetch(`${testEnv.authUrl}/health`, { redirect: 'manual' })
    }
    const secondCsp = second.headers.get('content-security-policy') ?? ''
    const secondNonce = extractScriptSrcNonce(secondCsp)
    if (firstNonce === secondNonce) {
      throw new Error(
        `CSP nonce reused across responses: "${firstNonce}" — expected a fresh nonce per request`,
      )
    }
  },
)

// ---------------------------------------------------------------------------
// Metrics scenario
// ---------------------------------------------------------------------------

When(
  'GET \\/metrics is called on the auth service without credentials',
  async function (this: EpdsWorld) {
    await captureGet(this, `${testEnv.authUrl}/metrics`)
  },
)
