/**
 * Step definitions for internal-api.feature.
 *
 * All scenarios are pure HTTP — no browser needed. Steps call the
 * /_internal/* endpoints on pds-core directly using the shared secret.
 *
 * Note: Scenario "PAR login hint retrieval" is tagged @manual — it requires
 * a real PKCE PAR request. Implement when PAR submission steps exist
 * (needed for login-hint-resolution.feature too).
 */

import { Given, When, Then } from '@cucumber/cucumber'
import type { EpdsWorld } from '../support/world.js'
import { callInternalApi } from '../support/utils.js'

// ---------------------------------------------------------------------------
// Background
// ---------------------------------------------------------------------------

// The internalSecret guard also prevents account-creation Givens from running
// in scenarios that require the secret — if the secret is absent the entire
// scenario is marked pending before createAccountViaOAuth is called.
Given('the internal API secret is configured', function (this: EpdsWorld) {
  return this.skipIfNoInternalSecret()
})

// ---------------------------------------------------------------------------
// Account-by-email
// ---------------------------------------------------------------------------

When(
  'the internal API is queried for the account by email',
  async function (this: EpdsWorld) {
    if (!this.testEmail)
      throw new Error('No testEmail — account creation step must run first')
    const { status, body } = await callInternalApi(
      `/_internal/account-by-email?email=${encodeURIComponent(this.testEmail)}`,
      this.env.internalSecret,
    )
    this.lastHttpStatus = status
    this.lastApiResponse = body
  },
)

Then("the response contains the account's DID", function (this: EpdsWorld) {
  if (!this.userDid)
    throw new Error('No userDid — account creation step must run first')
  if (!this.lastApiResponse)
    throw new Error('No API response — query step must run first')
  const did = this.lastApiResponse.did
  if (did !== this.userDid) {
    throw new Error(`Expected DID "${this.userDid}" but got "${String(did)}"`)
  }
})

When(
  'the internal API is queried for account-by-email with an unknown address',
  async function (this: EpdsWorld) {
    const unknown = `unknown-${Date.now()}@example.com`
    const { status, body } = await callInternalApi(
      `/_internal/account-by-email?email=${encodeURIComponent(unknown)}`,
      this.env.internalSecret,
    )
    this.lastHttpStatus = status
    this.lastApiResponse = body
  },
)

Then('the response status is 200', function (this: EpdsWorld) {
  if (this.lastHttpStatus !== 200) {
    throw new Error(
      `Expected status 200 but got ${String(this.lastHttpStatus)}`,
    )
  }
})

Then('the response body has a null DID', function (this: EpdsWorld) {
  if (!this.lastApiResponse)
    throw new Error('No API response — query step must run first')
  if (this.lastApiResponse.did !== null) {
    throw new Error(
      `Expected did to be null but got "${String(this.lastApiResponse.did)}"`,
    )
  }
})

// ---------------------------------------------------------------------------
// Account-by-handle
// ---------------------------------------------------------------------------

When(
  'the internal API is queried for the account by handle',
  async function (this: EpdsWorld) {
    if (!this.userHandle)
      throw new Error('No userHandle — account creation step must run first')
    const { status, body } = await callInternalApi(
      `/_internal/account-by-handle?handle=${encodeURIComponent(this.userHandle)}`,
      this.env.internalSecret,
    )
    this.lastHttpStatus = status
    this.lastApiResponse = body
  },
)

Then("the response contains the account's email", function (this: EpdsWorld) {
  if (!this.testEmail)
    throw new Error('No testEmail — account creation step must run first')
  if (!this.lastApiResponse)
    throw new Error('No API response — query step must run first')
  const email = this.lastApiResponse.email
  if (email !== this.testEmail) {
    throw new Error(
      `Expected email "${this.testEmail}" but got "${String(email)}"`,
    )
  }
})

// ---------------------------------------------------------------------------
// Check-handle
// ---------------------------------------------------------------------------

When(
  'the internal API is queried to check if the handle exists',
  async function (this: EpdsWorld) {
    if (!this.userHandle)
      throw new Error('No userHandle — account creation step must run first')
    const { status, body } = await callInternalApi(
      `/_internal/check-handle?handle=${encodeURIComponent(this.userHandle)}`,
      this.env.internalSecret,
    )
    this.lastHttpStatus = status
    this.lastApiResponse = body
  },
)

Then('the response indicates the handle exists', function (this: EpdsWorld) {
  if (!this.lastApiResponse)
    throw new Error('No API response — query step must run first')
  if (this.lastApiResponse.exists !== true) {
    throw new Error(
      `Expected exists to be true but got "${String(this.lastApiResponse.exists)}"`,
    )
  }
})

// ---------------------------------------------------------------------------
// Auth errors
// ---------------------------------------------------------------------------

When(
  'the check-handle endpoint is called with an incorrect secret',
  async function (this: EpdsWorld) {
    const { status, body } = await callInternalApi(
      `/_internal/check-handle?handle=somehandle.pds.test`,
      'definitely-wrong-secret',
    )
    this.lastHttpStatus = status
    this.lastApiResponse = body
  },
)

When(
  'an internal endpoint is called without the secret header',
  async function (this: EpdsWorld) {
    const { status, body } = await callInternalApi(
      `/_internal/account-by-email?email=test@example.com`,
      null,
    )
    this.lastHttpStatus = status
    this.lastApiResponse = body
  },
)

When(
  'an internal endpoint is called with an incorrect secret',
  async function (this: EpdsWorld) {
    const { status, body } = await callInternalApi(
      `/_internal/account-by-email?email=test@example.com`,
      'definitely-wrong-secret',
    )
    this.lastHttpStatus = status
    this.lastApiResponse = body
  },
)

Then('the response status is 401', function (this: EpdsWorld) {
  if (this.lastHttpStatus !== 401) {
    throw new Error(
      `Expected status 401 but got ${String(this.lastHttpStatus)}`,
    )
  }
})

Then('the response body contains an auth error', function (this: EpdsWorld) {
  if (!this.lastApiResponse)
    throw new Error('No API response — query step must run first')
  const error = this.lastApiResponse.error
  if (typeof error !== 'string' || !error) {
    throw new Error(
      `Expected response body to contain an error string but got "${String(error)}"`,
    )
  }
})

// check-handle returns 403 (not 401) on bad secret — this is an intentional
// server-side inconsistency documented in the route code
Then('the response status is 403', function (this: EpdsWorld) {
  if (this.lastHttpStatus !== 403) {
    throw new Error(
      `Expected status 403 but got ${String(this.lastHttpStatus)}`,
    )
  }
})
