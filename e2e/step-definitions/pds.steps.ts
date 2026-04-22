/**
 * Step definitions for automatic-account-creation.feature.
 *
 * Covers PDS-level assertions that don't require an access token:
 *   - Creating a new account via the OAuth flow (shared Given)
 *   - Asserting DID + handle on the welcome page
 *   - Resolving a handle via the public resolveHandle XRPC endpoint
 *   - Asserting handle subdomain format and HTTPS reachability
 *   - Asserting that password-based createSession is rejected
 */

import { Given, When, Then } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import type { EpdsWorld } from '../support/world.js'
import { testEnv } from '../support/env.js'
import { getPage } from '../support/utils.js'
import { createAccountViaOAuth } from '../support/flows.js'

/**
 * Shared Given used by all automatic-account-creation scenarios.
 * Drives a full new-user OAuth sign-up with a unique email and stores
 * world.userDid and world.userHandle for subsequent steps.
 */
Given(
  'a new user has registered via the demo client',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    const email = `new-${Date.now()}@example.com`
    await createAccountViaOAuth(this, email)
  },
)

Then(
  "the welcome page shows the user's DID and handle",
  async function (this: EpdsWorld) {
    if (!this.userDid)
      throw new Error('No userDid — account creation step must run first')
    if (!this.userHandle)
      throw new Error('No userHandle — account creation step must run first')
    const page = getPage(this)
    await expect(page.locator('body')).toContainText(this.userDid)
    await expect(page.locator('body')).toContainText(this.userHandle)
  },
)

Then(
  'the handle is a short alphanumeric subdomain of the PDS domain',
  function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.userHandle)
      throw new Error('No userHandle — account creation step must run first')
    const pdsDomain = new URL(testEnv.pdsUrl).hostname
    // Handle must be <short-alphanumeric>.<pds-domain>
    const pattern = new RegExp(
      `^[a-z0-9]{4,20}\\.${pdsDomain.replace(/\./g, '\\.')}$`,
    )
    if (!pattern.test(this.userHandle)) {
      throw new Error(
        `Handle "${this.userHandle}" does not match expected pattern *.<pdsDomain> (${pdsDomain})`,
      )
    }
  },
)

Then(
  'the handle resolves to the correct DID via the PDS',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.userHandle)
      throw new Error('No userHandle — account creation step must run first')
    if (!this.userDid)
      throw new Error('No userDid — account creation step must run first')
    const url = `${testEnv.pdsUrl}/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(this.userHandle)}`
    const res = await fetch(url)
    if (!res.ok) {
      throw new Error(
        `resolveHandle failed: ${res.status} for handle "${this.userHandle}"`,
      )
    }
    const body = (await res.json()) as { did?: string }
    if (body.did !== this.userDid) {
      throw new Error(
        `resolveHandle returned DID "${body.did}" but expected "${this.userDid}"`,
      )
    }
  },
)

Then(
  'the handle subdomain resolves via HTTPS',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.userHandle)
      throw new Error('No userHandle — account creation step must run first')
    if (!this.userDid)
      throw new Error('No userDid — account creation step must run first')
    // /.well-known/atproto-did is served by pds-core for every valid handle subdomain
    const url = `https://${this.userHandle}/.well-known/atproto-did`
    const res = await fetch(url)
    if (!res.ok) {
      throw new Error(`HTTPS check failed for "${url}": ${res.status}`)
    }
    const text = (await res.text()).trim()
    const expectedDid = this.userDid.trim()
    if (text !== expectedDid) {
      throw new Error(
        `Expected DID "${expectedDid}" at ${url} but got: "${text}"`,
      )
    }
  },
)

When(
  'someone attempts createSession with any password',
  async function (this: EpdsWorld) {
    if (!this.userDid)
      throw new Error('No userDid — account creation step must run first')
    // Try to authenticate using the DID as the identifier and a random password.
    // Auto-created accounts have no usable password so this must fail.
    const res = await fetch(
      `${testEnv.pdsUrl}/xrpc/com.atproto.server.createSession`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identifier: this.userDid,
          password: 'definitely-not-the-password',
        }),
      },
    )
    const body = (await res.json()) as Record<string, unknown>
    this.lastHttpStatus = res.status
    this.lastHttpJson = body
  },
)

Then(
  'the createSession request fails with an auth error',
  function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    const status = this.lastHttpStatus
    const body = this.lastHttpJson
    if (!status)
      throw new Error('No HTTP status — createSession step must run first')
    if (!body)
      throw new Error('No HTTP JSON body — createSession step must run first')
    if (status !== 401) {
      throw new Error(
        `Expected createSession to fail with 401 but got status ${status}`,
      )
    }

    const error = body.error
    if (error !== 'AuthenticationRequired') {
      throw new Error(
        `Expected error "AuthenticationRequired" but got "${String(error)}"`,
      )
    }

    const message = body.message
    if (message !== 'Invalid identifier or password') {
      throw new Error(
        `Expected message "Invalid identifier or password" but got "${String(message)}"`,
      )
    }
  },
)
