/**
 * Infrastructure-level step definitions shared across all feature files.
 *
 * This file contains only environment/health-check Givens and generic UI
 * interaction steps. Scenario-specific setup steps live in the step file
 * for their feature area (e.g. auth.steps.ts).
 */

import { Given, When } from '@cucumber/cucumber'
import type { EpdsWorld } from '../support/world.js'
import { testEnv } from '../support/env.js'
import { getPage } from '../support/utils.js'

/**
 * Health-check the PDS with a short retry budget. The CI workflow already
 * polls /health for 5 minutes before invoking the e2e suite, so any
 * failure here is *post* deploy-readiness — typically a transient Railway
 * edge / undici DNS blip that resolves in seconds. Without retries, a
 * single such blip on the first scenario fails an entire 9-minute e2e
 * run; with retries, the rest of the suite runs unimpaired.
 *
 * Each attempt has its own AbortSignal.timeout(2s) so a hung connection
 * cannot blow past the documented wall-clock budget of 6 × (2s fetch +
 * 2s backoff) = ~24s. Real outages still surface — the suite cannot make
 * meaningful progress past this Given without a live PDS, so a hard
 * failure is the right outcome once the budget is spent.
 */
Given('the ePDS test environment is running', async function (this: EpdsWorld) {
  const url = `${testEnv.pdsUrl}/health`
  const maxAttempts = 6
  const perAttemptTimeoutMs = 2000
  const backoffMs = 2000
  let lastErr: unknown
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetch(url, {
        signal: AbortSignal.timeout(perAttemptTimeoutMs),
      })
      if (res.ok) return
      lastErr = new Error(`PDS health check failed: ${res.status} at ${url}`)
    } catch (err) {
      lastErr = err
    }
    if (attempt < maxAttempts) {
      await new Promise((resolve) => setTimeout(resolve, backoffMs))
    }
  }
  throw new Error(
    `PDS health check failed after ${maxAttempts} attempts at ${url}: ${
      lastErr instanceof Error ? lastErr.message : String(lastErr)
    }`,
  )
})

/**
 * Verifies that a demo client's OAuth client-metadata document is fetchable
 * and structurally valid (contains a `client_id` field). In atproto OAuth
 * there's no explicit "registration" step: a client is known to the PDS
 * purely by virtue of its metadata URL being discoverable at fetch time,
 * so this step is a startup health check, not a side-effectful setup.
 */
async function assertClientMetadataDiscoverable(
  baseUrl: string,
  label: string,
): Promise<void> {
  const url = `${baseUrl}/client-metadata.json`
  const res = await fetch(url)
  if (!res.ok) {
    throw new Error(
      `${label} client-metadata.json not discoverable: ${res.status} at ${url}`,
    )
  }
  const body = (await res.json()) as Record<string, unknown>
  if (!body.client_id) {
    throw new Error(`${label} client-metadata.json is missing client_id`)
  }
}

Given(
  "the demo OAuth client's metadata is discoverable",
  async function (this: EpdsWorld) {
    await assertClientMetadataDiscoverable(testEnv.demoUrl, 'demo')
  },
)

Given(
  "the trusted demo OAuth client's metadata is discoverable",
  async function (this: EpdsWorld) {
    await assertClientMetadataDiscoverable(
      testEnv.demoTrustedUrl,
      'trusted demo',
    )
  },
)

Given(
  "the untrusted demo OAuth client's metadata is discoverable",
  async function (this: EpdsWorld) {
    // Defence-in-depth for --name invocations: normally scenarios
    // that reach this Given are tagged @untrusted-client and are
    // already excluded by cucumber.mjs when E2E_DEMO_UNTRUSTED_URL
    // is unset, but a user running `--name "..."` bypasses tag
    // exclusions entirely.
    if (!testEnv.demoUntrustedUrl) return 'pending'
    await assertClientMetadataDiscoverable(
      testEnv.demoUntrustedUrl,
      'untrusted demo',
    )
  },
)

// Generic UI interaction — clicking any button by its visible label.
// Used across consent, branding, and any other feature that needs button clicks.
When(
  'the user clicks {string}',
  async function (this: EpdsWorld, label: string) {
    const page = getPage(this)
    await page.getByRole('button', { name: label }).click()
  },
)
