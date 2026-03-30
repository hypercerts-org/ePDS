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

Given('the ePDS test environment is running', async function (this: EpdsWorld) {
  const res = await fetch(`${testEnv.pdsUrl}/health`)
  if (!res.ok) {
    throw new Error(
      `PDS health check failed: ${res.status} at ${testEnv.pdsUrl}/health`,
    )
  }
})

Given('a demo OAuth client is registered', async function (this: EpdsWorld) {
  const res = await fetch(`${testEnv.demoUrl}/client-metadata.json`)
  if (!res.ok) {
    throw new Error(
      `Demo client metadata not found: ${res.status} at ${testEnv.demoUrl}/client-metadata.json`,
    )
  }
  const body = (await res.json()) as Record<string, unknown>
  if (!body.client_id) {
    throw new Error('client-metadata.json is missing client_id')
  }
})

// Generic UI interaction — clicking any button by its visible label.
// Used across consent, branding, and any other feature that needs button clicks.
When(
  'the user clicks {string}',
  async function (this: EpdsWorld, label: string) {
    const page = getPage(this)
    await page.getByRole('button', { name: label }).click()
  },
)
