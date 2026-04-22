import { When, Then } from '@cucumber/cucumber'
import type { EpdsWorld } from '../support/world.js'
import { testEnv } from '../support/env.js'

// Cucumber Expressions treat `/` as an alternation separator.
// Use String.raw so `\/` reaches Cucumber as a literal escaped slash.

// -- /health (ePDS version) --

When(
  String.raw`the PDS \/health endpoint is queried`,
  async function (this: EpdsWorld) {
    const res = await fetch(`${testEnv.pdsUrl}/health`)
    this.lastHttpStatus = res.status
    this.lastHttpJson = (await res.json()) as Record<string, unknown>
  },
)

Then(
  'the response contains an ePDS version string',
  function (this: EpdsWorld) {
    const { version } = this.lastHttpJson as { version?: string }
    if (!version || typeof version !== 'string') {
      throw new Error(
        `/health response is missing "version": ${JSON.stringify(this.lastHttpJson)}`,
      )
    }
    // Expect semver, optionally with +sha suffix (e.g. "0.2.2" or "0.2.2+f37823ee")
    if (!/^\d+\.\d+\.\d+/.test(version)) {
      throw new Error(
        `/health version does not start with semver: "${version}"`,
      )
    }
  },
)

// -- auth service /health (ePDS version) --

When(
  String.raw`the auth service \/health endpoint is queried`,
  async function (this: EpdsWorld) {
    const res = await fetch(`${testEnv.authUrl}/health`)
    this.lastHttpStatus = res.status
    this.lastHttpJson = (await res.json()) as Record<string, unknown>
  },
)

// -- /xrpc/_health (upstream @atproto/pds version) --

When(
  String.raw`the PDS \/xrpc\/_health endpoint is queried`,
  async function (this: EpdsWorld) {
    const res = await fetch(`${testEnv.pdsUrl}/xrpc/_health`)
    this.lastHttpStatus = res.status
    this.lastHttpJson = (await res.json()) as Record<string, unknown>
  },
)

Then(
  'the response contains an upstream PDS version string',
  function (this: EpdsWorld) {
    const { version } = this.lastHttpJson as { version?: string }
    if (!version || typeof version !== 'string') {
      throw new Error(
        `/xrpc/_health response is missing "version": ${JSON.stringify(this.lastHttpJson)}`,
      )
    }
    if (!/^\d+\.\d+\.\d+/.test(version)) {
      throw new Error(
        `/xrpc/_health version does not start with semver: "${version}"`,
      )
    }
  },
)
