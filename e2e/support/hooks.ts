import {
  BeforeAll,
  AfterAll,
  Before,
  After,
  Status,
  setDefaultTimeout,
} from '@cucumber/cucumber'
import { chromium, type Browser } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import type { EpdsWorld } from './world.js'
import { testEnv } from './env.js'
import { mailpitAuthHeader, clearMailpit } from './mailpit.js'

// Railway services have cold-start latency and SMTP delivery can be slow.
// Setup steps like "a returning user has already approved the demo client"
// involve multiple email waits + browser flows and need more headroom.
setDefaultTimeout(120_000)

export let sharedBrowser: Browser | undefined

BeforeAll(async function () {
  await mkdir('reports/screenshots', { recursive: true })
  sharedBrowser = await chromium.launch({ headless: testEnv.headless })

  // Wipe any emails left over from previous runs
  if (testEnv.mailpitPass) {
    await fetch(`${testEnv.mailpitUrl}/api/v1/messages`, {
      method: 'DELETE',
      headers: { Authorization: mailpitAuthHeader() },
    })
  }
})

Before(async function (this: EpdsWorld) {
  this.browser = sharedBrowser
  this.context = await sharedBrowser!.newContext()
  this.page = await this.context.newPage()
  this.page.setDefaultNavigationTimeout(30_000)
  this.page.setDefaultTimeout(15_000)
})

After(async function (this: EpdsWorld, scenario) {
  if (scenario.result?.status === Status.FAILED && this.page) {
    const safeName = scenario.pickle.name
      .replaceAll(/[^a-z0-9]+/gi, '-')
      .replaceAll(/^-|-$/g, '')
      .toLowerCase()
      .slice(0, 100)
    await this.page.screenshot({
      path: `reports/screenshots/${safeName}.png`,
      fullPage: true,
    })
  }
  if (this.context) await this.context.close()

  // Clear emails sent to this scenario's test email so they don't bleed into the next scenario
  if (testEnv.mailpitPass && this.testEmail) {
    await clearMailpit(this.testEmail)
  }
})

AfterAll(async function () {
  await sharedBrowser?.close()
})
