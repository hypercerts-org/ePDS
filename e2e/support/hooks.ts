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

Before(async function (this: EpdsWorld, scenario) {
  this.browser = sharedBrowser
  this.context = await sharedBrowser!.newContext()
  this.page = await this.context.newPage()
  this.page.setDefaultNavigationTimeout(30_000)
  this.page.setDefaultTimeout(15_000)
  // Capture browser console + page errors per scenario for post-mortem
  // debugging. Stream is reattached by resetBrowserContext so a context
  // reset mid-scenario doesn't lose further messages.
  const { createWriteStream } = await import('node:fs')
  const { attachConsoleCapture } = await import('./utils.js')
  const safeName = scenario.pickle.name
    .replaceAll(/[^a-z0-9]+/gi, '-')
    .replaceAll(/^-|-$/g, '')
    .toLowerCase()
    .slice(0, 100)
  this.consoleCapture = createWriteStream(
    `reports/screenshots/${safeName}.console.log`,
    { flags: 'w' },
  )
  attachConsoleCapture(this.page, this.consoleCapture)
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
    try {
      const { writeFile } = await import('node:fs/promises')
      const content = await this.page.content()
      await writeFile(`reports/screenshots/${safeName}.html`, content)
    } catch (err) {
      // Best-effort: if page.content() or writeFile fails (closed context,
      // disk error), log but don't fail the already-failing scenario.
      console.warn(
        `After hook: failed to capture page HTML for "${safeName}":`,
        err,
      )
    }
  }
  if (this.secondaryContext) await this.secondaryContext.close()
  if (this.context) await this.context.close()

  // Close the per-scenario console-capture stream so file descriptors
  // don't leak across a long run and buffered output is flushed to
  // disk before the next scenario starts. resetBrowserContext
  // re-attaches THIS same stream to the new Page (see utils.ts) rather
  // than creating a new one, so there is only ever one stream per
  // scenario to close here.
  const consoleCapture = this.consoleCapture
  this.consoleCapture = undefined
  if (consoleCapture) {
    await new Promise<void>((resolve) => consoleCapture.end(resolve))
  }

  // Clear emails sent to this scenario's test email so they don't bleed into the next scenario
  if (testEnv.mailpitPass && this.testEmail) {
    try {
      await clearMailpit(this.testEmail)
    } catch (err) {
      // Cleanup failure should not fail a passing scenario — log and move on
      console.warn(
        `After hook: clearMailpit cleanup failed for ${this.testEmail}:`,
        err,
      )
    }
  }
})

AfterAll(async function () {
  await sharedBrowser?.close()
})
