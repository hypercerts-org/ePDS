/**
 * Step definitions for account-settings.feature authentication scenarios.
 */

import * as crypto from 'node:crypto'

import { Given, Then, When } from '@cucumber/cucumber'
import { expect } from '@playwright/test'
import type { Page } from '@playwright/test'
import { testEnv } from '../support/env.js'
import { extractOtp, waitForEmail } from '../support/mailpit.js'
import type { EpdsWorld } from '../support/world.js'
import { getPage } from '../support/utils.js'
import { createAccountViaOAuth } from '../support/flows.js'
import { sharedBrowser } from '../support/hooks.js'

function escapeForRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function getPdsDomain(): string {
  return new URL(testEnv.pdsUrl).hostname
}

function assertHandleIsRandomSubdomain(handle: string): void {
  const pdsDomain = getPdsDomain()
  const pattern = new RegExp(
    `^[a-z0-9]{4,20}\\.${pdsDomain.replace(/\./g, '\\.')}$`,
  )
  if (!pattern.test(handle)) {
    throw new Error(
      `Handle "${handle}" does not match expected pattern *.<pdsDomain> (${pdsDomain})`,
    )
  }
}

function generateHandleLocalPart(length = 10): string {
  const bytes = crypto.randomBytes(length)
  return Array.from(bytes, (byte) => (byte % 36).toString(36)).join('')
}

function getSessionsSection(page: Page) {
  return page.locator('section', {
    has: page.getByRole('heading', { name: 'Active Sessions' }),
  })
}

function getSessionRows(page: Page) {
  return getSessionsSection(page).locator('.setting-row')
}

async function assertPdsAccountMissing(did: string): Promise<void> {
  const res = await fetch(
    `${testEnv.pdsUrl}/xrpc/com.atproto.repo.describeRepo?repo=${encodeURIComponent(did)}`,
  )
  if (res.ok) {
    throw new Error(
      `Expected repo to be missing for DID "${did}" but describeRepo returned ${res.status}`,
    )
  }
}

async function assertGetSessionFails(did: string): Promise<void> {
  const res = await fetch(
    `${testEnv.pdsUrl}/xrpc/com.atproto.server.getSession`,
    {
      headers: {
        Authorization: `Bearer ${did}`,
      },
    },
  )
  if (res.ok) {
    throw new Error(
      `Expected getSession to fail for DID "${did}" but got ${res.status}`,
    )
  }
}

async function assertOnAccountSettingsPage(world: EpdsWorld): Promise<void> {
  const page = getPage(world)
  const authBase = escapeForRegex(testEnv.authUrl)
  await expect(page).toHaveURL(new RegExp(`^${authBase}/account(\\?.*)?$`))
}

async function completeAccountSettingsOtpLogin(
  world: EpdsWorld,
): Promise<void> {
  if (!world.testEmail) {
    throw new Error(
      'No test email set — "a returning user has a PDS account" step must run first',
    )
  }

  const page = getPage(world)

  await page.fill('#email', world.testEmail)
  await page.getByRole('button', { name: 'Continue with email' }).click()
  await expect(page.locator('#otp')).toBeVisible({ timeout: 30_000 })

  const message = await waitForEmail(`to:${world.testEmail}`)
  const otp = await extractOtp(message.ID)
  await page.fill('#otp', otp)
  await page.getByRole('button', { name: 'Verify' }).click()
}

async function resetContext(world: EpdsWorld): Promise<void> {
  await world.context?.close()
  if (!sharedBrowser) throw new Error('sharedBrowser is not initialised')
  world.context = await sharedBrowser.newContext()
  world.page = await world.context.newPage()
  world.page.setDefaultNavigationTimeout(30_000)
  world.page.setDefaultTimeout(15_000)
}

Given(
  'the user is logged into account settings',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'

    const email = `account-settings-${Date.now()}@example.com`
    await createAccountViaOAuth(this, email)

    await resetContext(this)

    const page = getPage(this)
    await page.goto(`${testEnv.authUrl}/account`)
    await completeAccountSettingsOtpLogin(this)
    await assertOnAccountSettingsPage(this)
  },
)

When(
  /^a user navigates to \/account without a session$/,
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await page.goto(`${testEnv.authUrl}/account`)
  },
)

When(
  'the user enters their email and verifies the OTP',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    await completeAccountSettingsOtpLogin(this)
  },
)

Then(
  /^the browser is redirected to \/account$/,
  async function (this: EpdsWorld) {
    await assertOnAccountSettingsPage(this)
  },
)

Then(
  /^the browser is redirected to \/account\/login$/,
  async function (this: EpdsWorld) {
    const page = getPage(this)
    const authBase = escapeForRegex(testEnv.authUrl)
    await expect(page).toHaveURL(
      new RegExp(`^${authBase}/account/login(\\?.*)?$`),
    )
  },
)

When(
  /^the user navigates to \/account\/login$/,
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await page.goto(`${testEnv.authUrl}/account/login`)
  },
)

When(/^they view the \/account page$/, async function (this: EpdsWorld) {
  const page = getPage(this)
  await page.goto(`${testEnv.authUrl}/account`)
})

Then(
  /^a login form is displayed \(separate from the OAuth flow\)$/,
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(
      page.getByRole('heading', { name: 'Account Settings' }),
    ).toBeVisible()
    await expect(
      page.getByText('Sign in to manage your account', { exact: true }),
    ).toBeVisible()
    await expect(page.locator('#email')).toBeVisible()
    await expect(
      page.getByRole('button', { name: 'Continue with email' }),
    ).toBeVisible()
  },
)

Then(
  'the account settings dashboard is displayed',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await expect(
      page.getByRole('heading', { name: 'Account Settings' }),
    ).toBeVisible()
    await expect(
      page.locator('.setting-row', { hasText: 'DID:' }),
    ).toBeVisible()
    await expect(
      page.locator('.setting-row', { hasText: 'Primary Email:' }),
    ).toBeVisible()
  },
)

Then('the page displays their DID', async function (this: EpdsWorld) {
  if (!this.userDid) {
    throw new Error(
      'No DID available — "a returning user has a PDS account" step must run first',
    )
  }

  const page = getPage(this)
  const didRow = page.locator('.setting-row', { hasText: 'DID:' })
  await expect(didRow).toContainText(this.userDid)
})

Then('the page displays their primary email', async function (this: EpdsWorld) {
  if (!this.testEmail) {
    throw new Error(
      'No test email set — "a returning user has a PDS account" step must run first',
    )
  }

  const page = getPage(this)
  const emailRow = page.locator('.setting-row', { hasText: 'Primary Email:' })
  await expect(emailRow).toContainText(this.testEmail.toLowerCase())
})

Then(
  'the page displays their current handle',
  async function (this: EpdsWorld) {
    if (!this.userHandle) {
      throw new Error(
        'No userHandle — "a returning user has a PDS account" step must run first',
      )
    }

    const page = getPage(this)
    const handleRow = page.locator('.setting-row', {
      hasText: 'Current Handle:',
    })
    await expect(handleRow).toContainText(this.userHandle)
  },
)

Then(
  'their current handle is a random subdomain of the PDS domain',
  function (this: EpdsWorld) {
    if (!this.userHandle) {
      throw new Error(
        'No userHandle — "a returning user has a PDS account" step must run first',
      )
    }

    assertHandleIsRandomSubdomain(this.userHandle)
  },
)

When('the user submits a valid new handle', async function (this: EpdsWorld) {
  if (!this.userHandle) {
    throw new Error(
      'No userHandle — "a returning user has a PDS account" step must run first',
    )
  }

  const page = getPage(this)
  const currentLocalPart = this.userHandle.split('.')[0] ?? ''
  let localPart = generateHandleLocalPart()
  if (localPart === currentLocalPart) {
    localPart = generateHandleLocalPart(12)
  }

  this.updatedHandleLocalPart = localPart
  this.updatedHandle = `${localPart}.${getPdsDomain()}`

  await page.fill('input[name="handle"]', localPart)
  const authBase = escapeForRegex(testEnv.authUrl)
  await Promise.all([
    page.waitForURL(new RegExp(`^${authBase}/account(\\?.*)?$`)),
    page.getByRole('button', { name: 'Update' }).click(),
  ])
})

Then("the user's handle is updated", function (this: EpdsWorld) {
  if (!this.userHandle) {
    throw new Error(
      'No userHandle — "a returning user has a PDS account" step must run first',
    )
  }
  if (!this.updatedHandle) {
    throw new Error('No updatedHandle — handle update step must run first')
  }

  if (this.updatedHandle === this.userHandle) {
    throw new Error('Updated handle matches the original handle')
  }

  this.userHandle = this.updatedHandle
})

Then(
  'the settings page reflects the updated handle',
  async function (this: EpdsWorld) {
    if (!this.updatedHandle) {
      throw new Error('No updatedHandle — handle update step must run first')
    }

    await assertOnAccountSettingsPage(this)
    const page = getPage(this)
    const handleRow = page.locator('.setting-row', {
      hasText: 'Current Handle:',
    })
    await expect(handleRow).toContainText(this.updatedHandle)
  },
)

Then(
  "the updated handle resolves to the user's DID via the PDS",
  async function (this: EpdsWorld) {
    if (!this.updatedHandle) {
      throw new Error('No updatedHandle — handle update step must run first')
    }
    if (!this.userDid) {
      throw new Error(
        'No userDid — "a returning user has a PDS account" step must run first',
      )
    }

    const url = `${testEnv.pdsUrl}/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(
      this.updatedHandle,
    )}`
    const res = await fetch(url)
    if (!res.ok) {
      throw new Error(
        `resolveHandle failed: ${res.status} for handle "${this.updatedHandle}"`,
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

Given(
  'the user has at least one other active session',
  async function (this: EpdsWorld) {
    if (!testEnv.mailpitPass) return 'pending'
    if (!this.testEmail) {
      throw new Error(
        'No test email set — "the user is logged into account settings" step must run first',
      )
    }
    if (!sharedBrowser) throw new Error('sharedBrowser is not initialised')

    const secondarySessionAgent = `e2e-secondary-session-${Date.now()}`
    this.secondarySessionAgent = secondarySessionAgent
    this.secondaryContext = await sharedBrowser.newContext({
      userAgent: secondarySessionAgent,
    })
    this.secondaryPage = await this.secondaryContext.newPage()
    this.secondaryPage.setDefaultNavigationTimeout(30_000)
    this.secondaryPage.setDefaultTimeout(15_000)

    const originalPage = this.page
    this.page = this.secondaryPage
    try {
      await this.secondaryPage.goto(`${testEnv.authUrl}/account`)
      await completeAccountSettingsOtpLogin(this)
      await assertOnAccountSettingsPage(this)
    } finally {
      this.page = originalPage
    }
  },
)

When('the user views the sessions section', async function (this: EpdsWorld) {
  const page = getPage(this)
  await assertOnAccountSettingsPage(this)

  const sessionsSection = getSessionsSection(page)
  await sessionsSection.scrollIntoViewIfNeeded()
  await expect(
    sessionsSection.getByRole('heading', { name: 'Active Sessions' }),
  ).toBeVisible()
})

Then('active sessions are listed', async function (this: EpdsWorld) {
  const page = getPage(this)
  const sessionRows = getSessionRows(page)
  await expect.poll(async () => sessionRows.count()).toBeGreaterThan(1)
})

When('the user revokes another session', async function (this: EpdsWorld) {
  const page = getPage(this)
  const secondarySessionAgent = this.secondarySessionAgent
  if (!secondarySessionAgent) {
    throw new Error(
      'No secondary session agent set — "the user has at least one other active session" step must run first',
    )
  }

  const sessionsSection = getSessionsSection(page)
  const secondaryRow = sessionsSection.locator('.setting-row', {
    hasText: secondarySessionAgent,
  })
  await expect(secondaryRow).toHaveCount(1)
  await expect(secondaryRow.locator('.session-agent')).not.toContainText(
    '(current)',
  )

  const revokeButton = secondaryRow.getByRole('button', { name: 'Revoke' })
  await revokeButton.click()
  await page.waitForLoadState('networkidle')
  await assertOnAccountSettingsPage(this)
})

Then('that session is no longer listed', async function (this: EpdsWorld) {
  const page = getPage(this)
  const secondarySessionAgent = this.secondarySessionAgent
  if (!secondarySessionAgent) {
    throw new Error(
      'No secondary session agent set — "the user has at least one other active session" step must run first',
    )
  }

  await page.reload()
  const sessionsSection = getSessionsSection(page)
  await sessionsSection.scrollIntoViewIfNeeded()
  await expect(
    sessionsSection.locator('.setting-row', { hasText: secondarySessionAgent }),
  ).toHaveCount(0)
})

When(
  'the user initiates account deletion and confirms',
  async function (this: EpdsWorld) {
    const page = getPage(this)
    await assertOnAccountSettingsPage(this)

    const dangerZone = page.locator('section', {
      has: page.getByRole('heading', { name: 'Danger Zone' }),
    })
    const details = dangerZone.locator('details')
    await details.locator('summary', { hasText: 'Delete account...' }).click()

    const confirmInput = details.locator('input[name="confirm"]')
    await expect(confirmInput).toBeVisible()
    await confirmInput.fill('DELETE')

    const submitButton = details.getByRole('button', {
      name: 'Delete my account',
    })
    await Promise.all([
      page.waitForURL('**/account/delete', { timeout: 30_000 }),
      submitButton.click(),
    ])
  },
)

Then(
  /^the browser is redirected away from \/account \(signed out\)$/,
  async function (this: EpdsWorld) {
    const page = getPage(this)
    const authBase = escapeForRegex(testEnv.authUrl)

    await expect(page).not.toHaveURL(
      new RegExp(`^${authBase}/account(\\?.*)?$`),
    )
    await expect(
      page.getByRole('heading', { name: 'Account Deleted' }),
    ).toBeVisible()

    await page.goto(`${testEnv.authUrl}/account`)
    await expect(page).toHaveURL(
      new RegExp(`^${authBase}/account/login(\\?.*)?$`),
    )
  },
)

Then(
  "the user's PDS account no longer exists",
  async function (this: EpdsWorld) {
    if (!this.userDid) {
      throw new Error(
        'No DID available — "a returning user has a PDS account" step must run first',
      )
    }

    await assertPdsAccountMissing(this.userDid)
  },
)

Then(
  "com.atproto.server.getSession fails for the user's DID",
  async function (this: EpdsWorld) {
    if (!this.userDid) {
      throw new Error(
        'No DID available — "a returning user has a PDS account" step must run first',
      )
    }

    await assertGetSessionFails(this.userDid)
  },
)
