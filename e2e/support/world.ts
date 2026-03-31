import { World, setWorldConstructor } from '@cucumber/cucumber'
import type { Browser, BrowserContext, Page } from '@playwright/test'
import { testEnv } from './env.js'

export class EpdsWorld extends World {
  browser?: Browser
  context?: BrowserContext
  page?: Page

  /** OTP code extracted from the most recent email — set by email steps, read by auth steps. */
  otpCode?: string

  /** Subject line of the most recent email — set by email steps. */
  lastEmailSubject?: string

  /** Generated unique email for the current scenario — set by "unique test email" steps. */
  testEmail?: string

  /** DID captured from the demo welcome page after successful OAuth sign-up. */
  userDid?: string

  /** Handle captured from the demo welcome page after successful OAuth sign-up. */
  userHandle?: string

  /** HTTP status code from the most recent direct API call — set by API steps. */
  lastHttpStatus?: number

  /** Response body from the most recent internal API call — set by internal-api steps. */
  lastApiResponse?: Record<string, unknown>

  /** Most recent PAR request_uri — set by PAR submission steps. */
  lastRequestUri?: string

  get env() {
    return testEnv
  }

  /**
   * Call in any step that requires Mailpit. If E2E_MAILPIT_PASS is not set,
   * marks the step as pending and cucumber-js skips remaining steps in the scenario.
   * When Mailpit is available, this is a no-op and the step executes normally.
   */
  skipIfNoMailpit(): 'pending' | undefined {
    if (!testEnv.mailpitPass) {
      return 'pending'
    }
  }

  /**
   * Call in any step that requires the internal API secret. If
   * E2E_EPDS_INTERNAL_SECRET is not set, marks the step as pending and
   * cucumber-js skips remaining steps in the scenario.
   * When the secret is available, this is a no-op and the step executes normally.
   */
  skipIfNoInternalSecret(): 'pending' | undefined {
    if (!testEnv.internalSecret) {
      return 'pending'
    }
  }
}

setWorldConstructor(EpdsWorld)
