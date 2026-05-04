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

  /** Plain-text body of the most recent email — set by email steps that need body assertions. */
  lastEmailBody?: string

  /** Generated unique email for the current scenario — set by "unique test email" steps. */
  testEmail?: string

  /** Generated unique backup email for backup-email scenarios — set by "unique backup email" steps. */
  backupEmail?: string

  /** DID captured from the demo welcome page after successful OAuth sign-up. */
  userDid?: string

  /** Handle captured from the demo welcome page after successful OAuth sign-up. */
  userHandle?: string

  /** Secondary browser context for multi-session account settings scenarios. */
  secondaryContext?: BrowserContext

  /** Secondary page for multi-session account settings scenarios. */
  secondaryPage?: Page

  /** Email of an unrelated PDS account created in a fresh browser context;
   *  used by Flow 1 hint-vs-bindings scenarios that need a handle that
   *  resolves on the PDS but is NOT bound to the primary user's device. */
  otherUserEmail?: string

  /** Handle of the unrelated account — fed into login_hint to drive the
   *  hint-mismatch path. */
  otherUserHandle?: string

  /** DID of the unrelated account, kept alongside email/handle for
   *  parity with the primary user fields. */
  otherUserDid?: string

  /** New handle local part submitted via account settings. */
  updatedHandleLocalPart?: string

  /** Full handle after account settings update (local + domain). */
  updatedHandle?: string

  /** HTTP status code from the most recent direct API call — set by API steps. */
  lastHttpStatus?: number

  /** Parsed JSON body from the most recent direct HTTP call — set by API steps. */
  lastHttpJson?: Record<string, unknown>

  /** Raw text body from the most recent direct HTTP call — set by steps fetching HTML/SVG. */
  lastHttpBody?: string

  /** Content-Type header from the most recent direct HTTP call. */
  lastHttpContentType?: string

  /** Most recent PAR request_uri — set by PAR submission steps. */
  lastRequestUri?: string

  /** Computed background colors captured by client-branding scenarios, keyed by label. */
  capturedBgColors?: Record<string, string>

  /** URL captured when the auth-service login page redirects to the
   *  client's `epds_handle_login_url` after handle-mode submission.
   *  Used by atproto-login-button scenarios. */
  handleLoginRedirectUrl?: string

  /** Console-capture stream for the current scenario. Set by hooks on
   *  scenario start, re-attached after resetBrowserContext. */
  consoleCapture?: NodeJS.WritableStream

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
}

setWorldConstructor(EpdsWorld)
