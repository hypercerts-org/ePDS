import { describe, it, expect } from 'vitest'
import {
  FLASH_SUCCESS_MESSAGES,
  FLASH_ERROR_MESSAGES,
  resolveAccountFlashFromQuery,
  renderSettingsPage,
} from '../routes/account-settings.js'

describe('account-settings flash messages', () => {
  // Every code referenced in a redirect from a POST handler needs an
  // entry in the matching lookup, otherwise the user lands on the
  // settings page with no acknowledgement of the action they took.
  // These tests guard against drift — adding a new code without a
  // corresponding entry would mean the redirect silently dropped.

  it('has a success message for each code redirected to from a POST handler', () => {
    const expectedSuccessCodes = [
      'backup_added',
      'backup_verified',
      'backup_removed',
      'handle_updated',
      'session_revoked',
    ]
    for (const code of expectedSuccessCodes) {
      expect(
        FLASH_SUCCESS_MESSAGES[code],
        `missing FLASH_SUCCESS_MESSAGES["${code}"]`,
      ).toBeTruthy()
    }
  })

  it('has an error message for each code redirected to from a POST handler', () => {
    const expectedErrorCodes = [
      'invalid_email',
      'already_primary',
      'account_not_found',
      'send_failed',
      'backup_remove_failed',
      'revoke_failed',
      'verify_failed',
      'invalid_handle',
      'handle_failed',
      'handle_taken',
      'delete_failed',
      'confirm_delete',
    ]
    for (const code of expectedErrorCodes) {
      expect(
        FLASH_ERROR_MESSAGES[code],
        `missing FLASH_ERROR_MESSAGES["${code}"]`,
      ).toBeTruthy()
    }
  })

  it('returns undefined for unknown codes — the GET handler treats this as "no banner"', () => {
    expect(FLASH_SUCCESS_MESSAGES['attacker_injected_text']).toBeUndefined()
    expect(FLASH_ERROR_MESSAGES['<script>alert(1)</script>']).toBeUndefined()
  })

  it('all messages are plain text, no HTML', () => {
    // The renderer escapeHtml's the lookup result anyway (defence in
    // depth) but the values themselves shouldn't carry markup.
    for (const msg of Object.values(FLASH_SUCCESS_MESSAGES)) {
      expect(msg).not.toMatch(/<[a-z]/i)
    }
    for (const msg of Object.values(FLASH_ERROR_MESSAGES)) {
      expect(msg).not.toMatch(/<[a-z]/i)
    }
  })
})

describe('account-settings flash rendering', () => {
  const renderPage = (messages: {
    successMessage?: string
    errorMessage?: string
  }) =>
    renderSettingsPage({
      did: 'did:plc:test',
      email: 'primary@example.com',
      handleDomain: 'example.com',
      currentHandle: null,
      backupEmails: [],
      sessions: [],
      currentSessionToken: 'current-session',
      csrfToken: 'csrf-token',
      ...messages,
    })

  it('renders successful actions as an accessible status', () => {
    const html = renderPage({ successMessage: 'Backup email removed.' })
    expect(html).toContain(
      '<div class="flash flash-success" role="status">Backup email removed.</div>',
    )
  })

  it('renders escaped failures as an alert', () => {
    const html = renderPage({ errorMessage: '<script>failed</script>' })
    expect(html).toContain(
      '<div class="flash flash-error" role="alert">&lt;script&gt;failed&lt;/script&gt;</div>',
    )
    expect(html).not.toContain('<script>failed</script>')
  })
})

describe('resolveAccountFlashFromQuery', () => {
  it('returns the success message when the success code is known', () => {
    const result = resolveAccountFlashFromQuery({ success: 'backup_added' })
    expect(result.successMessage).toBe(FLASH_SUCCESS_MESSAGES.backup_added)
    expect(result.errorMessage).toBeNull()
  })

  it('returns the error message when the error code is known', () => {
    const result = resolveAccountFlashFromQuery({
      success: '',
      error: 'invalid_handle',
    })
    expect(result.successMessage).toBeNull()
    expect(result.errorMessage).toBe(FLASH_ERROR_MESSAGES.invalid_handle)
  })

  it('returns null on both sides when the query is empty', () => {
    expect(resolveAccountFlashFromQuery({})).toEqual({
      successMessage: null,
      errorMessage: null,
    })
  })

  it('returns null on both sides for unknown codes (safety against URL-injection of attacker text)', () => {
    expect(
      resolveAccountFlashFromQuery({
        success: 'attacker_chosen_text',
        error: '<script>alert(1)</script>',
      }),
    ).toEqual({ successMessage: null, errorMessage: null })
  })

  it('ignores non-string query values gracefully (e.g. ?success=foo&success=bar arrays)', () => {
    expect(
      resolveAccountFlashFromQuery({
        success: ['backup_added', 'backup_removed'],
        error: 12345,
      }),
    ).toEqual({ successMessage: null, errorMessage: null })
  })
})
