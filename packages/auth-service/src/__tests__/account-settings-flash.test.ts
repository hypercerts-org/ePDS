import { describe, it, expect } from 'vitest'
import {
  FLASH_SUCCESS_MESSAGES,
  FLASH_ERROR_MESSAGES,
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
