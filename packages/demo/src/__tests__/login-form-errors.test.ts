import { describe, expect, it } from 'vitest'
import { getLoginErrorMessage } from '../lib/login-errors.js'

describe('getLoginErrorMessage', () => {
  it('gives a retry and escalation path when PAR setup fails', () => {
    expect(getLoginErrorMessage('par_failed')).toBe(
      "Sign-in couldn't start. Please try again. If it keeps happening, contact support.",
    )
  })

  it('asks the user to retry after an interrupted OAuth state', () => {
    expect(getLoginErrorMessage('state_mismatch')).toBe(
      'Your sign-in session expired or was interrupted. Please try again.',
    )
  })

  it('retains a safe fallback for unknown error codes', () => {
    expect(getLoginErrorMessage('unexpected_code')).toBe(
      'Unexpected error: unexpected_code',
    )
  })
})
