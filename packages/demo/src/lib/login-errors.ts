const ERROR_MESSAGES: Record<string, string> = {
  auth_failed: 'Sign-in failed. Please try again.',
  session_expired:
    'Your sign-in took too long to finish. Please sign in again.',
  par_failed:
    "Sign-in couldn't start. Please try again. If it keeps happening, contact support.",
  invalid_email: 'Please enter a valid email address.',
  invalid_handle: 'Please enter a valid handle (e.g. you.bsky.social).',
  invalid_login_hint:
    "We didn't recognise that account. Please sign in with your email instead.",
  token_failed: "Sign-in couldn't be completed. Please sign in again.",
  state_mismatch:
    'Your sign-in session expired or was interrupted. Please try again.',
}

export function getLoginErrorMessage(errorCode: string | null): string | null {
  return errorCode
    ? ERROR_MESSAGES[errorCode] || `Unexpected error: ${errorCode}`
    : null
}
