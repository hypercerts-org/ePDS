/**
 * Shared OTP-verify error-message picker for the server-rendered
 * sign-in flows (`/account/verify-otp` and `/auth/recover/verify`).
 *
 * Both routes call better-auth's `signInEmailOTP` and need to
 * translate the caught error into user-facing copy. They have the
 * same three meaningful cases:
 *
 *   1. Lockout / aged-out — "Too many attempts" or "OTP expired"
 *      from better-auth. The current code can no longer succeed, so
 *      point the user at Resend.
 *
 *   2. "Invalid OTP" — usually a recoverable typo. better-auth uses
 *      the same text after deleting a locked-out row, so these stateless
 *      server-rendered routes cannot distinguish that later case and must
 *      avoid claiming certainty they do not have.
 *
 *   3. Internal failure — anything else (network, DB, unexpected).
 *      Show a generic try-again message.
 *
 * Returning the message string rather than a structured kind keeps
 * the call sites simple — they just feed it straight into their
 * `renderOtpForm({ error: ... })` helper.
 *
 * The branching is exported as a pure function so unit tests can
 * cover all three branches without standing up a router.
 */

export function pickOtpVerifyErrorMessage(err: unknown): string {
  const errText = err instanceof Error ? err.message.toLowerCase() : ''
  if (/too many attempts|expir/.test(errText)) {
    return 'That code can no longer be used. Click "Resend code" below to get a fresh one.'
  }
  if (errText.includes('invalid')) {
    return 'Invalid code. Please try again.'
  }
  return 'Verification failed. Please try again.'
}
