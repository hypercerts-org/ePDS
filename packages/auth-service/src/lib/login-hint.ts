/**
 * Classification of an OAuth `login_hint`, and the privacy rule that follows
 * from it.
 *
 * An email hint was supplied by whoever built the URL, so echoing it back
 * (pre-filling the form) reveals nothing. A handle or DID is public, and the
 * address it resolves to is the account's private email: that one must stay
 * server-side.
 */

/**
 * Whether a login_hint is an email address rather than a handle or DID.
 *
 * Same rule as `resolveLoginHint`: '@' never appears in a handle or DID, so
 * its presence marks an email.
 */
export function isEmailLoginHint(loginHint: string): boolean {
  return loginHint.includes('@')
}

/**
 * Decide how a resolved login_hint may reach the browser.
 *
 * - Email hint: `prefillEmail` carries it, exactly as the caller supplied it.
 * - Handle/DID hint: the resolved address is returned only as `flowEmail`,
 *   for the caller to store on the auth_flow row; `prefillEmail` stays empty.
 */
export function splitResolvedHint(
  hint: string | null,
  resolvedEmail: string | null,
): { prefillEmail: string; flowEmail: string | null } {
  if (!hint || !resolvedEmail) return { prefillEmail: '', flowEmail: null }
  return isEmailLoginHint(hint)
    ? { prefillEmail: resolvedEmail, flowEmail: null }
    : { prefillEmail: '', flowEmail: resolvedEmail }
}
