/**
 * Mask an email for display: a few leading characters of the local part,
 * `***`, then the domain (`al***@example.com`).
 *
 * The domain stays visible, so the visible prefix is what keeps the label
 * from reconstructing the address. It scales with the local part and never
 * exceeds about half of it:
 *
 * - 1-2 characters: none (`***@example.com`)
 * - 3-4 characters: one (`a***@example.com`)
 * - 5 or more: two (`al***@example.com`)
 *
 * Only for addresses the browser did not supply. Typed emails are masked by
 * the page's own inline script, which has no such rule.
 */
export function maskEmail(email: string): string {
  // Last '@': the domain is what follows it, even if a quoted local part
  // contains an '@' of its own.
  const at = email.lastIndexOf('@')
  if (at <= 0) return '***'

  const local = Array.from(email.slice(0, at))
  const visible = visibleCharCount(local.length)
  return `${local.slice(0, visible).join('')}***${email.slice(at)}`
}

function visibleCharCount(localLength: number): number {
  if (localLength >= 5) return 2
  if (localLength >= 3) return 1
  return 0
}
