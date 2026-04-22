export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

/**
 * Mask an email so that knowing a user's handle does not let an observer
 * recover (or easily guess) their email address. Both the local part and the
 * domain — including the TLD — are masked. Dot-separated segments are masked
 * independently so that segment boundaries are preserved but lengths and
 * characters are not revealed.
 *
 * Each segment is replaced with `***` followed by its final character (or
 * just `***` if the segment is a single character). Revealing the TLD (e.g.
 * `.com`) would otherwise make popular providers like `gmail.com` trivially
 * identifiable, which in turn makes the local part much more guessable.
 *
 * Example: `persons.address@gmail.com` → `***s.***s@***l.***m`
 */
export function maskEmail(email: string): string {
  const atIndex = email.lastIndexOf('@')
  if (atIndex <= 0 || atIndex === email.length - 1) return email
  const local = email.slice(0, atIndex)
  const domain = email.slice(atIndex + 1)
  return maskDottedSegments(local) + '@' + maskDottedSegments(domain)
}

function maskDottedSegments(s: string): string {
  return s
    .split('.')
    .map((seg) => (seg.length <= 1 ? '***' : '***' + seg.slice(-1)))
    .join('.')
}

/**
 * Returns the group size to use for OTP display, or null if no grouping applies.
 * Only groups codes of length 8 or more.
 * Tries groups of 4 first, then groups of 3.
 */
function otpGroupSize(length: number): number | null {
  if (length < 8) return null
  if (length % 4 === 0) return 4
  if (length % 3 === 0) return 3
  return null
}

function chunkString(s: string, size: number): string[] {
  const chunks: string[] = []
  for (let i = 0; i < s.length; i += size) chunks.push(s.slice(i, i + size))
  return chunks
}

/**
 * Format an OTP code for plain-text display (subject lines, plain-text email bodies).
 * Groups codes of length >= 8 with spaces where possible (groups of 4, then 3).
 * Lengths that don't divide evenly, or are under 8, are returned as-is.
 *
 * Examples: 8 → "1234 5678", 9 → "123 456 789", 12 → "1234 5678 9012"
 */
export function formatOtpPlain(code: string): string {
  const groupSize = otpGroupSize(code.length)
  if (!groupSize) return code
  return chunkString(code, groupSize).join(' ')
}

/**
 * Format an OTP code for display inside an HTML email.
 * Groups codes of length >= 8 using <span> elements with a CSS gap between
 * them — no separator character exists in the DOM so copy-paste yields the
 * flat code. Lengths that don't divide evenly, or are under 8, are returned
 * as HTML-escaped flat strings.
 *
 * Examples: 8 → two spans "1234" + "5678", 9 → three spans "123"+"456"+"789"
 */
export function formatOtpHtmlGrouped(code: string): string {
  const groupSize = otpGroupSize(code.length)
  if (!groupSize) return escapeHtml(code)
  return chunkString(code, groupSize)
    .map((chunk, i) =>
      i === 0
        ? `<span>${escapeHtml(chunk)}</span>`
        : `<span style="padding-left:0.35em">${escapeHtml(chunk)}</span>`,
    )
    .join('')
}
