import * as crypto from 'node:crypto'

const TOKEN_BYTES = 32 // 256 bits of entropy

/**
 * Generate a cryptographically secure magic link token.
 * Returns the raw token (to send in email) and its SHA-256 hash (to store in DB).
 */
export function generateMagicLinkToken(): { token: string; tokenHash: string } {
  const rawBytes = crypto.randomBytes(TOKEN_BYTES)
  const token = rawBytes.toString('base64url')
  const tokenHash = hashToken(token)
  return { token, tokenHash }
}

/**
 * SHA-256 hash a token for storage. Since tokens have high entropy,
 * a simple hash is sufficient (no need for bcrypt/scrypt).
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex')
}

/** Timing-safe comparison of two strings. */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    const dummy = Buffer.alloc(a.length)
    crypto.timingSafeEqual(dummy, dummy)
    return false
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))
}

/** Generate an 8-digit OTP code. Returns the code and its SHA-256 hash. */
export function generateOtpCode(): { code: string; codeHash: string } {
  const num = crypto.randomInt(0, 100_000_000)
  const code = num.toString().padStart(8, '0')
  const codeHash = hashToken(code)
  return { code, codeHash }
}

/** Generate a CSRF token. */
export function generateCsrfToken(): string {
  return crypto.randomBytes(32).toString('hex')
}

export interface CallbackParams {
  request_uri: string
  email: string
  approved: string
  new_account: string
}

/**
 * Sign the magic-callback redirect parameters with HMAC-SHA256.
 * Returns the hex signature and the Unix timestamp (seconds) used.
 *
 * Payload: request_uri, email, approved, new_account, and ts joined by newlines.
 * A timestamp is included so signatures expire (see verifyCallback).
 */
export function signCallback(
  params: CallbackParams,
  secret: string,
): { sig: string; ts: string } {
  const ts = Math.floor(Date.now() / 1000).toString()
  const payload = [
    params.request_uri,
    params.email,
    params.approved,
    params.new_account,
    ts,
  ].join('\n')
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex')
  return { sig, ts }
}

const CALLBACK_MAX_AGE_SECONDS = 5 * 60 // 5 minutes

/**
 * Verify a signed magic-callback redirect URL.
 * Returns true only when the signature is valid and the timestamp is fresh.
 * Uses timingSafeEqual to avoid timing side-channels.
 */
export function verifyCallback(
  params: CallbackParams,
  ts: string,
  sig: string,
  secret: string,
): boolean {
  const tsNum = parseInt(ts, 10)
  if (isNaN(tsNum)) return false

  const now = Math.floor(Date.now() / 1000)
  const age = now - tsNum
  if (age < 0 || age > CALLBACK_MAX_AGE_SECONDS) return false

  const payload = [
    params.request_uri,
    params.email,
    params.approved,
    params.new_account,
    ts,
  ].join('\n')
  const expected = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex')

  // Both are hex-encoded HMAC-SHA256 (always 64 chars / 32 bytes).
  // Guard against wrong-length input to keep timingSafeEqual happy.
  if (sig.length !== expected.length) return false
  return crypto.timingSafeEqual(
    Buffer.from(expected, 'hex'),
    Buffer.from(sig, 'hex'),
  )
}

/**
 * Generate a random handle subdomain (6-char base36).
 * ~2.17 billion possibilities. Checks for collision via callback.
 */
export function generateRandomHandle(domain: string): string {
  const bytes = crypto.randomBytes(4)
  const num = bytes.readUInt32BE(0)
  const id = num.toString(36).padStart(6, '0').slice(0, 6)
  return `${id}.${domain}`
}
