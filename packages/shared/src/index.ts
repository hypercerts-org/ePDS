export { MagicPdsDb } from './db.js'
export type {
  MagicLinkTokenRow,
  AccountEmailRow,
  BackupEmailRow,
  EmailRateLimitRow,
} from './db.js'
export {
  generateMagicLinkToken,
  hashToken,
  timingSafeEqual,
  generateCsrfToken,
  generateOtpCode,
  generateRandomHandle,
  signCallback,
  verifyCallback,
} from './crypto.js'
export type { CallbackParams } from './crypto.js'
export type {
  MagicLinkConfig,
  EmailConfig,
  AuthConfig,
  RateLimitConfig,
} from './types.js'
export { DEFAULT_RATE_LIMITS } from './types.js'
export { createLogger } from './logger.js'
export { escapeHtml, maskEmail } from './html.js'
