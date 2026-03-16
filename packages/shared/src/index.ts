export { EpdsDb } from './db.js'
export type {
  VerificationTokenRow,
  BackupEmailRow,
  EmailRateLimitRow,
  AuthFlowRow,
} from './db.js'
export {
  generateVerificationToken,
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
  EpdsLinkConfig,
  EmailConfig,
  AuthConfig,
  RateLimitConfig,
} from './types.js'
export { DEFAULT_RATE_LIMITS } from './types.js'
export { createLogger } from './logger.js'
export { escapeHtml, maskEmail } from './html.js'
export {
  validateLocalPart,
  LOCAL_PART_MIN,
  LOCAL_PART_MAX,
  VALID_HANDLE_MODES,
} from './handle.js'
export type { HandleMode } from './handle.js'
