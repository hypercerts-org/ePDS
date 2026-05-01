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
  verifyInternalSecret,
  generateCsrfToken,
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
export {
  escapeHtml,
  maskEmail,
  formatOtpPlain,
  formatOtpHtmlGrouped,
} from './html.js'
export {
  validateLocalPart,
  LOCAL_PART_MIN,
  LOCAL_PART_MAX,
  VALID_HANDLE_MODES,
  resolveHandleMode,
} from './handle.js'
export type { HandleMode } from './handle.js'
export {
  resolveClientMetadata,
  resolveClientName,
  escapeCss,
  MAX_CSS_BYTES,
  getClientCss,
  getClientFaviconUrl,
  getClientFaviconUrlDark,
  clearClientMetadataCache,
  getClientMetadataCacheStatus,
  _seedClientMetadataCacheForTest,
} from './client-metadata.js'
export type {
  ClientMetadata,
  ClientBranding,
  ResolveClientMetadataOptions,
} from './client-metadata.js'
export {
  PREVIEW_CACHE_STATUS_HTML,
  PREVIEW_CLIENT_ID_INPUT_HTML,
  PREVIEW_CLIENT_ID_SCRIPT_HTML,
  AUTH_PREVIEW_ROUTES,
  PDS_PREVIEW_ROUTES,
  renderPreviewLinksSections,
  renderPreviewIndexPage,
} from './preview-ui.js'
export type { PreviewRoute } from './preview-ui.js'
export { validateClientMetadataForPreview } from './preview-validation.js'
export type {
  CheckSeverity,
  PreviewCheck,
  PreviewValidationResult,
} from './preview-validation.js'
export { parsePromptTokens, promptHasLogin } from './oidc-prompt.js'
export { getEpdsVersion } from './version.js'
export { makeSafeFetch } from './safe-fetch.js'
export type { SafeFetchOptions } from './safe-fetch.js'
export { postHook } from './test-utils/post-hook.js'
export type { PostHookResult } from './test-utils/post-hook.js'
export { ERROR_CSS, renderError } from './render-error.js'
export type { RenderErrorOptions } from './render-error.js'
