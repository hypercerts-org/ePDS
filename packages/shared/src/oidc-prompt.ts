/**
 * Helpers for parsing the OIDC `prompt` parameter.
 *
 * Per OpenID Connect Core 1.0 §3.1.2.1, `prompt` is a space-delimited
 * list of values (e.g. `"login consent"`), not a single literal. An
 * exact string check (`p === 'login'`) misses every multi-token value
 * that includes `login`. Both pds-core's auth-ui-guard and
 * auth-service's session-reuse layer must agree on what counts as
 * "the client asked for forced re-authentication", so the parsing
 * lives here in shared rather than being duplicated per package.
 *
 * Express's `req.query` parser also surfaces repeated query keys as
 * arrays (`?prompt=login&prompt=consent` → `['login', 'consent']`), so
 * we accept both string and string-array shapes.
 */

/** Tokenise an OIDC `prompt` parameter value into its space-delimited
 *  set. Returns an empty Set for null/undefined/non-string-or-array
 *  input. Array shapes (from repeated query keys) are joined with a
 *  space before tokenising so `?prompt=login&prompt=consent` produces
 *  the same set as `prompt=login%20consent`. */
export function parsePromptTokens(value: unknown): Set<string> {
  let raw: string
  if (typeof value === 'string') {
    raw = value
  } else if (
    Array.isArray(value) &&
    value.every((v): v is string => typeof v === 'string')
  ) {
    raw = value.join(' ')
  } else {
    return new Set()
  }
  return new Set(raw.split(/\s+/).filter(Boolean))
}

/** True when the given OIDC prompt value contains the `login` token.
 *  Both the auth-ui-guard and the auth-service login-page route use
 *  this — they must agree on what counts as "forced login" so the
 *  guard's bounce condition and the auth-service's session-reuse /
 *  initial-step decisions apply to exactly the same requests. */
export function promptHasLogin(value: unknown): boolean {
  return parsePromptTokens(value).has('login')
}
