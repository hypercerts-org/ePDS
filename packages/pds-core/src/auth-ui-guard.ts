/**
 * Pre-route middleware that short-circuits any request which would cause
 * upstream @atproto/oauth-provider to render either of its two stock
 * authentication UIs:
 *
 *   1. The three-button welcome page ("Authenticate / Create new account /
 *      Sign in / Cancel") — rendered when the device has zero bound
 *      accounts (partial cookie
 *      pair, stale pair, migration-005 TTL purge, fixation race, etc.).
 *
 *   2. The sign-in-view (handle + password form) — rendered when bindings
 *      exist but every binding upstream considers has loginRequired: true.
 *      Three triggers: the stored PAR has prompt=login; every binding's
 *      auth age exceeds authenticationMaxAge (default 7d); a login_hint
 *      pre-selects an individually stale binding among otherwise-fresh
 *      bindings on the same device.
 *
 * Both UIs are unreachable from ePDS by design — every entry point should
 * either show the enriched chooser (when the device has fresh bound
 * accounts) or fall back to auth-service's email/OTP form. ePDS accounts
 * are passwordless, so the password form in particular is a contract
 * violation: the user gets a form they cannot submit.
 *
 * Upstream's DeviceManager.hasSession/getCookies has a side effect — it
 * deletes the device row on a partial cookie pair — so we re-parse the
 * cookies ourselves using the exported Zod schemas rather than calling
 * upstream. We then query account bindings via the public
 * accountManager.listDeviceAccounts API. If bindings exist we additionally
 * mirror upstream's matchesHint + checkLoginRequired logic to detect the
 * sign-in-view path; on any bounce condition we 303 to auth-service and
 * clear stale device-session cookies, otherwise we let upstream proceed.
 *
 * See docs/design/session-reuse-bugs.md for the full failure-mode taxonomy.
 */
import type { NextFunction, Request, Response } from 'express'
import type { DeviceAccount, OAuthProvider } from '@atproto/oauth-provider'
import {
  DEVICE_ID_BYTES_LENGTH,
  DEVICE_ID_PREFIX,
  SESSION_ID_BYTES_LENGTH,
  SESSION_ID_PREFIX,
} from '@atproto/oauth-provider'
import type { Logger } from 'pino'
import {
  parsePromptTokens as parsePromptTokensShared,
  promptHasLogin as promptHasLoginShared,
} from '@certified-app/shared'
import { loadDeviceBindings } from './lib/device-accounts.js'

/** Re-export of the shared implementation. The canonical home is
 *  `@certified-app/shared`; this re-export exists so internal callers
 *  in pds-core (and the existing `auth-ui-guard.test.ts` import site)
 *  don't have to be touched on every refactor. New callers should
 *  import from `@certified-app/shared` directly. */
export const parsePromptTokens = parsePromptTokensShared
/** Re-export of the shared implementation. The canonical home is
 *  `@certified-app/shared`; this re-export exists so internal callers
 *  in pds-core (and the existing `auth-ui-guard.test.ts` import site)
 *  don't have to be touched on every refactor. New callers should
 *  import from `@certified-app/shared` directly. */
export const promptHasLogin = promptHasLoginShared

const DEVICE_ID_RE = new RegExp(
  `^${DEVICE_ID_PREFIX}[0-9a-f]{${DEVICE_ID_BYTES_LENGTH * 2}}$`,
)
const SESSION_ID_RE = new RegExp(
  `^${SESSION_ID_PREFIX}[0-9a-f]{${SESSION_ID_BYTES_LENGTH * 2}}$`,
)

/** True when this request path is one where upstream may render the
 *  stock welcome page. We guard the two routes upstream exposes:
 *
 *   - `/oauth/authorize` — OAuth authorization flow entry
 *   - `/account*` — standalone account management UI
 */
export function isGuardedPath(path: string): boolean {
  if (path === '/oauth/authorize') return true
  return /^\/account(?:\/.*)?$/.test(path)
}

/** Parse dev-id + ses-id from the Cookie header without any side effects.
 *  Returns both ids when both cookies are present and valid per upstream's
 *  Zod schemas; null otherwise. Matches the parsing rules in
 *  `@atproto/oauth-provider`'s DeviceManager.parseCookie exactly so our
 *  accept/reject decision stays aligned with upstream's.
 *
 *  Both ids are returned because the guard validates the sessionId
 *  against the device row server-side: the device cookie pair can be
 *  syntactically well-formed yet semantically stale (cookie-jar
 *  divergence after a logout/rotation race, restored backup, manual
 *  deletion of the server-side row, etc.). A fresh-looking cookie pair
 *  whose ses-id no longer matches the stored sessionId is exactly the
 *  case that lets a request slip past the bindings check and land on
 *  upstream's stock welcome page.
 *
 *  Only decodes the two names we care about: a sibling cookie with a
 *  malformed percent-escape (e.g. analytics SDKs that set `x=%GG`) must
 *  not be able to crash the guard. dev-id/ses-id values are hex strings
 *  upstream never percent-encodes, so decoding them is nominally a
 *  no-op, but we keep the decode to stay exactly in step with upstream's
 *  DeviceManager.parseCookie — and wrap it in try/catch so a pathological
 *  value returns null rather than throwing URIError. */
export function parseDeviceCookies(
  cookieHeader: string | undefined,
): { deviceId: string; sessionId: string } | null {
  if (!cookieHeader) return null
  const jar: Record<string, string> = {}
  for (const part of cookieHeader.split(/;\s*/)) {
    const eq = part.indexOf('=')
    if (eq <= 0) continue
    const name = part.slice(0, eq)
    if (name !== 'dev-id' && name !== 'ses-id') continue
    if (Object.hasOwn(jar, name)) continue
    const raw = part.slice(eq + 1)
    try {
      jar[name] = decodeURIComponent(raw)
    } catch {
      return null
    }
  }
  const devId = jar['dev-id']
  const sesId = jar['ses-id']
  if (!devId || !sesId) return null
  if (!DEVICE_ID_RE.test(devId)) return null
  if (!SESSION_ID_RE.test(sesId)) return null
  return { deviceId: devId, sessionId: sesId }
}

/** Build the auth-service URL we bounce empty-device requests to.
 *  Preserves the original query string verbatim and appends
 *  `prompt=login` so auth-service's shouldReuseSession takes the
 *  forced-login branch (bypassing any future session-reuse check that
 *  might otherwise redirect back here). */
export function buildBounceUrl(authHostname: string, origUrl: string): string {
  const authScheme =
    authHostname === 'localhost' || authHostname.endsWith('.localhost')
      ? 'http'
      : 'https'
  const authBase = `${authScheme}://${authHostname}`
  const target = new URL('/oauth/authorize', authBase)
  // Parse the original URL to lift its query string. Malformed
  // percent-encoding (e.g. `?x=%GG`) would otherwise throw and 500 the
  // request before the bounce; on parse failure drop the inherited
  // query rather than propagate the exception — the bounce still
  // succeeds with just `prompt=login`, and auth-service will render
  // its own error for a truly broken request_uri.
  try {
    const parsed = new URL(origUrl, 'https://placeholder')
    // Assign the raw serialized query so repeated params (e.g. `scope`
    // appearing twice) survive verbatim; searchParams.forEach + set()
    // would collapse repeats to the last value, contradicting the
    // "preserves the original query string verbatim" contract below.
    target.search = parsed.search
  } catch {
    // Leave target.search empty; prompt=login is appended below.
  }
  // We intentionally override any incoming prompt — the forced-login
  // branch is the whole point of the bounce.
  target.searchParams.set('prompt', 'login')
  return target.toString()
}

/** True if the request looks like part of an active OAuth flow — i.e.
 *  it carries a `request_uri` we can preserve on the bounce. Bare
 *  `/account*` navigation (bookmarks, direct URL typing) has no
 *  OAuth context; bouncing such requests to auth-service's
 *  `/oauth/authorize` would just produce a 400 "Missing request_uri".
 *  For those we fall through to upstream instead. */
function hasOauthContext(origUrl: string): boolean {
  // Degrade safely on malformed percent-encoding — returning false lets
  // the request fall through to upstream rather than 500ing on `?x=%GG`.
  try {
    const parsed = new URL(origUrl, 'https://placeholder')
    return parsed.searchParams.has('request_uri')
  } catch {
    return false
  }
}

/** Emit Set-Cookie headers that clear dev-id and ses-id (plus their
 *  `:hash` sidecars) in both their host-only and domain-scoped variants.
 *  Browsers treat each scope as a distinct cookie, so clearing only one
 *  leaves the other behind. The `:hash` variants only materialise when
 *  upstream is configured with cookie signing keys (which ePDS doesn't
 *  do today — `@atproto/pds@0.4.211` never threads them through), but
 *  the list matches `DEVICE_COOKIE_NAMES` in `cookie-domain.ts` so a
 *  future upstream change can't leave orphan sidecars behind. */
export function appendCookieClearHeaders(
  res: Response,
  cookieDomain: string | null,
): void {
  const names = ['dev-id', 'dev-id:hash', 'ses-id', 'ses-id:hash']
  for (const name of names) {
    res.append('Set-Cookie', `${name}=; Max-Age=0; Path=/`)
    if (cookieDomain) {
      res.append(
        'Set-Cookie',
        `${name}=; Max-Age=0; Path=/; Domain=${cookieDomain}`,
      )
    }
  }
}

/** Create the Express middleware. `cookieDomain` may be null when the
 *  auth-service and pds-core don't share a common parent domain — in
 *  that case there's no domain-scoped cookie to clear. */
export function createAuthUiGuard(opts: {
  authHostname: string
  provider: OAuthProvider | null
  cookieDomain: string | null
  logger?: Partial<Pick<Logger, 'error' | 'debug'>>
}) {
  const { authHostname, provider, cookieDomain, logger } = opts
  return async function authUiGuard(
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> {
    if (req.method !== 'GET') {
      next()
      return
    }
    if (!isGuardedPath(req.path)) {
      next()
      return
    }
    if (!provider) {
      next()
      return
    }
    // Bare /account* navigation (bookmark, direct URL) has no OAuth
    // context to preserve. auth-service's /oauth/authorize rejects such
    // requests with a 400 "Missing request_uri" — worse UX than the
    // stock upstream welcome page the guard was meant to suppress. Let
    // upstream handle these; the PR's @docker-only scenarios only cover
    // flows that originate at an OAuth entry point.
    const inOauthFlow = hasOauthContext(req.url)
    const bounceOrPass = (): void => {
      if (!inOauthFlow) {
        next()
        return
      }
      res.status(303)
      appendCookieClearHeaders(res, cookieDomain)
      res.setHeader('Location', buildBounceUrl(authHostname, req.url))
      res.setHeader('Cache-Control', 'no-store')
      res.end()
    }
    const parsed = parseDeviceCookies(req.headers.cookie)
    if (!parsed) {
      bounceOrPass()
      return
    }
    // Validate the cookie pair against the device row + list bound
    // accounts. A syntactically-valid cookie pair whose ses-id no
    // longer matches the stored value (logout/rotation race, restored
    // backup, manual deletion of the server-side row, fixation reset,
    // etc.), or a device with zero bound accounts (migration-005 1h
    // TTL purge for remember=0 rows), would otherwise sail past and
    // let upstream render its stock welcome page. Both cases come
    // back as `null` or `[]` from the helper — bounce on either.
    const bindings = await loadDeviceBindings({
      provider,
      deviceId: parsed.deviceId,
      sessionId: parsed.sessionId,
      logCtx: 'guard',
      logger,
    })
    if (!bindings || bindings.length === 0) {
      bounceOrPass()
      return
    }

    // At this point bindings exist, so upstream won't render the welcome
    // page. But it may still render its sign-in-view (handle + password
    // form) when every binding it would consider has loginRequired: true
    // — see oauth-provider.ts:622-624. ePDS accounts are passwordless,
    // so any path into that form is unusable. Three independent triggers
    // force upstream into that state:
    //
    //   - stored PAR `parameters.prompt === 'login'` (forces every
    //     session loginRequired regardless of auth age)
    //   - every binding's auth age exceeds upstream's
    //     authenticationMaxAge (default 7d, applied per-binding)
    //   - login_hint matches one binding which is itself stale, even
    //     when other bindings on the device are fresh (upstream
    //     pre-selects the hinted account; clicking falls through to
    //     sign-in-view)
    //
    // Read the stored PAR parameters and compute upstream's
    // candidate-binding set; bounce when every candidate would be
    // loginRequired. See features/session-reuse-bugs.feature for the
    // externally-reproducible scenarios under "Sign-in-view leaks".
    const params = await loadStoredPar({
      provider,
      requestUrl: req.url,
      logger,
    })
    if (promptHasLogin(params?.prompt)) {
      bounceOrPass()
      return
    }
    const candidates = filterCandidateBindings(bindings, params?.login_hint)
    if (candidates.every((b) => provider.checkLoginRequired(b))) {
      bounceOrPass()
      return
    }
    next()
  }
}

// ---------------------------------------------------------------------------
// Helpers used only by the guard middleware. The cookie-pair-validating
// `loadDeviceBindings` lives in `lib/device-accounts.ts` so this file and
// the /_internal/device-accounts endpoint share the same miss semantics.
// What's left here is the stored-PAR / login_hint logic that's unique to
// the guard.
// ---------------------------------------------------------------------------

type StoredPar = {
  prompt?: string
  login_hint?: string
}

// Local alias so the helpers' signatures read clearly. Upstream's
// DeviceAccount has the fields we need (`account` for the hint match,
// `updatedAt` for checkLoginRequired).
type Binding = DeviceAccount

/** Read the stored PAR parameters for the request_uri on the current URL.
 *  Returns null when the URL has no request_uri, when the lookup fails, or
 *  when stored data is shaped unexpectedly. Used to read `prompt` and
 *  `login_hint` for the bounce decisions on flows where the stored PAR
 *  forces re-authentication or hints at a stale binding. */
async function loadStoredPar(opts: {
  provider: OAuthProvider
  requestUrl: string
  logger?: Partial<Pick<Logger, 'error' | 'debug'>>
}): Promise<StoredPar | null> {
  const { provider, requestUrl, logger } = opts
  let requestUri: string | null
  try {
    requestUri = new URL(requestUrl, 'https://placeholder').searchParams.get(
      'request_uri',
    )
  } catch {
    return null
  }
  if (!requestUri) return null
  const REQUEST_URI_PREFIX = 'urn:ietf:params:oauth:request_uri:'
  if (!requestUri.startsWith(REQUEST_URI_PREFIX)) return null
  const requestId = decodeURIComponent(
    requestUri.slice(REQUEST_URI_PREFIX.length),
  )
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- requestManager.store not in upstream types
    const store = (provider.requestManager as any).store
    const stored = await store.readRequest(requestId)
    const params = stored?.parameters
    if (!params || typeof params !== 'object') return null
    return {
      prompt: typeof params.prompt === 'string' ? params.prompt : undefined,
      login_hint:
        typeof params.login_hint === 'string' ? params.login_hint : undefined,
    }
  } catch (err) {
    logger?.error?.({ err, requestId }, 'guard: store.readRequest failed')
    return null
  }
}

/** Apply upstream's `matchesHint` semantics to narrow the binding list to
 *  the candidates upstream would consider. When no hint is set OR the hint
 *  matches no binding, all bindings are candidates (chooser-like). When the
 *  hint matches exactly one binding (sub or preferred_username), that's the
 *  only candidate. Mirrors oauth-provider.ts:1100-1108. */
function filterCandidateBindings(
  bindings: Binding[],
  loginHint: string | undefined,
): Binding[] {
  if (!loginHint) return bindings
  const matched = bindings.filter(
    ({ account }) =>
      account.sub === loginHint || account.preferred_username === loginHint,
  )
  return matched.length === 1 ? matched : bindings
}
