/**
 * Session-reuse detection for HYPER-268.
 *
 * When a user has already signed in via any OAuth client in this browser,
 * the upstream @atproto/oauth-provider's DeviceManager stores a dev-id
 * cookie on the shared parent domain (see packages/pds-core cookie-domain
 * middleware). The auth-service uses these helpers to decide, on incoming
 * /oauth/authorize requests, whether to bypass its own email/OTP login
 * form and redirect the browser to pds-core's upstream middleware, which
 * then either auto-selects a matching session (flow 1 with login_hint)
 * or renders the account chooser (flow 2).
 */
import { promptHasLogin } from '@certified-app/shared'

/** Shape of the request data the helpers consume. Intentionally narrow
 *  so we can unit-test without an Express instance. Mirrors the fields
 *  of `http.IncomingMessage`/`express.Request` that we actually read. */
export type SessionReuseRequest = {
  /** The parsed Express `req.cookies` bag (populated when the
   *  cookie-parser middleware is installed). May be undefined. */
  cookies?: Record<string, string>
  /** Raw HTTP headers. We fall back to parsing `cookie` here when the
   *  parsed bag is missing. */
  headers: {
    cookie?: string
  }
  /** Parsed query string. We honour `prompt=login` as an override. */
  query: Record<string, unknown>
}

/** True if the request carries BOTH `dev-id` and `ses-id` cookies,
 *  meaning the browser has a full upstream device-session cookie pair
 *  on the pds-core side that the auth-service should defer to rather
 *  than re-prompting for credentials.
 *
 *  A half-pair (only `dev-id` or only `ses-id`) is a stale/divergent
 *  jar state — browser eviction, manual cookie deletion, or the
 *  remember=0 TTL split between the two cookies can all produce it.
 *  Upstream's DeviceManager cannot hydrate a session from a half-pair
 *  and rendering its fallback welcome page is the regression this
 *  Layer 1 check guards against; see docs/design/session-reuse-bugs.md.
 *  When only one cookie is present, we return false here so
 *  auth-service renders its email form, and the orphan cookie gets
 *  cleared further down the response pipeline.
 *
 *  Uses the parsed cookie bag first (which is produced by cookie-parser
 *  and normalised), then falls back to regex-scanning the raw Cookie
 *  header so we never miss an existing session even in configurations
 *  where cookie-parser is not mounted. */
export function hasDeviceSessionCookie(req: SessionReuseRequest): boolean {
  const hasFromBag = (name: string): boolean =>
    !!req.cookies && typeof req.cookies[name] === 'string'
  const raw = req.headers.cookie ?? ''
  const hasFromRaw = (name: string): boolean =>
    new RegExp(String.raw`(?:^|;\s*)${name}=`).test(raw)
  const hasDevId = hasFromBag('dev-id') || hasFromRaw('dev-id')
  const hasSesId = hasFromBag('ses-id') || hasFromRaw('ses-id')
  return hasDevId && hasSesId
}

/** Extract the raw `dev-id` and `ses-id` cookie values from the
 *  request. Mirrors {@link hasDeviceSessionCookie}'s parsed-bag-then-raw
 *  fallback so we never miss a cookie in configurations where
 *  cookie-parser is not mounted. Returns null when either cookie is
 *  missing or the raw header is malformed. */
export function readDeviceSessionCookies(
  req: SessionReuseRequest,
): { devId: string; sesId: string } | null {
  const fromBag = (name: string): string | null =>
    req.cookies && typeof req.cookies[name] === 'string'
      ? req.cookies[name]
      : null
  const fromRaw = (name: string): string | null => {
    const raw = req.headers.cookie ?? ''
    const m = raw.match(new RegExp(String.raw`(?:^|;\s*)${name}=([^;]*)`))
    if (!m) return null
    try {
      return decodeURIComponent(m[1])
    } catch {
      return null
    }
  }
  const devId = fromBag('dev-id') ?? fromRaw('dev-id')
  const sesId = fromBag('ses-id') ?? fromRaw('ses-id')
  if (!devId || !sesId) return null
  return { devId, sesId }
}

/** True if the request carries either `dev-id` or `ses-id` but not
 *  both — a divergent cookie jar that should trigger a cleanup-clear
 *  on the next response rather than being treated as a usable session.
 *
 *  Split out so callers can distinguish "fresh visitor, no cookies at
 *  all" (no action) from "orphan cookie needs clearing" (Set-Cookie
 *  with Max-Age=0) without duplicating the cookie-bag plumbing. */
export function hasOrphanDeviceCookie(req: SessionReuseRequest): {
  devId: boolean
  sesId: boolean
  isOrphan: boolean
} {
  const raw = req.headers.cookie ?? ''
  const hasDevId =
    (!!req.cookies && typeof req.cookies['dev-id'] === 'string') ||
    /(?:^|;\s*)dev-id=/.test(raw)
  const hasSesId =
    (!!req.cookies && typeof req.cookies['ses-id'] === 'string') ||
    /(?:^|;\s*)ses-id=/.test(raw)
  return {
    devId: hasDevId,
    sesId: hasSesId,
    isOrphan: hasDevId !== hasSesId,
  }
}

/** True if the client is asking the authorization server to force a
 *  fresh credential prompt. Maps to OIDC's standard `prompt=login`
 *  parameter (https://openid.net/specs/openid-connect-core-1_0.html
 *  #AuthRequest): "The Authorization Server SHOULD prompt the End-User
 *  for reauthentication". The capture-phase rebind of upstream's
 *  "Another account" button injected into the chooser in pds-core uses
 *  this to opt out of session reuse.
 *
 *  Delegates to the shared `promptHasLogin` so this check matches
 *  pds-core's auth-ui-guard exactly: both the space-delimited token
 *  case (`prompt=login consent`) and the array-of-strings case that
 *  Express produces from repeated query keys (`?prompt=login&prompt=consent`)
 *  are honoured. */
export function isForceLoginPrompt(req: SessionReuseRequest): boolean {
  return promptHasLogin(req.query.prompt)
}

/** Optional context for the hint-vs-bindings check that gates Flow 1
 *  session reuse. When a `login_hint` resolves to an email and the
 *  device has bound accounts, the auth-service must only reuse the
 *  session if the hinted email is one of those bindings — otherwise
 *  the chooser would either auto-select the wrong account (single
 *  binding) or surface the hinted user's mailbox to a stranger
 *  (multi-binding). On any miss we fall back to the email/OTP form,
 *  leaving the device cookies intact so other accounts on the device
 *  remain reusable on subsequent un-hinted visits.
 *
 *  - `resolvedEmail`: the lowercased email a `login_hint` resolved to,
 *    or null when there was no hint or it could not be resolved.
 *  - `deviceBoundEmails`: lowercased emails of every account bound to
 *    the current (dev-id, ses-id) cookie pair, or null when the pair
 *    was malformed/stale (in which case session reuse must be skipped
 *    irrespective of any hint).
 *
 *  When `resolvedEmail` is null the hint check is bypassed and the
 *  decision falls back to cookie presence — preserving the current
 *  no-hint behaviour. */
export type SessionReuseHintContext = {
  resolvedEmail?: string | null
  deviceBoundEmails?: string[] | null
}

/** True if the current /oauth/authorize request should be redirected to
 *  pds-core's upstream /oauth/authorize for session-reuse handling,
 *  bypassing the ePDS email/OTP form. */
export function shouldReuseSession(
  req: SessionReuseRequest,
  hintCtx?: SessionReuseHintContext,
): boolean {
  if (isForceLoginPrompt(req)) return false
  if (!hasDeviceSessionCookie(req)) return false
  // No hint to compare against: fall back to cookie-presence-only logic.
  const resolvedEmail = hintCtx?.resolvedEmail
  if (!resolvedEmail) return true
  // Hint present but caller didn't supply a bindings list (legacy call
  // sites): preserve existing behaviour rather than silently disabling
  // reuse.
  if (hintCtx.deviceBoundEmails === undefined) return true
  // Hint present and caller could not resolve a bindings list (cookie
  // pair was malformed or stale at pds-core): treat as no usable session.
  if (hintCtx.deviceBoundEmails === null) return false
  // Lowercase both sides at comparison time. The current producer
  // (pds-core's loadDeviceAccountEmails) already normalises, but the
  // type is `string[]` and a future caller could supply mixed-case
  // bindings — re-normalising here keeps the gate's correctness
  // independent of producer discipline.
  const target = resolvedEmail.toLowerCase()
  return hintCtx.deviceBoundEmails.some((e) => e.toLowerCase() === target)
}

/** Derive the shared parent domain that pds-core's cookie-domain
 *  middleware uses when broadening upstream device-session cookies, so
 *  auth-service can emit matching `Domain=` clears when it detects an
 *  orphan half-pair. Duplicates the relationship rule in pds-core's
 *  `cookie-domain.ts` intentionally — these helpers run in different
 *  packages and must stay in lockstep; a divergence here resurfaces
 *  the Layer 1 regression (orphan survives, half-pair bounce loops).
 *  Returns null when the hosts are unrelated (e.g. Railway preview
 *  envs) or identical (cookies already readable without a Domain). */
export function deriveSharedCookieDomain(
  authHostname: string,
  pdsHostname: string,
): string | null {
  if (!authHostname || !pdsHostname) return null
  if (authHostname === pdsHostname) return null
  if (authHostname.endsWith(`.${pdsHostname}`)) return pdsHostname
  return null
}

/** Minimal response shape that
 *  {@link appendOrphanDeviceCookieClearHeaders} needs. Mirrors the
 *  narrow interface used by the cookie-domain middleware. */
export interface OrphanClearResponse {
  append: (name: string, value: string) => unknown
}

/** Emit Max-Age=0 Set-Cookie headers that clear dev-id and ses-id
 *  (plus their `:hash` sidecars) in both host-only and domain-scoped
 *  variants. Browsers treat each scope as a distinct cookie — clearing
 *  only one leaves the other behind. We clear all four names
 *  unconditionally (not just the orphan half) because the caller has
 *  already confirmed we're in an orphan state; purging is idempotent
 *  and simpler than branching. The `:hash` sidecars only materialise
 *  when upstream has cookie signing keys configured (which ePDS doesn't
 *  do today), but the set matches `DEVICE_COOKIE_NAMES` in pds-core so
 *  a future upstream change can't leave orphan sidecars behind. */
export function appendOrphanDeviceCookieClearHeaders(
  res: OrphanClearResponse,
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

/** Build the pds-core /oauth/authorize URL to redirect to, preserving
 *  the full original query string unmodified. pds-core's upstream
 *  middleware uses request_uri to look up the PAR request and
 *  login_hint to auto-select a matching session. */
export function buildPdsAuthorizeRedirect(
  pdsPublicUrl: string,
  query: Record<string, unknown>,
): string {
  const target = new URL('/oauth/authorize', pdsPublicUrl)
  for (const [k, v] of Object.entries(query)) {
    if (typeof v === 'string') {
      target.searchParams.set(k, v)
    } else if (Array.isArray(v)) {
      for (const one of v) {
        if (typeof one === 'string') target.searchParams.append(k, one)
      }
    }
  }
  return target.toString()
}
