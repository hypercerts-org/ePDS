/**
 * better-auth plugin that lets the login page drive the email-OTP endpoints
 * without ever holding the account's email address.
 *
 * When the OAuth `login_hint` is a handle or DID, `GET /oauth/authorize`
 * resolves it to the account's email and stores it on the `auth_flow` row.
 * Rendering that address into the page would let anyone who knows a handle
 * read the owner's private email, so the page sends `{ useFlowEmail: true }`
 * instead and this hook swaps the stored address in before better-auth sees
 * the request.
 *
 * Hook placement: better-auth's router runs every plugin's `onRequest`
 * before its rate limiter, origin check and endpoint handler, and passes the
 * request we return to all of them. So the rewritten request is rate limited
 * by IP and path, origin-checked, and handled by the stock endpoint (which
 * sets the session cookie) exactly as if the browser had sent the email.
 * Nothing else about the request changes. The one exception is the hook's
 * own 400/500 answers, which are returned before the limiter and so are not
 * counted by it; they cost a bounded body read and one SQLite point read.
 *
 * Scope is deliberately narrow:
 * - only the two OTP endpoints the login page calls;
 * - only when the body has `useFlowEmail: true` and no `email` key — a
 *   browser-supplied email is never overridden;
 * - everything else is returned untouched.
 */
import type { BetterAuthPlugin } from 'better-auth'
import { createLogger, type EpdsDb } from '@certified-app/shared'
import { AUTH_FLOW_COOKIE } from './auth-flow.js'

const logger = createLogger('auth:flow-email')

/**
 * Error `code` the login page recognises as "the server no longer holds an
 * email for this sign-in" and answers by showing the email entry step.
 */
export const FLOW_EMAIL_UNAVAILABLE_CODE = 'EPDS_FLOW_EMAIL_UNAVAILABLE'

const FLOW_EMAIL_UNAVAILABLE_MESSAGE =
  "We couldn't find the email for this sign-in. Enter your email address to continue."

/** Endpoint paths, relative to the better-auth base path, the page calls. */
const FLOW_EMAIL_PATHS = new Set([
  '/email-otp/send-verification-otp',
  '/sign-in/email-otp',
])

/**
 * The login page's bodies are a few dozen bytes. This hook runs before
 * better-auth's rate limiter, so it must not buffer an arbitrarily large
 * body from an unauthenticated caller; anything bigger passes through
 * untouched and fails better-auth's own validation. The cap is enforced on
 * the bytes actually read rather than on a `content-length` header, which a
 * proxy may omit and a client may misstate.
 */
const MAX_BODY_BYTES = 4096

type HookResult = { request: Request } | { response: Response } | undefined

/** The slice of better-auth's context the hook needs (`AuthContext` satisfies it). */
interface HookContext {
  baseURL: string
}

/**
 * `/api/auth/sign-in/email-otp` → `/sign-in/email-otp`, given the base URL's
 * path. Exact, like better-auth's router, which 404s a trailing slash.
 */
function pathWithinBase(request: Request, ctx: HookContext): string {
  const basePath = new URL(ctx.baseURL).pathname
  const pathname = new URL(request.url).pathname
  return pathname.startsWith(basePath + '/')
    ? pathname.slice(basePath.length)
    : pathname
}

/**
 * Read at most `limit` bytes of `clone`'s body as text, or null if it is
 * empty or longer. Stops reading as soon as the limit is crossed, so an
 * oversized body is never buffered here.
 */
async function readBoundedText(
  clone: Request,
  limit: number,
): Promise<string | null> {
  // Request bodies are byte streams; the DOM typings leave the chunk `any`.
  const reader = clone.body?.getReader() as
    | ReadableStreamDefaultReader<Uint8Array>
    | undefined
  if (!reader) return null
  const chunks: Uint8Array[] = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > limit) {
      // Not awaited: a tee'd branch's cancel() only settles once the other
      // branch (the original request, which better-auth still has to read)
      // is cancelled too, so awaiting it would hang here.
      void reader.cancel().catch(() => undefined)
      return null
    }
    chunks.push(value)
  }
  return Buffer.concat(chunks).toString('utf8')
}

/**
 * Parse a small JSON object body from a clone, leaving `request`'s own
 * body unread so it can still be passed through. Returns null for
 * anything that isn't a bounded JSON object.
 */
async function readSmallJsonObject(
  request: Request,
): Promise<Record<string, unknown> | null> {
  const contentType = request.headers.get('content-type')?.toLowerCase()
  if (!contentType?.includes('application/json')) return null
  try {
    const text = await readBoundedText(request.clone(), MAX_BODY_BYTES)
    const parsed: unknown = text === null ? null : JSON.parse(text)
    return typeof parsed === 'object' &&
      parsed !== null &&
      !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null
  } catch {
    return null
  }
}

/**
 * The `epds_auth_flow` cookie's value, or null if it is absent or appears
 * more than once.
 *
 * Duplicates are ambiguous, and the rest of the app (cookie-parser: first
 * wins) resolves them differently from better-auth's parser (last wins). The
 * hook has to act on the same flow `/auth/complete` will, so refuse to pick
 * one. Flow ids are hex, so no URL-decoding is needed.
 */
function readFlowCookie(cookieHeader: string): string | null {
  const values = cookieHeader.split(';').flatMap((pair) => {
    const eq = pair.indexOf('=')
    // Compare the trimmed name exactly, as cookie-parser does, so a cookie
    // it would count (`epds_auth_flow =x`) is counted here too.
    return eq >= 0 && pair.slice(0, eq).trim() === AUTH_FLOW_COOKIE
      ? [pair.slice(eq + 1).trim()]
      : []
  })
  return values.length === 1 ? values[0] : null
}

function readFlowEmail(
  request: Request,
  db: Pick<EpdsDb, 'getAuthFlowLoginHintEmail'>,
): string | null {
  const cookieHeader = request.headers.get('cookie')
  const flowId = cookieHeader ? readFlowCookie(cookieHeader) : null
  return flowId ? db.getAuthFlowLoginHintEmail(flowId) : null
}

function withEmail(
  request: Request,
  body: Record<string, unknown>,
  email: string,
): Request {
  const { useFlowEmail: _useFlowEmail, ...rest } = body
  const headers = new Headers(request.headers)
  // The body length changes; a stale content-length would misdescribe it.
  headers.delete('content-length')
  return new Request(request.url, {
    method: request.method,
    headers,
    body: JSON.stringify({ ...rest, email }),
  })
}

/**
 * The `onRequest` hook, exported separately from the plugin so tests can
 * drive it without constructing a full better-auth context.
 */
export function createFlowEmailHook(
  db: Pick<EpdsDb, 'getAuthFlowLoginHintEmail'>,
): (request: Request, ctx: HookContext) => Promise<HookResult> {
  return async (request, ctx) => {
    if (request.method !== 'POST') return undefined
    const path = pathWithinBase(request, ctx)
    if (!FLOW_EMAIL_PATHS.has(path)) return undefined

    const body = await readSmallJsonObject(request)
    if (body?.useFlowEmail !== true || 'email' in body) return undefined

    let email: string | null
    try {
      email = readFlowEmail(request, db)
    } catch (err) {
      // An exception escaping onRequest is not caught by better-auth's
      // router, so answer here rather than leave the request hanging.
      logger.error({ err, path }, 'Failed to read the auth_flow email')
      return {
        response: Response.json(
          { message: 'Internal server error. Please try again.' },
          { status: 500 },
        ),
      }
    }
    if (!email) {
      // Debug, not info: callers need no valid flow to reach this branch, and
      // it answers before better-auth's rate limiter, so an info line per
      // request would be attacker-controlled log volume.
      logger.debug(
        { path },
        'useFlowEmail requested but the auth_flow has no usable stored email (no or duplicate cookie, unknown or expired flow)',
      )
      return {
        response: Response.json(
          {
            code: FLOW_EMAIL_UNAVAILABLE_CODE,
            message: FLOW_EMAIL_UNAVAILABLE_MESSAGE,
          },
          { status: 400 },
        ),
      }
    }

    return { request: withEmail(request, body, email) }
  }
}

export function flowEmailPlugin(
  db: Pick<EpdsDb, 'getAuthFlowLoginHintEmail'>,
): BetterAuthPlugin {
  return {
    id: 'epds-flow-email',
    onRequest: createFlowEmailHook(db),
  }
}
