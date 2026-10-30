/**
 * Better Auth configuration for the auth service.
 *
 * This module creates and exports a better-auth instance configured with:
 * - Email OTP plugin (for future migration from custom OTP implementation)
 * - Social providers (Google, GitHub — only when env vars are set)
 * - Session lifetime from env vars
 * - An `after` hook that surfaces OTP verification failures in our logs,
 *   with the user's email attached (see logOtpVerificationFailure below)
 *
 * The instance is mounted at /api/auth/* alongside the existing custom routes.
 */
import type { EpdsDb } from '@certified-app/shared'
import { createLogger } from '@certified-app/shared'
import { betterAuth } from 'better-auth'
import { APIError, createAuthMiddleware } from 'better-auth/api'
import { generateRandomString } from 'better-auth/crypto'
import { getMigrations } from 'better-auth/db'
import { emailOTP } from 'better-auth/plugins'
import type { GithubOptions, GoogleOptions } from 'better-auth/social-providers'
import Database from 'better-sqlite3'
import type { EmailSender } from './email/sender.js'
import { getDidByEmail } from './lib/get-did-by-email.js'
import { mapGoogleProfileToUser } from './lib/google-email-verified.js'
import { ensurePdsUrl } from './lib/pds-url.js'
import { hasVerifiedEmail } from './lib/verified-email.js'

export type BetterAuthInstance = ReturnType<typeof createBetterAuth>

/** The logger type used across this module — avoids a direct pino dependency. */
type BetterAuthLogger = ReturnType<typeof createLogger>

const logger = createLogger('auth:better-auth')

/**
 * Map a better-auth OTP reason string to a self-contained log message.
 *
 * better-auth's own messages ("OTP expired", "Invalid OTP", "Too many
 * attempts") are terse and, out of context, ambiguous — "Too many attempts"
 * alone doesn't say attempts at what. We map each to a message that stands on
 * its own in a log line, sharing an "OTP verification failed:" prefix so the
 * whole class is greppable while each reason stays distinct at a glance.
 *
 * Mapping here (rather than logging better-auth's string verbatim) also
 * decouples our logs from better-auth's exact wording: if a future version
 * renames a reason, our log messages don't silently change.
 *
 * Note on "Invalid OTP": better-auth throws it both for a wrong code and for
 * no pending code at all, so the message says "invalid or unrecognized" rather
 * than implying only a typo. The two cases remain indistinguishable in the log.
 * "Too many attempts" additionally deletes the stored code (better-auth 1.4.18
 * dist/plugins/email-otp/routes.mjs), which the message reflects.
 */
const OTP_FAILURE_MESSAGES: Record<string, string> = {
  'OTP expired': 'OTP verification failed: code expired',
  'Invalid OTP': 'OTP verification failed: invalid or unrecognized code',
  'Too many attempts':
    'OTP verification failed: too many attempts, code invalidated',
}

const OTP_FAILURE_FALLBACK = 'OTP verification failed'

/**
 * Surface a better-auth OTP verification failure in our own logs, with the
 * user's email attached.
 *
 * The main OAuth login flow posts straight from the browser to
 * /api/auth/sign-in/email-otp, handled by better-auth's node handler. On
 * verification failure better-auth throws a 4xx `APIError` whose message is the
 * exact reason — "OTP expired", "Invalid OTP" or "Too many attempts". These are
 * the only signal distinguishing a genuinely-late email (expired) from a user
 * retyping a stale code (invalid), so we log them to make the split countable
 * over time. Expired / invalid codes are routine user error and log at `info`;
 * a 403 (too many attempts) can signal brute-forcing and logs at `warn`. Both
 * levels are visible at prod's default `info` level.
 *
 * Unlike better-auth's instance-wide `onAPIError` hook, this runs from an
 * `after` middleware that receives the per-request endpoint context, so the
 * request body — and hence `email` — is available. Fields are ordered for a
 * developer debugging a specific failure: email (who) first, then statusCode
 * (a quick 400/403 split), then path. The reason lives in the message, so it is
 * not duplicated as a field. The `err` object is deliberately omitted: for 4xx
 * client errors the mapped message already captures the cause, and the full
 * APIError (with stack) is noise in Railway's logfmt rendering.
 *
 * Only 4xx `APIError`s are logged. 3xx redirects (status "FOUND") are filtered
 * by better-auth before the after hook runs, and 5xx errors are already logged
 * by better-auth's own error handler; both are skipped to avoid double-logging.
 * Non-`APIError` values (e.g. a successful response) are ignored.
 */
export function logOtpVerificationFailure(
  error: unknown,
  email: unknown,
  path: string,
  log: BetterAuthLogger,
): void {
  if (!(error instanceof APIError)) return

  const statusCode = error.statusCode
  if (statusCode < 400 || statusCode >= 500) return

  const reason = error.body?.message ?? error.message
  // Unmapped reasons keep the shared "OTP verification failed:" prefix (so the
  // whole class stays greppable) and append the raw reason for context.
  const message =
    OTP_FAILURE_MESSAGES[reason] ?? `${OTP_FAILURE_FALLBACK}: ${reason}`

  // Expired / invalid codes are routine user error, so they log at `info`.
  // A 403 (too many attempts) is the one outcome that can signal brute-forcing
  // rather than a fumble, so it warrants `warn`.
  const level = statusCode === 403 ? 'warn' : 'info'

  log[level](
    {
      email: typeof email === 'string' ? email : undefined,
      statusCode,
      path,
    },
    message,
  )
}

/**
 * OTP *verification* endpoints whose 4xx failures we log with the user's email.
 *
 * This is an explicit allowlist rather than a `/email-otp/*` prefix match,
 * because that prefix also covers the OTP *send* endpoints
 * (`/email-otp/send-verification-otp`, `/email-otp/request-password-reset`),
 * whose failures are not verification failures and would be mislabelled.
 */
const OTP_VERIFY_PATHS = new Set([
  '/sign-in/email-otp',
  '/email-otp/check-verification-otp',
  '/email-otp/verify-email',
  '/email-otp/reset-password',
])

export function isOtpVerifyPath(path: string): boolean {
  return OTP_VERIFY_PATHS.has(path)
}

const AUTH_FLOW_COOKIE = 'epds_auth_flow'

/** The social providers passed to better-auth, keyed by provider id. */
export interface SocialProvidersConfig {
  google?: GoogleOptions
  github?: GithubOptions
}

/**
 * Build the social providers config from env vars.
 * Only includes providers where both client ID and secret are set.
 *
 * Google's `email_verified` claim is not used as-is: `mapProfileToUser`
 * replaces it with a strict check that also requires Google to be
 * authoritative for the address (see lib/google-email-verified.ts).
 */
export function buildSocialProviders(
  env: NodeJS.ProcessEnv = process.env,
): SocialProvidersConfig {
  const providers: SocialProvidersConfig = {}

  const googleId = env.GOOGLE_CLIENT_ID
  const googleSecret = env.GOOGLE_CLIENT_SECRET
  if (googleId && googleSecret) {
    providers.google = {
      clientId: googleId,
      clientSecret: googleSecret,
      // Always show Google's account chooser. Otherwise Google silently
      // reuses whichever account the browser is signed in to, which may
      // not be the one the user meant to sign in with.
      prompt: 'select_account',
      mapProfileToUser: mapGoogleProfileToUser,
    }
  }

  const githubId = env.GITHUB_CLIENT_ID
  const githubSecret = env.GITHUB_CLIENT_SECRET
  if (githubId && githubSecret) {
    providers.github = { clientId: githubId, clientSecret: githubSecret }
  }

  return providers
}

/**
 * Social providers that were configured — exported for use by the login
 * page. createBetterAuth refills this object in place, so importers always
 * see the providers of the running instance.
 */
export const socialProviders: SocialProvidersConfig = {}

/**
 * The message better-auth reports when {@link refuseUnverifiedUser} refuses
 * a user. Its OAuth callback turns it into `?error=email_not_verified` on
 * the errorCallbackURL; its ID-token sign-in returns it as a 401.
 */
export const EMAIL_NOT_VERIFIED = 'email not verified'

/**
 * better-auth `databaseHooks.user.create.before`: never create a user whose
 * email address is not verified.
 *
 * Email OTP always creates verified users (the code proves the address), so
 * in practice this refuses social sign-ins whose provider does not vouch
 * for the email. Such a sign-in must not leave a user behind: an email-OTP
 * sign-in for that address later marks the existing user verified
 * (better-auth 1.4.18 email-otp), while the social identity stays linked to
 * it, so whoever controls the social account would from then on sign in as
 * the person who proved the address by email.
 */
export function refuseUnverifiedUser(user: {
  emailVerified?: unknown
}): Promise<void> {
  if (hasVerifiedEmail(user)) return Promise.resolve()
  return Promise.reject(
    new APIError('FORBIDDEN', { message: EMAIL_NOT_VERIFIED }),
  )
}

/** The `databaseHooks` ePDS passes to better-auth. */
export const databaseHooks = {
  user: {
    create: { before: refuseUnverifiedUser },
  },
}

/**
 * Create a better-auth instance wired to the given EmailSender and EpdsDb.
 *
 * Called once during app startup from index.ts.
 * Returns `unknown` to avoid leaking the better-sqlite3 type into declaration files;
 * callers cast to the actual type via the `BetterAuthInstance` helper below.
 *
 * The `db` parameter is used to look up `auth_flow` rows during OTP sending
 * so that client branding can be applied based on the active OAuth flow.
 */
/**
 * Run better-auth migrations at startup — creates user, session, account,
 * and verification tables if they don't exist yet. Safe to call on every
 * startup (no-ops when tables are already present).
 *
 * The otpLength parameter is accepted for API consistency but does not affect
 * the schema — better-auth stores OTP codes as hashed strings regardless of
 * length, so the column definition is the same for any valid otpLength.
 */
export async function runBetterAuthMigrations(
  dbLocation: string,
  authHostname: string,
  otpLength: number,
  otpCharset: 'numeric' | 'alphanumeric' = 'numeric',
): Promise<void> {
  const betterAuthDb = new Database(dbLocation)
  const tempAuth = betterAuth({
    secret: process.env.AUTH_SESSION_SECRET,
    database: betterAuthDb,
    baseURL: `https://${authHostname}`,
    basePath: '/api/auth',
    plugins: [
      emailOTP({
        otpLength,
        expiresIn: 600,
        allowedAttempts: 5,
        storeOTP: 'hashed',
        ...(otpCharset === 'alphanumeric'
          ? { generateOTP: () => generateRandomString(otpLength, 'A-Z', '0-9') }
          : {}),
        async sendVerificationOTP() {},
      }),
    ],
  })
  const { toBeCreated, toBeAdded, runMigrations } = await getMigrations(
    tempAuth.options,
  )
  if (toBeCreated.length > 0 || toBeAdded.length > 0) {
    logger.info(
      {
        toBeCreated: toBeCreated.map((t) => t.table),
        toBeAdded: toBeAdded.map((t) => t.table),
      },
      'Running better-auth migrations',
    )
    await runMigrations()
    logger.info('better-auth migrations complete')
  } else {
    logger.info('better-auth schema up to date, no migrations needed')
  }
  betterAuthDb.close()
}

export function createBetterAuth(
  emailSender: EmailSender,
  db: EpdsDb,
  otpLength: number,
  otpCharset: 'numeric' | 'alphanumeric' = 'numeric',
) {
  const dbLocation = process.env.DB_LOCATION ?? './data/epds.sqlite'
  const authHostname = process.env.AUTH_HOSTNAME ?? 'auth.localhost'
  const pdsName = process.env.SMTP_FROM_NAME ?? 'ePDS'
  const pdsDomain = process.env.PDS_HOSTNAME ?? 'localhost'

  // Session lifetime from env (in seconds, default 7 days / 1 day update age)
  const sessionExpiresIn = parseInt(
    process.env.SESSION_EXPIRES_IN ?? String(7 * 24 * 60 * 60),
    10,
  )
  const sessionUpdateAge = parseInt(
    process.env.SESSION_UPDATE_AGE ?? String(24 * 60 * 60),
    10,
  )

  delete socialProviders.google
  delete socialProviders.github
  Object.assign(socialProviders, buildSocialProviders())

  const betterAuthDb = new Database(dbLocation)

  return betterAuth({
    // Use AUTH_SESSION_SECRET so better-auth doesn't fall back to its
    // default secret (which throws in production).
    secret: process.env.AUTH_SESSION_SECRET,
    // TS4058: BetterSqlite3.Database leaks into the inferred return type when
    // passed directly; casting to `any` breaks the inference chain so declaration
    // emit succeeds without casting the entire createBetterAuth return value.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    database: betterAuthDb as any,
    baseURL: `https://${authHostname}`,
    basePath: '/api/auth',

    // Surface OTP verification failures ("OTP expired" vs "Invalid OTP" vs
    // "Too many attempts") in our pino logs, with the user's email attached.
    //
    // This uses an `after` middleware rather than the instance-wide
    // `onAPIError` hook because only the per-request endpoint context exposes
    // the request body (and hence the email). The after hook runs, then
    // better-auth re-throws the APIError, so the HTTP response is unchanged.
    // See logOtpVerificationFailure above.
    hooks: {
      // createAuthMiddleware's handler type requires a Promise return. Our
      // logging is synchronous, so the callback stays non-async and returns a
      // resolved promise rather than suppressing the require-await lint.
      after: createAuthMiddleware((ctx) => {
        if (isOtpVerifyPath(ctx.path)) {
          logOtpVerificationFailure(
            ctx.context.returned,
            ctx.body?.email,
            ctx.path,
            logger,
          )
        }
        return Promise.resolve()
      }),
    },

    session: {
      expiresIn: sessionExpiresIn,
      updateAge: sessionUpdateAge,
    },

    databaseHooks,

    socialProviders,

    plugins: [
      emailOTP({
        otpLength,
        expiresIn: 600,
        allowedAttempts: 5,
        storeOTP: 'hashed',
        ...(otpCharset === 'alphanumeric'
          ? { generateOTP: () => generateRandomString(otpLength, 'A-Z', '0-9') }
          : {}),

        /**
         * Wire OTP sending to the existing EmailSender.
         *
         * Resolves client branding by reading the epds_auth_flow cookie from
         * the request context (if present) and looking up the auth_flow row to
         * get the client_id. Falls back to the default PDS template when no
         * client context is available (e.g. account settings login).
         *
         * Not awaited to avoid timing side-channels (fire and forget).
         */
        async sendVerificationOTP({ email, otp }, ctx) {
          // Determine whether this is a first-time sign-up or a returning user
          // by checking if a PDS account already exists for this email.
          const pdsUrl = ensurePdsUrl(
            process.env.PDS_INTERNAL_URL,
            `https://${process.env.PDS_HOSTNAME ?? 'localhost'}`,
          )
          const internalSecret = process.env.EPDS_INTERNAL_SECRET ?? ''
          const did = await getDidByEmail(email, pdsUrl, internalSecret)
          const isNewUser = !did

          // Try to resolve client_id from the active auth_flow via cookie
          let clientId: string | undefined
          try {
            const flowId = ctx?.getCookie(AUTH_FLOW_COOKIE) ?? null
            if (flowId) {
              const flow = db.getAuthFlow(flowId)
              if (flow?.clientId) {
                clientId = flow.clientId
              }
            }
          } catch (err) {
            // Non-fatal: cookie or DB lookup failure just means no branding
            logger.warn(
              { err, email },
              'Failed to resolve auth_flow for client branding',
            )
          }

          emailSender
            .sendOtpCode({
              to: email,
              code: otp,
              clientAppName: pdsName,
              clientId,
              pdsName,
              pdsDomain,
              isNewUser,
            })
            .catch((err: unknown) => {
              // Log and swallow — caller does not await this.
              // `EmailSender.timedSendMail` stamps the SMTP handoff
              // duration onto the error so this single line carries it.
              const elapsedMs =
                err instanceof Error
                  ? (err as Error & { elapsedMs?: number }).elapsedMs
                  : undefined
              logger.error(
                { err, email, isNewUser, elapsedMs },
                'better-auth: failed to send OTP email',
              )
            })
        },
      }),
    ],
  })
}
