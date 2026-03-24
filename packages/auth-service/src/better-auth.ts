/**
 * Better Auth configuration for the auth service.
 *
 * This module creates and exports a better-auth instance configured with:
 * - Email OTP plugin (for future migration from custom OTP implementation)
 * - Social providers (Google, GitHub — only when env vars are set)
 * - Session lifetime from env vars
 *
 * The instance is mounted at /api/auth/* alongside the existing custom routes.
 * No existing behavior is changed — this is a foundation-only step.
 */
import type { EpdsDb } from '@certified-app/shared'
import { createLogger } from '@certified-app/shared'
import { betterAuth, APIError } from 'better-auth'
import { createAuthMiddleware } from 'better-auth/api'
import { generateRandomString } from 'better-auth/crypto'
import { getMigrations } from 'better-auth/db'
import { emailOTP } from 'better-auth/plugins'
import Database from 'better-sqlite3'
import type { EmailSender } from './email/sender.js'
import { getDidByEmail } from './lib/get-did-by-email.js'
import { ensurePdsUrl } from './lib/pds-url.js'

export type BetterAuthInstance = ReturnType<typeof createBetterAuth>

/**
 * Enforce ToS acceptance for new users on the OTP sign-in endpoint.
 *
 * Exported separately from createBetterAuth so it can be unit-tested directly
 * without instantiating a full better-auth instance.
 *
 * Called from hooks.before — fires on every better-auth request, so the path
 * guard is load-bearing (better-auth's matcher is hardcoded to `() => true`).
 *
 * Execution order: runBeforeHooks → endpoint (Zod validation + handler).
 * ctx.body therefore still contains raw pre-validation JSON, including any
 * tosAccepted field, before Zod strips unknown keys.
 *
 * PDS-unreachable behaviour: getDidByEmail never throws — it catches all
 * errors internally and returns null. A null DID is treated as a new user,
 * so ToS acceptance is still required. This is the safe default: we cannot
 * confirm the account exists, so we enforce consent.
 */
export async function enforceTosAcceptance(
  ctx: { path: string; body: unknown },
  pdsUrl: string,
  internalSecret: string,
): Promise<void> {
  // Path guard — this function is called on every better-auth request
  if (ctx.path !== '/sign-in/email-otp') return

  const rawEmail = (ctx.body as { email?: unknown } | undefined)?.email
  if (typeof rawEmail !== 'string') return // let better-auth's own schema validation reject it
  const email = rawEmail.trim().toLowerCase()
  if (!email) return // let better-auth's own schema validation reject it

  const did = await getDidByEmail(email, pdsUrl, internalSecret)
  const isNewUser = !did
  if (!isNewUser) return // returning users already accepted ToS at sign-up

  // New user (or PDS unreachable — null DID): require explicit ToS acceptance.
  // tosAccepted is sent as a JSON boolean by the client's verifyOtp().
  const tosAccepted = (ctx.body as { tosAccepted?: boolean } | undefined)
    ?.tosAccepted
  if (!tosAccepted) {
    throw new APIError('BAD_REQUEST', {
      message: 'You must accept the Terms of Service to create an account.',
    })
  }
}

const logger = createLogger('auth:better-auth')

const AUTH_FLOW_COOKIE = 'epds_auth_flow'

/**
 * Build the social providers config from env vars.
 * Only includes providers where both client ID and secret are set.
 */
function buildSocialProviders(): Record<
  string,
  { clientId: string; clientSecret: string }
> {
  const providers: Record<string, { clientId: string; clientSecret: string }> =
    {}

  const googleId = process.env.GOOGLE_CLIENT_ID
  const googleSecret = process.env.GOOGLE_CLIENT_SECRET
  if (googleId && googleSecret) {
    providers.google = { clientId: googleId, clientSecret: googleSecret }
  }

  const githubId = process.env.GITHUB_CLIENT_ID
  const githubSecret = process.env.GITHUB_CLIENT_SECRET
  if (githubId && githubSecret) {
    providers.github = { clientId: githubId, clientSecret: githubSecret }
  }

  return providers
}

/** Social providers that were configured — exported for use by the login page. */
export let socialProviders: Record<
  string,
  { clientId: string; clientSecret: string }
> = {}

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

  socialProviders = buildSocialProviders()

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

    session: {
      expiresIn: sessionExpiresIn,
      updateAge: sessionUpdateAge,
    },

    socialProviders,

    hooks: {
      before: createAuthMiddleware(async (ctx) => {
        const pdsUrl = ensurePdsUrl(
          process.env.PDS_INTERNAL_URL,
          `https://${process.env.PDS_HOSTNAME ?? 'localhost'}`,
        )
        const internalSecret = process.env.EPDS_INTERNAL_SECRET ?? ''
        await enforceTosAcceptance(ctx, pdsUrl, internalSecret)
      }),
    },

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
              // Log and swallow — caller does not await this
              logger.error(
                { err, email, isNewUser },
                'better-auth: failed to send OTP email',
              )
            })
        },
      }),
    ],
  })
}
