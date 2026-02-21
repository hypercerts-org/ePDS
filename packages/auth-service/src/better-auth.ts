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
import Database from 'better-sqlite3'
import { betterAuth } from 'better-auth'
import { getMigrations } from 'better-auth/db'
import { emailOTP } from 'better-auth/plugins'
import { createLogger } from '@certified-app/shared'
import type { EpdsDb } from '@certified-app/shared'
import type { EmailSender } from './email/sender.js'

const logger = createLogger('auth:better-auth')

const AUTH_FLOW_COOKIE = 'magic_auth_flow'

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
 */
export async function runBetterAuthMigrations(
  dbLocation: string,
  authHostname: string,
): Promise<void> {
  const betterAuthDb = new Database(dbLocation)
  const tempAuth = betterAuth({
    database: betterAuthDb,
    baseURL: `https://${authHostname}`,
    basePath: '/api/auth',
    plugins: [
      emailOTP({
        otpLength: 8,
        expiresIn: 600,
        allowedAttempts: 5,
        storeOTP: 'hashed',
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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function createBetterAuth(emailSender: EmailSender, db: EpdsDb): any {
  const dbLocation = process.env.DB_LOCATION ?? './data/epds.sqlite'
  const authHostname = process.env.AUTH_HOSTNAME ?? 'auth.localhost'
  const pdsName = process.env.SMTP_FROM_NAME ?? 'Magic PDS'
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
    database: betterAuthDb,
    baseURL: `https://${authHostname}`,
    basePath: '/api/auth',

    session: {
      expiresIn: sessionExpiresIn,
      updateAge: sessionUpdateAge,
    },

    socialProviders,

    plugins: [
      emailOTP({
        otpLength: 8,
        expiresIn: 600,
        allowedAttempts: 5,
        storeOTP: 'hashed',

        /**
         * Wire OTP sending to the existing EmailSender.
         *
         * Resolves client branding by reading the magic_auth_flow cookie from
         * the request context (if present) and looking up the auth_flow row to
         * get the client_id. Falls back to the default PDS template when no
         * client context is available (e.g. account settings login).
         *
         * Not awaited to avoid timing side-channels (fire and forget).
         */
        // eslint-disable-next-line @typescript-eslint/require-await -- better-auth requires Promise<void> return but OTP email is fire-and-forget
        async sendVerificationOTP({ email, otp, type }, ctx) {
          const isNewUser = type === 'sign-in'

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
                { err, email, type },
                'better-auth: failed to send OTP email',
              )
            })
        },
      }),
    ],
  })
}
