import { createLogger } from '@certified-app/shared'
import express from 'express'
import cookieParser from 'cookie-parser'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
const __dirname = path.dirname(fileURLToPath(import.meta.url))
import { toNodeHandler } from 'better-auth/node'
import { AuthServiceContext, type AuthServiceConfig } from './context.js'
import { createBetterAuth, runBetterAuthMigrations } from './better-auth.js'
import { csrfProtection } from './middleware/csrf.js'
import { requestRateLimit } from './middleware/rate-limit.js'
import { createLoginPageRouter } from './routes/login-page.js'
import { createConsentRouter } from './routes/consent.js'
import { createRecoveryRouter } from './routes/recovery.js'
import { createAccountLoginRouter } from './routes/account-login.js'
import { createAccountSettingsRouter } from './routes/account-settings.js'
import { createCompleteRouter } from './routes/complete.js'
import { createChooseHandleRouter } from './routes/choose-handle.js'

const logger = createLogger('auth-service')

/** Only allow hex color values like #fff, #3E7053, #3E705380 */
function isValidHexColor(val: string | undefined): val is string {
  return val != null && /^#[0-9a-fA-F]{3,8}$/.test(val)
}

export function createAuthService(config: AuthServiceConfig): {
  app: express.Express
  ctx: AuthServiceContext
} {
  const ctx = new AuthServiceContext(config)
  const app = express()

  // Mount better-auth BEFORE express.json() so it can parse its own request bodies.
  // All better-auth endpoints live under /api/auth/*.
  const betterAuthInstance = createBetterAuth(ctx.emailSender, ctx.db)
  app.all('/api/auth/*', toNodeHandler(betterAuthInstance))

  // Middleware
  app.set('trust proxy', 1)
  app.use(express.urlencoded({ extended: true }))
  app.use(express.json())
  app.use(cookieParser())
  app.use('/static', express.static(path.resolve(__dirname, '..', 'public')))
  app.use(csrfProtection(config.csrfSecret))
  app.use(requestRateLimit({ windowMs: 60_000, maxRequests: 60 }))

  // Security headers
  app.use((_req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'no-referrer')
    res.setHeader(
      'Content-Security-Policy',
      `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'`,
    )
    res.setHeader(
      'Strict-Transport-Security',
      'max-age=63072000; includeSubDomains; preload',
    )
    next()
  })

  // Routes
  app.use(createLoginPageRouter(ctx))
  app.use(createConsentRouter(ctx))
  app.use(createRecoveryRouter(ctx, betterAuthInstance))
  app.use(createAccountLoginRouter(betterAuthInstance))
  app.use(createAccountSettingsRouter(ctx, betterAuthInstance))
  app.use(createCompleteRouter(ctx, betterAuthInstance))
  app.use(createChooseHandleRouter(ctx, betterAuthInstance))

  // Metrics endpoint (protect with admin auth in production)
  app.get('/metrics', (req, res) => {
    const adminPassword = process.env.PDS_ADMIN_PASSWORD
    if (adminPassword) {
      const authHeader = req.headers.authorization
      if (
        !authHeader ||
        authHeader !==
          'Basic ' + Buffer.from('admin:' + adminPassword).toString('base64')
      ) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }
    }
    const metrics = ctx.db.getMetrics()
    res.json({
      ...metrics,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage().rss,
      timestamp: Date.now(),
    })
  })

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'auth' })
  })

  return { app, ctx }
}

// Entry point when run directly
async function main() {
  const config: AuthServiceConfig = {
    hostname: process.env.AUTH_HOSTNAME || 'auth.localhost',
    port: parseInt(process.env.AUTH_PORT || '3001', 10),
    sessionSecret:
      process.env.AUTH_SESSION_SECRET || 'dev-session-secret-change-me',
    csrfSecret: process.env.AUTH_CSRF_SECRET || 'dev-csrf-secret-change-me',
    epdsCallbackSecret:
      process.env.EPDS_CALLBACK_SECRET || 'dev-callback-secret-change-me',
    pdsHostname: process.env.PDS_HOSTNAME || 'localhost',
    pdsPublicUrl: process.env.PDS_PUBLIC_URL || 'http://localhost:3000',
    email: {
      provider: (process.env.EMAIL_PROVIDER || 'smtp') as 'smtp',
      smtpHost: process.env.SMTP_HOST || 'localhost',
      smtpPort: parseInt(process.env.SMTP_PORT || '1025', 10),
      smtpUser: process.env.SMTP_USER || undefined,
      smtpPass: process.env.SMTP_PASS || undefined,
      from: process.env.SMTP_FROM || 'noreply@localhost',
      fromName: process.env.SMTP_FROM_NAME || 'ePDS',
    },
    dbLocation: process.env.DB_LOCATION || './data/epds.sqlite',
    brandColor: isValidHexColor(process.env.AUTH_BRAND_COLOR)
      ? process.env.AUTH_BRAND_COLOR
      : undefined,
    backgroundColor: isValidHexColor(process.env.AUTH_BACKGROUND_COLOR)
      ? process.env.AUTH_BACKGROUND_COLOR
      : undefined,
    panelColor: isValidHexColor(process.env.AUTH_PANEL_COLOR)
      ? process.env.AUTH_PANEL_COLOR
      : undefined,
  }

  if (
    process.env.AUTH_BRAND_COLOR &&
    !isValidHexColor(process.env.AUTH_BRAND_COLOR)
  ) {
    logger.warn('AUTH_BRAND_COLOR rejected: must be a hex color (e.g. #3E7053)')
  }
  if (
    process.env.AUTH_BACKGROUND_COLOR &&
    !isValidHexColor(process.env.AUTH_BACKGROUND_COLOR)
  ) {
    logger.warn(
      'AUTH_BACKGROUND_COLOR rejected: must be a hex color (e.g. #3E7053)',
    )
  }
  if (
    process.env.AUTH_PANEL_COLOR &&
    !isValidHexColor(process.env.AUTH_PANEL_COLOR)
  ) {
    logger.warn('AUTH_PANEL_COLOR rejected: must be a hex color (e.g. #3E7053)')
  }

  await runBetterAuthMigrations(config.dbLocation, config.hostname)

  const { app, ctx } = createAuthService(config)

  const server = app.listen(config.port, () => {
    logger.info(
      { port: config.port, hostname: config.hostname },
      'Auth service running',
    )
  })

  const shutdown = () => {
    logger.info('Auth service shutting down')
    server.close()
    ctx.destroy()
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

void main()
