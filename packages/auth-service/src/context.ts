import { createLogger } from '@magic-pds/shared'
import { MagicPdsDb } from '@magic-pds/shared'
import { MagicLinkTokenService } from './magic-link/token.js'
import { RateLimiter } from './magic-link/rate-limit.js'
import { EmailSender } from './email/sender.js'

export interface AuthServiceConfig {
  hostname: string
  port: number
  sessionSecret: string
  csrfSecret: string
  /** Shared HMAC-SHA256 secret for signing magic-callback redirect URLs. */
  magicCallbackSecret: string
  pdsHostname: string
  pdsPublicUrl: string
  magicLink: {
    expiryMinutes: number
    maxAttemptsPerToken: number
  }
  email: {
    provider: 'smtp' | 'sendgrid' | 'ses' | 'postmark'
    smtpHost?: string
    smtpPort?: number
    smtpUser?: string
    smtpPass?: string
    from: string
    fromName: string
  }
  dbLocation: string
}

const logger = createLogger('auth-service')

export class AuthServiceContext {
  public readonly db: MagicPdsDb
  public readonly tokenService: MagicLinkTokenService
  public readonly rateLimiter: RateLimiter
  public readonly emailSender: EmailSender
  public readonly config: AuthServiceConfig

  constructor(config: AuthServiceConfig) {
    this.config = config
    this.db = new MagicPdsDb(config.dbLocation)
    this.tokenService = new MagicLinkTokenService(this.db, config.magicLink)
    this.rateLimiter = new RateLimiter(this.db)
    this.emailSender = new EmailSender(config.email)

    // Cleanup expired tokens every 5 minutes
    setInterval(() => {
      const cleaned = this.tokenService.cleanup()
      if (cleaned > 0) {
        logger.debug({ cleaned }, 'Cleaned up expired magic link tokens')
      }
      const sessions = this.db.cleanupExpiredSessions()
      if (sessions > 0) {
        logger.debug({ sessions }, 'Cleaned up expired account sessions')
      }
      this.db.cleanupOldRateLimitEntries()
      this.db.cleanupOldOtpFailures()
    }, 5 * 60 * 1000)
  }

  destroy(): void {
    this.db.close()
  }
}
