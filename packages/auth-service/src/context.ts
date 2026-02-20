import { createLogger } from '@magic-pds/shared'
import { MagicPdsDb } from '@magic-pds/shared'
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
  public readonly emailSender: EmailSender
  public readonly config: AuthServiceConfig

  constructor(config: AuthServiceConfig) {
    this.config = config
    this.db = new MagicPdsDb(config.dbLocation)
    this.emailSender = new EmailSender(config.email)

    // Cleanup expired tokens every 5 minutes
    setInterval(() => {
      const flows = this.db.cleanupExpiredAuthFlows()
      if (flows > 0) {
        logger.debug({ flows }, 'Cleaned up expired auth flows')
      }
      this.db.cleanupOldRateLimitEntries()
      this.db.cleanupOldOtpFailures()
    }, 5 * 60 * 1000)
  }

  destroy(): void {
    this.db.close()
  }
}
