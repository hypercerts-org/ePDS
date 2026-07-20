/**
 * Resend email webhook receiver.
 *
 * The route consumes the untouched request body, verifies Resend's Svix
 * signature before inspecting the payload, accepts only email events used by
 * ePDS, and emits one structured log entry per event. Resend may retry the same
 * source ID (logged as `eventId`) and may deliver an email's events out of
 * order, so log consumers must deduplicate and order events when calculating
 * latency.
 */
import express, { Router } from 'express'
import addressparser from 'nodemailer/lib/addressparser/index.js'
import { Webhook } from 'svix'
import { createLogger } from '@certified-app/shared'

const logger = createLogger('auth:email-webhook')

export const RESEND_WEBHOOK_PATH = '/webhooks/resend'

const LOGGED_RESEND_EVENT_TYPES = [
  'email.sent',
  'email.delivered',
  'email.delivery_delayed',
  'email.opened',
  'email.bounced',
  'email.failed',
  'email.complained',
  'email.suppressed',
  'email.scheduled',
] as const

const IGNORED_RESEND_EVENT_TYPES = ['email.clicked', 'email.received'] as const
const RESEND_EVENT_TYPES = [
  ...LOGGED_RESEND_EVENT_TYPES,
  ...IGNORED_RESEND_EVENT_TYPES,
] as const

const WARNING_RESEND_EVENT_TYPES = [
  'email.delivery_delayed',
  'email.complained',
  'email.suppressed',
] as const

type LoggedResendEventType = (typeof LOGGED_RESEND_EVENT_TYPES)[number]
type ResendEventType = (typeof RESEND_EVENT_TYPES)[number]
type EmailEventType =
  | 'sent'
  | 'delivered'
  | 'delayed'
  | 'opened'
  | 'bounced'
  | 'failed'
  | 'complained'
  | 'suppressed'
  | 'scheduled'
type OtpCharset = 'numeric' | 'alphanumeric'

const NORMALIZED_EVENT_TYPES: Record<LoggedResendEventType, EmailEventType> = {
  'email.sent': 'sent',
  'email.delivered': 'delivered',
  'email.delivery_delayed': 'delayed',
  'email.opened': 'opened',
  'email.bounced': 'bounced',
  'email.failed': 'failed',
  'email.complained': 'complained',
  'email.suppressed': 'suppressed',
  'email.scheduled': 'scheduled',
}

interface ResendEvent {
  type: ResendEventType
  created_at: string
  data: {
    email_id: string
    to: [string, ...string[]]
    from: string
    subject: string
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function parseSingleEmailAddress(value: string): string | null {
  try {
    const addresses = addressparser(value, { flatten: true })
    if (addresses.length !== 1) return null
    const address = addresses[0]?.address.trim().toLowerCase()
    return address || null
  } catch (err) {
    logger.warn({ err }, 'Failed to parse email sender address')
    return null
  }
}

function isResendEvent(value: unknown): value is ResendEvent {
  if (!isRecord(value) || !isRecord(value.data)) return false

  const data = value.data
  return (
    typeof value.type === 'string' &&
    (RESEND_EVENT_TYPES as readonly string[]).includes(value.type) &&
    typeof value.created_at === 'string' &&
    Number.isFinite(Date.parse(value.created_at)) &&
    typeof data.email_id === 'string' &&
    Array.isArray(data.to) &&
    data.to.length > 0 &&
    data.to.every((recipient) => typeof recipient === 'string') &&
    typeof data.from === 'string' &&
    typeof data.subject === 'string'
  )
}

interface SvixHeaders {
  'svix-id': string
  'svix-timestamp': string
  'svix-signature': string
}

type VerificationResult =
  | { ok: true; headers: SvixHeaders; event: ResendEvent }
  | {
      ok: false
      error:
        | 'Invalid webhook request'
        | 'Invalid webhook signature'
        | 'Invalid webhook payload'
    }

function getSvixHeaders(req: express.Request): SvixHeaders | null {
  const id = req.get('svix-id')
  const timestamp = req.get('svix-timestamp')
  const signature = req.get('svix-signature')
  if (!id || !timestamp || !signature) return null
  return {
    'svix-id': id,
    'svix-timestamp': timestamp,
    'svix-signature': signature,
  }
}

function verifyResendWebhook(
  req: express.Request,
  verifier: Webhook,
): VerificationResult {
  const headers = getSvixHeaders(req)
  if (!headers || !Buffer.isBuffer(req.body)) {
    return { ok: false, error: 'Invalid webhook request' }
  }

  let payload: unknown
  try {
    payload = verifier.verify(req.body, headers)
  } catch (err) {
    logger.warn(
      { err, provider: 'resend', eventId: headers['svix-id'] },
      'Rejected email webhook with invalid signature',
    )
    return { ok: false, error: 'Invalid webhook signature' }
  }

  if (!isResendEvent(payload)) {
    logger.warn(
      { provider: 'resend', eventId: headers['svix-id'] },
      'Rejected invalid email webhook payload',
    )
    return { ok: false, error: 'Invalid webhook payload' }
  }
  return { ok: true, headers, event: payload }
}

const NUMERIC_OTP_CANDIDATE =
  /(^|\D)((?:\d{3,4}(?: \d{3,4}){1,3}|\d{4,12}))(?!\d)/g
const ALPHANUMERIC_OTP_CANDIDATE =
  /(^|[^A-Za-z0-9])((?:[A-Z0-9]{3,4}(?: [A-Z0-9]{3,4}){1,3}|[A-Z0-9]{4,12}))(?![A-Za-z0-9])/g

function otpGroupSize(length: number): number | null {
  if (length < 8) return null
  if (length % 4 === 0) return 4
  if (length % 3 === 0) return 3
  return null
}

function isOtpCandidate(candidate: string, otpLength: number): boolean {
  const raw = candidate.replaceAll(' ', '')
  if (raw.length !== otpLength) return false
  if (!candidate.includes(' ')) return true

  const groupSize = otpGroupSize(otpLength)
  if (!groupSize) return false
  const groups = candidate.split(' ')
  return (
    groups.length === otpLength / groupSize &&
    groups.every((group) => group.length === groupSize)
  )
}

function redactOtpFromSubject(
  subject: string,
  otpLength: number,
  otpCharset: OtpCharset,
): string {
  const pattern =
    otpCharset === 'numeric'
      ? NUMERIC_OTP_CANDIDATE
      : ALPHANUMERIC_OTP_CANDIDATE
  return subject.replace(
    pattern,
    (match: string, prefix: string, candidate: string) =>
      isOtpCandidate(candidate, otpLength) ? `${prefix}[REDACTED]` : match,
  )
}

function isLoggedResendEvent(
  event: ResendEvent,
): event is ResendEvent & { type: LoggedResendEventType } {
  return (LOGGED_RESEND_EVENT_TYPES as readonly string[]).includes(event.type)
}

function logResendEvent(
  event: ResendEvent & { type: LoggedResendEventType },
  svixId: string,
  otpLength: number,
  otpCharset: OtpCharset,
): void {
  const fields = {
    provider: 'resend',
    eventId: svixId,
    eventType: NORMALIZED_EVENT_TYPES[event.type],
    occurredAt: event.created_at,
    messageId: event.data.email_id,
    email: event.data.to[0],
    subject: redactOtpFromSubject(event.data.subject, otpLength, otpCharset),
  }
  const message = 'Received email event'
  if ((WARNING_RESEND_EVENT_TYPES as readonly string[]).includes(event.type)) {
    logger.warn(fields, message)
  } else {
    logger.info(fields, message)
  }
}

export function createResendWebhookRouter(
  webhookSecret: string,
  expectedFrom: string,
  otpLength: number,
  otpCharset: OtpCharset,
): Router {
  const router = Router()
  const verifier = new Webhook(webhookSecret)
  const expectedFromAddress = parseSingleEmailAddress(expectedFrom)
  if (!expectedFromAddress) {
    throw new Error('RESEND_WEBHOOK_SECRET requires a valid SMTP_FROM address')
  }

  router.post(
    RESEND_WEBHOOK_PATH,
    express.raw({ type: 'application/json', limit: '64kb' }),
    (req, res) => {
      const result = verifyResendWebhook(req, verifier)
      if (!result.ok) {
        res.status(400).json({ error: result.error })
        return
      }

      const eventId = result.headers['svix-id']
      if (!isLoggedResendEvent(result.event)) {
        logger.debug(
          {
            provider: 'resend',
            eventId,
            eventType: result.event.type.slice('email.'.length),
          },
          'Ignored unsupported email webhook event',
        )
        res.status(200).json({ received: true, ignored: true })
        return
      }

      const eventFromAddress = parseSingleEmailAddress(result.event.data.from)
      if (eventFromAddress !== expectedFromAddress) {
        logger.debug(
          { provider: 'resend', eventId },
          'Ignored email webhook for another sender',
        )
        res.status(200).json({ received: true, ignored: true })
        return
      }

      logResendEvent(result.event, eventId, otpLength, otpCharset)
      res.status(200).json({ received: true })
    },
  )

  return router
}
