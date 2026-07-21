import { beforeEach, describe, expect, it, vi } from 'vitest'
import express from 'express'
import { Webhook } from 'svix'

const { logDebug, logInfo, logWarn } = vi.hoisted(() => ({
  logDebug: vi.fn(),
  logInfo: vi.fn(),
  logWarn: vi.fn(),
}))

vi.mock('@certified-app/shared', () => ({
  createLogger: () => ({ debug: logDebug, info: logInfo, warn: logWarn }),
}))

import { createResendWebhookRouter } from '../routes/resend-webhook.js'

const WEBHOOK_SECRET = `whsec_${Buffer.from('test-webhook-secret').toString(
  'base64',
)}`

beforeEach(() => {
  logDebug.mockClear()
  logInfo.mockClear()
  logWarn.mockClear()
})

function makeEvent(type = 'email.sent'): Record<string, unknown> {
  return {
    type,
    created_at: '2026-07-14T10:00:00.000Z',
    data: {
      email_id: 'resend-email-123',
      to: ['person@example.com'],
      from: 'ePDS <login@example.org>',
      subject: '123456 — Your sign-in code',
    },
  }
}

async function postWebhook(
  event: Record<string, unknown>,
  options: {
    svixId?: string
    validSignature?: boolean
    includeHeaders?: boolean
    otpLength?: number
    otpCharset?: 'numeric' | 'alphanumeric'
  } = {},
): Promise<{ status: number; json: Record<string, unknown> }> {
  const app = express()
  app.use(
    createResendWebhookRouter(
      WEBHOOK_SECRET,
      'login@example.org',
      options.otpLength ?? 6,
      options.otpCharset ?? 'numeric',
    ),
  )
  const server = app.listen(0)

  try {
    server.unref()
    const port = await new Promise<number>((resolve, reject) => {
      server.once('error', reject)
      server.once('listening', () => {
        const address = server.address()
        if (typeof address === 'object' && address) resolve(address.port)
        else reject(new Error('Failed to resolve ephemeral port'))
      })
    })

    const payload = JSON.stringify(event)
    const svixId = options.svixId ?? 'msg_test_123'
    const timestamp = new Date()
    const signature =
      options.validSignature === false
        ? 'v1,invalid'
        : new Webhook(WEBHOOK_SECRET).sign(svixId, timestamp, payload)

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }
    if (options.includeHeaders !== false) {
      headers['svix-id'] = svixId
      headers['svix-timestamp'] = String(Math.floor(timestamp.getTime() / 1000))
      headers['svix-signature'] = signature
    }

    const response = await fetch(`http://127.0.0.1:${port}/webhooks/resend`, {
      method: 'POST',
      headers,
      body: payload,
    })
    return {
      status: response.status,
      json: (await response.json()) as Record<string, unknown>,
    }
  } finally {
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve()
      })
    })
  }
}

describe('Resend webhook receiver', () => {
  it('verifies, logs, and acknowledges a delivery event', async () => {
    const result = await postWebhook(makeEvent('email.delivered'))

    expect(result).toEqual({ status: 200, json: { received: true } })
    expect(logInfo).toHaveBeenCalledWith(
      {
        provider: 'resend',
        eventId: 'msg_test_123',
        eventType: 'delivered',
        occurredAt: '2026-07-14T10:00:00.000Z',
        messageId: 'resend-email-123',
        email: 'person@example.com',
        subject: '[REDACTED] — Your sign-in code',
      },
      'Received email event',
    )
  })

  it.each([
    ['email.opened', 'opened'],
    ['email.scheduled', 'scheduled'],
  ])('normalizes %s events as %s', async (resendType, normalizedType) => {
    const result = await postWebhook(makeEvent(resendType))

    expect(result).toEqual({ status: 200, json: { received: true } })
    expect(logInfo).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: 'resend',
        eventType: normalizedType,
        messageId: 'resend-email-123',
        email: 'person@example.com',
      }),
      'Received email event',
    )
  })

  it.each([
    {
      label: 'a grouped numeric code',
      subject: '1234 5678 — Your sign-in code',
      otpLength: 8,
      otpCharset: 'numeric' as const,
      expected: '[REDACTED] — Your sign-in code',
    },
    {
      label: 'an alphanumeric code',
      subject: 'AB12CD — Your sign-in code',
      otpLength: 6,
      otpCharset: 'alphanumeric' as const,
      expected: '[REDACTED] — Your sign-in code',
    },
    {
      label: 'a subject without a code',
      subject: 'Verify your backup email',
      otpLength: 6,
      otpCharset: 'numeric' as const,
      expected: 'Verify your backup email',
    },
  ])(
    'sanitizes $label without hiding the rest of the subject',
    async (test) => {
      const event = makeEvent()
      const data = event.data as Record<string, unknown>
      data.subject = test.subject

      await postWebhook(event, {
        otpLength: test.otpLength,
        otpCharset: test.otpCharset,
      })

      expect(logInfo.mock.calls[0]?.[0].subject).toBe(test.expected)
    },
  )

  it('logs retries with the same Svix ID for downstream deduplication', async () => {
    await postWebhook(makeEvent(), { svixId: 'msg_retry' })
    await postWebhook(makeEvent(), { svixId: 'msg_retry' })

    expect(logInfo).toHaveBeenCalledTimes(2)
    expect(logInfo.mock.calls.map(([fields]) => fields.eventId)).toEqual([
      'msg_retry',
      'msg_retry',
    ])
  })

  it('acknowledges account-wide events for other senders without logging them', async () => {
    const event = makeEvent()
    const data = event.data as Record<string, unknown>
    data.from = 'Another service <noreply@other.example>'

    const result = await postWebhook(event, { svixId: 'msg_other_sender' })

    expect(result).toEqual({
      status: 200,
      json: { received: true, ignored: true },
    })
    expect(logInfo).not.toHaveBeenCalled()
    expect(logDebug).toHaveBeenCalledWith(
      { provider: 'resend', eventId: 'msg_other_sender' },
      'Ignored email webhook for another sender',
    )
  })

  it.each([
    ['email.delivery_delayed', 'delayed'],
    ['email.complained', 'complained'],
    ['email.suppressed', 'suppressed'],
  ])('logs %s as %s at warning level', async (resendType, normalizedType) => {
    await postWebhook(makeEvent(resendType))

    expect(logWarn).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: 'resend',
        eventId: 'msg_test_123',
        eventType: normalizedType,
        messageId: 'resend-email-123',
      }),
      'Received email event',
    )
  })

  it('rejects an invalid signature before logging the payload', async () => {
    const result = await postWebhook(makeEvent(), { validSignature: false })

    expect(result.status).toBe(400)
    expect(result.json).toEqual({ error: 'Invalid webhook signature' })
    expect(logInfo).not.toHaveBeenCalled()
  })

  it('rejects a request without the required Svix headers', async () => {
    const result = await postWebhook(makeEvent(), { includeHeaders: false })

    expect(result).toEqual({
      status: 400,
      json: { error: 'Invalid webhook request' },
    })
    expect(logInfo).not.toHaveBeenCalled()
  })

  it.each(['email.clicked', 'email.received'])(
    'acknowledges ignored %s events without logging their payload',
    async (eventType) => {
      const result = await postWebhook(makeEvent(eventType))

      expect(result).toEqual({
        status: 200,
        json: { received: true, ignored: true },
      })
      expect(logInfo).not.toHaveBeenCalled()
      expect(logWarn).not.toHaveBeenCalled()
      expect(logDebug).toHaveBeenCalledWith(
        {
          provider: 'resend',
          eventId: 'msg_test_123',
          eventType: eventType.slice('email.'.length),
        },
        'Ignored unsupported email webhook event',
      )
    },
  )

  it('rejects unknown signed event types', async () => {
    const result = await postWebhook(makeEvent('email.unknown'))

    expect(result.status).toBe(400)
    expect(result.json).toEqual({ error: 'Invalid webhook payload' })
    expect(logInfo).not.toHaveBeenCalled()
  })

  it('rejects an email event without a recipient email', async () => {
    const event = makeEvent()
    const data = event.data as Record<string, unknown>
    data.to = []

    const result = await postWebhook(event)

    expect(result.status).toBe(400)
    expect(result.json).toEqual({ error: 'Invalid webhook payload' })
    expect(logInfo).not.toHaveBeenCalled()
  })
})
