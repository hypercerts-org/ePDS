/**
 * Shared Mailpit API helpers used by both step definitions and scenario setup flows.
 *
 * All functions require Mailpit credentials to be configured in testEnv.
 * Callers are responsible for checking testEnv.mailpitPass before invoking these.
 */

import { testEnv } from './env.js'

export interface MailpitMessage {
  ID: string
  Subject: string
}

interface MailpitSearchResponse {
  messages?: MailpitMessage[]
}

async function searchMessages(
  query: string,
  limit: number,
): Promise<MailpitMessage[]> {
  const res = await fetch(
    `${testEnv.mailpitUrl}/api/v1/search?query=${encodeURIComponent(query)}&limit=${limit}`,
    { headers: { Authorization: mailpitAuthHeader() } },
  )

  if (!res.ok) {
    if (res.status >= 400 && res.status < 500) {
      throw new Error(`Mailpit search failed with client error: ${res.status}`)
    }
    throw new Error(`Mailpit search failed with server error: ${res.status}`)
  }

  const data = (await res.json()) as MailpitSearchResponse
  return data.messages ?? []
}

export function mailpitAuthHeader(): string {
  return `Basic ${Buffer.from(`${testEnv.mailpitUser}:${testEnv.mailpitPass}`).toString('base64')}`
}

/**
 * Poll Mailpit search until a message matching the query arrives, or timeout.
 * Returns the first matching message.
 */
export async function waitForEmail(
  query: string,
  timeoutMs = 60_000,
): Promise<MailpitMessage> {
  const interval = 500
  const attempts = Math.ceil(timeoutMs / interval)

  for (let i = 0; i < attempts; i++) {
    try {
      const messages = await searchMessages(query, 1)
      if (messages.length > 0) {
        return messages[0]
      }
    } catch (err) {
      if (err instanceof Error && err.message.includes('client error')) {
        throw err
      }
    }
    await new Promise<void>((r) => setTimeout(r, interval))
  }

  throw new Error(`No email matching "${query}" arrived within ${timeoutMs}ms`)
}

/**
 * Extract the OTP code from the plain-text body of a Mailpit message.
 *
 * Fetches the plain-text rendering via /view/{id}.txt and uses a multiline
 * regex to find a line that is exactly otpLength chars of the correct charset
 * and nothing else. The `m` flag makes ^ and $ match per-line, so the code
 * must occupy its own line with no surrounding text — this avoids false
 * positives from words like "verification" in alphanumeric mode.
 *
 * This relies on the default email templates sending the raw code (not
 * formatOtpPlain) on its own line in the plain-text body.
 */
export async function extractOtp(messageId: string): Promise<string> {
  const res = await fetch(`${testEnv.mailpitUrl}/view/${messageId}.txt`, {
    headers: { Authorization: mailpitAuthHeader() },
  })
  const body = await res.text()
  const charClass =
    testEnv.otpCharset === 'alphanumeric' ? '[A-Za-z0-9]' : '\\d'
  const pattern = new RegExp(`^(${charClass}{${testEnv.otpLength}})$`, 'm')
  const match = pattern.exec(body)
  if (!match) {
    throw new Error(
      `Could not extract OTP (length=${testEnv.otpLength}, charset=${testEnv.otpCharset}) from email body:\n${body}`,
    )
  }
  return match[1]
}

/**
 * Delete all Mailpit messages addressed to a specific recipient.
 * Uses the search-based delete endpoint to avoid wiping the entire inbox,
 * which would cause race conditions when scenarios run in parallel workers.
 */
export async function clearMailpit(recipient: string): Promise<void> {
  const res = await fetch(
    `${testEnv.mailpitUrl}/api/v1/search?query=${encodeURIComponent(`to:${recipient}`)}`,
    { method: 'DELETE', headers: { Authorization: mailpitAuthHeader() } },
  )
  if (!res.ok) {
    throw new Error(`Mailpit DELETE /api/v1/search failed: ${res.status}`)
  }
}
