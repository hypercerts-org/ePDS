/**
 * Client-branded email template resolution.
 *
 * When an OAuth client advertises `email_template_uri` (and optionally
 * `email_subject_template`) in its client metadata, we fetch the remote
 * template and substitute `{{code}}`, `{{app_name}}`, `{{logo_uri}}`,
 * `{{email}}`, plus conditional `{{#is_new_user}}...{{/is_new_user}}`
 * blocks. The real sender and the /preview/emails/* routes both go
 * through `buildClientBrandedEmail` so what the browser previews
 * matches what production will actually put in the envelope.
 */
import {
  createLogger,
  escapeHtml,
  formatOtpPlain,
  makeSafeFetch,
} from '@certified-app/shared'
import { resolveClientMetadata } from '../lib/client-metadata.js'
import type { RenderedEmail } from './templates.js'

const logger = createLogger('auth:email-template')

const MAX_TEMPLATE_SIZE = 100_000 // 100KB
const TEMPLATE_CACHE_TTL = 10 * 60 * 1000 // 10 minutes

const templateCache = new Map<string, { html: string; fetchedAt: number }>()

// Template URIs can be signed URLs or carry credentials in the query
// string, so the full URI is treated as sensitive. Log only the parsed
// hostname/protocol (or a marker when parsing fails) — enough to debug
// allowlist/fetch problems without leaking secrets into log aggregators.
function templateLogContext(uri: string): {
  templateHostname?: string
  templateProtocol?: string
  templateUri?: string
} {
  try {
    const url = new URL(uri)
    return { templateHostname: url.hostname, templateProtocol: url.protocol }
  } catch {
    return { templateUri: '<invalid>' }
  }
}

// Strip CR/LF from values that end up in SMTP headers (Subject, From
// display-name). Even trusted clients' remotely-fetched metadata could
// be compromised; a newline in a header value would let an attacker
// inject arbitrary headers after it.
function sanitizeHeaderValue(value: string): string {
  return value.replace(/[\r\n]+/g, ' ').trim()
}

/** Seed the template cache. Intended for tests only. */
export function _seedTemplateCacheForTest(uri: string, html: string): void {
  templateCache.set(uri, { html, fetchedAt: Date.now() })
}

/** Clear the template cache. Intended for tests only. */
export function _clearTemplateCacheForTest(): void {
  templateCache.clear()
}

// SSRF-hardened fetch for email templates: HTTPS-only, no private IPs,
// 5s timeout, 100KB body cap. EPDS_ALLOW_PRIVATE_IPS is the same opt-out
// client-metadata fetch honours — local docker-compose e2e runs need it
// because trusted clients are served from docker-internal IPs.
const safeFetch = makeSafeFetch({
  timeoutMs: 5_000,
  maxBodyBytes: MAX_TEMPLATE_SIZE,
  allowPrivateIps: process.env.EPDS_ALLOW_PRIVATE_IPS === 'true',
})

export async function fetchTemplate(uri: string): Promise<string | null> {
  const allowedDomains = process.env.EMAIL_TEMPLATE_ALLOWED_DOMAINS
  if (allowedDomains) {
    try {
      const domains = allowedDomains.split(',').map((d) => d.trim())
      const hostname = new URL(uri).hostname
      if (!domains.includes(hostname)) {
        logger.warn(
          { hostname },
          'Email template domain not in allowlist, ignoring',
        )
        return null
      }
    } catch {
      return null
    }
  }

  const cached = templateCache.get(uri)
  if (cached && Date.now() - cached.fetchedAt < TEMPLATE_CACHE_TTL) {
    return cached.html
  }
  try {
    const res = await safeFetch(uri)
    if (!res.ok) return null

    const html = await res.text()
    if (html.length > MAX_TEMPLATE_SIZE) {
      logger.warn(
        { ...templateLogContext(uri), size: html.length },
        'Email template too large, ignoring',
      )
      return null
    }

    if (!html.includes('{{code}}')) {
      logger.warn(
        templateLogContext(uri),
        'Email template missing {{code}} placeholder, ignoring',
      )
      return null
    }
    templateCache.set(uri, { html, fetchedAt: Date.now() })
    return html
  } catch (err) {
    logger.warn(
      { err, ...templateLogContext(uri) },
      'Failed to fetch email template',
    )
    return null
  }
}

export function renderTemplate(
  template: string,
  vars: Record<string, string | boolean>,
): string {
  let html = template

  // Conditional sections first: {{#key}}...{{/key}} and {{^key}}...{{/key}}
  for (const [key, value] of Object.entries(vars)) {
    if (typeof value === 'boolean') {
      const showRegex = new RegExp(
        `\\{\\{#${key}\\}\\}([\\s\\S]*?)\\{\\{/${key}\\}\\}`,
        'g',
      )
      const hideRegex = new RegExp(
        `\\{\\{\\^${key}\\}\\}([\\s\\S]*?)\\{\\{/${key}\\}\\}`,
        'g',
      )
      html = html.replace(showRegex, value ? '$1' : '')
      html = html.replace(hideRegex, value ? '' : '$1')
    }
  }

  // String variables, HTML-escaped.
  for (const [key, value] of Object.entries(vars)) {
    if (typeof value === 'string') {
      html = html.replaceAll(`{{${key}}}`, escapeHtml(value))
    }
  }

  return html
}

export function renderSubjectTemplate(
  template: string,
  vars: Record<string, string>,
): string {
  let subject = template
  for (const [key, value] of Object.entries(vars)) {
    subject = subject.replaceAll(`{{${key}}}`, value)
  }
  return subject
}

/**
 * Resolve a client's email-branding metadata, fetch the remote template,
 * and render `{ subject, text, html, fromName }`. Returns null when the
 * client isn't trusted, has no branded template, the fetch fails, or
 * the template is invalid — the caller is expected to fall back to the
 * default.
 *
 * Only clients on `trustedClients` are honoured: an untrusted `client_id`
 * could otherwise cause an outbound fetch to an attacker-controlled URL
 * and put attacker-authored HTML alongside the PDS's own `From:`
 * address. This matches the gate on `EmailSender.sendOtpCode` and on
 * CSS branding injection.
 */
export async function buildClientBrandedEmail(opts: {
  clientId: string
  code: string
  isNewUser: boolean
  toEmail: string
  fallbackAppName: string
  fallbackFromName: string
  pdsName: string
  pdsDomain: string
  trustedClients: readonly string[]
}): Promise<(RenderedEmail & { fromName: string }) | null> {
  const {
    clientId,
    code,
    isNewUser,
    toEmail,
    fallbackAppName,
    fallbackFromName,
    pdsName,
    pdsDomain,
    trustedClients,
  } = opts

  if (!trustedClients.includes(clientId)) return null

  let metadata
  try {
    metadata = await resolveClientMetadata(clientId)
  } catch (err) {
    logger.warn({ err, clientId }, 'Failed to resolve client metadata')
    return null
  }
  if (!metadata.email_template_uri) return null

  const template = await fetchTemplate(metadata.email_template_uri)
  if (!template) return null

  const appName = metadata.client_name || fallbackAppName
  const html = renderTemplate(template, {
    code,
    app_name: appName,
    logo_uri: metadata.logo_uri || '',
    is_new_user: isNewUser,
    email: toEmail,
  })

  let subject: string
  if (metadata.email_subject_template) {
    // Expose both {{code}} (raw, e.g. "12345678") and {{code_formatted}}
    // (grouped, e.g. "1234 5678" for lengths >= 8). Fallback subjects use
    // the formatted form, so clients that want to match PDS readability
    // UX can opt in with `{{code_formatted}}` in their template.
    subject = renderSubjectTemplate(metadata.email_subject_template, {
      code,
      code_formatted: formatOtpPlain(code),
      app_name: appName,
    })
  } else if (isNewUser) {
    subject = `${formatOtpPlain(code)} — Welcome to ${appName}`
  } else {
    subject = `${formatOtpPlain(code)} is your sign-in code for ${appName}`
  }

  // Plain-text alternative stays PDS-controlled: the remote branded
  // template only owns the HTML. Mirror buildSignInCodeEmail /
  // buildWelcomeCodeEmail so clients that see text/plain (mail clients
  // without HTML, accessibility tools, bounce scanners) get the same
  // identity and footer as the default path.
  const text = (
    isNewUser
      ? [
          `Welcome to ${appName}!`,
          '',
          `Your verification code:`,
          '',
          code,
          '',
          `Enter this code to confirm your email and create your account.`,
          '',
          `This code expires in 10 minutes.`,
          '',
          `If you didn't sign up, you can safely ignore this email.`,
        ]
      : [
          `Your sign-in code for ${appName}:`,
          '',
          code,
          '',
          `This code expires in 10 minutes.`,
          '',
          `If you didn't request this, you can safely ignore this email.`,
        ]
  )
    .concat(['', `--`, `${pdsName} (${pdsDomain})`])
    .join('\n')

  const fromName = metadata.client_name || fallbackFromName

  return {
    subject: sanitizeHeaderValue(subject),
    text,
    html,
    fromName: sanitizeHeaderValue(fromName),
  }
}
