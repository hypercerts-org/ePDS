/**
 * Integration tests for /preview/emails/* routes. Bring up an express
 * app with the preview-emails router mounted, listen on an ephemeral
 * port, and hit it with fetch. The real EmailSender is not constructed
 * — we cast a minimal AuthServiceContext stub because the router only
 * reads `config.email.{from,fromName}`, `config.{hostname,pdsHostname}`,
 * and `config.trustedClients`.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import express, { type Express } from 'express'
import type { AddressInfo } from 'node:net'
import type { Server } from 'node:http'
import { createPreviewEmailsRouter } from '../routes/preview-emails.js'
import type { AuthServiceContext } from '../context.js'
import {
  _seedTemplateCacheForTest,
  _clearTemplateCacheForTest,
} from '../email/client-template.js'
import {
  _seedClientMetadataCacheForTest,
  clearClientMetadataCache,
} from '@certified-app/shared'

const TRUSTED_CLIENT = 'https://branded.example/client-metadata.json'
const TRUSTED_TEMPLATE_URI = 'https://branded.example/email-template.html'

function makeCtxStub(): AuthServiceContext {
  return {
    config: {
      hostname: 'auth.preview.example',
      pdsHostname: 'pds.preview.example',
      email: { from: 'noreply@pds.preview.example', fromName: 'Preview PDS' },
      trustedClients: [TRUSTED_CLIENT],
    },
  } as unknown as AuthServiceContext
}

let server: Server
let baseUrl: string
let app: Express
let originalPreviewFlag: string | undefined

beforeAll(async () => {
  originalPreviewFlag = process.env.AUTH_PREVIEW_ROUTES
  app = express()
  app.use(createPreviewEmailsRouter(makeCtxStub()))
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      resolve()
    })
  })
  const addr = server.address() as AddressInfo
  baseUrl = `http://127.0.0.1:${addr.port}`
})

afterAll(async () => {
  if (originalPreviewFlag === undefined) {
    delete process.env.AUTH_PREVIEW_ROUTES
  } else {
    process.env.AUTH_PREVIEW_ROUTES = originalPreviewFlag
  }
  await new Promise<void>((resolve, reject) => {
    server.close((err) => {
      if (err) reject(err)
      else resolve()
    })
  })
})

beforeEach(() => {
  process.env.AUTH_PREVIEW_ROUTES = '1'
  clearClientMetadataCache()
  _clearTemplateCacheForTest()
})

describe('preview-emails router — gate', () => {
  it('returns 404 for every email route when AUTH_PREVIEW_ROUTES is unset', async () => {
    delete process.env.AUTH_PREVIEW_ROUTES
    for (const path of [
      '/preview/emails/new-user',
      '/preview/emails/returning-user',
      '/preview/emails/recovery',
    ]) {
      const res = await fetch(`${baseUrl}${path}`)
      expect(res.status).toBe(404)
    }
  })
})

describe('preview-emails router — rendering', () => {
  it('renders the new-user welcome email inside an iframe with srcdoc', async () => {
    const res = await fetch(`${baseUrl}/preview/emails/new-user?otp=123456`)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toMatch(/text\/html/)
    expect(res.headers.get('cache-control')).toBe('no-store')
    const body = await res.text()
    expect(body).toContain('New user')
    // pdsName now mirrors better-auth.ts (SMTP_FROM_NAME / fromName),
    // not the auth-service hostname. Preview must match production.
    expect(body).toContain('Preview PDS')
    expect(body).toContain('<iframe')
    expect(body).toContain('sandbox=""')
    expect(body).toContain('srcdoc="')
    // The real sender's welcome HTML, escaped for the srcdoc attribute.
    expect(body).toContain('Welcome to Preview PDS')
  })

  it('renders the returning-user OTP email with the app name', async () => {
    const res = await fetch(
      `${baseUrl}/preview/emails/returning-user?otp=12345678&app=MyApp`,
    )
    expect(res.status).toBe(200)
    const body = await res.text()
    expect(body).toContain('Returning user')
    expect(body).toContain('MyApp')
    expect(body).toContain('1234 5678') // formatted in subject
  })

  it('renders the recovery email with the backup verification URL', async () => {
    const url = 'https://auth.preview.example/account/verify?t=xyz'
    const res = await fetch(
      `${baseUrl}/preview/emails/recovery?verify_url=${encodeURIComponent(url)}`,
    )
    expect(res.status).toBe(200)
    const body = await res.text()
    expect(body).toContain('Account recovery')
    expect(body).toContain('Verify your backup email')
    // The URL lives inside the iframe's srcdoc attribute, so it is
    // HTML-escaped twice: once for the email HTML, once for the attribute.
    // A substring of the path is enough to prove it made it through.
    expect(body).toContain('verify?t=xyz')
  })

  it('exposes from/to/subject headers in the preview shell', async () => {
    const res = await fetch(
      `${baseUrl}/preview/emails/returning-user?to=bob@test.example`,
    )
    const body = await res.text()
    expect(body).toContain('Preview PDS')
    expect(body).toContain('noreply@pds.preview.example')
    expect(body).toContain('bob@test.example')
  })
})

describe('preview-emails router — ?client_id branded path', () => {
  it('renders the branded template for a trusted client (returning-user)', async () => {
    _seedClientMetadataCacheForTest(TRUSTED_CLIENT, {
      client_name: 'Branded App',
      email_template_uri: TRUSTED_TEMPLATE_URI,
      email_subject_template: '{{code}} — your {{app_name}} code',
      logo_uri: 'https://branded.example/logo.png',
    })
    _seedTemplateCacheForTest(
      TRUSTED_TEMPLATE_URI,
      '<html><body>Code {{code}} for {{app_name}}</body></html>',
    )

    const res = await fetch(
      `${baseUrl}/preview/emails/returning-user?otp=654321&client_id=${encodeURIComponent(TRUSTED_CLIENT)}`,
    )
    expect(res.status).toBe(200)
    const body = await res.text()
    // Branded subject template — "{{code}} — your {{app_name}} code"
    expect(body).toContain('654321 — your Branded App code')
    // Branded HTML appears inside the iframe srcdoc (HTML-escaped).
    expect(body).toContain('Code 654321 for Branded App')
    // From display name comes from the client's client_name.
    expect(body).toContain('Branded App')
  })

  it('renders the branded template for a trusted client (new-user)', async () => {
    _seedClientMetadataCacheForTest(TRUSTED_CLIENT, {
      client_name: 'Branded App',
      email_template_uri: TRUSTED_TEMPLATE_URI,
    })
    _seedTemplateCacheForTest(
      TRUSTED_TEMPLATE_URI,
      '<html><body>{{#is_new_user}}NEW USER{{/is_new_user}} code {{code}}</body></html>',
    )

    const res = await fetch(
      `${baseUrl}/preview/emails/new-user?otp=123456&client_id=${encodeURIComponent(TRUSTED_CLIENT)}`,
    )
    expect(res.status).toBe(200)
    const body = await res.text()
    // {{#is_new_user}} conditional keeps the section on the welcome route.
    expect(body).toContain('NEW USER code 123456')
    // Default welcome subject (no email_subject_template in metadata).
    expect(body).toContain('Welcome to Branded App')
  })

  it('falls back to the default template when ?client_id is untrusted', async () => {
    // Seed branded metadata for a client_id that is *not* on trustedClients.
    // The preview must not fetch, render, or surface any of it.
    const untrusted = 'https://evil.example/client-metadata.json'
    _seedClientMetadataCacheForTest(untrusted, {
      client_name: 'Evil App',
      email_template_uri: 'https://evil.example/pwn.html',
      email_subject_template: '{{code}} — pwned',
    })
    _seedTemplateCacheForTest(
      'https://evil.example/pwn.html',
      '<html><body>PWNED {{code}}</body></html>',
    )

    const res = await fetch(
      `${baseUrl}/preview/emails/returning-user?otp=999999&client_id=${encodeURIComponent(untrusted)}`,
    )
    expect(res.status).toBe(200)
    const body = await res.text()
    // Default subject uses the PDS fromName (SMTP_FROM_NAME in prod),
    // not the untrusted client's metadata.
    expect(body).toContain('Preview PDS')
    expect(body).not.toContain('pwned')
    expect(body).not.toContain('Evil App')
    expect(body).not.toContain('PWNED')
  })

  it('falls back to the default template when trusted client has no email_template_uri', async () => {
    _seedClientMetadataCacheForTest(TRUSTED_CLIENT, {
      client_name: 'Branded App',
      // no email_template_uri — should fall through to the default
    })

    const res = await fetch(
      `${baseUrl}/preview/emails/returning-user?otp=111222&client_id=${encodeURIComponent(TRUSTED_CLIENT)}`,
    )
    expect(res.status).toBe(200)
    const body = await res.text()
    expect(body).toContain('Preview PDS')
  })
})
