import { Router, type Request, type Response, type NextFunction } from 'express'
import type { AuthServiceContext } from '../context.js'
import {
  createLogger,
  hashToken,
  generateVerificationToken,
  escapeHtml,
  validateLocalPart,
} from '@certified-app/shared'
import { fromNodeHeaders } from 'better-auth/node'
import { getDidByEmail } from '../lib/get-did-by-email.js'
import { getHandleByDid } from '../lib/get-handle-by-did.js'
import { ensurePdsUrl } from '../lib/pds-url.js'
import { renderError } from '../lib/render-error.js'
import { POWERED_BY_CSS, POWERED_BY_HTML } from '../lib/page-helpers.js'

const logger = createLogger('auth:account-settings')

/**
 * User-visible flash-message lookup tables for the GET /account
 * page. The POST handlers redirect back with `?success=<code>` or
 * `?error=<code>` and the GET handler renders the matching message.
 *
 * Whitelisted lookup (not `?success=Some+raw+text`) so attackers
 * can't inject arbitrary text into the settings page via a crafted
 * URL.
 *
 * Exported for unit testing.
 */
export const FLASH_SUCCESS_MESSAGES: Record<string, string> = {
  backup_added:
    'Backup email added. Click the verification link we sent to confirm.',
  backup_verified: 'Backup email verified.',
  backup_removed: 'Backup email removed.',
  handle_updated: 'Handle updated.',
  session_revoked: 'Session revoked.',
}

export const FLASH_ERROR_MESSAGES: Record<string, string> = {
  invalid_email: 'That email address is not valid.',
  already_primary:
    'That email is already your primary — you can sign in with it directly.',
  account_not_found: "We couldn't find an account for your sign-in.",
  send_failed:
    "We couldn't send the verification email. Please try again in a moment.",
  backup_remove_failed:
    "We couldn't remove that backup email. Please try again in a moment.",
  revoke_failed:
    "We couldn't revoke that session. Please try again in a moment.",
  verify_failed:
    'That verification link is no longer valid. Add the backup email again to receive a fresh link.',
  invalid_handle:
    "That handle isn't valid. Use 5–20 characters: letters, numbers, or hyphens.",
  handle_failed:
    "We couldn't change your handle. It may be reserved or already taken.",
  delete_failed:
    "We couldn't delete your account right now. Please try again in a moment.",
  handle_taken: 'That handle is not available — please choose another.',
  confirm_delete:
    'Type DELETE in the confirmation box to permanently delete your account.',
}

/**
 * Resolve the success / error message pair from a /account request's
 * query params. Whitelist the keys via the FLASH_*_MESSAGES tables so
 * an attacker can't craft a URL like
 * `/account?error=Some+raw+text` to inject arbitrary copy.
 *
 * Exported so the route handler can stay declarative AND be unit-
 * tested without needing a fake express request.
 */
export function resolveAccountFlashFromQuery(query: {
  success?: unknown
  error?: unknown
}): { successMessage: string | null; errorMessage: string | null } {
  const successCode = typeof query.success === 'string' ? query.success : ''
  const errorCode = typeof query.error === 'string' ? query.error : ''
  return {
    successMessage: FLASH_SUCCESS_MESSAGES[successCode] ?? null,
    errorMessage: FLASH_ERROR_MESSAGES[errorCode] ?? null,
  }
}

/**
 * Middleware that validates a better-auth session and injects it into res.locals.
 * If not authenticated, redirects to /account/login.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth instance has no exported type
function requireBetterAuth(auth: any) {
  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      const session = await auth.api.getSession({
        headers: fromNodeHeaders(req.headers),
      })
      if (!session?.user?.email) {
        res.redirect(303, '/account/login')
        return
      }
      res.locals.betterAuthSession = session
      next()
    } catch {
      res.redirect(303, '/account/login')
    }
  }
}

export function createAccountSettingsRouter(
  ctx: AuthServiceContext,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth instance has no exported type
  auth: any,
): Router {
  const router = Router()
  const requireAuth = requireBetterAuth(auth)

  const pdsUrl = ensurePdsUrl(
    process.env.PDS_INTERNAL_URL,
    ctx.config.pdsPublicUrl,
  )
  const internalSecret = process.env.EPDS_INTERNAL_SECRET ?? ''

  // GET /account - main settings page
  router.get('/account', requireAuth, async (req: Request, res: Response) => {
    const session = res.locals.betterAuthSession
    const email = session.user.email.toLowerCase()
    const handleDomain = ctx.config.pdsHostname

    // Look up DID from PDS
    const did = await getDidByEmail(email, pdsUrl, internalSecret)
    const backupEmails = did ? ctx.db.getBackupEmails(did) : []
    const currentHandle = did ? await getHandleByDid(did, pdsUrl) : null

    // Get all better-auth sessions for this user
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth session type not exported
    let sessions: any[] = []
    try {
      const sessionsResponse = await auth.api.listSessions({
        headers: fromNodeHeaders(req.headers),
      })
      sessions = Array.isArray(sessionsResponse) ? sessionsResponse : []
    } catch (err) {
      logger.warn({ err }, 'Failed to list sessions')
    }

    // The POST handlers below redirect back to /account with a
    // ?success=… or ?error=… query param to confirm the action.
    // resolveAccountFlashFromQuery whitelists the recognised codes
    // so an attacker can't craft a URL that injects arbitrary text.
    const { successMessage, errorMessage } = resolveAccountFlashFromQuery(
      req.query as { success?: unknown; error?: unknown },
    )

    res.type('html').send(
      renderSettingsPage({
        did: did ?? '(unknown)',
        email,
        handleDomain,
        currentHandle,
        backupEmails,
        sessions,
        currentSessionToken: session.session.token,
        csrfToken: res.locals.csrfToken,
        successMessage,
        errorMessage,
      }),
    )
  })

  // POST /account/backup-email/add
  router.post(
    '/account/backup-email/add',
    requireAuth,
    async (req: Request, res: Response) => {
      const session = res.locals.betterAuthSession
      const email = ((req.body.email as string) || '').trim().toLowerCase()
      const primaryEmail = session.user.email.toLowerCase()

      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        res.redirect(303, '/account?error=invalid_email')
        return
      }

      if (email === primaryEmail) {
        res.redirect(303, '/account?error=already_primary')
        return
      }

      const did = await getDidByEmail(primaryEmail, pdsUrl, internalSecret)
      if (!did) {
        res.redirect(303, '/account?error=account_not_found')
        return
      }

      try {
        const { token, tokenHash } = generateVerificationToken()
        ctx.db.addBackupEmail(did, email, tokenHash)

        const baseUrl =
          'https://' + ctx.config.hostname + '/account/backup-email/verify'
        const verifyUrl = new URL(baseUrl)
        verifyUrl.searchParams.set('token', token)

        await ctx.emailSender.sendBackupEmailVerification({
          to: email,
          verifyUrl: verifyUrl.toString(),
          pdsName: ctx.config.hostname,
          pdsDomain: ctx.config.pdsHostname,
        })

        res.redirect(303, '/account?success=backup_added')
      } catch (err) {
        logger.error({ err }, 'Failed to add backup email')
        res.redirect(303, '/account?error=send_failed')
      }
    },
  )

  // GET /account/backup-email/verify?token=... - show confirmation form
  router.get('/account/backup-email/verify', (req: Request, res: Response) => {
    const token = req.query.token as string | undefined
    if (!token) {
      res
        .status(400)
        .type('html')
        .send(renderError('Missing verification token.'))
      return
    }

    res.type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="/static/favicon.svg" media="(prefers-color-scheme: light)" type="image/svg+xml">
  <link rel="icon" href="/static/favicon-dark.svg" media="(prefers-color-scheme: dark)" type="image/svg+xml">
  <title>Verify Backup Email</title>
  <style>${SETTINGS_CSS}</style>
</head>
<body>
  <div class="page-wrap" style="max-width: 420px;">
    <div class="container" style="max-width: 420px; text-align: center;">
      <h1>Verify Backup Email</h1>
      <p style="color: #666; margin: 16px 0;">Click the button below to confirm your backup email.</p>
      <form method="POST" action="/account/backup-email/verify">
        <input type="hidden" name="csrf" value="${escapeHtml(res.locals.csrfToken)}">
        <input type="hidden" name="token" value="${escapeHtml(token)}">
        <button type="submit" class="btn-primary-sm" style="padding: 12px 24px; font-size: 16px;">Confirm verification</button>
      </form>
    </div>
    ${POWERED_BY_HTML}
  </div>
</body>
</html>`)
  })

  // POST /account/backup-email/verify - perform actual verification
  router.post('/account/backup-email/verify', (req: Request, res: Response) => {
    const token = ((req.body.token as string) || '').trim()
    if (!token) {
      res
        .status(400)
        .type('html')
        .send(renderError('Missing verification token.'))
      return
    }

    const tokenHash = hashToken(token)
    const verified = ctx.db.verifyBackupEmail(tokenHash)

    if (verified) {
      res.redirect(303, '/account?success=backup_verified')
    } else {
      res.redirect(303, '/account?error=verify_failed')
    }
  })

  // POST /account/backup-email/remove
  router.post(
    '/account/backup-email/remove',
    requireAuth,
    async (req: Request, res: Response) => {
      const session = res.locals.betterAuthSession
      const email = ((req.body.email as string) || '').trim().toLowerCase()
      if (!email) {
        res.redirect(303, '/account?error=invalid_email')
        return
      }
      const did = await getDidByEmail(
        session.user.email,
        pdsUrl,
        internalSecret,
      )
      if (!did) {
        res.redirect(303, '/account?error=account_not_found')
        return
      }
      try {
        ctx.db.removeBackupEmail(did, email)
        res.redirect(303, '/account?success=backup_removed')
      } catch (err) {
        logger.error({ err }, 'Failed to remove backup email')
        res.redirect(303, '/account?error=backup_remove_failed')
      }
    },
  )

  // POST /account/session/revoke — revoke a specific better-auth session by token
  router.post(
    '/account/session/revoke',
    requireAuth,
    async (req: Request, res: Response) => {
      const tokenToRevoke = req.body.session_token as string
      if (!tokenToRevoke) {
        res.redirect(303, '/account?error=revoke_failed')
        return
      }
      try {
        await auth.api.revokeSession({
          body: { token: tokenToRevoke },
          headers: fromNodeHeaders(req.headers),
        })
        res.redirect(303, '/account?success=session_revoked')
      } catch (err) {
        logger.warn({ err }, 'Failed to revoke session')
        res.redirect(303, '/account?error=revoke_failed')
      }
    },
  )

  // POST /account/sessions/revoke-all — revoke all sessions for this user
  router.post(
    '/account/sessions/revoke-all',
    requireAuth,
    async (req: Request, res: Response) => {
      try {
        await auth.api.revokeSessions({
          headers: fromNodeHeaders(req.headers),
        })
      } catch (err) {
        logger.warn({ err }, 'Failed to revoke all sessions')
      }
      res.redirect(303, '/account/login')
    },
  )

  // POST /account/logout — sign out via better-auth
  router.post('/account/logout', async (req: Request, res: Response) => {
    try {
      await auth.api.signOut({
        headers: fromNodeHeaders(req.headers),
      })
    } catch {
      /* ignore */
    }
    res.redirect(303, '/account/login')
  })

  // POST /account/handle - update user handle via PDS admin API
  router.post(
    '/account/handle',
    requireAuth,
    async (req: Request, res: Response) => {
      const session = res.locals.betterAuthSession
      const rawHandle = ((req.body.handle as string) || '').trim()
      const handleDomain = ctx.config.pdsHostname

      const normalizedLocal = validateLocalPart(rawHandle, handleDomain)
      if (normalizedLocal === null) {
        res.redirect(303, '/account?error=invalid_handle')
        return
      }

      const fullHandle = `${normalizedLocal}.${handleDomain}`

      const did = await getDidByEmail(
        session.user.email,
        pdsUrl,
        internalSecret,
      )
      if (!did) {
        res.redirect(303, '/account?error=handle_failed')
        return
      }

      try {
        const pdsAdminPassword = process.env.PDS_ADMIN_PASSWORD
        if (!pdsAdminPassword) {
          logger.error('PDS_ADMIN_PASSWORD not set, cannot update handle')
          res.redirect(303, '/account?error=handle_failed')
          return
        }

        const response = await fetch(
          ctx.config.pdsPublicUrl +
            '/xrpc/com.atproto.admin.updateAccountHandle',
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization:
                'Basic ' +
                Buffer.from('admin:' + pdsAdminPassword).toString('base64'),
            },
            body: JSON.stringify({ did, handle: fullHandle }),
          },
        )

        if (!response.ok) {
          const body = await response.text()
          logger.error(
            { status: response.status, body },
            'Failed to update handle via PDS admin API',
          )
          res.redirect(303, '/account?error=handle_taken')
          return
        }

        res.redirect(303, '/account?success=handle_updated')
      } catch (err) {
        logger.error({ err }, 'Failed to update handle')
        res.redirect(303, '/account?error=handle_failed')
      }
    },
  )

  // POST /account/delete - delete account via PDS admin API + local cleanup
  router.post(
    '/account/delete',
    requireAuth,
    async (req: Request, res: Response) => {
      const session = res.locals.betterAuthSession
      const confirmation = req.body.confirm as string

      if (confirmation !== 'DELETE') {
        res.redirect(303, '/account?error=confirm_delete')
        return
      }

      const did = await getDidByEmail(
        session.user.email,
        pdsUrl,
        internalSecret,
      )
      if (!did) {
        res.redirect(303, '/account?error=delete_failed')
        return
      }

      try {
        const pdsAdminPassword = process.env.PDS_ADMIN_PASSWORD
        if (!pdsAdminPassword) {
          logger.error('PDS_ADMIN_PASSWORD not set, cannot delete account')
          res.redirect(303, '/account?error=delete_failed')
          return
        }

        const response = await fetch(
          ctx.config.pdsPublicUrl + '/xrpc/com.atproto.admin.deleteAccount',
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization:
                'Basic ' +
                Buffer.from('admin:' + pdsAdminPassword).toString('base64'),
            },
            body: JSON.stringify({ did }),
          },
        )

        if (!response.ok) {
          const body = await response.text()
          logger.error(
            { status: response.status, body },
            'Failed to delete account via PDS admin API',
          )
          res.redirect(303, '/account?error=delete_failed')
          return
        }

        // Clean up local data (backup emails, etc.)
        ctx.db.deleteAccountData(did)

        // Sign out of better-auth
        try {
          await auth.api.signOut({ headers: fromNodeHeaders(req.headers) })
        } catch {
          /* ignore */
        }

        res.type('html').send(renderDeletedPage())
      } catch (err) {
        logger.error({ err }, 'Failed to delete account')
        res.redirect(303, '/account?error=delete_failed')
      }
    },
  )

  return router
}

export function renderSettingsPage(opts: {
  did: string
  email: string
  handleDomain: string
  currentHandle: string | null
  backupEmails: Array<{ email: string; verified: number; id: number }>
  sessions: Array<{
    token: string
    createdAt: Date | string
    userAgent?: string | null
    ipAddress?: string | null
  }>
  currentSessionToken: string
  csrfToken: string
  successMessage?: string | null
  errorMessage?: string | null
}): string {
  // Prepend any flash banners INSIDE the existing page-wrap so they
  // sit above the settings content. Both go through escapeHtml even
  // though the source dictionary is whitelisted — defence-in-depth
  // against a future maintainer accidentally widening the lookup.
  const flashHtml = [
    opts.successMessage
      ? `<div class="flash flash-success" role="status">${escapeHtml(opts.successMessage)}</div>`
      : '',
    opts.errorMessage
      ? `<div class="flash flash-error" role="alert">${escapeHtml(opts.errorMessage)}</div>`
      : '',
  ].join('')
  const backupRows = opts.backupEmails
    .map(
      (be) => `
    <div class="setting-row">
      <span>${escapeHtml(be.email)} ${be.verified ? '(verified)' : '(pending)'}</span>
      <form method="POST" action="/account/backup-email/remove" style="display:inline">
        <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
        <input type="hidden" name="email" value="${escapeHtml(be.email)}">
        <button type="submit" class="btn-danger-sm">Remove</button>
      </form>
    </div>
  `,
    )
    .join('')

  const sessionRows = opts.sessions
    .map((s) => {
      const date = new Date(s.createdAt).toLocaleString()
      const isCurrent = s.token === opts.currentSessionToken
      const agent = s.userAgent ? s.userAgent.substring(0, 60) : 'Unknown'
      return `
    <div class="setting-row">
      <div>
        <span class="session-agent">${escapeHtml(agent)}${isCurrent ? ' (current)' : ''}</span>
        <span class="session-date">${date}</span>
      </div>
      ${
        isCurrent
          ? ''
          : `<form method="POST" action="/account/session/revoke" style="display:inline">
        <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
        <input type="hidden" name="session_token" value="${escapeHtml(s.token)}">
        <button type="submit" class="btn-danger-sm">Revoke</button>
      </form>`
      }
    </div>
  `
    })
    .join('')

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="/static/favicon.svg" media="(prefers-color-scheme: light)" type="image/svg+xml">
  <link rel="icon" href="/static/favicon-dark.svg" media="(prefers-color-scheme: dark)" type="image/svg+xml">
  <title>Account Settings</title>
  <style>${SETTINGS_CSS}</style>
</head>
<body>
  <div class="page-wrap">
    <div class="container">
    <div class="header">
      <h1>Account Settings</h1>
      <form method="POST" action="/account/logout" style="display:inline">
        <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
        <button type="submit" class="btn-secondary">Sign out</button>
      </form>
    </div>

    ${flashHtml}

    <section class="section">
      <h2>Account</h2>
      <div class="setting-row"><strong>DID:</strong> <code>${escapeHtml(opts.did)}</code></div>
      <div class="setting-row"><strong>Primary Email:</strong> ${escapeHtml(opts.email)}</div>
    </section>

    <section class="section">
      <h2>Handle</h2>
      <p class="info">Your handle is your public username on the AT Protocol network.</p>
      <div class="setting-row"><strong>Current Handle:</strong> <code>${escapeHtml(opts.currentHandle ?? '(unknown)')}</code></div>
      <form method="POST" action="/account/handle" class="inline-form">
        <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
        <input type="text" name="handle" placeholder="yourname" autocomplete="off" autocapitalize="none" spellcheck="false" required>
        <span class="handle-suffix">.${escapeHtml(opts.handleDomain)}</span>
        <button type="submit" class="btn-primary-sm">Update</button>
      </form>
    </section>

    <section class="section">
      <h2>Backup Emails</h2>
      <p class="info">Backup emails can be used to recover your account if you lose access to your primary email.</p>
      ${backupRows || '<p class="info">No backup emails configured.</p>'}
      <form method="POST" action="/account/backup-email/add" class="inline-form">
        <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
        <input type="email" name="email" placeholder="backup@example.com" required>
        <button type="submit" class="btn-primary-sm">Add backup email</button>
      </form>
    </section>

    <section class="section danger-zone">
      <h2>Danger Zone</h2>
      <p class="info">Permanently delete your account and all associated data. This cannot be undone.</p>
      <details>
        <summary class="btn-danger-sm" style="cursor:pointer; display:inline-block;">Delete account...</summary>
        <form method="POST" action="/account/delete" style="margin-top: 12px;">
          <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
          <p class="info">Type <strong>DELETE</strong> to confirm:</p>
          <div class="inline-form">
            <input type="text" name="confirm" placeholder="DELETE" required pattern="DELETE">
            <button type="submit" class="btn-danger">Delete my account</button>
          </div>
        </form>
      </details>
    </section>

    <section class="section">
      <h2>Active Sessions</h2>
      ${sessionRows || '<p class="info">No active sessions.</p>'}
      <form method="POST" action="/account/sessions/revoke-all" style="margin-top: 12px">
        <input type="hidden" name="csrf" value="${escapeHtml(opts.csrfToken)}">
        <button type="submit" class="btn-danger">Revoke all sessions</button>
      </form>
    </section>
    </div>
    ${POWERED_BY_HTML}
  </div>
</body>
</html>`
}

function renderDeletedPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="/static/favicon.svg" media="(prefers-color-scheme: light)" type="image/svg+xml">
  <link rel="icon" href="/static/favicon-dark.svg" media="(prefers-color-scheme: dark)" type="image/svg+xml">
  <title>Account Deleted</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
    .page-wrap { display: flex; flex-direction: column; align-items: stretch; max-width: 420px; width: 100%; }
    ${POWERED_BY_CSS}
    .container { background: white; border-radius: 12px; padding: 40px; width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }
    h1 { font-size: 24px; margin-bottom: 12px; color: #111; }
    p { color: #666; font-size: 15px; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="page-wrap">
    <div class="container">
      <h1>Account Deleted</h1>
      <p>Your account and all associated data have been permanently deleted.</p>
    </div>
    ${POWERED_BY_HTML}
  </div>
</body>
</html>`
}

const SETTINGS_CSS = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; padding: 40px 20px; }
  .page-wrap { display: flex; flex-direction: column; align-items: stretch; max-width: 640px; margin: 0 auto; }
  ${POWERED_BY_CSS}
  .container { background: white; border-radius: 12px; padding: 32px; max-width: 640px; margin: 0 auto; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
  .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; border-bottom: 1px solid #eee; padding-bottom: 16px; }
  h1 { font-size: 24px; color: #111; }
  h2 { font-size: 18px; color: #333; margin-bottom: 12px; }
  .flash { padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; }
  .flash-success { background: #f0fff4; color: #28a745; border: 1px solid #c3e6cb; }
  .flash-error { background: #fdf0f0; color: #dc3545; border: 1px solid #f5c6cb; }
  .section { margin-bottom: 28px; padding-bottom: 20px; border-bottom: 1px solid #f0f0f0; }
  .section:last-child { border-bottom: none; margin-bottom: 0; }
  .setting-row { display: flex; justify-content: space-between; align-items: center; padding: 8px 0; font-size: 14px; color: #333; }
  .setting-row code { background: #f5f5f5; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
  .session-agent { display: block; font-size: 13px; color: #333; }
  .session-date { display: block; font-size: 12px; color: #999; }
  .info { color: #666; font-size: 14px; line-height: 1.5; margin-bottom: 12px; }
  .inline-form { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
  .inline-form input[type="text"], .inline-form input[type="email"] { flex: 1; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; min-width: 120px; }
  .btn-primary-sm { padding: 8px 16px; background: #0f1828; color: white; border: none; border-radius: 6px; font-size: 14px; cursor: pointer; white-space: nowrap; }
  .btn-primary-sm:hover { background: #1a2a40; }
  .btn-secondary { color: #0f1828; background: none; border: none; font-size: 14px; cursor: pointer; text-decoration: underline; }
  .btn-danger { padding: 8px 16px; background: #dc3545; color: white; border: none; border-radius: 6px; font-size: 14px; cursor: pointer; }
  .btn-danger:hover { background: #c82333; }
  .btn-danger-sm { padding: 4px 12px; background: none; color: #dc3545; border: 1px solid #dc3545; border-radius: 4px; font-size: 12px; cursor: pointer; }
  .btn-danger-sm:hover { background: #dc3545; color: white; }
  .handle-suffix { font-size: 14px; color: #666; white-space: nowrap; align-self: center; overflow: hidden; text-overflow: ellipsis; }
  .danger-zone { border-color: #f5c6cb; }
  .danger-zone h2 { color: #dc3545; }
  details summary { list-style: none; }
  details summary::-webkit-details-marker { display: none; }
`
