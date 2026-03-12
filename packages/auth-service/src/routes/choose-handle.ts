/**
 * GET  /auth/choose-handle — Render handle picker page for new users
 * POST /auth/choose-handle — Validate chosen handle, sign callback, redirect
 * GET  /api/check-handle   — JSON availability endpoint (session-gated)
 *
 * Flow:
 *   1. New user arrives here after OTP verification (redirected from /auth/complete)
 *   2. User picks a local-part handle; client-side JS checks availability in real-time
 *   3. On POST, server validates format + availability, then:
 *      a. Signs the epds-callback URL with the chosen handle included in HMAC
 *      b. Deletes auth_flow row + clears cookie (deferred cleanup from complete.ts)
 *      c. Redirects to pds-core /oauth/epds-callback
 *
 * The auth_flow cookie and row are intentionally kept alive through the GET
 * (complete.ts deferred cleanup) and only cleaned up on successful POST.
 */
import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import { createLogger, escapeHtml, signCallback } from '@certified-app/shared'
import { fromNodeHeaders } from 'better-auth/node'
import { getDidByEmail } from '../lib/get-did-by-email.js'

const logger = createLogger('auth:choose-handle')

const AUTH_FLOW_COOKIE = 'epds_auth_flow'

/** Regex for valid handle local parts: 3-20 chars, lowercase alphanumeric + hyphens, no leading/trailing hyphen */
export const HANDLE_REGEX = /^[a-z0-9][a-z0-9-]{1,18}[a-z0-9]$/

/** Reserved handles that cannot be registered */
export const RESERVED_HANDLES = new Set([
  'admin',
  'support',
  'help',
  'abuse',
  'postmaster',
  'root',
  'system',
  'moderator',
  'www',
  'mail',
  'ftp',
  'api',
  'auth',
  'oauth',
  'account',
  'settings',
  'security',
  'info',
  'contact',
  'noreply',
  'no-reply',
])

export function createChooseHandleRouter(
  ctx: AuthServiceContext,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth instance has no exported type
  auth: any,
): Router {
  const router = Router()

  const pdsUrl = process.env.PDS_INTERNAL_URL || ctx.config.pdsPublicUrl
  const internalSecret = process.env.EPDS_INTERNAL_SECRET ?? ''
  const handleDomain = ctx.config.pdsHostname

  /**
   * Shared guard: validates the auth_flow cookie + session.
   * Returns { flowId, flow, email } on success, or sends an error response and returns null.
   */
  async function getFlowAndSession(
    req: Request,
    res: Response,
  ): Promise<{
    flowId: string
    flow: { requestUri: string }
    email: string
  } | null> {
    // Guard 1: auth_flow cookie
    const flowId = req.cookies[AUTH_FLOW_COOKIE] as string | undefined
    if (!flowId) {
      logger.warn('No epds_auth_flow cookie on choose-handle')
      res
        .status(400)
        .type('html')
        .send(renderError('Session expired, please start over'))
      return null
    }

    // Guard 2: auth_flow row in DB
    const flow = ctx.db.getAuthFlow(flowId)
    if (!flow) {
      logger.warn({ flowId }, 'auth_flow not found or expired on choose-handle')
      res.clearCookie(AUTH_FLOW_COOKIE)
      res
        .status(400)
        .type('html')
        .send(renderError('Session expired, please start over'))
      return null
    }

    // Guard 3: better-auth session
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth session type not exported
    let session: any
    try {
      session = await auth.api.getSession({
        headers: fromNodeHeaders(req.headers),
      })
    } catch (err) {
      logger.error(
        { err },
        'Failed to get better-auth session on choose-handle',
      )
      res
        .status(500)
        .type('html')
        .send(renderError('Authentication failed. Please try again.'))
      return null
    }

    if (!session?.user?.email) {
      logger.warn({ flowId }, 'No authenticated session on choose-handle')
      res
        .status(401)
        .type('html')
        .send(renderError('Session expired, please start over'))
      return null
    }

    return { flowId, flow, email: session.user.email.toLowerCase() }
  }

  // ---------------------------------------------------------------------------
  // Handler 1: GET /auth/choose-handle — Render handle picker page
  // ---------------------------------------------------------------------------
  router.get('/auth/choose-handle', async (req: Request, res: Response) => {
    const result = await getFlowAndSession(req, res)
    if (!result) return

    const { email } = result

    // Guard: if PDS account already exists for this email, redirect to /auth/complete
    const did = await getDidByEmail(email, pdsUrl, internalSecret)
    if (did) {
      logger.info(
        { email },
        'Existing user reached choose-handle — redirecting to /auth/complete',
      )
      res.redirect(303, '/auth/complete')
      return
    }

    const error = req.query.error as string | undefined
    res.type('html').send(renderChooseHandlePage(handleDomain, error))
  })

  // ---------------------------------------------------------------------------
  // Handler 2: POST /auth/choose-handle — Validate, sign callback, redirect
  // ---------------------------------------------------------------------------
  router.post('/auth/choose-handle', async (req: Request, res: Response) => {
    const result = await getFlowAndSession(req, res)
    if (!result) return

    const { flowId, flow, email } = result

    // Step 1: Read and normalise the local part
    const rawHandle = ((req.body.handle as string) || '').trim().toLowerCase()

    // Step 2: Validate format
    if (!HANDLE_REGEX.test(rawHandle)) {
      logger.debug({ rawHandle }, 'Invalid handle format on POST choose-handle')
      res
        .type('html')
        .send(
          renderChooseHandlePage(
            handleDomain,
            'Invalid handle format. Use 3-20 lowercase letters, numbers, or hyphens.',
          ),
        )
      return
    }

    // Step 3: Check reserved blocklist
    if (RESERVED_HANDLES.has(rawHandle)) {
      logger.debug(
        { rawHandle },
        'Reserved handle rejected on POST choose-handle',
      )
      res
        .type('html')
        .send(renderChooseHandlePage(handleDomain, 'That handle is reserved.'))
      return
    }

    // Step 4: Construct full handle and check availability via PDS internal API
    const fullHandle = `${rawHandle}.${handleDomain}`
    let handleAvailable = false
    try {
      const checkRes = await fetch(
        `${pdsUrl}/_internal/check-handle?handle=${encodeURIComponent(fullHandle)}`,
        {
          headers: { 'x-internal-secret': internalSecret },
          signal: AbortSignal.timeout(5000),
        },
      )
      if (checkRes.ok) {
        const data = (await checkRes.json()) as { exists: boolean }
        handleAvailable = !data.exists
      } else {
        logger.warn(
          { status: checkRes.status, fullHandle },
          'PDS check-handle returned non-OK status',
        )
      }
    } catch (err) {
      logger.error({ err, fullHandle }, 'Failed to check handle availability')
      res
        .type('html')
        .send(
          renderChooseHandlePage(
            handleDomain,
            'Could not verify handle availability. Please try again.',
          ),
        )
      return
    }

    if (!handleAvailable) {
      res
        .type('html')
        .send(
          renderChooseHandlePage(handleDomain, 'That handle is already taken.'),
        )
      return
    }

    // Step 5: Sign callback with handle included in HMAC payload
    const callbackParams = {
      request_uri: flow.requestUri,
      email,
      approved: '1',
      new_account: '1',
      handle: fullHandle,
    }
    const { sig, ts } = signCallback(
      callbackParams,
      ctx.config.epdsCallbackSecret,
    )
    const params = new URLSearchParams({ ...callbackParams, ts, sig })

    // Step 6: Cleanup — delete auth_flow row and clear cookie
    ctx.db.deleteAuthFlow(flowId)
    res.clearCookie(AUTH_FLOW_COOKIE)

    logger.info(
      { email, flowId, fullHandle },
      'Handle chosen: redirecting to epds-callback',
    )
    res.redirect(
      303,
      `${ctx.config.pdsPublicUrl}/oauth/epds-callback?${params.toString()}`,
    )
  })

  // ---------------------------------------------------------------------------
  // Handler 3: GET /api/check-handle — JSON availability endpoint
  // ---------------------------------------------------------------------------
  router.get('/api/check-handle', async (req: Request, res: Response) => {
    // Guard: require active better-auth session
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth session type not exported
    let session: any
    try {
      session = await auth.api.getSession({
        headers: fromNodeHeaders(req.headers),
      })
    } catch {
      res.status(401).json({ error: 'unauthenticated' })
      return
    }

    if (!session?.user?.email) {
      res.status(401).json({ error: 'unauthenticated' })
      return
    }

    // Read and validate the local part
    const localPart = ((req.query.handle as string) || '').trim().toLowerCase()

    if (!HANDLE_REGEX.test(localPart)) {
      res.json({ error: 'invalid_format' })
      return
    }

    if (RESERVED_HANDLES.has(localPart)) {
      res.json({ error: 'reserved', available: false })
      return
    }

    const fullHandle = `${localPart}.${handleDomain}`

    try {
      const checkRes = await fetch(
        `${pdsUrl}/_internal/check-handle?handle=${encodeURIComponent(fullHandle)}`,
        {
          headers: { 'x-internal-secret': internalSecret },
          signal: AbortSignal.timeout(5000),
        },
      )
      if (!checkRes.ok) {
        logger.warn(
          { status: checkRes.status, fullHandle },
          'PDS check-handle returned non-OK on /api/check-handle',
        )
        res.json({ error: 'check_failed' })
        return
      }
      const data = (await checkRes.json()) as { exists: boolean }
      const available = !data.exists
      res.json({ available, handle: fullHandle })
    } catch (err) {
      logger.error(
        { err, fullHandle },
        'Failed to check handle availability via PDS',
      )
      res.json({ error: 'check_failed' })
    }
  })

  return router
}

// ---------------------------------------------------------------------------
// Template
// ---------------------------------------------------------------------------

function renderChooseHandlePage(handleDomain: string, error?: string): string {
  const errorHtml = error
    ? `<div class="error" id="error-msg">${escapeHtml(error)}</div>`
    : `<div class="error" id="error-msg" style="display:none;"></div>`

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Choose your handle</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { background: white; border-radius: 12px; padding: 40px; max-width: 420px; width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    h1 { font-size: 24px; margin-bottom: 8px; color: #111; }
    .subtitle { color: #666; margin-bottom: 24px; font-size: 15px; line-height: 1.5; }
    .field { margin-bottom: 16px; }
    .field label { display: block; font-size: 14px; font-weight: 500; color: #333; margin-bottom: 6px; }
    .handle-row { display: flex; align-items: center; gap: 0; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; background: white; }
    .handle-row:focus-within { border-color: #0f1828; }
    .handle-row input { flex: 1; padding: 10px 12px; border: none; font-size: 16px; outline: none; background: transparent; min-width: 0; }
    .handle-suffix { padding: 10px 12px; background: #f8f9fa; color: #555; font-size: 15px; white-space: nowrap; border-left: 1px solid #ddd; }
    .status { min-height: 20px; font-size: 14px; margin-top: 6px; }
    .status.available { color: #28a745; }
    .status.taken { color: #dc3545; }
    .status.checking { color: #888; }
    .status.format-error { color: #dc3545; }
    .error { color: #dc3545; background: #fdf0f0; padding: 12px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
    .btn-primary { width: 100%; padding: 12px; background: #0f1828; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; margin-top: 8px; }
    .btn-primary:hover:not(:disabled) { background: #1a2a40; }
    .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Choose your handle</h1>
    <p class="subtitle">Your handle is your public username on the AT Protocol network.</p>

    ${errorHtml}

    <form method="POST" action="/auth/choose-handle" id="handle-form">
      <div class="field">
        <label for="handle-input">Handle</label>
        <div class="handle-row">
          <input
            type="text"
            id="handle-input"
            name="handle"
            placeholder="yourname"
            autocomplete="off"
            autocapitalize="none"
            spellcheck="false"
            maxlength="20"
          >
          <span class="handle-suffix">.${escapeHtml(handleDomain)}</span>
        </div>
        <div class="status" id="handle-status"></div>
      </div>
      <button type="submit" id="submit-btn" class="btn-primary" disabled>Continue</button>
    </form>
  </div>

  <script>
    (function() {
      var HANDLE_REGEX = /^[a-z0-9][a-z0-9-]{1,18}[a-z0-9]$/;
      var RESERVED = new Set([
        'admin','support','help','abuse','postmaster','root','system',
        'moderator','www','mail','ftp','api','auth','oauth','account',
        'settings','security','info','contact','noreply','no-reply'
      ]);

      var input = document.getElementById('handle-input');
      var statusEl = document.getElementById('handle-status');
      var submitBtn = document.getElementById('submit-btn');
      var errorMsg = document.getElementById('error-msg');
      var debounceTimer = null;
      var lastChecked = '';
      var isAvailable = false;

      function setStatus(text, cls) {
        statusEl.textContent = text;
        statusEl.className = 'status' + (cls ? ' ' + cls : '');
      }

      function updateSubmit() {
        submitBtn.disabled = !isAvailable;
      }

      function checkAvailability(value) {
        if (value === lastChecked) return;
        lastChecked = value;
        isAvailable = false;
        updateSubmit();

        setStatus('Checking\u2026', 'checking');

        fetch('/api/check-handle?handle=' + encodeURIComponent(value))
          .then(function(r) { return r.json(); })
          .then(function(data) {
            if (data.error === 'invalid_format') {
              setStatus('Invalid format.', 'format-error');
            } else if (data.error === 'reserved') {
              setStatus('\u2717 That handle is reserved.', 'taken');
            } else if (data.error) {
              setStatus('Could not check availability.', 'format-error');
            } else if (data.available) {
              setStatus('\u2713 Available!', 'available');
              isAvailable = true;
            } else {
              setStatus('\u2717 Already taken.', 'taken');
            }
            updateSubmit();
          })
          .catch(function() {
            setStatus('Could not check availability.', 'format-error');
            updateSubmit();
          });
      }

      input.addEventListener('input', function() {
        // Normalise: lowercase, strip invalid chars
        var raw = this.value.toLowerCase().replace(/[^a-z0-9-]/g, '');
        if (this.value !== raw) {
          var pos = this.selectionStart;
          this.value = raw;
          this.setSelectionRange(pos, pos);
        }

        isAvailable = false;
        updateSubmit();
        clearTimeout(debounceTimer);

        if (!raw) {
          setStatus('', '');
          return;
        }

        if (RESERVED.has(raw)) {
          setStatus('\u2717 That handle is reserved.', 'taken');
          return;
        }

        if (!HANDLE_REGEX.test(raw)) {
          setStatus('3\u201320 characters, letters, numbers, or hyphens. Cannot start or end with a hyphen.', 'format-error');
          return;
        }

        // Valid format — debounce the availability check
        debounceTimer = setTimeout(function() {
          checkAvailability(raw);
        }, 500);
      });

      // Hide server-rendered error once user starts typing
      input.addEventListener('input', function() {
        if (errorMsg && errorMsg.style.display !== 'none') {
          errorMsg.style.display = 'none';
        }
      }, { once: true });
    })();
  </script>
</body>
</html>`
}

function renderError(message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Error</title></head>
<body><p style="color:red;padding:20px">${escapeHtml(message)}</p></body>
</html>`
}
