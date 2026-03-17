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
 *      b. Auth_flow row is left intact for handle_taken retry — TTL cleanup handles expiry
 *      c. Redirects to pds-core /oauth/epds-callback
 *
 * The auth_flow cookie and row are intentionally kept alive so that if pds-core
 * redirects back with ?error=handle_taken, the user can retry with a different handle.
 * Stale rows are cleaned up by cleanupExpiredAuthFlows() every 5 minutes.
 */
import { Router, type Request, type Response } from 'express'
import type { AuthServiceContext } from '../context.js'
import {
  createLogger,
  escapeHtml,
  signCallback,
  validateLocalPart,
  type HandleMode,
} from '@certified-app/shared'
import { fromNodeHeaders } from 'better-auth/node'
import { getDidByEmail } from '../lib/get-did-by-email.js'

const logger = createLogger('auth:choose-handle')

const AUTH_FLOW_COOKIE = 'epds_auth_flow'

export function createChooseHandleRouter(
  ctx: AuthServiceContext,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- better-auth instance has no exported type
  auth: any,
): Router {
  const router = Router()

  const pdsUrl = process.env.PDS_INTERNAL_URL
  const internalSecret = process.env.EPDS_INTERNAL_SECRET
  if (!pdsUrl || !internalSecret) {
    throw new Error('PDS_INTERNAL_URL and EPDS_INTERNAL_SECRET must be set')
  }
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
    flow: {
      requestUri: string
      handleMode: HandleMode | null
    }
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

    // Reset the PAR request inactivity timer so it doesn't expire while the
    // user is on this page. atproto's AUTHORIZATION_INACTIVITY_TIMEOUT is 5 min
    // — without this ping, users who take >5 min to pick a handle would hit
    // "This request has expired" inside epds-callback after account creation.
    try {
      const pingRes = await fetch(
        `${pdsUrl}/_internal/ping-request?request_uri=${encodeURIComponent(result.flow.requestUri)}`,
        {
          headers: { 'x-internal-secret': internalSecret },
          signal: AbortSignal.timeout(3000),
        },
      )
      if (!pingRes.ok) {
        logger.warn(
          { status: pingRes.status, requestUri: result.flow.requestUri },
          'Failed to extend request_uri on choose-handle',
        )
        res
          .status(400)
          .type('html')
          .send(renderError('Session expired, please start over'))
        return
      }
    } catch (err) {
      logger.warn({ err }, 'Failed to ping request_uri on choose-handle')
      res
        .status(400)
        .type('html')
        .send(renderError('Session expired, please start over'))
      return
    }

    const KNOWN_ERROR_MESSAGES: Record<string, string> = {
      handle_taken: 'That handle was just taken — please choose another.',
    }
    const rawError = req.query.error as string | undefined
    const error = rawError
      ? (KNOWN_ERROR_MESSAGES[rawError] ?? rawError)
      : undefined
    const showRandomButton = result.flow.handleMode === 'picker-with-random'
    res
      .type('html')
      .send(
        renderChooseHandlePage(
          handleDomain,
          error,
          res.locals.csrfToken,
          showRandomButton,
        ),
      )
  })

  // ---------------------------------------------------------------------------
  // Handler 2: POST /auth/choose-handle — Validate, sign callback, redirect
  // ---------------------------------------------------------------------------
  router.post('/auth/choose-handle', async (req: Request, res: Response) => {
    const result = await getFlowAndSession(req, res)
    if (!result) return

    const { flowId, flow, email } = result
    const showRandomButton = flow.handleMode === 'picker-with-random'

    // Guard: if PDS account already exists, bounce back to /auth/complete
    // (mirrors the same check in the GET handler — prevents signing a
    // new_account callback for an existing user who somehow reaches this POST)
    const did = await getDidByEmail(email, pdsUrl, internalSecret)
    if (did) {
      logger.info(
        { email },
        'Existing user reached POST choose-handle — redirecting to /auth/complete',
      )
      res.redirect(303, '/auth/complete')
      return
    }

    // Re-ping the PAR request to ensure it hasn't expired while the user was
    // on the handle picker page. Without this, a user who took >5 min would
    // get "This request has expired" inside epds-callback after account creation.
    try {
      const pingRes = await fetch(
        `${pdsUrl}/_internal/ping-request?request_uri=${encodeURIComponent(flow.requestUri)}`,
        {
          headers: { 'x-internal-secret': internalSecret },
          signal: AbortSignal.timeout(3000),
        },
      )
      if (!pingRes.ok) {
        logger.warn(
          { status: pingRes.status, requestUri: flow.requestUri },
          'Failed to extend request_uri on POST choose-handle',
        )
        res
          .status(400)
          .type('html')
          .send(renderError('Session expired, please start over'))
        return
      }
    } catch (err) {
      logger.warn({ err }, 'Failed to ping request_uri on POST choose-handle')
      res
        .status(400)
        .type('html')
        .send(renderError('Session expired, please start over'))
      return
    }

    // Step 1: Read and normalise the local part
    const rawHandle = ((req.body.handle as string) || '').trim()

    // Step 2: Validate format and normalise via atproto spec + product constraints
    const normalizedLocal = validateLocalPart(rawHandle, handleDomain)
    if (normalizedLocal === null) {
      logger.debug({ rawHandle }, 'Invalid handle format on POST choose-handle')
      res
        .type('html')
        .send(
          renderChooseHandlePage(
            handleDomain,
            'Invalid handle format. Use 5-20 lowercase letters, numbers, or hyphens.',
            res.locals.csrfToken,
            showRandomButton,
          ),
        )
      return
    }

    // Step 3: Construct full handle and check availability via PDS internal API
    const fullHandle = `${normalizedLocal}.${handleDomain}`
    let handleAvailable: boolean
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
        res
          .type('html')
          .send(
            renderChooseHandlePage(
              handleDomain,
              'Could not verify handle availability. Please try again.',
              res.locals.csrfToken,
              showRandomButton,
            ),
          )
        return
      }
    } catch (err) {
      logger.error({ err, fullHandle }, 'Failed to check handle availability')
      res
        .type('html')
        .send(
          renderChooseHandlePage(
            handleDomain,
            'Could not verify handle availability. Please try again.',
            res.locals.csrfToken,
            showRandomButton,
          ),
        )
      return
    }

    if (!handleAvailable) {
      res
        .type('html')
        .send(
          renderChooseHandlePage(
            handleDomain,
            'That handle is already taken.',
            res.locals.csrfToken,
            showRandomButton,
          ),
        )
      return
    }

    // Step 5: Sign callback with handle local part included in HMAC payload.
    // Only the local part (e.g. 'alice') is sent — pds-core appends its own
    // trusted handleDomain, eliminating any possibility of domain mismatch.
    const callbackParams = {
      request_uri: flow.requestUri,
      email,
      approved: '1',
      new_account: '1',
      handle: normalizedLocal,
    }
    const { sig, ts } = signCallback(
      callbackParams,
      ctx.config.epdsCallbackSecret,
    )
    const params = new URLSearchParams({ ...callbackParams, ts, sig })

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

    // Read, validate and normalise the local part
    const rawLocalPart = ((req.query.handle as string) || '').trim()
    const normalizedLocal = validateLocalPart(rawLocalPart, handleDomain)
    if (normalizedLocal === null) {
      res.json({ error: 'invalid_format' })
      return
    }

    const fullHandle = `${normalizedLocal}.${handleDomain}`

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
        res.json({ error: 'service_unavailable' })
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
      res.json({ error: 'service_unavailable' })
    }
  })

  return router
}

// ---------------------------------------------------------------------------
// Template
// ---------------------------------------------------------------------------

function renderChooseHandlePage(
  handleDomain: string,
  error?: string,
  csrfToken?: string,
  showRandomButton?: boolean,
): string {
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
    .btn-secondary { width: 100%; padding: 10px; background: white; color: #0f1828; border: 1px solid #0f1828; border-radius: 8px; font-size: 15px; font-weight: 500; cursor: pointer; margin-top: 8px; }
    .btn-secondary:hover:not(:disabled) { background: #f0f2f5; }
    .btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Choose your handle</h1>
    <p class="subtitle">Your handle is your public username on the AT Protocol network.</p>

    ${errorHtml}

    <form method="POST" action="/auth/choose-handle" id="handle-form">
      <input type="hidden" name="csrf" value="${escapeHtml(csrfToken || '')}">
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
            minlength="5"
            maxlength="20"
          >
          <span class="handle-suffix">.${escapeHtml(handleDomain)}</span>
        </div>
        <div class="status" id="handle-status"></div>
      </div>
      ${showRandomButton ? `<button type="button" id="random-btn" class="btn-secondary">Generate random handle</button>` : ''}
      <button type="submit" id="submit-btn" class="btn-primary">Create</button>
    </form>
  </div>

  <script>
    (function() {
      var input = document.getElementById('handle-input');
      var statusEl = document.getElementById('handle-status');
      var submitBtn = document.getElementById('submit-btn');
      var errorMsg = document.getElementById('error-msg');
      var form = document.getElementById('handle-form');
      var debounceTimer = null;
      var currentAbort = null;

      // isAvailable: null = unknown, true = confirmed available, false = confirmed taken.
      // submitBtn is disabled only when handle is confirmed taken or unavailable.
      var isAvailable = null;

      function setStatus(text, cls) {
        statusEl.textContent = text;
        statusEl.className = 'status' + (cls ? ' ' + cls : '');
      }

      function updateSubmit() {
        submitBtn.disabled = isAvailable === false;
      }
      updateSubmit();

      function checkAvailability(value) {
        // Cancel any in-flight request for a previous value
        if (currentAbort) currentAbort.abort();
        currentAbort = new AbortController();

        setStatus('Checking\u2026', 'checking');

        fetch('/api/check-handle?handle=' + encodeURIComponent(value), {
          signal: currentAbort.signal,
        })
          .then(function(r) { return r.json(); })
          .then(function(data) {
            currentAbort = null;
            if (data.error === 'invalid_format') {
              isAvailable = false;
              setStatus('5\u201320 characters, letters, numbers, or hyphens. Cannot start or end with a hyphen.', 'format-error');
            } else if (data.error) {
              // Service error: unknown state — don't block the button, show a hint
              isAvailable = null;
              setStatus('Could not check availability.', 'format-error');
            } else if (data.available) {
              isAvailable = true;
              setStatus('\u2713 Available!', 'available');
            } else {
              isAvailable = false;
              setStatus('\u2717 Already taken.', 'taken');
            }
            updateSubmit();
          })
          .catch(function(err) {
            if (err.name === 'AbortError') return; // silently ignore cancelled requests
            currentAbort = null;
            // Network/timeout error: unknown state — don't block if handle isn't confirmed taken
            isAvailable = null;
            setStatus('Could not check availability.', 'format-error');
            updateSubmit();
          });
      }

      input.addEventListener('input', function() {
        // Normalise: lowercase, strip invalid chars as you type
        var raw = this.value.toLowerCase().replace(/[^a-z0-9-]/g, '');
        if (this.value !== raw) {
          var pos = this.selectionStart;
          this.value = raw;
          this.setSelectionRange(pos, pos);
        }

        // Reset state unconditionally on every keystroke
        isAvailable = null;
        clearTimeout(debounceTimer);
        if (currentAbort) { currentAbort.abort(); currentAbort = null; }

        if (!raw) {
          setStatus('', '');
          updateSubmit();
          return;
        }

        // Let the server validate format — kick off debounced availability check
        updateSubmit();
        debounceTimer = setTimeout(function() {
          checkAvailability(raw);
        }, 500);
      });

      // Random handle button: generate a base36 local part client-side (mirrors
      // generateRandomHandle() in shared/src/crypto.ts) and confirm availability
      // via /api/check-handle, retrying up to 3 times on collision.
      var randomBtn = document.getElementById('random-btn');
      if (randomBtn) {
        function randomLocalPart() {
          var arr = new Uint8Array(4);
          crypto.getRandomValues(arr);
          // Reconstruct as unsigned 32-bit big-endian int (matches readUInt32BE)
          var num = ((arr[0] << 24) | (arr[1] << 16) | (arr[2] << 8) | arr[3]) >>> 0;
          return num.toString(36).padStart(6, '0').slice(0, 6);
        }

        function tryRandomHandle(attemptsLeft) {
          if (attemptsLeft <= 0) {
            setStatus('Could not find a free handle. Try again.', 'format-error');
            randomBtn.disabled = false;
            return;
          }
          var local = randomLocalPart();
          input.value = local;
          isAvailable = null;
          updateSubmit();
          setStatus('Checking\u2026', 'checking');

          fetch('/api/check-handle?handle=' + encodeURIComponent(local), {
            signal: AbortSignal.timeout(5000),
          })
            .then(function(r) { return r.json(); })
            .then(function(data) {
              if (data.available) {
                isAvailable = true;
                setStatus('\u2713 Available!', 'available');
                updateSubmit();
                randomBtn.disabled = false;
              } else if (data.error) {
                // Service error — don't retry, surface the problem
                setStatus('Could not check availability.', 'format-error');
                randomBtn.disabled = false;
              } else {
                // Genuinely taken — retry with a new random value
                tryRandomHandle(attemptsLeft - 1);
              }
            })
            .catch(function() {
              setStatus('Could not check availability.', 'format-error');
              randomBtn.disabled = false;
            });
        }

        randomBtn.addEventListener('click', function() {
          clearTimeout(debounceTimer);
          if (currentAbort) { currentAbort.abort(); currentAbort = null; }
          randomBtn.disabled = true;
          tryRandomHandle(3);
        });
      }

      // Disable button for the duration of the POST to prevent double-submit
      form.addEventListener('submit', function() {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Creating\u2026';
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
