/**
 * ePDS Core
 *
 * Wraps the stock @atproto/pds with:
 * - OAuth /epds-callback endpoint that issues authorization codes directly
 * - Modified AS metadata pointing authorization_endpoint to auth subdomain
 * - Account creation for new users (via PLC + repo init)
 *
 * Flow:
 *   1. Client -> PAR -> PDS (stock)
 *   2. PDS redirects to auth.pds.example/oauth/authorize (via AS metadata)
 *   3. User enters email, receives verification code, verifies
 *   4. Auth service redirects to pds.example/oauth/epds-callback
 *   5. ePDS callback: creates account if needed, issues code, redirects to client
 */
import * as dotenv from 'dotenv'
dotenv.config()

// @atproto/pds reads PDS_PORT, not PORT.  On Railway the platform injects
// PORT and uses it for healthchecks, so fall back to PORT when PDS_PORT is
// not explicitly set.  This must happen before readEnv().
import { applyPdsPortFallback } from './lib/resolve-port.js'
applyPdsPortFallback()

import type * as http from 'node:http'
import { randomBytes, timingSafeEqual, createHash } from 'node:crypto'
import { PDS, envToCfg, envToSecrets, readEnv } from '@atproto/pds'
import { readFileSync } from 'node:fs'
/* v8 ignore next 3 -- module-level init, only testable via e2e */
const atprotoPdsPkg: { version: string } = JSON.parse(
  readFileSync(require.resolve('@atproto/pds/package.json'), 'utf8'),
)
import { HandleUnavailableError } from '@atproto/oauth-provider'
import {
  generateRandomHandle,
  createLogger,
  verifyCallback,
  escapeHtml,
  validateLocalPart,
  resolveClientMetadata,
  getClientCss,
  getEpdsVersion,
} from '@certified-app/shared'
import { shouldRewriteSecFetchSite } from './lib/sec-fetch-site-rewrite.js'
import { createClientCssInjectionMiddleware } from './lib/client-css-injection.js'

const logger = createLogger('pds-core')

async function main() {
  const env = readEnv()
  env.version ??= atprotoPdsPkg.version
  const cfg = envToCfg(env)
  const secrets = envToSecrets(env)

  const authHostname = process.env.AUTH_HOSTNAME || 'auth.localhost'
  const handleDomain = process.env.PDS_HOSTNAME || 'localhost'
  const pdsUrl = cfg.service.publicUrl || `https://${handleDomain}`

  const pds = await PDS.create(cfg, secrets)
  const ctx = pds.ctx
  const provider = ctx.oauthProvider

  if (!provider) {
    logger.warn(
      'OAuth provider not configured, starting without ePDS callback integration',
    )
  } else {
    logger.info('OAuth provider active, setting up ePDS callback integration')
  }

  // =========================================================================
  // EPDS CALLBACK - The core integration endpoint
  // =========================================================================
  //
  // Called by the auth service after OTP verification + user consent.
  // Steps: load device -> resolve account -> issue code -> redirect to client

  const epdsCallbackSecret =
    process.env.EPDS_CALLBACK_SECRET || 'dev-callback-secret-change-me'

  // When true, consent may be skipped on initial sign-up for trusted clients
  // that request it via epds_skip_consent_on_signup in their metadata.
  const signupAllowConsentSkip =
    process.env.PDS_SIGNUP_ALLOW_CONSENT_SKIP === 'true' ||
    process.env.PDS_SIGNUP_ALLOW_CONSENT_SKIP === '1'

  pds.app.get('/oauth/epds-callback', async (req, res) => {
    // We use `as any` casts for branded OAuth types (RequestUri, Code, etc.)
    // since these internal types aren't cleanly exported from @atproto/oauth-provider.

    const requestUri = req.query.request_uri as string
    const email = ((req.query.email as string) || '').toLowerCase()
    const approved = req.query.approved === '1'
    const _isNewAccount = req.query.new_account === '1'
    const ts = req.query.ts as string
    const sig = req.query.sig as string

    if (!requestUri || !email || !approved) {
      res.status(400).json({ error: 'Missing required parameters' })
      return
    }

    // Verify HMAC-SHA256 signature before performing any account operations.
    // This prevents an attacker with a valid request_uri from forging a callback
    // with an arbitrary victim email.
    if (!ts || !sig) {
      res.status(403).json({ error: 'Missing signature' })
      return
    }

    const approvedStr = req.query.approved as string
    const newAccountStr = req.query.new_account as string
    const handleParam = req.query.handle as string | undefined
    const signatureValid = verifyCallback(
      {
        request_uri: requestUri,
        email,
        approved: approvedStr,
        new_account: newAccountStr,
        handle: handleParam,
      },
      ts,
      sig,
      epdsCallbackSecret,
    )

    if (!signatureValid) {
      // Distinguish expired from invalid to help with clock-skew debugging
      const tsNum = parseInt(ts, 10)
      const age = Math.floor(Date.now() / 1000) - tsNum
      if (!isNaN(tsNum) && age > 5 * 60) {
        res.status(400).json({ error: 'Callback signature expired' })
      } else {
        res.status(403).json({ error: 'Invalid callback signature' })
      }
      return
    }

    // Extract handle local part from verified callback params (tamper-proof — covered by HMAC).
    // The callback now carries only the local part (e.g. 'alice'); we append our own
    // trusted handleDomain here so there is no possibility of domain mismatch.
    const chosenHandleLocal = handleParam
    const chosenHandle = chosenHandleLocal
      ? `${chosenHandleLocal}.${handleDomain}`
      : undefined

    // Defense in depth: validate the local part format before use.
    // (auth-service already validated, but we re-check at the trust boundary)
    if (chosenHandleLocal) {
      if (validateLocalPart(chosenHandleLocal, handleDomain) === null) {
        logger.error(
          { handle: chosenHandleLocal },
          'invalid handle local part format in epds-callback',
        )
        res.status(400).send('Invalid handle format')
        return
      }
    }

    if (!provider) {
      res.status(500).json({ error: 'OAuth provider not configured' })
      return
    }

    try {
      // Step 1: Load or create device session
      const deviceInfo = await provider.deviceManager.load(
        req as unknown as http.IncomingMessage,
        res as unknown as http.ServerResponse,
      )
      const { deviceId, deviceMetadata } = deviceInfo

      // Step 2: Refresh the PAR request expiry timer.
      // Call get() WITHOUT deviceId so it doesn't bind one — the stock
      // oauthMiddleware will bind the browser's deviceId when we redirect
      // through /oauth/authorize below.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider requestManager not exported
      const requestData = await (provider.requestManager as any).get(requestUri)
      const { clientId } = requestData

      // Step 3: Resolve or create the account.
      // Use the PDS accountManager directly — account.sqlite is the single source of truth.
      // Backup email lookup (recovery flow) is handled by the auth-service before issuing
      // the HMAC-signed callback; by the time we reach here, email is the verified primary.
      const existingAccount =
        await pds.ctx.accountManager.getAccountByEmail(email)
      let did: string | undefined = existingAccount?.did

      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider Account type not exported
      let account: any

      if (did) {
        // Existing account
        const accountData = await provider.accountManager.getAccount(did)
        account = accountData.account
      } else if (chosenHandle) {
        // User chose a handle — pre-check existence before attempting createAccount.
        // This avoids treating non-collision errors (datastore failures, invite-code
        // misconfiguration, etc.) as handle collisions.
        const existingHandle =
          await pds.ctx.accountManager.getAccount(chosenHandle)
        if (existingHandle) {
          logger.warn(
            { handle: chosenHandle },
            'chosen handle already taken (pre-check)',
          )
          res.redirect(
            303,
            `https://${authHostname}/auth/choose-handle?error=handle_taken`,
          )
          return
        }

        // Handle is free — attempt account creation. Any error here is NOT a
        // collision (we just confirmed the handle is available), so log as error
        // and return 500 rather than silently redirecting to handle_taken.
        try {
          account = await provider.accountManager.createAccount(
            deviceId,
            deviceMetadata,
            {
              locale: 'en',
              handle: chosenHandle,
              email,
              // Use a random unguessable password so the PDS creates a proper account
              // row (registerAccount requires a password). The password is never
              // returned or stored anywhere accessible, so the account is effectively
              // passwordless — login is only possible via the magic OTP flow.
              password: randomBytes(32).toString('hex'),
              // Invite code is required when PDS_INVITE_REQUIRED is true (the default).
              // EPDS_INVITE_CODE should be a high-useCount code generated via the admin API.
              inviteCode: process.env.EPDS_INVITE_CODE,
            },
          )
          did = account.sub
          logger.info(
            { did, email, handle: chosenHandle },
            'Created account with chosen handle',
          )
        } catch (createErr: unknown) {
          if (createErr instanceof HandleUnavailableError) {
            // Reserved handle slipped past the pre-check (pre-check only tests DB existence,
            // not the reserved-subdomain list). Redirect back to handle picker.
            logger.warn(
              { handle: chosenHandle },
              'Handle unavailable during createAccount (reserved or taken)',
            )
            res.redirect(
              303,
              `https://${authHostname}/auth/choose-handle?error=handle_taken`,
            )
            return
          }
          logger.error(
            { err: createErr, handle: chosenHandle },
            'createAccount failed',
          )
          res
            .status(500)
            .type('html')
            .send(renderError('Account creation failed. Please try again.'))
          return
        }
      } else {
        /**
         * CONTRACT: absent `handle` param is the agreed signal from auth-service that
         * the user chose random-mode (handleMode='random' in the auth_flow row).
         *
         * @see {@link ../../auth-service/src/routes/complete.ts}
         * @see {@link ../../shared/src/__tests__/crypto.test.ts}
         */
        for (let attempt = 0; attempt < 3; attempt++) {
          try {
            const randomHandle = generateRandomHandle(handleDomain)
            account = await provider.accountManager.createAccount(
              deviceId,
              deviceMetadata,
              {
                locale: 'en',
                handle: randomHandle,
                email,
                // Use a random unguessable password so the PDS creates a proper account
                // row (registerAccount requires a password). The password is never
                // returned or stored anywhere accessible, so the account is effectively
                // passwordless — login is only possible via the magic OTP flow.
                password: randomBytes(32).toString('hex'),
                // Invite code is required when PDS_INVITE_REQUIRED is true (the default).
                // EPDS_INVITE_CODE should be a high-useCount code generated via the admin API.
                inviteCode: process.env.EPDS_INVITE_CODE,
              },
            )
            did = account.sub
            logger.info({ did, email, handle: randomHandle }, 'Created account')
            break
          } catch (createErr: unknown) {
            if (attempt === 2) throw createErr
            logger.warn(
              { err: createErr, attempt },
              'Account creation attempt failed, retrying',
            )
          }
        }
      }

      // Step 4: Bind account to device session (for future SSO).
      await provider.accountManager.upsertDeviceAccount(deviceId, account.sub)

      // Step 5: Determine whether to skip consent on sign-up.
      // Consent is skipped only when ALL of these hold:
      //   a) This is a brand-new account (not an existing user)
      //   b) PDS_SIGNUP_ALLOW_CONSENT_SKIP is truthy
      //   c) The client is trusted (listed in PDS_OAUTH_TRUSTED_CLIENTS)
      //   d) The client's metadata has epds_skip_consent_on_signup: true
      const isNewAccount = !existingAccount

      if (isNewAccount && signupAllowConsentSkip) {
        try {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider Client type not exported
          const client = await (provider.clientManager as any).getClient(
            clientId,
          )
          const clientMetadata = await resolveClientMetadata(clientId)

          if (
            client.info?.isTrusted &&
            clientMetadata.epds_skip_consent_on_signup === true
          ) {
            // Bind device to the PAR request so setAuthorized() can proceed
            // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider requestManager not exported
            const requestData = await (provider.requestManager as any).get(
              requestUri,
              deviceId,
            )
            const { parameters } = requestData

            // Issue authorization code directly (bypasses /oauth/authorize)
            // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider requestManager not exported
            const code = await (provider.requestManager as any).setAuthorized(
              requestUri,
              client,
              account,
              deviceId,
              deviceMetadata,
            )

            // Record the client as authorized so future logins can auto-approve
            const scopeStr = parameters.scope as string | undefined
            const scopes = scopeStr?.split(' ') ?? []
            await provider.accountManager.setAuthorizedClient(account, client, {
              authorizedScopes: scopes,
            })

            // Build redirect URL and send user directly to client
            const redirectUri = parameters.redirect_uri as string | undefined
            if (!redirectUri) {
              res
                .status(400)
                .json({ error: 'No redirect_uri in authorization request' })
              return
            }

            const redirectUrl = new URL(redirectUri)
            const responseMode = (parameters.response_mode as string) || 'query'
            const redirectParams: [string, string][] = [
              ['iss', pdsUrl],
              ['code', code],
            ]
            if (parameters.state) {
              redirectParams.push(['state', parameters.state as string])
            }

            if (responseMode === 'fragment') {
              const fragmentParams = new URLSearchParams()
              for (const [k, v] of redirectParams) fragmentParams.set(k, v)
              redirectUrl.hash = fragmentParams.toString()
            } else {
              for (const [k, v] of redirectParams) {
                redirectUrl.searchParams.set(k, v)
              }
            }

            res.setHeader('Cache-Control', 'no-store')
            res.redirect(303, redirectUrl.toString())

            logger.info(
              { did, clientId },
              'ePDS callback: consent skipped on sign-up (trusted client), redirecting to client',
            )
            return
          }
        } catch (err) {
          // If consent-skip fails for any reason, fall through to normal flow
          logger.warn(
            { err, clientId },
            'ePDS callback: consent-skip check failed, falling through to normal flow',
          )
        }
      }

      // Step 6: Set login_hint in the stored PAR parameters so the stock
      // authorize UI auto-selects this account's session and skips account
      // selection (going straight to consent or auto-approve).
      // The oauth-provider UI checks `selected` which is true when
      // login_hint matches the account AND prompt !== 'select_account'.
      // prompt is already 'consent' (forced by the provider for
      // unauthenticated clients).
      if (did) {
        const REQUEST_URI_PREFIX = 'urn:ietf:params:oauth:request_uri:'
        const requestId = decodeURIComponent(
          requestUri.slice(REQUEST_URI_PREFIX.length),
        )
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider store not exported
        const store = (provider.requestManager as any).store
        const storedRequest = await store.readRequest(requestId)
        if (storedRequest?.parameters) {
          await store.updateRequest(requestId, {
            parameters: { ...storedRequest.parameters, login_hint: did },
          })
        }
      }

      // Step 7: Redirect through the stock /oauth/authorize endpoint.
      // The oauthMiddleware will call provider.authorize() which:
      // - Finds the device session we just created via upsertDeviceAccount
      // - Checks checkConsentRequired() against actual OAuth scopes
      // - Auto-approves if no consent needed (SSO match, previously authorized scopes)
      // - Renders the upstream consent UI (consent-view.tsx) if consent is required
      const authorizeUrl = new URL('/oauth/authorize', pdsUrl)
      authorizeUrl.searchParams.set('request_uri', requestUri)
      authorizeUrl.searchParams.set('client_id', clientId)

      res.setHeader('Cache-Control', 'no-store')
      res.redirect(303, authorizeUrl.toString())

      logger.info(
        { did, clientId, isNewAccount },
        'ePDS callback: redirecting to stock /oauth/authorize for consent/approval',
      )
    } catch (err) {
      logger.error({ err }, 'ePDS callback error')

      // Try to redirect error back to client
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider requestManager not exported
        const requestData = await (provider.requestManager as any).get(
          requestUri,
        )
        const redirectUri = requestData?.parameters?.redirect_uri
        if (redirectUri) {
          const errorUrl = new URL(redirectUri)
          errorUrl.searchParams.set('error', 'server_error')
          errorUrl.searchParams.set(
            'error_description',
            'Authentication failed',
          )
          errorUrl.searchParams.set('iss', pdsUrl)
          if (requestData.parameters.state) {
            errorUrl.searchParams.set('state', requestData.parameters.state)
          }
          res.redirect(303, errorUrl.toString())
          return
        }
      } catch {
        // Fall through
      }

      if (!res.headersSent) {
        res.status(500).json({ error: 'Authentication failed' })
      }
    }
  })

  // =========================================================================
  // Override AS metadata - point authorization_endpoint to auth subdomain
  // =========================================================================
  //
  // The stock OAuth provider pre-serializes metadata into a buffer at init time
  // via staticJsonMiddleware, mounted as middleware (app.use) before any routes.
  // We can't override it with app.get() since middleware runs first.
  //
  // Solution: inject our own middleware at the very front of the Express stack
  // so it intercepts the request before the stock OAuth middleware.

  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Express middleware injected into raw stack
  const asMetadataOverride = (req: any, res: any, next: any) => {
    if (
      req.method === 'GET' &&
      req.path === '/.well-known/oauth-authorization-server'
    ) {
      const authUrl = `https://${authHostname}`
      res.setHeader('Access-Control-Allow-Origin', '*')
      res.setHeader('Cache-Control', 'public, max-age=300')
      res.setHeader('Content-Type', 'application/json')
      res.json({
        ...provider!.metadata,
        authorization_endpoint: `${authUrl}/oauth/authorize`,
      })
      return
    }
    next()
  }

  // Rewrite sec-fetch-site: same-site → same-origin for GET /oauth/authorize.
  //
  // PR #21 changed epds-callback to redirect through the stock
  // @atproto/oauth-provider /oauth/authorize endpoint. The browser tags that
  // redirect as `same-site` (auth subdomain → PDS origin), but the upstream
  // oauth-provider rejects `same-site` — it only accepts `same-origin`,
  // `cross-site`, or `none`.
  //
  // We rewrite only when the referer is the auth subdomain, the PDS itself,
  // or absent (no referer). Unknown same-site origins are left untouched to
  // preserve the security boundary.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Express middleware injected into raw stack
  const secFetchSiteRewrite = (req: any, _res: any, next: any) => {
    if (
      shouldRewriteSecFetchSite({
        method: req.method,
        path: req.path,
        secFetchSite: req.headers['sec-fetch-site'],
        referer: req.headers['referer'],
        authOrigin: `https://${authHostname}`,
        pdsOrigin: pdsUrl,
      })
    ) {
      req.headers['sec-fetch-site'] = 'same-origin'
    }
    next()
  }

  // Insert both middlewares at position 0 in the Express middleware stack so
  // they run before the stock authRoutes middleware. Register them both, then
  // pop and splice each one in, in reverse registration order so that
  // secFetchSiteRewrite ends up at insertIdx and asMetadataOverride follows.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- accessing Express internal _router stack
  const stack = (pds.app as any)._router?.stack
  if (stack) {
    // Find expressInit and insert right after it so req.path is available,
    // but before the authRoutes router that serves stock OAuth metadata.
    let insertIdx = 0
    for (let i = 0; i < stack.length; i++) {
      if (stack[i].name === 'expressInit') {
        insertIdx = i + 1
        break
      }
    }

    pds.app.use(asMetadataOverride)
    const metadataLayer = stack.pop()

    pds.app.use(secFetchSiteRewrite)
    const secFetchLayer = stack.pop()

    // Insert in order: secFetchSiteRewrite first, then asMetadataOverride
    stack.splice(insertIdx, 0, secFetchLayer, metadataLayer)
    logger.info('AS metadata override and sec-fetch-site rewrite installed')
  }

  // =========================================================================
  // CSS injection for trusted OAuth clients
  // =========================================================================
  //
  // The npm @atproto/oauth-provider pre-computes CSS at factory init time.
  // We intercept /oauth/authorize responses to inject a <style> tag with
  // client-provided CSS and add the SHA256 hash to the CSP style-src.

  const trustedClients = (process.env.PDS_OAUTH_TRUSTED_CLIENTS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

  if (trustedClients.length > 0) {
    const cssInjectionMiddleware = createClientCssInjectionMiddleware({
      trustedClients,
      resolveClientMetadata,
      getClientCss,
      resolveClientIdFromRequestUri: provider
        ? async (requestUri: string) => {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider requestManager not exported
            const requestData = await (provider.requestManager as any).get(requestUri)
            return requestData?.clientId as string | undefined
          }
        : undefined,
      logger,
    })

    // Insert into Express stack after expressInit (same approach as AS metadata)
    pds.app.use(cssInjectionMiddleware)
    const cssLayer = stack?.pop()
    if (stack && cssLayer) {
      let insertIdx = 0
      for (let i = 0; i < stack.length; i++) {
        if (stack[i].name === 'expressInit') {
          insertIdx = i + 1
          break
        }
      }
      stack.splice(insertIdx, 0, cssLayer)
      logger.info(
        { trustedClients },
        'CSS injection middleware installed for trusted OAuth clients',
      )
    }
  }

  // =========================================================================
  // Internal endpoints
  // =========================================================================

  /** Timing-safe check of the x-internal-secret header. Returns false if the
   *  env var is unset or the header is missing/mismatched.
   *  Both values are hashed to SHA-256 so timingSafeEqual always receives
   *  equal-length buffers, avoiding length-leak timing side-channels and
   *  ERR_INVALID_ARG_VALUE throws from multibyte string length mismatches. */
  function verifyInternalSecret(
    header: string | string[] | undefined,
  ): boolean {
    const secret = process.env.EPDS_INTERNAL_SECRET
    if (!secret || typeof header !== 'string') return false
    const hash = (v: string) => createHash('sha256').update(v).digest()
    return timingSafeEqual(hash(header), hash(secret))
  }

  // Protected internal endpoint for auth service to look up an account by email.
  // Replaces the old unauthenticated /_magic/check-email to prevent email enumeration.
  // Queries account.sqlite directly via the PDS accountManager — no mirror table needed.
  pds.app.get('/_internal/account-by-email', async (req, res) => {
    if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const email = ((req.query.email as string) || '').trim().toLowerCase()
    if (!email) {
      res.status(400).json({ error: 'Missing email' })
      return
    }
    try {
      const account = await pds.ctx.accountManager.getAccountByEmail(email)
      res.json({ did: account?.did ?? null })
    } catch (err) {
      logger.error({ err }, 'Failed to look up account by email')
      res.status(500).json({ error: 'Internal server error' })
    }
  })

  // Protected internal endpoint for auth service to look up an account by handle or DID.
  // Used to resolve AT Protocol login_hints (handles or DIDs) to email addresses so the
  // auth service can skip the email form and go straight to OTP.
  // accountManager.getAccount() accepts both handles and DIDs.
  pds.app.get('/_internal/account-by-handle', async (req, res) => {
    if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const handle = ((req.query.handle as string) || '').trim()
    if (!handle) {
      res.status(400).json({ error: 'Missing handle' })
      return
    }
    try {
      const account = await pds.ctx.accountManager.getAccount(handle)
      res.json({ email: account?.email ?? null })
    } catch (err) {
      logger.error({ err }, 'Failed to look up account by handle')
      res.status(500).json({ error: 'Internal server error' })
    }
  })

  // Protected internal endpoint for auth service to check if a handle is already
  // taken on this PDS. Used by the handle availability checker during signup.
  // Returns only { exists: boolean } — never returns email, DID, or other account data.
  pds.app.get('/_internal/check-handle', async (req, res) => {
    if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const handle = ((req.query.handle as string) || '').trim()
    if (!handle) {
      res.status(400).json({ error: 'missing handle param' })
      return
    }
    try {
      const account = await pds.ctx.accountManager.getAccount(handle)
      res.json({ exists: !!account })
    } catch (err) {
      logger.error({ err, handle }, 'Failed to check handle availability')
      res.status(503).json({ error: 'handle_check_failed' })
    }
  })

  // TEMPORARY debug endpoint for HYPER-270 investigation.
  //
  // Dumps all authorized_client and account_device rows for a given DID so
  // we can observe which grants were (or weren't) persisted when a user
  // clicks Authorize on the upstream consent UI for an untrusted client.
  //
  // Gated on EPDS_DEBUG_GRANTS=1 in addition to the usual
  // EPDS_INTERNAL_SECRET check so it only comes online in environments
  // where we've explicitly enabled it. Remove this endpoint and its env
  // var before merging PR #21.
  if (process.env.EPDS_DEBUG_GRANTS === '1') {
    pds.app.get('/_internal/debug-grants', async (req, res) => {
      if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }
      const sub = ((req.query.sub as string) || '').trim()
      if (!sub) {
        res.status(400).json({ error: 'Missing sub' })
        return
      }
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/pds accountManager internals not exported
        const am = pds.ctx.accountManager as any
        const db = am.db

        const authorizedClients = await db.db
          .selectFrom('authorized_client')
          .select(['did', 'clientId', 'createdAt', 'updatedAt', 'data'])
          .where('did', '=', sub)
          .execute()

        const accountDevices = await db.db
          .selectFrom('account_device')
          .select(['did', 'deviceId', 'createdAt', 'updatedAt'])
          .where('did', '=', sub)
          .execute()

        res.json({ sub, authorizedClients, accountDevices })
      } catch (err) {
        logger.error({ err, sub }, 'debug-grants query failed')
        res.status(500).json({ error: 'query_failed', message: String(err) })
      }
    })

    // Also expose a "recent accounts" lookup so we can find the sub of the
    // e2e test user without knowing its DID up front.
    pds.app.get('/_internal/debug-recent-accounts', async (req, res) => {
      if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }
      const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 5))
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const am = pds.ctx.accountManager as any
        const db = am.db

        // Join actor with account to pull the email too, so we can
        // cross-reference e2e scenario test emails (e.g. the
        // "approved-untrusted-<ts>@example.com" pattern) against the
        // DID in the debug-grants lookup.
        const rows = await db.db
          .selectFrom('actor')
          .leftJoin('account', 'account.did', 'actor.did')
          .select([
            'actor.did as did',
            'actor.handle as handle',
            'actor.createdAt as createdAt',
            'account.email as email',
          ])
          .orderBy('actor.createdAt', 'desc')
          .limit(limit)
          .execute()

        res.json({ rows })
      } catch (err) {
        logger.error({ err }, 'debug-recent-accounts query failed')
        res.status(500).json({ error: 'query_failed', message: String(err) })
      }
    })

    logger.warn(
      'EPDS_DEBUG_GRANTS=1: /_internal/debug-grants and /_internal/debug-recent-accounts endpoints are enabled (HYPER-270 debugging)',
    )
  }

  // Protected internal endpoint for auth service to reset the inactivity timer
  // on a pending PAR request_uri. Called when the user loads the handle selection
  // page so the request doesn't expire while they are choosing a handle.
  // atproto's AUTHORIZATION_INACTIVITY_TIMEOUT is 5 minutes — without this ping,
  // users who take >5 min on the handle page would get "This request has expired"
  // inside epds-callback after account creation, leaving the auth flow broken.
  pds.app.get('/_internal/ping-request', async (req, res) => {
    if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const requestUri = ((req.query.request_uri as string) || '').trim()
    if (!requestUri) {
      res.status(400).json({ error: 'Missing request_uri' })
      return
    }
    if (!provider) {
      res.status(503).json({ error: 'OAuth provider not available' })
      return
    }
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider requestManager not exported
      await (provider.requestManager as any).get(requestUri)
      res.json({ ok: true })
    } catch (err) {
      // Request expired or not found — not a server error, just report it
      logger.debug(
        { err, requestUri },
        'ping-request: request_uri expired or not found',
      )
      res.status(404).json({ error: 'request_expired' })
    }
  })

  // Protected internal endpoint for auth service to retrieve the login_hint
  // stored in a PAR request. Third-party apps put the handle/DID in the PAR body
  // but don't duplicate it on the authorization redirect URL. The auth service
  // needs to retrieve it to resolve the user's email for OTP.
  pds.app.get('/_internal/par-login-hint', async (req, res) => {
    if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const requestUri = ((req.query.request_uri as string) || '').trim()
    if (!requestUri) {
      res.status(400).json({ error: 'Missing request_uri' })
      return
    }
    try {
      const oauthProvider = pds.ctx.oauthProvider
      if (!oauthProvider) {
        res.status(503).json({ error: 'OAuth provider not available' })
        return
      }
      // Cast to the branded RequestUri type expected by requestManager.get()
      const request = await oauthProvider.requestManager.get(
        requestUri as `urn:ietf:params:oauth:request_uri:req-${string}`,
      )
      res.json({ login_hint: request.parameters.login_hint ?? null })
    } catch (err) {
      logger.debug({ err, requestUri }, 'Failed to read PAR login_hint')
      // Not found or expired — not an error, just no hint available
      res.json({ login_hint: null })
    }
  })

  // =========================================================================
  // TLS check - used by Caddy on-demand TLS to verify handle ownership
  // =========================================================================

  pds.app.get('/tls-check', async (req, res) => {
    await checkHandleRoute(pds, authHostname, req, res)
  })

  pds.app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'epds', version: getEpdsVersion() })
  })

  await pds.start()
  logger.info({ port: cfg.service.port, pdsUrl, authHostname }, 'ePDS running')

  const shutdown = async () => {
    logger.info('ePDS shutting down')
    await pds.destroy()
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

/** Caddy on-demand TLS ask handler.
 *  Returns 200 if the domain is the PDS hostname, the auth subdomain, or a
 *  valid hosted handle, so Caddy knows it should provision a certificate for it. */
async function checkHandleRoute(
  pds: PDS,
  authHostname: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Express types not directly available in this package
  req: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Express types not directly available in this package
  res: any,
) {
  try {
    const { domain } = req.query
    if (!domain || typeof domain !== 'string') {
      return res.status(400).json({
        error: 'InvalidRequest',
        message: 'bad or missing domain query param',
      })
    }
    // Allow the PDS hostname and the auth subdomain through unconditionally
    if (domain === pds.ctx.cfg.service.hostname || domain === authHostname) {
      return res.json({ success: true })
    }
    const isHostedHandle = pds.ctx.cfg.identity.serviceHandleDomains.find(
      (avail: string) => domain.endsWith(avail),
    )
    if (!isHostedHandle) {
      return res.status(400).json({
        error: 'InvalidRequest',
        message: 'handles are not provided on this domain',
      })
    }
    const account = await pds.ctx.accountManager.getAccount(domain)
    if (!account) {
      return res.status(404).json({
        error: 'NotFound',
        message: 'handle not found for this domain',
      })
    }
    return res.json({ success: true })
  } catch (err) {
    logger.error({ err }, 'check handle failed')
    return res
      .status(500)
      .json({ error: 'InternalServerError', message: 'Internal Server Error' })
  }
}

function renderError(message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Error</title></head>
<body><p style="color:red;padding:20px">${escapeHtml(message)}</p></body>
</html>`
}

main().catch((err: unknown) => {
  logger.fatal({ err }, 'Failed to start ePDS')
  process.exit(1)
})
