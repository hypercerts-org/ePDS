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
import { randomBytes } from 'node:crypto'
import * as path from 'node:path'
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
  verifyInternalSecret,
  validateLocalPart,
  resolveClientMetadata,
  getClientCss,
  getClientMetadataCacheStatus,
  getEpdsVersion,
  renderError,
  validateClientMetadataForPreview,
} from '@certified-app/shared'
import { shouldRewriteSecFetchSite } from './lib/sec-fetch-site-rewrite.js'
import {
  findInsertionIndex,
  installCssInjectionMiddleware,
} from './lib/client-css-injection.js'
import express, { type Application, type Request, type Response } from 'express'
import {
  createPreviewConsentHandler,
  renderPreviewIndex,
} from './lib/preview-consent.js'
import { createPreviewChooserHandler } from './lib/preview-chooser.js'
import {
  createCookieDomainMiddleware,
  deriveCookieDomain,
} from './cookie-domain.js'
import { createChooserEnrichmentMiddleware } from './chooser-enrichment.js'
import { createUpstreamFaviconMiddleware } from './upstream-favicon.js'
import { createAuthUiGuard, parsePromptTokens } from './auth-ui-guard.js'
import { loadDeviceAccountEmails } from './lib/device-accounts.js'
import { handleCallbackError } from './lib/epds-callback-error.js'
import { installTestHooks } from './lib/test-hooks.js'

const logger = createLogger('pds-core')

/**
 * Wire up the /preview/* routes on the given Express app, if
 * `createPreviewConsentHandler` returned a handler (i.e. the env flag
 * is on). No-op otherwise. Factored out of `main` to keep its cognitive
 * complexity under the Sonar ceiling.
 */
function installPreviewRoutes(
  app: Application,
  opts: {
    previewConsentHandler: NonNullable<
      ReturnType<typeof createPreviewConsentHandler>
    >
    previewChooserHandler: NonNullable<
      ReturnType<typeof createPreviewChooserHandler>
    >
    authHostname: string
    pdsPublicUrl: string
    trustedClients: string[]
  },
): void {
  // auth-service runs on auth.<PDS_HOSTNAME>; pds-core is pdsPublicUrl.
  // Use https for real hostnames, http for localhost (see setup.sh and
  // Caddyfile — same rule applied in auth-service's preview router).
  const authScheme =
    opts.authHostname === 'localhost' ||
    opts.authHostname.endsWith('.localhost')
      ? 'http'
      : 'https'
  const authPublicUrl = `${authScheme}://${opts.authHostname}`
  app.get('/preview', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8')
    res.send(
      renderPreviewIndex({ authPublicUrl, pdsPublicUrl: opts.pdsPublicUrl }),
    )
  })
  app.get('/preview/consent', opts.previewConsentHandler)
  app.get('/preview/chooser', opts.previewChooserHandler)
  app.get('/preview/cache-status', (_req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store')
    res.json({ now: Date.now(), entries: getClientMetadataCacheStatus() })
  })
  app.get('/preview/validate', async (req: Request, res: Response) => {
    const url =
      typeof req.query.client_id === 'string' ? req.query.client_id : ''
    res.setHeader('Cache-Control', 'no-store')
    if (!url) {
      res.json({ url: '', fetched: false, checks: [] })
      return
    }
    const result = await validateClientMetadataForPreview(
      url,
      opts.trustedClients,
    )
    res.json(result)
  })
  logger.info(
    'Preview routes installed (PDS_PREVIEW_ROUTES=1): /preview, /preview/consent, /preview/chooser, /preview/cache-status, /preview/validate',
  )
}

async function main() {
  const env = readEnv()
  env.version ??= atprotoPdsPkg.version
  const cfg = envToCfg(env)
  const secrets = envToSecrets(env)

  const authHostname = process.env.AUTH_HOSTNAME || 'auth.localhost'
  const handleDomain = process.env.PDS_HOSTNAME || 'localhost'
  const pdsUrl = cfg.service.publicUrl || `https://${handleDomain}`

  // The shared parent domain for cross-subdomain device-session cookies, or
  // null when auth-service and pds-core are on unrelated hostnames (e.g.
  // Railway preview envs, where both services live under up.railway.app
  // and cookies stay host-only). Computed once and reused for both the
  // cookie-domain broadening middleware and the host-only-twin clear in
  // /oauth/epds-callback. When null, the broadening is a no-op so device
  // cookies are themselves host-only — emitting host-only clears in that
  // case would evict the freshly-minted session cookies.
  const cookieDomain = deriveCookieDomain(authHostname, handleDomain)

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

    // Captured from Step 2's requestManager.get() — used by the catch
    // block to redirect any later failure back to the client per RFC
    // 6749 §4.1.2.1, even when the PAR row has since been deleted (in
    // particular: RequestManager.get() deletes any expired row in the
    // same call that throws AccessDeniedError, so by the time the
    // catch block runs there's nothing left to re-read). Empty when
    // Step 2 itself threw — i.e. the PAR was already dead on entry,
    // the case the @par-callback-error scenario covers — and the
    // catch falls through to a styled HTML page in that branch.
    let capturedRedirectUri: string | undefined
    let capturedState: string | undefined

    try {
      // Step 1: Load or create device session
      const deviceInfo = await provider.deviceManager.load(
        req as unknown as http.IncomingMessage,
        res as unknown as http.ServerResponse,
      )
      const { deviceId, deviceMetadata } = deviceInfo

      // Step 1b (issue #116): when this deployment broadens device-session
      // cookies to a shared parent domain, evict any host-only twin that
      // a pre-PR-#103 session may have left in the browser jar. Browsers
      // store host-only and Domain-scoped cookies of the same name as
      // distinct entries; when both are present, the cookie parser picks
      // the host-only one first per RFC 6265 §5.4 ordering, shadowing the
      // fresh Domain-scoped pair we just emitted in Step 1. The explicit
      // host-only Max-Age=0 clear here forces the browser to evict the
      // stale twin before the very next request, so the welcome-page
      // guard at /oauth/authorize sees only the fresh pair. Idempotent —
      // emitting clears for cookies that don't exist is a no-op.
      // The cookie-domain middleware passes Max-Age=0 lines through
      // unchanged (also added in #116) so these clears reach the browser
      // without a Domain= attribute and match the host-only scope.
      // Skipped on deployments where the cookie-domain broadening is a
      // no-op (auth-service and pds-core on unrelated hostnames, e.g.
      // Railway preview envs under up.railway.app) — there the device
      // cookies set in Step 1 are themselves host-only, so emitting a
      // host-only clear would evict them.
      if (cookieDomain) {
        for (const name of ['dev-id', 'dev-id:hash', 'ses-id', 'ses-id:hash']) {
          res.append('Set-Cookie', `${name}=; Max-Age=0; Path=/`)
        }
      }

      // Step 2: Refresh the PAR request expiry timer.
      // Call get() WITHOUT deviceId so it doesn't bind one — the stock
      // oauthMiddleware will bind the browser's deviceId when we redirect
      // through /oauth/authorize below.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider requestManager not exported
      const requestData = await (provider.requestManager as any).get(requestUri)
      const { clientId } = requestData
      // Stash redirect_uri/state now while the PAR is alive — if a later
      // step throws and the row has since been deleted (e.g. flushed
      // post-success or the test-only delete-par hook), the catch block
      // can still mount an RFC 6749 redirect to the client.
      capturedRedirectUri = requestData?.parameters?.redirect_uri
      capturedState = requestData?.parameters?.state

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

      // Step 6: Mutate the stored PAR parameters before redirecting to the
      // stock /oauth/authorize endpoint:
      //
      //   - Set `login_hint` to the freshly-authenticated DID so the stock
      //     authorize UI auto-selects this account's session and skips
      //     account selection. The oauth-provider UI checks `selected`,
      //     which is true when login_hint matches the account AND
      //     prompt !== 'select_account'. (prompt is already 'consent',
      //     forced by the provider for unauthenticated clients.)
      //
      //   - Strip the `login` token from `prompt` if present. The
      //     auth-ui-guard at /oauth/authorize bounces requests whose
      //     stored PAR carries prompt=login, so leaving it set after a
      //     successful OTP cycle would loop forever: authenticate →
      //     bounce → authenticate → bounce. By the time this hop fires,
      //     the user IS freshly authenticated; the forced-login
      //     contract is satisfied. Other prompt tokens ('consent',
      //     'select_account', etc.) stay untouched — only 'login' is
      //     loop-forming.
      if (did) {
        const REQUEST_URI_PREFIX = 'urn:ietf:params:oauth:request_uri:'
        const requestId = decodeURIComponent(
          requestUri.slice(REQUEST_URI_PREFIX.length),
        )
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider store not exported
        const store = (provider.requestManager as any).store
        const storedRequest = await store.readRequest(requestId)
        if (storedRequest?.parameters) {
          const nextParams: Record<string, unknown> = {
            ...storedRequest.parameters,
            login_hint: did,
          }
          // Strip the 'login' token from the prompt parameter, leaving any
          // other tokens (e.g. 'consent') intact. Per OIDC Core §3.1.2.1
          // prompt is space-delimited; a third-party client could send
          // 'login consent', and an exact-string strip would miss 'login'
          // in that case and re-trigger the guard's bounce after every
          // OTP cycle.
          if (typeof nextParams.prompt === 'string') {
            const remaining = parsePromptTokens(nextParams.prompt)
            remaining.delete('login')
            if (remaining.size === 0) {
              delete nextParams.prompt
            } else {
              nextParams.prompt = [...remaining].join(' ')
            }
          }
          await store.updateRequest(requestId, { parameters: nextParams })
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
      handleCallbackError({
        res,
        err,
        capturedRedirectUri,
        capturedState,
        pdsUrl,
        logger,
        renderError,
      })
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
  // Auth-UI guard: never let upstream render the welcome page or sign-in-view
  // =========================================================================
  //
  // The stock @atproto/oauth-provider has two authentication UIs that ePDS
  // must never surface:
  //
  //   1. Welcome page (Authenticate / Create new account / Sign in / Cancel) —
  //      rendered when upstream ends up with a device that has zero bound
  //      accounts (partial cookie pairs, stale pairs, fixation-race device
  //      deletions, or the migration-005 1h TTL purge of remember=0 bindings).
  //
  //   2. Sign-in-view (handle + password form) — rendered when bindings exist
  //      but every binding upstream considers has loginRequired: true (forced
  //      `prompt=login`, all bindings older than authenticationMaxAge, or
  //      login_hint pre-selecting an individually stale binding).
  //
  // ePDS users should always land on the email/OTP form or the enriched
  // account picker. See docs/design/session-reuse-bugs.md.
  //
  // The guard intercepts /oauth/authorize and /account* before upstream's
  // own middleware and bounces to auth-service with stale cookies cleared
  // whenever upstream would render either UI. All other requests pass
  // through unchanged.

  const authUiGuardMiddleware = createAuthUiGuard({
    authHostname,
    provider: provider ?? null,
    cookieDomain,
    logger,
  })
  pds.app.use(authUiGuardMiddleware)
  // Fail closed: the guard has to run BEFORE upstream's OAuth / account
  // middleware, otherwise it can never intercept the stock UIs. If the
  // Express `_router.stack` we rely on isn't exposed (Express 5, future
  // pds-core swap), refuse to start rather than silently run the service
  // with the guard defeated — the whole security value of this guard
  // depends on the splice succeeding.
  if (!stack) {
    throw new Error(
      'Auth-UI guard install failed: Express _router.stack is unavailable — refusing to start pds-core with an inert guard',
    )
  }
  const guardLayer = stack.pop()
  if (!guardLayer) {
    throw new Error(
      'Auth-UI guard install failed: middleware layer missing from stack after pop',
    )
  }
  let guardIdx = 0
  for (let i = 0; i < stack.length; i++) {
    if (stack[i].name === 'expressInit') {
      guardIdx = i + 1
      break
    }
  }
  stack.splice(guardIdx, 0, guardLayer)
  logger.info('Auth-UI guard installed')

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

  installCssInjectionMiddleware(pds.app, stack, {
    trustedClients,
    resolveClientMetadata,
    getClientCss,
    resolveClientIdFromRequestUri: provider
      ? async (requestUri: string) => {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @atproto/oauth-provider requestManager not exported
          const requestData = await (provider.requestManager as any).get(
            requestUri,
          )
          return requestData?.clientId as string | undefined
        }
      : undefined,
    logger,
  })

  // auth-service origin baked into the injected enrichment script's
  // "Another account" rebind, and into the chooser preview's
  // <meta name="epds-auth-origin"> so the preview exercises the same
  // rebind path. Hoisted above preview wiring so it's available to
  // createPreviewChooserHandler. https for real hosts, http for
  // localhost-flavoured dev.
  const authOriginScheme =
    authHostname === 'localhost' || authHostname.endsWith('.localhost')
      ? 'http'
      : 'https'
  const authOrigin = `${authOriginScheme}://${authHostname}`

  // =========================================================================
  // Preview routes for iterating on branding.css
  // =========================================================================
  //
  // Gated by PDS_PREVIEW_ROUTES=1. Renders the OAuth consent + chooser
  // pages with fixture hydration data so client-app developers can
  // iterate on their branding.css without walking through the full
  // OAuth flow. The CSS injection middleware above intercepts /preview/*
  // responses exactly like /oauth/authorize — the trusted-clients gate
  // still applies. See docs/tutorial.md for the full reference.

  const previewConsentHandler = createPreviewConsentHandler({
    trustedClients,
    resolveClientMetadata,
    getClientCss,
    logger,
  })
  const previewChooserHandler = createPreviewChooserHandler({
    trustedClients,
    resolveClientMetadata,
    getClientCss,
    authOrigin,
    logger,
  })
  if (previewConsentHandler && previewChooserHandler) {
    installPreviewRoutes(pds.app, {
      previewConsentHandler,
      previewChooserHandler,
      authHostname,
      pdsPublicUrl: pdsUrl,
      trustedClients,
    })
  }

  // =========================================================================
  // Account chooser enrichment (HYPER-268)
  // =========================================================================
  //
  // The upstream @atproto/oauth-provider account chooser (/account) is a
  // compiled React SPA that renders each bound account as a clickable
  // row — showing only the handle (preferred_username), not the email.
  // For ePDS deployments where handles may be randomly generated and
  // hard for users to recognise, this is a real UX problem. We need
  // email alongside handle so users can identify themselves.
  //
  // Strategy — reusing the PR #9 response-rewrite pattern:
  //   1. Intercept HTML responses from the upstream /account routes.
  //   2. Inject a <script> in the <head> (before the hydration script
  //      fires) that (a) captures the upstream deviceSessions payload
  //      via an accessor on window.__deviceSessions, (b) watches the
  //      DOM after hydration, and (c) appends each account's email as
  //      a small label next to its handle. See cross-client-session-reuse.md
  //      for the design doc.
  //
  // Unlike PR #9's CSS injection, we're inserting JS — which requires
  // adding a script hash to the CSP script-src directive rather than
  // style-src.

  // authOrigin is computed above (preview wiring also needs it).

  const chooserEnrichmentMiddleware = createChooserEnrichmentMiddleware({
    resolveClientMetadata,
    authOrigin,
  })

  pds.app.use(chooserEnrichmentMiddleware)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- accessing Express internal _router stack
  const chooserStack = (pds.app as any)._router?.stack
  if (chooserStack) {
    const chooserLayer = chooserStack.pop()
    // Must run AFTER compression so our res.end wrapper sees the raw
    // uncompressed HTML and can find the `</head>` marker — same
    // constraint as the CSS-injection middleware above. Earlier
    // iterations spliced this immediately after expressInit, which
    // left compression's wrapped end() on top of ours so we only ever
    // saw gzipped bytes and the <script> never got injected.
    const insertIdx = findInsertionIndex(chooserStack)
    chooserStack.splice(insertIdx, 0, chooserLayer)
    logger.info(
      { insertIdx },
      'Account chooser enrichment middleware installed (HYPER-268)',
    )
  }

  // Favicon injection for upstream `@atproto/oauth-provider`-rendered
  // pages (`/account*`, `/oauth/*`). Same post-compression placement as
  // chooser-enrichment so our wrapped end() sees the raw uncompressed
  // HTML and can find `<head>`.
  pds.app.use(createUpstreamFaviconMiddleware())
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- accessing Express internal _router stack
  const faviconStack = (pds.app as any)._router?.stack
  if (faviconStack) {
    const faviconLayer = faviconStack.pop()
    const insertIdx = findInsertionIndex(faviconStack)
    faviconStack.splice(insertIdx, 0, faviconLayer)
    logger.info({ insertIdx }, 'Upstream favicon middleware installed')
  }

  // Serve /static/favicon*.svg from packages/pds-core/public so the
  // pds-core-rendered error page and the /preview/consent shell can
  // reference the Certified favicon without a cross-origin request to
  // the auth-service host.
  const publicDir = path.resolve(__dirname, '..', 'public')
  pds.app.get('/favicon.ico', (_req, res) => {
    res.sendFile(path.join(publicDir, 'favicon.svg'))
  })
  pds.app.use('/static', express.static(publicDir))

  // =========================================================================
  // Cookie domain broadening (HYPER-268)
  // =========================================================================
  //
  // Upstream @atproto/oauth-provider sets dev-id and ses-id cookies with no
  // Domain attribute, which scopes them to the exact pds-core host. The
  // auth-service runs on a sibling subdomain (e.g. auth.pds.foo.com) and
  // cannot read those cookies — so it has no way to detect an existing
  // device session when a second OAuth client starts a new /oauth/authorize
  // flow.
  //
  // Fix: intercept all outbound Set-Cookie headers for the device-session
  // cookies and inject Domain=<parent>. With Domain=pds.foo.com both
  // pds.foo.com and auth.pds.foo.com see the cookie, unlocking the
  // cross-subdomain session-reuse path.
  //
  // Auto-derived: if AUTH_HOSTNAME ends with .<PDS_HOSTNAME>, PDS_HOSTNAME
  // is the shared parent and we use it as the cookie domain. Otherwise
  // (e.g. Railway preview envs where services have unrelated hostnames
  // under a public suffix), there is no valid parent and the middleware
  // is skipped — session reuse simply isn't possible on those topologies.
  // Upstream's DeviceManager has no domain option, so we rewrite headers
  // rather than pass config.

  if (cookieDomain) {
    const cookieDomainMiddleware = createCookieDomainMiddleware(cookieDomain)

    pds.app.use(cookieDomainMiddleware)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- accessing Express internal _router stack
    const cookieStack = (pds.app as any)._router?.stack
    if (cookieStack) {
      const cookieLayer = cookieStack.pop()
      let insertIdx = 0
      for (let i = 0; i < cookieStack.length; i++) {
        if (cookieStack[i].name === 'expressInit') {
          insertIdx = i + 1
          break
        }
      }
      cookieStack.splice(insertIdx, 0, cookieLayer)
    }
    logger.info(
      { cookieDomain },
      'Cookie domain broadening middleware installed (HYPER-268)',
    )
  }

  // =========================================================================
  // Internal endpoints
  // =========================================================================

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

  // Protected internal endpoint for auth-service to enumerate the emails
  // of every account bound to the supplied (dev-id, ses-id) cookie pair.
  // Used by Flow 1 session-reuse: when a login_hint resolves to an email
  // that is NOT in this list, auth-service skips the chooser redirect and
  // renders its own OTP form for a fresh sign-in. A null `emails` field
  // means the cookie pair was malformed, unknown, or stale (ses-id no
  // longer matches the device row) — caller should treat this the same
  // as "no usable session" and bypass session reuse for this request.
  pds.app.get('/_internal/device-accounts', async (req, res) => {
    if (!verifyInternalSecret(req.headers['x-internal-secret'])) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const devId = ((req.query.dev_id as string) || '').trim()
    const sesId = ((req.query.ses_id as string) || '').trim()
    if (!devId || !sesId) {
      res.status(400).json({ error: 'Missing dev_id or ses_id' })
      return
    }
    if (!provider) {
      res.status(503).json({ error: 'OAuth provider not available' })
      return
    }
    const emails = await loadDeviceAccountEmails({
      provider,
      deviceId: devId,
      sessionId: sesId,
      logger,
    })
    res.json({ emails })
  })

  installTestHooks({ pds, app: pds.app, logger })

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

main().catch((err: unknown) => {
  logger.fatal({ err }, 'Failed to start ePDS')
  process.exit(1)
})
