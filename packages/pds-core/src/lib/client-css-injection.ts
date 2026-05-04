import { createHash } from 'node:crypto'

import type { ClientMetadata } from '@certified-app/shared'
import { DEFAULT_BRANDING_CSS } from './default-branding.js'

type LoggerLike = {
  info: (obj: object, msg: string) => void
  warn: (obj: object, msg: string) => void
  debug: (obj: object, msg: string) => void
}

type ClientCssInjectionDeps = {
  trustedClients: string[]
  resolveClientMetadata: (clientId: string) => Promise<ClientMetadata>
  getClientCss: (
    clientId: string,
    metadata: ClientMetadata,
    trustedClients: string[],
  ) => string | null
  /** Resolve client_id from a PAR request_uri (optional). */
  resolveClientIdFromRequestUri?: (
    requestUri: string,
  ) => Promise<string | undefined>
  logger: LoggerLike
}

type RequestLike = {
  method: string
  path: string
  query: Record<string, unknown>
}

type EndLike = (...args: unknown[]) => unknown

type ResponseLike = {
  setHeader: (name: string, value: string | string[]) => unknown
  removeHeader: (name: string) => void
  end: EndLike
  readonly headersSent: boolean
}

type NextLike = (err?: unknown) => void

export function shouldInjectClientCss(
  method: string,
  path: string,
  clientId: string | undefined,
  trustedClients: string[],
): boolean {
  return (
    method === 'GET' &&
    path === '/oauth/authorize' &&
    typeof clientId === 'string' &&
    trustedClients.includes(clientId)
  )
}

export function appendStyleHashToCsp(csp: string, cssHash: string): string {
  return csp.replace(/style-src\s+([^;]*)/, `style-src $1 'sha256-${cssHash}'`)
}

export function injectStyleTagIntoHtml(
  chunk: unknown,
  styleTag: string,
): { chunk: unknown; rewritten: boolean } {
  if (typeof chunk === 'string' && chunk.includes('</head>')) {
    return {
      chunk: chunk.replace('</head>', `${styleTag}</head>`),
      rewritten: true,
    }
  }

  if (Buffer.isBuffer(chunk)) {
    const str = chunk.toString('utf-8')
    if (str.includes('</head>')) {
      return {
        chunk: str.replace('</head>', `${styleTag}</head>`),
        rewritten: true,
      }
    }
  }

  return { chunk, rewritten: false }
}

/**
 * Find the right position in an Express middleware stack to insert a layer.
 *
 * The CSS injection middleware must be placed AFTER the compression
 * middleware so that its res.end wrapper sees the uncompressed HTML
 * (see commit 76a48e8 for the full explanation). Falls back to after
 * expressInit if compression is not found.
 *
 * @returns The index at which to splice the new layer.
 */
export function findInsertionIndex(
  stack: Array<{ name?: string }>,
  preferAfter: string = 'compression',
  fallbackAfter: string = 'expressInit',
): number {
  for (let i = 0; i < stack.length; i++) {
    if (stack[i].name === preferAfter) return i + 1
  }
  for (let i = 0; i < stack.length; i++) {
    if (stack[i].name === fallbackAfter) return i + 1
  }
  return 0
}

type ExpressAppLike = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Express app.use() accepts broad middleware signatures
  use: (middleware: (...args: any[]) => any) => void
}

/**
 * Create and install the CSS injection middleware into an Express app's
 * stack, positioned after the compression middleware.
 */
export function installCssInjectionMiddleware(
  app: ExpressAppLike,
  stack: Array<{ name?: string }> | undefined,
  deps: ClientCssInjectionDeps,
): void {
  // Always install — the middleware injects DEFAULT_BRANDING_CSS for
  // every /oauth/authorize response, then layers a trusted client's
  // branding.css on top when applicable.
  const middleware = createClientCssInjectionMiddleware(deps)
  app.use(middleware)
  const layer = stack?.pop()
  if (stack && layer) {
    const insertIdx = findInsertionIndex(stack)
    stack.splice(insertIdx, 0, layer)
    deps.logger.info(
      { trustedClients: deps.trustedClients, insertIdx },
      'CSS injection middleware installed (default + trusted-client branding)',
    )
  }
}

export function createClientCssInjectionMiddleware({
  trustedClients,
  resolveClientMetadata,
  getClientCss,
  resolveClientIdFromRequestUri,
  logger,
}: ClientCssInjectionDeps) {
  return async function clientCssInjectionMiddleware(
    req: unknown,
    res: unknown,
    next: NextLike,
  ) {
    const request = req as RequestLike
    const response = res as ResponseLike
    const query = request.query

    if (request.method !== 'GET' || request.path !== '/oauth/authorize') {
      next()
      return
    }

    // Resolve client_id: it may be on the query string directly, or
    // inside a PAR request_uri that needs to be looked up via the
    // oauth-provider's request manager. PAR-based flows (the common
    // case in ePDS) only carry request_uri on the query string.
    let clientId =
      typeof query.client_id === 'string' ? query.client_id : undefined
    if (!clientId && resolveClientIdFromRequestUri) {
      const requestUri =
        typeof query.request_uri === 'string' ? query.request_uri : undefined
      if (requestUri) {
        try {
          clientId = await resolveClientIdFromRequestUri(requestUri)
        } catch (err) {
          logger.warn(
            { err, requestUri },
            'CSS middleware: failed to resolve client_id from request_uri',
          )
        }
      }
    }

    // Resolve trusted-client css if applicable. Untrusted/unknown
    // clients still get DEFAULT_BRANDING_CSS — only the per-client
    // override layer is gated.
    let clientCss: string | null = null
    if (clientId && trustedClients.includes(clientId)) {
      try {
        const metadata = await resolveClientMetadata(clientId)
        clientCss = getClientCss(clientId, metadata, trustedClients)
      } catch (err) {
        logger.warn(
          { err, clientId },
          'Failed to resolve client CSS, falling back to default branding only',
        )
      }
    } else {
      logger.debug(
        {
          clientId: clientId ?? null,
          path: request.path,
          hasRequestUri: !!query.request_uri,
        },
        'CSS middleware: no trusted client_id; injecting default branding only',
      )
    }

    // Default first, client second — cascade order means client styles
    // win on overlapping selectors.
    const defaultStyle = `<style>${DEFAULT_BRANDING_CSS}</style>`
    const clientStyle = clientCss ? `<style>${clientCss}</style>` : ''
    const styleTag = `${defaultStyle}${clientStyle}`

    // CSP `style-src 'sha256-…'` hashes are per-`<style>` element, so
    // append each block's hash separately.
    const cssHashes = [
      createHash('sha256').update(DEFAULT_BRANDING_CSS).digest('base64'),
      ...(clientCss
        ? [createHash('sha256').update(clientCss).digest('base64')]
        : []),
    ]

    const origSetHeader = response.setHeader.bind(response)
    response.setHeader = (name: string, value: string | string[]) => {
      if (
        name.toLowerCase() === 'content-security-policy' &&
        typeof value === 'string'
      ) {
        for (const h of cssHashes) {
          value = appendStyleHashToCsp(value, h)
        }
      }
      return origSetHeader(name, value)
    }

    const origEnd = response.end.bind(response)
    const wrappedEnd: EndLike = (chunk?: unknown, ...args: unknown[]) => {
      const result = injectStyleTagIntoHtml(chunk, styleTag)
      if (result.rewritten && !response.headersSent) {
        // Skip the Content-Length / ETag rewrite once upstream has
        // already flushed its headers — removeHeader() would throw
        // ERR_HTTP_HEADERS_SENT and crash the process. See the matching
        // guard in chooser-enrichment.ts for the full rationale.
        response.removeHeader('Content-Length')
        response.removeHeader('ETag')
      }
      return origEnd(result.chunk, ...args)
    }
    response.end = wrappedEnd

    next()
  }
}
