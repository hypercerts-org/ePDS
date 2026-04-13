import { createHash } from 'node:crypto'

import type { ClientMetadata } from '@certified-app/shared'

type LoggerLike = {
  warn: (obj: object, msg: string) => void
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
  resolveClientIdFromRequestUri?: (requestUri: string) => Promise<string | undefined>
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
        } catch {
          // request_uri expired or invalid — skip CSS injection
        }
      }
    }

    if (!clientId || !trustedClients.includes(clientId)) {
      next()
      return
    }

    try {
      const metadata = await resolveClientMetadata(clientId)
      const css = getClientCss(clientId, metadata, trustedClients)
      if (!css) {
        next()
        return
      }

      const cssHash = createHash('sha256').update(css).digest('base64')
      const styleTag = `<style>${css}</style>`

      const origSetHeader = response.setHeader.bind(response)
      response.setHeader = (name: string, value: string | string[]) => {
        if (
          name.toLowerCase() === 'content-security-policy' &&
          typeof value === 'string'
        ) {
          value = appendStyleHashToCsp(value, cssHash)
        }
        return origSetHeader(name, value)
      }

      const origEnd = response.end.bind(response)
      const wrappedEnd: EndLike = (chunk?: unknown, ...args: unknown[]) => {
        const result = injectStyleTagIntoHtml(chunk, styleTag)
        if (result.rewritten) {
          response.removeHeader('Content-Length')
          response.removeHeader('ETag')
        }
        return origEnd(result.chunk, ...args)
      }
      response.end = wrappedEnd

      next()
    } catch (err) {
      logger.warn(
        { err, clientId },
        'Failed to resolve client CSS, skipping injection',
      )
      next()
    }
  }
}
