import { escapeHtml } from './html.js'

/**
 * CSS shared across every styled error page in the project. Both
 * auth-service and pds-core consume it as-is. Layout is a centred
 * white card on a light-grey body, designed to look reasonable
 * regardless of which host serves it.
 *
 * Auth-service composes additional rules on top (the "Powered by
 * Certified" footer) — see `auth-service/src/lib/render-error.ts`.
 */
export const ERROR_CSS = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
  .page-wrap { display: flex; flex-direction: column; align-items: stretch; max-width: 420px; width: 100%; }
  .container { background: white; border-radius: 12px; padding: 40px; width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }
  h1 { font-size: 24px; margin-bottom: 16px; color: #111; }
  .error { color: #dc3545; background: #fdf0f0; padding: 12px; border-radius: 8px; font-size: 15px; line-height: 1.5; }
`

export interface RenderErrorOptions {
  /** Page <title> and the in-page <h1>. Defaults to "Error". */
  title?: string
  /** Extra CSS to append after ERROR_CSS, e.g. auth-service's
   *  powered-by footer rules. */
  extraCss?: string
  /** Additional HTML inserted INSIDE `.page-wrap` after the
   *  `.container`, e.g. auth-service's powered-by footer link.
   *  Caller is responsible for ensuring this string is safe HTML —
   *  it is not escaped. */
  bodyExtra?: string
}

/**
 * Render a styled HTML error page. Used by every endpoint that needs
 * to surface a recoverable problem to the user without leaking JSON
 * or sending the user to a stack trace. Status codes are the
 * caller's responsibility — this only produces the body.
 */
export function renderError(
  message: string,
  options: RenderErrorOptions = {},
): string {
  const { title = 'Error', extraCss = '', bodyExtra = '' } = options
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="/static/favicon.svg" media="(prefers-color-scheme: light)" type="image/svg+xml">
  <link rel="icon" href="/static/favicon-dark.svg" media="(prefers-color-scheme: dark)" type="image/svg+xml">
  <title>${escapeHtml(title)}</title>
  <style>${ERROR_CSS}${extraCss}</style>
</head>
<body>
  <div class="page-wrap">
    <div class="container">
      <h1>${escapeHtml(title)}</h1>
      <p class="error">${escapeHtml(message)}</p>
    </div>
    ${bodyExtra}
  </div>
</body>
</html>`
}
