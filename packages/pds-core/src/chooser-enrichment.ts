/**
 * Chooser enrichment for HYPER-268 cross-client session reuse.
 *
 * Upstream `@atproto/oauth-provider` renders its account chooser at
 * `/account` as a compiled React SPA that shows each bound account as a
 * clickable row — handle only, no email. For ePDS deployments where
 * handles may be randomly generated, users can't tell which account is
 * theirs, so we augment the chooser in two ways via response rewriting:
 *
 *   1. Inject a post-hydration script that appends each account's email
 *      alongside the handle. The email is already present in the
 *      `__deviceSessions` hydration payload — upstream's SPA just does
 *      not render it.
 *   2. Inject a "Use a different account" link that redirects to
 *      `auth.<host>/oauth/authorize?prompt=login` with the original
 *      OAuth params, letting users opt out of session reuse.
 *
 * The approach mirrors PR #9's CSS injection pattern for trusted-client
 * branding: intercept `/account*` HTML responses, inject a `<script>`
 * into the `<head>`, and update CSP `script-src` with the new hash.
 */

import { createHash } from 'node:crypto'

/**
 * Build the post-hydration enrichment script injected into `/account*`
 * HTML responses. Returns a JS source string that will run in the
 * browser with the SPA's origin.
 *
 * The script is pure — it takes no runtime parameters beyond the
 * passed-in `authHostname`, which is baked into the generated code as
 * the target for the "Use a different account" link. That means the
 * script content (and its SHA256 hash used for CSP) is deterministic
 * per deployment.
 *
 * Design constraints the script must respect at runtime:
 *   - Idempotent: runs repeatedly via MutationObserver, must not
 *     double-inject.
 *   - Fail-safe: upstream SPA restructures cause missing selectors;
 *     must not throw.
 *   - Self-contained: no external dependencies, no ES module imports —
 *     this runs in a plain `<script>` tag.
 */
export function buildChooserEnrichmentScript(authHostname: string): string {
  return `(function(){
  // Capture the upstream __deviceSessions before the SPA clears it.
  var captured = null;
  try {
    Object.defineProperty(window, '__deviceSessions', {
      configurable: true,
      set: function(v) {
        captured = v;
        // Forward to a plain data prop so the SPA still sees the value.
        Object.defineProperty(window, '__deviceSessions', {
          configurable: true, enumerable: true, writable: true, value: v,
        });
      },
      get: function() { return captured; },
    });
  } catch (_) {}

  // Build a link back to auth.<domain>/oauth/authorize?prompt=login with
  // the original OAuth params. The authorize params live in the current
  // URL's query string when the chooser renders inside /oauth/authorize,
  // or are embedded in the hydration data; we use location.search as a
  // best-effort source (works for /oauth/authorize; falls back to empty
  // on /account standalone navigations).
  function buildDifferentAccountHref() {
    try {
      var u = new URL('https://${authHostname}/oauth/authorize');
      var src = new URLSearchParams(window.location.search);
      src.forEach(function(val, key) { u.searchParams.set(key, val); });
      u.searchParams.set('prompt', 'login');
      return u.toString();
    } catch (_) {
      return 'https://${authHostname}/oauth/authorize?prompt=login';
    }
  }

  // Enrich each visible account row with its email. Runs repeatedly
  // via a MutationObserver because the SPA hydrates/re-renders after
  // initial HTML delivery.
  function enrich() {
    if (!captured || !Array.isArray(captured)) return;
    var byHandle = Object.create(null);
    var bySub = Object.create(null);
    captured.forEach(function(s) {
      var a = s && s.account;
      if (!a) return;
      if (a.preferred_username) byHandle[a.preferred_username] = a.email || '';
      if (a.sub) bySub[a.sub] = a.email || '';
    });

    // Heuristic: every element that contains a handle-like string
    // ("@username" or the raw preferred_username) gets an email label
    // appended once, marked with data-epds-enriched to prevent
    // double-injection.
    var nodes = document.querySelectorAll('#root [class*="account"], #root li, #root button');
    nodes.forEach(function(el) {
      if (el.dataset && el.dataset.epdsEnriched) return;
      var text = el.textContent || '';
      var email = '';
      for (var handle in byHandle) {
        if (text.indexOf(handle) >= 0) { email = byHandle[handle]; break; }
      }
      if (!email) {
        for (var sub in bySub) {
          if (text.indexOf(sub) >= 0) { email = bySub[sub]; break; }
        }
      }
      if (!email) return;
      var label = document.createElement('span');
      label.className = 'epds-email-label';
      label.style.cssText = 'display:block;font-size:0.85em;color:#6b7280;margin-top:2px;';
      label.textContent = email;
      el.appendChild(label);
      if (el.dataset) el.dataset.epdsEnriched = '1';
    });

    // "Use a different account" link — inject once.
    if (!document.getElementById('epds-use-different-account')) {
      var root = document.getElementById('root');
      if (root) {
        var wrap = document.createElement('div');
        wrap.style.cssText = 'text-align:center;margin:16px 0;';
        var a = document.createElement('a');
        a.id = 'epds-use-different-account';
        a.href = buildDifferentAccountHref();
        a.textContent = 'Use a different account';
        a.style.cssText = 'color:#2563eb;text-decoration:underline;font-size:0.9em;';
        wrap.appendChild(a);
        root.appendChild(wrap);
      }
    }
  }

  function start() {
    enrich();
    var obs = new MutationObserver(function(){ enrich(); });
    obs.observe(document.documentElement, { childList: true, subtree: true });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();`
}

/** SHA256-in-base64 hash of an arbitrary string, CSP-style. */
export function sha256Base64(input: string): string {
  return createHash('sha256').update(input).digest('base64')
}

/**
 * Rewrite a Content-Security-Policy header value to authorise an inline
 * `<script>` with the given SHA256 hash. Handles two cases:
 *
 *   1. CSP has a `script-src` directive — append `'sha256-<hash>'` to it.
 *   2. CSP has no `script-src` directive (e.g. upstream relies on
 *      `default-src 'none'`) — append a fresh `; script-src
 *      'sha256-<hash>'` clause so our inline script isn't silently
 *      blocked.
 */
export function appendScriptHashToCsp(
  cspValue: string,
  scriptHash: string,
): string {
  if (/script-src\s+[^;]*/.test(cspValue)) {
    return cspValue.replace(
      /script-src\s+([^;]*)/,
      `script-src $1 'sha256-${scriptHash}'`,
    )
  }
  return `${cspValue}${cspValue.endsWith(';') ? '' : ';'} script-src 'sha256-${scriptHash}'`
}

/**
 * True if the given Express request should trigger chooser enrichment.
 * Matches upstream's `createAccountPageMiddleware` regex exactly so every
 * variant of the chooser URL (`/account`, `/account/foo`, …) is rewritten.
 */
export function isChooserRequest(req: {
  method: string
  path: string
}): boolean {
  if (req.method !== 'GET') return false
  return /^\/account(?:\/.*)?$/.test(req.path)
}

/**
 * Inject a `<script>` tag at the very start of the `<head>` element in
 * an HTML body chunk. Returns the rewritten string and a boolean
 * indicating whether the head was found — callers use the flag to
 * decide whether to strip stale Content-Length / ETag headers.
 *
 * Deliberately only rewrites the first `<head>` occurrence: upstream's
 * HTML always has exactly one, and rewriting all occurrences would
 * break inline `<head>` text mentioned in user content (unlikely but
 * defensive).
 */
export function injectScriptIntoHead(
  body: string,
  scriptTag: string,
): { body: string; injected: boolean } {
  if (!body.includes('<head>')) {
    return { body, injected: false }
  }
  return {
    body: body.replace('<head>', `<head>${scriptTag}`),
    injected: true,
  }
}

/**
 * Minimal shape of `http.ServerResponse` we need to wrap in the
 * chooser-enrichment middleware. We only call setHeader, end, and
 * removeHeader; keeping the type narrow lets unit tests construct
 * mocks without depending on Node's full http types.
 */
export interface ChooserEnrichmentResponse {
  setHeader: (name: string, value: string | string[] | number) => unknown
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- http.ServerResponse.end has complex overloads
  end: (chunk?: any, ...args: any[]) => unknown
  removeHeader: (name: string) => void
}

/** Minimal Express request shape consumed by the middleware. */
export interface ChooserEnrichmentRequest {
  method: string
  path: string
}

/** Minimal Express middleware `next()` callback. */
export type ChooserEnrichmentNext = () => void

/**
 * Build the Express middleware that intercepts HTML responses for the
 * upstream `/account*` chooser routes and injects the enrichment
 * script + CSP hash. The script content (and therefore its hash) is
 * computed once at factory time so the per-request work is just
 * header/body rewriting — same hot-path pattern as the cookie-domain
 * middleware.
 *
 * Pure factory: side-effect-free at module load, safe to construct in
 * unit tests with a synthetic request/response pair.
 */
export function createChooserEnrichmentMiddleware(authHostname: string) {
  const enrichmentJs = buildChooserEnrichmentScript(authHostname)
  const enrichmentScriptHash = sha256Base64(enrichmentJs)
  const enrichmentScriptTag = `<script>${enrichmentJs}</script>`

  return function chooserEnrichmentMiddleware(
    req: ChooserEnrichmentRequest,
    res: ChooserEnrichmentResponse,
    next: ChooserEnrichmentNext,
  ): void {
    if (!isChooserRequest(req)) {
      next()
      return
    }

    // Wrap res.setHeader to append our script hash to CSP script-src.
    const origSetHeader = res.setHeader.bind(res)
    res.setHeader = (name: string, value: string | string[] | number) => {
      if (
        typeof name === 'string' &&
        name.toLowerCase() === 'content-security-policy' &&
        typeof value === 'string'
      ) {
        value = appendScriptHashToCsp(value, enrichmentScriptHash)
      }
      return origSetHeader(name, value)
    }

    // Wrap res.end to inject the <script> tag at the start of <head>.
    const origEnd = res.end.bind(res)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- http.ServerResponse.end overloads
    res.end = (chunk: any, ...args: any[]) => {
      if (typeof chunk === 'string') {
        const { body, injected } = injectScriptIntoHead(
          chunk,
          enrichmentScriptTag,
        )
        if (injected) {
          chunk = body
          res.removeHeader('Content-Length')
          res.removeHeader('ETag')
        }
      } else if (Buffer.isBuffer(chunk)) {
        const { body, injected } = injectScriptIntoHead(
          chunk.toString('utf-8'),
          enrichmentScriptTag,
        )
        if (injected) {
          chunk = body
          res.removeHeader('Content-Length')
          res.removeHeader('ETag')
        }
      }
      return origEnd(chunk, ...args)
    }

    next()
  }
}
