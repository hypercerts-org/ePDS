/**
 * Shared HTML snippets for the preview route index pages served by
 * pds-core and auth-service. Keeping these here avoids two copies that
 * would drift apart: the behaviour (live-bound client_id input, links
 * updated on input, localStorage persistence) should be identical on
 * both services.
 */

/**
 * <label> + <input> markup for the persisted client_id field. The
 * surrounding page is expected to have CSS that styles label/input — we
 * don't emit styles here so each index page can keep its own look.
 */
export const PREVIEW_CLIENT_ID_INPUT_HTML = `<label for="client-id-input">Client metadata URL (persisted in this browser):</label>
  <input id="client-id-input" type="url" placeholder="https://your-app.example/client-metadata.json" autocomplete="url" spellcheck="false">
  <div id="validation" class="validation" aria-live="polite"></div>`

/**
 * A single preview route, used by both services' index pages. `path` is
 * the route path (e.g. `/preview/login`); `query` is optional raw query
 * string appended as-is (e.g. `error=Handle+already+taken`).
 */
export interface PreviewRoute {
  path: string
  query?: string
  label: string
}

/** Routes served by auth-service. */
export const AUTH_PREVIEW_ROUTES: readonly PreviewRoute[] = [
  { path: '/preview/login', label: 'Login — email step' },
  { path: '/preview/login-otp', label: 'Login — OTP step' },
  {
    path: '/preview/choose-handle',
    label: 'Choose handle (picker + random)',
  },
  {
    path: '/preview/choose-handle',
    query: 'error=Handle+already+taken',
    label: 'Choose handle (picker + random, with error)',
  },
  {
    path: '/preview/choose-handle-picker',
    label: 'Choose handle (picker only)',
  },
  {
    path: '/preview/choose-handle-picker',
    query: 'error=Handle+already+taken',
    label: 'Choose handle (picker only, with error)',
  },
  { path: '/preview/recovery', label: 'Recovery — email step' },
  { path: '/preview/recovery-otp', label: 'Recovery — OTP step' },
] as const

/** Routes served by pds-core. */
export const PDS_PREVIEW_ROUTES: readonly PreviewRoute[] = [
  { path: '/preview/consent', label: 'Consent page' },
] as const

function renderRouteList(
  routes: readonly PreviewRoute[],
  baseUrl: string | null,
): string {
  // baseUrl=null means same-origin (path-relative); non-null means
  // cross-origin (absolute). Either way the link gets `data-preview-link`
  // so the wire-links script rewrites it with `?client_id=` from the
  // current input. The script preserves the origin of cross-origin hrefs
  // so carrying the client_id across services works.
  const items = routes.map((r) => {
    const qs = r.query ? `?${r.query}` : ''
    const href = baseUrl ? `${baseUrl}${r.path}${qs}` : `${r.path}${qs}`
    return `<li><a href="${href}" data-preview-link>${r.label}</a></li>`
  })
  return items.join('\n    ')
}

/**
 * Render the two grouped <section>s listing all preview routes from both
 * services. Links to the current service are relative (so the persisted
 * client_id input rewrites them live); links to the other service are
 * absolute.
 *
 * @param currentService - which service is rendering this index
 * @param authPublicUrl  - absolute base URL (no trailing slash) of the
 *                         auth-service, used when currentService !== 'auth'
 * @param pdsPublicUrl   - absolute base URL (no trailing slash) of
 *                         pds-core, used when currentService !== 'pds'
 */
export function renderPreviewLinksSections(opts: {
  currentService: 'auth' | 'pds'
  authPublicUrl: string
  pdsPublicUrl: string
}): string {
  const authBase = opts.currentService === 'auth' ? null : opts.authPublicUrl
  const pdsBase = opts.currentService === 'pds' ? null : opts.pdsPublicUrl
  const authList = renderRouteList(AUTH_PREVIEW_ROUTES, authBase)
  const pdsList = renderRouteList(PDS_PREVIEW_ROUTES, pdsBase)
  // On each index page the sibling service's heading links to that
  // service's /preview index, so users can jump between the two
  // without hunting for the URL. Tag it with data-preview-link so the
  // wire-up script rewrites it with the current client_id — same as
  // the route links — and the value carries across services.
  const authHeading =
    opts.currentService === 'auth'
      ? 'auth-service'
      : `<a href="${opts.authPublicUrl}/preview" data-preview-link>auth-service</a>`
  const pdsHeading =
    opts.currentService === 'pds'
      ? 'pds-core'
      : `<a href="${opts.pdsPublicUrl}/preview" data-preview-link>pds-core</a>`
  return `<section class="preview-group">
  <h2>${authHeading}</h2>
  <ul>
    ${authList}
  </ul>
</section>
<section class="preview-group">
  <h2>${pdsHeading}</h2>
  <ul>
    ${pdsList}
  </ul>
</section>`
}

const PREVIEW_INDEX_STYLES = `body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 768px; margin: 40px auto; padding: 0 16px; color: #222; }
    h1 { font-size: 22px; }
    h2 { font-size: 16px; margin: 24px 0 4px; }
    p { line-height: 1.5; }
    code { background: #f0f0f0; padding: 2px 6px; border-radius: 4px; font-size: 14px; }
    pre { background: #f0f0f0; padding: 10px 12px; border-radius: 6px; overflow-x: auto; margin: 8px 0; }
    pre code { background: none; padding: 0; font-size: 13px; }
    ul { line-height: 2; }
    a { color: #0b5ed7; }
    label { display: block; margin: 16px 0 6px; font-weight: 500; }
    input[type="url"] { width: 100%; padding: 8px 10px; font-size: 14px; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    input[type="url"]:focus { outline: 2px solid #0b5ed7; outline-offset: -1px; border-color: transparent; }
    .preview-group { margin-top: 16px; }
    .cache-status { margin-top: 32px; padding: 12px 16px; background: #f8f9fa; border: 1px solid #e5e7eb; border-radius: 8px; }
    .cache-status h2 { font-size: 15px; margin: 0 0 4px; }
    .cache-status-hint { font-size: 13px; color: #555; margin: 0 0 8px; }
    .cache-entries { list-style: none; padding: 0; margin: 0; }
    .cache-entry { display: flex; align-items: center; gap: 10px; padding: 4px 0; min-width: 0; }
    .cache-entry-url { flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
    .cache-entry-ttl { flex: 0 0 auto; font-variant-numeric: tabular-nums; font-weight: 500; color: #444; font-size: 13px; }
    .cache-entry-preview { flex: 0 0 auto; padding: 2px 10px; font-size: 12px; border: 1px solid #cbd5e1; border-radius: 4px; background: white; cursor: pointer; color: #0b5ed7; }
    .cache-entry-preview:hover { background: #eff6ff; border-color: #0b5ed7; }
    .validation { margin-top: 8px; }
    .validation-list { list-style: none; padding: 0; margin: 0; display: grid; gap: 4px; }
    .validation-row { display: grid; grid-template-columns: 1.25em auto 1fr; column-gap: 8px; align-items: baseline; font-size: 14px; }
    .validation-label { font-weight: 500; }
    .validation-detail { color: #555; font-size: 13px; }
    .validation-ok .validation-label { color: #15803d; }
    .validation-warn .validation-label { color: #b45309; }
    .validation-error .validation-label { color: #b91c1c; }
    .validation-loading, .validation-error-inline { font-size: 13px; color: #555; margin: 6px 0 0; }`

/**
 * Render a full preview-index HTML page. Both pds-core and auth-service
 * serve near-identical index pages — same styles, same client_id input,
 * same route list, same cache-status block, same wire-up script — so
 * the whole shell lives here. Per-service wording (title, heading, two
 * intro blurbs) is derived from `currentService` so the two pages can't
 * drift apart.
 */
export function renderPreviewIndexPage(opts: {
  currentService: 'auth' | 'pds'
  authPublicUrl: string
  pdsPublicUrl: string
}): string {
  const serviceName =
    opts.currentService === 'auth' ? 'auth-service' : 'pds-core'
  const siblingName =
    opts.currentService === 'auth' ? 'pds-core' : 'auth-service'
  const linksHtml = renderPreviewLinksSections({
    currentService: opts.currentService,
    authPublicUrl: opts.authPublicUrl,
    pdsPublicUrl: opts.pdsPublicUrl,
  })
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${serviceName} previews</title>
  <style>
    ${PREVIEW_INDEX_STYLES}
  </style>
</head>
<body>
  <h1>${serviceName} preview routes</h1>
  <p>Each link below renders one of the ePDS preview pages with fixture data, so you can iterate on your client's <code>branding.css</code> without walking through the full OAuth flow. Routes from both services are listed here; links under <em>${siblingName}</em> point to the other service and don't pick up the client-metadata URL below — enter it once per service.</p>
  ${PREVIEW_CLIENT_ID_INPUT_HTML}
  ${linksHtml}
  <p>The trusted-clients check still applies: your URL must be on <code>PDS_OAUTH_TRUSTED_CLIENTS</code> for its CSS to be injected, exactly as in a real OAuth flow. Leave the field blank to render the pages unbranded (baseline).</p>
  <p>Alternatively, skip the field and append this query string to any of the links above:</p>
  <pre><code>?client_id=&lt;URL-of-your-client-metadata.json&gt;</code></pre>
  ${PREVIEW_CACHE_STATUS_HTML}
  ${PREVIEW_CLIENT_ID_SCRIPT_HTML}
</body>
</html>`
}

/**
 * Block that surfaces the live state of the shared client-metadata
 * cache. Preview routes themselves always bypass this cache; what's
 * shown here is what real OAuth flows on this service are currently
 * seeing — useful for answering "has my branding.css change reached
 * real users yet?".
 *
 * Populated + kept fresh by PREVIEW_CACHE_STATUS_SCRIPT_HTML.
 */
export const PREVIEW_CACHE_STATUS_HTML = `<section id="cache-status" class="cache-status" aria-live="polite">
    <h2>Real-flow metadata cache</h2>
    <p class="cache-status-hint">Preview routes always re-fetch client metadata, so edits to your <code>branding.css</code> show up on the next refresh here. The list below reflects what real OAuth flows are still seeing — each entry is cached for 10 minutes from its last real fetch, so until it expires, real users won't pick up your changes yet.</p>
    <div id="cache-status-body"><em>Loading…</em></div>
  </section>`

/**
 * Inline <script> that wires the client_id input to every
 * `a[data-preview-link]` on the page: typing in the input rewrites each
 * link's `?client_id=...` param live, and the value is persisted to
 * localStorage under a shared key so the next visit starts with the
 * same value.
 *
 * The snippet is self-contained — no template placeholders, nothing
 * interpolated from user input — so it's safe to embed verbatim inside
 * a <script> tag.
 */
export const PREVIEW_CLIENT_ID_SCRIPT_HTML = `<script>
(function () {
  var STORAGE_KEY = 'epds:preview:client_id';
  var input = document.getElementById('client-id-input');
  if (input) wireClientIdInput(input);
  wireCacheStatus();

  function escape(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function wireClientIdInput(input) {
    function applyToLinks(value) {
      var links = document.querySelectorAll('a[data-preview-link]');
      var pageOrigin = window.location.origin;
      for (var i = 0; i < links.length; i++) {
        var a = links[i];
        var base = a.getAttribute('data-preview-href') || a.getAttribute('href');
        a.setAttribute('data-preview-href', base);
        var url = new URL(base, pageOrigin);
        if (value) {
          url.searchParams.set('client_id', value);
        } else {
          url.searchParams.delete('client_id');
        }
        // Cross-origin links keep the explicit origin so the param
        // carries across services; same-origin stays path-relative.
        var out = url.origin === pageOrigin
          ? url.pathname + url.search
          : url.toString();
        a.setAttribute('href', out);
      }
    }

    var validationBox = document.getElementById('validation');
    var validateToken = 0; // invalidate stale in-flight results

    var ICONS = { ok: '✅', warn: '⚠️', error: '❌' };

    function renderValidation(payload) {
      if (!validationBox) return;
      if (!payload || !payload.url) {
        validationBox.innerHTML = '';
        return;
      }
      if (!payload.checks.length) {
        validationBox.innerHTML = '';
        return;
      }
      var rows = payload.checks.map(function (c) {
        var icon = ICONS[c.severity] || '•';
        // Prefer the server-provided *Html fields (they mark field
        // names / URL fragments with <code>); fall back to plain text
        // and escape it. The title attribute stays plain.
        var labelHtml = c.labelHtml ? c.labelHtml : escape(c.label);
        var detailHtml = c.detailHtml ? c.detailHtml : escape(c.detail);
        return (
          '<li class="validation-row validation-' + c.severity + '" title="' +
          escape(c.detail) + '"><span class="validation-icon" aria-hidden="true">' +
          icon + '</span><span class="validation-label">' + labelHtml +
          '</span><span class="validation-detail">' + detailHtml +
          '</span></li>'
        );
      }).join('');
      validationBox.innerHTML = '<ul class="validation-list">' + rows + '</ul>';
    }

    function runValidation(value) {
      if (!validationBox) return;
      var myToken = ++validateToken;
      if (!value) {
        renderValidation(null);
        return;
      }
      validationBox.innerHTML =
        '<p class="validation-loading"><em>Checking metadata…</em></p>';
      fetch('/preview/validate?client_id=' + encodeURIComponent(value), {
        cache: 'no-store',
      })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (payload) {
          if (myToken !== validateToken) return; // a newer input invalidated this
          renderValidation(payload);
        })
        .catch(function () {
          if (myToken !== validateToken) return;
          validationBox.innerHTML =
            '<p class="validation-error-inline">Validation request failed.</p>';
        });
    }

    var debounceTimer;
    function scheduleValidation(value) {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(function () { runValidation(value); }, 400);
    }

    // Resolution order for the initial client_id value:
    //   1. ?client_id=<url> on the current page URL (so shareable links
    //      like /preview?client_id=... land with the right value), which
    //      also gets persisted so subsequent visits retain it.
    //   2. localStorage from a prior visit.
    //   3. empty.
    var initial = '';
    try {
      var urlParam = new URL(window.location.href).searchParams.get('client_id');
      if (urlParam) {
        initial = urlParam;
        try { window.localStorage.setItem(STORAGE_KEY, urlParam); } catch (_) { /* ignore */ }
      } else {
        initial = window.localStorage.getItem(STORAGE_KEY) || '';
      }
      input.value = initial;
      applyToLinks(initial);
      // Ensure the address bar matches the input: covers the case where
      // the value came from localStorage and not the URL, so a reload
      // still carries the client_id.
      updateAddressBar(initial);
      if (initial) runValidation(initial); // no debounce on initial load
    } catch (_) {
      applyToLinks('');
    }

    function updateAddressBar(v) {
      // Keep the page URL in sync with the input so a reload restores
      // the current client_id without having to re-type it. Uses
      // replaceState (not pushState) so we don't fill history with
      // one entry per keystroke.
      try {
        var u = new URL(window.location.href);
        if (v) u.searchParams.set('client_id', v);
        else u.searchParams.delete('client_id');
        window.history.replaceState(null, '', u.pathname + u.search + u.hash);
      } catch (_) { /* ignore */ }
    }

    input.addEventListener('input', function () {
      var v = input.value.trim();
      try {
        if (v) window.localStorage.setItem(STORAGE_KEY, v);
        else window.localStorage.removeItem(STORAGE_KEY);
      } catch (_) { /* ignore */ }
      applyToLinks(v);
      updateAddressBar(v);
      scheduleValidation(v);
    });
  }

  function wireCacheStatus() {
    var body = document.getElementById('cache-status-body');
    if (!body) return;

    // Entries are refetched every 15s; the countdown ticks client-side
    // every second against the server's "now" captured at fetch time
    // (skewTo = serverNow - Date.now()), so clock drift between server
    // and client doesn't matter.
    var entries = [];
    var skewTo = 0;

    function fmt(ms) {
      if (ms <= 0) return 'expired';
      var s = Math.round(ms / 1000);
      var m = Math.floor(s / 60);
      s = s - m * 60;
      if (m > 0) return m + 'm ' + (s < 10 ? '0' : '') + s + 's';
      return s + 's';
    }

    function render() {
      if (!entries.length) {
        body.innerHTML = '<p><em>No entries currently cached.</em></p>';
        return;
      }
      var now = Date.now() + skewTo;
      var rows = entries
        .map(function (e) {
          // Defence in depth: the shared client-metadata cache should
          // only ever hold https URLs, but since we're rendering into
          // href="..." with target="_blank", reject anything that isn't
          // http(s) so a rogue entry can't turn into javascript: / data:.
          var lower = String(e.clientId).toLowerCase();
          var hasSafeScheme =
            lower.indexOf('https://') === 0 || lower.indexOf('http://') === 0;
          var safeUrl = hasSafeScheme ? e.clientId : '#';
          var href = escape(safeUrl);
          return (
            '<li class="cache-entry">' +
            '<a class="cache-entry-url" href="' + href + '" target="_blank" rel="noopener">' +
            escape(e.clientId) +
            '</a>' +
            '<span class="cache-entry-ttl">' + fmt(e.expiresAt - now) + '</span>' +
            '<button type="button" class="cache-entry-preview" data-client-id="' +
            href + '" title="Copy this URL into the input above so you can preview it">Preview</button>' +
            '</li>'
          );
        })
        .join('');
      body.innerHTML = '<ul class="cache-entries">' + rows + '</ul>';
    }

    // Event delegation: the Preview buttons are re-rendered on every
    // refresh, so attach one listener on the static container instead of
    // re-wiring per-entry.
    body.addEventListener('click', function (ev) {
      var target = ev.target;
      if (!(target && target.classList && target.classList.contains('cache-entry-preview'))) return;
      var clientId = target.getAttribute('data-client-id');
      if (!clientId) return;
      var fieldInput = document.getElementById('client-id-input');
      if (!fieldInput) return;
      fieldInput.value = clientId;
      fieldInput.dispatchEvent(new Event('input', { bubbles: true }));
      fieldInput.focus();
      fieldInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });

    function refresh() {
      fetch('/preview/cache-status', { cache: 'no-store' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (payload) {
          if (!payload) return;
          skewTo = payload.now - Date.now();
          entries = payload.entries || [];
          render();
        })
        .catch(function () { /* ignore transient errors */ });
    }

    refresh();
    setInterval(refresh, 15000);
    setInterval(render, 1000);
  }
})();
</script>`
