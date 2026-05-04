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
 * string appended as-is (e.g. `error=Handle+already+taken`); `controls`
 * declares per-link form controls (number / checkbox / select) that
 * bind to query params on the link so a single entry can cover what
 * would otherwise be a matrix of variants.
 */
export interface PreviewRoute {
  path: string
  query?: string
  label: string
  controls?: readonly PreviewRouteControl[]
}

/**
 * Inline form control rendered next to a preview-route link. Each
 * control's current value is reflected as a query parameter on its
 * link's href, live-updated as the user changes the control. Controls
 * are independent across links; a `param` value on one link does not
 * affect any other link.
 */
export type PreviewRouteControl =
  | {
      type: 'number'
      param: string
      label: string
      min: number
      max: number
      default: number
    }
  | {
      type: 'checkbox'
      param: string
      label: string
      // When checked, the param is set to '1'; when unchecked, the
      // param is removed from the URL. Default sets the initial state.
      default: boolean
    }
  | {
      type: 'select'
      param: string
      label: string
      options: readonly { value: string; label: string }[]
      // Default value MUST match one of the options. The empty string
      // is treated as "param absent" — useful for "no error" defaults.
      default: string
    }

/** Routes served by auth-service. */
export const AUTH_PREVIEW_ROUTES: readonly PreviewRoute[] = [
  { path: '/preview/login', label: 'Login — email step' },
  { path: '/preview/login-otp', label: 'Login — OTP step' },
  {
    path: '/preview/choose-handle',
    label: 'Choose handle',
    // Single link covers the matrix that used to be 4 separate entries
    // (picker vs picker+random × error none vs Handle taken). Mode
    // dropdown defaults to Auto: no override emitted, server resolves
    // from client_id metadata via the same `resolveHandleMode` chain
    // real OAuth flows use (query > metadata > env default). Picking
    // an explicit mode applies the same per-request override
    // (?epds_handle_mode=) clients can use in production.
    controls: [
      {
        type: 'select',
        param: 'epds_handle_mode',
        label: 'Mode',
        options: [
          { value: '', label: 'Auto (from client metadata)' },
          { value: 'picker', label: 'Picker' },
          { value: 'random', label: 'Random' },
          { value: 'picker-with-random', label: 'Picker + random' },
        ],
        default: '',
      },
      {
        type: 'select',
        param: 'error',
        label: 'Error',
        options: [
          { value: '', label: 'None' },
          { value: 'Handle already taken', label: 'Handle already taken' },
        ],
        default: '',
      },
    ],
  },
  { path: '/preview/recovery', label: 'Recovery — email step' },
  { path: '/preview/recovery-otp', label: 'Recovery — OTP step' },
  {
    path: '/preview/emails/new-user',
    label: 'Email — new-user welcome / verify',
  },
  {
    path: '/preview/emails/returning-user',
    label: 'Email — returning-user sign-in OTP',
  },
  {
    path: '/preview/emails/recovery',
    label: 'Email — backup email verification',
  },
] as const

/** Routes served by pds-core. */
export const PDS_PREVIEW_ROUTES: readonly PreviewRoute[] = [
  { path: '/preview/consent', label: 'Consent page' },
  {
    path: '/preview/chooser',
    label: 'Account chooser',
    controls: [
      {
        type: 'number',
        param: 'numAccounts',
        label: 'Accounts',
        // Min matches the server-side clamp in preview-chooser.ts: 0
        // would render an empty __sessions array and let the upstream
        // SPA fall through to its no-session welcome view.
        min: 1,
        max: 10,
        default: 1,
      },
      // The handle-mode is normally resolved from client metadata in
      // production; a per-request override (?epds_handle_mode=) is
      // available to clients and the preview exposes the same
      // override here. "Auto" = no override emitted, server resolves
      // from the client_id field above (or env default).
      {
        type: 'select',
        param: 'epds_handle_mode',
        label: 'Handle mode',
        options: [
          { value: '', label: 'Auto (from client metadata)' },
          { value: 'picker', label: 'Picker' },
          { value: 'random', label: 'Random' },
          { value: 'picker-with-random', label: 'Picker + random' },
        ],
        default: '',
      },
    ],
  },
] as const

function attrEscape(s: string): string {
  return s
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
}

function renderControl(
  c: PreviewRouteControl,
  linkId: string,
  idx: number,
): string {
  // Each control carries data-preview-link-id (which link it binds to)
  // and data-preview-param (which query param to write). The wire
  // script reads these attributes; no per-control JS lives here.
  const ctlId = `${linkId}-c${idx}`
  const labelHtml = `<label class="preview-control" for="${ctlId}">${attrEscape(c.label)}: `
  const dataAttrs = `data-preview-link-id="${linkId}" data-preview-param="${attrEscape(c.param)}"`
  switch (c.type) {
    case 'number':
      return (
        labelHtml +
        `<input id="${ctlId}" type="number" min="${c.min}" max="${c.max}" value="${c.default}" ${dataAttrs}></label>`
      )
    case 'checkbox':
      return (
        labelHtml +
        `<input id="${ctlId}" type="checkbox" ${c.default ? 'checked' : ''} ${dataAttrs}></label>`
      )
    case 'select': {
      const opts = c.options
        .map(
          (o) =>
            `<option value="${attrEscape(o.value)}"${o.value === c.default ? ' selected' : ''}>${attrEscape(o.label)}</option>`,
        )
        .join('')
      return (
        labelHtml +
        `<select id="${ctlId}" ${dataAttrs}>${opts}</select></label>`
      )
    }
  }
}

function renderRouteList(
  routes: readonly PreviewRoute[],
  baseUrl: string | null,
  idPrefix: string,
): string {
  // baseUrl=null means same-origin (path-relative); non-null means
  // cross-origin (absolute). Either way the link gets `data-preview-link`
  // so the wire-links script rewrites it with `?client_id=` from the
  // current input. The script preserves the origin of cross-origin hrefs
  // so carrying the client_id across services works.
  //
  // Routes with `controls` get a unique id so the wire script can find
  // their bound form controls. Controls render inline next to the link.
  const items = routes.map((r, i) => {
    const qs = r.query ? `?${r.query}` : ''
    const href = baseUrl ? `${baseUrl}${r.path}${qs}` : `${r.path}${qs}`
    const linkId = r.controls ? `${idPrefix}-${i}` : ''
    const linkIdAttr = linkId ? ` id="${linkId}"` : ''
    const controlsHtml = r.controls
      ? ' <span class="preview-route-controls">' +
        r.controls.map((c, i) => renderControl(c, linkId, i)).join(' ') +
        '</span>'
      : ''
    // Each row is a flex container so the link sits on the left and the
    // controls hug it on the same line; controls only wrap to a second
    // line on narrow viewports.
    return `<li><a href="${href}" data-preview-link${linkIdAttr}>${r.label}</a>${controlsHtml}</li>`
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
  // Stable per-group ID prefixes so a control's data-preview-link-id
  // points at exactly one element in the document.
  const authList = renderRouteList(AUTH_PREVIEW_ROUTES, authBase, 'auth-rt')
  const pdsList = renderRouteList(PDS_PREVIEW_ROUTES, pdsBase, 'pds-rt')
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
  <ul class="preview-routes preview-routes-auth">
    ${authList}
  </ul>
</section>
<section class="preview-group">
  <h2>${pdsHeading}</h2>
  <ul class="preview-routes preview-routes-pds">
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
    /* Each route is a flex row: link on the left, controls hug it on the
       same line, wrapping to a second line only on narrow viewports. */
    .preview-routes { padding-left: 24px; margin: 4px 0; }
    .preview-routes li {
      display: flex;
      align-items: baseline;
      flex-wrap: wrap;
      gap: 6px 12px;
      padding: 3px 0;
    }
    .preview-route-controls {
      display: inline-flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    .preview-route-controls .preview-control {
      display: inline-flex;
      align-items: baseline;
      gap: 4px;
      margin: 0;
      font-size: 12px;
      font-weight: normal;
      color: #555;
    }
    .preview-route-controls input[type="number"] { width: 52px; }
    .preview-route-controls select,
    .preview-route-controls input[type="number"] { font-size: 12px; padding: 1px 4px; }
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
  // Single shared link-rewriter so per-link controls and the
  // client_id input both produce the same final href.
  function applyAllToLinks() {
    var pageOrigin = window.location.origin;
    var clientIdValue = input ? input.value.trim() : '';
    var links = document.querySelectorAll('a[data-preview-link]');
    for (var i = 0; i < links.length; i++) {
      var a = links[i];
      var base = a.getAttribute('data-preview-href') || a.getAttribute('href');
      a.setAttribute('data-preview-href', base);
      var url = new URL(base, pageOrigin);
      if (clientIdValue) url.searchParams.set('client_id', clientIdValue);
      else url.searchParams.delete('client_id');
      // Per-link controls bound to this <a> by id.
      var id = a.getAttribute('id');
      if (id) {
        var ctls = document.querySelectorAll(
          '[data-preview-link-id="' + id + '"][data-preview-param]'
        );
        for (var j = 0; j < ctls.length; j++) {
          var c = ctls[j];
          var p = c.getAttribute('data-preview-param');
          var v = c.type === 'checkbox'
            ? (c.checked ? '1' : '')
            : String(c.value || '').trim();
          if (v) url.searchParams.set(p, v);
          else url.searchParams.delete(p);
        }
      }
      var out = url.origin === pageOrigin
        ? url.pathname + url.search
        : url.toString();
      a.setAttribute('href', out);
    }
  }
  if (input) wireClientIdInput(input);
  wireCacheStatus();
  wirePreviewControls();

  function wirePreviewControls() {
    // Per-link form controls (number / checkbox / select) declared in
    // PreviewRoute.controls. Each control carries:
    //   data-preview-link-id  → id of its <a data-preview-link>
    //   data-preview-param    → query-param name to write
    // On change, re-apply every link so this control's value AND any
    // active client_id land in the link's final href.
    var controls = document.querySelectorAll('[data-preview-link-id][data-preview-param]');
    for (var i = 0; i < controls.length; i++) {
      var c = controls[i];
      var ev = c.tagName === 'SELECT' || c.type === 'checkbox' ? 'change' : 'input';
      c.addEventListener(ev, applyAllToLinks);
    }
    // Apply initial control values so a fresh page reflects them
    // before the user touches anything.
    applyAllToLinks();
  }

  function escape(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function wireClientIdInput(input) {

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
      applyAllToLinks();
      // Ensure the address bar matches the input: covers the case where
      // the value came from localStorage and not the URL, so a reload
      // still carries the client_id.
      updateAddressBar(initial);
      if (initial) runValidation(initial); // no debounce on initial load
    } catch (_) {
      applyAllToLinks();
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
      applyAllToLinks();
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
