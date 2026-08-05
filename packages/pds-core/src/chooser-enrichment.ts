/**
 * Chooser enrichment for HYPER-268 cross-client session reuse.
 *
 * Upstream `@atproto/oauth-provider` renders its account chooser at
 * `/account` as a compiled React SPA that shows each bound account as a
 * clickable row — handle only, no email. For ePDS deployments where
 * handles may be randomly generated, users can't tell which account is
 * theirs, so we augment the chooser via response rewriting: inject a
 * post-hydration script that (a) appends each account's email alongside
 * the handle (email is already in `__deviceSessions` but not rendered),
 * (b) hides upstream's "Sign up" affordance (ePDS signup goes through
 * auth-service, not upstream), and (c) rebinds upstream's "Another
 * account" button to hard-navigate to auth-service's email form instead
 * of letting the upstream SPA swap to its stock sign-in form.
 *
 * The approach mirrors PR #9's CSS injection pattern for trusted-client
 * branding: intercept `/account*` HTML responses, inject a `<script>`
 * into the `<head>`, and update CSP `script-src` with the new hash.
 */

import { createHash } from 'node:crypto'
import type {
  ClientMetadata,
  HandleMode,
  ResolveClientMetadataOptions,
} from '@certified-app/shared'
import { resolveHandleMode, VALID_HANDLE_MODES } from '@certified-app/shared'
import {
  resolveOAuthClientIdFromQuery,
  type ResolveClientIdFromRequestUri,
} from './lib/oauth-request-context.js'

/**
 * Build the post-hydration enrichment script injected into `/account*`
 * HTML responses. Returns a JS source string that will run in the
 * browser with the SPA's origin.
 *
 * The script is pure — it takes no runtime parameters. That means the
 * script content (and its SHA256 hash used for CSP) is deterministic.
 *
 * Design constraints the script must respect at runtime:
 *   - Idempotent: runs repeatedly via MutationObserver, must not
 *     double-inject.
 *   - Fail-safe: upstream SPA restructures cause missing selectors;
 *     must not throw.
 *   - Self-contained: no external dependencies, no ES module imports —
 *     this runs in a plain `<script>` tag.
 */
export function buildChooserEnrichmentScript(): string {
  return String.raw`(function(){
  // Capture upstream's hydration data before the SPA reads it and unsets
  // the global. Two different globals carry the same account array shape
  // depending on which upstream route is rendering:
  //   - /oauth/authorize (the chooser that pops up mid OAuth flow)
  //     sets window.__sessions (type: readonly Session[])
  //   - /account          (the standalone account-management SPA)
  //     sets window.__deviceSessions (type: readonly ActiveDeviceSession[])
  // Both contain { account: { sub, email, preferred_username, ... }, ... }
  // so our DOM-enrichment heuristic can operate on either one.
  var capturedGlobals = Object.create(null);
  function interceptGlobal(name) {
    try {
      Object.defineProperty(window, name, {
        configurable: true,
        set: function(v) {
          capturedGlobals[name] = v;
          // Forward to a plain data prop so the SPA still sees the value.
          Object.defineProperty(window, name, {
            configurable: true, enumerable: true, writable: true, value: v,
          });
        },
        get: function() { return capturedGlobals[name]; },
      });
    } catch (_) {}
  }
  interceptGlobal('__deviceSessions');
  interceptGlobal('__sessions');

  // Current OAuth flow's handle-assignment mode, written into a
  // <meta name="epds-handle-mode"> by the pds-core middleware. When
  // "random", the handle is a server-generated opaque string that the
  // user never chose, so OAuth authorize chooser rows show the email as
  // the primary identifier while keeping the handle available through an
  // explicit accessible description.
  // Any unknown / missing value disables hiding and renders handle +
  // email side-by-side, same as pre-Layer-4 behaviour.
  function readHandleMode() {
    try {
      var meta = document.querySelector('meta[name="epds-handle-mode"]');
      var v = meta && meta.getAttribute('content');
      if (v === 'random' || v === 'picker' || v === 'picker-with-random') return v;
    } catch (_) {}
    return null;
  }

  // Auth-service origin for "Another account" click redirect, written
  // into <meta name="epds-auth-origin"> by the pds-core middleware.
  // Empty/missing → rebind is skipped and upstream's click handler runs
  // (which swaps the chooser for upstream's stock sign-in form — not
  // what we want, but fail-closed is worse than the upstream default).
  function readAuthOrigin() {
    try {
      var meta = document.querySelector('meta[name="epds-auth-origin"]');
      var v = meta && meta.getAttribute('content');
      if (typeof v === 'string' && v) return v;
    } catch (_) {}
    return '';
  }

  // Build the auth-service URL the "Another account" rebind navigates
  // to. prompt=login is OIDC's force-reauth signal; auth-service's
  // shouldReuseSession honours it and falls through to the email form
  // instead of redirecting back to pds-core's chooser. Preserves
  // request_uri / client_id / scope etc. so the OAuth flow resumes
  // after the new account signs in.
  //
  // Adds epds_skip_par_hint=1 — an ePDS-private signal that tells
  // auth-service "ignore the login_hint stored in the PAR for this
  // request" (issue #138). The user clicked "Another account", so
  // they're overriding any hint the RP supplied at OAuth init: with
  // no hint resolved, the spec-correct rendering decision is the
  // email form. URL login_hint is also dropped; the PAR-body hint
  // can't be mutated from here, hence the explicit skip flag.
  //
  // Returns '' when there is no request_uri in the current URL
  // (standalone /account navigation, bookmark, direct URL) — auth-service
  // rejects /oauth/authorize without request_uri with a 400, so letting
  // upstream handle the click is strictly better UX than a hard error
  // page. The caller skips the rebind in that case.
  function buildAnotherAccountUrl(authOrigin) {
    var params = new URLSearchParams(window.location.search || '');
    if (!params.has('request_uri')) return '';
    params.set('prompt', 'login');
    params.set('epds_skip_par_hint', '1');
    params.delete('login_hint');
    return authOrigin + '/oauth/authorize?' + params.toString();
  }

  function buildAccounts() {
    return buildAccountsFromSources([capturedGlobals.__sessions, capturedGlobals.__deviceSessions]);
  }

  function buildDeviceAccounts() {
    return buildAccountsFromSources([capturedGlobals.__deviceSessions]);
  }

  function buildAccountsFromSources(sources) {
    var accounts = [];
    sources.forEach(function(source) {
      if (!Array.isArray(source)) return;
      source.forEach(function(session) {
        var account = session && session.account;
        if (!account) return;
        accounts.push({
          sub: account.sub || '',
          email: account.email || '',
          preferred_username: account.preferred_username || '',
          selected: !!(account.selected || session.selected),
        });
      });
    });
    return accounts;
  }

  function matchAccountIdentifier(accounts, text) {
    var trimmed = (text || '').trim();
    if (!trimmed) return null;
    for (var i = 0; i < accounts.length; i++) {
      var account = accounts[i];
      if (!account.email) continue;
      if (account.preferred_username) {
        if (trimmed === account.preferred_username) return account;
        if (trimmed === '@' + account.preferred_username) return account;
      }
      if (account.sub && trimmed === account.sub) return account;
    }
    return null;
  }

  function selectedAccount(accounts) {
    for (var i = 0; i < accounts.length; i++) {
      if (accounts[i].selected) return accounts[i];
    }
    return accounts.length === 1 ? accounts[0] : null;
  }

  function formatPublicHandle(handle) {
    return handle && handle.charAt(0) === '@' ? handle : '@' + handle;
  }

  function appendAriaReference(el, attr, id) {
    var current = el.getAttribute(attr) || '';
    var refs = current ? current.split(/\s+/) : [];
    for (var i = 0; i < refs.length; i++) {
      if (refs[i] === id) return;
    }
    refs.push(id);
    el.setAttribute(attr, refs.join(' ').trim());
  }

  function appendIdentityInfoIcon(el, tooltipText) {
    var id = 'epds-identity-tooltip-' + Math.random().toString(36).slice(2);
    var icon = document.createElement('button');
    icon.type = 'button';
    icon.className = 'epds-identity-info-icon';
    icon.textContent = 'ⓘ';
    icon.setAttribute('aria-label', 'Identity information');
    icon.setAttribute('aria-describedby', id);
    icon.setAttribute('aria-expanded', 'false');
    icon.style.cssText = 'border:0;background:transparent;padding:0 0 0 .25em;cursor:pointer;font:inherit;line-height:1;color:inherit;';

    var tooltip = document.createElement('span');
    tooltip.id = id;
    tooltip.className = 'epds-identity-tooltip';
    tooltip.setAttribute('role', 'tooltip');
    tooltip.hidden = true;
    tooltip.textContent = tooltipText;
    tooltip.style.cssText = 'position:absolute;z-index:10;max-width:20rem;margin-left:.35em;padding:.35em .5em;border-radius:.25rem;background:#111;color:#fff;font-size:.875em;line-height:1.3;';

    var pinned = false;
    function show() {
      tooltip.hidden = false;
      icon.setAttribute('aria-expanded', 'true');
    }
    function hide() {
      if (pinned) return;
      tooltip.hidden = true;
      icon.setAttribute('aria-expanded', 'false');
    }
    icon.addEventListener('mouseenter', show);
    icon.addEventListener('focus', show);
    icon.addEventListener('mouseleave', hide);
    icon.addEventListener('blur', hide);
    icon.addEventListener('click', function(e) {
      e.preventDefault();
      e.stopPropagation();
      pinned = !pinned;
      if (pinned) show();
      else {
        tooltip.hidden = true;
        icon.setAttribute('aria-expanded', 'false');
      }
    });
    // WCAG 1.4.13 (Content on Hover or Focus) requires hover/focus content
    // to be dismissible without moving the pointer or focus. Clearing
    // pinned first matters: hide() returns early while pinned, so without
    // it a keyboard user who pinned the tooltip has no way to close it.
    // keyup rather than keydown so we do not race the surrounding page for
    // an Escape it may also act on.
    icon.addEventListener('keyup', function(e) {
      if (e.key !== 'Escape' && e.key !== 'Esc') return;
      if (tooltip.hidden) return;
      e.stopPropagation();
      pinned = false;
      hide();
    });

    el.insertAdjacentElement('afterend', tooltip);
    el.insertAdjacentElement('afterend', icon);
  }

  function isConsentIdentityElement(el) {
    var parent = el.parentElement;
    if (!parent) return false;
    var tagName = (el.tagName || '').toLowerCase();
    if (tagName !== 'b' && tagName !== 'strong') return false;
    return hasApprovedConsentIdentityContext(el, parent);
  }

  function normalizeConsentContextText(text) {
    return (text || '').replace(/\s+/g, ' ').trim();
  }

  function textAroundChild(parent, child) {
    var before = '';
    var after = '';
    var seenChild = false;
    for (var i = 0; i < parent.childNodes.length; i++) {
      var node = parent.childNodes[i];
      if (node === child) {
        seenChild = true;
        continue;
      }
      var text = node.nodeType === Node.TEXT_NODE ? node.data : (node.textContent || '');
      if (seenChild) after += text;
      else before += text;
    }
    return {
      before: normalizeConsentContextText(before),
      after: normalizeConsentContextText(after),
    };
  }

  function hasApprovedConsentIdentityContext(el, parent) {
    var context = textAroundChild(parent, el);
    if (context.after !== 'account') return false;
    if (context.before === 'Grant access to your') return true;
    if (context.before === 'wants to access your') return true;
    return /^.+ wants to access your$/.test(context.before);
  }

  function enrichConsentIdentity(accounts, handleMode) {
    if (!isConsentLikePage()) return;
    var selected = selectedAccount(accounts);
    var consentAccounts = selected ? [selected] : accounts;
    var root = document.getElementById('root');
    if (!root) return;
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
    var node;
    while ((node = walker.nextNode())) {
      if (node.dataset && node.dataset.epdsConsentEnriched) continue;
      var text = (node.textContent || '').trim();
      if (!text || !isConsentIdentityElement(node)) continue;
      var account = matchAccountIdentifier(consentAccounts, text);
      if (!account) continue;

      if (handleMode === 'random') {
        node.textContent = account.email;
        appendIdentityInfoIcon(
          node,
          'Public AT Protocol handle: ' + formatPublicHandle(text) + '. Handles are public account names used by AT Protocol apps.',
        );
      } else {
        appendIdentityInfoIcon(
          node,
          'This handle is associated with ' + account.email + '.',
        );
      }
      if (node.dataset) node.dataset.epdsConsentEnriched = '1';
    }
  }

  function isOauthAuthorizePage() {
    return window.location && window.location.pathname === '/oauth/authorize';
  }

  function isPreviewChooserPage() {
    return window.location && window.location.pathname === '/preview/chooser';
  }

  function isPreviewConsentPage() {
    return window.location && window.location.pathname === '/preview/consent';
  }

  function isChooserLikePage() {
    return isOauthAuthorizePage() || isPreviewChooserPage();
  }

  function isConsentLikePage() {
    return isOauthAuthorizePage() || isPreviewConsentPage() || isPreviewChooserPage();
  }

  function isAccountPage() {
    var pathname = (window.location && window.location.pathname) || '';
    return pathname === '/account' || pathname.indexOf('/account/') === 0;
  }

  function isAccountDetailPage() {
    var pathname = (window.location && window.location.pathname) || '';
    return pathname.indexOf('/account/did:') === 0;
  }

  function ownTextOf(el) {
    var own = '';
    for (var i = 0; i < el.childNodes.length; i++) {
      var c = el.childNodes[i];
      if (c.nodeType === Node.TEXT_NODE) own += c.data;
    }
    return own;
  }

  function accountSelectorButtons(root) {
    var buttons = [];
    var candidates = root.querySelectorAll('button, a');
    for (var i = 0; i < candidates.length; i++) {
      var candidate = candidates[i];
      if ((candidate.tagName || '').toLowerCase() !== 'button') continue;
      if (candidate.getAttribute('aria-label') !== 'Select an account') continue;
      buttons.push(candidate);
    }
    return buttons;
  }

  function enrichAccountSelector(root) {
    if (!isAccountDetailPage()) return;
    var accounts = buildDeviceAccounts();
    if (!accounts.length) return;
    var selectors = accountSelectorButtons(root);
    for (var i = 0; i < selectors.length; i++) {
      var selector = selectors[i];
      if (selector.dataset && selector.dataset.epdsAccountSelectorEnriched) continue;
      var walker = document.createTreeWalker(selector, NodeFilter.SHOW_ELEMENT);
      var node;
      var selectorMatches = [];
      while ((node = walker.nextNode())) {
        if (node.dataset && node.dataset.epdsEnriched) continue;
        var own = ownTextOf(node);
        if (!own) continue;
        var account = matchAccountIdentifier(accounts, own);
        if (account) selectorMatches.push({ el: node, account: account, text: own });
      }
      if (!selectorMatches.length) continue;
      var match = selectorMatches[0];
      var duplicateMatches = selectorMatches.filter(function(candidate) {
        return candidate.account === match.account;
      });
      var publicIdentifier = match.account.preferred_username
        ? formatPublicHandle(match.account.preferred_username)
        : formatPublicHandle((match.text || '').trim());
      selector.setAttribute('aria-label', 'Select account ' + match.account.email + ' (' + publicIdentifier + ')');
      if (duplicateMatches.length > 1) {
        duplicateMatches[0].el.textContent = match.account.email;
        duplicateMatches[0].el.classList.add('epds-email-label');
        for (var d = 1; d < duplicateMatches.length; d++) {
          duplicateMatches[d].el.classList.add('epds-handle-label');
          if (duplicateMatches[d].el.dataset) duplicateMatches[d].el.dataset.epdsEnriched = '1';
        }
      } else {
        match.el.classList.add('epds-handle-label');
        var label = document.createElement('span');
        label.className = 'epds-email-label';
        label.style.cssText =
          'min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;'
        label.textContent = match.account.email;
        var wrap = match.el.parentElement;
        if (wrap) {
          wrap.style.flexDirection = 'column';
          wrap.style.alignItems = 'flex-start';
          wrap.style.minWidth = '0';
          match.el.insertAdjacentElement('afterend', label);
        } else {
          match.el.appendChild(label);
        }
      }
      if (match.el.dataset) match.el.dataset.epdsEnriched = '1';
      if (selector.dataset) selector.dataset.epdsAccountSelectorEnriched = '1';
    }
  }

  // Monotonic across MutationObserver ticks. Deliberately NOT derived
  // from the per-tick match index: the match list is rebuilt every tick
  // and already-enriched rows are skipped, so a row enriched on a later
  // re-render would restart at 0 and collide with an earlier row's id.
  // Duplicate ids make aria-describedby resolve to the first match, so
  // a row would announce a different account's handle.
  var hiddenHandleSeq = 0;

  // Enrich each visible account row with its email. Runs repeatedly
  // via a MutationObserver because the SPA hydrates/re-renders after
  // initial HTML delivery.
  function enrich() {
    if (!isChooserLikePage() && !isPreviewConsentPage() && !isAccountPage()) return;
    var accounts = buildAccounts();
    if (!accounts.length) return;
    var handleMode = readHandleMode();
    var hideHandle = handleMode === 'random' && isChooserLikePage();

    enrichConsentIdentity(accounts, handleMode);

    // Find the deepest element whose own trimmed text exactly matches a
    // known handle, @handle, or DID, and append the email next to it.
    // Upstream's markup
    // varies between versions; walking by leaf-element text is more
    // resilient than guessing at class names. We skip elements that have
    // children whose text also matches (so we only label the deepest
    // match per row — usually a <span> or similar inline container).
    var root = document.getElementById('root');
    if (!root) return;
    enrichAccountSelector(root);
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
    var node;
    var matches = [];
    while ((node = walker.nextNode())) {
      if (node.dataset && node.dataset.epdsEnriched) continue;
      // Compute "own text" — text content excluding descendant element
      // text. We approximate by joining Text-node children's data.
      var own = ownTextOf(node);
      if (!own) continue;
      var account = matchAccountIdentifier(accounts, own);
      if (account) matches.push({ el: node, account: account, email: account.email });
    }
    function accountListAnchor(el) {
      var anchor = el.closest('a');
      if (!anchor) return null;
      var href = anchor.getAttribute('href') || '';
      var ariaLabel = anchor.getAttribute('aria-label') || '';
      if (href.indexOf('/account/did:') !== 0) return null;
      if (ariaLabel.indexOf('View and manage account for') !== 0) return null;
      return anchor;
    }
    function emptyAccountTitle(anchor) {
      var headings = anchor.querySelectorAll('h2');
      for (var i = 0; i < headings.length; i++) {
        if (!((headings[i].textContent || '').trim())) return headings[i];
      }
      return null;
    }
    function enrichAccountListRow(m) {
      var anchor = accountListAnchor(m.el);
      if (!anchor || (anchor.dataset && anchor.dataset.epdsAccountListEnriched)) return;
      var ownText = (m.el.textContent || '').trim();
      var publicIdentifier = m.account.preferred_username
        ? formatPublicHandle(m.account.preferred_username)
        : formatPublicHandle(ownText);
      var title = emptyAccountTitle(anchor);
      if (title) {
        title.textContent = m.email;
        title.classList.add('epds-email-label');
      } else {
        var label = document.createElement('span');
        label.className = 'epds-email-label';
        label.style.cssText =
          'min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;'
        label.textContent = m.email;
        var wrap = m.el.parentElement;
        if (wrap) {
          wrap.style.flexDirection = 'column';
          wrap.style.alignItems = 'flex-start';
          wrap.style.minWidth = '0';
          wrap.appendChild(label);
        } else {
          m.el.appendChild(label);
        }
      }
      m.el.classList.add('epds-handle-label');
      anchor.setAttribute('aria-label', 'View and manage account for ' + m.email + ' (' + publicIdentifier + ')');
      if (m.el.dataset) m.el.dataset.epdsEnriched = '1';
      if (anchor.dataset) anchor.dataset.epdsAccountListEnriched = '1';
    }
    matches.forEach(function(m) {
      if (isAccountPage()) {
        enrichAccountListRow(m);
        return;
      }
      // oauth-provider-ui 0.4.3 renders chooser rows this way; revisit if the upstream PDS UI is upgraded.
      var row = m.el.closest('[role="button"][tabindex="0"]');
      if (!row) return;
      // Upstream wraps the handle span in a flex-row container:
      //   <span class="flex flex-wrap items-center">
      //     <span aria-label="Identifier">HANDLE</span>
      //   </span>
      // We append our email as a sibling of the handle AND flip that
      // container to flex-column, so handle and email stack as two
      // rows without needing wrap-line hacks. The outer row-level
      // flex (icon | wrap | chevron) is unaffected, so the chevron
      // stays snug to the right of whichever is the widest of the
      // two lines.
      //
      // Stable classes (epds-handle-label, epds-email-label) let
      // branding CSS restyle or reorder the pair via e.g.
      //   .epds-email-label { order: -1 }
      // No inline typography (font-size, color, weight) so normal CSS
      // specificity rules apply when branding wants to override.
      var ownText = (m.el.textContent || '').trim();
      var label = document.createElement('span');
      label.className = 'epds-email-label';
      label.style.cssText =
        'min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;'
      label.textContent = ' ' + m.email;
      if (m.el.dataset) m.el.dataset.epdsEnriched = '1';
      m.el.classList.add('epds-handle-label');
      var wrap = m.el.parentElement;
      if (wrap) {
        wrap.style.flexDirection = 'column';
        wrap.style.alignItems = 'flex-start';
        wrap.style.minWidth = '0';
        wrap.appendChild(label);
      } else {
        m.el.appendChild(label);
      }

      row.setAttribute('aria-label', 'Sign in as ' + m.email);

      // Random-handle mode: the handle is server-assigned gibberish
      // the user never chose (e.g. "frail-ivy-cabbage.pds.example").
      // Keep it out of normal visual layout, but attach a separate
      // non-interactive description so assistive technology can still
      // expose the underlying handle without making it the row name.
      if (hideHandle) {
        if (ownText) {
          var description = document.createElement('span');
          var descriptionId = 'epds-hidden-handle-' + (hiddenHandleSeq++);
          description.id = descriptionId;
          description.className = 'epds-hidden-handle-description';
          description.textContent = 'Underlying handle: ' + ownText;
          description.style.cssText =
            'position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0;';
          description.setAttribute('aria-hidden', 'false');
          row.appendChild(description);
          appendAriaReference(row, 'aria-describedby', descriptionId);
        }
        m.el.style.display = 'none';
      }
    });
  }

  // Hide upstream's "Sign up" affordance on the chooser. ePDS does not
  // route signups through upstream (account creation goes through
  // auth-service's OTP flow), so upstream's button leads to a crash in
  // its compiled bundle. Match by exact text content; the button lives
  // inside #root alongside the chooser list. Idempotent via
  // dataset.epdsHidden so the MutationObserver doesn't thrash.
  function hideSignup() {
    var root = document.getElementById('root');
    if (!root) return;
    var candidates = root.querySelectorAll('button, a');
    for (var i = 0; i < candidates.length; i++) {
      var el = candidates[i];
      if (el.dataset && el.dataset.epdsHidden) continue;
      var text = (el.textContent || '').trim();
      if (text === 'Sign up') {
        el.style.display = 'none';
        el.setAttribute('aria-hidden', 'true');
        if (el.dataset) el.dataset.epdsHidden = '1';
      }
    }
  }

  // Rebind upstream's "Another account" button so clicking it hard-
  // navigates to auth-service's email form instead of letting upstream's
  // React SPA swap the chooser for its stock sign-in component. Handler
  // is attached in capture phase so it runs before React's delegated
  // root-level listener. Idempotent via dataset.epdsRebound.
  function rebindAnotherAccount(authOrigin) {
    if (!authOrigin) return;
    // No request_uri on the current URL means we have no OAuth flow to
    // resume — buildAnotherAccountUrl would produce a URL auth-service
    // 400s on. Leave upstream's default handler alone in that case.
    if (!buildAnotherAccountUrl(authOrigin)) return;
    var root = document.getElementById('root');
    if (!root) return;
    // Upstream @atproto/oauth-provider-ui renders this as a
    // div-with-role, NOT a native button:
    //   <div role="button" aria-label="Login to account that is not listed">
    //     Another account
    //   </div>
    // The aria-label is more stable across upstream copy changes than
    // the visible text, so match on that with a text-content fallback
    // scoped to anything with role=button (div OR button).
    var btn = root.querySelector(
      '[role="button"][aria-label="Login to account that is not listed"]',
    );
    if (!btn) {
      var candidates = root.querySelectorAll('[role="button"]');
      for (var i = 0; i < candidates.length; i++) {
        if ((candidates[i].textContent || '').trim() === 'Another account') {
          btn = candidates[i];
          break;
        }
      }
    }
    if (!btn || (btn.dataset && btn.dataset.epdsRebound)) return;
    btn.addEventListener(
      'click',
      function (e) {
        e.preventDefault();
        e.stopImmediatePropagation();
        window.location.href = buildAnotherAccountUrl(authOrigin);
      },
      true,
    );
    if (btn.dataset) btn.dataset.epdsRebound = '1';
  }

  function start() {
    var authOrigin = readAuthOrigin();
    function tick() {
      enrich();
      hideSignup();
      rebindAnotherAccount(authOrigin);
    }
    tick();
    var obs = new MutationObserver(tick);
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

/** Escape a string for safe interpolation into a double-quoted HTML
 *  attribute value. Used for operator-configured inputs like authOrigin
 *  — not strictly user-controlled, but cheap defense-in-depth against
 *  attribute-escape injection if a misconfigured value contains `"`,
 *  `<`, or `&`. */
export function escapeHtmlAttr(s: string): string {
  return s
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
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
 * Upstream's `@atproto/oauth-provider` renders the account chooser on
 * two different routes:
 *
 *   - `/oauth/authorize` — rendered inline during an OAuth authorize
 *     request when a device session exists. URL stays at `/oauth/authorize`;
 *     the SPA hydrates from `window.__sessions`.
 *   - `/account*` — the standalone account-management SPA. Hydrates
 *     from `window.__deviceSessions`.
 *
 * We intercept both. The response rewriter only injects when the body
 * actually contains a `<head>` tag, so POST bodies and non-HTML
 * responses (e.g. the JSON API under `/oauth/authorize/accept`) pass
 * through unchanged.
 */
export function isChooserRequest(req: {
  method: string
  path: string
}): boolean {
  if (req.method !== 'GET') return false
  if (req.path === '/oauth/authorize') return true
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
 * Inject a `<meta name="epds-handle-mode" content="...">` tag into the
 * `<head>` so the client-side enrichment script can read the current
 * OAuth flow's handle-assignment mode. Per-request value, stable tag
 * structure — no CSP impact because meta elements are not executable.
 *
 * Returns { body, injected } where `injected` is false if no `<head>`
 * was found (same contract as `injectScriptIntoHead`), so callers can
 * skip stale Content-Length stripping in that case.
 */
export function injectHandleModeMeta(
  body: string,
  handleMode: HandleMode,
): { body: string; injected: boolean } {
  const metaTag = `<meta name="epds-handle-mode" content="${handleMode}">`
  return injectScriptIntoHead(body, metaTag)
}

/**
 * Minimal shape of `http.ServerResponse` we need to wrap in the
 * chooser-enrichment middleware. We only call setHeader, end,
 * removeHeader, and read headersSent; keeping the type narrow lets
 * unit tests construct mocks without depending on Node's full http types.
 */
export interface ChooserEnrichmentResponse {
  setHeader: (name: string, value: string | string[] | number) => unknown
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- http.ServerResponse.end has complex overloads
  end: (chunk?: any, ...args: any[]) => unknown
  removeHeader: (name: string) => void
  readonly headersSent: boolean
}

/** Minimal Express request shape consumed by the middleware. Includes
 *  an optional `query` because the handle-mode resolver reads
 *  `epds_handle_mode` / `client_id` off the authorize URL when
 *  present; requests without parsed query treat those as absent and
 *  fall back through the resolver's precedence chain. */
export interface ChooserEnrichmentRequest {
  method: string
  path: string
  query?: Record<string, unknown>
}

/** Minimal Express middleware `next()` callback. */
export type ChooserEnrichmentNext = () => void

/** Factory deps for the chooser-enrichment middleware. */
export interface ChooserEnrichmentDeps {
  /** Client-metadata resolver — same function the CSS-injection
   *  middleware uses. Passed in so tests can stub without network. */
  resolveClientMetadata: (
    clientId: string,
    options?: ResolveClientMetadataOptions,
  ) => Promise<ClientMetadata>
  /** Resolve client_id from a PAR request_uri when the current OAuth
   *  page URL does not carry a direct client_id. Passed in from pds-core
   *  startup so this middleware can use the provider request manager
   *  without depending on provider internals or persisted request tables. */
  resolveClientIdFromRequestUri?: ResolveClientIdFromRequestUri
  /** Auth-service origin (e.g. "https://auth.example") used by the
   *  injected script's "Another account" rebind to hard-navigate to
   *  the email form instead of letting upstream's SPA swap to its
   *  stock sign-in component. Written into a
   *  <meta name="epds-auth-origin"> tag per request. Empty string
   *  disables the rebind. */
  authOrigin?: string
  /** Optional structured logger for fallback diagnostics. */
  logger?: {
    debug: (bindings: Record<string, unknown>, message: string) => void
  }
}

/**
 * Build the Express middleware that intercepts HTML responses for the
 * upstream `/account*` chooser routes and injects the enrichment
 * script + CSP hash. The script content (and therefore its hash) is
 * computed once at factory time so the per-request work is just
 * header/body rewriting — same hot-path pattern as the cookie-domain
 * middleware.
 *
 * Per-request work: the middleware resolves the current OAuth flow's
 * handle-assignment mode from `req.query.epds_handle_mode` and the
 * client-metadata cache, and injects a `<meta name="epds-handle-mode">`
 * tag so the static enrichment script can hide the handle (with a
 * title= tooltip) when the mode is `random`. Meta tags don't contribute
 * to CSP script-src, so the script hash remains stable.
 *
 * Pure factory: side-effect-free at module load, safe to construct in
 * unit tests with a synthetic request/response pair.
 */
const DEFAULT_CHOOSER_ENRICHMENT_DEPS: ChooserEnrichmentDeps = {
  resolveClientMetadata: (): Promise<ClientMetadata> => Promise.resolve({}),
}

export function createChooserEnrichmentMiddleware(
  deps: ChooserEnrichmentDeps = DEFAULT_CHOOSER_ENRICHMENT_DEPS,
) {
  const {
    resolveClientMetadata: resolveMeta,
    resolveClientIdFromRequestUri,
    authOrigin = '',
    logger,
  } = deps

  const enrichmentJs = buildChooserEnrichmentScript()
  const enrichmentScriptHash = sha256Base64(enrichmentJs)
  const enrichmentScriptTag = `<script>${enrichmentJs}</script>`
  // authOrigin is operator-configured (derived from AUTH_HOSTNAME) and
  // always a valid origin URL in practice, but we HTML-escape it
  // anyway so a misconfiguration can't break the rewritten page or
  // enable attribute-escape injection.
  const authOriginMetaTag = `<meta name="epds-auth-origin" content="${escapeHtmlAttr(authOrigin)}">`

  return async function chooserEnrichmentMiddleware(
    req: ChooserEnrichmentRequest,
    res: ChooserEnrichmentResponse,
    next: ChooserEnrichmentNext,
  ): Promise<void> {
    if (!isChooserRequest(req)) {
      next()
      return
    }

    // Resolve the handle-assignment mode for this flow so the script
    // can decide whether to hide the handle. Uses the same three-level
    // precedence as auth-service (query > client metadata > env default)
    // via the shared resolver — otherwise the signup page and the
    // chooser can disagree about whether handles are user-chosen.
    //
    // We await the client-metadata lookup before wiring up res.end so
    // the injected <meta name="epds-handle-mode"> deterministically
    // reflects whatever the resolver returns. A fire-and-forget
    // .then() would race against upstream's synchronous res.end, which
    // can run in the same call stack as next() and beat the microtask.
    // On a warm cache the resolver is effectively synchronous; on
    // cache miss we pay the network fetch here, matching auth-
    // service's safeResolveClientMetadata contract. Failure logs at
    // debug and falls back to the query/env-derived mode.
    const query = req.query ?? {}
    const queryMode =
      typeof query.epds_handle_mode === 'string'
        ? query.epds_handle_mode
        : undefined
    let metaMode: string | undefined
    const hasValidQueryMode =
      typeof queryMode === 'string' &&
      (VALID_HANDLE_MODES as readonly string[]).includes(queryMode)
    if (!hasValidQueryMode) {
      try {
        const clientId = await resolveOAuthClientIdFromQuery(
          query,
          resolveClientIdFromRequestUri,
        )
        if (clientId) {
          const meta = await resolveMeta(clientId)
          const raw = meta.epds_handle_mode
          if (typeof raw === 'string') metaMode = raw
        }
      } catch (err) {
        // Presence only: request_uri is a short-lived bearer reference to
        // the PAR entry, so logging its value makes it replayable.
        logger?.debug(
          {
            err,
            hasRequestUri: typeof query.request_uri === 'string',
            queryMode,
          },
          'chooser-enrichment: failed to resolve handle mode from OAuth request context',
        )
        // Failed request_uri or metadata lookups leave metaMode
        // undefined, so resolveHandleMode falls through to the query
        // value or the env default.
      }
    }
    const handleMode = resolveHandleMode(queryMode, metaMode)

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
    //
    // removeHeader() throws ERR_HTTP_HEADERS_SENT once the upstream has
    // flushed its status + headers. Upstream's SPA route writes headers
    // synchronously before calling res.end(), so we must be prepared for
    // headersSent=true when our wrapped end() fires. Skip the
    // Content-Length/ETag rewrite in that case — the response will still
    // reach the client with whatever length upstream declared (undefined
    // or chunked), which is harmless for this endpoint.
    const origEnd = res.end.bind(res)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- http.ServerResponse.end overloads
    res.end = (chunk: any, ...args: any[]) => {
      const stripLengthHeaders = () => {
        if (res.headersSent) return
        res.removeHeader('Content-Length')
        res.removeHeader('ETag')
      }
      // Meta + script: inject both in a single <head> rewrite.
      // Order matters — the meta tag must appear before the script
      // tag in the DOM so the script can read document.querySelector
      // on DOMContentLoaded without needing a second MutationObserver
      // pass just for the meta. `handleMode` was finalised above
      // before next() ran, so no race with upstream's synchronous
      // res.end.
      const combinedHeadInjection =
        `<meta name="epds-handle-mode" content="${handleMode}">` +
        authOriginMetaTag +
        enrichmentScriptTag
      if (typeof chunk === 'string') {
        const { body, injected } = injectScriptIntoHead(
          chunk,
          combinedHeadInjection,
        )
        if (injected) {
          chunk = body
          stripLengthHeaders()
        }
      } else if (Buffer.isBuffer(chunk)) {
        const { body, injected } = injectScriptIntoHead(
          chunk.toString('utf-8'),
          combinedHeadInjection,
        )
        if (injected) {
          chunk = body
          stripLengthHeaders()
        }
      }
      return origEnd(chunk, ...args)
    }

    next()
  }
}
