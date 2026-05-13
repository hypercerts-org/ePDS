/**
 * Default CSS injected into upstream `@atproto/oauth-provider-ui` HTML
 * (consent + chooser screens) so an unbranded ePDS deployment renders
 * with the same neutral Certified-style aesthetic as auth-service's
 * hand-rolled login page — rather than the upstream's purple-on-white
 * defaults.
 *
 * This stylesheet is injected unconditionally (every /oauth/authorize
 * response), with trusted-client `branding.css` injected *after* it so
 * client themes still win via cascade order.
 *
 * Goal: keep these pages visually consistent with auth-service's
 * /preview/login — same page background (#E8E8E8 muted grey), same
 * card surface (#F8F8F8) with thin #E5E5E5 borders and soft shadow,
 * same input/button styling (#FFFFFF surfaces with #E5E5E5 borders).
 *
 * The selectors mirror those used by `packages/demo/src/lib/theme.ts`
 * (the per-preset `injectedCss` arrays). See that file for inline notes
 * on why each Tailwind utility class needs an override.
 */
export const DEFAULT_BRANDING_CSS = [
  // Provider-UI reads the branding "primary" via
  // `rgb(var(--branding-color-primary))`. Default to near-black so the
  // Authorize / primary buttons match the auth-service login page's
  // dark pill button. Channels are space-separated RGB.
  ':root { --branding-color-primary: 26 19 15; --branding-color-primary-contrast: 248 248 248; }',
  // Body + html: muted page background (matches auth-service's
  // `--page-bg`). Provider-UI sets bg-white via Tailwind, so a
  // class-targeted override plus !important is needed.
  'body { background: #E8E8E8 !important; color: #1A130F !important; }',
  'html { background: #E8E8E8; }',
  // Consent / chooser layout — the upstream provider-ui splits the
  // viewport into a header column (left) and a content column (right)
  // via `md:bg-slate-100 md:dark:bg-slate-800` and the unscoped
  // <main>'s default white background. To mirror the login page's
  // "card on a muted page" composition we paint the right <main> as a
  // raised card and let the left strip stay flush with the page bg.
  '.md\\:bg-slate-100, .md\\:dark\\:bg-slate-800 { background-color: #E8E8E8 !important; }',
  '.md\\:dark\\:border-slate-700 { border-color: transparent !important; }',
  // Right-side <main>: lift it onto a card surface with the same
  // colour, border, radius and soft shadow as the login card.
  'main { background: #F8F8F8; border: 1px solid #E5E5E5; border-radius: 20px; box-shadow: 0 1px 2px rgba(0,0,0,0.03); margin: 16px; }',
  // Completion states such as "Login complete" render plain text rather
  // than a form, so nudge that card up to sit on the same optical plane
  // as the left-side title without moving form-heavy consent screens.
  '@media (min-width: 768px) { main:not(:has(form)) { transform: translateY(-26px); } }',
  // Three-tone text hierarchy. Provider-UI uses Tailwind slate / gray /
  // neutral utility classes for primary / muted / hint text — remap to
  // the same shades the login page uses.
  '.text-slate-900, .dark\\:text-slate-100, .text-slate-800, .dark\\:text-slate-200, .text-gray-800, .dark\\:text-gray-200 { color: #1A130F !important; }',
  '.text-slate-700, .text-slate-600, .dark\\:text-slate-300, .dark\\:text-slate-400 { color: #6b6b6b !important; }',
  '.text-slate-500, .text-gray-500, .text-neutral-500, .dark\\:text-neutral-400, .dark\\:text-gray-300, .dark\\:text-gray-400 { color: #8a8a8a !important; }',
  // Account-chooser rows + Deny/Cancel/Back secondary buttons. The
  // chooser uses `bg-gray-100` (resting) → `hover:bg-gray-200` for
  // each account; secondary buttons use `bg-gray-300`. Repaint all of
  // them as #FFFFFF surfaces with the login page's #E5E5E5 input border
  // so they look like the email/OTP inputs and social buttons.
  '.bg-gray-100, .dark\\:bg-gray-800, .bg-gray-200, .dark\\:bg-gray-700, .bg-gray-300, .dark\\:bg-slate-600 { background-color: #FFFFFF !important; color: #1A130F !important; border: 1px solid #E5E5E5 !important; }',
  // Hover lift: light neutral, like .btn-social:hover on the login page.
  '.hover\\:bg-gray-200:hover, .dark\\:hover\\:bg-gray-700:hover { background-color: #FAFAFA !important; }',
  // Upstream stock PDS FormCard action rows use row-reverse + horizontal spacing.
  // Longer primary labels, such as "Sign in with Certified", cramp on
  // narrow screens, so stack below Tailwind's md breakpoint only.
  '@media (max-width: 767.98px) { .flex.flex-row-reverse.flex-wrap.items-center.justify-end.space-x-2.space-x-reverse { flex-direction: column-reverse !important; align-items: stretch !important; gap: 0.5rem !important; } .flex.flex-row-reverse.flex-wrap.items-center.justify-end.space-x-2.space-x-reverse > * { margin-left: 0 !important; margin-right: 0 !important; margin-inline-start: 0 !important; margin-inline-end: 0 !important; } .flex.flex-row-reverse.flex-wrap.items-center.justify-end.space-x-2.space-x-reverse > .flex-auto { display: none !important; } }',
].join(' ')
