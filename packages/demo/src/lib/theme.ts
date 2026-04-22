/**
 * Named theme presets for the demo client.
 *
 * Selected via `EPDS_CLIENT_THEME` env var (e.g. "ocean").
 * Each preset provides:
 *   - `page`: inline style values for the demo's own React pages
 *   - `injectedCss`: CSS string served in client-metadata.json branding,
 *     which the auth-service and pds-core CSS middleware inject into
 *     login / consent / choose-handle / recovery pages
 *
 * The injected CSS must target TWO distinct markups on a single string:
 *   1. auth-service's hand-rolled login / OTP / handle-chooser / recovery
 *      pages, which use semantic class names (.container, .btn-primary,
 *      .field, …).
 *   2. @atproto/oauth-provider-ui's consent page, which is a Tailwind-
 *      utility build and consumes colors via CSS custom properties
 *      (`--branding-color-primary` etc., space-separated RGB channels
 *      consumed by `rgb(var(--…))` / `bg-primary` / `text-primary`).
 *
 * Overriding the `--branding-color-*` vars at `:root` is the leverage
 * point: one declaration recolours every `bg-primary`, `text-primary`,
 * `border-primary` utility on the consent page simultaneously.
 *
 * When `EPDS_CLIENT_THEME` is unset, `getTheme()` returns `null` and
 * callers fall back to their existing defaults (the light look the
 * untrusted demo uses).
 */

export interface PageTheme {
  /** Page background */
  bg: string
  /** Card / container surface */
  surface: string
  /** Card box-shadow */
  surfaceShadow: string
  /** Primary text */
  text: string
  /** Secondary / muted text */
  textMuted: string
  /** Tertiary / hint text */
  textHint: string
  /** Primary button background */
  primary: string
  /** Primary button hover background */
  primaryHover: string
  /** Input background */
  inputBg: string
  /** Input border */
  inputBorder: string
  /** Input focus border */
  focusBorder: string
  /** Error text */
  errorText: string
  /** Error background */
  errorBg: string
  /** Logo icon background (SVG rect fill) */
  logoBg: string
}

export interface Theme {
  page: PageTheme
  injectedCss: string
}

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

const ocean: Theme = {
  page: {
    bg: '#1a1033',
    surface: '#251845',
    surfaceShadow: '0 2px 12px rgba(0,0,0,0.4)',
    text: '#e8e0f0',
    textMuted: '#a78bbd',
    textHint: '#7c6894',
    primary: '#8b5cf6',
    primaryHover: '#7c3aed',
    inputBg: '#1a1033',
    inputBorder: '#3d2a5c',
    focusBorder: '#8b5cf6',
    errorText: '#fca5a5',
    errorBg: '#450a0a',
    logoBg: '#8b5cf6',
  },
  injectedCss: [
    // Provider-UI consent page: recolour Tailwind utilities via the
    // --branding-color-* custom props the UI reads through
    // `rgb(var(--branding-color-primary))`. Channels are space-separated.
    ':root { --branding-color-primary: 139 92 246; --branding-color-primary-contrast: 26 16 51; }',
    // Body background & primary text. Provider-UI sets these on <body>
    // via `bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100`,
    // so class-specific selectors (plus !important for dark-mode) are
    // needed to override Tailwind's equal-specificity rules.
    'body { background: #1a1033 !important; color: #e8e0f0 !important; }',
    'html { background: #1a1033; }',
    // Consent page's "left strip" header column (md:bg-slate-100
    // md:dark:bg-slate-800) — paint it a shade lighter than body so
    // it reads as a distinct surface, matching the demo's own cards.
    '.md\\:bg-slate-100, .md\\:dark\\:bg-slate-800 { background-color: #251845 !important; }',
    '.md\\:dark\\:border-slate-700 { border-color: #3d2a5c !important; }',
    // Three-tone text hierarchy on the consent page. Provider-UI uses
    // `text-slate-{100,200,300,400}` + `text-neutral-{400,500}` for
    // primary / muted / hint text; remap to the theme's three shades.
    '.text-slate-900, .dark\\:text-slate-100, .text-slate-800, .dark\\:text-slate-200, .text-gray-800, .dark\\:text-gray-200 { color: #e8e0f0 !important; }',
    '.text-slate-700, .text-slate-600, .dark\\:text-slate-300, .dark\\:text-slate-400 { color: #a78bbd !important; }',
    '.text-slate-500, .text-gray-500, .text-neutral-500, .dark\\:text-neutral-400, .dark\\:text-gray-300, .dark\\:text-gray-400 { color: #7c6894 !important; }',
    // Consent page secondary buttons (Deny access etc.) default to
    // .bg-gray-300 / .dark:bg-slate-600, which reads as a jarring
    // slate-grey against the themed card. Tint them to a muted surface
    // that harmonises with the palette.
    '.bg-gray-300, .dark\\:bg-slate-600, .bg-gray-200, .dark\\:bg-gray-800, .dark\\:bg-gray-700 { background-color: #3d2a5c !important; color: #e8e0f0 !important; }',
    // auth-service hand-rolled markup
    '.container { background: #251845; box-shadow: 0 2px 12px rgba(0,0,0,0.4); }',
    'h1 { color: #e8e0f0; }',
    '.subtitle { color: #a78bbd; }',
    '.field label { color: #d4c4e8; }',
    '.field input { background: #1a1033; border-color: #3d2a5c; color: #e8e0f0; }',
    '.field input:focus { border-color: #8b5cf6; }',
    '.field input::placeholder { color: #7c6894; }',
    '.otp-input { color: #e8e0f0; }',
    '.otp-input:focus { border-color: #8b5cf6 !important; }',
    '.btn-primary { background: #8b5cf6; }',
    '.btn-primary:hover { background: #7c3aed; }',
    '.btn-secondary { color: #a78bbd; }',
    '.btn-social { background: #1a1033; border-color: #3d2a5c; color: #e8e0f0; }',
    '.btn-social:hover { background: #3d2a5c; }',
    '.divider { color: #7c6894; }',
    '.divider::before, .divider::after { background: #3d2a5c; }',
    '.error { background: #450a0a; color: #fca5a5; }',
    '.recovery-link { color: #7c6894; }',
    '.recovery-link:hover { color: #a78bbd; }',
    '.handle-row { border-color: #3d2a5c; }',
    '.handle-suffix { color: #7c6894; background: #1a1033; border-color: #3d2a5c; }',
    '.status.available { color: #4ade80; }',
    '.status.taken { color: #fca5a5; }',
    '.status.checking { color: #7c6894; }',
    '.permissions { background: #1a1033; }',
    '.permissions li::before { color: #4ade80; }',
    '.account-info { background: #2d1a4f; color: #c4b5fd; }',
  ].join(' '),
}

const amber: Theme = {
  page: {
    bg: '#1a1208',
    surface: '#2d2010',
    surfaceShadow: '0 2px 12px rgba(0,0,0,0.4)',
    text: '#fef3c7',
    textMuted: '#d4a574',
    textHint: '#a07848',
    primary: '#f59e0b',
    primaryHover: '#d97706',
    inputBg: '#1a1208',
    inputBorder: '#4a3520',
    focusBorder: '#f59e0b',
    errorText: '#fca5a5',
    errorBg: '#450a0a',
    logoBg: '#f59e0b',
  },
  injectedCss: [
    // Provider-UI consent page: recolour Tailwind utilities via the
    // --branding-color-* custom props the UI reads through
    // `rgb(var(--branding-color-primary))`. Channels are space-separated.
    ':root { --branding-color-primary: 245 158 11; --branding-color-primary-contrast: 26 18 8; }',
    // Body background & primary text. Provider-UI sets these on <body>
    // via `bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100`,
    // so class-specific selectors (plus !important for dark-mode) are
    // needed to override Tailwind's equal-specificity rules.
    'body { background: #1a1208 !important; color: #fef3c7 !important; }',
    'html { background: #1a1208; }',
    // Consent page's "left strip" header column (md:bg-slate-100
    // md:dark:bg-slate-800) — paint it a shade lighter than body so
    // it reads as a distinct surface, matching the demo's own cards.
    '.md\\:bg-slate-100, .md\\:dark\\:bg-slate-800 { background-color: #2d2010 !important; }',
    '.md\\:dark\\:border-slate-700 { border-color: #4a3520 !important; }',
    // Three-tone text hierarchy on the consent page. Provider-UI uses
    // `text-slate-{100,200,300,400}` + `text-neutral-{400,500}` for
    // primary / muted / hint text; remap to the theme's three shades.
    '.text-slate-900, .dark\\:text-slate-100, .text-slate-800, .dark\\:text-slate-200, .text-gray-800, .dark\\:text-gray-200 { color: #fef3c7 !important; }',
    '.text-slate-700, .text-slate-600, .dark\\:text-slate-300, .dark\\:text-slate-400 { color: #d4a574 !important; }',
    '.text-slate-500, .text-gray-500, .text-neutral-500, .dark\\:text-neutral-400, .dark\\:text-gray-300, .dark\\:text-gray-400 { color: #a07848 !important; }',
    // Consent page secondary buttons (Deny access etc.) default to
    // .bg-gray-300 / .dark:bg-slate-600, which reads as a jarring
    // slate-grey against the themed card. Tint them to a muted surface
    // that harmonises with the palette.
    '.bg-gray-300, .dark\\:bg-slate-600, .bg-gray-200, .dark\\:bg-gray-800, .dark\\:bg-gray-700 { background-color: #4a3520 !important; color: #fef3c7 !important; }',
    // auth-service hand-rolled markup
    '.container { background: #2d2010; box-shadow: 0 2px 12px rgba(0,0,0,0.4); }',
    'h1 { color: #fef3c7; }',
    '.subtitle { color: #d4a574; }',
    '.field label { color: #e8d5b0; }',
    '.field input { background: #1a1208; border-color: #4a3520; color: #fef3c7; }',
    '.field input:focus { border-color: #f59e0b; }',
    '.field input::placeholder { color: #a07848; }',
    '.otp-input { color: #fef3c7; }',
    '.otp-input:focus { border-color: #f59e0b !important; }',
    '.btn-primary { background: #f59e0b; color: #1a1208; }',
    '.btn-primary:hover { background: #d97706; }',
    '.btn-secondary { color: #d4a574; }',
    '.btn-social { background: #1a1208; border-color: #4a3520; color: #fef3c7; }',
    '.btn-social:hover { background: #4a3520; }',
    '.divider { color: #a07848; }',
    '.divider::before, .divider::after { background: #4a3520; }',
    '.error { background: #450a0a; color: #fca5a5; }',
    '.recovery-link { color: #a07848; }',
    '.recovery-link:hover { color: #d4a574; }',
    '.handle-row { border-color: #4a3520; }',
    '.handle-suffix { color: #a07848; background: #1a1208; border-color: #4a3520; }',
    '.status.available { color: #4ade80; }',
    '.status.taken { color: #fca5a5; }',
    '.status.checking { color: #a07848; }',
    '.permissions { background: #1a1208; }',
    '.permissions li::before { color: #4ade80; }',
    '.account-info { background: #3d2a10; color: #fbbf24; }',
  ].join(' '),
}

const presets: Record<string, Theme> = {
  ocean,
  amber,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Returns the active theme, or `null` when no theme is configured.
 * Reads `EPDS_CLIENT_THEME` at call time so it works in both
 * server components and route handlers.
 */
export function getTheme(): Theme | null {
  const name = process.env.EPDS_CLIENT_THEME
  if (!name) return null
  return presets[name] ?? null
}

/**
 * Returns just the page-level style values, or `null`.
 * Server-only — reads EPDS_CLIENT_THEME at call time.
 */
export function getPageTheme(): PageTheme | null {
  return getTheme()?.page ?? null
}
