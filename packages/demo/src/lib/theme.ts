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
  /** Primary button text */
  primaryText: string
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

interface InjectedCssOptions {
  primaryChannels: string
  primaryContrastChannels: string
  fieldLabel: string
  secondarySurfaceHover: string
  accountInfoBg: string
  accountInfoText: string
}

function buildInjectedCss(
  page: PageTheme,
  options: InjectedCssOptions,
): string {
  const {
    primaryChannels,
    primaryContrastChannels,
    fieldLabel,
    secondarySurfaceHover,
    accountInfoBg,
    accountInfoText,
  } = options

  return [
    // Provider-UI consent page: recolour Tailwind utilities via the
    // --branding-color-* custom props the UI reads through
    // `rgb(var(--branding-color-primary))`. Channels are space-separated.
    `:root { --branding-color-primary: ${primaryChannels}; --branding-color-primary-contrast: ${primaryContrastChannels}; }`,
    // Body background & primary text. Provider-UI sets these on <body>
    // via `bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100`,
    // so class-specific selectors (plus !important for dark-mode) are
    // needed to override Tailwind's equal-specificity rules.
    `body { background: ${page.bg} !important; color: ${page.text} !important; }`,
    `html { background: ${page.bg}; }`,
    // Consent page's "left strip" header column (md:bg-slate-100
    // md:dark:bg-slate-800) — paint it a shade lighter than body so
    // it reads as a distinct surface, matching the demo's own cards.
    String.raw`.md\:bg-slate-100, .md\:dark\:bg-slate-800 { background-color: ${page.surface} !important; }`,
    String.raw`.md\:dark\:border-slate-700 { border-color: ${page.inputBorder} !important; }`,
    `main { background: ${page.surface} !important; border-color: ${page.inputBorder} !important; box-shadow: ${page.surfaceShadow} !important; }`,
    // Three-tone text hierarchy on the consent page. Provider-UI uses
    // `text-slate-{100,200,300,400}` + `text-neutral-{400,500}` for
    // primary / muted / hint text; remap to the theme's three shades.
    String.raw`.text-slate-900, .dark\:text-slate-100, .text-slate-800, .dark\:text-slate-200, .text-gray-800, .dark\:text-gray-200 { color: ${page.text} !important; }`,
    String.raw`.text-slate-700, .text-slate-600, .dark\:text-slate-300, .dark\:text-slate-400 { color: ${page.textMuted} !important; }`,
    String.raw`.text-slate-500, .text-gray-500, .text-neutral-500, .dark\:text-neutral-400, .dark\:text-gray-300, .dark\:text-gray-400 { color: ${page.textHint} !important; }`,
    // Consent page secondary buttons (Deny access etc.) default to
    // .bg-gray-300 / .dark:bg-slate-600, which reads as a jarring
    // slate-grey against the themed card. Tint them to a muted surface
    // that harmonises with the palette.
    String.raw`.bg-gray-100, .bg-gray-300, .dark\:bg-slate-600, .bg-gray-200, .dark\:bg-gray-800, .dark\:bg-gray-700 { background-color: ${page.inputBorder} !important; color: ${page.text} !important; border-color: ${page.inputBorder} !important; }`,
    String.raw`.hover\:bg-gray-200:hover, .dark\:hover\:bg-gray-700:hover { background-color: ${secondarySurfaceHover} !important; }`,
    // auth-service hand-rolled markup
    `:root { --page-bg: ${page.bg}; --card-bg: ${page.surface}; --card-border: ${page.inputBorder}; --input-bg: ${page.inputBg}; --input-border: ${page.inputBorder}; --muted-foreground: ${page.textMuted}; --focus-border: ${page.focusBorder}; --btn-secondary-border: ${page.inputBorder}; }`,
    `.container { background: ${page.surface}; box-shadow: ${page.surfaceShadow}; }`,
    `h1 { color: ${page.text}; }`,
    `.subtitle { color: ${page.textMuted}; }`,
    `.field label { color: ${fieldLabel}; }`,
    `.field input { background: ${page.inputBg}; border-color: ${page.inputBorder}; color: ${page.text}; }`,
    `.field input:focus { border-color: ${page.focusBorder}; }`,
    `.field input::placeholder { color: ${page.textHint}; }`,
    `.otp-box { color: ${page.text}; }`,
    `.otp-box:focus { border-color: ${page.focusBorder} !important; }`,
    `.btn-primary { background: ${page.primary}; color: ${page.primaryText}; }`,
    `.btn-primary:hover { background: ${page.primaryHover}; }`,
    `.btn-secondary { color: ${page.textMuted}; }`,
    `.btn-social { background: ${page.inputBg}; border-color: ${page.inputBorder}; color: ${page.text}; }`,
    `.btn-atproto { background: ${page.inputBg} !important; border-color: ${page.inputBorder} !important; color: ${page.text} !important; }`,
    `.btn-social:hover { background: ${page.inputBorder}; }`,
    `.divider { color: ${page.textHint}; }`,
    `.divider::before, .divider::after { background: ${page.inputBorder}; }`,
    `.error { background: ${page.errorBg}; color: ${page.errorText}; }`,
    `.flash-msg.error { background: ${page.errorBg}; color: ${page.errorText}; }`,
    `.recovery-link { color: ${page.textHint}; }`,
    `.recovery-link:hover { color: ${page.textMuted}; }`,
    `.handle-row { border-color: ${page.inputBorder}; }`,
    `.handle-suffix { color: ${page.textHint}; background: ${page.inputBg}; border-color: ${page.inputBorder}; }`,
    '.status.available { color: #4ade80; }',
    `.status.taken { color: ${page.errorText}; }`,
    `.status.checking { color: ${page.textHint}; }`,
    `.permissions { background: ${page.inputBg}; }`,
    '.permissions li::before { color: #4ade80; }',
    `.account-info { background: ${accountInfoBg}; color: ${accountInfoText}; }`,
  ].join(' ')
}

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

const oceanPage: PageTheme = {
  bg: '#1a1033',
  surface: '#251845',
  surfaceShadow: '0 2px 12px rgba(0,0,0,0.4)',
  text: '#e8e0f0',
  textMuted: '#a78bbd',
  textHint: '#7c6894',
  primary: '#8b5cf6',
  primaryText: '#ffffff',
  primaryHover: '#7c3aed',
  inputBg: '#1a1033',
  inputBorder: '#3d2a5c',
  focusBorder: '#8b5cf6',
  errorText: '#fca5a5',
  errorBg: '#450a0a',
  logoBg: '#8b5cf6',
}

const ocean: Theme = {
  page: oceanPage,
  injectedCss: buildInjectedCss(oceanPage, {
    primaryChannels: '139 92 246',
    primaryContrastChannels: '26 16 51',
    fieldLabel: '#d4c4e8',
    secondarySurfaceHover: '#4c3570',
    accountInfoBg: '#2d1a4f',
    accountInfoText: '#c4b5fd',
  }),
}

const amberPage: PageTheme = {
  bg: '#1a1208',
  surface: '#2d2010',
  surfaceShadow: '0 2px 12px rgba(0,0,0,0.4)',
  text: '#fef3c7',
  textMuted: '#d4a574',
  textHint: '#b98b55',
  primary: '#f59e0b',
  primaryText: '#1a1208',
  primaryHover: '#d97706',
  inputBg: '#1a1208',
  inputBorder: '#4a3520',
  focusBorder: '#f59e0b',
  errorText: '#fca5a5',
  errorBg: '#450a0a',
  logoBg: '#f59e0b',
}

const amber: Theme = {
  page: amberPage,
  injectedCss: buildInjectedCss(amberPage, {
    primaryChannels: '245 158 11',
    primaryContrastChannels: '26 18 8',
    fieldLabel: '#e8d5b0',
    secondarySurfaceHover: '#5a4228',
    accountInfoBg: '#3d2a10',
    accountInfoText: '#fbbf24',
  }),
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
