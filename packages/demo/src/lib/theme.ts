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
    // Provider UI 0.10 consumes semantic color roles. Client CSS loads after
    // the provider stylesheet, so these values also win over its dark-media
    // defaults without coupling the theme to generated utility-class names.
    `:root { color-scheme: light; --branding-color-primary: ${primaryChannels}; --branding-color-primary-contrast: ${primaryContrastChannels}; --background: ${page.surface}; --foreground: ${page.text}; --card: ${page.surface}; --card-foreground: ${page.text}; --popover: ${page.surface}; --popover-foreground: ${page.text}; --secondary: ${page.inputBg}; --secondary-foreground: ${page.text}; --muted: ${page.bg}; --muted-foreground: ${page.textMuted}; --accent: ${secondarySurfaceHover}; --accent-foreground: ${page.text}; --border: ${page.inputBorder}; --input: ${page.inputBorder}; --ring: ${page.focusBorder}; --page-bg: ${page.bg}; --card-bg: ${page.surface}; --card-border: ${page.inputBorder}; --input-bg: ${page.inputBg}; --input-border: ${page.inputBorder}; --focus-border: ${page.focusBorder}; --btn-secondary-border: ${page.inputBorder}; }`,
    `body, html { background: ${page.bg} !important; color: ${page.text} !important; }`,
    // data-slot is the provider's component contract; unlike its generated
    // Tailwind utility sequence, it describes the card across UI rebuilds.
    `[data-slot="card"] { border: 1px solid ${page.inputBorder}; box-shadow: ${page.surfaceShadow}; }`,
    `[data-slot="card-footer"] { border-color: ${page.inputBorder}; }`,
    // auth-service hand-rolled markup

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
    // Standalone actions under Verify (.btn-secondary buttons and the
    // .recovery-link anchor) are one visual class, so they must theme
    // identically — see the link-affordance convention in login-page.ts.
    `.btn-secondary, .recovery-link { color: ${page.textMuted}; }`,
    `.btn-secondary:hover, .recovery-link:hover { color: ${page.text}; }`,
    `.btn-social { background: ${page.inputBg}; border-color: ${page.inputBorder}; color: ${page.text}; }`,
    `.btn-atproto { background: ${page.inputBg} !important; border-color: ${page.inputBorder} !important; color: ${page.text} !important; }`,
    `.btn-social:hover { background: ${page.inputBorder}; }`,
    `.divider { color: ${page.textHint}; }`,
    `.divider::before, .divider::after { background: ${page.inputBorder}; }`,
    `.error { background: ${page.errorBg}; color: ${page.errorText}; }`,
    `.flash-msg.error { background: ${page.errorBg}; color: ${page.errorText}; }`,
    `.handle-row { border-color: ${page.inputBorder}; }`,
    `.handle-suffix { color: ${page.textHint}; background: ${page.inputBg}; border-color: ${page.inputBorder}; }`,
    '.status.available { color: #4ade80; }',
    `.status.unavailable { color: ${page.errorText}; }`,
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

const maEarthConsentMvpPage: PageTheme = {
  bg: '#F2ECE4',
  surface: '#FAF8F6',
  surfaceShadow: '0 12px 32px rgba(33,32,31,0.10)',
  text: '#21201F',
  textMuted: '#4C4139',
  textHint: '#6B6259',
  primary: '#21201F',
  primaryText: '#FAF8F6',
  primaryHover: '#3A3735',
  inputBg: '#EAE1D7',
  inputBorder: '#D4C9BC',
  focusBorder: '#D4B08A',
  errorText: '#B25032',
  errorBg: '#F7E8E2',
  logoBg: '#21201F',
}

/**
 * Temporary consent-screen concept for Ma Earth review on provider UI 0.10.
 * This is deployment scaffolding for the stacked PR, not production ownership
 * of Ma Earth's client branding. Remove it after the visual review.
 */
export const MAEARTH_CONSENT_MVP_THEME: Theme = {
  page: maEarthConsentMvpPage,
  injectedCss: [
    buildInjectedCss(maEarthConsentMvpPage, {
      primaryChannels: '33 32 31',
      primaryContrastChannels: '250 248 246',
      fieldLabel: '#4C4139',
      secondarySurfaceHover: '#DDD4C8',
      accountInfoBg: '#EAE1D7',
      accountInfoText: '#4C4139',
    }),
    ':root { --branding-color-error: 178 80 50; --branding-color-warning: 180 140 80; --branding-color-success: 93 138 93; --recovery-link-display: none; }',
    '.auth-background > div:has(> [data-slot="card"]) { max-width: 30rem; }',
    '[data-slot="card"] { border-radius: 18px; }',
    '[data-slot="card-footer"] { background: #EAE1D7; }',
    '[data-slot="card-title"] { letter-spacing: -0.01em; }',
    '[data-slot="button"] { min-height: 2.5rem; }',
    '[data-slot="button"].bg-secondary { border-color: #D4C9BC; }',
    '[data-slot="avatar"]:has(> img[alt="Ma Earth"]) { width: 6rem; height: 2rem; border-radius: 0; }',
    '[data-slot="avatar"]:has(> img[alt="Ma Earth"])::after { display: none; }',
    'div:has(> [data-slot="avatar"] > img[alt="Ma Earth"]) { width: 6rem; margin-left: 0; }',
    '[data-slot="avatar"] > img[alt="Ma Earth"] { width: 100%; height: 100%; object-fit: contain; }',
  ].join(' '),
}

const presets: Record<string, Theme> = {
  ocean,
  amber,
  'maearth-consent-mvp': MAEARTH_CONSENT_MVP_THEME,
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
