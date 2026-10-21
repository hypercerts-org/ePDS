/**
 * Default CSS injected into upstream `@atproto/oauth-provider-ui` HTML
 * (consent + chooser screens) so an unbranded ePDS deployment matches the
 * neutral Certified-style aesthetic used by auth-service.
 *
 * Provider UI 0.10 exposes semantic color roles and stable `data-slot`
 * attributes. Keep this stylesheet on those contracts rather than generated
 * gray/slate utility classes, which changed substantially from UI 0.8.
 *
 * This stylesheet is injected before trusted-client `branding.css`, allowing a
 * client theme to override every value through normal cascade ordering.
 */
export const DEFAULT_BRANDING_CSS = [
  // The provider derives --primary and --ring from these supported branding
  // channels. The remaining variables are its semantic UI roles.
  ':root { color-scheme: light; --branding-color-primary: 26 19 15; --branding-color-primary-contrast: 248 248 248; --background: #F8F8F8; --foreground: #1A130F; --card: #F8F8F8; --card-foreground: #1A130F; --popover: #F8F8F8; --popover-foreground: #1A130F; --secondary: #FFFFFF; --secondary-foreground: #1A130F; --muted: #E8E8E8; --muted-foreground: #6B6B6B; --accent: #FAFAFA; --accent-foreground: #1A130F; --border: #E5E5E5; --input: #E5E5E5; }',
  // Keep the document behind AuthShell on the same muted surface. AuthShell
  // itself consumes --muted through its stable `auth-background` class.
  'html, body { background: #E8E8E8 !important; color: var(--foreground) !important; }',
  // Card is an explicit component contract in UI 0.10. The provider supplies
  // its layout and spacing; ePDS adds only the familiar border and soft lift.
  '[data-slot="card"] { border: 1px solid var(--border); box-shadow: 0 1px 2px rgba(0,0,0,0.03); }',
  '[data-slot="card-footer"] { border-color: var(--border); }',
].join(' ')
