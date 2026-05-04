/**
 * Checkbox that adds `prompt=login` to the demo's authorize request when
 * checked, asking the authorization server to force a fresh credential
 * prompt regardless of any existing session cookies (OIDC `prompt=login`).
 *
 * Uncontrolled: relies on the surrounding form's GET submission. When
 * checked the browser includes `prompt=login` in the query string; when
 * unchecked the param is omitted entirely.
 */
'use client'

interface ForceLoginCheckboxProps {
  disabled?: boolean
}

export function ForceLoginCheckbox({ disabled }: ForceLoginCheckboxProps) {
  return (
    <label
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        fontSize: '13px',
        color: 'var(--theme-text-muted, #6b7280)',
        marginBottom: '12px',
        cursor: 'pointer',
      }}
    >
      <input type="checkbox" name="prompt" value="login" disabled={disabled} />
      Force re-authentication (<code>prompt=login</code>)
    </label>
  )
}
