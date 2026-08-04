/**
 * Pure helper for deriving HTML input attributes from OTP configuration.
 *
 * Extracted so that both the recovery and account-login routes use identical
 * logic, and so the logic can be unit-tested without rendering or parsing HTML.
 */

export type OtpCharset = 'numeric' | 'alphanumeric'

export interface OtpInputProps {
  pattern: string
  placeholder: string
  inputmode: 'numeric' | 'text'
  autocapitalize: 'characters' | 'off'
}

export function buildOtpInputProps(
  otpLength: number,
  otpCharset: OtpCharset,
): OtpInputProps {
  if (otpCharset === 'alphanumeric') {
    return {
      pattern: `[A-Z0-9]{${otpLength}}`,
      placeholder: 'X'.repeat(otpLength),
      inputmode: 'text',
      autocapitalize: 'characters',
    }
  }
  return {
    pattern: `[0-9]{${otpLength}}`,
    placeholder: '0'.repeat(otpLength),
    inputmode: 'numeric',
    autocapitalize: 'off',
  }
}

/** Build the character-removal pattern shared by server-rendered OTP inputs. */
export function buildOtpInputFilter(otpCharset: OtpCharset): RegExp {
  return otpCharset === 'alphanumeric' ? /[^A-Za-z0-9]/g : /\D/g
}

/**
 * Render the OTP input's character-filtering behaviour as a standalone
 * `<script>` tag rather than an `oninput="..."` attribute.
 *
 * Inline event-handler attributes are NOT covered by a CSP nonce — only
 * `'unsafe-inline'` (or a hash with `unsafe-hashes`) permits them. Since the
 * auth-service serves `script-src 'self' 'nonce-...'`, the attribute form is
 * silently blocked and the filter stops running. Emitting a nonced script that
 * attaches the same listener keeps the behaviour under the strict policy.
 */
export function renderOtpInputFilterScript(
  inputId: string,
  otpCharset: OtpCharset,
  cspNonce?: string,
): string {
  const filter = buildOtpInputFilter(otpCharset)
  const upper = otpCharset === 'alphanumeric' ? '.toUpperCase()' : ''
  const nonceAttr = cspNonce ? ` nonce="${cspNonce}"` : ''
  return `<script${nonceAttr}>
(function() {
  var input = document.getElementById(${JSON.stringify(inputId)});
  if (!input) return;
  input.addEventListener('input', function() {
    this.value = this.value.replace(${filter.toString()}, '')${upper};
  });
})();
</script>`
}

/** Accept a supported preview override, otherwise preserve the configured policy. */
export function resolvePreviewOtpCharset(
  requested: string | undefined,
  configured: OtpCharset,
): OtpCharset {
  return requested === 'numeric' || requested === 'alphanumeric'
    ? requested
    : configured
}
