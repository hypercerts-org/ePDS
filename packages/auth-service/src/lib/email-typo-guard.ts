const COMMON_EMAIL_DOMAINS = [
  'gmail.com',
  'hotmail.com',
  'outlook.com',
  'yahoo.com',
  'icloud.com',
] as const

/**
 * Return the optimal-string-alignment distance between two strings.
 *
 * Unlike plain Levenshtein distance, one adjacent transposition counts as one
 * edit, so common mistakes such as `gmial.com` are recognised conservatively.
 */
function editDistance(left: string, right: string): number {
  const rows = left.length + 1
  const columns = right.length + 1
  const distance = Array.from({ length: rows }, () =>
    Array<number>(columns).fill(0),
  )

  for (let row = 0; row < rows; row += 1) distance[row][0] = row
  for (let column = 0; column < columns; column += 1) {
    distance[0][column] = column
  }

  for (let row = 1; row < rows; row += 1) {
    for (let column = 1; column < columns; column += 1) {
      const substitutionCost = left[row - 1] === right[column - 1] ? 0 : 1
      distance[row][column] = Math.min(
        distance[row - 1][column] + 1,
        distance[row][column - 1] + 1,
        distance[row - 1][column - 1] + substitutionCost,
      )

      if (
        row > 1 &&
        column > 1 &&
        left[row - 1] === right[column - 2] &&
        left[row - 2] === right[column - 1]
      ) {
        distance[row][column] = Math.min(
          distance[row][column],
          distance[row - 2][column - 2] + 1,
        )
      }
    }
  }

  return distance[left.length][right.length]
}

/**
 * Suggest a corrected address when its domain is exactly one edit away from a
 * common provider. Exact domains and less-certain matches are left untouched.
 */
export function suggestEmailAddress(email: string): string | null {
  const trimmed = email.trim()
  const at = trimmed.lastIndexOf('@')
  if (at <= 0 || at !== trimmed.indexOf('@') || at === trimmed.length - 1) {
    return null
  }

  const localPart = trimmed.slice(0, at)
  const domain = trimmed.slice(at + 1).toLowerCase()
  if (COMMON_EMAIL_DOMAINS.some((candidate) => candidate === domain)) {
    return null
  }

  const suggestion = COMMON_EMAIL_DOMAINS.find(
    (candidate) => editDistance(domain, candidate) === 1,
  )
  return suggestion ? `${localPart}@${suggestion}` : null
}

export const EMAIL_TYPO_GUARD_CSS = `
.email-typo-suggestion { position: relative; margin: -10px 0 20px; padding: 12px 34px 12px 12px; border: 1px solid var(--email-typo-border, #e4c86a); border-radius: 8px; background: var(--email-typo-bg, #fff8dc); color: var(--email-typo-foreground, #4a3b00); font-size: 14px; line-height: 1.5; text-align: left; }
.email-typo-suggestion[hidden] { display: none; }
.email-typo-suggestion p { margin: 0; }
.email-typo-action { border: 1px solid var(--email-typo-action-border, currentColor); border-radius: 6px; padding: 3px 8px; background: var(--email-typo-action-bg, rgba(255, 255, 255, 0.65)); color: inherit; font: inherit; font-size: 13px; font-weight: 600; line-height: 1.3; cursor: pointer; }
.email-typo-action:hover { background: var(--email-typo-action-hover-bg, rgba(255, 255, 255, 0.9)); }
.email-typo-action:focus-visible, .email-typo-dismiss:focus-visible { outline: 2px solid currentColor; outline-offset: 2px; }
.email-typo-accept { display: inline-block; margin-top: 8px; }
.email-typo-dismiss { position: absolute; top: 4px; right: 4px; display: flex; width: 24px; height: 24px; align-items: center; justify-content: center; border: 0; border-radius: 3px; padding: 0; background: transparent; color: inherit; font: inherit; font-size: 18px; line-height: 1; opacity: 0.55; cursor: pointer; }
.email-typo-dismiss:hover { opacity: 0.85; }
.email-typo-suggestion ~ button[type="submit"]:disabled { opacity: 0.55; cursor: not-allowed; }
`

export function renderEmailTypoGuardMarkup(): string {
  return `<div class="email-typo-suggestion" hidden>
  <button type="button" class="email-typo-dismiss" aria-label="Dismiss email correction suggestion" title="Dismiss">&times;</button>
  <p role="status" aria-live="polite">Did you mean <strong class="email-typo-correction"></strong>?</p>
  <button type="button" class="email-typo-action email-typo-accept">Yes, fix it</button>
</div>`
}

/**
 * Render a dependency-free browser guard for one email form.
 *
 * Input changes reveal likely corrections immediately. The capture-phase
 * submit listener remains as defence in depth, so a typo cannot fire an OTP
 * request until the user accepts or dismisses the suggestion.
 *
 * When `cspNonce` is supplied the tag is stamped with `nonce="..."` so it
 * survives the auth-service's `script-src 'nonce-...'` policy; callers that
 * render outside a nonce-bearing response omit it.
 */
export function renderEmailTypoGuardScript(
  formId: string,
  inputId: string,
  cspNonce?: string,
): string {
  const nonceAttr = cspNonce ? ` nonce="${cspNonce}"` : ''
  return `<script${nonceAttr}>
(function() {
  var form = document.getElementById(${JSON.stringify(formId)});
  var input = document.getElementById(${JSON.stringify(inputId)});
  if (!form || !input) return;

  var commonDomains = ${JSON.stringify(COMMON_EMAIL_DOMAINS)};
  var prompt = form.querySelector('.email-typo-suggestion');
  var correctionText = form.querySelector('.email-typo-correction');
  var acceptButton = form.querySelector('.email-typo-accept');
  var dismissButton = form.querySelector('.email-typo-dismiss');
  var submitButton = form.querySelector('button[type="submit"]');
  if (!prompt || !correctionText || !acceptButton || !dismissButton || !submitButton) return;

  var originalEmail = '';
  var suggestedEmail = '';
  var bypassEmail = null;
  var promptActive = false;

  function editDistance(left, right) {
    var distance = [];
    var row;
    var column;
    for (row = 0; row <= left.length; row += 1) {
      distance[row] = [];
      distance[row][0] = row;
    }
    for (column = 0; column <= right.length; column += 1) {
      distance[0][column] = column;
    }
    for (row = 1; row <= left.length; row += 1) {
      for (column = 1; column <= right.length; column += 1) {
        var substitutionCost = left.charAt(row - 1) === right.charAt(column - 1) ? 0 : 1;
        distance[row][column] = Math.min(
          distance[row - 1][column] + 1,
          distance[row][column - 1] + 1,
          distance[row - 1][column - 1] + substitutionCost
        );
        if (
          row > 1 &&
          column > 1 &&
          left.charAt(row - 1) === right.charAt(column - 2) &&
          left.charAt(row - 2) === right.charAt(column - 1)
        ) {
          distance[row][column] = Math.min(
            distance[row][column],
            distance[row - 2][column - 2] + 1
          );
        }
      }
    }
    return distance[left.length][right.length];
  }

  function suggest(email) {
    var trimmed = email.trim();
    var at = trimmed.lastIndexOf('@');
    if (at <= 0 || at !== trimmed.indexOf('@') || at === trimmed.length - 1) return null;
    var localPart = trimmed.slice(0, at);
    var domain = trimmed.slice(at + 1).toLowerCase();
    for (var i = 0; i < commonDomains.length; i += 1) {
      if (domain === commonDomains[i]) return null;
    }
    for (var j = 0; j < commonDomains.length; j += 1) {
      if (editDistance(domain, commonDomains[j]) === 1) {
        return localPart + '@' + commonDomains[j];
      }
    }
    return null;
  }

  function hidePrompt() {
    prompt.hidden = true;
    if (promptActive) submitButton.disabled = false;
    promptActive = false;
    correctionText.textContent = '';
    originalEmail = '';
    suggestedEmail = '';
  }

  function showPrompt(email, correction) {
    originalEmail = email;
    suggestedEmail = correction;
    // Reveal the live region before changing its content so assistive
    // technology can observe and announce the suggestion mutation.
    prompt.hidden = false;
    promptActive = true;
    submitButton.disabled = true;
    correctionText.textContent = suggestedEmail;
  }

  function refreshPrompt() {
    var email = input.value.trim();
    var correction = suggest(email);
    if (correction) {
      showPrompt(email, correction);
    } else {
      hidePrompt();
    }
  }

  input.addEventListener('input', function() {
    bypassEmail = null;
    refreshPrompt();
  });

  form.addEventListener('submit', function(event) {
    var email = input.value.trim();
    if (bypassEmail !== null && email.toLowerCase() === bypassEmail.toLowerCase()) {
      bypassEmail = null;
      hidePrompt();
      return;
    }

    var correction = suggest(email);
    if (!correction) {
      hidePrompt();
      return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();
    showPrompt(email, correction);
    acceptButton.focus();
  }, true);

  acceptButton.addEventListener('click', function() {
    var correction = suggestedEmail;
    input.value = correction;
    bypassEmail = correction;
    hidePrompt();
    input.focus();
  });

  dismissButton.addEventListener('click', function() {
    bypassEmail = originalEmail;
    hidePrompt();
    input.focus();
  });

  refreshPrompt();
})();
</script>`
}
