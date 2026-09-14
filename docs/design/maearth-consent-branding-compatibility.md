# Ma Earth Consent Branding Compatibility

## Context

ePDS currently uses `@atproto/pds` 0.5.23, with the matching OAuth provider and
provider UI packages. The proposed upgrade to PDS 0.5.34 also upgrades the
provider UI from 0.8.9 to 0.10.3.

The provider UI upgrade changes the HTML structure and CSS utility classes used
by the upstream consent and account-selection screens. Ma Earth's existing
OAuth client metadata supplies custom branding CSS written for the old provider
UI. Ma Earth is outside our control, so its CSS cannot be changed as part of the
ePDS upgrade.

The goal is visual compatibility: after upgrading ePDS, a Ma Earth consent
screen should retain its current appearance without requiring any Ma Earth
change.

## Actual exposure

Ma Earth is a trusted ePDS OAuth client and requests random handles. Production
also has `PDS_SIGNUP_ALLOW_CONSENT_SKIP` enabled.

Its normal email login behaves as follows:

- New users complete the custom ePDS email/OTP flow and skip consent.
- Returning users with all requested scopes already granted complete the custom
  email/OTP flow and return directly to Ma Earth.
- Existing users connecting Ma Earth for the first time can see upstream
  consent because no prior grant exists.
- Existing users can see upstream consent again if Ma Earth requests additional
  scopes.
- The upstream account chooser is not part of Ma Earth's normal email flow. The
  callback supplies the authenticated DID as the login hint, including when the
  device remembers multiple accounts.
- A Ma Earth handle/DID login for an account on another PDS uses that PDS's
  authorization UI and branding. The Certified.one ePDS UI is not involved.

Trust and consent skip do not provide a blanket consent bypass for existing
accounts. Consent remains scope-aware.

## What is and is not affected

### Unaffected

The email, OTP, and random-handle pages are custom auth-service pages. Upgrading
the upstream provider UI does not replace their HTML. Ma Earth's existing CSS
rules for those pages should continue to work.

Gainforest's own login page is likewise owned by its authentication service and
is not changed by this provider UI upgrade.

### Affected

Rare Ma Earth consent screens are rendered by the upstream provider UI. UI
0.10.3 replaces many old utility classes, including gray/slate background and
text classes, with semantic classes and variables such as `bg-accent`,
`text-muted-foreground`, and `border-border`.

Ma Earth's existing CSS contains rules for the old provider markup. Those rules
will no longer match some new elements. Local source comparison confirms the
selector mismatch, but browser rendering is still required to measure visible
impact. Likely differences include:

- page and card backgrounds;
- text hierarchy;
- secondary controls and hover states;
- logo/title placement;
- responsive action layout.

Primary branding variables remain supported, so this is expected to be visual
degradation rather than a broken OAuth flow.

## Decision

Use a small Ma Earth-specific compatibility stylesheet owned by ePDS.

Do not:

- modify Ma Earth;
- build a generic client-CSS transformation system;
- mutate provider UI DOM to add legacy classes;
- rewrite all ePDS branding before visible differences are known;
- treat obsolete selectors alone as proof that every screen is visibly broken.

A generic compatibility layer would add disproportionate complexity for a rare,
client-specific screen. If more clients later need similar patches, reconsider
a documented semantic branding contract.

## Implementation shape

First render and compare the current and upgraded Ma Earth consent screens.
Then add only rules required to preserve the current appearance.

Suggested ownership:

```text
packages/pds-core/src/
├── lib/client-css-injection.ts       # selects and appends compatibility CSS
├── lib/maearth-branding-compat.ts    # focused ePDS-owned stylesheet
└── __tests__/                        # injection and rendered-contract coverage
```

CSS order on `/oauth/authorize` should be:

```text
1. ePDS default branding CSS
2. Ma Earth's existing client branding CSS
3. ePDS-owned Ma Earth compatibility CSS
```

The final layer applies only when the exact trusted Ma Earth client ID is
resolved. It should target only the upgraded provider consent UI and should not
alter auth-service email, OTP, or handle pages.

Keep the exception explicit and documented. Avoid parsing or rewriting remote
client CSS.

## Implementation sequence

1. Establish reference screenshots or computed styles for today's Ma Earth
   consent screen using an existing Certified.one user with no Ma Earth grant.
2. Upgrade PDS, OAuth provider, and provider UI together in an isolated branch.
3. Render the same consent scenario with Ma Earth's unchanged branding CSS.
4. List actual visible differences. Ignore obsolete rules that produce no
   visible regression.
5. Add the smallest ePDS-owned compatibility stylesheet needed to reproduce the
   current appearance.
6. Inject it after client CSS only for Ma Earth's trusted client ID.
7. Verify first-grant and expanded-scope consent on desktop and mobile.
8. Confirm normal new-user and returning-user email/OTP flows remain unchanged.

## Required tests

- Compatibility CSS is injected for the exact Ma Earth client ID.
- It is not injected for other trusted or untrusted clients.
- It is injected only on the upstream authorization response where needed.
- Ma Earth's existing client CSS remains present and precedes the compatibility
  stylesheet.
- First-grant consent preserves current background, card, text, logo, primary
  action, secondary action, hover, and responsive behavior.
- Expanded-scope consent has the same result.
- New-user random-handle signup still skips consent.
- Returning users with existing grants still return without consent.

## Separate upgrade work

This branding decision does not replace other PDS 0.5.34 upgrade tasks:

- align `@atproto/pds`, `@atproto/oauth-provider`, and
  `@atproto/oauth-provider-ui` versions;
- update the `Another account` lookup to support native `<button>` elements;
- validate provider errors, preview assets, OAuth flows, runtime dependencies,
  and standard PDS behavior.

## Evidence limits

Findings came from local source snapshots. Production client metadata, rendered
pages, computed styles, and deployment configuration were not fetched or
inspected. Visual changes must be measured before compatibility CSS is written.
