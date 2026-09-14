# Ma Earth Consent Branding on Provider UI 0.10.3

## Context

ePDS is upgrading `@atproto/pds` from 0.5.23 to 0.5.34 and the matching
`@atproto/oauth-provider-ui` from 0.8.9 to 0.10.3. Provider UI 0.10.3 changes
the authorization-page component structure, CSS utility classes, spacing,
typography, and controls. It is a redesigned authorization UI, not only a
class-name update.

Ma Earth supplies its branding through the public OAuth client metadata at:

```text
https://maearth.com/atproto-client-metadata.json
```

Its current `branding.css` was written against the older provider UI. There is
no separate historical Ma Earth CSS version to restore or compare. The same
current CSS partly applies to UI 0.10.3 through generic element selectors and
branding variables, while selectors coupled to the old gray/slate utilities or
old component structure no longer match.

## Revised objective

Do not recreate the old provider consent layout.

Create an MVP showing how Ma Earth's current visual language can apply to the
new authorization layout. The result is for Ma Earth team review before any
change is proposed in the Ma Earth application.

```text
provider UI 0.10.3 authorization layout
  + permanent generic ePDS branding fixes
  + temporary adaptation of current Ma Earth branding.css
  = Ma Earth consent-screen MVP
```

The MVP should preserve Ma Earth's recognizable brand choices:

- warm page, card, and secondary-control surfaces;
- dark primary actions with light text;
- warm muted text and borders;
- the Ma Earth wordmark;
- consistent inputs, focus states, and hover states;
- forced light-theme behavior where the current CSS requires it;
- intentional desktop and mobile presentation.

It should retain the new provider's information architecture, consent copy,
permission presentation, and security behavior.

## Non-goals

Do not:

- force the new provider component tree into the old layout;
- treat pixel parity with provider UI 0.8.9 as the target;
- modify Ma Earth's production metadata or application during the MVP;
- install a permanent copy of Ma Earth's stylesheet in ePDS;
- build a generic client-CSS transformation system;
- mutate provider DOM solely to recreate removed utility classes;
- hide or rewrite new consent information introduced upstream;
- infer successful styling from selector presence without rendering the page.

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

## Work split

Keep permanent ePDS compatibility work separate from the temporary Ma Earth
showcase.

### Permanent ePDS work

The stacked PR should retain:

1. A repaired `/preview/consent` fixture for provider UI 0.10.3. The upgraded UI
   selects a session through `authorizeData.selectedDid` and identifies the
   account through `account.did`; the old fixture's `session.selected` and
   `account.sub` shape no longer opens consent directly.
2. Updates to `DEFAULT_BRANDING_CSS` where ePDS-owned selectors depend on old
   provider utility classes or structure.
3. Regression tests proving the preview opens consent and generic branding
   targets the installed provider UI contract.
4. Documentation of the new provider UI dependency.

These changes belong to ePDS and remain after the visual review.

### Temporary Ma Earth showcase

A separate, clearly identified commit should:

1. Start from the CSS currently returned by Ma Earth's production client
   metadata.
2. Adapt obsolete selectors to provider UI 0.10.3's semantic targets and current
   DOM.
3. Serve that adapted CSS from the trusted ePDS demo client metadata so the PR
   Railway deployment can render it without changing Ma Earth or Railway
   variables.
4. Affect only the temporary demo presentation.
5. Be reverted after the Ma Earth team has reviewed the MVP.

The temporary fixture is deployment scaffolding, not the eventual source of
truth for Ma Earth branding.

## CSS adaptation strategy

Prefer provider theme variables and semantic targets over brittle utility-class
chains.

```diff
- .bg-gray-100
- .text-slate-600
- .md\:bg-slate-100
- .grid h1.text-primary

+ :root branding variables
+ .bg-background / .bg-card / .bg-accent
+ .text-foreground / .text-muted-foreground
+ .border-border
+ stable elements and accessibility attributes where necessary
```

Apply these rules:

1. **Use variables first.** Keep `--branding-color-primary` and
   `--branding-color-primary-contrast` as the main provider-supported controls.
2. **Map semantic surfaces deliberately.** Give page, card, accent, muted, and
   border roles explicit Ma Earth colors instead of broadly recoloring every
   element with a matching class fragment.
3. **Use stable element selectors for controls.** Style submit buttons, links,
   inputs, and selects by role or element when the component contract supports
   it.
4. **Avoid copy replacement through pseudo-elements.** The MVP should not hide
   provider text and synthesize different text unless product requirements
   explicitly demand it.
5. **Use metadata-provided identity.** Prefer the provider-rendered client name
   and logo to broad selectors such as `img[alt*="Logo"]` where possible.
6. **Scope structural selectors narrowly.** When a semantic class is
   insufficient, target the authorization component involved rather than all
   provider pages.
7. **Validate interaction states.** Hover, focus-visible, disabled, loading,
   warning, and error states are part of the visual contract.
8. **Test responsive behavior.** Desktop and mobile must both be intentional;
   desktop-only selector matching is not sufficient.

The expected CSS order remains:

```text
1. upstream provider UI CSS
2. ePDS default branding CSS
3. client branding.css
```

The temporary demo's adapted Ma Earth stylesheet occupies layer 3. Permanent
ePDS defaults must not contain Ma Earth-specific palette or logo rules.

## Implementation and review sequence

```text
pds/upgrade-0-5-34                 # PR #251
└── pds/maearth-branding-compat    # stacked PR
    ├── permanent preview + generic selector fixes
    └── temporary Ma Earth MVP fixture
```

1. Repair the consent preview and prove it opens the consent component from the
   installed provider UI bundle.
2. Render provider UI 0.10.3 with ePDS defaults only and record its DOM,
   computed styles, and desktop/mobile screenshots.
3. Load Ma Earth's current production metadata and stylesheet without modifying
   the upstream resource.
4. Add the smallest new-selector adaptation that produces a coherent Ma Earth
   version of the redesigned authorization page.
5. Expose the adapted stylesheet through the trusted demo metadata on the
   stacked branch.
6. Push the branch and open a PR based on `pds/upgrade-0-5-34`, allowing Railway
   to create isolated deployments.
7. Review the deployed consent preview on desktop and mobile, including hover,
   focus, and expanded permission content.
8. Iterate on the MVP with visual evidence rather than selector guesses.
9. Present the result to the Ma Earth team as a proposed first version for the
   new provider UI.
10. Revert the temporary demo fixture after review. Keep the preview repair,
    generic ePDS selector updates, tests, and documentation.
11. If approved, implement the final stylesheet in the Ma Earth repository so
    its client metadata remains the source of truth.

## Required validation

### Automated

- `/preview/consent` selects its fixture account and renders consent under
  provider UI 0.10.3.
- `/preview/chooser` continues to render the chooser.
- Permanent default-branding selectors cover the new semantic provider targets.
- Trusted demo CSS is injected after ePDS defaults.
- Untrusted clients do not receive the temporary trusted-client stylesheet.
- CSP permits each injected style block.
- Existing chooser, OAuth, and account-switching tests continue to pass.

### Visual

Capture desktop and mobile states for:

- consent page initial state;
- expanded permission details, when available;
- primary and secondary actions;
- hover, keyboard focus, disabled, and loading states;
- long client name or scope content;
- warning and error presentation;
- Ma Earth logo sizing and alignment;
- light-theme behavior under a dark OS preference.

Compare the MVP against Ma Earth's broader product language, not against the old
provider component geometry. The review question is: “Does the redesigned
consent page look intentionally Ma Earth while retaining the provider's new
consent behavior?”

## Cleanup and ownership

Before the stacked PR is made merge-ready:

```text
keep
├── provider UI 0.10.3 preview repair
├── generic ePDS default-branding fixes
├── regression tests
└── documentation

drop
└── temporary Ma Earth CSS served by the demo
```

If the Ma Earth team accepts the direction, the production adaptation should be
implemented and reviewed in the Ma Earth application. ePDS should continue to
consume the public client metadata rather than owning a permanent client-specific
stylesheet.

## Evidence limits

The public production metadata and current CSS were retrieved during this
assessment. The upgraded PR preview currently demonstrates that the old consent
fixture opens the chooser instead of consent, which must be repaired before a
valid visual comparison.

No Ma Earth production configuration was changed. No claim about the final
appearance should be made until the repaired preview is deployed and reviewed
in a browser at desktop and mobile sizes.
