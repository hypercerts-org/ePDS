---
'ePDS': patch
---

Small grey text on the sign-in page is darker and easier to read.

**Affects:** End users, Operators

**End users:** the 13px grey text — the terms line, the "Recover with backup email" link, the "or continue with" / "or use email" separators, and the "powered by Certified" footer — was too light to meet the WCAG AA contrast minimum against either the card or the page background behind it. It is now dark enough to pass on both.

**Operators:** the `--muted-foreground` custom property on the sign-in page changes from `#999` to `#666`. If your `branding.css` overrides it, check your value clears 4.5:1 against both `#F8F8F8` (the card) and `#E8E8E8` (the page); the old default reached only 2.68:1 and 2.33:1 respectively. The separator text between the social and email sign-in options now follows `--muted-foreground` too, where it previously ignored the override and stayed grey.
