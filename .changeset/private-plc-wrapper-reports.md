---
'ePDS': patch
---

Protect rotation reports without changing existing directory permissions, and accept PLC URLs with a trailing slash in the shell wrapper.

**Affects:** Operators

**Operators:** Both wrappers now save each run in a new private subdirectory beneath `REPORT_DIR` and reject a symlink as that directory. Use the `Saved report:` path printed on stderr to locate each report.
