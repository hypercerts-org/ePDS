---
'ePDS': patch
---

The approval and account-chooser screens now honour the handle mode your app asked for, instead of falling back to the server default.

**Affects:** Client app developers

**Client app developers:** no action needed — `epds_handle_mode` is resolved exactly as before (the `/oauth/authorize` query parameter, then your OAuth client metadata, then the server default). Previously the resolved mode was lost on the way to the approval step, so a flow that asked for a chosen handle could still show a generated one there. The mode is now carried through `/oauth/epds-callback` and applied on the approval and chooser screens. Values that are not one of the recognised modes are ignored rather than forwarded.
