---
'ePDS': patch
---

Handle picker now flags reserved handles as unavailable upfront.

**Affects:** End users

**End users:** the handle picker has a live availability check that says ✓ Available or ✗ Already taken as you type. For reserved handles (admin, support, www, …) it used to show ✓ Available, then refuse the handle on submit with a "not available" error — wasting the time you spent on the form. The live check now flags reserved handles as unavailable up front so you can keep going without losing what you typed.
