---
'ePDS': patch
---

Pasted sign-in codes are no longer auto-submitted with stray punctuation or letters.

**Affects:** End users

**End users:** if you copied your sign-in code from somewhere that wrapped it in punctuation or extra characters (e.g. an email reading "Your code is 1234-5678"), the page used to drop the punctuation straight into the digit boxes and submit the result, which the server would then reject as an invalid code. The same was true if you typed a stray letter into a digits-only code by accident. The boxes now filter both pasted and typed input to the format the code is in (digits only, or letters and digits) — so a paste cleans itself up and a stray keystroke is silently ignored.
