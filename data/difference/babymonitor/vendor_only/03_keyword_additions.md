KEYWORD ADDITIONS — Baby monitor category
=========================================

Source: mined from the 8 resolved-"Yes" rows of 03_final.csv (vendor-only CVEs confirmed a
true match by AI consensus + human review).

NET KEYWORD ADDITIONS: none.

Why: all 8 Yes rows are generic IP cameras pulled in by an over-broad vendor list —
D-Link DCS-825L / DCS-700L, Motorola MBP853, Luvion Grand Elite 3 Connect. None of them
even contain the phrase "baby monitor"; they are camera CVEs. The generic terms that would
catch them ("ip camera", "network camera") already exist in the camera workbook, and
"baby monitor" is already a keyword.

This is the documented babymonitor contamination (the difference set is ~95% generic IP
cameras). The fix is NOT a keyword — it is tightening the babymonitor VENDOR list so generic
D-Link DCS surveillance cameras stop being attributed to this category.

VENDOR-LIST ACTION (not keyword search)
---------------------------------------
- D-Link DCS-825L / DCS-700L: generic IP cameras — remove from the babymonitor vendor list
  (keep only genuine baby-monitor models if any).
- Motorola MBP-series, Luvion Grand Elite: these ARE baby monitors — keep, but they are
  already brand-matched.


NOTE
----
Zero keyword yield here is itself the finding: the category's recall problem is a vendor-list
precision problem. Defer any keyword work until the vendor list is tightened (per Open
scoping note — babymonitor needs vendor-list cleanup).
