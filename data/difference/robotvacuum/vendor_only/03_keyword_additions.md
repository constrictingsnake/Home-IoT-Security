KEYWORD ADDITIONS — Robot vacuum category
=========================================

Source: mined from the 14 resolved-"Yes" rows of 03_final.csv (vendor-only CVEs confirmed
a true match by AI consensus + human review).

The Yes rows are Neato Botvac vacuums, ECOVACS Deebot vacuums, SwitchBot — AND, notably,
ECOVACS **robot lawnmowers**. The existing keywords "robot vacuum" / "robot cleaner"
already cover the vacuums (these rows are brand-matched and mostly don't repeat the device
phrase). The actionable yield is a cross-category leak, not a vacuum keyword.

Brand names go to the vendor list, not the keyword search.


CROSS-CATEGORY — belongs in the `garden` keyword set (robotic lawn care)
-----------------------------------------------------------------------
robot lawnmower / robotic lawnmower
robot mower / lawn mower            (mower 3, lawnmower 3)

These surfaced under robotvacuum only because ECOVACS makes both; route them to `garden`
when that category is built (per Finalized Category Scope, garden = irrigation + mowers).

VACUUM keyword additions
------------------------
(none) — "robot vacuum" / "robot cleaner" already capture the device class; the Yes rows
add no new vacuum-specific phrasing.

VENDOR-LIST ADDITIONS (brands found here — for Jason's vendor search)
--------------------------------------------------------------------
Neato (Botvac), ECOVACS (Deebot — vacuums; also lawnmowers → garden), SwitchBot


NOTE
----
Net keyword yield for robotvacuum itself is zero — the category is already well-served by
its two keywords. The real takeaway is that robot-lawnmower CVEs are entering through the
vacuum vendor list; capture them properly with `garden` keywords (robot mower / robotic
lawnmower) rather than leaving them mislabeled here.
