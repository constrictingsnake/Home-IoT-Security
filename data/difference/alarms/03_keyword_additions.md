KEYWORD ADDITIONS — Alarms category
===================================

Source: mined from the 18 resolved-"Yes" rows of 03_final.csv (vendor-only alarm CVEs
confirmed a true match by AI consensus + human review).

The Yes rows are residential security panels and wireless alarm systems:
Qolsys IQ Panel, SimpliSafe (Original / SS3), ABUS Secvest, Abode iota Security Kit.

Brand names go to the vendor list, not the keyword search (see bottom).
Frequencies are raw hits across the 18 rows — a priority guide only.


HIGH-VALUE — device-type terms (the current keyword list has "smart alarm / home alarm /
siren" but NOT the way these CVEs actually phrase themselves)
----------------------------------------------------------------------------------------
alarm system          (9)
wireless alarm system (6 'wireless alarm')
security system            -- common consumer phrasing, currently uncaught
security panel             -- the device class (panel-based alarm); pairs with "alarm panel"
alarm panel           (1)

SECONDARY — component terms (lower precision, add only if recall is short)
-------------------------------------------------------------------------
security kit          (2)   -- e.g. "All-In-One Security Kit"
alarm keypad / keypad (3)
base station          (2)   -- alarm base station

ALREADY IN THE KEYWORD LIST (no action)
---------------------------------------
smart alarm / home alarm / siren / motion sensor / door sensor / window sensor

VENDOR-LIST ADDITIONS (brands found here — for Jason's vendor search, not keywords)
----------------------------------------------------------------------------------
Qolsys (IQ Panel / IQ4 Hub), SimpliSafe, ABUS (Secvest), Abode


NOTE
----
"alarm system" and "wireless alarm system" are the high-confidence adds — they are how
residential alarm CVEs are routinely described and rarely collide with non-home products.
"security system" / "security panel" widen recall but carry more noise (also match
enterprise/industrial security), so flag them for a precision check on the next pass.
