KEYWORD ADDITIONS — Camera category
===================================

Source: mined from the 255 resolved-"Yes" rows of 03_final.csv (vendor-only camera CVEs
that NO keyword in any workbook caught, confirmed a true match by AI consensus + human
review). The recurring generic terms in those descriptions are phrasings the keyword
search is currently missing — adding them should pull these CVEs into the keyword results
on the next pass.

Brand names (Reolink — 100 rows, Foscam, Wyze, Swann, etc.) are NOT listed here: they
belong to the vendor list, not the keyword search.

Frequencies are raw description-text hits across the 255 rows — a priority guide only.


HIGH-VALUE — protocol / format markers (high precision; rarely appear in non-camera CVEs)
----------------------------------------------------------------------------------------
onvif                 (22)   -- standard IP-camera interoperability protocol; best single add
rtsp                  (8)    -- real-time streaming protocol
rtmp                  (2)
p2p camera            (1)    -- "p2p" alone is too generic; pair it

DEVICE-TYPE TERMS (not currently in the keyword workbooks)
----------------------------------------------------------
dvr                   (12)
digital video recorder
video recorder        (1)
ptz camera            (10 'ptz')  -- pan-tilt-zoom camera
webcam
cctv                  -- bare term; existing list only has "cctv camera"

ALREADY IN THE KEYWORD LIST (confirmed by this mining — no action needed)
------------------------------------------------------------------------
ip camera
network camera
surveillance camera
security camera
nvr / network video recorder

DO NOT ADD (false-precision traps)
----------------------------------
cgi (168), firmware (124), http request (182) — these are code-path / boilerplate tokens,
not device-type markers. They appear in this set only because Reolink's cgiserver bug
dominates it; adding them would flood the keyword results with unrelated CVEs.


NOTE
----
The strongest single addition is "onvif": it is the standard IP-camera interoperability
protocol, appears across many of these CVEs, and almost never shows up in unrelated
products — so it adds recall with very little false-positive cost. "rtsp" and "dvr"
behave similarly. The bulk of this Yes set is Reolink (brand-matched), so the headline
lever for cameras remains the vendor list, with onvif/rtsp/dvr/ptz as the keyword top-ups.
