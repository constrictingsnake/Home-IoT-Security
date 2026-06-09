KEYWORD ADDITIONS — Step 1 (Camera category)
=============================================

Source: mined from the "Yes" rows of difference_step_1 (the 264 vendor-only camera
CVEs that NO keyword in any workbook caught). The recurring generic terms in those
descriptions are the phrasings the keyword search is currently missing — adding them
should pull these CVEs into the keyword results on the next pass.

Brand names found in these rows (Foscam, Opticam, Wyze, Swann, etc.) are NOT listed
here — those belong to the vendor list, not the keyword search.

Frequencies are from the 264-row description text and are a priority guide only.


HIGH-VALUE — protocol / format markers (high precision; rarely appear in non-camera CVEs)
----------------------------------------------------------------------------------------
onvif                 (31)
rtsp                  (6)
p2p camera

DEVICE-TYPE TERMS (not currently in the keyword workbooks)
----------------------------------------------------------
dvr                   (18)
digital video recorder
video recorder        (4)
webcam                (2)
ptz camera            (2)
cctv                  (8)   -- bare term; existing list only has "cctv camera"
hd camera             (23)
indoor camera         (5)
multi-camera          (4)
ip cam
wifi cam

ALREADY IN THE KEYWORD LIST (confirmed by this mining — no action needed)
------------------------------------------------------------------------
ip camera
network camera
nvr
wifi camera


NOTE
----
The strongest single addition is "onvif": it is the standard IP-camera interoperability
protocol, appears across many of these CVEs, and almost never shows up in unrelated
products — so it adds recall with very little false-positive cost. "rtsp" and "dvr"
behave similarly.
