KEYWORD ADDITIONS — Doorbell category
=====================================

Source: mined from the 20 resolved-"Yes" rows of 03_final.csv (vendor-only doorbell CVEs
confirmed a true match by AI consensus + human review).

KEY FINDING: the current keyword list only has "video doorbell" / "smart doorbell", but
every Yes row here is a **video door intercom / entrance panel / wallpad** — an entire
device class the keyword search is blind to. The brands (Akuvox E11/C315, Fermax outdoor
panel, Comelit, COMMAX WallPad, Aiphone entrance station) are intercom makers. The literal
intercom terms appear in only a few of THESE descriptions (the rows were brand-matched),
but adding them generalizes the keyword search to catch the whole intercom class that is
currently invisible to it.

Brand names go to the vendor list, not the keyword search (see bottom).


HIGH-VALUE — device-type terms (the missing intercom class)
-----------------------------------------------------------
intercom
video intercom
door intercom
door station
entrance station / entrance panel   (1 'entrance station', 1 'outdoor panel')
door phone / video door phone
wallpad / wall pad                  (1)   -- in-home answering panel (COMMAX WallPad)
door entry

SECONDARY (lower precision)
---------------------------
access control        (4)   -- broad; matches enterprise badge systems too — precision-check
sip                   (2)   -- VoIP-doorbell signalling; pair with a device word, never alone

ALREADY IN THE KEYWORD LIST (no action)
---------------------------------------
video doorbell / smart doorbell

VENDOR-LIST ADDITIONS (brands found here — for Jason's vendor search)
--------------------------------------------------------------------
Akuvox, Fermax, Comelit, COMMAX, Aiphone


NOTE
----
"intercom" / "video intercom" / "door station" are the high-value adds: doorbells and
door intercoms are the same residential device class, and the keyword search presently
recovers none of them by phrasing. Avoid "access control" and bare "sip" as standalone
keywords — both pull heavy enterprise/VoIP noise.
