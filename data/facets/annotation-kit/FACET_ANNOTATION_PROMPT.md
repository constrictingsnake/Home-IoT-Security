# Facet Annotation Rubric (shared by all annotators)

This is the **single source of truth** every facet annotator follows — Claude, Codex, and
Gemini. Annotate identically so agreement between annotators means something.

It is the Phase A / Phase 2 counterpart to
[`CLASSIFICATION_PROMPT.md`](../difference/CLASSIFICATION_PROMPT.md), which governs CVE
scope judgments. **That rubric judges whether a CVE belongs to a category. This one
describes a device.** They share nothing but their structure — do not carry rules across.

## Your task

You are given one **device** (vendor and product name) and one **facet**. Choose exactly
one value from that facet's closed list, or `unsure`.

The value definitions are in [`VALUE_DEFINITIONS.md`](VALUE_DEFINITIONS.md), generated
directly from the ontology. Read the facet's entry before answering it the first time.

## The hard constraint — judge the DEVICE, never a CVE

You are describing a product, not a vulnerability.

- Use the **vendor and product name**, and what you know about that product or its class.
- You will **not** be given CVE descriptions, CWE identifiers, or CVSS vectors, and you must
  not go looking for them.
- The `cve_count` column is a statistical **weight** used when the answers are aggregated.
  It is not evidence about the device. A device with 40 CVEs is not thereby more
  cloud-dependent or more likely to have a web admin UI. **Ignore it when choosing a value.**

**Why this matters more than it looks.** These facets are later crossed against the
weakness classes (CWE) of the same devices' CVEs. If a facet value were inferred from CVE
text, that contrast would be correlating the text with itself and every result built on it
would be circular. This is not hypothetical: `facet_derive.py` attempted exactly that, and
two published contrasts stand retracted because of it. Keeping your judgment on the product
side of that line is what makes the whole exercise worth running.

## Blind-annotation principle (non-negotiable)

- Annotate using **only** the device identity and the value definitions.
- **Never** look for, reference, or be influenced by another annotator's answer.
- **Never** look up the ontology's current value for this facet. The existing assignments
  were made by one author in one pass with no source; reproducing them is precisely what
  this exercise is designed to avoid. If you already know a prior value, set it aside — an
  answer that echoes the prior is worth less than an honest `unsure`.

## Choosing a value

- **One value per row.** These are the single-valued facets; the multi-valued ones are not
  part of this pass.
- **Answer for the product named, not for its category.** You may be given a device that
  sits oddly in its category — answer for the device in front of you. Do not adjust toward
  what you think the category's answer should be; the whole point is to find out whether
  categories are internally consistent, and smoothing your answers toward the category
  destroys the measurement.
- **`unsure` is a real answer, and you should use it.** Use it when the product name does
  not identify the device well enough to judge, or when the facet genuinely does not apply.
  Forcing a guess manufactures fake agreement. Per-facet `unsure` rates are reported as a
  reliability signal in their own right, so an honest abstention is informative output, not
  a gap.
- **How `unsure` is scored:** as an additional value, not as a missing answer. It therefore
  lowers measured agreement, which is the conservative and honest direction — an annotator
  who cannot assign a value has not agreed with one who can.

## Confidence

Record `High` or `Low` for every row.

- **High** — you recognise this product or its class and the value follows from what it is.
- **Low** — you are inferring from a generic name, or the definition's boundary is unclear
  for this device.

Confidence is used for flagging, not for weighting: rows where two annotators are both Low,
or where annotators disagree, route to human adjudication.

## Reasoning

One short line: what about the product drove the value. Enough that a human adjudicating a
disagreement can see where the two annotators diverged. Do not pad it.

## Worked examples

| device | facet | value | confidence | reasoning |
|---|---|---|---|---|
| `simplisafe:ss3` | `credentialModel` | `AccountLinked` | High | Consumer alarm panel; setup binds to a SimpliSafe account. |
| `tp-link:smart_plug` | `computeTier` | `unsure` | Low | Generic name, no model — TP-Link plugs span MCU and Linux designs. |
| `abb:terra_ac_wallbox_80a` | `consumerAvailability` | `InstallerChannel` | High | Hardwired 80A AC wallbox; commissioned by an electrician. |
| `amazon:echo` | `hasWebAdminUI` | `false` | High | Administered entirely through the Alexa app; no LAN HTTP admin surface. |

Note the second row. `unsure` at Low confidence is the correct answer there — a guess
between `McuClass` and `EmbeddedLinux` would be noise entering the distribution as signal.
