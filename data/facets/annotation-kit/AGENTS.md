# Codex instructions — facet annotation

You are acting as **one of three blind annotators** describing home IoT devices. Read this
file, then `FACET_ANNOTATION_PROMPT.md` (the rubric), then `VALUE_DEFINITIONS.md`.

## Your job

Fill the `Value`, `Confidence`, and `Reasoning` columns of **`codex.csv`** (480 rows).
Touch no other file.

- **`Value`** — exactly one entry from that row's `allowed_values` column (pipe-separated),
  or `unsure`. Copy the string exactly; a value outside the list is discarded, not corrected.
- **`Confidence`** — `High` or `Low`.
- **`Reasoning`** — one short sentence saying what about the product drove the answer.

## The hard constraint

**Judge the device from its vendor and product name only.** Do not look up, infer from, or
reason about CVE descriptions, CWE IDs, or CVSS scores for these devices — not in this repo,
not on the web. The facets are later crossed against weakness data, and a facet assigned
from CVE text would correlate that data with itself.

`cve_count` is a statistical **weight** for aggregation, not evidence. A device with 40 CVEs
is not thereby more cloud-dependent. Ignore it when choosing a value.

## Blindness

Do not open the ontology (`ontology/homeiot.ttl`), the project guide (`CLAUDE.md`), the
plans in `docs/plans/`, or the other annotators' sheets (`claude.csv`, `gemini.csv`).
Each of those states either the current facet assignment or the results this exercise
exists to test independently. Your sheet physically lacks the other columns; keep it that
way by not going looking.

**Stay in this directory.** Everything you need is here.

## `unsure` is a real answer

If the product name does not identify the device well enough to judge, answer `unsure` at
`Low` confidence. Forcing a guess manufactures fake agreement, which is worse than an
honest abstention — the abstention rate is itself a reported result. Do not use `unsure`
to avoid thinking, but do not avoid it either.

## Working through the file

Rows are **device-major**: 12 consecutive rows are the same device, one per facet. Re-read
a facet's entry in `VALUE_DEFINITIONS.md` when you reach an unfamiliar one — the definitions
are narrow and several are easy to answer from the everyday sense of the word instead of the
defined one.

That is more than one comfortable pass. Work in chunks of ~10 devices, saving as you go.
Partial progress is fine and expected — the merge only uses rows that are filled, and an
unfilled row is visibly missing rather than silently wrong.

## Do not

- Do not adjust an answer toward what a category's answer "should" be. You are describing
  **this device**, not its category. Devices that sit oddly in their category are exactly
  what this measurement is for, and smoothing them away destroys the signal.
- Do not fill a value you would not defend. Low confidence is free; a wrong High is not.
