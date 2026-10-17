# Plan — Paper submission fixes (`home_iot_security_report.tex` re-sync + bibliography verification)

## Current status (2026-09-05) — PHASE 1 COMPLETE; Phases 2–5 outstanding

**Phase 1 executed 2026-09-05.** Every §III number was recomputed from
`judgment_store.csv` / `nvd_all.csv` / `cwe888_cve_map.csv` / `term_precision.csv` at edit
time rather than copied from the tables below; all but three matched the plan exactly.
The three deviations, all resolved in favour of the measurement:

1. **§1.4 CWE-888 split** — plan said 115 one-class / 105 span and 181 (11.2%) overall;
   measured **123 / 97** and **173 (10.7%)**. The plan's variant counts an assignment as
   "spanning two classes" when one of its CWEs is *unmapped* (50 rows have empty
   `cwe888_classes`), which is not what the prose claims. The union definition is also
   internally consistent (76 + 97 = 173); the plan's is not, the same arithmetic flaw the
   stale text had (90 + 112 ≠ 182).
2. **§1.6 term split** — plan said 14 vendor / 6 keyword; measured **15 vendor / 5
   keyword rows over 19 distinct terms** (`smart display` is registered as both a vendor
   and a keyword term, so it occupies two of the 20 rows). The five keyword prune
   candidates the plan names are correct.
3. **§1.2 exclusion wording** — "nearly all in `streaming`" is understated: **all 2,015**
   excluded rows are `streaming`.

Two things Phase 5's acceptance checks should absorb:

- **The Phase 5 grep in step 2 is defective and will report a false all-clear.** Numbers
  in the tex are written `6{,}535`, but `6[,{]535` matches only `6,535`/`6{535`. Use a
  brace-aware pattern, e.g. `6\{?,?\}?535`. Under the corrected pattern the only stale
  Phase-1 hit remaining is the §V-B sentence at ~line 994, which is Phase 2.1's to fix.
- Phase 1 also rewrote the per-category FP narrative (1.5) and added the §III→RQ1
  reconciliation bridge, so RQ1's 1,738/1,676 no longer appear from nowhere.

Phase 1 was verified by brace-balance and label-resolution checks only. **Phase 5.1 is now
done: the paper compiles** (2026-09-14, `tectonic` 0.17.0, 19 pages, 0 errors, 0 undefined
references, 0 undefined citations, 0 overfull boxes) — see Phase 5.1 below for what the build
caught that the static checks could not.

---

## Original status — DRAFTED, ready to execute

This plan turns the 2026-09-05 full-repo audit into an ordered fix list for submitting the paper.
It is the paper-side half that `PLAN_scope_exclusion.md` §"Downstream cascade" called for
("do the tvOS regeneration and the number re-sync together, once") — the data-side regeneration
happened (store, CWE-888 artifacts, CVSS artifacts are all current), **the paper re-sync never did**.

**The data layer needs no work.** Verified 2026-09-05: all four ontology gates green
(`--check` 31/31 + byte-identical CSVs, `--self-test` all 5 criteria load-bearing, `--sources`,
`--verify-kg` 1,738/1,904 reconciling); judgment store fully settled (8,124 rows, 0 unresolved);
`n_scored == n_cves` everywhere. Do **not** re-run searches, reviews, or the ontology build for
this plan. The paper's RQ1 tables are already byte-identical to the generated files — only the
"22 non-empty" wording changes there (§2.1).

Two dataset vintages are mixed in the paper today: §III (methodology) + RQ2 are written against
the pre-rebuild / pre-tvOS-exclusion state (6,535 rows, snapshot 2026-06-25/360,981), while RQ1
is current (1,738 / 1,676 / 1,904, snapshot 2026-08-05/373,518). **Decision taken by this plan:
pin everything to the current (2026-08-05) vintage**, since RQ1's inlined tables, the KG, and
every tracked derived CSV already are.

Execution order = phase order below. Phases 1–3 are mechanical (no author judgment beyond
wording); Phase 4 contains the open decision points; Phase 5 is verification.

---

## Phase 1 — Re-sync §III (Methodology) to the current store and snapshot

Every replacement value below was measured 2026-09-05 directly from
`data/difference/judgment_store.csv` (8,124 rows) and `data/nvd-snapshot/nvd_all.csv`
(2026-08-05, 373,518 records). Where a value should be recomputed rather than hand-typed,
the source file/script is named — prefer recomputing at edit time.

### 1.1 Snapshot date and size (three places)

| tex location | stale | replace with |
|---|---|---|
| §III-B (~line 248) | "on 2026-06-25, for a total of 360,981 unique CVE records" | 2026-08-05, 373,518 |
| §III-B (~line 309) and §V-C (~line 992) | "as of 2026-06-25" | as of 2026-08-05 |
| Data Availability (~line 1128) | "360,981 CVE records … as of 2026-06-25" | 373,518 … 2026-08-05 |

Source of truth: `data/nvd-snapshot/SNAPSHOT.md` (auto-written by `download_nvd.py`).

### 1.2 Candidate counts and the §III↔RQ1 bridge (~lines 309–326)

Stale: "6,535 candidate pairs … 3,413 confirmed … form the analysis set … 3,121 rejected
(one row remained unresolved)". Also the provenance split 3,069/802/588/2,076.

Replace with the current numbers **and add the missing reconciliation** — the paper currently
never explains how §III's confirmed count becomes RQ1's 1,738. Target framing:

> 8,124 candidate (category, CVE) pairs entered review (4,241 vendor-only, 1,049 keyword-only,
> 766 intersection, 2,068 CPE-expansion). 3,753 settled as true matches and 4,371 as false
> positives, with no rows outstanding. Applying the tvOS scope exclusion (§III-A) removes 2,015
> of the true matches — nearly all in `streaming` — leaving **1,738 confirmed CVE–category
> assignments over 1,676 distinct CVEs as the analysis set**.

This makes the tvOS paragraph (already present, ~line 319) carry its quantitative consequence,
and RQ1's opening numbers stop appearing from nowhere. The intersection direction must also be
added to §III-E's union sentence (see 1.5).

### 1.3 §III-C CWE/CVSS extraction (~lines 344–365)

| stale | replace with (measured over the 1,676-CVE analysis set) |
|---|---|
| "Of the 3,413 confirmed home IoT CVEs, 633 carried no usable CWE" | 118 of 1,676 (7.0%) |
| "remaining 2,780 CVEs … 289 unique CWE identifiers" | remaining 1,558 CVEs … 155 unique CWEs |
| "2,284 v3.1, 804 v3.0, 272 v2.0, 53 no CVSS score" | 1,211 v3.1 · 330 v3.0 · 81 v2.0-only · **54 v4.0** · 0 unscored (per distinct CVE) |
| "The corpus mixes both CVSS v2 and v3.x scores" | mixes v2, v3.x, **and v4.0** |

Two content changes ride along:
- **CVSS v4.0 must be described.** 54 CVEs are scored only under v4.0 (the `cvssMetricV40`
  parser fix — `docs/RESULTS.md` §"NVD snapshot refresh"). Before writing the
  version-preference sentence, read the actual preference order out of
  `scripts/download_nvd.py` and state that order — do not guess it.
- **Drop the unscored caveat, add the coverage claim**: score and vector coverage are now
  100% (1,676/1,676). "predominantly recent CVEs awaiting NVD enrichment" is obsolete.

### 1.4 §III-D CWE-888 over-counting stats (~lines 384–392)

The `% NUMBERS PROVISIONAL` comment at line 384 flagged exactly this. Replace and then delete
the comment:

| stale | replace with (denominator: 1,613 assignments with ≥1 mapped CWE, from `cwe888_cve_map.csv`) |
|---|---|
| 90 (3.0%) single CWE → two classes | 76 (4.7%) |
| 225 (7.6%) with ≥2 CWEs; 113 one class / 112 span | 220 (13.6%); 115 / 105 |
| 182 CVEs (6.1%) contribute to >1 class | 181 (11.2%) |

Note the unit while editing: these are per (category, CVE) *assignments*, and the shares roughly
doubled versus the stale text — "bounded in practice" still holds but the prose should not
promise "6%" anywhere.

### 1.5 §III-E false-positive review (~lines 428–468)

- Union sentence: "unions the vendor-only, keyword-only, and CPE-expansion directions" →
  add **intersection** (766 rows; it is a fourth reviewed direction, per CLAUDE.md Stage 3).
- "every row was judged independently and blind by five reviewers" → overstates the humans.
  Rephrase: three AI reviewers judged every row blind; the two human reviewers blind-adjudicated
  the flagged rows.
- Aggregates: 6,535 → 8,124; 3,413 (52.2%) / 3,121 (47.8%) → 3,753 (46.2%) / 4,371 (**53.8%**);
  "single row still outstanding" → review complete, none outstanding.
- Pairwise agreement: 87.4 / 88.1 / 85.2, unanimity 81.5% → **87.0 (Claude–Codex) /
  86.3 (Claude–Gemini) / 85.2 (Codex–Gemini), unanimity 80.3%** (recompute at edit time from
  the store; simple equality over non-blank judgment pairs).
- Final labels: 5,302 / 1,226 / 6 → **6,467 ai-consensus / 1,638 human / 19 strong-consensus**.
  The "976 were flagged" figure has no current counterpart in the store — either recompute it
  from the per-category `02_needs_human_review.csv` files or (simpler, recommended) drop the
  flagged-count sentence and let the 1,638 human-settled figure carry the point.
- The 99.7% (293/294) relaxation-validation figure is a one-time historical validation —
  **keep as is**.
- **Per-category FP narrative must be rewritten, not just renumbered.** Current rates
  (No/total, from the store): highest — sleeptracker 100% (n=29), airconditioner 96.2% (n=133),
  thermostat 80.0%, babymonitor 78.0%, cameras 77.6% (n=3,950); lowest with non-trivial n —
  home-power 13.5%, streaming 14.3% (n=2,440), garden 29.6%, hub 30.0%. Two prose claims break:
  smart speakers is no longer a low-FP example (now **62.0%**, driven by a 48-row
  `smart display` false-positive bomb — worth one sentence, it is a good illustration of the
  term-precision loop), and sensors/ev-charging dropped out of the "highest" tier.

### 1.6 §III-F term precision (~lines 481–489) and §V-B echo (~line 960)

- "343 distinct terms … 10 crossed this threshold" → **426 terms … 20 prune candidates**
  (`data/difference/term_precision.csv`). Same fix in §V-B ("10 of 343").
- "Almost all are vendor terms" is now false: 14 vendor / 6 keyword. The keyword prune
  candidates (`smart display`, `home hub`, `evse`, `charge point`, `weather station`) deserve
  the mention — they show the loop prunes both lists, which strengthens the section.
- Surviving examples verified still true, keep: `synology surveillance station` /
  `geutebruck` / `digital watchdog` at 0.0 over 7–25 rows; `d-link` at 0.044 over 1,802.

---

## Phase 2 — Fix wrong/contradictory claims in otherwise-current sections

### 2.1 RQ1 (three wording fixes, tables untouched)

- "22 non-empty CWE-888 primary classes" (~line 496) → **21** (`Malware` has zero attributions;
  verified in `cwe888_distribution.csv`). Optionally also regenerate the tables without the
  all-blank `Malware` column, or leave the column and just fix the prose.
- Treemap selection (~line 502): "the four categories with the most confirmed CVEs … the only
  categories above N=75" is false by CVE count (streaming 76 > 75; ev-charging 71). The cutoff
  is by **CWE attributions** (996/282/86/85; next largest 61) — say "most CWE attributions"
  and "N > 75 attributions", matching `generate_cwe888_treemaps.py`'s own header comment.
- §V-B completeness sentence (~line 968): "effectively complete: all 6,535 reviewed rows carry
  a settled label, with a single row still outstanding" is self-contradictory and stale →
  "complete: all 8,124 reviewed rows carry a settled label."

### 2.2 §V-D facet-validity wording (~line 1048)

"86 of 120 measured cells (72%) clear 0.80, and 12 fall below 0.60" conflates modal-share bands
with verdicts (product-weighted shares: 82 ≥ 0.80, 13 < 0.60; the 86/12 are the
`summary-defensible` / `NOT-USABLE` **verdict** counts, which combine both weightings).
Rephrase in verdict terms: "86 of 120 measured cells received a *defensible* verdict, 22
*grouping-only*, and 12 *not usable*" (`data/facets/facet_distribution.csv`). Mirror the same
wording in CLAUDE.md's Phase-A paragraph if touched.

### 2.3 Data Availability

- `results_all_<category>.xlsx` → `.csv` (what the repo actually contains).
- Resolve the two `\stub`s (repository URL/DOI; access-restrictions statement).

---

## Phase 3 — Bibliography verification pass (every entry, no exceptions)

Audit result: **5 of 5 spot-checked suspicious entries were wrong** — drafted-from-memory
author lists, the exact failure mode `study_sources.tsv`'s header warns about. The five
confirmed corrections (web-verified 2026-09-05):

| key | fix |
|---|---|
| `alsubaei2018` | Authors are **B. Ali and A. I. Awad** (Sensors 18(3):817, 2018, DOI 10.3390/s18030817). Rename key to `ali2018` to match the manifest; fix the prose "Alsubaei et al." |
| `kumar2019` | Authors are **D. Kumar, K. Shen, B. Case, D. Garg, G. Alperovich, D. Kuznetsov, R. Gupta, Z. Durumeric** (USENIX Security 2019). Listed Sorber/Lau/Snoeren/Feamster are fabricated |
| `sanders2017` | Paper is by **J. Dahmen, D. J. Cook, X. Wang, W. Honglei**, *J. Reliable Intelligent Environments* 3:83–98, 2017 — authors **and** venue wrong ("Buildings 7(3):55"). Rename key; fix prose "Sanders et al." |
| `apthorpe2019` | "Privacy and Security in Internet-Connected Cameras" (ICIOT 2019) is by **J. Valente, K. Koneru, A. A. Cárdenas**. Rename key; fix both prose mentions of "Apthorpe et al." (§II-C twice — the baby-monitor sentence and the sleep-monitor sentence, where `apthorpe2017` may stand alone) |
| `jacobsson2018` | First author is **J. Bugeja** (Bugeja, Jonsson, Jacobsson, PerCom Workshops 2018, pp. 537–542). Cite as Bugeja et al.; fix prose "Jacobsson performs…" |

Remaining work, same pass:
1. `firmrec2024` — resolve the `\stub[verify title/authors]` or drop the citation.
2. `taxonomyci2023`, `voicecontrol2022`, `iotflow2023` — no authors at all; complete or drop.
3. **Verify every other entry against the actual paper** (title, authors, venue, year, pages).
   The five above prove memory-drafting contaminated the list; nothing is trusted until checked.
4. Sync `ontology/study_sources.tsv`: flip `verified=no → yes` (with corrected metadata) for
   each of the 7 unconfirmed manifest entries as it is checked — this also clears the
   `--sources` gate warning. The manifest check only proves a key is registered, never that its
   metadata is right; this pass is the human check it defers to.

---

## Phase 4 — RQ2 regeneration + structural decisions (author input needed)

### 4.1 RQ2 — regenerate wholesale (mechanical part)

The entire section (table + prose) is pre-tvOS-exclusion; its findings are not just stale but
**inverted**. Regenerate from `cvss_analysis.py` outputs (`cvss_distribution.csv`,
`cvss_severity.csv`, `cvss_matrix.md`, `cvss_dunn_pairwise.csv`) and rewrite the prose around
the current result:

- **`hub` is now the dominant high-severity category**: median 9.8, mean 8.73, Critical share
  53.4% (132/247) — not `alarms` (median 8.8, mean 8.06). Twelve of the thirteen significant
  Dunn pairs involve hub scoring higher; the paper's reported significant pairs (streaming
  lower than alarms/hub/cameras; alarms higher than robotvacuum/cameras) mostly no longer exist
  (only alarms–robotvacuum survives).
- Omnibus: **17** categories with ≥5 scored CVEs (airconditioner now qualifies), KW
  **H = 169.820, df = 16, p = 9.1×10⁻²⁸**; 5 excluded below n=5 (fans, fridge, sensors,
  airpurifier, appliances) — the paper's "16 categories / H=77.454 / df=15 / four excluded"
  all change, as does "120 pairwise comparisons" → **136**.
- "streaming — by far the largest category by CVE count (n=2,081)" must go; streaming is now
  n=76. The old table's biggest tell (`streaming` 2,081 contradicting the paper's own tvOS
  exclusion) disappears with the regeneration.
- Table regeneration: rebuild `tab:cvss-summary` from `cvss_matrix.md`'s table (all 22
  populated categories — the old table silently omitted `fans` and `airpurifier`), keeping the
  $\dagger$ convention for the 5 sub-threshold categories.
- The hub-concentration caveat from `docs/RESULTS.md` should be imported: `hub` is ~45%
  single-vendor (Insteon), so hedge the hub-dominance sentence accordingly (same discipline the
  RQ3 scope-changed figure gets).

### 4.2 Open decisions (do not decide silently — confirm with authors)

1. **v2/v3.x/v4 pooling in the Kruskal–Wallis.** 81 v2-only scores are pooled with v3.x/v4 and
   v2 skews low (`cvss_matrix.md` caveat). `--score-versions 3` exists. Decide: pool (status
   quo, footnote the confound) or report the v3-only sensitivity in a sentence. Recommendation:
   footnote + one sensitivity sentence.
2. **Add RQ3 (CVSS vector distributions)?** The analysis is done and blocked on nothing
   (100% vector coverage; pooled AV:N 73%, Scope-Changed 17%, C+I+A 56% — `cvss_vector_matrix.md`).
   The paper currently has no RQ3 section. Recommendation: include — it is finished work and
   mirrors the transportation study's depth.
3. **Report the recall estimate in §V-C (external validity).** Pooled 2-source raw recall
   ≈0.60 (upper bound; `recall_estimate.csv`, with the CLAUDE.md §Stage-6 caveats). The
   machinery exists and answers the obvious reviewer question; the `yes`-population recall is
   not paper-grade, but the raw figure is defensible. Recommendation: one paragraph + caveats.
4. **Double-blind check.** §III-E names both human reviewers, and one is
   "Suhani~\stub[last name]". If the venue is double-blind, anonymize; either way resolve the
   stub and the author-block placeholder.
5. **Empty sections**: Abstract, Keywords, Introduction, Lessons Learned, Conclusions — author
   writing, gated on Phases 1–4 so the numbers they cite are final.

### 4.3 LaTeX mechanics

- `\label{sec:conclusion:data-availability}` sits on a **starred** section, so
  `\ref` (used in RQ2, ~line 833) prints the *previous numbered* section's number. Fix: un-star
  the section, or reference it by name/`\hyperref`.
- Remove the `% NUMBERS PROVISIONAL` comment (1.4) and the two `BEGIN GENERATED` blocks'
  refresh notes stay as-is (they are correct process documentation).

---

## Phase 5 — Compile + verification (acceptance checks)

1. ✅ **DONE 2026-09-14 — the paper compiles.** Toolchain installed with `brew install tectonic`
   (formula, no sudo, fetches packages on demand — the cask route needs an interactive sudo and
   was not usable here). Build command:

   ```bash
   cd docs && tectonic -X compile home_iot_security_report.tex --outdir <build> --keep-logs
   ```

   Result: **19 pages, 0 errors, 0 undefined references, 0 undefined citations, 0 overfull
   boxes**, 59 bibitems all cited. `brew install poppler` was added to render pages for visual
   inspection (`pdftoppm`/`pdftotext`).

   **Four defects the build caught that brace-balance and label-resolution could not:**
   - a bare `\paragraph` under `\section` is lettered by IEEEtran, so §III's lead-in rendered
     as "a)" before III-A → `\paragraph*`;
   - a cross-reference that *resolved cleanly to the wrong subsection* after the restructure
     (review pointed at III-C for the tvOS exclusion, which had moved into III-D);
   - a "described below" that had become a forward reference across two subsections;
   - `tab:facet-kappa` overflowing its column by 1.9pt → `\tabcolsep` 4pt.

   ⚠️ **Still worth one `pdflatex` run before submission.** `tectonic` is XeTeX-based while the
   paper's header documents pdflatex; the 52 remaining warnings are all `TU/ptm` font-shape
   substitutions (XeTeX asking IEEEtran for Times in Unicode encoding) and would not occur under
   pdflatex. As a hedge, all literal em-dashes were converted to `---`: no non-ASCII now remains
   outside `%` comments, so the file needs no `inputenc`/`fontspec`.

   Visual check done on the rendered pages: the §III numbered list, all four stage-titled
   subsections, and `tab:facet-kappa` all typeset correctly. Two `\stub` markers still render as
   red brackets — deliberate, see Phase 5 item 3 / the outline's item 3.
2. **Stale-number grep must come back empty** over the tex:
   `grep -nE '6[,{]535|3[,{]413|3[,{]121|360[,{]981|2026-06-25|343 distinct|976 were|2[,{]081|H=77|df=15|df~=~15' docs/home_iot_security_report.tex`
3. **Cross-check script** (run, don't trust the edit): recompute from
   `judgment_store.csv` — total rows 8,124; Yes 3,753; excluded-Yes 2,015; analysis 1,738/1,676;
   agreement 87.0/86.3/85.2/80.3 — and diff each against the tex. The audit scripts from
   2026-09-05 are reproducible one-liners; consider dropping the store cross-check into
   `scripts/` as `paper_number_check.py` so the next vintage bump can't silently desync again
   (this plan exists because the previous one did).
4. **All four ontology gates stay green** (`--check`, `--self-test`, `--sources` — which after
   Phase 3 should report 10/10 verified — `--verify-kg`).
5. **Public-release hygiene** (only before the repo URL goes into Data Availability):
   remove `Onboarding-Docs/` (four tracked third-party copyrighted PDFs) from the public
   artifact — `git rm` on a release branch or filter from the archive; decide whether root-level
   `Design.pdf` / `Devices List.docx` ship. `.env` is confirmed ignored and unleaked;
   `.claude/settings.local.json` untracked.

---

## Explicitly out of scope for this plan

- Any re-run of searches, reviews, CPE expansion, or mining — the data layer is verified current.
- The RQ1 tables/treemaps (already in sync; only the two prose fixes in §2.1).
- The κ table (verified exact against `facet_agreement.csv`).
- The F4 cameras device-subtype pass and the other open items in `PLAN_facet_system_fixes.md`.
