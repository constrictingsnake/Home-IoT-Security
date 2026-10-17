# Review: our paper vs. Rezaei et al. (LLIoT, EuroS&P 2026)

**Compared:** `docs/home_iot_security_report.tex` (working draft, 2026-10) against Rezaei, Bayhan,
Continella, van der Ham-de Vos, van Rijswijk-Deij, *"SoK: Understanding the state of IoT-specific
vulnerabilities via CVE characterization with LLIoT"* (PDF dated 2026-05-25, 22 pp.), **plus their
released artifact** (`github.com/Tina-Rezaei/LLIoT`: prompts v1–v20, the 211,182-row label table
from `initdb/lliot_dump.sql.gz`, batch config) and the **CISA KEV catalog** (downloaded
2026-10-13, 1,740 entries).

Every number below marked **[measured]** was computed for this review by joining
`data/difference/judgment_store.csv` and `data/nvd-snapshot/nvd_all.csv` (2026-08-05) against
LLIoT's released labels and KEV. The join script is
`<scratchpad>/compare.py` — not committed; see §9 for whether to promote it.

---

## 0. Bottom line — the ten things that matter most

1. **LLIoT independently agrees with 97.2% of our confirmed set.** Of our 1,265 confirmed CVEs that
   both datasets cover (2013–2024), O3 under LLIoT's prompt called 1,229 IoT. Different model
   family, different prompt, different design. That is the strongest **external precision check**
   we have, and it costs one paragraph. **[measured]**
2. **The 36 disagreements expose a bug in our tvOS exclusion.** 32 of them are `streaming`
   Apple CVEs. They carry the **legacy CPE `apple:apple_tv`**, not `apple:tvos`. The exclusion
   matches only `tvos`, so **33 of the 76 streaming CVEs that survive it (43%) are Apple
   multi-OS CVEs** — 31 co-list iOS or macOS. The exclusion was written to remove exactly these.
   Every `streaming` number in RQ1/RQ2 (Memory Access 36%, n=76, 14.5% Critical) is
   contaminated. **[measured]**
3. **We have no exploitation axis, and LLIoT does (§6.4).** In CISA KEV, our confirmed set is
   **10/1,676 = 0.60%** against an NVD baseline of 0.45%. That gap is **not significant**
   (p≈0.23, Poisson). All 10 hits are `cameras`. `hub` has the highest CVSS but **0 of 247** in
   KEV, and that severity/exploitation mismatch is publishable. **[measured]**
4. **The tvOS exclusion removes 37 KEV-listed CVEs** — more than our entire confirmed set holds
   (10). The paper has to say that the exclusion drops the most-exploited slice of `streaming`.
   **[measured]**
5. **Our KEV-listed rejections include a labeling inconsistency.** CVE-2021-33044 and
   CVE-2021-33045 are Dahua auth bypasses with **identical descriptions**. 33044 settled `Yes`
   (AI consensus). 33045 settled `No` (two humans). 33045 is in CISA KEV. **[measured]**
6. **LLIoT's labels give a named recall-gap list, which capture–recapture cannot.** LLIoT tags
   4,134 CVEs as consumer IoT. Our searches surfaced only 1,455 of them (35%). 801 of the
   never-surfaced ones carry a home-ish LLIoT category. **The root cause is visible in the
   artifact:** our vendor terms are over-qualified (`smartthings hub`, `home assistant yellow`).
   That makes the SmartThings app (10 CVEs) and the Home Assistant platform (6) unreachable,
   even though our own rubric says companion apps are in scope. Some brands are missing outright:
   Gogogate/ismartgate 11, Osram Lightify 9, Chamberlain myQ, Qrio, Linkplay, Buffalo, Lenovo
   Smart Camera, Luvion. **[measured]**
7. **A category-routing gap.** At least 10 consumer camera CVEs were judged `No` under the wrong
   category and never reviewed under the right one. Examples: Kerui Tuya camera under
   `airconditioner`, Alarm.com ADC-V522IR camera under `alarms`/`thermostat`, Yale WIPC-301W under
   `doorlock`, Blink Sync Module under `sensors`. Per-category review has no "wrong category,
   re-route" outcome. **[measured]**
8. **Our rubric changed during or after AI collection.** Per git: the 4(b) home-control clause
   and per-category scope notes landed **2026-07-02**, and the companion-app rule **2026-07-05**.
   AI judgments were collected 06-01–07-02 (Codex finished 06-30). The paper says all three
   reviewers apply "one shared rubric and one shared per-category scope note". As written, that
   is not supportable. LLIoT pins one prompt version (v20). **Verify whether the text existed
   before it was committed**; if it did not, disclose this.
9. **Our related-work paragraph on LLIoT has three factual slips** (§3.2). It also omits about 10
   papers their SoK made canonical. A reviewer who knows LLIoT will check this paragraph first.
10. **Their human adjudication is not blind to the LLM, and neither is ours.** Their 44
    human–LLM conflicts were settled by one tie-breaker who saw the LLM reasoning. That is how O3
    rose from 94.67% to 99.31%. Our human queue ships all three AI columns
    (`human_review_queue.csv`). Our paper's "blind-adjudicated" must say "blind to each other,
    not to the AI judgments". We should not attack their non-blindness while ours has the same
    property.

---

## 1. Side-by-side comparison

| Dimension | LLIoT (Rezaei et al.) | Ours |
|---|---|---|
| **Research question** | Which CVEs are IoT, and how do IoT CVEs differ from non-IoT? | Which CVEs affect *home* IoT, and how do weakness/severity profiles differ **across 24 device categories**? |
| **Scope** | All IoT: consumer, **industrial (51% of their IoT set)**, healthcare, automotive, smart city. Includes protocols (ZigBee/MQTT stacks), IoT platforms, IoT cloud (AWS IoT). Routers/modems out. | Residential only (5 criteria + 4(b) home-control surfaces). Industrial/enterprise out (criterion 3). Protocol libraries out unless tied to a device. Companion app + vendor cloud in. Routers out. |
| **Taxonomy** | 4 layers: device / communication / application / cloud. Layer labels **abandoned**: human α=0.28. | 24 leaf categories → 13 folding categories, as an OWL ontology with SHACL + reasoner gates. Descriptive facets measured for validity (Phase A) and reliability (κ). |
| **Corpus** | NVD + CVE.org API, CVEs 2013–2024: 224,531 total, 211,182 published. | One NVD snapshot (2026-08-05), 373,518 records, all years. Confirmed set spans 2001–2026; **24% (402) fall outside LLIoT's window**, 367 of them 2025–26. |
| **Candidate generation** | **None.** Every published CVE is classified (open world). | Vendor terms (1,564) + keyword phrases (208), whole-word matched against description+CPE, then CPE expansion (closed world). |
| **Classifier** | One LLM (O3) in production, picked from 4 benchmarked (GPT-4o, O3, DeepSeek-r1-70B, Llama4-scout). | 3 LLM reviewers in production (Claude Code, ChatGPT Codex, gemma-4-31b-it), structurally blind to each other. Disagreement or double-Low goes to **2 humans**. |
| **Unit of judgment** | CVE → {IoT, nonIoT} + layer + sector + free category | (category, CVE) → {Yes, No, Maybe} × {High, Low} |
| **Ground truth** | 300 CVEs (150 keyword-filtered + 150 random). 9 experts in 3 groups of 3, α=0.80. Tie-breaker. 44 human–LLM conflicts re-adjudicated. 10 borderline items dropped → 290. | No separate gold set. Humans adjudicate the 1,638 flagged rows and every settled label lives in the store. The **unflagged 6,467 AI-consensus rows were never audited by a human** except through the 294-row relaxation validation. |
| **Accuracy claim** | O3 94.67% → **99.31%** after correction; Wilson CI [97.52, 99.81]; expected error 0.19–2.48% over 211k. | None stated. Implicit: the strong-consensus relaxation, 293/294 (99.7%) as written, **recomputes to 291/294 (99.0%)** from the published store (see memory note). |
| **Consistency** | 1,000 CVEs × 10 runs: unanimity 92% (IoT 86%, non-IoT 98%), C̄=0.98, α=0.94. | Single pass per reviewer, no self-consistency. Inter-model agreement: pairwise 85–87%, unanimous 80.3%. |
| **Recall** | Not estimated. Coverage judged against VarIoT/Chen. | Capture–recapture: pooled 0.603 [0.556, 0.648], plus a 3-source log-linear variant. |
| **Dataset comparison** | vs VarIoT (33k) and Chen (1.6k): Venn diagrams, per-category coverage, 100-sample manual audits of each exclusive set. | None. |
| **Output size** | 15,116 IoT CVEs (4,134 consumer). | 1,676 CVEs / 1,738 (category, CVE) assignments. |
| **Cost / time** | O3, 10 h, €7,604. | Not reported. *Report it:* API cost of the Gemini pass + person-hours of the human queue. |
| **Analysis** | Temporal trend, severity per year, **CVSS component deltas IoT − non-IoT**, top-20 CWE per year, memory-safety bucket, **KEV**, recommendations. | CWE-888 class distribution per category (micro/macro), CVSS per category, Kruskal–Wallis + Dunn. **No non-IoT baseline, no temporal axis, no exploitation axis, no CVSS components.** |
| **CWE handling** | Raw CWE IDs; memory-safety bucket of 8 CWEs. | CWE-888 primary classes via parent resolution (10.7% multi-class). 7.0% CWE-less. |
| **CVSS version rule** | v3.1, else "highest available". | v3.1 > v3.0 > v4.0 > v2.0, with a v2-excluded sensitivity check. |
| **Release** | Code, prompts v1–v20, full 211k labels with reasons, expert reviews with reasoning, Postgres dump. | Code, term lists, rubric, per-reviewer judgment files, store, ontology, KG. Snapshot rebuild procedure (not the snapshot). |
| **Venue/genre** | SoK at EuroS&P. | Empirical study (IEEEtran conf. template). |

---

## 2. Prompt differences

### 2.1 Their prompt
The paper (Appendix B, Fig. 11) and the repo (`prompts/prompt_v20.txt`) **do not match**:

| Element | Paper Appendix B | Repo `prompt_v20.txt` | What production used (from the label table) |
|---|---|---|---|
| Layer field name | `"layer"` | `"component"` | `affected_component` column |
| Sector enum | `"consumer iot"` | `"smart homes iot"` | **`consumer iot`** (4,134 rows). The paper version matches production; the repo v20 does not. |
| Category instruction | absent | "choose a single high-level category … e.g. cameras, lighting, sensors, actuators, chisets, WiFi modules, netwrok infrustructure" | free-text `category` populated |
| Sector instruction | absent | "Also, determine the sector of the affected product." | populated |
| Typos | "rhe", "itselft", "commentart", "automative" | "chisets", "netwrok infrustructure", "automative" | — |

**Prompt drift v1 → v20** (both versions are in the repo). v1 put **Broadcom Wi-Fi SoCs and
BusyBox** inside the device layer, listed attack examples (UART/JTAG, side channels), and defined
IoT-specific as "*primarily or exclusively* deployed within IoT contexts". v20 dropped all of
that. It added "**the vulnerable product is itself an active, functional element of an IoT
system**" and a **default-to-negative** rule: "insufficient or no clear evidence … then it is
nonIoT". Twenty iterations tuned against a 300-item gold set is a prompt-overfitting risk they do
not discuss. The paper admits one tune outright: GPT-4o's ZigBee-dissector error was fixed "with
a small rephrasing of the classification rule".

**Inference settings.** Batch jobs ran O3 at `temperature: 1` (o3's only allowed value), which is
why they measured 10-run consistency. Ollama models ran with defaults.

### 2.2 Our prompt (`data/difference/CLASSIFICATION_PROMPT.md` + `categories.csv` scope note)

| Design choice | LLIoT | Ours | Assessment |
|---|---|---|---|
| Question asked | "Is this CVE IoT?" (open world) | "Does this CVE affect a home IoT device **of this category**?" (closed world, candidate check) | Ours is narrower and easier, which is part of why our agreement is high. Theirs must also reject the 93% non-IoT bulk. |
| Definition style | Architectural (4 layers + examples) | Criterial (5 necessary conditions) + per-category in/out note | Ours is more operational. Theirs lets layer reasoning leak into the label. |
| Inputs | description + "Affected Products" (CPE-derived product names) | `description` + raw `cpe_strings` + category + scope note | Equivalent information. We pass `part` (`a`/`o`/`h`), which helps app-vs-device calls. |
| Default when uncertain | **nonIoT** ("insufficient evidence → nonIoT") | **Maybe/Low → human** | Ours is safer for precision but costs human time. Theirs biases recall down on terse CVEs. Note that our "missing CPE does not force Maybe" rule pushes the other way. |
| Abstention | none on the label (only `layer: unsure`) | `Maybe` (always Low) | Ours is better for a gold-standard pipeline. |
| Confidence | none | High/Low, **load-bearing** in the flag rule | Ours is unusual and justified by Fig. `review_confidence` (91.3% vs 4.1–36.6% unanimity). Good material for the paper. |
| Reasoning | **always** required | only for Low/Maybe | **Weakness of ours:** 6,467 settled rows carry no reasoning when High, so a reviewer cannot audit them. LLIoT can show a reason for every label. Consider a sentence on why (cost/anchoring), or a sampled audit. |
| Extra labels | layer, sector, free category | none | Their free-text category is what made the routing gap in §6.4 visible. We should record a "better category" suggestion on `No` rows. |
| Scope edge rules | routers/modems out. MQTT-on-server example out. OpenSSL in when it affects IoT deployments. | Companion app/cloud in. Multi-product app bug → Yes for each named line. Connectivity ≠ membership. tvOS out (post-hoc). | Ours is more explicit on the edges that actually generate disagreements. |
| Few-shot | zero-shot | zero-shot | Same. |
| Output format | JSON only | Gemini: JSON MIME, temperature 0. Claude/Codex: fill CSV columns manually. | Ours is **heterogeneous across reviewers**. Two reviewers ran interactively with no recorded model build, a reproducibility gap the paper already admits (line 611). |
| Versioning | v1–v20 kept and released | 4 commits (06-13, 07-02, 07-05, 07-08). **Substantive rules added 07-02 and 07-05, at or after the end of AI collection.** | Must be disclosed or disproved (see §0.8). Suggest stating the rubric commit each reviewer column was produced under. |
| Blindness | Eval: 4 LLMs independent. Production: one model. Humans independent within a group; tie-breaker sees everything. | Structural: separate copies per AI reviewer. Humans blind to each other **but see AI columns**. | Our AI-to-AI blindness is a real advantage. Our human-to-AI blindness is not. |

### 2.3 What to adopt from theirs
- Keep a **free-text category field** on `No` rows, to catch misrouting (§6.4).
- Run a **self-consistency check** on Gemini: k=5 on a 200-row sample at the same temperature.
  It costs little and answers the obvious reviewer question.
- **Release prompt versions with dates**, and state which version produced each column.
- Do **not** adopt default-to-negative. Our Maybe/human path is a strength. Say why.

---

## 3. Related work

### 3.1 Their structure
Three parts, each ending in a "Takeaway":
1. **IoT taxonomy**: 3-layer (≈9 surveys), 4-layer with middleware (Guth, Alrawi's
   device/app/channel/cloud, Rondon), network-stack (Mohanta, Yang), 6-layer (Di Martino). They
   conclude cloud is under-modeled, which motivates their 4 layers.
2. **IoT CVE distinction**: VarIoT (keyword, broad), Chen et al. (keyword + manual, 1,739 CVEs
   with Windows/macOS false positives), Kumar & Fung 2024 (keyword only, no validation),
   report-centric (Feng et al. USENIX'19), firmware TPC version matching (Zhao ISSTA'22, Oser
   TOPS'22), metadata (Blinowski CPE+SVM; **Rivera: NVD `part = h` only**). Their three gaps:
   no consistent definition, weak heuristics, no scalable validation.
3. **IoT vulnerability analysis**: Alsadi AsiaCCS'25 (exploitation factors on VarIoT), Pérez
   S&P'24 (IoT-centric vendor patching), Arat (graph risk), Zhao TDSC (1.36M deployed devices, 73
   N-days), Fang TMC (attack graphs). Takeaway: downstream studies inherit dataset errors.

### 3.2 Ours (lines 78–159), and the problems
**Structure:** definition/scope → consumer vs industrial → device-category studies →
NVD/AI-assisted methods. It is a strong scope-justification section and a **thin method-lineage
section**. LLIoT's SoK is now the reference survey of IoT-CVE identification, so a reviewer will
measure our §II-D against it.

**Factual slips in our LLIoT sentence (lines 146–151):**
| Our text | What the paper says | Fix |
|---|---|---|
| "combine a written IoT definition, keyword filtering, a triple-expert 300-CVE ground truth, and an LLM labeler over the full 2013–2024 CVE set" | Keyword filtering is used **only to sample half of the 300-item gold set**. The production dataset has no keyword step. | Say the LLM classifies **every** CVE with no candidate filter, which is the contrast with our design. |
| "reporting LLM agreement around 95%" | 95% is **accuracy** (GPT-4o 95.33%, O3 94.67%), rising to 99.31% after relabeling. Agreement is α=0.87 across 4 LLMs and 92% unanimity across 10 O3 runs. | "accuracy of 95% (99.3% after correcting the gold set)". |
| "directly motivating our blind multi-model review" | Our review design predates LLIoT's May 2026 PDF: the AI columns were collected June 2026, and the rubric file existed by 06-13. | Say "parallels" or "complements", not "motivating", unless the team actually read a preprint first. |
| "we differ by using three blind AI reviewers plus human adjudication rather than a single production LLM" | Accurate. | Keep. Add the real difference: closed-world candidate review vs open-world classification, and residential vs all-IoT scope. |

**Missing citations their SoK made standard** (add the ones that bear on our claims):
| Paper | Why we need it |
|---|---|
| **VarIoT** (Janiszewski et al., Sensors 2021) | The largest IoT CVE dataset. Keyword-based, about 30% FP per LLIoT's audit. Contextualizes our 53.8% FP rate. |
| **Chen et al. IoT-J 2024/25** (already `chen2025`) | Check our "~198k" claim against their 1,739/1,619 counts. |
| **Kumar & Fung, CIoT 2024** | Keyword-only IoT CVE analysis. Note the name clash with our `kumar2019` (Durumeric group). |
| **Blinowski & Piotrowski 2020** | CPE-based ML classification, including a "home systems" class. The closest prior home-specific CPE work. |
| **Rivera et al. 2025** (survival analysis, `part = h` filter) | Directly relevant to our CPE-expansion `part ∈ {o,h}` guardrail. Their `h`-only filter misses firmware; ours keeps `o`. Cite it as the contrast. |
| **Feng et al., USENIX Sec 2019** | "IoT attacks almost exclusively use known vulnerabilities". The motivation for studying NVD at all. |
| **Alsadi et al., AsiaCCS 2025** | IoT exploitation factors. Needed the moment we add KEV. |
| **Pérez, van Eeten, Gañán, S&P 2024** | IoT-centric vendor patching. Relevant to the Insteon-concentration caveat (line 1308). |
| **Zhao et al., ISSTA 2022 / Oser et al., TOPS 2022** | Firmware TPC → CVE. The contrast to text search. |
| **Jin et al., CCS 2022** (market-scale IoT) | They cite it for borderline mobile libraries, and it backs our companion-app rule. |
| **Alladi et al. 2020** | Already cited by both. |

**Positioning paragraph to write.** LLIoT answers "which CVEs are IoT"; we answer "which CVEs
are *which* home device". These are **complementary, not competing**. Our §6.1 check shows the
two agree on 97% of the overlap, and LLIoT's consumer slice (4,134) is the natural population to
compare our 1,676 against. Then name the three things LLIoT cannot do:
1. per-device-category profiles (their free-text category is an LLM afterthought, not reviewed)
2. a recall estimate
3. a residential boundary (51% of their IoT set is industrial)

---

## 4. Methodology comparison (granular)

| # | Issue | LLIoT | Ours | Verdict / action |
|---|---|---|---|---|
| M1 | **Open vs closed world** | Classifies all 211k CVEs, so no term-induced recall loss. | Terms bound recall, which is why stage 10 exists. | Our biggest structural weakness relative to them. §6.3 turns it into a quantified, named gap. |
| M2 | **Definition grounding** | Literature-derived layers. No formal check that the definition decides cases. | Criteria + OWL reasoner + deletion self-test (all 5 criteria load-bearing). | **Our clear advantage.** Lead with the deletion test, not the "31/31 rulings". |
| M3 | **Gold set** | 300 items, α=0.80, released with reasoning. | None separate. The store is the gold, but only the 1,638 flagged rows have human verdicts. | **Gap.** Add a **random audit of ~150 unflagged AI-consensus rows**, humans blind to AI columns. That gives a precision estimate with a CI for the 6,467 rows no human saw. It is the single most reviewer-proof addition available. |
| M4 | **Correction loop bias** | Tie-breaker sees LLM reasoning, then LLM accuracy is recomputed on the corrected labels (circular). | Humans see AI columns, then the relaxation rule is validated against those humans (also circular). | Acknowledge in Threats. Don't cite AI-vs-human agreement (memory note). |
| M5 | **Multi-model** | 4 models benchmarked, one deployed. | 3 deployed. | Ours is stronger as deployment. Theirs is stronger as **model selection evidence**: we never benchmarked our 3 against anything. M3's audit would give per-model accuracy for free. |
| M6 | **Consistency** | 10 runs, unanimity, C̄, α. | None. | Cheap fix in §2.3. |
| M7 | **Borderline handling** | Drops 10 borderline items from evaluation (WolfSSL, BusyBox). | Maybe → human. Policy rulings recorded (Frigate=In, pro cameras by consumer availability). | Ours is more principled. Their *dropping* borderline cases inflates accuracy, and it is a fair critique to make politely. |
| M8 | **Per-category structure** | No. | Yes. Creates the **routing gap** (§6.4): a CVE judged under the wrong category has no path to the right one. | Fix: a "belongs to another category" flag that re-queues the row. |
| M9 | **Post-hoc scope exclusion** | None. | tvOS, applied after review; **leaks via `apple:apple_tv`** (§6.2). | Fix the rule to cover `apple:apple_tv`, or argue explicitly why those are different. Recompute streaming. |
| M10 | **Temporal window** | 2013–2024 fixed. | All years, snapshot-pinned. 2025–26 = 22% of our set. | Advantage: ours is more current. Add a year histogram, because we currently have **no temporal analysis**. |
| M11 | **Dataset comparison** | Against 2 prior datasets with exclusive-set audits. | None. | Do it **against LLIoT itself** (§6). It is the natural baseline and the numbers are already computed. |
| M12 | **Reproducibility cost** | €7,604, 10 h, batch API. | Unreported. | Report it. Note that the manual Claude/Codex columns are not re-runnable like their batch job. |
| M13 | **Error propagation** | Wilson CI on accuracy, extrapolated to 211k. | No error bar on any count. | M3 gives one. |

---

## 5. Analysis-section comparison

| Analysis | LLIoT §6 | Ours (RQ1/RQ2) | Gap / what to add |
|---|---|---|---|
| Baseline | IoT vs **non-IoT** everywhere | Category vs category only | **Add a non-IoT baseline.** Use LLIoT's nonIoT labels or the NVD remainder; one table makes every RQ1/RQ2 claim interpretable. |
| Temporal | Counts per year, growth ratio (IoT 8.5× vs 6× since 2013), severity per year, CWE per year | none | Year histogram + severity-by-year for cameras/hub. |
| Severity | Banded shares per year | Per-category mean/median/bands + KW/Dunn | Ours is statistically stronger. Theirs has no tests at all. |
| CVSS components | **Fig. 8: pp deltas per metric** (UI:N +20.3, PR:N +12) | none | Reproduced below on our snapshot. Directly addresses "why is home IoT severe". |
| CWE | Raw top-20 per year; memory-safety bucket | CWE-888 classes | Report **both**: CWE-888 for comparability with Goseva-Popstojanova, raw top-20 for comparability with LLIoT. |
| Exploitation | VulnCheck KEV counts (§6.4, stops at counts) | none | §7 below. |
| Recommendations | 4 stakeholder recommendations (credentials, memory safety, web exposure, CRA/RED) | §"Lessons" empty | Use our hub/camera contrast to make recommendations that are **device-class specific**, which theirs cannot be. |

### 5.1 Their Fig. 8 reproduced on our snapshot, extended to our set **[measured]**
CVSS v3 vectors from `nvd_all.csv` joined to their labels. Their UI:N delta reproduces at +21.1pp
(they report +20.3), so the join is sound.

| Metric:value | **Ours** (n=1,541) | LLIoT consumer (3,988) | LLIoT IoT (14,345) | LLIoT non-IoT (178,154) |
|---|---|---|---|---|
| AV:N | 73.8 | 64.6 | 71.1 | 72.0 |
| AV:A | **14.8** | 11.3 | 7.0 | 2.0 |
| AV:L | **6.4** | 21.1 | 18.9 | 25.2 |
| AV:P | 5.0 | 3.1 | 3.0 | 0.8 |
| AC:H | 9.8 | 6.2 | 6.1 | 6.1 |
| PR:N | 67.0 | 67.6 | 68.6 | 57.9 |
| UI:N | **91.4** | 88.7 | 85.3 | 64.2 |
| S:C | 17.1 | 10.1 | 9.8 | 19.6 |
| C:H / I:H / A:H | 69.7 / 63.6 / 69.4 | 69.6 / 59.9 / 70.9 | 66.5 / 57.0 / 67.0 | 55.0 / 47.0 / 56.1 |
| AV:N∧PR:N∧UI:N | 42.1 | 45.0 | 47.7 | 29.4 |
| Critical / High / Med / Low (all versions) | 27.8 / 43.8 / 26.8 / 1.6 | 26.4 / 44.5 / 27.6 / 1.5 | 23.9 / 45.7 / 28.8 / 1.5 | 13.7 / 37.7 / 45.9 / 2.6 |

Readings:
- Home IoT is **more Adjacent-network and less Local** than LLIoT's consumer slice (AV:A 14.8 vs
  11.3, AV:L 6.4 vs 21.1). This is consistent with our scope removing chipsets and Android
  drivers, which are mostly AV:L.
- **UI:N 91.4%** is the highest of any population. On user interaction, home IoT is the extreme
  of IoT, not merely like it.
- **Critical share 27.8% vs non-IoT 13.7%** (2×). This is the comparison RQ2 is missing.

### 5.2 CWE contrast **[measured, CWE-occurrence counts]**
| | Ours | LLIoT consumer | LLIoT IoT | LLIoT non-IoT |
|---|---|---|---|---|
| Memory-safety bucket (LLIoT's 8 CWEs) | **23.5%** | 31.6% | 23.6% | 22.0% |
| CWE-798 hard-coded creds | **5.3%** | 3.2% | 2.9% | 0.5% |
| CWE-78 OS cmd injection | **6.8%** | 4.6% | 3.1% | 1.9% |
| CWE-79 XSS | 2.5% | 3.5% | 4.7% | 15.4% |

Top raw CWEs, ours: 121 (stack BOF) 7.2, 78 6.8, 20 5.9, 787 5.6, 798 5.3, 287 4.8. LLIoT
consumer: 787 8.5, 120 5.1, 20 4.7, 78 4.6, 125 4.4.

**Finding worth a paragraph.** LLIoT's headline is "memory safety dominates IoT". Under a
residential scope, home IoT's memory-safety share (23.5%) is **indistinguishable from non-IoT
(22.0%)**. LLIoT's elevated consumer figure (31.6%) is plausibly driven by chipsets and drivers,
which their consumer slice contains and our criterion 2 excludes. What distinguishes home IoT is
**hard-coded credentials (10× non-IoT)** and **command injection (3.6×)**. Both fit our
camera-dominated Tainted-Input/Authentication profile. The hub/camera split in RQ1 (Memory Access
61% vs 16%) shows that a single "IoT memory-safety" figure averages over device classes that
differ sharply. That is the argument for per-category analysis.

---

## 6. Cross-check against LLIoT's released labels **[measured]**

### 6.1 Agreement on our confirmed set
| Our set (2013–24) | LLIoT-labelled | LLIoT says IoT |
|---|---|---|
| Confirmed Yes | 1,265 | **1,229 (97.2%)**. Sectors: consumer 1,134, industrial 36, smart-city 32, automotive 26 |
| Rejected (No in every category) | 2,600 | 795 (30.6%). Industrial 299, consumer 283, smart-city 162 |
| tvOS-excluded | 1,746 | 26 (1.5%). LLIoT treats tvOS as non-IoT, which **supports our exclusion** |

Per category, every category except `streaming` (54.3%) and `cameras` (99.4%) is at 100%.

### 6.2 The 36 disagreements → tvOS exclusion leak
- 32 are `streaming`, mostly Apple multi-OS CVEs: Safari, WebKit, iCloud, plus kernel CVEs from
  2016–2019. LLIoT labels them "smartphones/computers", "browser" and "operating system".
- They escaped the exclusion because their CPE is **`cpe:2.3:[a|o]:apple:apple_tv`**, NVD's
  pre-rename product string, not `apple:tvos`. The exclusion keys on `tvos`; all 2,015 excluded
  rows contain it.
- **Size:** 33 of 76 surviving `streaming` CVEs (43%), 31 of them co-listing iPhone OS or macOS.
- The rest: CVE-2015-7292 (Amazon Fire OS staging driver, arguably a tablet), and 4 `cameras`
  that LLIoT calls NAS (CVE-2016-7819/7820, CVE-2021-34345) or nonIoT (CVE-2022-25012).
  **Spot-check those 4.**
- **Action:** extend the exclusion to `apple:apple_tv` CPEs (record them as `Excluded`, never
  flip judgments). Then regenerate the streaming rows of Table III, Table V and the RQ1 text. If
  the team decides `apple_tv` CVEs are device-specific, that needs an explicit argument, because
  31 of the 33 contradict it.

### 6.3 Recall probe: LLIoT consumer IoT we never surfaced
- LLIoT consumer IoT: 4,134.
  - In our candidate set: 1,455. Of those, 1,146 confirmed, 284 rejected, 26 tvOS-excluded.
  - **Never surfaced: 2,679.**
- Never-surfaced, by LLIoT category: chipsets 971 (out, criterion 2), camera(s) 362, network/gateway
  196 (mostly out), actuators 127, printers 120 (out), wearables 81 (out), sensors 64, OS 51,
  lighting 33, smart TV ~47, NAS 38 (out), locks 7, smart speaker 12.
- 801 carry a home-ish category. In a random 30 of those:
  - **~14 clearly in our scope:** Luvion baby monitor, GoCloud and Buffalo cameras, SmartThings
    app, Linkplay speaker, Videofied/Frontel alarm, Lenovo Smart Camera, Amazon Cloud Cam,
    BTicino door-entry app, Chamberlain myQ, Qrio lock, Skyworth TV OS, DTE energy app
  - **~8 borderline:** ZoneMinder ×3, MajorDoMo, Homematic software, Lightify *Pro*, ThroughTek
    Kalay SDK, Anni XVR
  - **~8 out:** projector, printer, trackers, Intel RealSense, Dreambox
- Rough extrapolation: **~300–450 in-scope CVEs** in 2013–2024 that our terms never reach. n=30,
  so read it as order-of-magnitude only.
- **Root causes, verified against `vendor_terms.csv`:**
  - **Over-qualification.** `hub,samsung smartthings hub`, `hub,smartthings hub` and
    `hub,home assistant yellow|green` cannot match "SmartThings prior to 1.7.89" (CPE
    `samsung:smartthings`, app) or the Home Assistant core (`home-assistant:home-assistant`). The
    product-word qualification convention is right for megavendors but **structurally excludes
    the companion-app/platform CVEs our rubric declares in scope.**
  - **Missing brands:** gogogate/ismartgate (11), Osram Lightify (9), ZoneMinder (68, needs a
    scope call consistent with Frigate=In), Amazon Blink **XT2 sync module** (7; `blink camera`
    doesn't match the CPE `blink_xt2_sync_module_firmware`), Chamberlain myQ, Qrio, Linkplay,
    TrackR (out), Buffalo WNC01WH, Lenovo smart camera, Luvion, Barni, Microdigital, C-MOR.
- **Use in paper:** next to capture–recapture, write: "an independent LLM-labelled corpus contains
  N in-scope CVEs our terms never reach; we attribute them to (a) and (b)". It is an
  **independent lower bound** on misses that shares no mechanism with capture–recapture. Our
  capture–recapture assumes the same term-based capture process, so this is a genuinely different
  instrument. **Or, better, fix the terms and rerun** (the memory note says rebuilding beats
  adding terms).

### 6.4 Category-routing gap
LLIoT camera-labelled consumer CVEs that we judged `No` only under a **non-camera** category and
never reviewed as `cameras`:

| CVE | Our category | Device |
|---|---|---|
| CVE-2024-48214 | airconditioner | Kerui Tuya 3MP camera |
| CVE-2018-19588, CVE-2019-9657 | alarms, thermostat | Alarm.com ADC-V522IR camera |
| CVE-2018-7661 | babymonitor | Papenmeier WiFi Baby Monitor app (**`No` under babymonitor looks wrong on its face. Check.**) |
| CVE-2024-31408, CVE-2024-39290 | doorbell | Aiphone IX/IXG intercom (likely commercial, so probably fine) |
| CVE-2020-10176 | doorlock | Yale WIPC-301W camera |
| CVE-2019-7728, CVE-2019-7729 | hub | Bosch Smart Camera app |
| CVE-2018-20161 | sensors | Blink Sync Module. Human note: "belongs in hub category, not sensors". **The humans saw it and the pipeline had nowhere to send it.** |

Also CVE-2023-6913 (Imou Life app, an Imou camera app) was rejected under `cameras` with "unrecognized
vendor". That is Codex-style over-exclusion that all three shared.

### 6.5 Rejected-but-LLIoT-consumer (284)
181 are `cameras`, mostly NVR/DVR/pro lines (NUUO, Dahua NVR, AirLive) rejected under our
consumer-availability rule. These are legitimate scope differences. Worth one sentence: "the
largest source of disagreement with LLIoT is our consumer-availability boundary, which LLIoT has
no equivalent of".

---

## 7. CISA KEV **[measured]**

### 7.1 Rates
| Population | n | KEV | Rate |
|---|---|---|---|
| NVD snapshot, all years | 373,518 | 1,691 | 0.45% |
| NVD snapshot, 2013–2024 | 220,905 | 1,282 | 0.58% |
| **Ours, confirmed** | **1,676** | **10** | **0.60%** (Poisson 95% CI ≈ 0.24–1.01%) |
| Ours, confirmed, 2013–24 | 1,274 | 10 | 0.78% |
| Ours, rejected | 4,024 | 38 | 0.94% |
| Ours, tvOS-excluded | 2,015 | **37** | **1.84%** |
| LLIoT IoT | 15,116 | 45 | 0.30% |
| LLIoT non-IoT | 196,066 | 1,250 | 0.64% |
| LLIoT consumer IoT | 4,134 | 21 | 0.51% |
| LLIoT industrial IoT | 7,705 | 12 | 0.16% |

- Expected KEV count in our set at the baseline rate is 7.5; observed is 10; p≈0.23. **The
  difference is not significant. Do not claim home IoT is over-exploited.**
- LLIoT used **VulnCheck KEV** (4,005 entries; 1,399 for CISA at their writing): IoT 209/15,116 =
  1.38% vs non-IoT 3,099/196,066 = 1.58%. Under CISA today: 0.30% vs 0.64%. **Both sources put
  IoT at or below non-IoT.** Their §6.4 states the counts and draws no conclusion, even though
  their CVSS story ("lower effort, higher impact, more exploitable") predicts the opposite. We
  can point that out gently.

### 7.2 Our 10 KEV hits — all `cameras`
| CVE | Vendor / product | KEV added | CVSS |
|---|---|---|---|
| CVE-2020-5735 | Amcrest cameras/NVR | 2021-11-03 | 8.8 |
| CVE-2021-36260 | Hikvision web server | 2022-01-10 | 9.8 |
| CVE-2016-11021 | D-Link DCS-930L | 2022-03-25 | 7.2 |
| CVE-2023-47565 | QNAP VioStor NVR | 2023-12-21 | 8.8 |
| CVE-2021-33044 | Dahua IP camera | 2024-08-21 | 9.8 |
| CVE-2019-11001 | Reolink | 2024-12-18 | 7.2 |
| CVE-2021-40407 | Reolink RLC-410W | 2024-12-18 | 7.2 |
| CVE-2020-25078 / 25079 | D-Link DCS-2530L/2670L | 2025-08-05 | 7.5 / 8.8 |
| CVE-2017-7921 | Hikvision | 2026-03-05 | 9.8 |

- Median lag from NVD publish to KEV listing: **1,071 days** (range 13–3,225). Home-camera
  exploitation is recognized years after disclosure, and 4 of the 10 were added in the last 14
  months. That is a **patch-lifetime** story, and Pérez et al. S&P'24 is the citation.
- **`hub`: 0/247 KEV despite median CVSS 9.8 and 53.4% Critical.** Severity does not predict
  exploitation here, and Insteon's 45% share (line 1308) is the likely reason: discontinued,
  low-exposure products. This is a better RQ2 caveat than the vendor-concentration one alone.
- `cameras` 10/885 = 1.13% vs NVD 0.45% is suggestive (expected 4.0, observed 10, p≈0.008 one-sided, uncorrected), but it is
  one category among 22 tested post hoc. **Report it as a hypothesis.**

### 7.3 KEV CVEs we rejected (38)
- 24 D-Link (incl. one joint D-Link/TRENDnet entry): 23 are routers (DIR-*), DSL modems, NAS (DNS-320), an AP — **correct exclusions** under
  router-out and NAS-out; all were pulled in by the bare `d-link` camera term (precision 0.044,
  already flagged).
- 3 Ubiquiti UniFi OS (2026, correct), 2 Adobe Flash and Apache Struts (noise), 2 Qualcomm
  chipsets (criterion 2).
- **Borderline, re-examine:**
  - **CVE-2021-33045** (Dahua): the identical-twin inconsistency in §0.5
  - **D-Link DNR-322L** (CVE-2022-40799): a consumer mydlink NVR, and the human decision
    conflicts with the "Frigate NVR = In" precedent
  - **NUUO NVRmini** ×2 and **GeoVision** ×2: pro, likely correct under consumer availability
  - **Meteobridge** (CVE-2025-4008): a consumer weather-station bridge under `garden`; the humans
    said No

### 7.4 How to add KEV to the paper properly
1. **Pin the catalog version** (date + entry count + SHA-256), the same way as the NVD snapshot.
   CISA KEV mutates daily: 1,740 now vs 1,399 when LLIoT wrote.
2. Report **CISA and VulnCheck** side by side. CISA is scoped to federal enterprise risk (BOD
   22-01/26-04) and **structurally under-lists consumer devices**, which is a construct threat to
   any "home IoT is/isn't exploited" claim. VulnCheck is a superset and the source LLIoT used.
3. Add **EPSS** (`PLAN_analysis_improvements.md` item 7): with only 10 KEV events, a continuous
   probability is the only way to compare categories.
4. Use KEV as a **validity check on review**, not only as a finding: "of 48 KEV-listed CVEs in our
   candidate set, 10 were confirmed; the 38 rejections are routers/NAS/chipsets, with 1
   inconsistency corrected". That is a strong statement about the review.
5. Disclose that the **tvOS exclusion removes 37 KEV-listed CVEs**, which is where most of the
   streaming exploitation sits.

---

## 8. LLIoT weaknesses to know about (be fair; we share some)

| Weakness | Shared by us? |
|---|---|
| Ground-truth correction with LLM reasoning visible (circular accuracy uplift 94.67 → 99.31) | **Yes, partly:** our humans see AI columns |
| Borderline items dropped from evaluation (10/300) | No. We route them to humans. |
| One model, temperature 1, 8% of labels unstable across runs (14% for IoT) | We have no stability measure at all |
| Gold set is 50% keyword-selected, so it over-represents easy IoT positives; random non-IoT is trivially easy | N/A |
| Layer taxonomy (their SoK contribution) failed reliability (α=0.28) and is unused in the analysis | Our facets failed κ on 8/12. Same honesty, and we handle it better (withheld in code). |
| Paper/repo prompt mismatch (v20 ≠ Appendix B) | Our rubric changed during collection (§0.8) |
| "Memory safety dominates" is likely a chipset artifact (§5.2) | N/A. Our scope removes it. |
| KEV section reports counts without interpretation | We have no KEV yet |
| No recall estimate | We have one |
| Industrial is 51% of "IoT", so their IoT vs non-IoT contrasts are mostly OT vs IT | N/A |

---

## 9. Prioritized action list

**Correctness fixes (do before anything else):**
1. Extend the tvOS exclusion to `apple:apple_tv` CPEs (33 rows). Regenerate the streaming rows in
   Tables III, IV and V, the CWE-888 matrix, the treemaps, the funnel and the review figures.
   Re-run the `--verify-kg` gate.
2. Resolve CVE-2021-33044/33045 to one label. Then sweep for other identical-description pairs
   with split final labels: a cheap script over the store.
3. Re-examine the §6.4 routing rows, especially Papenmeier, Blink Sync and Alarm.com.
4. Verify the rubric timeline (§0.8). Either show the scope-note and app rules predate collection
   (an earlier draft or file), or disclose the versioning in §III-E.
5. Line 600 ("blind-adjudicated"): say "blind to each other; adjudicators saw the AI judgments".
   Lines 651/1456: 293/294 → 291/294 (99.0%), or label it a historical measurement.

**Paper additions (high value per effort):**
6. Rewrite the LLIoT sentence (lines 146–151) per §3.2. Add a positioning paragraph and the
   missing citations.
7. Add **§ external agreement**: 97.2% LLIoT concordance plus the 284-row disagreement typology.
8. Add **KEV (CISA + VulnCheck) + EPSS** to RQ2, or as a short RQ3, per §7.4.
9. Add a **non-IoT baseline** (LLIoT non-IoT labels) for CVSS components (§5.1 table → a figure
   like their Fig. 8) and for the raw top-20 CWEs (§5.2).
10. Add the **recall probe** (§6.3) to stage 10 / external validity.
11. Add a year histogram (no temporal analysis exists now).

**Pipeline improvements:**
12. Add companion-app/platform terms (`smartthings`, `home-assistant` as a CPE-scoped term, Blink
    XT2, Lightify, myQ, gogogate, Qrio, Linkplay…). Rebuild the searches and re-review only the
    new rows.
13. Add a "belongs to category X" field on `No` verdicts that re-queues the row.
14. Random 150-row human audit of unflagged AI-consensus rows, **with AI columns stripped**.
15. Gemini self-consistency (k=5, 200 rows).
16. Promote `compare.py` to `scripts/lliot_kev_join.py` with a pinned KEV copy and LLIoT label
    extract under `data/external/`. Check LLIoT's license (repo `LICENSE`, 1 KB) before
    redistributing their labels; citing and re-deriving is safe either way.

---

### Provenance
- LLIoT paper: `https://conand.me/publications/rezaei-lliot-2026.pdf`, created 2026-05-25.
- LLIoT artifact: GitHub `Tina-Rezaei/LLIoT` HEAD as of 2026-10-13. The label table has 211,182
  rows (15,116 IoT / 196,066 non-IoT), matching the paper exactly. `dataset_benchmark/CVE_IoT.sqlite`
  is **Chen et al.'s** 1,739-CVE dataset, not LLIoT's.
- CISA KEV CSV fetched 2026-10-13, 1,740 entries (1,691 present in our snapshot).
- Our data: `judgment_store.csv` (8,124 rows) and `nvd_all.csv` (2026-08-05) at HEAD `f3fe842`
  plus uncommitted working-tree changes.
