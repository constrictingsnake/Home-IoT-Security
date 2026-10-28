# Plan — Does LLIoT's method work on our research question? (one researcher, ChatGPT-based)

> **STATUS (2026-10-26): P3 + P4 DONE — 3,035/3,035 main + 152/152 reruns valid; stability 97.4%. Next: P5 — adjudication sheet built (amended to ~2 h, § The adjudication sheet).** Kit, scripts, sample
> (3,035 CVEs) and pilot jobs are built. A ran the smoke test and the 42 pilot jobs (§ Pilot
> log). **Changed 2026-10-25, before the Phase 0 commit: the study is one researcher (Aarav)
> on one ChatGPT Plus plan**, run from a Claude Code session (§ One-researcher workflow). B's
> pilot is replaced by A rerunning the 40 single pilot jobs (`pilot-rerun`) for the stability
> read. Gate passed 2026-10-25; main run and reruns finished 2026-10-26 (§ Pilot log). **Deviation, disclosed:** the pilot
> ran before the Phase 0 commit. Pilot outputs never enter the analysis, so no analysed label
> predates the pre-registration. After that commit, changes to hypotheses, sample sizes, prompt or metrics are
> dated amendments with a reason, never silent edits.
>
> **Supersedes an uncommitted draft** (`PLAN_single_model_baseline.md`, 2026-10-15, deleted
> unexecuted). Same core design: one model, open world, our rubric. This version makes **category
> accuracy** a primary outcome, uses category-balanced strata, and runs headless via `codex exec`.

## Research question

> **If we used LLIoT's method — one LLM classifying every CVE, no vendor/keyword search — on
> *our* question, would it (a) correctly decide which CVEs affect a home IoT device, and
> (b) correctly assign them to our 24 categories?**

"LLIoT's method" here means their **design**: open world (no candidate filter), one model, one
pass, one CVE at a time, JSON output. It does **not** mean their prompt or their definition of
IoT. The model is given **our** rubric and scope notes, because the question is whether the
method answers *our* question. Testing their prompt would answer a different question
(`LLIOT_COMPARISON_REVIEW.md` §6 already covers how their labels relate to ours).

**What we compare against:** our pipeline (search → triple-AI review → humans), with blind human
adjudication as ground truth for both. The pipeline is the benchmark, not the truth. Its
category labels in particular are incomplete. A CVE is only ever reviewed under the categories
the search routed it to, and 192 in-window CVEs were reviewed under more than one category. So
"the model disagrees with the pipeline" is never scored as a model error without a human verdict.

## Pre-registered hypotheses and the decision each one drives

**(a) Home-IoT detection**

| # | Hypothesis | If supported | If not |
|---|---|---|---|
| Ha1 | **Precision is non-inferior**: the model's home-IoT precision is within 5 pp of the pipeline's. | The single-model method is precise enough for our question. | It over-includes. Report what it lets in (by `exclusion_reason`), and keep the review stage. |
| Ha2 | **Recall is higher**: the model finds in-scope CVEs the pipeline never surfaced (strata U1–U3). | Report the estimated count + CI as a named recall gap; route found brands/apps to `vendor_terms.csv` via the normal vetted path. | The search stage isn't losing material recall; report the upper CI bound. |

**(b) Category assignment** (scored on CVEs humans confirm as home IoT)

| # | Hypothesis | If supported | If not |
|---|---|---|---|
| Hb1 | **Primary category is right ≥ 90%** of the time; exact category-set match ≥ 80%. | The model can replace search-based routing. | Report where it fails (Hb3). Category assignment would need a review step. |
| Hb2 | **Category accuracy ≥ 80% in every family** (`data/ontology/families.csv`) with n ≥ 10. Leaf categories with n < 10 are reported at family level only, per the tail rule. | No family is a blind spot. | Name the failing families; those are where per-category review earns its cost. |
| Hb3 | **Errors concentrate on the known hard boundaries**: cameras ↔ babymonitor ↔ doorbell, hub ↔ lighting ↔ smartplugs, alarms ↔ sensors. ≥ 60% of category errors fall on these pairs. | The rubric's scope notes, not the method, are the weak point. Feed this back into `scope_note`s. | The errors are diffuse, so it's the method. |
| Hb4 | **The model fixes misrouting the pipeline can't**: on the routing-probe stratum, it assigns the human-confirmed category more often than the pipeline. | Report it as the main structural advantage of open-world classification. | Report that per-category review loses nothing here. |

**Run quality**

| # | Hypothesis | If supported | If not |
|---|---|---|---|
| H5 | **Stability ≥ 90%** on the home-IoT verdict and ≥ 85% on the primary category across reruns. | Single-pass labels are usable. | Single-model labels need majority-of-k; recompute cost. |

**Overall verdict, pre-registered.**
- **"The method works on our question"**: Ha1 + Hb1 + Hb2 hold.
- **"Works as a recall net only"**: Ha2 holds but Ha1 or Hb1 fails. Then the model is useful
  for finding candidates, which still need our review.
- **"Doesn't work"**: neither of the above. That justifies our search + review design with a
  measured gap, a result the paper can use either way.

## Population and sample

**Population:** `data/nvd-snapshot/nvd_all.csv` (vintage 2026-08-05), published 2013–2024,
REJECTED removed: **206,834 CVEs**. The window matches LLIoT's, which lets their labels enrich
the recall strata. Our 402 confirmed CVEs outside it are out of scope for this test; say so.

**Strata.** Counts were **measured 2026-10-16** against `judgment_store.csv` and LLIoT's released
`iot_cls.tsv`. The sampler recomputes and logs them, and stops if any drifts by more than 1%.
LLIoT's labels are used **only to stratify** the never-surfaced pool, so the recall sample isn't
99% empty. Every estimate is reweighted by stratum, so this introduces no bias.

| Stratum | Definition | Population | Sample | Tests |
|---|---|---|---|---|
| **Y** | pipeline `yes`, **category-balanced**: census of every category with ≤ 40 confirmed, plus cameras 80, hub 60, alarms 40, streaming 40 | 1,274 CVEs | **~500** | (b) above all; (a) precision of the pipeline |
| **M** | pipeline `yes` in **> 1 category** | 25 | **25 (census)** | Multi-label assignment |
| **R** | routing probe: CVEs reviewed under > 1 category with split verdicts, plus the 11 known misroutes (review §6.4) | 142 | 100 (all 11 known kept) | Hb4 |
| **N** | pipeline `no` | 2,621 | 300 (150 where LLIoT says consumer IoT, 150 not) | (a) Does the model accept our rejects? |
| **X** | tvOS-excluded | 1,746 | 50 | Does the model apply the tvOS rule? |
| **U1** | never surfaced, LLIoT says consumer IoT | 2,632 | 400 | Recall, enriched |
| **U2** | never surfaced, LLIoT says other-sector IoT | 10,047 | 200 | Home devices filed under another sector |
| **U3** | never surfaced, everything else | 188,514 | 1,500 | The only unbiased recall cell |
| | | | **~3,075** | |

- Confirmed-Yes counts per category in window: cameras 649, hub 216, alarms 81, streaming 71,
  ev-charging 37, smartplugs 36, home-power 32, smartspeakers 32, doorlock 30, doorbell 28,
  lighting 23, thermostat 15, babymonitor 13, robotvacuum 12, pet 11, garden 6, and ≤ 3 each for
  airconditioner, appliances, airpurifier, fridge, sensors. **fans, shades and sleeptracker have
  none**, so their category accuracy can't be measured from Y. It can only come from positives the
  model finds in U, and is reported as "unmeasured" otherwise.
- Strata can overlap (a Y CVE can also be in R). The sampler assigns each CVE to one stratum in
  the order M → R → Y → X → N → U.
- U3's prevalence is low, so 1,500 rows give a bound, not a precise estimate.
- **Priority if throughput is short** (decided at the gate): Y, M, R first, since they carry
  question (b) and nothing else does. Then U1, N, U3 (down to 750 at minimum), then the rest.
- Fixed RNG seed in the manifest.

## The model and the run kit

### Runner: `codex exec`, headless, one fresh session per job
```
codex exec --ephemeral --ignore-user-config --ignore-rules --skip-git-repo-check \
  -C <run dir> -s read-only -m gpt-5.6-sol -c model_reasoning_effort=medium \
  -c 'web_search="disabled"' --disable <17 tool features, see lliot_run.py DISABLE> \
  --json --output-schema schema.json -o out/<job>.json  -   < job_preamble.txt + job JSON
```
- A new process per job with `--ephemeral` gives every job a fresh session.
- The run dir is **outside any git repo** and holds only the kit's own `AGENTS.md`, `schema.json`
  and the job files. Codex loads that `AGENTS.md` as its instructions; that file **is** the
  prompt (below).
  - The repo's `AGENTS.md`, which tells Codex it is the pipeline's reviewer, is never on the
    path, because Codex looks for instructions from the git root down to the working dir.
  - `--ignore-user-config` drops `config.toml` (plugins, MCP servers, the `ultra` default).
  - No global `~/.codex/AGENTS.md` exists on A's machine (checked 2026-10-16).
- **Verified on A's account, 2026-10-16** (`lliot_run.py smoke`, plus a canary test):
  1. **`AGENTS.md` is loaded.** The session quotes its first heading. Delivery path:
     `agents-md`. `--inline-instructions` is the fallback if a later smoke test says otherwise.
  2. **No web search.** `-c web_search="disabled"`; the session reports no web tool.
  3. **No shell, file or code access, enforced by the setup, not just the prompt.** The read-only
     sandbox blocks writes but not reads, so with a shell the model could read
     `judgment_store.csv`. `lliot_run.py` disables the shell, exec, code-mode, multi-agent,
     image, browser, computer-use, plugin, app and skill features.
     - Canary test: from an empty dir with **no** `AGENTS.md`, the model was told to read a
       random-token file outside the run dir by any means. It could not. Code mode "fails
       closed" and sub-agent spawn fails, and the token never appeared.
     - With the kit's `AGENTS.md` loaded, it also refuses on instruction.
  4. Transient OpenAI 503s occur. Codex retries them, and the driver retries a failed job once.
- `--output-schema` enforces the JSON shape.
- `scripts/lliot_run.py` walks one researcher's queue: resumable, retries a schema failure once,
  logs every job.

### Model and effort
- **Model: `gpt-5.6-sol` at `medium` reasoning effort**, for every job, pinned
  by `lliot_run.py` with `-m` and `-c model_reasoning_effort=medium`. Your local config defaults
  to `ultra`, so an unpinned run would burn quota without saying so. Chosen for **ChatGPT Plus**:
  - **Measured 2026-10-16 on A's Plus account:** every `gpt-6*` model (`gpt-6.1-sol`,
    `gpt-6-sol`, `gpt-6-astra`, `gpt-6-luna`) is refused with "not supported when using Codex
    with a ChatGPT account". All three `gpt-5.6` models work. The cached model list shows models
    the account can't use, so test before choosing.
  - Among those, `gpt-5.6-sol` is the "workhorse" tier. `gpt-5.6-terra` ("for straightforward
    work") and `gpt-5.6-luna` ("fast and efficient") are lighter. The
    cameras/babymonitor/doorbell boundaries aren't straightforward, and question (b) depends on
    them.
  - `medium` rather than `high`: quota is the binding constraint, and the pilot checks it is enough.
- **Pilot check, decided at the gate and never mid-run.** The pilot measures usage per job.
  - If ~3,035 single jobs on one Plus plan won't fit in a reasonable window, first switch to 20-CVE batches.
  - Only if that still won't fit, drop to `gpt-5.6-terra`, and only after it matches
    `gpt-5.6-sol` on the 40 pilot CVEs at ≥ the measured rerun stability.
  - Record any change as an amendment. A mid-run switch voids the run.
- It's a ChatGPT model, like LLIoT's (o3), but not o3, since Codex doesn't offer it. Say "an
  OpenAI model, as in LLIoT", never "LLIoT's model".

### Prompt: the kit's `AGENTS.md`, generated by `scripts/lliot_build_prompt.py`
Built from `CLASSIFICATION_PROMPT.md` and `categories.csv`, never hand-edited. `--check` fails if
the file on disk is stale. Our rubric can't be copied over as-is, because its framing is
pipeline-specific. The split:

| Rubric section | Treatment | Why |
|---|---|---|
| *What "home IoT device" means* (the 5 criteria) | **verbatim** | The definition under test must be exactly ours |
| *Calibration rules* (Maybe→Low, missing-CPE, companion-app rule) | **verbatim**, minus one bullet | That bullet says "only rows with reasoning get human attention", which is true in the pipeline and false here |
| *Your task* | replaced | It hands the model one category and asks if a keyword match was a "false positive", which presupposes a search step. Now open world: is it home IoT, and which of the 24 categories, most specific first |
| *Blind-judgment principle* | replaced | It concerns other reviewers' columns, and there are none here. Now: use only the given fields; no commands, files or web |
| *Per-category scope* | replaced by **all 24 `scope_note`s inlined verbatim** | The rubric only points at `categories.csv`, which the model can't see. These notes are what separate cameras/babymonitor/doorbell |
| *Output* | replaced | JSON to the schema; `categories` field added; reasoning **always** required, where the pipeline leaves it empty on High |

- **No base-rate prior.** The prompt deliberately does not say "most CVEs are not IoT". That would
  nudge toward `No` and bias the recall Ha2 tests. LLIoT's prompt does carry a
  default-to-negative rule; ours doesn't, and the paper should say so.
- **Input format** (each job's stdin): a JSON array of `{cve_id, description, cpe_strings}`.
  It works unchanged for 1 or 20 CVEs, so the batching decision doesn't change the prompt hash.
- **Rubric-version note:** this uses today's rubric. Some of the pipeline's AI columns were
  collected under the pre-2026-07-02 rubric (review §0.8). Report that as a threat to the
  pipeline-vs-model comparison, not a reason to roll the prompt back.

### Job granularity — decided at the pilot
LLIoT sent one CVE per request; that's part of the method. The pilot runs the same 40 CVEs
singly and as 20-CVE jobs.
- If batched agreement with single ≥ the measured rerun stability, batch at 20.
- Otherwise, run singly.
- Record it as an amendment, and in the paper say whether we deviated from LLIoT here.

### Output schema (`run-kit/schema.json`, generated with the prompt)
`{"results": [ … ]}`, one entry per input CVE: `cve_id`, `home_iot` (Yes/No/Maybe), `categories`
(ordered array, enum of the 24 slugs, first = primary, empty for No), `confidence` (High/Low),
`reasoning` (always one sentence). The slug enum means the model can't invent a category.

### Blindness controls
1. The kit runs outside the repo, with the flags above.
2. Jobs carry only `cve_id, description, cpe_strings`. No stratum, year, pipeline label or LLIoT
   label. Rows are shuffled across strata, so every job mixes them.
3. **Runners never open model outputs.** The driver and validator print pass/fail and counts only,
   because the researcher adjudicates later. When Claude drives the runs in-session, Claude
   never opens `outputs/`, `out/` or `logs/` either: whatever it reads, the adjudicator sees.
   Agreement figures come from `lliot_validate.py --agree`, which prints counts only.

## One-researcher workflow

**Changed 2026-10-25, before the Phase 0 commit, so this is part of the pre-registration, not an
amendment.** The plan was built for two researchers (A = Aarav, B = Suhani) on two Plus plans,
with odd/even job assignment, cross-reruns and two blind adjudicators. It is now **one
researcher, A = Aarav**, on one ChatGPT Plus plan, with `lliot_run.py` driven from a Claude Code
session (long runs in the background). What that changes:

| Was (two people) | Now (one) | Cost to the study |
|---|---|---|
| B reruns the 40 pilot singles; A-vs-B is the stability read | A reruns them (`pilot-rerun`, fresh ephemeral sessions) | Small: same model, effort and prompt either way; a second account added little independence |
| Odd jobs A, even jobs B, two quotas | Every job owned by A, one quota | Quota halves. Batching would cut input ~12× (~31M vs ~2.7M tokens), but the gate rule decides, and it chose single (§ Pilot log), so the sample may need trimming |
| 5% cross-reruns on the other person's plan | 5% reruns, same plan, later fresh sessions | Small, as above |
| Two blind adjudicators, κ, reconciliation | One adjudicator + a **test–retest subsample** (below) | **Real.** No inter-rater check on the ground truth; see § Threats |
| B recomputes headline numbers | Recomputed from raw files in a fresh Claude session | Arithmetic check only; it judges nothing, so no circularity |

**Who must not be the second adjudicator.** Rejected alternatives, recorded so they aren't
reopened: (1) the store's existing human verdicts, made with AI columns visible, which already
contaminates AI-vs-human agreement; (2) Claude, a pipeline reviewer and the author of the rubric
and facet definitions, the same circularity that flattered the 2-rater facet κ.

### Interface contract (as built)
- `manifest.csv`: `cve_id, stratum, order, pilot, seed`, one row per sampled CVE; `order` is the shuffled position jobs are cut from
- `strata.csv`: `stratum, population, sample, weight`, the reweighting table
- `jobs.csv`: `job, set (pilot-single|pilot-batch|pilot-rerun|main|rerun), owner (A), rerun_of, n, cve_ids`
- `outputs/A/<set>/<job>.json`, matching `run-kit/schema.json`
- `run_log_A.csv`: `job, set, owner, started, finished, seconds, model, effort, delivery, exit, retries, valid, input_tokens, cached_input_tokens, output_tokens, reasoning_output_tokens, usage_note`

Every job mixes strata, so run order is never confounded with stratum or category.

### Phases
```
P0  pre-register, freeze schemas, pin LLIoT label extract
P1  scripts built (lliot_build_prompt / sample / run / validate)
P2  pilot: 40 CVEs single + 2 batched (done) + 40 single reruns (pilot-rerun)
    ── gate: throughput, model/effort, batching, final sample; then the Phase 0 commit
P3  run main jobs (unattended)   meanwhile: lliot_compare.py, lliot_analyze.py on pilot + fake data
P4  run the 5% reruns
P5  adjudicate the full sheet blind; ≥ 1 week later, re-adjudicate the test–retest subsample
P6  lliot_analyze.py → results.md; headline numbers recomputed from raw files in a fresh session
```
The analysis scripts are written during P3, while jobs run unattended, which keeps them off the
critical path: P0 → P2 → P3 → P5.

| Phase | Status / what |
|---|---|
| **0. Pre-register** | **Done except the commit:** LLIoT labels pinned in `data/external/lliot/` (MIT; slim extract committed, full table gitignored). After the gate: commit, then record the hash. |
| **1. Build** | **Done** (built by Claude, 2026-10-16; single-owner + `pilot-rerun` + `--agree`, 2026-10-25). The cross-review a second person would have given is not available; A reviews the scripts before the main run. |
| **2. Pilot** | Pilot done 2026-10-16; `pilot-rerun` 2026-10-25. Gate inputs: rerun stability, single-vs-batch agreement, usage-meter readings. |
| **Gate** | Final sample from throughput (priority order above); amend if sizes change |
| **3. Classify** | `run --set main`; glance at the run log for progress and quota, never outputs |
| **4. Stability** | `run --set rerun` (5%, same prompt and plan, fresh sessions) |
| **5. Adjudicate** | Whole sheet, blind. Unresolved rows stay `Maybe`, no tie-breaker (decided 2026-10-16), reported as such. Then the test–retest pass. |
| **6. Analyse** | Run the analysis; recompute the headline numbers independently from raw files |

### The adjudication sheet (P5)

> **AMENDMENT 2026-10-26 — sheet cut to the adjudicator's ~2 hours.** Reason: one adjudicator
> with ~2 h available, against the ~730 rows (~12 h) the design below implies. Decided from
> counts only (model vs pipeline disagreement per stratum, `lliot_compare.py`), before any label
> was seen. Measured: 398 of 3,035 sampled CVEs disagree — 330 on home IoT (N 97, U1 168, Y 40,
> R 11, U2 13, U3 1) and 68 on category only (Y 38, M 18, R 12).
> - **Core, 103 rows, shuffled together:** all 68 category disagreements; 15 agreement controls
>   (both home IoT, same categories, from Y/M/R); 20 of the 168 U1 CVEs the model calls home IoT.
> - **Extension, 310 rows, shuffled:** every other home-IoT disagreement, done in sheet order as
>   far as time allows. Stopping is by time only, never by content, so any completed prefix is a
>   random subsample of the extension and is weighted as such.
> - **Test–retest: 15 core rows** (was 100), ≥ 1 week after the core.
> - **Consequences, stated as limits:** the category question (Hb1, Hb3, Hb4) is answered from
>   every disagreement; Hb2 per-family accuracy mostly falls under n = 10 and is reported pooled;
>   Ha2 recall rests on 20 U1 rows (wide CI); **Ha1 precision is measured only if the extension
>   gets far enough into the N and Y rows**, otherwise reported as not measured. The remainder of
>   this section is the original design, kept for the record.
- **Rows:**
  - every sampled CVE where the model and the pipeline disagree on home IoT **or** on the
    category set (any difference counts), capped at a stratified 600 if there are more
  - **all of M and R**
  - plus 150 agreement controls: 75 Yes-and-same-categories, 75 No (≥ 50 from U3). These catch
    errors both methods share.
- **Shows only** `description`, `cpe_strings`, the rubric and all 24 scope notes. No model label,
  no pipeline label, no stratum, in a shuffled order.
- **Test–retest subsample (replaces inter-rater κ):** a stratified 100 adjudicated rows,
  reshuffled and re-adjudicated blind **≥ 1 week** after the first pass, without access to the
  first-pass sheet. Report test–retest κ on home IoT and on primary category separately. It
  measures the adjudicator's consistency, **not** agreement between people, and is reported as
  such. The first-pass label is the one scored; disagreements are listed, not silently resolved.
- **Columns:**
  - `home_iot (Yes/No/Maybe)`
  - `categories` (ordered, first = primary)
  - `exclusion_reason` (for No: criterion 1–5 / not a device / insufficient info)
  - `notes`
- **Prior-exposure flag:** rows already carrying a human verdict in the store are flagged.
  Report with and without them, since those verdicts were made with AI columns visible.
- **Judge by the written rules only.** Adjudicators see exactly the kit's `AGENTS.md`. When a
  call rests on a precedent that isn't in it (e.g. the recorded rulings Frigate NVR = In, pro
  cameras judged by consumer availability), tag `notes` with `precedent:<ruling>`. The model never
  saw that precedent, so those rows are reported both ways. Otherwise the model is scored against
  rules it was never given.
- **Two-phase estimation:** adjudicated rows are weighted by inverse sampling probability within
  (stratum × agreement pattern). Unadjudicated agreeing rows inherit the control sample's error
  rate for their cell. No row is assumed correct without that correction.

## Metrics (reweighted to the population; 95% CIs by stratified bootstrap)

**(a) Home IoT**
- **Ma1 Precision**, model and pipeline, against adjudicated labels (Ha1).
- **Ma2 Recall**: estimated in-scope total N̂ and each method's share of it (Ha2). Also report it
  next to the Stage-6 capture–recapture recall, an independent check.
- **Ma3 What it gets wrong**: the `exclusion_reason` mix on false positives, and the strata
  where false negatives sit.

**(b) Category**, on human-confirmed Yes only, model and pipeline side by side
- **Mb1 Primary-category accuracy**, **exact-set match**, and mean **Jaccard** of the category
  sets (Hb1).
- **Mb2 Per-family and per-category accuracy**. Leaf categories with n < 10 are reported at
  family level only (Hb2).
- **Mb3 Confusion matrix** over the 24 slugs, plus the share of errors on the pre-named hard
  boundaries (Hb3).
- **Mb4 Routing**: on R, the share where each method's category matches the human one (Hb4).

**Run quality and cost**
- **M5 Stability**: rerun agreement and κ, on home IoT and primary category (H5).
- **M6 Cost**:
  - plan usage per job and person-hours per phase
  - extrapolated to a full 206,834-CVE run, with the assumption stated
  - set against LLIoT's reported €7,604 / 10 h and our review person-hours

## Threats to state up front
- **The pipeline's Codex column was also produced by Codex**, with no recorded model build.
  Errors may correlate, which inflates raw model–pipeline agreement. Every precision, recall and
  accuracy figure rests on human adjudication and is unaffected. Report raw agreement against
  both the pipeline's final labels and its Codex column alone.
- **The pipeline's categories are incomplete as truth.** The design handles this by scoring only
  against humans, and it is also why R exists.
- **One adjudicator, who is the study's own researcher**, and some rows overlap their earlier
  unblinded review. With no second rater there is no inter-rater κ: ground truth is one person's
  reading of the rubric, and an individual bias would pass into every precision, recall and
  accuracy figure unseen. Test–retest κ and the prior-exposure split are the mitigation, and
  they are weaker than the two-adjudicator design they replace (changed 2026-10-25).
- **Category tail:** 3 categories have no confirmed CVEs and 5 have ≤ 3. Category accuracy there
  is unmeasured or family-level only, never a percentage on n=2.
- **Not LLIoT's model, and not their prompt.** That's deliberate given the question. Say so.
- **Rubric drift** in the pipeline's AI columns (review §0.8).
- **Unwritten precedents.** Humans know scope rulings the prompt doesn't carry. The `precedent:`
  tag makes the effect measurable rather than hidden.
- **Window:** 2013–2024 only.
- **Not exactly reproducible:** plan-based runs record no model build. The run logs and the
  prompt hash are the mitigation.

## Files
```
data/external/lliot/          # pinned iot_cls.tsv + SHA-256 (used for stratification only)
data/lliot-comparison/
  manifest.csv
  run-kit/                    # AGENTS.md + schema.json (generated), jobs/ (from lliot_sample.py)
  outputs/A/                  # validated JSON, copied back from the run dir
  run_log_A.csv
  adjudication/{A,A_retest}.csv
  results.md
scripts/lliot_build_prompt.py (done), lliot_sample.py, lliot_run.py, lliot_validate.py,
        lliot_compare.py, lliot_analyze.py
```

## Effort estimate
- **P0:** half a day.
- **P1:** done.
- **P2:** half a day.
- **P3:** ~3,035 jobs if run singly, or ~152 if batched at 20, all on one plan. Unattended, so mostly
  wall-clock time. The pilot measures it.
- **P5:** ~800 rows × ~1 min ≈ 13–14 h, plus ~2 h for the test–retest 100.
  Category labelling makes rows a little slower than a Yes/No call.
- **P6:** 1 day.

## Pinned inputs (recorded 2026-10-16)
LLIoT artifact, `github.com/Tina-Rezaei/LLIoT` HEAD `56ed1d2`, fetched 2026-10-13, MIT License.
**Pinned 2026-10-16 in `data/external/lliot/`** (see its README for full hashes):
- `iot_cls_full.tsv`: full 211,182-row table, 75 MB, gitignored; SHA-256 `9e0ab0a4a385feb2…`
- `lliot_labels.csv`: `cve_id, is_iot, sector`, committed; SHA-256 `2ed3293648be7141…`. The
  sampler reads only this.

## Sample as drawn (2026-10-16, seed 20261016)
All seven base counts matched the plan exactly. **3,035 CVEs** in total.

| Stratum | Population | Sample |
|---|---|---|
| M | 25 | 25 |
| R | 142 | 100 |
| Y (19 per-category sub-strata) | 1,119 | 461 |
| X-consumer / X-other | 25 / 1,720 | 25 / 24 |
| N-consumer / N-other | 271 / 2,339 | 150 / 150 |
| U1 / U2 / U3 | 2,632 / 10,047 / 188,514 | 400 / 200 / 1,500 |

Y per category, census unless capped:

| | | | | | |
|---|---|---|---|---|---|
| cameras 80/574 | hub 60/160 | alarms 40/73 | streaming 40/71 | ev-charging 37 | home-power 31 |
| smartspeakers 31 | doorlock 29 | doorbell 25 | smartplugs 23 | lighting 14 | robotvacuum 12 |
| thermostat 11 | pet 9 | babymonitor 7 | garden 6 | appliances 3 | sensors 2 |
| airconditioner 1 | | | | | |

M and R remove some CVEs first, which is why the Y populations sit below the per-category
confirmed counts above. Pilot: 40 CVEs (Y 10, U3 8, U1 6, N 6, U2 4, M 2, R 2, X 2).

## Pilot log
**A (Aarav), 2026-10-16:** smoke test passed (above). 42/42 pilot jobs valid, 0 retries.

| | Single (40 jobs) | Batched-20 (2 jobs) |
|---|---|---|
| Time per CVE | ~8 s | ~1.9 s |
| Input tokens per CVE | ~10,400 (instructions dominate) | ~900 |
| Output / reasoning tokens per CVE | ~105 / ~31 | ~98 / ~45 |

- **Single vs batched agreement, same 40 CVEs:** home IoT **36/40 (90%)**; primary category
  14/14 where both gave one.
- Usage-meter readings were not recorded for the pilot or its rerun; A records them on the first
  main-run day.
- Agreement figures are now reproducible counts-only: `lliot_validate.py --agree
  outputs/A/pilot-single outputs/A/pilot-batch` gives the 36/40 and 14/14 above.

**B (Suhani), 2026-10-27 — supplementary, cross-account replication.** Run on B's own Plus
account and machine under the original two-person pilot (pushed as `3e7e97d` after the
one-researcher change, which had not yet been pushed). 42/42 valid, Codex 0.151.0,
`gpt-5.6-sol` @ medium. **These outputs never enter the analysis** (pilot rule); they bear only
on the method.
- **Cross-account stability (A single vs B single):** home IoT **39/40 (97.5%)**, primary
  category **15/16 (93.8%)** — identical to A's same-account rerun, so the 97.4% main-run
  stability is not an artefact of one account or machine.
- **Batching, second replicate (B single vs B batched-20):** home IoT 37/40 (92.5%), primary
  14/15. Pooled with A: **73/80 (91%)**, below stability in both replicates. Under the original
  rule (batch only if batched agreement ≥ cross-account stability) the gate decision is the
  same: single.
- **Smoke/canary on a second machine:** AGENTS.md loaded, web search off, outside-file read
  failed closed, no `~/.codex/AGENTS.md`. **Discrepancy, recorded:** B's session listed
  `functions.exec` and collaboration tools, which A's did not. The canary still failed closed.
  No main-run job ran on B's machine; resolve this before any further run there.
- No usage-meter reading (the usage screen was unavailable); token totals are in
  `run_log_B.csv`.

**A, pilot rerun (2026-10-25):** the 40 single jobs again, fresh sessions (`pilot-rerun`),
replacing B's pilot. 40/40 valid, 0 retries, ~4.4 s/job, ~10,440 input tokens/job.
- **Rerun stability (single vs single):** home IoT **39/40 (97.5%)**; primary category **15/16
  (93.8%)** where both gave one. Both clear H5's thresholds (90% / 85%) on the pilot.
- **Gate rule applied:** batched-vs-single agreement (90%) is **below** rerun stability (97.5%),
  so the pre-registered rule says **run singly** (`--size 1`). Note the margin is 4 vs 1
  disagreements on n=40; the rule is followed as written, not re-argued after seeing the data.

**Quota measurement (2026-10-25), first 100 main jobs:** 100/100 valid, 0 retries, ~4.3 s/job,
~10,500 input tokens/job. ChatGPT usage page: 5-hour limit 94% → 86% left (**~8% per 100 jobs**,
so ~1,250 jobs per 5-hour window); weekly 98% → 97% left (**~1% per 100**, rounded, so the
remaining ~3,087 jobs need roughly 15–45% of a week).
- **Gate decision: the full sample (3,035 + 152 reruns) runs, untrimmed**, at `--size 1`,
  across ~3 five-hour windows, each run capped with `--limit` below the 5-hour cap.
- **Deviation, disclosed:** these 100 main jobs ran before the Phase 0 commit, to measure quota.
  Their prompt, model and job files are the pre-registered ones, and no output was opened.

**Main run log (2026-10-25/26):**
- Jobs 1–1,000: 2 workers, 0 failures.
- After the 5-hour reset, a 1,100-job batch got 407 **HTTP 429 Too Many Requests** (spread
  evenly, 2–3 s each, no output). A one-worker retry recovered only 142 of them (steady ~35%
  success). Quota was not the cause: 43% of the 5-hour and 91% of the weekly limit were left.
  Usage for the 835 successful jobs in that window: ~57% of 5-hour, ~9% weekly.
- A 429'd job never reaches the model and leaves no output, and throttling is by timing, not
  CVE content, so retrying them introduces no selection bias.
- State at pause: **1,835 / 3,035 main jobs valid**; 265 failed (to retry) + 935 not started +
  152 reruns = 1,352 jobs left, about one 5-hour window at ~7% per 100.
- Resumed 2026-10-26 after adding 429 backoff to `lliot_run.py` (`BACKOFF_S` 60/120/240/480 s,
  not counted as the job's one retry; driver only, no pre-registered hash changes). 20-job test
  clean, then the remaining 1,180 at 1 worker, 14:44–16:09: 0 failures, 0 backoff waits.
- **Main run complete: 3,035 / 3,035 valid.** Reruns: **152 / 152 valid.**
- **M5 stability (P4, 5% reruns):** home IoT **148/152 (97.4%)**; primary category **24/25
  (96.0%)** where both gave one. H5 thresholds (90% / 85%) met; consistent with the pilot's 97.5%.

## Pre-registration
- Commit hash: `db8757f` (committed 2026-10-25 as `559bcf1`; rebased unchanged onto `3e7e97d` before its first push, 2026-10-28)
- Prompt (`run-kit/AGENTS.md`) SHA-256: `8d5c8319d48bf99c41590a042f0482af5167641a4ed86edc6de228d32cf5713b`
- Schema (`run-kit/schema.json`) SHA-256: `d69a99b032842c42bf4879f3d9643252d34db8d8ebbd2139d768fce28fd37692`
  - Both as generated 2026-10-16. Rerun `lliot_build_prompt.py --check` at Phase 0. A changed
    hash means the rubric or scope notes moved, which needs an amendment.
- Codex CLI version: 0.151.0 · model: `gpt-5.6-sol` · reasoning effort: `medium` (confirm at the gate)
- Job granularity: **single** (gate rule, 2026-10-25: batched 90% < rerun stability 97.5%). Cut 2026-10-25: 3,035 main jobs + 152 reruns.
- Seed: `20261016`
- Tie-breaker: none. Unresolved rows stay `Maybe`.
- Researchers: one (A = Aarav), one ChatGPT Plus plan; one adjudicator + test–retest subsample of 100 (2026-10-25)
- Job preamble (`run-kit/job_preamble.txt`) SHA-256: `35c9e30ec3ad3c1eb56881ae58def20151a7e3308cbe17024819fc3e79e69fbf`
