# LLIoT-method experiment: how to run it

Design: `docs/plans/PLAN_lliot_method_comparison.md`. **One researcher, A = Aarav** (changed
2026-10-25; the plan was originally two-person). You need this repo, Python 3, and the Codex CLI
signed in to your ChatGPT Plus account. You do **not** need the NVD snapshot: job files are
already cut. Runs can be driven from a Claude Code session; long ones go in the background.

## Rules (the run is worthless without these)
- **Never open** anything under `outputs/`, or `out/` / `logs/` in the run dir. You adjudicate
  these CVEs blind later. The scripts print only ok/FAILED, counts and timings. If Claude drives
  the run, the same rule binds Claude: anything it reads, you see.
- Run only through `scripts/lliot_run.py`. It pins the model (`gpt-5.6-sol`, `medium`), verifies
  the prompt hashes, and switches off every tool. Never run Codex on these jobs by hand.
- The run dir must be **outside** this repo and outside any git repo. `setup` refuses otherwise.

## Steps (1–4 done 2026-10-16)
```
# 1. one-time: create the run dir and copy in the kit + jobs (rerun to sync new jobs)
python3 scripts/lliot_run.py setup --owner A --run-dir ~/lliot-run

# 2. smoke test: must print "AGENTS.md loaded: YES", answer NO to web search, and list no
#    shell/exec_command tool
python3 scripts/lliot_run.py smoke --run-dir ~/lliot-run

# 3. pilot: 40 single + 2 batched, then the 40 singles again for rerun stability
python3 scripts/lliot_run.py run --run-dir ~/lliot-run --set pilot-single --workers 2
python3 scripts/lliot_run.py run --run-dir ~/lliot-run --set pilot-batch  --workers 2
python3 scripts/lliot_run.py run --run-dir ~/lliot-run --set pilot-rerun  --workers 2

# 4. copy validated outputs into the repo, then commit outputs/A/ and run_log_A.csv
python3 scripts/lliot_run.py collect --run-dir ~/lliot-run

# 5. gate inputs, counts only (never a label)
python3 scripts/lliot_validate.py --agree data/lliot-comparison/outputs/A/pilot-single data/lliot-comparison/outputs/A/pilot-rerun
python3 scripts/lliot_validate.py --agree data/lliot-comparison/outputs/A/pilot-single data/lliot-comparison/outputs/A/pilot-batch
```
On the first main-run day, note the Codex usage meter (ChatGPT → Codex usage) before and after,
and write both readings into `usage_note` on that day's last row of `run_log_A.csv`. That is how
we learn whether the run fits in one Plus allowance.

After the gate, cut the main jobs (`lliot_sample.py jobs --size N`). Then:
```
python3 scripts/lliot_run.py setup --owner A --run-dir ~/lliot-run   # syncs the new jobs
python3 scripts/lliot_run.py run --run-dir ~/lliot-run --set main --workers 2
python3 scripts/lliot_run.py run --run-dir ~/lliot-run --set rerun --workers 2
python3 scripts/lliot_run.py collect --run-dir ~/lliot-run
```
`run` is resumable: if it stops (quota, sleep, network), run the same command again. It skips
finished jobs and retries failed ones. Transient OpenAI 503s happen. A job that still fails after
its retry is logged with `valid=no`; rerunning picks it up.

## Files
| Path | What |
|---|---|
| `manifest.csv`, `strata.csv`, `jobs.csv` | sample, stratum weights, job list (sampler output) |
| `run-kit/` | generated: `AGENTS.md`, `schema.json`, `job_preamble.txt` (hash-pinned), `jobs/` |
| `outputs/A/`, `run_log_A.csv` | validated outputs and run log |
| `outputs/B/`, `run_log_B.csv` | Suhani's pilot (2026-10-27): supplementary cross-account replication, never analysed |

## Adjudication (P5)
`python3 scripts/lliot_compare.py` built the sheets (once; it refuses to redraw). Then:
- **`adjudication/sheet_A.csv`**: do **R001–R103** (the core, ~2 h). Rows after R103 are optional;
  keep going in order for as long as you have time and stop whenever. Never skip around or pick
  rows by content.
- Judge with **`run-kit/AGENTS.md`**, the same rules the model got. For each row fill:
  `home_iot` (Yes/No/Maybe) · `categories` (slugs, most specific first, `|`-separated, empty for
  No) · `exclusion_reason` (for No: criterion 1–5 / not a device / insufficient info) · `notes`
  (tag `precedent:<ruling>` when a call rests on a ruling not in AGENTS.md).
- **`adjudication/retest_A.csv`**: 15 rows. Do it **on or after 2026-11-02**, without looking at
  your sheet_A answers.
- **Never open `adjudication/_key.csv`.** It maps rows to CVEs and says which way the methods
  disagreed.
