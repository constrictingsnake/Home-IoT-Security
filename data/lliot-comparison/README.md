# LLIoT-method experiment: how to run your half

Design: `docs/plans/PLAN_lliot_method_comparison.md`. Researcher **A = Aarav**, **B = Suhani**.
You only need this repo, Python 3, and the Codex CLI signed in to your own ChatGPT Plus account.
You do **not** need the NVD snapshot: job files are already cut.

## Rules (the run is worthless without these)
- **Never open** anything under `outputs/`, or `out/` / `logs/` in your run dir. You adjudicate
  these CVEs blind later. The scripts print only ok/FAILED, counts and timings.
- Run only through `scripts/lliot_run.py`. It pins the model (`gpt-5.6-sol`, `medium`), verifies
  the prompt hashes, and switches off every tool. Never run Codex on these jobs by hand.
- The run dir must be **outside** this repo and outside any git repo. `setup` refuses otherwise.

## Steps (replace `B` with your letter; A is already done through step 4)
```
# 1. one-time: create your run dir and copy in the kit + your jobs
python3 scripts/lliot_run.py setup --owner B --run-dir ~/lliot-run

# 2. smoke test: must print "AGENTS.md loaded: YES", answer NO to web search, and list no
#    shell/exec_command tool. If the model is refused on your account, stop and tell Aarav.
python3 scripts/lliot_run.py smoke --run-dir ~/lliot-run

# 3. pilot: the same 42 jobs Aarav ran (40 single + 2 batched)
python3 scripts/lliot_run.py run --run-dir ~/lliot-run --set pilot-single --workers 2
python3 scripts/lliot_run.py run --run-dir ~/lliot-run --set pilot-batch  --workers 2

# 4. copy validated outputs into the repo, then commit outputs/B/ and run_log_B.csv
python3 scripts/lliot_run.py collect --run-dir ~/lliot-run
```
Before step 3, note your Codex usage meter (ChatGPT → Codex usage). Note it again after, and
write both readings into `usage_note` on your last pilot row of `run_log_B.csv`. That is how the
gate learns whether ~1,550 jobs fit in a Plus allowance.

After the gate, Aarav cuts the main jobs (`lliot_sample.py jobs --size N`). Then:
```
python3 scripts/lliot_run.py setup --owner B --run-dir ~/lliot-run   # syncs the new jobs
python3 scripts/lliot_run.py run --run-dir ~/lliot-run --set main --workers 2
python3 scripts/lliot_run.py run --run-dir ~/lliot-run --set rerun --workers 2
python3 scripts/lliot_run.py collect --run-dir ~/lliot-run
```
`run` is resumable: if it stops (quota, sleep, network), run the same command again. It skips
finished jobs and retries failed ones. Transient OpenAI 503s happen. A job that still fails after
its retry is logged with `valid=no`; rerunning picks it up.

## Files
| Path | Owner | What |
|---|---|---|
| `manifest.csv`, `strata.csv`, `jobs.csv` | sampler | sample, stratum weights, job→owner |
| `run-kit/` | generated | `AGENTS.md`, `schema.json`, `job_preamble.txt` (hash-pinned), `jobs/` |
| `outputs/A/`, `run_log_A.csv` | A | A's validated outputs and run log |
| `outputs/B/`, `run_log_B.csv` | B | B's validated outputs and run log |
