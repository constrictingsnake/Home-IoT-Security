#!/usr/bin/env python3
"""Driver for the LLIoT-method experiment: runs `codex exec` over one researcher's jobs.

docs/plans/PLAN_lliot_method_comparison.md § The model and the run kit. Each job is one fresh,
ephemeral Codex process in a run dir OUTSIDE any git repo, so the only instructions it can load
are the kit's generated AGENTS.md (never this repo's reviewer AGENTS.md).

Commands, in the order a researcher uses them:
  setup    create/sync the run dir: kit files (hash-checked) + this owner's job files
  smoke    one non-classification call: does the session see the kit's AGENTS.md, which tools
           does it have, is web search off? Prints the reply (it contains no CVE labels).
  run      run every not-yet-done job in a set (pilot-single | pilot-batch | pilot-rerun |
           main | rerun);
           resumable, one retry on failure, appends to data/lliot-comparison/run_log_<owner>.csv
  collect  validate outputs and copy the valid ones into data/lliot-comparison/outputs/<owner>/

BLINDNESS: nothing here prints a model label. Model output and event logs stay in the run dir
(out/, logs/); do not open them — the researcher adjudicates these CVEs later.

Usage:
    python3 scripts/lliot_run.py setup   --owner A --run-dir ~/lliot-run
    python3 scripts/lliot_run.py smoke   --run-dir ~/lliot-run
    python3 scripts/lliot_run.py run     --run-dir ~/lliot-run --set pilot-single
    python3 scripts/lliot_run.py collect --run-dir ~/lliot-run
"""
import argparse
import concurrent.futures
import csv
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lliot_validate import validate_output  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXP = os.path.join(ROOT, "data", "lliot-comparison")
KIT = os.path.join(EXP, "run-kit")

# Pre-registered (plan § Pre-registration). A run refuses to start if the kit doesn't match.
MODEL = "gpt-5.6-sol"
EFFORT = "medium"
KIT_SHA256 = {
    "AGENTS.md": "8d5c8319d48bf99c41590a042f0482af5167641a4ed86edc6de228d32cf5713b",
    "schema.json": "d69a99b032842c42bf4879f3d9643252d34db8d8ebbd2139d768fce28fd37692",
    "job_preamble.txt": "35c9e30ec3ad3c1eb56881ae58def20151a7e3308cbe17024819fc3e79e69fbf",
}
INSTRUCTIONS_HEADING = "# Instructions — home IoT CVE classification"
# Tools the classifier must not have (verified by `smoke`). The read-only sandbox blocks writes
# but not reads, so a shell could read this repo's judgments; blindness must be structural.
DISABLE = ["shell_tool", "unified_exec", "shell_snapshot", "code_mode_host", "multi_agent",
           "image_generation", "view_image", "apps", "plugins", "browser_use",
           "browser_use_external", "in_app_browser", "computer_use", "tool_suggest",
           "skill_search", "goals", "hooks"]
TIMEOUT_S = 900
SETS = ("pilot-single", "pilot-batch", "pilot-rerun", "main", "rerun")
LOG_FIELDS = ["job", "set", "owner", "started", "finished", "seconds", "model", "effort",
              "delivery", "exit", "retries", "valid", "input_tokens", "cached_input_tokens",
              "output_tokens", "reasoning_output_tokens", "usage_note"]
_lock = threading.Lock()


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def die(msg):
    sys.exit(f"STOP: {msg}")


def check_outside_repo(run_dir):
    real = os.path.realpath(run_dir)
    if real == os.path.realpath(ROOT) or real.startswith(os.path.realpath(ROOT) + os.sep):
        die(f"{run_dir} is inside this repo. The run dir must be outside it.")
    p = subprocess.run(["git", "-C", real, "rev-parse", "--is-inside-work-tree"],
                       capture_output=True, text=True)
    if p.returncode == 0 and p.stdout.strip() == "true":
        die(f"{run_dir} is inside a git work tree. Codex would load AGENTS.md files from it.")


def check_kit(where):
    for name, want in KIT_SHA256.items():
        path = os.path.join(where, name)
        if not os.path.exists(path):
            die(f"{path} missing")
        if sha(path) != want:
            die(f"{path} does not match the pre-registered hash. Regenerate with "
                "lliot_build_prompt.py, or amend the pre-registration deliberately.")


def owner_of(run_dir):
    p = os.path.join(run_dir, ".lliot_owner")
    if not os.path.exists(p):
        die(f"{run_dir} is not set up; run `setup` first")
    return open(p).read().strip()


def load_jobs():
    path = os.path.join(EXP, "jobs.csv")
    if not os.path.exists(path):
        die("data/lliot-comparison/jobs.csv missing; run lliot_sample.py jobs first")
    return list(csv.DictReader(open(path, encoding="utf-8")))


def my_jobs(owner, which=None):
    return [j for j in load_jobs()
            if j["owner"] in (owner, "both") and (which is None or j["set"] == which)]


def job_src(job):
    sub = "pilot" if job["set"].startswith("pilot") else "main"
    return os.path.join(KIT, "jobs", sub, job["job"] + ".json")


# ---------------------------------------------------------------- setup
def cmd_setup(a):
    run_dir = os.path.expanduser(a.run_dir)
    os.makedirs(run_dir, exist_ok=True)
    check_outside_repo(run_dir)
    check_kit(KIT)
    op = os.path.join(run_dir, ".lliot_owner")
    if os.path.exists(op) and open(op).read().strip() != a.owner:
        die(f"{run_dir} belongs to owner {open(op).read().strip()}, not {a.owner}")
    with open(op, "w") as f:
        f.write(a.owner + "\n")
    for name in KIT_SHA256:
        shutil.copy2(os.path.join(KIT, name), os.path.join(run_dir, name))
    n = 0
    for j in my_jobs(a.owner):
        dst = os.path.join(run_dir, "jobs", j["set"], j["job"] + ".json")
        if not os.path.exists(dst):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(job_src(j), dst)
            n += 1
    check_kit(run_dir)
    print(f"Run dir {run_dir} ready for owner {a.owner}: kit verified, {n} new job files copied.")


# ---------------------------------------------------------------- codex call
def codex_cmd(run_dir, out_path, schema=True):
    cmd = ["codex", "exec", "--ephemeral", "--ignore-user-config", "--ignore-rules",
           "--skip-git-repo-check", "-C", run_dir, "-s", "read-only",
           "-m", MODEL, "-c", f"model_reasoning_effort={EFFORT}", "-c", 'web_search="disabled"',
           "--json", "-o", out_path]
    for feat in DISABLE:
        cmd += ["--disable", feat]
    if schema:
        cmd += ["--output-schema", os.path.join(run_dir, "schema.json")]
    return cmd + ["-"]


def usage_from_events(text):
    """Last-seen token counts in codex --json events (cumulative), without reading any content."""
    keys = ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens")
    found = {}

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in keys and isinstance(v, int):
                    found[k] = v
                else:
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    for line in text.splitlines():
        try:
            walk(json.loads(line))
        except ValueError:
            pass
    return found


def cmd_smoke(a):
    run_dir = os.path.expanduser(a.run_dir)
    check_outside_repo(run_dir)
    check_kit(run_dir)
    out = os.path.join(run_dir, "smoke.txt")
    prompt = ("This is a setup check, not a classification task. Do not run any tool or command. "
              "Answer in plain text:\n"
              "1. Quote verbatim the first markdown heading of the AGENTS.md instructions you were "
              "given, or write NONE if you were given no AGENTS.md.\n"
              "2. List every tool available to you in this session, by name.\n"
              "3. Can any of those tools search the web or fetch URLs? Answer YES or NO.\n")
    p = subprocess.run(codex_cmd(run_dir, out, schema=False), input=prompt, text=True,
                       capture_output=True, timeout=TIMEOUT_S)
    reply = open(out, encoding="utf-8").read() if os.path.exists(out) else ""
    print(f"exit={p.returncode}\n--- reply ---\n{reply}\n-------------")
    if p.returncode != 0:  # errors arrive as --json events on stdout, not on stderr
        errs = [l for l in p.stdout.splitlines() if '"error"' in l]
        print("\n".join(errs[-3:])[-2000:] or p.stderr[-2000:])
    ok = INSTRUCTIONS_HEADING in reply
    print("AGENTS.md loaded:", "YES" if ok else "NO -> use `run --inline-instructions`")
    print("Check the tool list and the web-search answer above by eye; record both in the run log notes.")


# ---------------------------------------------------------------- run
def append_log(owner, row):
    path = os.path.join(EXP, f"run_log_{owner}.csv")
    with _lock:
        new = not os.path.exists(path)
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=LOG_FIELDS)
            if new:
                w.writeheader()
            w.writerow(row)


def run_one(run_dir, owner, job, inline):
    jpath = os.path.join(run_dir, "jobs", job["set"], job["job"] + ".json")
    out = os.path.join(run_dir, "out", job["set"], job["job"] + ".json")
    logp = os.path.join(run_dir, "logs", job["set"], job["job"] + ".jsonl")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    os.makedirs(os.path.dirname(logp), exist_ok=True)
    stdin = open(os.path.join(run_dir, "job_preamble.txt"), encoding="utf-8").read()
    stdin += open(jpath, encoding="utf-8").read()
    if inline:
        stdin = open(os.path.join(run_dir, "AGENTS.md"), encoding="utf-8").read() + "\n\n" + stdin
    started = time.time()
    retries, code, errs, usage = 0, None, ["not run"], {}
    for attempt in range(2):
        if os.path.exists(out):
            os.remove(out)
        try:
            p = subprocess.run(codex_cmd(run_dir, out), input=stdin, text=True,
                               capture_output=True, timeout=TIMEOUT_S)
            code = p.returncode
            with open(logp, "w", encoding="utf-8") as f:
                f.write(p.stdout)
            usage = usage_from_events(p.stdout)
        except subprocess.TimeoutExpired:
            code = "timeout"
        errs = validate_output(jpath, out)
        if code == 0 and not errs:
            break
        retries = attempt + 1 if attempt == 0 else retries
    finished = time.time()
    row = {"job": job["job"], "set": job["set"], "owner": owner,
           "started": dt.datetime.fromtimestamp(started).isoformat(timespec="seconds"),
           "finished": dt.datetime.fromtimestamp(finished).isoformat(timespec="seconds"),
           "seconds": round(finished - started), "model": MODEL, "effort": EFFORT,
           "delivery": "inline" if inline else "agents-md", "exit": code, "retries": retries,
           "valid": "yes" if not errs else "no", "usage_note": "" if not errs else errs[0][:120]}
    row.update({k: usage.get(k, "") for k in LOG_FIELDS if k.endswith("tokens")})
    append_log(owner, row)
    return job["job"], not errs, round(finished - started)


def cmd_run(a):
    run_dir = os.path.expanduser(a.run_dir)
    check_outside_repo(run_dir)
    check_kit(run_dir)
    check_kit(KIT)
    owner = owner_of(run_dir)
    todo = []
    for j in my_jobs(owner, a.set):
        out = os.path.join(run_dir, "out", j["set"], j["job"] + ".json")
        jp = os.path.join(run_dir, "jobs", j["set"], j["job"] + ".json")
        if not os.path.exists(jp):
            die(f"{jp} missing; rerun `setup` to sync job files")
        if os.path.exists(out) and not validate_output(jp, out):
            continue  # done and valid
        todo.append(j)
    if a.limit:
        todo = todo[:a.limit]
    print(f"owner {owner}, set {a.set}: {len(todo)} jobs to run "
          f"(model {MODEL}, effort {EFFORT}, workers {a.workers})")
    ok = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(run_one, run_dir, owner, j, a.inline_instructions) for j in todo]
        for i, f in enumerate(concurrent.futures.as_completed(futs), 1):
            name, good, secs = f.result()
            ok += good
            print(f"  [{i}/{len(todo)}] {name}: {'ok' if good else 'FAILED'} ({secs}s)", flush=True)
    print(f"{ok}/{len(todo)} valid. Failures are logged in run_log_{owner}.csv; rerun to retry them.")


# ---------------------------------------------------------------- collect
def cmd_collect(a):
    run_dir = os.path.expanduser(a.run_dir)
    owner = owner_of(run_dir)
    copied = bad = 0
    for j in my_jobs(owner):
        out = os.path.join(run_dir, "out", j["set"], j["job"] + ".json")
        jp = os.path.join(run_dir, "jobs", j["set"], j["job"] + ".json")
        if not os.path.exists(out):
            continue
        if validate_output(jp, out):
            bad += 1
            continue
        dst = os.path.join(EXP, "outputs", owner, j["set"], j["job"] + ".json")
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(out, dst)
        copied += 1
    print(f"Copied {copied} valid outputs into data/lliot-comparison/outputs/{owner}/ "
          f"({bad} invalid left in the run dir).")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup")
    s.add_argument("--owner", required=True, choices=["A"])  # one researcher since 2026-10-25
    s.add_argument("--run-dir", required=True)
    s = sub.add_parser("smoke")
    s.add_argument("--run-dir", required=True)
    s = sub.add_parser("run")
    s.add_argument("--run-dir", required=True)
    s.add_argument("--set", required=True, choices=SETS)
    s.add_argument("--limit", type=int, help="run at most N jobs this time")
    s.add_argument("--workers", type=int, default=1, help="parallel codex processes (default 1)")
    s.add_argument("--inline-instructions", action="store_true",
                   help="prepend AGENTS.md to stdin (only if `smoke` showed it isn't loaded)")
    s = sub.add_parser("collect")
    s.add_argument("--run-dir", required=True)
    a = ap.parse_args()
    {"setup": cmd_setup, "smoke": cmd_smoke, "run": cmd_run, "collect": cmd_collect}[a.cmd](a)


if __name__ == "__main__":
    main()
