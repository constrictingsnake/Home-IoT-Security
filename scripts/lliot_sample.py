#!/usr/bin/env python3
"""Sampler for the LLIoT-method experiment (docs/plans/PLAN_lliot_method_comparison.md).

Two steps, run in order:

  sample   Compute every in-window CVE's pipeline status, partition the population into the
           plan's strata, draw the seeded sample, pick the 40 pilot CVEs.
           -> data/lliot-comparison/manifest.csv   (cve_id, stratum, order, pilot, seed)
           -> data/lliot-comparison/strata.csv     (stratum, population, sample) — the weights
  jobs     Cut the manifest into job files once the pilot gate has fixed the job size, assign
           owners (odd jobs A, even jobs B), pick the 5% cross-reruns.
           -> data/lliot-comparison/run-kit/jobs/{main,pilot}/*.json
           -> data/lliot-comparison/jobs.csv        (job, set, owner, rerun_of, n, cve_ids)

Population: nvd_all.csv, published 2013-2024, REJECTED removed. Pipeline status per CVE:
  yes        a non-excluded store row with Final Judgment Yes
  excluded   only tvOS-excluded Yes rows
  no         reviewed, and neither of the above
  not-surfaced  in no search output and not in the store
A CVE in a search output but not in the store stops the script: that needs a decision first.

Strata are assigned in the order M -> R -> Y -> X -> N -> U, each from what earlier strata left,
so they partition the population and every estimate can be reweighted by population/sample.

Job files carry only cve_id, description, cpe_strings. The stratum never reaches the model.

Usage:
    python3 scripts/lliot_sample.py sample
    python3 scripts/lliot_sample.py jobs --size 1      # or --size 20, per the pilot gate
    python3 scripts/lliot_sample.py jobs --pilot-only  # just the pilot job files
"""
import argparse
import collections
import csv
import glob
import json
import os
import random
import sys

csv.field_size_limit(10**9)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NVD = os.path.join(ROOT, "data", "nvd-snapshot", "nvd_all.csv")
STORE = os.path.join(ROOT, "data", "difference", "judgment_store.csv")
LLIOT = os.path.join(ROOT, "data", "external", "lliot", "lliot_labels.csv")
OUT = os.path.join(ROOT, "data", "lliot-comparison")
KIT = os.path.join(OUT, "run-kit")

SEED = 20261016
WINDOW = (2013, 2024)

# Base cells measured 2026-10-16 (plan § Population and sample). Drift > 1% stops the sampler.
EXPECTED = {"population": 206834, "yes": 1274, "no": 2621, "excluded": 1746,
            "not-surfaced:consumer": 2632, "not-surfaced:iot-other": 10047,
            "not-surfaced:rest": 188514}

# Y: categories with <= 40 confirmed CVEs are a census; the four big ones are capped.
Y_CAPS = {"cameras": 80, "hub": 60, "alarms": 40, "streaming": 40}
Y_CENSUS_MAX = 40
R_CAP = 100
# The 11 known misroutes, LLIOT_COMPARISON_REVIEW.md §6.4 (camera-type devices judged No under
# another category and never reviewed under the right one).
KNOWN_MISROUTES = ["CVE-2024-48214", "CVE-2018-19588", "CVE-2019-9657", "CVE-2018-7661",
                   "CVE-2024-31408", "CVE-2024-39290", "CVE-2020-10176", "CVE-2019-7728",
                   "CVE-2019-7729", "CVE-2018-20161", "CVE-2023-6913"]
SIZES = {"N-consumer": 150, "N-other": 150, "X-other": 24,
         "U1": 400, "U2": 200, "U3": 1500}
# Pilot: 40 CVEs spread over the strata, so the batching/stability read isn't all-No.
PILOT = {"Y": 10, "M": 2, "R": 2, "N": 6, "X": 2, "U1": 6, "U2": 4, "U3": 8}
RERUN_SHARE = 0.05


def is_rejected(desc):
    return desc.startswith("** REJECT") or "Rejected reason" in desc[:40]


def load_population():
    pop = {}
    for r in csv.DictReader(open(NVD, encoding="utf-8")):
        y = r["published"][:4]
        if y.isdigit() and WINDOW[0] <= int(y) <= WINDOW[1] and not is_rejected(r["description"]):
            pop[r["cve_id"]] = r
    return pop


def load_status(pop):
    rows = list(csv.DictReader(open(STORE, encoding="utf-8")))
    yes_cats = collections.defaultdict(set)
    verdicts = collections.defaultdict(dict)
    excl = set()
    for r in rows:
        c = r["cve_id"]
        verdicts[c][r["category"]] = r["Final Judgment"]
        if r["Excluded"]:
            excl.add(c)
        elif r["Final Judgment"] == "Yes":
            yes_cats[c].add(r["category"])
    surfaced = set()
    for f in (glob.glob(os.path.join(ROOT, "data", "keyword-search", "keyword_*.csv")) +
              glob.glob(os.path.join(ROOT, "data", "vendor-search", "results_all_*.csv"))):
        base = os.path.basename(f)
        if "candidates" in base or "terms" in base or "gameconsoles" in base:
            continue
        surfaced |= {r["cve_id"] for r in csv.DictReader(open(f, encoding="utf-8"))}

    status = {}
    for c in pop:
        if c in yes_cats:
            status[c] = "yes"
        elif c in excl:
            status[c] = "excluded"
        elif c in verdicts:
            status[c] = "no"
        elif c in surfaced:
            status[c] = "surfaced-unreviewed"
        else:
            status[c] = "not-surfaced"
    return status, yes_cats, verdicts


def load_lliot():
    ll = {}
    for r in csv.DictReader(open(LLIOT, encoding="utf-8")):
        if r["is_iot"] == "true":
            ll[r["cve_id"]] = "consumer" if r["sector"] == "consumer iot" else "iot-other"
        else:
            ll[r["cve_id"]] = "noniot"
    return ll


def check_drift(pop, status, ll):
    cnt = collections.Counter(status.values())
    if cnt.get("surfaced-unreviewed"):
        sys.exit(f"STOP: {cnt['surfaced-unreviewed']} in-window CVEs are in a search output but "
                 "not in the store. Decide how to treat them before sampling (plan § Population).")
    got = {"population": len(pop), "yes": cnt["yes"], "no": cnt["no"], "excluded": cnt["excluded"]}
    ns = collections.Counter(ll.get(c, "noniot") if ll.get(c) != "noniot" else "rest"
                             for c in pop if status[c] == "not-surfaced")
    got["not-surfaced:consumer"] = ns["consumer"]
    got["not-surfaced:iot-other"] = ns["iot-other"]
    got["not-surfaced:rest"] = ns["rest"] + ns["noniot"]
    bad = []
    for k, exp in EXPECTED.items():
        print(f"  {k:24s} expected {exp:7d}  got {got[k]:7d}")
        if abs(got[k] - exp) > 0.01 * exp:
            bad.append(k)
    if bad:
        sys.exit(f"STOP: counts drifted > 1% from the plan for {bad}. Amend the plan first.")


def assign_strata(pop, status, yes_cats, verdicts, ll, rng):
    """Return {cve_id: stratum} for sampled CVEs and {stratum: population} for weights."""
    remaining = set(pop)
    population, sample = {}, {}

    def take(name, members, n=None, must=()):
        members = sorted(members & remaining)
        population[name] = len(members)
        chosen = set(must) & set(members)
        rest = [c for c in members if c not in chosen]
        k = len(rest) if n is None else max(0, min(len(rest), n - len(chosen)))
        chosen |= set(rng.sample(rest, k))
        for c in chosen:
            sample[c] = name
        remaining.difference_update(members)  # the whole cell leaves the pool, sampled or not

    # M: confirmed in >1 category (census)
    take("M", {c for c, s in yes_cats.items() if len(s) > 1})
    # R: reviewed under >1 category with split verdicts, plus the known misroutes (always kept)
    split = {c for c, v in verdicts.items() if len(v) > 1 and len(set(v.values())) > 1}
    take("R", split | set(KNOWN_MISROUTES), n=R_CAP, must=KNOWN_MISROUTES)
    # Y: confirmed, one category, category-balanced (each category is its own sub-stratum)
    by_cat = collections.defaultdict(set)
    for c, s in yes_cats.items():
        if c in remaining and status.get(c) == "yes":
            by_cat[next(iter(s))].add(c)
    for cat in sorted(by_cat):
        cap = Y_CAPS.get(cat)
        if cap is None and len(by_cat[cat]) > Y_CENSUS_MAX:
            sys.exit(f"STOP: {cat} has {len(by_cat[cat])} confirmed CVEs but no cap in Y_CAPS")
        take(f"Y:{cat}", by_cat[cat], n=cap)
    # X: tvOS-excluded; every LLIoT-consumer one, plus 24 others
    x = {c for c in remaining if status[c] == "excluded"}
    take("X-consumer", {c for c in x if ll.get(c) == "consumer"})
    take("X-other", x, n=SIZES["X-other"])
    # N: rejected everywhere
    nn = {c for c in remaining if status[c] == "no"}
    take("N-consumer", {c for c in nn if ll.get(c) == "consumer"}, n=SIZES["N-consumer"])
    take("N-other", nn, n=SIZES["N-other"])
    # U: never surfaced
    u = {c for c in remaining if status[c] == "not-surfaced"}
    take("U1", {c for c in u if ll.get(c) == "consumer"}, n=SIZES["U1"])
    take("U2", {c for c in u if ll.get(c) == "iot-other"}, n=SIZES["U2"])
    take("U3", u, n=SIZES["U3"])
    if remaining:
        sys.exit(f"STOP: {len(remaining)} CVEs fell into no stratum (bug)")
    return sample, population


def cmd_sample(args):
    rng = random.Random(SEED)
    print("Loading snapshot, store, search outputs, LLIoT labels ...")
    pop = load_population()
    status, yes_cats, verdicts = load_status(pop)
    ll = load_lliot()
    print("Drift check against the plan's measured counts:")
    check_drift(pop, status, ll)

    sample, population = assign_strata(pop, status, yes_cats, verdicts, ll, rng)
    order = sorted(sample)
    rng.shuffle(order)  # global order: jobs are cut from this, so every job mixes strata

    # pilot: PILOT counts per stratum family, drawn from the sample
    fam = lambda s: s.split(":")[0].split("-")[0]
    by_fam = collections.defaultdict(list)
    for c in order:
        by_fam[fam(sample[c])].append(c)
    pilot = set()
    for f, k in PILOT.items():
        pilot |= set(by_fam[f][:k])  # order is already shuffled

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "manifest.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["cve_id", "stratum", "order", "pilot", "seed"])
        for i, c in enumerate(order, 1):
            w.writerow([c, sample[c], i, "yes" if c in pilot else "", SEED])
    n_by = collections.Counter(sample.values())
    with open(os.path.join(OUT, "strata.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["stratum", "population", "sample", "weight"])
        for s in sorted(population):
            n = n_by.get(s, 0)
            w.writerow([s, population[s], n, f"{population[s] / n:.4f}" if n else ""])
    print(f"\nSampled {len(sample)} of {len(pop)} CVEs; pilot {len(pilot)}.")
    for s in sorted(population):
        print(f"  {s:20s} population {population[s]:7d}  sample {n_by.get(s, 0):5d}")
    print("Wrote manifest.csv, strata.csv. Next: jobs --pilot-only, then jobs --size N after the gate.")


def job_payload(cves, pop_rows):
    return [{"cve_id": c, "description": pop_rows[c]["description"],
             "cpe_strings": pop_rows[c]["cpe_strings"]} for c in cves]


def write_job(path, payload):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=1)
        fh.write("\n")


def cmd_jobs(args):
    man = list(csv.DictReader(open(os.path.join(OUT, "manifest.csv"), encoding="utf-8")))
    man.sort(key=lambda r: int(r["order"]))
    wanted = {r["cve_id"] for r in man}
    pop_rows = {}
    for r in csv.DictReader(open(NVD, encoding="utf-8")):
        if r["cve_id"] in wanted:
            pop_rows[r["cve_id"]] = r

    rows = []  # jobs.csv rows
    pilot = [r["cve_id"] for r in man if r["pilot"] == "yes"]
    pdir = os.path.join(KIT, "jobs", "pilot")
    os.makedirs(pdir, exist_ok=True)
    for i, c in enumerate(pilot, 1):
        name = f"pilot-single-{i:02d}"
        write_job(os.path.join(pdir, name + ".json"), job_payload([c], pop_rows))
        rows.append([name, "pilot-single", "both", "", 1, c])
    for b in range(0, len(pilot), 20):
        chunk = pilot[b:b + 20]
        name = f"pilot-batch-{b // 20 + 1:02d}"
        write_job(os.path.join(pdir, name + ".json"), job_payload(chunk, pop_rows))
        rows.append([name, "pilot-batch", "both", "", len(chunk), "|".join(chunk)])

    if not args.pilot_only:
        if args.size not in (1, 20):
            sys.exit("--size must be 1 or 20 (the two options the pilot gate chooses between)")
        mdir = os.path.join(KIT, "jobs", "main")
        if os.path.isdir(mdir) and os.listdir(mdir):
            sys.exit(f"STOP: {mdir} already has job files. Main jobs are cut once; delete them "
                     "deliberately (and amend the plan) if the job size really changed.")
        os.makedirs(mdir, exist_ok=True)
        order = [r["cve_id"] for r in man]
        jobs = [order[i:i + args.size] for i in range(0, len(order), args.size)]
        owner_of = {}
        for j, chunk in enumerate(jobs, 1):
            name = f"job-{j:04d}"
            owner = "A" if j % 2 else "B"
            owner_of[name] = owner
            write_job(os.path.join(mdir, name + ".json"), job_payload(chunk, pop_rows))
            rows.append([name, "main", owner, "", len(chunk), "|".join(chunk)])
        # cross-reruns: 5% of each owner's jobs, rerun by the other owner
        rng = random.Random(SEED + 1)
        for owner, other in (("A", "B"), ("B", "A")):
            mine = sorted(n for n, o in owner_of.items() if o == owner)
            for name in sorted(rng.sample(mine, max(1, round(RERUN_SHARE * len(mine))))):
                src = next(r for r in rows if r[0] == name)
                rows.append([f"rerun-{name}", "rerun", other, name, src[4], src[5]])
                write_job(os.path.join(mdir, f"rerun-{name}.json"),
                          json.load(open(os.path.join(mdir, name + ".json"), encoding="utf-8")))

    with open(os.path.join(OUT, "jobs.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["job", "set", "owner", "rerun_of", "n", "cve_ids"])
        w.writerows(rows)
    c = collections.Counter((r[1], r[2]) for r in rows)
    for k in sorted(c):
        print(f"  {k[0]:13s} owner {k[1]:4s} {c[k]:5d} jobs")
    print("Wrote jobs.csv and run-kit/jobs/.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("sample", help="draw the stratified sample and the pilot set")
    j = sub.add_parser("jobs", help="cut job files and assign owners")
    j.add_argument("--size", type=int, help="CVEs per main job: 1 or 20 (set at the pilot gate)")
    j.add_argument("--pilot-only", action="store_true", help="write only the pilot job files")
    args = ap.parse_args()
    if args.cmd == "jobs" and not args.pilot_only and args.size is None:
        ap.error("jobs needs --size (or --pilot-only)")
    {"sample": cmd_sample, "jobs": cmd_jobs}[args.cmd](args)


if __name__ == "__main__":
    main()
