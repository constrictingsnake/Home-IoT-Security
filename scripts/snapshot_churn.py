#!/usr/bin/env python3
"""Snapshot churn diff — what NVD changed between two vintages of the same CVEs.

Run this BEFORE cutting over to a new snapshot (docs/plans/PLAN_nvd_update.md
Step 3). NVD reanalyses records after publication and is actively working through
its 2024+ CPE backlog, so a fixed set of already-confirmed CVEs does not hold
still between downloads. Measuring that drift on OUR confirmed population is a
data-quality finding for the threats-to-validity section, not just bookkeeping —
and it is the only chance to measure it, since the old vintage is irreproducible
(NVD serves current state only).

Population: every distinct CVE with `Final Judgment = Yes` in judgment_store.csv
and no `Excluded` ruling — the same population cwe888_analysis.py and
cvss_analysis.py report on. Use --all to diff the entire corpus instead.

What it measures, per CVE, old vs new:
  • base score changed (and by how much), gained/lost a score
  • CVSS version changed — in particular how many v2.0-only records NVD has
    re-scored under v3.x, which is what settles whether the pooled
    Kruskal-Wallis in cvss_analysis.py still mixes metric versions (plan §2.2)
  • gained a usable CWE — old rows with no CWE, or only the NVD-CWE-noinfo /
    NVD-CWE-Other placeholders, contribute nothing to RQ1 today
  • gained/lost CPE strings — a CPE-less CVE is a dead end for Stage 5 CPE
    expansion and for the `C` capture set in three-source recall
  • became REJECTED / dropped out of the corpus entirely
  • vector_string coverage in the new snapshot (RQ3's input)

Outputs (default data/nvd-snapshot/):
  snapshot_churn.csv  — one row per changed CVE: what changed, old value, new value
  snapshot_churn.md   — the summary tables, ready to cite

Usage:
    python3 scripts/snapshot_churn.py --new data/nvd-snapshot/nvd_all_2026-08.csv
    python3 scripts/snapshot_churn.py --new <new.csv> --old <old.csv> --all
"""
import argparse
import csv
import os
import sys
from collections import Counter, defaultdict

csv.field_size_limit(sys.maxsize)     # snapshot cpe_strings fields exceed the default

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_STORE = os.path.join(ROOT, "data", "difference", "judgment_store.csv")
DEFAULT_OLD = os.path.join(ROOT, "data", "nvd-snapshot", "nvd_all.csv")
DEFAULT_OUT_DIR = os.path.join(ROOT, "data", "nvd-snapshot")

# NVD's "we looked and there is nothing to say" placeholders. They occupy the
# cwe_ids column but carry no CWE, so cwe888_analysis.py counts the CVE and maps
# no weakness — same treatment here.
CWE_PLACEHOLDERS = {"NVD-CWE-noinfo", "NVD-CWE-Other"}

# NVD marks withdrawn records by rewriting the description, not by a status field
# on the 2.0 record we keep.
REJECT_PREFIXES = ("** REJECT **", "Rejected reason:", "** DISPUTED **")


def usable_cwes(raw):
    return [c for c in (raw or "").split("|") if c and c not in CWE_PLACEHOLDERS]


def is_rejected(description):
    d = (description or "").lstrip()
    return any(d.startswith(p) for p in REJECT_PREFIXES if p != "** DISPUTED **")


def load_snapshot(path, needed):
    """cve_id -> row dict, restricted to `needed` (None = keep everything)."""
    out = {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            cid = (row.get("cve_id") or "").strip().upper()
            if not cid or (needed is not None and cid not in needed):
                continue
            out[cid] = row
    return out


def load_population(store_path, include_excluded):
    """Distinct confirmed-Yes CVE ids, plus the categories each appears in."""
    cats_of = defaultdict(set)
    for row in csv.DictReader(open(store_path, newline="", encoding="utf-8-sig")):
        if str(row.get("Final Judgment", "")).strip() != "Yes":
            continue
        if str(row.get("Excluded", "")).strip() and not include_excluded:
            continue
        cats_of[row["cve_id"].strip().upper()].add(row["category"].strip())
    return cats_of


def fnum(raw):
    raw = (raw or "").strip()
    try:
        return float(raw)
    except ValueError:
        return None


def main():
    ap = argparse.ArgumentParser(
        description="Diff two NVD snapshot vintages over the confirmed-Yes population.")
    ap.add_argument("--new", required=True, help="New snapshot CSV (the incoming vintage)")
    ap.add_argument("--old", default=DEFAULT_OLD,
                    help=f"Old snapshot CSV (default: {os.path.relpath(DEFAULT_OLD, ROOT)})")
    ap.add_argument("--store", default=DEFAULT_STORE,
                    help="Judgment store CSV (default: data/difference/judgment_store.csv)")
    ap.add_argument("--all", action="store_true",
                    help="Diff every CVE in both snapshots, not just the confirmed-Yes set. "
                         "Slower and much noisier; the confirmed set is what gets published.")
    ap.add_argument("--include-excluded", action="store_true",
                    help="Keep rows a scope ruling took out of the analysis population.")
    ap.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                    help="Output directory (default: data/nvd-snapshot)")
    args = ap.parse_args()

    if args.all:
        cats_of, needed = {}, None
        print("Population: entire corpus (--all)")
    else:
        cats_of = load_population(args.store, args.include_excluded)
        needed = set(cats_of)
        print(f"Population: {len(needed):,} distinct confirmed-Yes CVEs")

    print(f"Loading old: {os.path.relpath(args.old, ROOT)} ...", flush=True)
    old = load_snapshot(args.old, needed)
    print(f"  {len(old):,} matched")
    print(f"Loading new: {os.path.relpath(args.new, ROOT)} ...", flush=True)
    new = load_snapshot(args.new, needed)
    print(f"  {len(new):,} matched")

    if needed is None:
        needed = set(old) | set(new)

    only_old = sorted(needed & set(old) - set(new))
    only_new = sorted(needed & set(new) - set(old))
    in_both = sorted(set(old) & set(new))
    absent = sorted(needed - set(old) - set(new))

    changes = []          # per-CVE change rows for the CSV
    tally = Counter()     # headline counts for the markdown
    score_deltas = []
    version_moves = Counter()

    def note(cid, kind, old_val, new_val):
        changes.append({
            "cve_id": cid,
            "change": kind,
            "old": old_val,
            "new": new_val,
            "categories": "|".join(sorted(cats_of.get(cid, ()))),
        })
        tally[kind] += 1

    for cid in in_both:
        o, n = old[cid], new[cid]

        # --- CVSS base score / version
        o_score, n_score = fnum(o.get("cvss_score")), fnum(n.get("cvss_score"))
        o_ver = (o.get("cvss_version") or "").strip()
        n_ver = (n.get("cvss_version") or "").strip()
        if o_score is None and n_score is not None:
            note(cid, "score_gained", "", f"{n_score} (v{n_ver})")
        elif o_score is not None and n_score is None:
            note(cid, "score_lost", f"{o_score} (v{o_ver})", "")
        elif o_score is not None and n_score is not None and o_score != n_score:
            note(cid, "score_changed", f"{o_score} (v{o_ver})", f"{n_score} (v{n_ver})")
            score_deltas.append(n_score - o_score)
        if o_ver != n_ver and o_ver and n_ver:
            note(cid, "version_changed", o_ver, n_ver)
            version_moves[f"{o_ver} -> {n_ver}"] += 1

        # --- CWE backfill
        o_cwe, n_cwe = usable_cwes(o.get("cwe_ids")), usable_cwes(n.get("cwe_ids"))
        if not o_cwe and n_cwe:
            note(cid, "cwe_gained", o.get("cwe_ids", ""), "|".join(n_cwe))
        elif o_cwe and not n_cwe:
            note(cid, "cwe_lost", "|".join(o_cwe), n.get("cwe_ids", ""))
        elif set(o_cwe) != set(n_cwe):
            note(cid, "cwe_changed", "|".join(o_cwe), "|".join(n_cwe))

        # --- CPE backfill
        o_cpe = [c for c in (o.get("cpe_strings") or "").split("|") if c]
        n_cpe = [c for c in (n.get("cpe_strings") or "").split("|") if c]
        if not o_cpe and n_cpe:
            note(cid, "cpe_gained", "0", f"{len(n_cpe)}")
        elif o_cpe and not n_cpe:
            note(cid, "cpe_lost", f"{len(o_cpe)}", "0")
        elif set(o_cpe) != set(n_cpe):
            note(cid, "cpe_changed", f"{len(o_cpe)}", f"{len(n_cpe)}")

        # --- withdrawn upstream
        if not is_rejected(o.get("description")) and is_rejected(n.get("description")):
            note(cid, "became_rejected", "", (n.get("description") or "")[:120])

    for cid in only_new:
        note(cid, "added_to_snapshot", "", "")
    for cid in only_old:
        note(cid, "dropped_from_snapshot", "", "")

    # --- state of the new snapshot on the fields the plan cares about
    def state(snap, ids):
        s = Counter()
        for cid in ids:
            r = snap.get(cid)
            if not r:
                continue
            s["unscored"] += 1 if fnum(r.get("cvss_score")) is None else 0
            ver = (r.get("cvss_version") or "").strip() or "none"
            s[f"ver:{ver}"] += 1
            s["no_cwe"] += 0 if usable_cwes(r.get("cwe_ids")) else 1
            s["no_cpe"] += 0 if (r.get("cpe_strings") or "").strip() else 1
            s["has_vector"] += 1 if (r.get("vector_string") or "").strip() else 0
            s["rejected"] += 1 if is_rejected(r.get("description")) else 0
        return s

    old_state, new_state = state(old, needed), state(new, needed)

    os.makedirs(args.out_dir, exist_ok=True)
    csv_path = os.path.join(args.out_dir, "snapshot_churn.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["cve_id", "change", "old", "new", "categories"])
        w.writeheader()
        w.writerows(sorted(changes, key=lambda r: (r["change"], r["cve_id"])))

    # ---------------------------------------------------------------- report
    scope = "entire corpus" if args.all else "confirmed-Yes CVEs"
    L = [f"# NVD snapshot churn — {os.path.basename(args.old)} → {os.path.basename(args.new)}", ""]
    L.append(f"Population: **{len(needed):,} {scope}**. "
             f"{len(in_both):,} present in both snapshots, {len(only_new):,} only in the new one, "
             f"{len(only_old):,} only in the old one"
             + (f", {len(absent):,} in neither" if absent else "") + ".")
    L += ["", "## Changes", "",
          "| Change | n | % of population |", "|---|---:|---:|"]
    for kind, n in tally.most_common():
        L.append(f"| `{kind}` | {n} | {100 * n / len(needed):.1f}% |")
    if not tally:
        L.append("| _(none)_ | 0 | 0.0% |")

    if score_deltas:
        ups = [d for d in score_deltas if d > 0]
        downs = [d for d in score_deltas if d < 0]
        L += ["", f"Base-score moves: **{len(ups)} up**, **{len(downs)} down**; "
                  f"mean delta {sum(score_deltas) / len(score_deltas):+.2f}, "
                  f"range {min(score_deltas):+.1f} to {max(score_deltas):+.1f}."]
    if version_moves:
        L += ["", "Metric-version moves: "
              + ", ".join(f"`{k}` ({v})" for k, v in version_moves.most_common()) + "."]

    L += ["", "## State of the population, before vs after", "",
          "| Property | old | new |", "|---|---:|---:|"]
    keys = ["unscored", "no_cwe", "no_cpe", "rejected", "has_vector"]
    keys += sorted({k for k in list(old_state) + list(new_state) if k.startswith("ver:")})
    labels = {
        "unscored": "no CVSS base score",
        "no_cwe": "no usable CWE (empty / noinfo / Other)",
        "no_cpe": "no CPE string",
        "rejected": "REJECTED upstream",
        "has_vector": "has a CVSS vector string",
    }
    for k in keys:
        label = labels.get(k, f"CVSS version {k[4:]}")
        L.append(f"| {label} | {old_state[k]:,} | {new_state[k]:,} |")

    L += ["", f"Per-CVE detail: `{os.path.relpath(csv_path, ROOT)}`.", ""]
    md_path = os.path.join(args.out_dir, "snapshot_churn.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print(f"\n{len(changes):,} changes across {len({c['cve_id'] for c in changes}):,} CVEs")
    for kind, n in tally.most_common():
        print(f"  {kind:<24} {n:>6}")
    print(f"\nWrote {os.path.relpath(csv_path, ROOT)}, {os.path.relpath(md_path, ROOT)}")


if __name__ == "__main__":
    main()
