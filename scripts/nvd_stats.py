#!/usr/bin/env python3
"""
nvd_stats.py — Summary statistics for an NVD query/snapshot CSV.

Computes the statistics one would want from a run of a query of the NVD database
and stores them as machine-readable JSON + CSV tables and a human-readable
Markdown report.

Works on any file in the project's common CVE schema:

    cve_id, published, description, cvss_score, cvss_version, cwe_ids,
    cpe_strings [, matched_terms]

That covers the fixed NVD snapshot (`data/nvd-snapshot/nvd_all.csv`, 7 cols) and
every per-category search output (`keyword_<cat>.csv` / `results_all_<cat>.xlsx`,
8 cols with the trailing `matched_terms` attribution column).

Usage
-----
    # Default: the fixed snapshot, report written next to it
    python3 scripts/nvd_stats.py

    # Any other query output (CSV or XLSX)
    python3 scripts/nvd_stats.py data/keyword-search/keyword_cameras.csv
    python3 scripts/nvd_stats.py data/vendor-search/results_all_cameras.xlsx

    # Override where the report/tables land, and how many top items to list
    python3 scripts/nvd_stats.py --out-dir /tmp/report --top 30

Notes
-----
* CVE descriptions contain embedded newlines, so rows are counted by parsing the
  CSV (pandas), never by `wc -l` — the latter over-counts badly.
* CVSS severity buckets follow the NVD v3 qualitative ranges
  (None 0.0 / Low 0.1-3.9 / Medium 4.0-6.9 / High 7.0-8.9 / Critical 9.0-10.0),
  applied to whatever CVSS version scored the CVE (v2 has no None band).
* CPE coverage-by-year is the key data-quality signal: NVD's 2024+ CPE backlog
  shows up as a coverage drop in the most recent years.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

SCHEMA_COLS = [
    "cve_id", "published", "description",
    "cvss_score", "cvss_version", "cwe_ids", "cpe_strings",
]


# ── severity bucketing (NVD v3 qualitative ranges) ────────────────────────────
def severity_bucket(score) -> str:
    if pd.isna(score):
        return "Unscored"
    s = float(score)
    if s == 0.0:
        return "None"
    if s < 4.0:
        return "Low"
    if s < 7.0:
        return "Medium"
    if s < 9.0:
        return "High"
    return "Critical"


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None", "Unscored"]


def pct(n: int, total: int) -> float:
    return round(100.0 * n / total, 2) if total else 0.0


def split_pipe(val) -> list[str]:
    if pd.isna(val) or not str(val).strip():
        return []
    return [p for p in str(val).split("|") if p]


# ── loading ──────────────────────────────────────────────────────────────────
def load(path: Path) -> pd.DataFrame:
    if path.suffix.lower() in (".xlsx", ".xls"):
        df = pd.read_excel(path)
    else:
        df = pd.read_csv(path, dtype={"cve_id": str}, low_memory=False)
    missing = [c for c in SCHEMA_COLS if c not in df.columns]
    if missing:
        sys.exit(f"error: {path} is missing expected columns: {missing}\n"
                 f"       found: {list(df.columns)}")
    return df


# ── settled review judgments (how many CVEs we've actually captured) ──────────
def default_judgments_path() -> Path:
    """final_resolved.csv, resolved relative to this script's repo."""
    return Path(__file__).resolve().parent.parent / "data" / "difference" / "final_resolved.csv"


def load_judgments(path: Path) -> pd.DataFrame | None:
    if not path.exists():
        return None
    j = pd.read_csv(path, dtype={"cve_id": str}, low_memory=False)
    if "Final Judgment" not in j.columns or "cve_id" not in j.columns:
        return None
    return j


def compute_capture(df: pd.DataFrame, jdf: pd.DataFrame, jpath: Path) -> dict:
    """Yes/No/pending tallies from settled judgments — globally, and restricted
    to the CVEs present in the current query file (join by cve_id)."""
    def norm(v) -> str:
        s = str(v).strip().lower()
        if s in ("yes", "no", "maybe"):
            return s.capitalize()
        return "Pending"  # pending / incomplete / blank

    verdict = jdf["Final Judgment"].map(norm)
    # A cve_id can be judged under >1 category; collapse to one verdict per CVE
    # (Yes wins — a true home-IoT match in any category means it's captured).
    rank = {"Yes": 3, "Maybe": 2, "No": 1, "Pending": 0}
    per_cve: dict[str, str] = {}
    for cid, v in zip(jdf["cve_id"].astype(str), verdict):
        if cid not in per_cve or rank[v] > rank[per_cve[cid]]:
            per_cve[cid] = v
    global_counts = Counter(per_cve.values())

    # Yes by category / direction, if those columns exist (combined file has them)
    yes_by_cat = {}
    ymask = verdict == "Yes"
    if "Category" in jdf.columns:
        yes_by_cat = jdf.loc[ymask, "Category"].value_counts().to_dict()

    # Direction-aware breakdown — separates real discovery from CPE densification.
    # Reports both Yes *rows* and distinct Yes *CVEs* per direction, then rolls the
    # directions up into three interpretive groups. Directions are disjoint within a
    # category, so grouping is meaningful; distinct-CVE dedup is by cve_id.
    dir_detail, group_cves = {}, {"discovery": set(), "densification": set(), "audit": set()}
    DIR_GROUP = {
        "vendor_only": "discovery", "keyword_only": "discovery",
        "cpe_expansion": "densification", "intersection": "audit",
    }
    if "Direction" in jdf.columns:
        yj = jdf.loc[ymask, ["Direction", "cve_id"]].copy()
        yj["cve_id"] = yj["cve_id"].astype(str)
        for d, grp in yj.groupby("Direction"):
            dir_detail[d] = {"yes_rows": int(len(grp)),
                             "distinct_cves": int(grp["cve_id"].nunique())}
            group_cves.setdefault(DIR_GROUP.get(d, "other"), set()).update(grp["cve_id"])
    groups = {g: {"distinct_cves": len(s)} for g, s in group_cves.items() if s}

    # Restrict to the CVEs in the current query file
    q_ids = set(df["cve_id"].astype(str))
    q_counts = Counter(per_cve.get(cid, "Unreviewed") for cid in q_ids)

    n_rows = len(q_ids)
    return {
        "source": str(jpath),
        "settled_rows": int(len(jdf)),
        "distinct_settled_cves": len(per_cve),
        "global": {k: int(global_counts.get(k, 0)) for k in ("Yes", "No", "Maybe", "Pending")},
        "yes_by_category": {k: int(v) for k, v in sorted(yes_by_cat.items(),
                                                         key=lambda kv: -kv[1])},
        "yes_by_direction": dict(sorted(dir_detail.items(),
                                        key=lambda kv: -kv[1]["yes_rows"])),
        "yes_by_group": groups,
        "this_query": {
            "cves": n_rows,
            "yes": int(q_counts.get("Yes", 0)),
            "no": int(q_counts.get("No", 0)),
            "maybe": int(q_counts.get("Maybe", 0)),
            "pending": int(q_counts.get("Pending", 0)),
            "unreviewed": int(q_counts.get("Unreviewed", 0)),
            "yes_pct_of_reviewed": pct(
                int(q_counts.get("Yes", 0)),
                int(q_counts.get("Yes", 0) + q_counts.get("No", 0) + q_counts.get("Maybe", 0)),
            ),
        },
    }


# ── stats ─────────────────────────────────────────────────────────────────────
def compute(df: pd.DataFrame) -> dict:
    stats: dict = {}
    n_rows = len(df)

    # ---- corpus size & uniqueness -------------------------------------------
    n_unique = df["cve_id"].nunique()
    stats["corpus"] = {
        "rows": n_rows,
        "unique_cves": int(n_unique),
        "duplicate_cve_rows": int(n_rows - n_unique),
    }

    # ---- temporal ------------------------------------------------------------
    pub = pd.to_datetime(df["published"], errors="coerce")
    n_dated = int(pub.notna().sum())
    year = pub.dt.year
    per_year = year.value_counts().sort_index()
    stats["temporal"] = {
        "with_publish_date": n_dated,
        "with_publish_date_pct": pct(n_dated, n_rows),
        "earliest": pub.min().strftime("%Y-%m-%d") if n_dated else None,
        "latest": pub.max().strftime("%Y-%m-%d") if n_dated else None,
        "per_year": {int(y): int(c) for y, c in per_year.items()},
    }

    # ---- CVSS ----------------------------------------------------------------
    score = pd.to_numeric(df["cvss_score"], errors="coerce")
    scored = score.dropna()
    n_scored = int(scored.size)
    buckets = df["cvss_score"].map(severity_bucket)
    sev_counts = buckets.value_counts()
    ver = df["cvss_version"].where(df["cvss_version"].notna())
    ver_counts = ver.astype(str).replace("nan", "missing").value_counts()
    stats["cvss"] = {
        "scored": n_scored,
        "scored_pct": pct(n_scored, n_rows),
        "unscored": int(n_rows - n_scored),
        "score_mean": round(float(scored.mean()), 2) if n_scored else None,
        "score_median": round(float(scored.median()), 2) if n_scored else None,
        "score_stdev": round(float(scored.std()), 2) if n_scored else None,
        "score_min": round(float(scored.min()), 1) if n_scored else None,
        "score_max": round(float(scored.max()), 1) if n_scored else None,
        "score_p25": round(float(scored.quantile(0.25)), 1) if n_scored else None,
        "score_p75": round(float(scored.quantile(0.75)), 1) if n_scored else None,
        "severity": {s: int(sev_counts.get(s, 0)) for s in SEVERITY_ORDER},
        "severity_pct": {s: pct(int(sev_counts.get(s, 0)), n_rows) for s in SEVERITY_ORDER},
        "version_breakdown": {str(k): int(v) for k, v in ver_counts.items()},
    }

    # ---- CWE -----------------------------------------------------------------
    cwe_lists = df["cwe_ids"].map(split_pipe)
    n_with_cwe = int((cwe_lists.map(len) > 0).sum())
    cwe_counter: Counter = Counter()
    for lst in cwe_lists:
        cwe_counter.update(lst)
    stats["cwe"] = {
        "with_cwe": n_with_cwe,
        "with_cwe_pct": pct(n_with_cwe, n_rows),
        "distinct_cwes": len(cwe_counter),
        "multi_cwe_rows": int((cwe_lists.map(len) > 1).sum()),
        "top": cwe_counter.most_common(TOP_N),
    }

    # ---- CPE -----------------------------------------------------------------
    cpe_lists = df["cpe_strings"].map(split_pipe)
    n_with_cpe = int((cpe_lists.map(len) > 0).sum())
    total_cpe = int(cpe_lists.map(len).sum())
    distinct_cpe: set[str] = set()
    vendor_product: Counter = Counter()
    part_counter: Counter = Counter()
    for lst in cpe_lists:
        for c in lst:
            distinct_cpe.add(c)
            parts = c.split(":")
            # cpe:2.3:<part>:<vendor>:<product>:...
            if len(parts) >= 5:
                part_counter[parts[2]] += 1
                vendor_product[f"{parts[3]}:{parts[4]}"] += 1
    # CPE coverage by year — surfaces NVD's recent-year backlog
    cpe_by_year: dict[int, dict] = {}
    if year.notna().any():
        has_cpe = cpe_lists.map(len) > 0
        tmp = pd.DataFrame({"year": year, "has_cpe": has_cpe})
        for y, grp in tmp.dropna(subset=["year"]).groupby("year"):
            tot = len(grp)
            cov = int(grp["has_cpe"].sum())
            cpe_by_year[int(y)] = {"total": tot, "with_cpe": cov, "pct": pct(cov, tot)}
    stats["cpe"] = {
        "with_cpe": n_with_cpe,
        "with_cpe_pct": pct(n_with_cpe, n_rows),
        "without_cpe": int(n_rows - n_with_cpe),
        "total_cpe_strings": total_cpe,
        "distinct_cpe_strings": len(distinct_cpe),
        "distinct_vendor_product": len(vendor_product),
        "avg_cpe_per_cve": round(total_cpe / n_with_cpe, 2) if n_with_cpe else 0.0,
        "part_breakdown": dict(part_counter),  # o=OS, h=hardware, a=application
        "top_vendor_product": vendor_product.most_common(TOP_N),
        "coverage_by_year": cpe_by_year,
    }

    # ---- completeness --------------------------------------------------------
    stats["completeness"] = {
        "missing_description": int(df["description"].isna().sum()
                                   + (df["description"].astype(str).str.strip() == "").sum()),
        "missing_cvss": int(n_rows - n_scored),
        "missing_cwe": int(n_rows - n_with_cwe),
        "missing_cpe": int(n_rows - n_with_cpe),
        "fully_populated": int(
            ((score.notna()) & (cwe_lists.map(len) > 0) & (cpe_lists.map(len) > 0)).sum()
        ),
    }

    # ---- matched_terms (search outputs only) ---------------------------------
    if "matched_terms" in df.columns:
        term_counter: Counter = Counter()
        multi = 0
        for val in df["matched_terms"]:
            terms = split_pipe(val)
            term_counter.update(terms)
            if len(terms) > 1:
                multi += 1
        stats["matched_terms"] = {
            "distinct_terms": len(term_counter),
            "rows_multi_term": multi,
            "hits_per_term": term_counter.most_common(),  # full list — usually small
        }

    return stats


# ── report rendering ──────────────────────────────────────────────────────────
def render_markdown(stats: dict, src: Path) -> str:
    c, t, cv, cw, cp, comp = (stats["corpus"], stats["temporal"], stats["cvss"],
                              stats["cwe"], stats["cpe"], stats["completeness"])
    L: list[str] = []
    L.append(f"# NVD Query Statistics — `{src.name}`")
    L.append("")
    L.append(f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
             f" from `{src}`_")
    L.append("")

    L.append("## Corpus")
    L.append(f"- **Rows:** {c['rows']:,}")
    L.append(f"- **Unique CVEs:** {c['unique_cves']:,}")
    L.append(f"- **Duplicate CVE rows:** {c['duplicate_cve_rows']:,}")
    L.append("")

    L.append("## Temporal coverage")
    L.append(f"- **Date range:** {t['earliest']} → {t['latest']}")
    L.append(f"- **With publish date:** {t['with_publish_date']:,} ({t['with_publish_date_pct']}%)")
    L.append("")
    L.append("| Year | CVEs |")
    L.append("|-----:|-----:|")
    for y in sorted(t["per_year"]):
        L.append(f"| {y} | {t['per_year'][y]:,} |")
    L.append("")

    L.append("## CVSS severity")
    L.append(f"- **Scored:** {cv['scored']:,} ({cv['scored_pct']}%) · **Unscored:** {cv['unscored']:,}")
    L.append(f"- **Score:** mean {cv['score_mean']} · median {cv['score_median']} "
             f"· sd {cv['score_stdev']} · range {cv['score_min']}–{cv['score_max']} "
             f"· IQR {cv['score_p25']}–{cv['score_p75']}")
    L.append("")
    L.append("| Severity | CVEs | % |")
    L.append("|----------|-----:|--:|")
    for s in SEVERITY_ORDER:
        L.append(f"| {s} | {cv['severity'][s]:,} | {cv['severity_pct'][s]}% |")
    L.append("")
    L.append("**CVSS version:** " + " · ".join(
        f"{k} = {v:,}" for k, v in sorted(cv["version_breakdown"].items())))
    L.append("")

    L.append("## CWE")
    L.append(f"- **With CWE:** {cw['with_cwe']:,} ({cw['with_cwe_pct']}%) "
             f"· **distinct CWEs:** {cw['distinct_cwes']:,} "
             f"· **multi-CWE rows:** {cw['multi_cwe_rows']:,}")
    L.append("")
    L.append(f"| Top {TOP_N} CWE | Count |")
    L.append("|------|------:|")
    for cwe, n in cw["top"]:
        L.append(f"| {cwe} | {n:,} |")
    L.append("")

    L.append("## CPE (deployment identifiability)")
    L.append(f"- **With CPE:** {cp['with_cpe']:,} ({cp['with_cpe_pct']}%) "
             f"· **without:** {cp['without_cpe']:,}")
    L.append(f"- **Distinct CPE strings:** {cp['distinct_cpe_strings']:,} "
             f"· **distinct vendor:product:** {cp['distinct_vendor_product']:,} "
             f"· **avg CPE/CVE:** {cp['avg_cpe_per_cve']}")
    pb = cp["part_breakdown"]
    L.append(f"- **CPE part mix:** "
             + " · ".join(f"{k} ({ {'o':'OS','h':'hardware','a':'application'}.get(k,k) })={v:,}"
                          for k, v in sorted(pb.items())))
    L.append("")
    L.append("**CPE coverage by year** (NVD's recent-year backlog shows here):")
    L.append("")
    L.append("| Year | CVEs | With CPE | Coverage |")
    L.append("|-----:|-----:|---------:|---------:|")
    for y in sorted(cp["coverage_by_year"]):
        r = cp["coverage_by_year"][y]
        L.append(f"| {y} | {r['total']:,} | {r['with_cpe']:,} | {r['pct']}% |")
    L.append("")
    L.append(f"| Top {TOP_N} vendor:product | CPE rows |")
    L.append("|------|------:|")
    for vp, n in cp["top_vendor_product"]:
        L.append(f"| {vp} | {n:,} |")
    L.append("")

    L.append("## Completeness")
    L.append(f"- Missing description: {comp['missing_description']:,}")
    L.append(f"- Missing CVSS: {comp['missing_cvss']:,}")
    L.append(f"- Missing CWE: {comp['missing_cwe']:,}")
    L.append(f"- Missing CPE: {comp['missing_cpe']:,}")
    L.append(f"- Fully populated (score+CWE+CPE): {comp['fully_populated']:,}")
    L.append("")

    if "capture" in stats:
        cap = stats["capture"]
        g, q = cap["global"], cap["this_query"]
        L.append("## Captured CVEs (settled review verdicts)")
        L.append(f"_From `{cap['source']}` — {cap['settled_rows']:,} settled rows, "
                 f"{cap['distinct_settled_cves']:,} distinct CVEs._")
        L.append("")
        L.append(f"- **Confirmed Yes (captured):** {g['Yes']:,} distinct CVEs  "
                 f"· No: {g['No']:,} · Maybe: {g['Maybe']:,} · Pending: {g['Pending']:,}")
        L.append(f"- **In this query file:** {q['yes']:,} Yes · {q['no']:,} No "
                 f"· {q['maybe']:,} Maybe · {q['pending']:,} pending "
                 f"· {q['unreviewed']:,} not in review set "
                 f"(Yes = {q['yes_pct_of_reviewed']}% of this file's reviewed rows)")
        L.append("")

        grp = cap.get("yes_by_group", {})
        if grp:
            GLABEL = {
                "discovery": "Text-search discovery (vendor_only + keyword_only)",
                "densification": "CPE-expansion densification (cpe_expansion)",
                "audit": "Intersection audit (V∩K)",
                "other": "Other",
            }
            GNOTE = {
                "discovery": "new in-scope CVEs the searches found",
                "densification": "extra version-CVEs on already-confirmed products — not new devices",
                "audit": "CVEs both searches agreed on",
                "other": "",
            }
            L.append("**Captured Yes by method** (the headline splits into discovery vs. densification):")
            L.append("")
            L.append("| Method | Distinct Yes CVEs | Note |")
            L.append("|--------|------------------:|------|")
            for gk in ("discovery", "densification", "audit", "other"):
                if gk in grp:
                    L.append(f"| {GLABEL[gk]} | {grp[gk]['distinct_cves']:,} | {GNOTE[gk]} |")
            L.append("")

        if cap["yes_by_direction"]:
            L.append("| Direction | Yes rows | Distinct Yes CVEs |")
            L.append("|-----------|---------:|------------------:|")
            for k, v in cap["yes_by_direction"].items():
                L.append(f"| {k} | {v['yes_rows']:,} | {v['distinct_cves']:,} |")
            L.append("")

        if cap["yes_by_category"]:
            L.append("| Category | Captured (Yes rows) |")
            L.append("|----------|--------------------:|")
            for k, v in cap["yes_by_category"].items():
                L.append(f"| {k} | {v:,} |")
            L.append("")

    if "matched_terms" in stats:
        mt = stats["matched_terms"]
        L.append("## Search-term attribution (`matched_terms`)")
        L.append(f"- **Distinct terms that hit:** {mt['distinct_terms']:,} "
                 f"· **rows matched by >1 term:** {mt['rows_multi_term']:,}")
        L.append("")
        L.append("| Term | Hits |")
        L.append("|------|-----:|")
        for term, n in mt["hits_per_term"]:
            L.append(f"| {term} | {n:,} |")
        L.append("")

    return "\n".join(L)


def write_tables(stats: dict, out_dir: Path, stem: str) -> list[Path]:
    """Write the big frequency tables as CSVs for downstream analysis/plotting."""
    written = []
    # per-year
    py = stats["temporal"]["per_year"]
    cpe_y = stats["cpe"]["coverage_by_year"]
    rows = []
    for y in sorted(set(py) | set(cpe_y)):
        cy = cpe_y.get(y, {})
        rows.append({"year": y, "cves": py.get(y, 0),
                     "with_cpe": cy.get("with_cpe", 0), "cpe_pct": cy.get("pct", 0.0)})
    p = out_dir / f"{stem}_by_year.csv"
    pd.DataFrame(rows).to_csv(p, index=False)
    written.append(p)
    # top CWE
    p = out_dir / f"{stem}_top_cwe.csv"
    pd.DataFrame(stats["cwe"]["top"], columns=["cwe", "count"]).to_csv(p, index=False)
    written.append(p)
    # top vendor:product
    p = out_dir / f"{stem}_top_vendor_product.csv"
    pd.DataFrame(stats["cpe"]["top_vendor_product"],
                 columns=["vendor_product", "cpe_rows"]).to_csv(p, index=False)
    written.append(p)
    # severity
    p = out_dir / f"{stem}_severity.csv"
    sev = stats["cvss"]["severity"]
    pd.DataFrame([{"severity": s, "count": sev[s],
                   "pct": stats["cvss"]["severity_pct"][s]} for s in SEVERITY_ORDER]
                 ).to_csv(p, index=False)
    written.append(p)
    if "matched_terms" in stats:
        p = out_dir / f"{stem}_term_hits.csv"
        pd.DataFrame(stats["matched_terms"]["hits_per_term"],
                     columns=["term", "hits"]).to_csv(p, index=False)
        written.append(p)
    if stats.get("capture", {}).get("yes_by_category"):
        p = out_dir / f"{stem}_captured_by_category.csv"
        pd.DataFrame(stats["capture"]["yes_by_category"].items(),
                     columns=["category", "captured_yes"]).to_csv(p, index=False)
        written.append(p)
    return written


def main() -> None:
    global TOP_N
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", nargs="?",
                    default="data/nvd-snapshot/nvd_all.csv",
                    help="CVE CSV/XLSX in the common schema (default: the fixed snapshot)")
    ap.add_argument("--out-dir", default=None,
                    help="where to write the report/tables (default: alongside the input)")
    ap.add_argument("--top", type=int, default=25,
                    help="how many items in each 'top N' table (default: 25)")
    ap.add_argument("--judgments", default=None,
                    help="settled-verdicts CSV for the captured-CVE section "
                         "(default: data/difference/final_resolved.csv)")
    ap.add_argument("--no-judgments", action="store_true",
                    help="skip the captured-CVE (Yes-count) section")
    args = ap.parse_args()

    TOP_N = args.top
    src = Path(args.input)
    if not src.exists():
        sys.exit(f"error: input not found: {src}")
    out_dir = Path(args.out_dir) if args.out_dir else src.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = src.stem + "_stats"

    print(f"Loading {src} …", file=sys.stderr)
    df = load(src)
    print(f"Loaded {len(df):,} rows. Computing statistics …", file=sys.stderr)
    stats = compute(df)

    if not args.no_judgments:
        jpath = Path(args.judgments) if args.judgments else default_judgments_path()
        jdf = load_judgments(jpath)
        if jdf is not None:
            stats["capture"] = compute_capture(df, jdf, jpath)
        elif args.judgments:
            print(f"warning: no usable judgments in {jpath}", file=sys.stderr)

    stats["_meta"] = {
        "source": str(src),
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "top_n": TOP_N,
    }

    json_path = out_dir / f"{stem}.json"
    json_path.write_text(json.dumps(stats, indent=2))
    md_path = out_dir / f"{stem}.md"
    md_path.write_text(render_markdown(stats, src))
    tables = write_tables(stats, out_dir, stem)

    print(f"\nWrote:\n  {json_path}\n  {md_path}")
    for t in tables:
        print(f"  {t}")

    # concise stdout summary
    c, cv, cp = stats["corpus"], stats["cvss"], stats["cpe"]
    print("\n── summary ──────────────────────────────────────────")
    print(f"  Unique CVEs        {c['unique_cves']:,}")
    print(f"  Date range         {stats['temporal']['earliest']} → {stats['temporal']['latest']}")
    print(f"  CVSS scored        {cv['scored']:,} ({cv['scored_pct']}%)  mean {cv['score_mean']}")
    print(f"  Critical / High    {cv['severity']['Critical']:,} / {cv['severity']['High']:,}")
    print(f"  With CPE           {cp['with_cpe']:,} ({cp['with_cpe_pct']}%)")
    print(f"  With CWE           {stats['cwe']['with_cwe']:,} ({stats['cwe']['with_cwe_pct']}%)")
    if "capture" in stats:
        cap = stats["capture"]
        grp = cap.get("yes_by_group", {})
        print(f"  Captured (Yes)     {cap['global']['Yes']:,} distinct CVEs confirmed")
        disc = grp.get("discovery", {}).get("distinct_cves", 0)
        dens = grp.get("densification", {}).get("distinct_cves", 0)
        audit = grp.get("audit", {}).get("distinct_cves", 0)
        parts = [f"{disc:,} text-search discovery", f"{dens:,} CPE densification"]
        if audit:
            parts.append(f"{audit:,} intersection audit")
        print(f"    └─ of which: " + " · ".join(parts))


if __name__ == "__main__":
    TOP_N = 25
    main()
