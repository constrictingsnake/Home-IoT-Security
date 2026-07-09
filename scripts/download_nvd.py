#!/usr/bin/env python3
"""
Download the entire NVD database → the project's offline snapshot.
=========================================================================
Pulls every CVE from the **NVD 2.0 REST API** and writes them to
`data/nvd-snapshot/nvd_all.csv` in the project's common schema
(`cve_id, published, description, cvss_score, cvss_version, cwe_ids,
cpe_strings`) — the *exact* columns Stage 1/2 (`cve_search.py`,
`build_search.py`) search against. Pinning one downloaded snapshot
is what makes the keyword and vendor searches comparable and the study
reproducible / citeable ("dataset as of <date>"). See `data/nvd-snapshot/SNAPSHOT.md`.

This is the API-based alternative to the per-year-feed route documented in
the `cve_search.py` header (STEP 1–2): one command, full corpus, resumable.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RESUMABLE BY DESIGN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The corpus is fetched in pages of 2000 CVEs across a few threads. After every
completed page the set of finished pages is written to `<out>.progress.json`,
and rows are appended to `<out>` immediately. So:
  • To PAUSE  — Ctrl-C, or `pkill -f download_nvd.py`.
  • To RESUME — run the same command again. It reads the progress file and the
                existing CSV, skips finished pages, and de-duplicates by CVE ID
                (so even a torn page on resume can't create duplicates).
You never lose more than the one page in flight (~2000 CVEs).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
USAGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  # API key is read from $NVD_API_KEY (load it from the gitignored .env first):
  cd /path/to/Home-IoT-Security             # the repo root
  set -a && source .env && set +a
  python3 scripts/download_nvd.py            # → data/nvd-snapshot/nvd_all.csv

  # Override anything:
  python3 scripts/download_nvd.py --out /tmp/nvd_all.csv --threads 2
  python3 scripts/download_nvd.py --api-key <key>        # instead of $NVD_API_KEY

An NVD API key (https://nvd.nist.gov/developers/request-an-api-key) raises the
rate limit and is strongly recommended; a full run is ~360k CVEs / ~181 pages
and takes ~2–3 h (the API is flaky — retries with backoff are normal).

When it finishes cleanly (no failed pages) it prints "All pages complete." and writes
`data/nvd-snapshot/SNAPSHOT.md` itself (date + CVE count) — then run `build_search.py`.

Requirements: requests (already installed).
"""

import argparse
import csv
import datetime
import json
import os
import queue
import sys
import threading
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# NVD descriptions can exceed the default 128 KB CSV field cap.
csv.field_size_limit(sys.maxsize)

# Same columns as every other dataset in the project (01_raw.csv, vendor files,
# keyword files). Keep in lock-step with cve_search.py's CSV_COLS.
CSV_COLS = ["cve_id", "published", "description",
            "cvss_score", "cvss_version", "cwe_ids", "cpe_strings"]

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000          # NVD 2.0 hard maximum per request
DEFAULT_THREADS = 3
MAX_PAGE_RETRIES = 20
REQUEST_TIMEOUT = 150            # the API routinely takes 40–150 s per page

# Default snapshot location, resolved relative to this script (so the command
# works from anywhere) — matches the project's run-from-anywhere convention.
_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.normpath(
    os.path.join(_HERE, "..", "data", "nvd-snapshot", "nvd_all.csv"))

_print_lock = threading.Lock()
_write_lock = threading.Lock()


def log(msg):
    with _print_lock:
        print(msg, flush=True)


def make_session(api_key):
    s = requests.Session()
    if api_key:
        s.headers.update({"apiKey": api_key})
    retry = Retry(total=3, backoff_factor=1,
                  status_forcelist=[429, 500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


def _en_description(descriptions):
    return next((d["value"] for d in descriptions if d.get("lang") == "en"), None)


def parse_nvd_20(item):
    """One NVD 2.0 `vulnerabilities[]` entry → one CSV row dict (or None)."""
    cve = item.get("cve", item)
    cve_id = cve.get("id", "")
    published = cve.get("published", "")[:10]
    description = _en_description(cve.get("descriptions", []))
    if not description:
        return None

    metrics = cve.get("metrics", {})
    cvss_score, cvss_version = None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            cvss_data = primary.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_version = cvss_data.get("version")
            break

    cwe_ids = []
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    cpe_strings = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for m in node.get("cpeMatch", []):
                uri = m.get("criteria", "")
                if uri:
                    cpe_strings.append(uri)

    return {
        "cve_id": cve_id,
        "published": published,
        "description": description,
        "cvss_score": cvss_score if cvss_score is not None else "",
        "cvss_version": cvss_version or "",
        "cwe_ids": "|".join(dict.fromkeys(cwe_ids)),
        "cpe_strings": "|".join(dict.fromkeys(cpe_strings)),
    }


def save_progress(progress_path, stats):
    with open(progress_path, "w") as f:
        json.dump({"completed_pages": sorted(stats["completed_pages"]),
                   "total_pages": stats["total_pages"],
                   "written": stats["written"]}, f)


def worker(thread_id, work_queue, fail_counts, api_key, writer,
           seen_ids, stats, progress_path):
    session = make_session(api_key)
    while True:
        try:
            page_num = work_queue.get(timeout=5)
        except queue.Empty:
            break

        start = page_num * RESULTS_PER_PAGE
        t0 = time.time()
        try:
            r = session.get(NVD_API,
                            params={"resultsPerPage": RESULTS_PER_PAGE,
                                    "startIndex": start},
                            timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            data = r.json()

            rows = [row for row in
                    (parse_nvd_20(i) for i in data.get("vulnerabilities", []))
                    if row]

            new_rows = 0
            with _write_lock:
                for row in rows:
                    if row["cve_id"] not in seen_ids:
                        seen_ids.add(row["cve_id"])
                        writer.writerow(row)
                        new_rows += 1
                stats["written"] += new_rows
                stats["pages_done"] += 1
                stats["completed_pages"].add(page_num)
                save_progress(progress_path, stats)

            elapsed = time.time() - t0
            pct = stats["pages_done"] / stats["total_pages"] * 100
            log(f"  [T{thread_id}] page {page_num:>3} (start={start:>6})  "
                f"+{new_rows:>4} new  total={stats['written']:>7}  {elapsed:.0f}s  "
                f"({stats['pages_done']}/{stats['total_pages']} = {pct:.0f}%)")

        except Exception as e:
            retries = fail_counts.get(page_num, 0) + 1
            fail_counts[page_num] = retries
            wait = min(30 * retries, 180)
            if retries > MAX_PAGE_RETRIES:
                log(f"  [T{thread_id}] GAVE UP page {page_num}: {e}")
                stats["failed_pages"].append(page_num)
            else:
                log(f"  [T{thread_id}] page {page_num} attempt {retries}: "
                    f"{type(e).__name__} — requeue in {wait}s")
                time.sleep(wait)
                work_queue.put(page_num)
        finally:
            work_queue.task_done()


SNAPSHOT_MD_TEMPLATE = """# NVD Snapshot

This directory holds the **fixed, offline NVD dataset** that Stage 1 (keyword search) and
Stage 2 (vendor/brand search) — both `scripts/build_search.py` — run against. Pinning one
snapshot is what makes the two search methods **comparable** (same data, same engine) and the
study **reproducible / citeable** ("dataset as of <date>").

The dataset file itself (`nvd_all.csv`) is **gitignored** (large, reproducible bulk data).
Only this provenance file is tracked.

## How to build the snapshot

Either the API route (this file's generator) or the per-year-feed route — see the header of
`scripts/cve_search.py` (STEP 1-2) for the latter's full detail.

```
set -a && source .env && set +a
python3 scripts/download_nvd.py            # -> data/nvd-snapshot/nvd_all.csv (+ this file)
```

Then run the searches:
```
python3 scripts/build_search.py
```

## Provenance

- **Snapshot date:** {date}
- **Source:** NVD 2.0 API (`https://services.nvd.nist.gov/rest/json/cves/2.0`), downloaded via `scripts/download_nvd.py` with NVD API key ({results_per_page} CVEs/page, {threads} threads)
- **Years included:** all CVEs in NVD as of download date
- **Total CVEs:** {total:,}
- **Notes:** Count is the number of unique CVE records (the `written` value in `nvd_all.csv.progress.json`), **not** `wc -l nvd_all.csv` — the latter over-counts because CVE descriptions contain embedded newlines, so one CVE can span several physical lines.

_This file is written automatically by `scripts/download_nvd.py` on a clean (no-failed-pages) run — do not hand-edit the Provenance section, it will be overwritten on the next run._
"""


def write_snapshot_md(out_path, total_written, threads):
    """Auto-write data/nvd-snapshot/SNAPSHOT.md (date + CVE count) after a clean run,
    replacing the old manual copy-paste reminder."""
    md_path = os.path.join(os.path.dirname(out_path), "SNAPSHOT.md")
    content = SNAPSHOT_MD_TEMPLATE.format(
        date=datetime.date.today().isoformat(),
        results_per_page=RESULTS_PER_PAGE,
        threads=threads,
        total=total_written,
    )
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(content)
    return md_path


def fetch_total(session):
    """Get NVD's current totalResults (with retries — the count call is flaky too)."""
    for attempt in range(10):
        try:
            r = session.get(NVD_API,
                            params={"resultsPerPage": 1, "startIndex": 0},
                            timeout=60)
            r.raise_for_status()
            return r.json()["totalResults"]
        except Exception as e:
            print(f"  count fetch attempt {attempt + 1}/10: {e}", flush=True)
            time.sleep(20)
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Download the entire NVD database to the project snapshot CSV.")
    parser.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"),
                        help="NVD API key (default: $NVD_API_KEY). Strongly recommended.")
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help=f"Output CSV (default: {DEFAULT_OUT}).")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Concurrent download threads (default: {DEFAULT_THREADS}).")
    args = parser.parse_args()

    if not args.api_key:
        print("WARNING: no API key ($NVD_API_KEY unset, --api-key not given). "
              "NVD will heavily rate-limit anonymous requests; this may crawl or "
              "fail. Load .env first:  set -a && source .env && set +a", flush=True)

    out = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    progress_path = out + ".progress.json"

    # --- Resume state: finished pages + already-written CVE IDs ---
    completed_pages = set()
    if os.path.exists(progress_path):
        with open(progress_path) as f:
            completed_pages = set(json.load(f).get("completed_pages", []))
        print(f"Resuming: {len(completed_pages)} pages already complete.", flush=True)

    seen_ids = set()
    if os.path.exists(out) and os.path.getsize(out) > 0:
        print(f"Loading existing CVE IDs from {out} ...", flush=True)
        with open(out, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                seen_ids.add(row["cve_id"])
        print(f"  Loaded {len(seen_ids):,} existing CVE IDs.", flush=True)

    # --- How many pages total? ---
    print("Fetching total CVE count from NVD ...", flush=True)
    total = fetch_total(make_session(args.api_key))
    if total is None:
        print("Could not fetch CVE count after retries. Aborting.", flush=True)
        sys.exit(1)

    pages = (total + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE
    remaining = [p for p in range(pages) if p not in completed_pages]
    print(f"Total: {total:,} CVEs | {pages} pages | {len(remaining)} remaining | "
          f"{args.threads} threads", flush=True)

    if not remaining:
        print("All pages already downloaded! Nothing to do.", flush=True)
        print(f"Snapshot is at: {out}", flush=True)
        return

    work_queue = queue.Queue()
    for p in remaining:
        work_queue.put(p)

    fail_counts = {}
    stats = {
        "written": len(seen_ids),
        "pages_done": len(completed_pages),
        "total_pages": pages,
        "completed_pages": completed_pages,
        "failed_pages": [],
    }

    file_mode = "a" if (os.path.exists(out) and os.path.getsize(out) > 0) else "w"
    t_start = time.time()

    with open(out, file_mode, newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLS)
        if file_mode == "w":
            writer.writeheader()

        threads = []
        for i in range(args.threads):
            t = threading.Thread(
                target=worker,
                args=(i, work_queue, fail_counts, args.api_key,
                      writer, seen_ids, stats, progress_path),
                daemon=True)
            threads.append(t)
            t.start()
            time.sleep(2)   # stagger thread starts to avoid an initial 429 burst

        for t in threads:
            t.join()

    elapsed = time.time() - t_start
    print(f"\nDone: {stats['written']:,} CVEs total, "
          f"{stats['pages_done']}/{pages} pages "
          f"({elapsed / 60:.1f} min this session).", flush=True)
    if stats["failed_pages"]:
        print(f"WARNING: permanently failed pages: {sorted(stats['failed_pages'])}\n"
              f"  Re-run the same command to retry just those pages "
              f"(SNAPSHOT.md not written until a clean run).", flush=True)
    else:
        md_path = write_snapshot_md(out, stats["written"], args.threads)
        print(f"All pages complete. Safe to use {out}\n"
              f"  Wrote {md_path} (date + CVE count)\n"
              f"  Next: run scripts/build_search.py", flush=True)


if __name__ == "__main__":
    main()
