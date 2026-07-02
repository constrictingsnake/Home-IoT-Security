#!/usr/bin/env python3
"""Gemini API reviewer for the difference workflow.

Fills the `Gemini Judgment` / `Gemini Confidence` / `Gemini Reasoning` columns of a blind
review copy (gemini.csv from make_review_copies.py) by sending each row's description and
cpe_strings to the Gemini API.

Blindness is structural here: only the description and CPE strings are ever sent to the
model — never another reviewer's columns.

Resumable: rows that already have a Gemini Judgment are skipped, and progress is written
to disk every --save-every rows, so the script can be re-run after an interruption or a
rate-limit without redoing work.

Setup:
    export GEMINI_API_KEY=...        # https://aistudio.google.com/apikey
    # requests + pandas are already installed in this project

Usage:
    python gemini_classify.py path/to/reviews/gemini.csv --category "security camera"
    python gemini_classify.py path/to/reviews/gemini.csv --category "smart lock" \
        --model gemini-2.5-flash --rps 1.0 --limit 50
"""
import argparse
import json
import os
import sys
import time

import pandas as pd
import requests

REVIEWER = "Gemini"
JUDGMENT_COL = f"{REVIEWER} Judgment"
CONF_COL = f"{REVIEWER} Confidence"
REASON_COL = f"{REVIEWER} Reasoning"

DEFAULT_MODEL = "gemini-2.5-flash"
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
RUBRIC_DEFAULT = os.path.join(
    os.path.dirname(__file__), "..", "data", "difference", "CLASSIFICATION_PROMPT.md"
)
SCOPE_DEFAULT = os.path.join(
    os.path.dirname(__file__), "..", "data", "difference", "category_scope.csv"
)

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "judgment": {"type": "string", "enum": ["Yes", "No", "Maybe"]},
        "confidence": {"type": "string", "enum": ["High", "Low"]},
        "reasoning": {"type": "string"},
    },
    "required": ["judgment", "confidence", "reasoning"],
}

BATCH_RESPONSE_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "cve_id": {"type": "string"},
            "judgment": {"type": "string", "enum": ["Yes", "No", "Maybe"]},
            "confidence": {"type": "string", "enum": ["High", "Low"]},
            "reasoning": {"type": "string"},
        },
        "required": ["cve_id", "judgment", "confidence", "reasoning"],
    },
}


def slug_from_path(csv_path):
    """Recover the category slug from a review-copy path.

    The gemini copy always lives at data/difference/<slug>/reviews/gemini.csv, so the
    slug is the grandparent directory name. Returns "" if the layout doesn't match.
    """
    parents = os.path.abspath(csv_path).split(os.sep)
    # .../<slug>/reviews/gemini.csv  → parents[-3] is <slug>
    if len(parents) >= 3 and parents[-2] == "reviews":
        return parents[-3]
    return ""


def load_scope_note(scope_path, slug):
    """Return the 2–3 line in/out scope note for a slug from category_scope.csv.

    Missing file or missing slug is non-fatal: warn and return "" so Gemini still runs
    (a new category without a scope row must not break the pass). Keyed by slug because
    the free-text --category label is not reversibly mappable to a slug.
    """
    if not slug:
        print("    warning: could not derive category slug from path — no scope note injected")
        return ""
    if not scope_path or not os.path.isfile(scope_path):
        print(f"    warning: scope file not found ({scope_path}) — no scope note injected")
        return ""
    df = pd.read_csv(scope_path, dtype=str).fillna("")
    match = df[df["slug"].str.strip() == slug]
    if match.empty:
        print(f"    warning: no scope row for slug {slug!r} in {scope_path} — no scope note injected")
        return ""
    return match.iloc[0]["scope_note"].strip()


def _scope_block(scope_note):
    """Render the scope note as a prompt section, or empty string if there is none."""
    if not scope_note:
        return ""
    return f"=== CATEGORY SCOPE (authoritative in/out for THIS category) ===\n{scope_note}\n\n"


def build_prompt(rubric, category, description, cpe, scope_note=""):
    return (
        f"{rubric}\n\n"
        f"=== DEVICE CATEGORY UNDER REVIEW ===\n{category}\n\n"
        f"{_scope_block(scope_note)}"
        f"=== CVE DESCRIPTION ===\n{description or '(none)'}\n\n"
        f"=== CPE STRINGS ===\n{cpe or '(none)'}\n\n"
        "Classify this CVE for the device category above. Judge ONLY from the description "
        "and CPE strings. Respond with the required JSON object."
    )


def build_batch_prompt(rubric, category, rows, scope_note=""):
    """rows: list of (cve_id, description, cpe) tuples."""
    entries = []
    for cve_id, description, cpe in rows:
        entries.append(
            f"--- CVE: {cve_id} ---\n"
            f"Description: {description or '(none)'}\n"
            f"CPE Strings: {cpe or '(none)'}"
        )
    block = "\n\n".join(entries)
    return (
        f"{rubric}\n\n"
        f"=== DEVICE CATEGORY UNDER REVIEW ===\n{category}\n\n"
        f"{_scope_block(scope_note)}"
        f"=== CVEs TO CLASSIFY ===\n{block}\n\n"
        "Classify EACH CVE above for the device category. Judge ONLY from each CVE's "
        "description and CPE strings. Return a JSON array with one object per CVE, each "
        "containing cve_id, judgment, confidence, and reasoning."
    )


def call_gemini(session, api_key, model, prompt):
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": RESPONSE_SCHEMA,
            "temperature": 0,
        },
    }
    resp = session.post(
        API_URL.format(model=model), params={"key": api_key}, json=payload, timeout=60
    )
    resp.raise_for_status()
    text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    obj, _ = json.JSONDecoder().raw_decode(text.strip())
    return obj["judgment"], obj["confidence"], obj.get("reasoning", "")


def call_gemini_batch(session, api_key, model, prompt):
    """Returns a dict of {cve_id: (judgment, confidence, reasoning)}."""
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": BATCH_RESPONSE_SCHEMA,
            "temperature": 0,
        },
    }
    resp = session.post(
        API_URL.format(model=model), params={"key": api_key}, json=payload, timeout=120
    )
    resp.raise_for_status()
    text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    items, _ = json.JSONDecoder().raw_decode(text.strip())
    # Strip the returned cve_id: weaker models (e.g. gemma) sometimes echo it with
    # surrounding whitespace, which would fail the exact-match map-back in classify_file.
    return {
        item["cve_id"].strip(): (item["judgment"], item["confidence"], item.get("reasoning", ""))
        for item in items
    }


def call_with_retry(session, api_key, model, prompt, max_retries=5, batch=False):
    fn = call_gemini_batch if batch else call_gemini
    for attempt in range(max_retries):
        try:
            return fn(session, api_key, model, prompt)
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else None
            if code == 429:
                # Don't retry 429s — each retry burns daily quota. Skip this row; a later
                # run will retry it once quota resets.
                raise
            if code in (500, 502, 503, 504) and attempt < max_retries - 1:
                wait = 2.0 ** attempt
                print(f"    HTTP {code} — retrying in {wait:.0f}s")
                time.sleep(wait)
                continue
            raise
    raise RuntimeError("max retries exceeded")


def classify_file(
    csv_path,
    category,
    *,
    model=DEFAULT_MODEL,
    rubric_path=RUBRIC_DEFAULT,
    scope_path=SCOPE_DEFAULT,
    scope_note=None,
    slug=None,
    rps=1.0,
    save_every=25,
    limit=0,
    redo=False,
    api_key=None,
    batch_size=1,
):
    """Fill the Gemini columns of one review copy in place. Returns rows classified.

    Importable so merge_judgments.py can run the Gemini pass before merging. Resumable:
    only blank rows are classified unless redo=True, and progress is flushed to disk.

    batch_size > 1 sends multiple rows per API call, amortizing rubric overhead and
    dramatically reducing round-trips. Results are mapped back by cve_id. Rows not
    returned by the model are left blank for retry.
    """
    api_key = api_key or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("Set GEMINI_API_KEY (get one at https://aistudio.google.com/apikey)")
    if not os.path.isfile(csv_path):
        raise FileNotFoundError(f"File not found: {csv_path}")
    if not os.path.isfile(rubric_path):
        raise FileNotFoundError(f"Rubric not found: {rubric_path}")

    with open(rubric_path, encoding="utf-8") as fh:
        rubric = fh.read()

    # Per-category scope note: gives Gemini the same in/out boundary Claude/Codex read
    # from category_scope.csv, keyed by the slug recovered from the review-copy path
    # (unless an explicit note/slug override is passed). Missing note is non-fatal.
    if scope_note is None:
        resolved_slug = slug if slug is not None else slug_from_path(csv_path)
        scope_note = load_scope_note(scope_path, resolved_slug)
        if scope_note:
            print(f"  Gemini: injecting scope note for {resolved_slug!r}")

    df = pd.read_csv(csv_path, dtype=str).fillna("")
    if "description" not in df.columns:
        raise ValueError(f"{csv_path}: missing 'description' column")
    for col in (JUDGMENT_COL, CONF_COL, REASON_COL):
        if col not in df.columns:
            df[col] = ""
    cpe_col = "cpe_strings" if "cpe_strings" in df.columns else None

    pending = list(df.index) if redo else list(df.index[df[JUDGMENT_COL].str.strip() == ""])
    if limit:
        pending = pending[:limit]
    if not pending:
        print("  Gemini: nothing to do — all rows already classified.")
        return 0

    use_batch = batch_size > 1
    n_calls = -(-len(pending) // batch_size) if use_batch else len(pending)
    print(
        f"  Gemini: classifying {len(pending)} rows with {model} "
        f"({'batch_size=' + str(batch_size) + ', ' if use_batch else ''}{n_calls} API calls) ..."
    )
    session = requests.Session()
    delay = 1.0 / rps if rps > 0 else 0.0
    done = 0

    def _write_row(idx, judgment, confidence, reasoning):
        if confidence == "High" and judgment != "Maybe":
            reasoning = ""
        df.at[idx, JUDGMENT_COL] = judgment
        df.at[idx, CONF_COL] = confidence
        df.at[idx, REASON_COL] = reasoning

    if use_batch:
        chunks = [pending[i : i + batch_size] for i in range(0, len(pending), batch_size)]
        for chunk in chunks:
            rows = [
                (df.at[idx, "cve_id"], df.at[idx, "description"], df.at[idx, cpe_col] if cpe_col else "")
                for idx in chunk
            ]
            prompt = build_batch_prompt(rubric, category, rows, scope_note)
            try:
                results = call_with_retry(session, api_key, model, prompt, batch=True)
            except Exception as e:
                cve_ids = [r[0] for r in rows]
                print(f"    batch {cve_ids}: error {e} — left blank for retry")
                if delay:
                    time.sleep(delay)
                continue

            # Map results back by cve_id; rows missing from the response stay blank.
            idx_by_cve = {df.at[idx, "cve_id"]: idx for idx in chunk}
            for cve_id, (judgment, confidence, reasoning) in results.items():
                if cve_id not in idx_by_cve:
                    print(f"    warning: model returned unknown cve_id {cve_id!r} — ignored")
                    continue
                _write_row(idx_by_cve[cve_id], judgment, confidence, reasoning)
                done += 1

            missing = [df.at[idx, "cve_id"] for idx in chunk if df.at[idx, JUDGMENT_COL].strip() == ""]
            if missing:
                print(f"    warning: model omitted {missing} — left blank for retry")

            if done % save_every < batch_size:
                df.to_csv(csv_path, index=False)
                print(f"    ...{done}/{len(pending)} saved")
            if delay:
                time.sleep(delay)
    else:
        for idx in pending:
            prompt = build_prompt(
                rubric, category, df.at[idx, "description"],
                df.at[idx, cpe_col] if cpe_col else "", scope_note,
            )
            try:
                judgment, confidence, reasoning = call_with_retry(session, api_key, model, prompt)
            except Exception as e:
                print(f"    row {idx} ({df.at[idx, 'cve_id']}): error {e} — left blank for retry")
                if delay:
                    time.sleep(delay)
                continue

            _write_row(idx, judgment, confidence, reasoning)
            done += 1
            if done % save_every == 0:
                df.to_csv(csv_path, index=False)
                print(f"    ...{done}/{len(pending)} saved")
            if delay:
                time.sleep(delay)

    df.to_csv(csv_path, index=False)
    print(f"  Gemini: classified {done} rows; saved to {csv_path}")
    return done


def main():
    ap = argparse.ArgumentParser(description="Classify a Gemini review copy via the Gemini API.")
    ap.add_argument("csv", help="Path to the Gemini review copy (gemini.csv)")
    ap.add_argument("--category", required=True, help="Device category, e.g. 'security camera'")
    ap.add_argument("--model", default=os.environ.get("GEMINI_MODEL", DEFAULT_MODEL))
    ap.add_argument("--rubric", default=RUBRIC_DEFAULT, help="Path to the shared rubric markdown")
    ap.add_argument("--scope", default=SCOPE_DEFAULT, help="Path to category_scope.csv (per-category in/out notes)")
    ap.add_argument("--slug", default=None,
                    help="Category slug for the scope lookup (default: derived from the csv path)")
    ap.add_argument("--rps", type=float, default=1.0, help="Max requests per second")
    ap.add_argument("--save-every", type=int, default=25, help="Write progress to disk every N rows")
    ap.add_argument("--limit", type=int, default=0, help="Classify only the first N pending rows (0 = all)")
    ap.add_argument("--redo", action="store_true", help="Re-classify rows that already have a Gemini judgment")
    ap.add_argument("--batch-size", type=int, default=1,
                    help="Rows per API call (default 1 = one row at a time; try 20 to cut round-trips ~20x)")
    args = ap.parse_args()

    try:
        classify_file(
            args.csv,
            args.category,
            model=args.model,
            rubric_path=args.rubric,
            scope_path=args.scope,
            slug=args.slug,
            rps=args.rps,
            save_every=args.save_every,
            limit=args.limit,
            redo=args.redo,
            batch_size=args.batch_size,
        )
    except (RuntimeError, FileNotFoundError, ValueError) as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
