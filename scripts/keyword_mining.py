#!/usr/bin/env python3
"""Keyword mining — surface device-type phrases missing from keyword_terms.csv.

`keyword_terms.csv` is hand-authored, so it systematically misses device-type language
that shows up in confirmed-Yes CVE descriptions but was never anticipated by a human.
This is the systematic version of what `03_keyword_additions.md` does anecdotally per
category: mine `final_resolved.csv` (the labelled Yes/No corpus from Stage 4 review) for
word n-grams that are discriminative of Yes over No, then score each survivor's real
new-yield against the snapshot using the exact matching semantics the real pipeline uses
(`cve_search.filter_by_keywords`, whole_word=True).

This script never edits keyword_terms.csv — it is read-only outside its two output
files. See docs/plans/PLAN_keyword_mining.md and CLAUDE.md (Stage 1/2 — keyword search)
for the full rationale, and docs/SCRIPTS_REFERENCE.md for the flag table.

Convention guard (CLAUDE.md): keyword_terms.csv holds device-type PHRASES ONLY — no
brands/protocols/firmware/umbrella terms. A candidate n-gram containing a token that is
itself a CPE vendor (>=3 CVEs in the snapshot) is brand-like and is routed to
keyword_candidates_brands.csv instead, for the vendor-mining side
(docs/plans/PLAN_cpe_brand_mining.md / cpe_brand_mining.py) to pick up.

Algorithm (see the plan doc for the full rationale):
  1. Per-category labelled doc sets from final_resolved.csv (Final Judgment Yes/No),
     pooled across all four review directions (the file already combines them).
     Categories with < 5 Yes rows are skipped — nothing to learn.
  2. Candidate 1-3-word n-grams extracted from Yes docs only, filtered: stopword-only
     edge tokens, CVE boilerplate / version-number / CWE language, already covered by
     an existing keyword_terms.csv term for that slug, and brand-like tokens (dropped
     to the side file).
  3. Discriminativeness score `n_yes * log((n_yes + 0.5) / (n_no + 0.5))`, keeping the
     top ~50 per category with n_yes >= 3 and n_yes > n_no. Deliberately simple — the
     human vet and the new-yield numbers do the real filtering, not this score.
  4. One snapshot pass (all surviving candidates across all categories at once) scores
     new_yield (CVEs neither text method already found, via cpe_expansion.load_known_cve_ids)
     and pct_device_cpe (fraction of new matches with a part in {o,h} CPE — low values
     signal a phrase that mostly matches software, a likely FP bomb).

Usage:
    python3 scripts/keyword_mining.py --all
    python3 scripts/keyword_mining.py streaming hub          # subset
    python3 scripts/keyword_mining.py --all --top 50 --min-yes 3

Writes data/keyword-search/keyword_candidates.csv (main output, sorted by new_yield
desc within each category) and data/keyword-search/keyword_candidates_brands.csv
(brand-filtered candidates, for the vendor-mining vet) plus a console summary.
"""
import argparse
import csv
import math
import os
import re
from collections import Counter, defaultdict

from cve_search import load_dataset, filter_by_keywords
from cpe_expansion import parse_cpe, DEVICE_PARTS, load_known_cve_ids
from build_search import read_terms
from build_review_sets import read_categories

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
SNAPSHOT = os.path.join(DATA, "nvd-snapshot", "nvd_all.csv")
CATEGORIES_PATH = os.path.join(DATA, "categories.csv")
FINAL_RESOLVED = os.path.join(DATA, "difference", "final_resolved.csv")
KEYWORD_TERMS_PATH = os.path.join(DATA, "keyword-search", "keyword_terms.csv")
OUT_PATH = os.path.join(DATA, "keyword-search", "keyword_candidates.csv")
BRANDS_OUT_PATH = os.path.join(DATA, "keyword-search", "keyword_candidates_brands.csv")

csv.field_size_limit(1 << 24)

MIN_YES_DOCS = 5  # categories below this are skipped — nothing to learn (plan Step 1)
MIN_VENDOR_CVES = 3  # brand filter: a token counts as "brand-like" at this CPE-vendor CVE count

STOPWORDS = {
    "the", "a", "of", "in", "and", "for", "with", "via", "an", "to", "is",
    # bare prepositions/particles — missing here let a 1-gram like "from"/"on"/"as"
    # survive as its own "candidate" (all_tokens_generic only drops a phrase whose
    # every token is listed, so a 1-token phrase needs that one token listed).
    "from", "on", "as", "at", "by", "into", "onto", "out",
}

# CVE boilerplate that would otherwise dominate discriminativeness scores without being
# a device-type phrase. Expected to grow on first run per the plan.
BOILERPLATE_PHRASES = {
    "buffer overflow", "remote attacker", "cross site scripting", "sql injection",
    "denial of service", "arbitrary code", "arbitrary code execution",
    "command injection", "authentication bypass", "firmware version", "web interface",
    "admin interface", "administrative interface", "default password",
    "path traversal", "privilege escalation", "stack based buffer",
    "heap based buffer", "out of bounds", "null pointer dereference",
    "memory corruption", "improper access control", "information disclosure",
    "code execution", "arbitrary file", "affected version", "prior to version",
    "allows remote", "allows attacker", "allows an attacker", "security update",
}

# Generic CVE-description vocabulary (attacker/buffer/overflow/version/exists/...) — a
# phrase is only dropped when EVERY token is in this set, so a compound like "security
# kit" or "http server"... survives on its non-generic token ("security") while a bare
# "buffer", "attacker can", or "vulnerability exists" (all-generic) is dropped. Discovered
# empirically on the first run (small-No-doc categories let boilerplate score highest —
# see PLAN_keyword_mining.md Step 2) — grown here per the plan's expectation.
GENERIC_CVE_WORDS = {
    "attacker", "attackers", "vulnerability", "vulnerabilities", "exploit", "exploits",
    "exploited", "exploiting", "exploitable", "exploitation", "remote", "local",
    "allows", "allow", "allowing", "allowed", "could", "would", "should", "can",
    "result", "results", "resulting", "resulted", "due", "prior", "version", "versions",
    "exist", "exists", "existing", "present", "contain", "contains", "contained",
    "discover", "discovers", "discovered", "disclose", "discloses", "disclosed",
    "disclosure", "arbitrary", "execute", "executes", "executed", "execution", "code",
    "buffer", "overflow", "overflows", "overflowed", "underflow", "injection",
    "inject", "injects", "injected", "bypass", "bypasses", "bypassed", "escalation",
    "privilege", "privileges", "unauthorized", "unauthenticated", "authentication",
    "authenticated", "session", "sessions", "token", "tokens", "parameter",
    "parameters", "request", "requests", "response", "responses", "input", "inputs",
    "output", "outputs", "function", "functions", "functionality", "module",
    "modules", "component", "components", "process", "processes", "processing",
    "service", "services", "application", "applications", "product", "products",
    "system", "systems", "file", "files", "directory", "directories", "path",
    "paths", "url", "urls", "http", "https", "api", "network", "memory", "cause",
    "causes", "caused", "causing", "potentially", "successful", "successfully",
    "may", "might", "affect", "affects", "affected", "affecting", "issue", "issues",
    "flaw", "flaws", "weakness", "weaknesses", "condition", "conditions", "occur",
    "occurs", "occurred", "occurring", "before", "after", "certain", "specific",
    "crafted", "malicious", "user", "users", "information", "error", "errors",
    "handling", "validate", "validates", "validation", "validated", "sanitize",
    "sanitizes", "sanitization", "sanitized", "permission", "permissions", "access",
    "control", "controls", "without", "following", "use", "uses", "used", "using",
    "this", "that", "these", "those", "send", "sends", "sent", "obtain", "obtains",
    "obtained", "gain", "gains", "gained", "denial", "dos", "server", "servers",
    "interface", "interfaces", "page", "pages", "field", "fields", "string",
    "strings", "value", "values", "object", "objects", "class", "classes",
    "method", "methods", "header", "headers", "cookie", "cookies", "form", "forms",
    "data", "unspecified", "multiple", "various", "several", "known", "publicly",
    "vendor", "vendors", "manufacturer", "manufacturers", "model", "models",
    "firmware", "hardware", "software", "device", "devices", "order", "kit",
    "lead", "leads", "leading", "trigger", "triggers", "triggered", "triggering",
    "long", "size", "specially-crafted", "inc", "llc", "ltd", "corp", "corporation",
    "incorporated", "co",
    # common English function words (pronouns/aux-verbs/conjunctions/prepositions/
    # determiners) — CVE descriptions are full sentences, so these swamp the
    # discriminativeness score exactly like the CVE-jargon words above.
    "which", "who", "whom", "whose", "what", "when", "where", "why", "how",
    "has", "have", "had", "having", "is", "are", "was", "were", "be", "been",
    "being", "am", "do", "does", "did", "doing", "will", "shall", "must", "ought",
    "not", "no", "nor", "but", "or", "so", "yet", "then", "than", "if", "whether",
    "although", "though", "while", "whereas", "unless", "upon", "within",
    "between", "among", "through", "over", "under", "above", "below", "up",
    "down", "off", "about", "against", "during", "near", "around", "across",
    "per", "toward", "towards", "throughout", "along", "amid", "beside",
    "besides", "despite", "except", "inside", "outside", "regarding", "unlike",
    "own", "same", "too", "very", "just", "even", "still", "again", "further",
    "once", "here", "there", "now", "some", "any", "every", "each", "both",
    "either", "neither", "another", "other", "others", "such", "more", "most",
    "less", "least", "much", "many", "one", "two", "three", "four", "five",
    "six", "seven", "eight", "nine", "ten", "first", "second", "third", "last",
    "next", "new", "bytes", "byte", "destination", "source", "copy", "copies",
    "copied", "length", "attack", "attacks", "attacking", "call", "calls",
    "called", "calling", "incorrect", "improper", "invalid", "insufficient",
    "inadequate", "listed", "list", "lists", "below", "home",
    # Apple multi-OS advisory boilerplate ("issue was addressed with improved
    # validation"; "fixed in macOS X, iOS Y") — the streaming category's Yes corpus
    # is heavily Apple TV, and these platform names are exactly what
    # GENERIC_PLATFORM_CPES already denies at the CPE level (CLAUDE.md Stage 5
    # guardrail 2c); this is the text-search analog of that same guardrail.
    "fixed", "addressed", "improved", "macos", "ios", "ipados", "watchos",
    "handler", "handlers", "param", "params", "parser", "arbitrarily", "os",
    "safari", "windows",
    # macOS release codenames — same shared-desktop-platform boilerplate class as
    # macos/ios above, just spelled as a marketing name instead of the OS name.
    "sonoma", "ventura", "sequoia", "sur", "catalina", "monterey", "mojave",
    "icloud", "visionos",
    # Found leaking through as top-scoring "candidates" on the first --all run —
    # generic CVE-description / infosec vocabulary that isn't a device-type phrase,
    # grown here the same way the block above was (empirically, per the plan).
    "note", "notes", "number", "numbers", "password", "passwords", "unknown",
    "root", "high", "low", "way", "ways", "early", "late",
    "respond", "responds", "responding", "responded",
    "contact", "contacts", "contacted", "contacting",
    "corruption", "corrupt", "corrupted", "corrupting",
    "app", "apps", "able", "unable", "build", "builds", "simply",
    "reboot", "reboots", "rebooted", "rebooting", "manipulation", "context",
    "lack", "proper", "leverage", "leverages", "leveraging", "leveraged",
    "installation", "installations", "json", "web", "site", "sites",
    "payload", "payloads", "stack", "stacks",
    "required", "require", "requires", "requiring", "incorrectly",
    "change", "changes", "changed", "changing", "because", "only",
    "credential", "credentials", "read", "reads", "reading",
    "update", "updates", "updated", "updating", "electronics",
    "command", "commands", "big", "maliciously",
    "it", "its", "involve", "involves", "involving", "involved",
    "management", "manage", "manages", "managed", "managing",
    "content", "contents", "make", "makes", "making", "made",
    "action", "actions", "xml", "format", "formats", "formatted", "formatting",
    "arise", "arises", "arising", "arose", "sensitive", "key", "keys",
    "valid", "validity", "admin", "administrator", "administrators", "series",
    "deviceid",
    # Hyphenated compounds are one TOKEN_RE token (hyphens don't split), so each
    # needs its own entry — they don't ride in on the bare-word form above.
    "denial-of-service", "man-in-the-middle", "network-adjacent",
    "user-supplied", "user-controlled", "heap-based", "stack-based",
}

TOKEN_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
VERSIONISH_RE = re.compile(r"^v?\d+[a-z]?$")  # version numbers: 79, 9x, 9z, v1, v2 ...
CWE_RE = re.compile(r"^cwe-\d+$")


def tokenize(text):
    # Strip apostrophes before matching so a possessive/contraction ("device's",
    # "don't") merges into one token instead of spawning an orphan "s"/"t" fragment.
    return TOKEN_RE.findall(text.replace("'", ""))


def ngrams(tokens, n_max=3):
    """Space-joined n-grams (1..n_max), sliding window over consecutive tokens."""
    n = len(tokens)
    for i in range(n):
        for size in (1, 2, 3):
            if size > n_max or i + size > n:
                break
            yield " ".join(tokens[i:i + size])


def singularize_last(phrase):
    """Strip a trailing plural 's'/'es' off the last token — cheap normalization so
    'ip cameras' compares equal to 'ip camera' without a real stemmer (deliberately
    simple, per the plan)."""
    toks = phrase.split(" ")
    last = toks[-1]
    if last.endswith("es") and len(last) > 4:
        toks[-1] = last[:-2]
    elif last.endswith("s") and len(last) > 3:
        toks[-1] = last[:-1]
    return " ".join(toks)


def doc_freqs(docs):
    """phrase -> number of docs containing it (doc-set n-grams, deduped per doc)."""
    freq = Counter()
    for doc in docs:
        toks = tokenize(doc)
        freq.update(set(ngrams(toks)))
    return freq


def load_labelled_docs():
    """category -> (yes_docs, no_docs), lowercased descriptions, from final_resolved.csv
    (already pools all four Stage-4 review directions)."""
    yes_docs = defaultdict(list)
    no_docs = defaultdict(list)
    with open(FINAL_RESOLVED, newline="") as f:
        for r in csv.DictReader(f):
            desc = (r.get("description") or "").strip().lower()
            if not desc:
                continue
            judgment = (r.get("Final Judgment") or "").strip().lower()
            cat = r["Category"]
            if judgment == "yes":
                yes_docs[cat].append(desc)
            elif judgment == "no":
                no_docs[cat].append(desc)
    return yes_docs, no_docs


def norm_phrase(s):
    return " ".join((s or "").strip().casefold().split())


def is_covered(phrase, existing_terms):
    """True if `phrase` equals, contains, or is contained by an existing term (both
    singularized), padded with spaces so containment respects word boundaries."""
    p = f" {singularize_last(norm_phrase(phrase))} "
    for term in existing_terms:
        t = f" {singularize_last(norm_phrase(term))} "
        if t in p or p in t:
            return True
    return False


def is_boilerplate(phrase):
    # TOKEN_RE keeps a hyphenated compound ("heap-based") as one token, so the 2-gram
    # "heap-based buffer" never string-equals the space-joined boilerplate entry
    # "heap based buffer" (3 space-separated words) without this normalization.
    dehyphenated = phrase.replace("-", " ")
    candidates = (phrase, singularize_last(phrase), dehyphenated, singularize_last(dehyphenated))
    return any(c in BOILERPLATE_PHRASES for c in candidates)


def has_version_or_cwe_token(toks):
    return any(VERSIONISH_RE.match(t) or t == "cwe" or CWE_RE.match(t) for t in toks)


def all_tokens_generic(toks):
    # STOPWORDS is folded in here (not just the edge check) so an interior filler
    # word ("attacker TO obtain") doesn't save an otherwise-all-generic phrase.
    return all(t in GENERIC_CVE_WORDS or t in STOPWORDS for t in toks)


def vendor_token(cpe):
    parts = cpe.split(":")
    if len(parts) < 5:
        return None
    v = parts[3].strip().lower()
    return v if v and v not in ("*", "-") else None


def build_vendor_counts(cves):
    """token -> distinct CVE count, from every CPE vendor field in the snapshot (one
    pass over the already-loaded in-memory list — no extra disk read)."""
    counts = Counter()
    for cve in cves:
        vendors = {v for c in cve["cpe_strings"] if (v := vendor_token(c))}
        counts.update(vendors)
    return counts


def brand_token_in(toks, vendor_counts):
    for t in toks:
        if vendor_counts.get(t, 0) >= MIN_VENDOR_CVES:
            return t
        t_us = t.replace("-", "_")
        if t_us != t and vendor_counts.get(t_us, 0) >= MIN_VENDOR_CVES:
            return t_us
    return None


def mine_category(cat, yes_docs, no_docs, existing_terms, vendor_counts, top_n, min_yes):
    """Steps 2+3 for one category -> (kept [(phrase, n_yes, n_no, score), ...], brand_dropped)."""
    if len(yes_docs) < MIN_YES_DOCS:
        print(f"  {cat}: only {len(yes_docs)} Yes doc(s) (< {MIN_YES_DOCS}) — skipping")
        return [], []

    yes_freq = doc_freqs(yes_docs)
    no_freq = doc_freqs(no_docs) if no_docs else Counter()
    slug_terms = existing_terms.get(cat, [])

    kept = []
    brand_dropped = []
    for phrase, n_yes in yes_freq.items():
        if n_yes < min_yes:
            continue
        toks = phrase.split(" ")
        if toks[0] in STOPWORDS or toks[-1] in STOPWORDS:
            continue
        if is_boilerplate(phrase) or has_version_or_cwe_token(toks) or all_tokens_generic(toks):
            continue
        if is_covered(phrase, slug_terms):
            continue
        brand_tok = brand_token_in(toks, vendor_counts)
        if brand_tok:
            brand_dropped.append({"category": cat, "phrase": phrase, "reason_vendor_token": brand_tok})
            continue

        n_no = no_freq.get(phrase, 0)
        if n_no >= n_yes:
            continue
        score = n_yes * math.log((n_yes + 0.5) / (n_no + 0.5))
        kept.append((phrase, n_yes, n_no, score))

    kept.sort(key=lambda x: -x[3])
    return kept[:top_n], brand_dropped


def score_new_yield(all_candidates_by_cat, cves):
    """Step 4 — one filter_by_keywords pass over the whole snapshot for every surviving
    candidate phrase across every category at once. Returns {(cat, phrase): {new_yield,
    pct_device_cpe, samples}}."""
    phrase_to_cats = defaultdict(set)
    for cat, rows in all_candidates_by_cat.items():
        for phrase, *_ in rows:
            phrase_to_cats[phrase].add(cat)
    unique_terms = list(phrase_to_cats)
    if not unique_terms:
        return {}

    print(f"Scoring new-yield for {len(unique_terms)} unique candidate phrase(s) "
          f"against {len(cves):,} snapshot CVEs (one pass)...")
    matches, _counts, matched_terms = filter_by_keywords(cves, unique_terms, whole_word=True)

    term_to_cve_ids = defaultdict(list)
    for cve in matches:
        cid = cve["cve_id"]
        for term in matched_terms.get(cid, []):
            term_to_cve_ids[term].append(cid)
    cve_by_id = {c["cve_id"]: c for c in matches}

    results = {}
    known_cache = {}
    for cat, rows in all_candidates_by_cat.items():
        known = known_cache.setdefault(cat, load_known_cve_ids(cat))
        for phrase, _n_yes, _n_no, _score in rows:
            new_ids = [cid for cid in term_to_cve_ids.get(phrase, []) if cid not in known]
            device_hits = 0
            samples = []
            for cid in new_ids:
                cve = cve_by_id[cid]
                if any(parse_cpe(c)[0] in DEVICE_PARTS for c in cve["cpe_strings"]):
                    device_hits += 1
                if len(samples) < 3:
                    samples.append((cid, (cve["description"] or "")[:150]))
            pct_device = round(device_hits / len(new_ids), 3) if new_ids else 0.0
            results[(cat, phrase)] = dict(new_yield=len(new_ids), pct_device_cpe=pct_device, samples=samples)
    return results


CANDIDATE_COLS = [
    "category", "phrase", "n_yes", "n_no", "score", "new_yield",
    "pct_device_cpe", "sample_cves", "sample_descriptions",
]
BRAND_COLS = ["category", "phrase", "reason_vendor_token"]


def write_candidates(rows):
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CANDIDATE_COLS)
        w.writeheader()
        w.writerows(rows)
    return OUT_PATH


def write_brand_candidates(rows):
    os.makedirs(os.path.dirname(BRANDS_OUT_PATH), exist_ok=True)
    with open(BRANDS_OUT_PATH, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=BRAND_COLS)
        w.writeheader()
        w.writerows(rows)
    return BRANDS_OUT_PATH


def print_summary(rows, brand_rows, categories):
    by_cat = defaultdict(list)
    for r in rows:
        by_cat[r["category"]].append(r)
    grand_new = 0
    for cat in categories:
        crows = by_cat.get(cat)
        if not crows:
            continue
        crows.sort(key=lambda r: -r["new_yield"])
        total_new = sum(r["new_yield"] for r in crows)
        grand_new += total_new
        print(f"\n=== {cat}: {len(crows)} candidate phrase(s), {total_new} total new-yield CVE(s) ===")
        for r in crows[:10]:
            print(f"  {r['phrase']:<32} n_yes={r['n_yes']:<4} n_no={r['n_no']:<4} "
                  f"score={r['score']:<8.2f} new_yield={r['new_yield']:<5} "
                  f"pct_device_cpe={r['pct_device_cpe']}")
    print(f"\n=== TOTAL: {len(rows)} candidate (category, phrase) pair(s), {grand_new} new-yield CVE(s) "
          f"across {len(by_cat)} categor(y/ies) ===")
    print(f"-> {os.path.relpath(OUT_PATH, ROOT)}")
    print(f"-> {len(brand_rows)} brand-filtered candidate(s) -> {os.path.relpath(BRANDS_OUT_PATH, ROOT)}")


def run(categories, top_n, min_yes):
    print("Loading final_resolved.csv (labelled corpus) and keyword_terms.csv...")
    yes_docs, no_docs = load_labelled_docs()
    existing_terms = read_terms(KEYWORD_TERMS_PATH)

    print(f"Loading NVD snapshot ({os.path.relpath(SNAPSHOT, ROOT)})...")
    cves = load_dataset(SNAPSHOT)
    vendor_counts = build_vendor_counts(cves)
    print(f"  {len(vendor_counts):,} distinct CPE vendor token(s) seen "
          f"(brand filter threshold: >= {MIN_VENDOR_CVES} CVEs)")

    print(f"Mining n-grams for {len(categories)} categor(y/ies)...")
    all_candidates_by_cat = {}
    brand_rows = []
    for cat in categories:
        kept, dropped = mine_category(
            cat, yes_docs.get(cat, []), no_docs.get(cat, []),
            existing_terms, vendor_counts, top_n, min_yes,
        )
        if kept:
            all_candidates_by_cat[cat] = kept
        brand_rows.extend(dropped)

    if not all_candidates_by_cat:
        print("No candidates survived filtering for any category.")
        write_candidates([])
        write_brand_candidates(brand_rows)
        return [], brand_rows

    yield_info = score_new_yield(all_candidates_by_cat, cves)

    rows = []
    for cat, kept in all_candidates_by_cat.items():
        for phrase, n_yes, n_no, score in kept:
            info = yield_info.get((cat, phrase), dict(new_yield=0, pct_device_cpe=0.0, samples=[]))
            samples = info["samples"]
            rows.append({
                "category": cat, "phrase": phrase, "n_yes": n_yes, "n_no": n_no,
                "score": round(score, 3), "new_yield": info["new_yield"],
                "pct_device_cpe": info["pct_device_cpe"],
                "sample_cves": "|".join(c for c, _d in samples),
                "sample_descriptions": "|".join(d for _c, d in samples),
            })

    rows.sort(key=lambda r: (r["category"], -r["new_yield"]))
    write_candidates(rows)
    write_brand_candidates(brand_rows)
    print_summary(rows, brand_rows, categories)
    return rows, brand_rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("categories", nargs="*", help="category slug(s); omit when using --all")
    ap.add_argument("--all", action="store_true", help="every category in categories.csv")
    ap.add_argument("--top", type=int, default=50,
                    help="max candidates kept per category before yield scoring (default: 50)")
    ap.add_argument("--min-yes", type=int, default=3,
                    help="min Yes-doc frequency required for a candidate (default: 3)")
    args = ap.parse_args()

    if args.all:
        cats = read_categories(CATEGORIES_PATH)
    elif args.categories:
        cats = args.categories
    else:
        ap.error("give one or more category slugs, or --all")

    run(cats, args.top, args.min_yes)


if __name__ == "__main__":
    main()
