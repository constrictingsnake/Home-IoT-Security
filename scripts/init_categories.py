#!/usr/bin/env python3
"""Scaffold per-category folders for the Stage 4 difference review, from a list.

Reads a text file of category names (one per line). For each category that does NOT
already have a folder under data/intersect/, it creates the skeleton:

    data/intersect/<category>/
    └── reviews/            (where claude.csv / codex.csv / gemini.csv will live)

Categories whose folder already exists are left **completely untouched** — the script is
idempotent and safe to re-run whenever you add new names to the list. After a folder
exists, drop the difference set in as 01_raw.csv and run make_review_copies.py (then
merge_judgments.py) to populate it.

Blank lines and lines beginning with '#' are ignored.

Usage:
    python init_categories.py categories.txt
    python init_categories.py categories.txt --base data/intersect
"""
import argparse
import os

DEFAULT_BASE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "difference"
)


def read_categories(path):
    categories = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            name = line.strip()
            if not name or name.startswith("#"):
                continue
            categories.append(name)
    return categories


def main():
    ap = argparse.ArgumentParser(
        description="Scaffold per-category difference-review folders from a newline-separated list."
    )
    ap.add_argument("categories_file", help="Text file with one category name per line")
    ap.add_argument(
        "--base",
        default=DEFAULT_BASE,
        help="Base directory for the category folders (default: data/intersect)",
    )
    args = ap.parse_args()

    if not os.path.isfile(args.categories_file):
        ap.error(f"Category file not found: {args.categories_file}")

    categories = read_categories(args.categories_file)
    if not categories:
        print("No categories found in the file (only blanks/comments).")
        return

    created, skipped = 0, 0
    for category in categories:
        folder = os.path.join(args.base, category)
        if os.path.isdir(folder):
            print(f"  exists, skipping: {category}")
            skipped += 1
            continue
        reviews = os.path.join(folder, "reviews")
        os.makedirs(reviews, exist_ok=True)
        # Keep the otherwise-empty scaffold trackable in git until 01_raw.csv lands.
        open(os.path.join(reviews, ".gitkeep"), "w").close()
        print(f"  created: {category}/  (+ reviews/)")
        created += 1

    print(f"\nDone. {created} created, {skipped} already existed ({len(categories)} in list).")


if __name__ == "__main__":
    main()
