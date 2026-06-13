# AGENTS.md — Instructions for the Codex reviewer

This repo runs a **triple-AI review** of "difference" CVEs — vendor CVEs that the keyword
search missed. Three reviewers judge each row **independently and blind**: Claude Code,
**Codex (you)**, and Gemini (API). `CLAUDE.md` documents the whole pipeline; this file is
specifically your job as Codex.

## Your job
You are the **Codex reviewer**. For the device category you are given, fill in **only your own
columns** in `data/difference/<category>/reviews/codex.csv`:

| Column | Values | When |
|--------|--------|------|
| `Codex Judgment` | `Yes` / `No` / `Maybe` | every row |
| `Codex Confidence` | `High` / `Low` | every row |
| `Codex Reasoning` | short, self-contained | required for `Low` and `Maybe`; empty otherwise |

Do **not** edit `01_raw.csv`, `claude.csv`, `gemini.csv`, `02_merged.csv`, or any other
category's files. Keep the existing columns and row order; just fill your three columns.

## Hard rules
1. **Judge blind.** Use ONLY each row's `description` and `cpe_strings`. Ignore every other
   column and never look for, reference, or be influenced by another reviewer's answer. Your
   file deliberately does not contain the other reviewers' judgments — keep your judgment
   independent.
2. **Follow the shared rubric exactly:** [`data/difference/CLASSIFICATION_PROMPT.md`](data/difference/CLASSIFICATION_PROMPT.md).
   It is the single source of truth for what qualifies as a home IoT device and how to assign
   Judgment / Confidence / Reasoning. Do not invent your own criteria.
3. Fill every row, then save `codex.csv` in place.

## After you finish
The operator combines all three reviewers with:
```
python scripts/merge_judgments.py --reviews data/difference/<category>/reviews
```
This writes `02_merged.csv` and flags rows that need a human. You do not run the merge.
