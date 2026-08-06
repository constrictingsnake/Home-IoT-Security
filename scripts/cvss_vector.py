#!/usr/bin/env python3
"""CVSS vector-string parsing, normalised to the CVSS 3.x metric set.

Shared by scripts/cvss_analysis.py (RQ3 distributions) and
scripts/ontology_build.py (the instance KG's vector predicates), so both read a
vector the same way and the graph can never disagree with the tables it is
verified against. Deliberately dependency-free — the ontology gate must not
acquire a scipy dependency just to read a metric value.

The 3.x pin, and the 4.0 back-conversion, follow the 2025 paper extension
(Onboarding-Docs/2025_Paper_Extension (1).pdf, Section V-B): not every old CVE
has a 4.0 vector and not every new one has a 3.x vector, and 3.x -> 4.0 is
lossy (4.0 dropped Scope), so 4.0 is converted back rather than forward.
"""

# Long-form value names, and the order they are reported in. Ordering is the
# CVSS spec's own (most→least remote for AV, least→most privileged for PR), so
# a table reads the way the extension's Figs. 8-10 do.
AV_NAMES = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
AC_NAMES = {"L": "Low", "H": "High"}
PR_NAMES = {"N": "None", "L": "Low", "H": "High"}
UI_NAMES = {"N": "None", "R": "Required"}
S_NAMES = {"U": "Unchanged", "C": "Changed"}
CIA_NAMES = {"N": "None", "L": "Low", "H": "High"}

METRIC_ORDER = [
    ("attack_vector", ["Network", "Adjacent", "Local", "Physical"]),
    ("attack_complexity", ["Low", "High"]),
    ("privileges_required", ["None", "Low", "High"]),
    ("user_interaction", ["None", "Required"]),
    ("scope", ["Unchanged", "Changed"]),
    ("confidentiality", ["High", "Low", "None"]),
    ("integrity", ["High", "Low", "None"]),
    ("availability", ["High", "Low", "None"]),
    ("impact_combination", ["C+I+A", "C+I", "C+A", "I+A", "C", "I", "A", "none"]),
]


def parse_vector(vector_string):
    """CVSS vector string -> dict of CVSS 3.x metric values (long names), or None.

    Handles 3.0/3.1 directly and back-converts 4.0 per the extension's method.
    Returns None for a 2.0 vector (no Scope metric, and N/P/C impact values are
    not 3.x's N/L/H — converting would invent data) or anything unparseable.
    """
    vs = (vector_string or "").strip()
    if not vs:
        return None
    parts = vs.split("/")
    if not parts[0].startswith("CVSS:"):
        return None                      # bare v2 vector, e.g. AV:N/AC:L/Au:N/C:P/I:P/A:P
    version = parts[0].split(":", 1)[1]
    f = dict(p.split(":", 1) for p in parts[1:] if ":" in p)

    if version.startswith("3."):
        try:
            return {
                "attack_vector": AV_NAMES[f["AV"]],
                "attack_complexity": AC_NAMES[f["AC"]],
                "privileges_required": PR_NAMES[f["PR"]],
                "user_interaction": UI_NAMES[f["UI"]],
                "scope": S_NAMES[f["S"]],
                "confidentiality": CIA_NAMES[f["C"]],
                "integrity": CIA_NAMES[f["I"]],
                "availability": CIA_NAMES[f["A"]],
            }
        except KeyError:
            return None

    if version.startswith("4."):
        try:
            # 4.0 renamed the vulnerable-system impact metrics VC/VI/VA; they are
            # the 3.x C/I/A. It also dropped Scope in favour of a separate
            # subsequent-system impact (SC/SI/SA) — any non-None value there is
            # exactly what Scope: Changed meant, so that is the back-conversion.
            subsequent_hit = any(f.get(k, "N") != "N" for k in ("SC", "SI", "SA"))
            # 4.0's User Interaction has three values (None/Passive/Active);
            # both non-None values collapse to 3.x's Required.
            ui = "None" if f.get("UI", "N") == "N" else "Required"
            return {
                "attack_vector": AV_NAMES[f["AV"]],
                "attack_complexity": AC_NAMES[f["AC"]],
                "privileges_required": PR_NAMES[f["PR"]],
                "user_interaction": ui,
                "scope": "Changed" if subsequent_hit else "Unchanged",
                "confidentiality": CIA_NAMES[f["VC"]],
                "integrity": CIA_NAMES[f["VI"]],
                "availability": CIA_NAMES[f["VA"]],
            }
        except KeyError:
            return None

    return None


def impact_combination(metrics):
    """Which of C/I/A a CVE actually affects, as the extension's Fig. 10 combos."""
    hit = [letter for letter, key in (("C", "confidentiality"),
                                      ("I", "integrity"),
                                      ("A", "availability"))
           if metrics[key] != "None"]
    return "+".join(hit) if hit else "none"
