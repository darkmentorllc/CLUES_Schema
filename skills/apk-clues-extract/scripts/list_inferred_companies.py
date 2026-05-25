#!/usr/bin/env python3
"""Phase-2 helper: list every (package_id, current_company) pair in a CLUES
output JSON whose `company` still carries the static-pass `(inferred from
package id)` marker. The Phase-2 web-enrichment agent reads this list,
runs WebSearch on each package_id, and produces a mapping JSON that
`apply_company_enrichment.py` then folds back into the CLUES file.

Usage:
    python3 list_inferred_companies.py CLUES_data_LLM_Android_APK_search.json

Output format (stdout, JSON):
    {
        "needs_enrichment": [
            { "package_id": "com.foo.bar", "current_company": "Foo (inferred from package id)", "record_count": 12 },
            ...
        ],
        "already_resolved": ["com.abbott.lingo.wellness", ...]
    }
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict


INFERRED_MARKER = "(inferred from package id)"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        sys.stderr.write(f"usage: {sys.argv[0]} CLUES_data_LLM_Android_APK_search.json\n")
        return 2
    path = argv[0]
    from clues_io import load_clues
    data = load_clues(path)

    # Per-package totals + per-package "any record still inferred" flag.
    # A package needs enrichment as long as AT LEAST ONE of its records still
    # carries the `(inferred from package id)` marker. Mixed packages (some
    # records curated, others not) are common: e.g. a host app whose own
    # UUIDs are inferred from the package id, but it also touches shared-SDK
    # UUIDs that got pre-tagged as `Unidentified shared SDK` (Phase 4).
    pkg_count: dict[str, int] = defaultdict(int)
    pkg_any_inferred: dict[str, bool] = defaultdict(bool)
    # Track the most-informative "current_company" for display: prefer one
    # of the inferred-marker values if any exists (that's the one Phase 2
    # will try to upgrade); otherwise fall back to whatever we see.
    pkg_display_company: dict[str, str] = {}
    for rec in data:
        company = rec.get("company", "Unknown")
        record_is_inferred = INFERRED_MARKER in company or company == "Unknown"
        for info in rec.get("android_info_array", []):
            pid = info.get("package_id")
            if not pid:
                continue
            pkg_count[pid] += 1
            if record_is_inferred:
                pkg_any_inferred[pid] = True
                pkg_display_company[pid] = company  # prefer the inferred form for the report
            else:
                pkg_display_company.setdefault(pid, company)

    needs = []
    resolved = []
    for pid in sorted(pkg_count):
        if pkg_any_inferred.get(pid):
            needs.append({
                "package_id": pid,
                "current_company": pkg_display_company.get(pid, "Unknown"),
                "record_count": pkg_count[pid],
            })
        else:
            resolved.append(pid)

    json.dump(
        {"needs_enrichment": needs, "already_resolved": resolved},
        sys.stdout,
        indent=2,
        ensure_ascii=False,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
