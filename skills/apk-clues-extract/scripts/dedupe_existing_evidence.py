#!/usr/bin/env python3
"""One-shot maintenance helper: walk an existing CLUES JSON file and apply
`dedupe_evidence_array` to every record. Use this once to clean up files that
were produced before the dedup safeguard was added to `extract_clues.py`.

Usage:
    python3 dedupe_existing_evidence.py CLUES_data_LLM_Android_APK_search.json [...more files]

The script:
  - Reads each file, applies dedupe_evidence_array per record.
  - Re-sorts records by (UUID-length, UUID) for stable diffs (matches
    `save_output` / `apply_*.py` behavior).
  - Writes back atomically (via .tmp + os.replace).
  - Reports per-file: records touched, evidence entries collapsed.

This is idempotent — running it on an already-deduped file is a no-op on
content (just touches mtime).
"""
from __future__ import annotations

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from extract_clues import dedupe_evidence_array  # noqa: E402


def dedupe_file(path: str) -> tuple[int, int, int]:
    """Apply dedupe to one CLUES JSON file. Returns
    (records_total, records_touched, evidence_entries_collapsed)."""
    from clues_io import load_clues, save_clues
    data = load_clues(path)
    if not data:
        sys.stderr.write(f"{path}: no records found (file missing or empty)\n")
        return (0, 0, 0)

    touched = 0
    collapsed = 0
    for rec in data:
        if not isinstance(rec, dict):
            continue
        ev = rec.get("evidence_array")
        if not ev:
            continue
        before = len(ev)
        deduped = dedupe_evidence_array(ev)
        after = len(deduped)
        if after != before:
            collapsed += (before - after)
            touched += 1
            rec["evidence_array"] = deduped

    data.sort(key=lambda r: (len(r.get("UUID", "")), r.get("UUID", "")))
    save_clues(data, path)
    return (len(data), touched, collapsed)


def main(argv: list[str]) -> int:
    if not argv:
        sys.stderr.write(f"usage: {sys.argv[0]} CLUES.json [...more files]\n")
        return 2
    grand_records = 0
    grand_touched = 0
    grand_collapsed = 0
    for path in argv:
        total, touched, collapsed = dedupe_file(path)
        sys.stderr.write(
            f"{path}: {total} records, "
            f"deduped {touched} records, "
            f"removed {collapsed} duplicate evidence entries\n"
        )
        grand_records += total
        grand_touched += touched
        grand_collapsed += collapsed
    if len(argv) > 1:
        sys.stderr.write(
            f"\nTOTAL: {grand_records} records across {len(argv)} files, "
            f"deduped {grand_touched} records, "
            f"removed {grand_collapsed} duplicate evidence entries\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
