#!/usr/bin/env python3
"""Phase-2 helper: apply a {package_id -> confirmed_company_name} mapping
produced by web search to a CLUES output JSON, and emit the Python-snippet
diff needed to extend `KNOWN_VENDOR_PACKAGES` in `extract_clues.py` so future
runs hit the table directly (preferred — reusable across all future scans).

Usage:
    python3 apply_company_enrichment.py CLUES_data_LLM_Android_APK_search.json mapping.json

`mapping.json` is a flat object:
    {
        "com.tntkhang.gtswatchface": "SmartWatchCenter",
        "com.monbuilding.app.legende": "Witco (formerly MonBuilding)",
        ...
    }

The script:
  1. Loads the CLUES file in place.
  2. For each record whose `android_info_array` mentions a mapped package_id,
     replaces the record's `company` with the confirmed value — but ONLY if
     the existing company is the `(inferred from package id)` placeholder
     (it never overwrites a previously-curated value).
  3. Writes the CLUES file back, sorted by UUID for stable diffs.
  4. Prints to stdout the suggested `KNOWN_VENDOR_PACKAGES` additions, keyed
     by the second-most-vendor-like package component (the one
     `extract_clues.company_from_package` would have matched), so a curator
     can paste the diff into `extract_clues.py` and benefit every future run.
"""
from __future__ import annotations

import json
import os
import sys

# Imported only to reuse the same TLD-like filter the extractor uses, so the
# `KNOWN_VENDOR_PACKAGES` diff we suggest is keyed the same way the extractor
# will look up.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from extract_clues import _TLDLIKE_COMPONENTS as TLDLIKE  # noqa: E402
from extract_clues import KNOWN_VENDOR_PACKAGES as KVP  # noqa: E402

INFERRED_MARKER = "(inferred from package id)"


def vendor_key_for(package_id: str) -> str | None:
    """Same logic as company_from_package: pick the first non-TLD-like,
    ≥3-char, non-numeric component. That's the key the in-script table is
    indexed by."""
    parts = [p for p in package_id.split(".") if p]
    for p in parts:
        if p.lower() in TLDLIKE:
            continue
        if p.isdigit() or len(p) < 3:
            continue
        return p.lower()
    return None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write(
            f"usage: {sys.argv[0]} CLUES_data_LLM_Android_APK_search.json mapping.json\n"
        )
        return 2
    clues_path, mapping_path = argv

    with open(mapping_path, "r", encoding="utf-8") as f:
        mapping_raw = json.load(f)
    if not isinstance(mapping_raw, dict):
        sys.stderr.write("mapping file must be a JSON object {package_id: company_name}\n")
        return 2
    # Normalize keys.
    mapping: dict[str, str] = {
        k.strip(): v.strip() for k, v in mapping_raw.items() if v and v.strip()
    }
    if not mapping:
        sys.stderr.write("mapping is empty; nothing to do\n")
        return 0

    from clues_io import load_clues, save_clues
    from company_sanitizer import sanitize_for_write
    data = load_clues(clues_path)

    # Sanitize the mapping ONCE up front so a stray "(Japan) — ..." in the
    # agent's Phase-2 output gets stripped before it ever lands in `company`.
    # We collect the stripped commentary as a per-package evidence entry,
    # and tack it onto every record the mapping touches below.
    sanitized_mapping: dict[str, str] = {}
    extra_evidence_by_pid: dict[str, dict] = {}
    for pid, raw in mapping.items():
        cleaned, ev = sanitize_for_write(
            raw, source=f"Phase-2 package_id={pid}", warn=True,
        )
        sanitized_mapping[pid] = cleaned
        if ev is not None:
            extra_evidence_by_pid[pid] = ev

    patched = 0
    for rec in data:
        current = rec.get("company", "")
        if INFERRED_MARKER not in current and current != "Unknown":
            continue  # never overwrite a curated value
        pkg_ids = [
            info.get("package_id", "")
            for info in rec.get("android_info_array", [])
        ]
        for pid in pkg_ids:
            if pid in sanitized_mapping:
                rec["company"] = sanitized_mapping[pid]
                if pid in extra_evidence_by_pid:
                    rec.setdefault("evidence_array", []).append(
                        dict(extra_evidence_by_pid[pid])
                    )
                patched += 1
                break

    data.sort(key=lambda r: (len(r.get("UUID", "")), r.get("UUID", "")))
    save_clues(data, clues_path)

    sys.stderr.write(f"Patched {patched} records across {len(mapping)} packages.\n")

    # Emit the suggested KNOWN_VENDOR_PACKAGES additions.
    additions: dict[str, str] = {}
    skipped: list[tuple[str, str]] = []
    for pid, company in mapping.items():
        key = vendor_key_for(pid)
        if key is None:
            skipped.append((pid, "no usable vendor key"))
            continue
        existing = KVP.get(key)
        if existing == company:
            continue  # already in table with the same value
        if existing is not None and existing != company:
            skipped.append((pid, f"key {key!r} already maps to {existing!r}"))
            continue
        additions[key] = company

    if additions:
        sys.stdout.write(
            "# Suggested additions to KNOWN_VENDOR_PACKAGES in extract_clues.py\n"
            "# (paste these inside the dict, sorted by key with the rest of the table)\n\n"
        )
        for key in sorted(additions):
            company = additions[key]
            sys.stdout.write(f'    "{key}": {company!r},\n')
        sys.stdout.write("\n")
    if skipped:
        sys.stderr.write("\nSkipped (not added to suggested diff):\n")
        for pid, reason in skipped:
            sys.stderr.write(f"  - {pid}: {reason}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
