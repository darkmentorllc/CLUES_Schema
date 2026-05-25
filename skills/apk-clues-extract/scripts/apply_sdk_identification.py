#!/usr/bin/env python3
"""Phase-4 helper: take a SDK-identification mapping from the agent loop and:

  1. Patch every CLUES record whose UUID is in a mapped cluster, replacing
     its `company` with the discovered SDK vendor name. Idempotent / safe
     for re-runs.
  2. Print to stdout the Python diff to extend `KNOWN_SDK_UUIDS` in
     `extract_clues.py` so subsequent Phase-1 runs short-circuit the
     identification entirely.

Mapping file format:
    {
      "<cluster_id>": {
        "company": "Revolve Robotics",                             # BARE COMPANY NAME ONLY
        "note":    "Kubi SDK / Zoom Android SDK bundle for the Kubi telepresence robot",
                                                                   # optional context; copied into
                                                                   # KNOWN_SDK_UUIDS and folded into
                                                                   # each record's UUID_purpose
        "uuid_names": {                                            # optional
          "9145": "SERVO_HORIZONTAL",
          ...
        },
        "uuids":   ["9145", "9146", "e001", ...]                   # the UUIDs in this cluster
      },
      ...
    }

The `company` field MUST be the bare company name. Anything descriptive
(product names, geographic origin, what BLE is used for, acquisition
history) belongs in `note` instead — it gets folded into UUID_purpose and
into KNOWN_SDK_UUIDS for future runs. If commentary slips into `company`
anyway, `company_sanitizer.sanitize_for_write` strips it transparently
and appends an evidence entry, but you'll get a stderr warning telling
you to put it in `note` next time.

Usage:
    python3 apply_sdk_identification.py \\
        CLUES_data_LLM_Android_APK_search.json \\
        sdk_identification_mapping.json
"""
from __future__ import annotations

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from extract_clues import KNOWN_SDK_UUIDS  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write(
            f"usage: {sys.argv[0]} CLUES_data_LLM_Android_APK_search.json sdk_mapping.json\n"
        )
        return 2
    clues_path, mapping_path = argv

    with open(mapping_path, "r", encoding="utf-8") as f:
        mapping = json.load(f)
    if not isinstance(mapping, dict):
        sys.stderr.write("mapping must be a JSON object\n")
        return 2

    _HERE = os.path.dirname(os.path.abspath(__file__))
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    from company_sanitizer import sanitize_for_write

    # Build uuid → (company, note, name?, sanitize_evidence?) lookup from the
    # mapping. If the agent put commentary into a cluster's `company`, strip
    # it once here so it doesn't leak into every record in the cluster.
    uuid_to_sdk: dict[str, dict] = {}
    for cluster_id, info in mapping.items():
        raw_company = info.get("company", "").strip()
        note = info.get("note", "").strip()
        names = info.get("uuid_names") or {}
        if not raw_company:
            sys.stderr.write(f"cluster {cluster_id!r} missing 'company'; skipping\n")
            continue
        company, sanitize_ev = sanitize_for_write(
            raw_company, source=f"Phase-4 cluster {cluster_id}", warn=True,
        )
        for u in info.get("uuids", []):
            ul = u.lower()
            uuid_to_sdk[ul] = {
                "company":      company,
                "note":         note,
                "name":         names.get(u) or names.get(ul) or "",
                "cluster":      cluster_id,
                "sanitize_evidence": sanitize_ev,
            }

    if not uuid_to_sdk:
        sys.stderr.write("mapping has no UUIDs; nothing to do\n")
        return 0

    from clues_io import load_clues, save_clues
    data = load_clues(clues_path)

    patched = 0
    for rec in data:
        u = rec["UUID"].lower()
        if u not in uuid_to_sdk:
            continue
        info = uuid_to_sdk[u]
        rec["company"] = info["company"]
        if info.get("sanitize_evidence"):
            rec.setdefault("evidence_array", []).append(
                dict(info["sanitize_evidence"])
            )
        # Upgrade UUID_name only if we have a curated one AND the current
        # is "Unknown" or less semantic. Conservative: never overwrite a
        # multi-word existing name.
        if info["name"] and (rec.get("UUID_name") in (None, "Unknown")):
            rec["UUID_name"] = info["name"]
        # Append a one-liner to UUID_purpose explaining the cross-app pattern.
        if info["note"] and info["note"] not in (rec.get("UUID_purpose") or ""):
            rec["UUID_purpose"] = (
                (rec.get("UUID_purpose") or "").rstrip()
                + f" Phase-4 SDK identification: {info['note']}."
            ).strip()
        patched += 1

    data.sort(key=lambda r: (len(r.get("UUID", "")), r.get("UUID", "")))
    save_clues(data, clues_path)
    sys.stderr.write(
        f"Patched {patched} records across {len(uuid_to_sdk)} mapped UUIDs.\n"
    )

    # Suggest KNOWN_SDK_UUIDS additions (skip UUIDs already in the table).
    additions: dict[str, dict] = {}
    for u, info in uuid_to_sdk.items():
        if u in KNOWN_SDK_UUIDS:
            continue
        additions[u] = info
    if additions:
        sys.stdout.write(
            "# Suggested additions to KNOWN_SDK_UUIDS in extract_clues.py\n"
            "# (paste these inside the dict, sorted by UUID with the rest of the table)\n\n"
        )
        for u in sorted(additions):
            info = additions[u]
            name = info["name"] or "Unknown"
            sys.stdout.write(
                f'    {u!r}: {{"company": {info["company"]!r}, '
                f'"name": {name!r}, '
                f'"note": {info["note"]!r}}},\n'
            )
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
