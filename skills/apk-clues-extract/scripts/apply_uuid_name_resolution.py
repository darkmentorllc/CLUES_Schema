#!/usr/bin/env python3
"""Phase-5 helper: apply a {UUID -> resolved-attributes} mapping produced by
the Phase-5 re-investigation pass back to a CLUES output JSON, and emit the
Python-snippet diff needed to extend `KNOWN_SDK_UUIDS` in `extract_clues.py`
so future runs hit the table directly.

Usage:
    python3 apply_uuid_name_resolution.py CLUES.json mapping.json

`mapping.json` is keyed by UUID (lowercase, canonical form) and each value is
a dict with optional fields:

    {
        "f8083536-849e-531c-c594-30f1f86a4ea5": {
            "UUID_name": "DEXCOM_DATA_TX_CHAR",
            "UUID_purpose": "...optional, replaces existing purpose...",
            "company":      "...optional company upgrade...",
            "note":         "...optional, becomes the KNOWN_SDK_UUIDS note...",
            "cache_in_sdk_table": true     // optional, default true
        },
        ...
    }

Only `UUID_name` is required. The script:

1. Loads the CLUES file in place.
2. For each record whose UUID is in the mapping:
     - replaces `UUID_name` ONLY when current is "Unknown" (never overwrites
       a previously-curated name);
     - if `UUID_purpose` is supplied, replaces it (always — purposes are
       always auto-generated, so a curator's better text wins);
     - if `company` is supplied AND the current company is "Unknown" or the
       Phase-1 `(inferred from package id)` placeholder or one of the
       Phase-4 `Unidentified shared SDK` / `Third-party SDK code` markers,
       replaces it;
     - appends a Phase-5 investigation note to the existing evidence_array
       if `note` is supplied.
3. Writes the CLUES file back, sorted by UUID for stable diffs.
4. Prints the Python diff for `KNOWN_SDK_UUIDS` so a curator can paste it
   into `extract_clues.py` and cache the resolution for every future run.
"""
from __future__ import annotations

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from extract_clues import KNOWN_SDK_UUIDS as KSU  # noqa: E402
from extract_clues import dedupe_evidence_array  # noqa: E402

INFERRED_PACKAGE_MARKER = "(inferred from package id)"
SHARED_SDK_MARKERS = (
    "Unidentified shared SDK",
    "Third-party SDK code (declared in Java package",
)


def _company_is_replaceable(current: str) -> bool:
    if not current or current == "Unknown":
        return True
    if INFERRED_PACKAGE_MARKER in current:
        return True
    for marker in SHARED_SDK_MARKERS:
        if marker in current:
            return True
    return False


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write(f"usage: {sys.argv[0]} CLUES.json mapping.json\n")
        return 2
    clues_path, mapping_path = argv

    with open(mapping_path, "r", encoding="utf-8") as f:
        mapping_raw = json.load(f)
    if not isinstance(mapping_raw, dict):
        sys.stderr.write("mapping file must be a JSON object keyed by UUID\n")
        return 2
    mapping: dict[str, dict] = {}
    for k, v in mapping_raw.items():
        if not isinstance(v, dict):
            sys.stderr.write(f"skipping {k!r}: value must be an object\n")
            continue
        if not v.get("UUID_name"):
            sys.stderr.write(f"skipping {k!r}: missing required UUID_name\n")
            continue
        mapping[k.lower().strip()] = v

    if not mapping:
        sys.stderr.write("mapping is empty after validation; nothing to do\n")
        return 0

    from clues_io import load_clues, save_clues
    from company_sanitizer import sanitize_for_write
    data = load_clues(clues_path)

    name_patched = 0
    purpose_patched = 0
    company_patched = 0
    note_patched = 0

    submitters: dict[str, str] = {}
    for rec in data:
        uuid = (rec.get("UUID") or "").lower()
        if uuid not in mapping:
            continue
        entry = mapping[uuid]
        # Track first observed submitter so a Phase-5 evidence note can keep
        # attribution consistent.
        for ev in rec.get("evidence_array", []):
            sub = ev.get("submitter")
            if sub:
                submitters.setdefault(uuid, sub)
                break

        new_name = entry.get("UUID_name")
        if new_name:
            current_name = rec.get("UUID_name", "")
            # Normal rule: only patch when current is "Unknown" — never overwrite
            # a curated name. EXCEPTION: the NOT_A_BLE_UUID_FALSE_POSITIVE marker
            # is special: it means "this whole record is invalid, not a real BLE
            # UUID". Phase 1 may have captured a non-BLE token with a name like
            # `FACEBOOK_ID` or `opinion_system_tag` (Gannett news topic GUIDs);
            # those names ARE wrong (they're not Bluetooth at all) and should be
            # replaced. Allow the FP marker to override anything.
            is_fp_marker = "NOT_A_BLE_UUID_FALSE_POSITIVE" in new_name
            if current_name == "Unknown" or is_fp_marker:
                rec["UUID_name"] = new_name
                name_patched += 1

        new_purpose = entry.get("UUID_purpose")
        if new_purpose:
            rec["UUID_purpose"] = new_purpose
            purpose_patched += 1

        new_company = entry.get("company")
        if new_company and _company_is_replaceable(rec.get("company", "")):
            cleaned_company, sanitize_ev = sanitize_for_write(
                new_company, source=f"Phase-5 UUID={uuid}", warn=True,
            )
            rec["company"] = cleaned_company
            if sanitize_ev is not None:
                rec.setdefault("evidence_array", []).append(dict(sanitize_ev))
            company_patched += 1

        note = entry.get("note")
        if note:
            rec.setdefault("evidence_array", []).append({
                "description": f"Phase-5 UUID-name resolution: {note}",
                "submitter": submitters.get(uuid, "Claude (Opus 4.7)"),
            })
            note_patched += 1

    # Dedupe every record's evidence_array — re-running this script on the
    # same mapping must be idempotent, and any historical duplicates from
    # before this safeguard existed get cleaned up here too.
    for rec in data:
        if rec.get("evidence_array"):
            rec["evidence_array"] = dedupe_evidence_array(rec["evidence_array"])

    data.sort(key=lambda r: (len(r.get("UUID", "")), r.get("UUID", "")))
    save_clues(data, clues_path)

    sys.stderr.write(
        f"Patched {name_patched} UUID_name, {purpose_patched} UUID_purpose, "
        f"{company_patched} company, {note_patched} evidence notes "
        f"across {len(mapping)} mapped UUIDs.\n"
    )

    # Emit suggested KNOWN_SDK_UUIDS additions for every mapping entry that
    # asked to be cached (default) and isn't already in the table.
    additions: dict[str, dict] = {}
    skipped: list[tuple[str, str]] = []
    for uuid, entry in mapping.items():
        if entry.get("cache_in_sdk_table") is False:
            continue
        existing = KSU.get(uuid)
        if existing is not None:
            if existing.get("name") == entry["UUID_name"]:
                continue
            skipped.append((uuid, f"already cached with name {existing.get('name')!r}"))
            continue
        additions[uuid] = {
            "company": entry.get("company") or existing and existing.get("company") or "Unknown",
            "name": entry["UUID_name"],
            "note": entry.get("note") or "Phase-5 UUID-name resolution",
        }

    if additions:
        sys.stdout.write(
            "# Suggested additions to KNOWN_SDK_UUIDS in extract_clues.py\n"
            "# (paste these inside the dict, sorted by UUID with the rest of the table)\n\n"
        )
        for uuid in sorted(additions):
            a = additions[uuid]
            sys.stdout.write(
                f'    {uuid!r}: '
                f'{{"company": {a["company"]!r}, '
                f'"name": {a["name"]!r}, '
                f'"note": {a["note"]!r}}},\n'
            )
        sys.stdout.write("\n")
    if skipped:
        sys.stderr.write("\nSkipped (not added to suggested diff):\n")
        for uuid, reason in skipped:
            sys.stderr.write(f"  - {uuid}: {reason}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
