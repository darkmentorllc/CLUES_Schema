#!/usr/bin/env python3
"""Phase-5 helper: list every record in a CLUES output JSON whose
`UUID_name == "Unknown"`, with all the context an agent needs to re-investigate
(UUID, company, usage, host packages, local APK paths, captured-then-rejected
field-name hints from the description fields).

The Phase-5 agent reads this list, decompiles APKs for the highest-impact
records, web-searches for SDK documentation, and produces a mapping JSON
that `apply_uuid_name_resolution.py` then folds back into the CLUES file.

Usage:
    python3 list_unknown_uuid_names.py CLUES_data_LLM_Android_APK_search.json
    python3 list_unknown_uuid_names.py CLUES.json --session-file /tmp/run-X.json

With `--session-file`, only UUIDs present in that file (the session-output
from a Phase-1 run) are reported — useful right after a fresh extraction so
the agent doesn't re-investigate the entire historical corpus.

Output format (stdout, JSON):
    {
        "needs_naming": [
            {
                "UUID": "...",
                "company": "...",
                "UUID_usage_array": ["GATT Service"],
                "parent_UUID": "..." (optional),
                "host_packages": [
                    {
                        "package_id": "...",
                        "version_name": "...",
                        "local_path": "/Volumes/.../X.apk"
                    }
                ],
                "record_count_in_array": N
            },
            ...
        ],
        "already_named": [ "uuid1", "uuid2", ... ]
    }

`needs_naming` is sorted by host_packages length descending (biggest blast
radius first — naming a UUID seen in many apps benefits more records).
"""
from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("clues_path", help="Path to the CLUES output JSON.")
    p.add_argument(
        "--session-file",
        default=None,
        help="If set, only report UUIDs present in this session-output JSON "
             "(the file --session-output wrote during the Phase-1 run).",
    )
    args = p.parse_args(argv)

    from clues_io import load_clues
    data = load_clues(args.clues_path)

    scope: set[str] | None = None
    if args.session_file:
        with open(args.session_file, "r", encoding="utf-8") as f:
            session = json.load(f)
        scope = {r.get("UUID", "").lower() for r in session if r.get("UUID")}

    needs = []
    already = []
    for rec in data:
        uuid = rec.get("UUID", "")
        if not uuid:
            continue
        if scope is not None and uuid.lower() not in scope:
            continue
        name = rec.get("UUID_name", "")
        if name == "Unknown" or not name:
            host_pkgs = []
            seen = set()
            for info in rec.get("android_info_array", []):
                pid = info.get("package_id")
                ver = info.get("version_name")
                path = info.get("package_path")
                key = (pid, ver)
                if key in seen:
                    continue
                seen.add(key)
                host_pkgs.append({
                    "package_id": pid,
                    "version_name": ver,
                    "local_path": path,
                })
            entry = {
                "UUID": uuid,
                "company": rec.get("company", "Unknown"),
                "UUID_usage_array": rec.get("UUID_usage_array", []),
                "host_packages": host_pkgs,
                "record_count_in_array": len(rec.get("android_info_array", [])),
            }
            if rec.get("parent_UUID"):
                entry["parent_UUID"] = rec["parent_UUID"]
            needs.append(entry)
        else:
            already.append(uuid)

    # Largest blast radius first.
    needs.sort(key=lambda e: (-len(e["host_packages"]), e["UUID"]))

    out = {
        "needs_naming": needs,
        "already_named_count": len(already),
    }
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
