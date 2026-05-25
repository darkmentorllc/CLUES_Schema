#!/usr/bin/env python3
"""Phase-3 helper: given a mapping `{"<package_id>@<version_name>": "<url>"}`
of verified APK-cache URLs (from `verify_apk_url.py`), add a URL evidence
entry to every CLUES record produced from that exact package+version.

Usage:
    python3 apply_apk_url_evidence.py \\
        CLUES_data_LLM_Android_APK_search.json \\
        url_mapping.json

`url_mapping.json` format:
    {
        "com.dexcom.stelo@2.1.0.2972": {
            "URL": "https://apkpure.com/stelo-by-dexcom/com.dexcom.stelo/download/2.1.0.2972",
            "verified": "ok",                          # from verify_apk_url.py
            "direct_download": false,                  # from verify_apk_url.py
            "submitter": "Claude (Opus 4.7)"           # optional, defaults to existing record's submitter
        },
        ...
    }

For each record whose android_info_array contains the matching
(package_id, version_name), the script appends one evidence_array entry:
    {
        "URL":        "<the URL>",
        "description": "APK at this package version is downloadable from <host>; verified <status>, direct download = <true|false>.",
        "submitter":   "<as supplied or inherited from the first existing evidence entry>"
    }

Duplicate URLs (already present in evidence_array) are skipped, so the
script is idempotent and safe to re-run.
"""
from __future__ import annotations

import json
import os
import sys
from urllib.parse import urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from extract_clues import dedupe_evidence_array  # noqa: E402


DEFAULT_SUBMITTER = "Claude (Opus 4.7)"


def add_url_evidence(rec: dict, url: str, status: str, direct: bool, submitter: str | None) -> bool:
    """Append the URL evidence to one record. Returns True if it was added,
    False if it was already present (idempotency)."""
    if not isinstance(rec.get("evidence_array"), list):
        rec["evidence_array"] = []
    existing_urls = {
        (e.get("URL") or "").strip().lower()
        for e in rec["evidence_array"]
        if isinstance(e, dict)
    }
    if url.strip().lower() in existing_urls:
        return False
    if submitter is None:
        # Inherit the submitter from the first existing evidence entry if any.
        for e in rec["evidence_array"]:
            if isinstance(e, dict) and e.get("submitter"):
                submitter = e["submitter"]
                break
    if submitter is None:
        submitter = DEFAULT_SUBMITTER

    host = urlparse(url).netloc or "the source"
    rec["evidence_array"].append({
        "URL": url,
        "description": (
            f"APK at this package + version is downloadable from {host}; "
            f"URL verified (status={status}, direct_download={direct})."
        ),
        "submitter": submitter,
    })
    return True


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write(
            f"usage: {sys.argv[0]} CLUES_data_LLM_Android_APK_search.json url_mapping.json\n"
        )
        return 2
    clues_path, mapping_path = argv

    with open(mapping_path, "r", encoding="utf-8") as f:
        mapping_raw = json.load(f)
    if not isinstance(mapping_raw, dict):
        sys.stderr.write("mapping must be a JSON object {'pkg@ver': {URL, verified, direct_download, submitter?}}\n")
        return 2

    # Pre-flight: ensure every entry was verified.
    for k, v in mapping_raw.items():
        if not isinstance(v, dict) or "URL" not in v or "verified" not in v:
            sys.stderr.write(f"entry {k!r} missing required fields URL+verified\n")
            return 2
        if v["verified"] != "ok":
            sys.stderr.write(
                f"refusing to add {k!r}: verified={v['verified']!r}. "
                f"Run verify_apk_url.py first and only commit URLs with status=ok.\n"
            )
            return 2

    from clues_io import load_clues, save_clues
    data = load_clues(clues_path)

    added = 0
    touched = 0
    for rec in data:
        rec_touched_here = False
        for ainfo in rec.get("android_info_array", []):
            key = f"{ainfo.get('package_id', '')}@{ainfo.get('version_name', '')}"
            if key in mapping_raw:
                entry = mapping_raw[key]
                if add_url_evidence(
                    rec,
                    entry["URL"],
                    entry["verified"],
                    bool(entry.get("direct_download", False)),
                    entry.get("submitter"),
                ):
                    added += 1
                    rec_touched_here = True
        if rec_touched_here:
            touched += 1
        # Dedupe regardless of whether THIS run added anything — historical
        # duplicates left behind by older runs get cleaned up here too.
        if rec.get("evidence_array"):
            rec["evidence_array"] = dedupe_evidence_array(rec["evidence_array"])

    data.sort(key=lambda r: (len(r.get("UUID", "")), r.get("UUID", "")))
    save_clues(data, clues_path)

    sys.stderr.write(
        f"Added {added} URL evidence entries across {touched} records "
        f"({len(mapping_raw)} mappings supplied).\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
