#!/usr/bin/env python3
"""Phase-3 helper: list every distinct `(package_id, version_name, version_code)`
tuple in a CLUES output JSON whose `evidence_array` does NOT yet contain a
download-URL item. The Phase-3 web-search agent reads this list, finds an
apkpure / apkcombo / apkmirror / archive.org URL for each tuple, verifies it
downloads, and feeds the mapping to `apply_apk_url_evidence.py`.

Usage:
    python3 list_apk_versions.py CLUES_data_LLM_Android_APK_search.json

Output format (stdout, JSON):
    {
        "needs_url": [
            {
                "package_id":    "com.dexcom.stelo",
                "version_name":  "2.1.0.2972",
                "version_code":  2972,
                "record_count":  17,
                "company":       "Dexcom",
                "local_path":    "/path/to/the.xapk"   # if known, else null
            },
            ...
        ],
        "already_has_url": ["com.foo.bar@1.2.3", ...]
    }

The mapping key for `apply_apk_url_evidence.py` uses
"<package_id>@<version_name>" as the join token — version_code is captured
for disambiguation but is not part of the key.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict


# Marker substrings that indicate an evidence_array_item is a re-download URL
# vs. some other URL (e.g. a documentation link a curator added). We look at
# the URL's host: if it's a known APK-cache site, that record already has its
# download URL.
KNOWN_APK_CACHE_HOSTS = (
    "apkpure.com",
    "apkpure.net",
    "apkcombo.com",
    "apkmirror.com",
    "apkmonk.com",
    "apkamp.com",
    "play.google.com/store/apps/details",
    "archive.org/details",
    "f-droid.org/packages",
    "uptodown.com",
)


def is_apk_cache_url(url: str) -> bool:
    u = (url or "").lower()
    return any(host in u for host in KNOWN_APK_CACHE_HOSTS)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        sys.stderr.write(f"usage: {sys.argv[0]} CLUES_data_LLM_Android_APK_search.json\n")
        return 2
    from clues_io import load_clues
    data = load_clues(argv[0])

    # tuple -> first-seen package_path / version_code / company / record_count
    info: dict[tuple[str, str], dict] = {}
    has_url_already: set[tuple[str, str]] = set()

    for rec in data:
        co = rec.get("company", "Unknown")
        urls_in_evidence = [
            e.get("URL", "") for e in rec.get("evidence_array", []) if isinstance(e, dict)
        ]
        for ainfo in rec.get("android_info_array", []):
            pid = ainfo.get("package_id")
            vn = ainfo.get("version_name")
            if not pid or vn is None:
                continue
            key = (pid, str(vn))
            slot = info.setdefault(key, {
                "package_id":   pid,
                "version_name": str(vn),
                "version_code": ainfo.get("version_code"),
                "record_count": 0,
                "company":      co,
                "local_path":   ainfo.get("package_path"),
            })
            slot["record_count"] += 1
            # Pull through company / local_path if we didn't have one.
            if slot["company"] in ("", "Unknown") and co not in ("", "Unknown"):
                slot["company"] = co
            if not slot["local_path"] and ainfo.get("package_path"):
                slot["local_path"] = ainfo["package_path"]
            # A record can carry URLs for SEVERAL different packages (when a
            # UUID is shared across multiple host apps). A URL only "covers"
            # the (pid, vn) we're inspecting if the URL actually mentions
            # this package_id — apkpure.net URLs always embed `/<package_id>/`
            # in the path, Play Store URLs use `?id=<package_id>`. Without
            # this check, the HID Global URL on a UUID shared with sesame
            # would be wrongly counted as covering sesame's own APK.
            for u in urls_in_evidence:
                if is_apk_cache_url(u) and pid in u:
                    has_url_already.add(key)
                    break

    needs = []
    resolved = []
    for key in sorted(info, key=lambda k: (-info[k]["record_count"], k[0], k[1])):
        if key in has_url_already:
            resolved.append(f"{key[0]}@{key[1]}")
        else:
            needs.append(info[key])

    json.dump(
        {"needs_url": needs, "already_has_url": resolved},
        sys.stdout,
        indent=2,
        ensure_ascii=False,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
