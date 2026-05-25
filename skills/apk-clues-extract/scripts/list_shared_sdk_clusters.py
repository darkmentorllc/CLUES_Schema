#!/usr/bin/env python3
"""Phase-4 helper: find clusters of UUIDs that look like they came from a
shared third-party SDK rather than from the host app's own code.

Heuristic for "shared SDK signal":
  - A UUID appears in ≥3 different host packages, AND
  - Those packages have non-overlapping inferred company names (no shared
    ≥3-letter token across the company names), AND
  - The UUID is NOT already in `KNOWN_SDK_UUIDS` (i.e. needs identification).

Records that pass the gate are clustered: two UUIDs are in the same cluster
if their host-package sets overlap by ≥50% (same SDK ⇒ same set of host
apps, modulo noise). Each cluster is one identification job for the agent.

Output (stdout, JSON):
    {
        "clusters": [
            {
                "cluster_id": "c0",
                "uuids":       ["9145", "9146", ...],
                "host_packages": [
                    {
                        "package_id":  "co.diaz.srvol",
                        "local_path":  "/Volumes/.../srvol.apk",
                        "version_name": "1.4.85.6",
                        "current_company_guess": "Diaz (inferred from package id)"
                    },
                    ...
                ],
                "uuid_field_names": {"9145": "SERVO_HORIZONTAL", ...},
                "suggested_action": "Decompile any one host app, look at ..."
            },
            ...
        ],
        "single_uuid_outliers": [
            { ... }   // shared by ≥3 apps but isolated (not clustering with others)
        ]
    }

Usage:
    python3 list_shared_sdk_clusters.py CLUES_data_LLM_Android_APK_search.json
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from extract_clues import KNOWN_SDK_UUIDS  # noqa: E402


def _tokens(name: str) -> set[str]:
    return set(re.findall(r"[A-Za-z]{3,}", name.lower()))


def _companies_share_a_token(companies: list[str]) -> bool:
    """If any pair of company names shares a ≥3-letter alpha token, treat
    them as "same vendor" (e.g. `Witco (formerly MonBuilding)` and
    `MonBuilding` share `monbuilding`)."""
    if len(companies) < 2:
        return True
    token_sets = [_tokens(c) for c in companies]
    base = token_sets[0]
    return any(base & ts for ts in token_sets[1:])


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        sys.stderr.write(f"usage: {sys.argv[0]} CLUES_data_LLM_Android_APK_search.json\n")
        return 2
    from clues_io import load_clues
    data = load_clues(argv[0])

    # For each UUID, collect (host_packages, company_guesses, field_names).
    by_uuid: dict[str, dict] = {}
    for rec in data:
        uuid = rec["UUID"].lower()
        if uuid in KNOWN_SDK_UUIDS:
            continue  # already identified
        infos = rec.get("android_info_array", [])
        if len(infos) < 3:
            continue
        companies = list({a.get("description", "") for a in infos})  # placeholder, set properly below
        companies = []
        host_pkgs = []
        for a in infos:
            host_pkgs.append({
                "package_id":            a.get("package_id"),
                "version_name":          a.get("version_name"),
                "local_path":            a.get("package_path"),
                "current_company_guess": rec.get("company"),
            })
        # Extract company guesses by looking at sibling records: every record
        # carries the same `company` field per UUID, but to detect "non-overlap"
        # we want to compare the per-app inferred companies, which were the
        # ones the script *would* have set if it had processed each APK in
        # isolation. Approximate: use the record's UUID_purpose description
        # to find per-app field names (we already have them per app).
        # In practice the record's `company` is one inferred value; what we
        # need is the inferred-company-from-package for each host pkg.
        for hp in host_pkgs:
            pid = hp["package_id"] or ""
            # Same logic as company_from_package's fallback (cheap).
            parts = [p for p in pid.split(".") if p]
            for part in parts:
                if part.lower() in {"com", "co", "org", "net", "io", "us", "uk", "fr", "de", "cn", "br", "app", "apps", "android", "mobile", "the", "branded", "white", "whitelabel"}:
                    continue
                if part.isdigit() or len(part) < 3:
                    continue
                companies.append(part.lower())
                break

        # Are any two host packages from different vendor tokens?
        unique_tokens = list(set(companies))
        if len(unique_tokens) < 3:
            continue

        # Capture the field-name hint per host package (best-effort: from
        # the record's per-app evidence descriptions).
        field_hint: dict[str, str | None] = {}
        for ev in rec.get("evidence_array", []):
            if not isinstance(ev, dict):
                continue
            desc = ev.get("description", "")
            m = re.search(r"decompiled DEX of ([^\s]+).*?Java field `([^`]+)`", desc)
            if m:
                field_hint[m.group(1)] = m.group(2)

        by_uuid[uuid] = {
            "uuid":           uuid,
            "host_packages":  host_pkgs,
            "company_tokens": unique_tokens,
            "uuid_name_so_far": rec.get("UUID_name"),
            "field_hints":    field_hint,
        }

    # Cluster UUIDs whose host-package sets overlap heavily.
    def pkg_set(u: str) -> frozenset[str]:
        return frozenset(p["package_id"] for p in by_uuid[u]["host_packages"] if p["package_id"])

    uuids = sorted(by_uuid)
    parent: dict[str, str] = {u: u for u in uuids}
    def find(u: str) -> str:
        while parent[u] != u:
            parent[u] = parent[parent[u]]
            u = parent[u]
        return u
    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb
    for i, ui in enumerate(uuids):
        si = pkg_set(ui)
        for uj in uuids[i+1:]:
            sj = pkg_set(uj)
            if not si or not sj:
                continue
            jaccard = len(si & sj) / len(si | sj)
            if jaccard >= 0.5:
                union(ui, uj)

    clusters: dict[str, list[str]] = defaultdict(list)
    for u in uuids:
        clusters[find(u)].append(u)

    out_clusters = []
    out_singletons = []
    for idx, members in enumerate(sorted(clusters.values(), key=lambda l: (-len(l), min(l)))):
        info_first = by_uuid[members[0]]
        # Union of host packages across all member UUIDs of this cluster.
        host_pkgs_map: dict[str, dict] = {}
        for u in members:
            for hp in by_uuid[u]["host_packages"]:
                pid = hp["package_id"]
                if pid and pid not in host_pkgs_map:
                    host_pkgs_map[pid] = hp
        host_pkgs = sorted(host_pkgs_map.values(), key=lambda h: h["package_id"])
        uuid_field_names = {u: by_uuid[u]["uuid_name_so_far"] for u in members if by_uuid[u]["uuid_name_so_far"] and by_uuid[u]["uuid_name_so_far"] != "Unknown"}
        item = {
            "cluster_id":  f"c{idx}",
            "uuids":       sorted(members),
            "host_packages": host_pkgs,
            "uuid_field_names": uuid_field_names,
            "suggested_action": (
                "Decompile any one host app (the smallest `local_path` is "
                "fastest). Look in the bt/* or ble/* or *.bluetooth.* "
                "Java packages for class names that aren't part of the "
                "host app's own brand (e.g. JADX leaves `compiled from: "
                "<OriginalName>.java` hints that survive obfuscation). "
                "Then web-search '<class name> Android SDK' or '<unique UUID> SDK' "
                "to find the third-party SDK vendor. The discovered vendor "
                "becomes the `company` for every UUID in this cluster."
            ),
        }
        if len(members) == 1:
            out_singletons.append(item)
        else:
            out_clusters.append(item)

    json.dump(
        {"clusters": out_clusters, "single_uuid_outliers": out_singletons},
        sys.stdout,
        indent=2,
        ensure_ascii=False,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
