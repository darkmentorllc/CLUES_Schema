#!/usr/bin/env python3
"""Phase-6 helper: derive lessons learned from the most recent Phase-1..5
session and emit a Python diff that extends two caches in `extract_clues.py`:

  - `KNOWN_NON_BLE_UUIDS`: UUID-shaped tokens Phase 5 confirmed are NOT BLE
    (Google Business Messages agent IDs, news-topic IDs, etc.). Adding these
    keeps future Phase-1 runs from re-emitting the same false-positive record.
  - `KNOWN_SDK_JAVA_PACKAGES`: Java-package-prefix → company mappings derived
    from Phase 4/5 SDK identifications. Adding these lets the next Phase-1
    run attribute a UUID found in `com.bluecats.sdk.*` straight to BlueCats
    on a single-APK basis, without waiting for the Phase-4 ≥3-host cluster
    threshold to fire.

This script does NOT modify `extract_clues.py` directly — it prints the diff
and the agent applies it with the Edit tool. Apply with care: each entry is
a load-bearing claim that benefits every future scan, so cite the evidence.

Usage:
    python3 generate_phase6_improvements.py CLUES.json /tmp/run-X-new-uuids.json

Output (stdout):
  - Header lines explaining each proposed addition with evidence
  - A `KNOWN_NON_BLE_UUIDS` set-extension diff
  - A `KNOWN_SDK_JAVA_PACKAGES` dict-extension diff
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import defaultdict
from typing import Iterable

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from extract_clues import KNOWN_NON_BLE_UUIDS as KNB        # noqa: E402
from extract_clues import KNOWN_SDK_JAVA_PACKAGES as KSJP   # noqa: E402
from extract_clues import _TLDLIKE_COMPONENTS as TLDLIKE    # noqa: E402

FALSE_POSITIVE_MARKER = "NOT_A_BLE_UUID_FALSE_POSITIVE"
THIRD_PARTY_MARKER_RE = re.compile(
    r"Third-party SDK code \(declared in Java package `([^`]+)`"
)


def _tokens(s: str) -> set[str]:
    """Lowercased ≥3-char alphanumeric tokens, with TLD-like prefixes removed.
    Used for the token-overlap check between Java packages and company names."""
    return {
        t.lower() for t in re.split(r"\W+", s)
        if t and t.lower() not in TLDLIKE and len(t) >= 3
    }


def _session_uuids(session_path: str) -> set[str]:
    with open(session_path, "r", encoding="utf-8") as f:
        session = json.load(f)
    return {(r.get("UUID") or "").lower() for r in session if r.get("UUID")}


def _extract_java_pkgs_from_evidence(rec: dict) -> list[tuple[str, int]]:
    """Pull every declaring Java package out of a record's evidence_array,
    counting how many evidence entries cite each. A UUID that shows up in N
    hosts may have N different declaring packages, and the MOST COMMON one
    is usually the real SDK source — not necessarily the longest. Phase 1
    writes 'declared in Java package `com.foo.bar` (third-party SDK)' into
    the discovery evidence.

    Returns [(java_pkg, count)] sorted by (-count, -len) so most-common-first,
    ties broken by longer (more specific) prefix. An empty list means no
    declaring-package evidence is present.

    Anti-bug-from-2026-05: previously this returned only the *longest* pkg,
    which silently dropped good attributions when a UUID was seen under
    multiple SDK names (e.g. Allegion's UUID shows up under
    `com.brivo.sdk.ble` in 5 host apps and under
    `com.kastle.kastlesdk.allegion.touring.constants` in 1 — the longest
    is the kastle one, but the real SDK source is brivo)."""
    counts: dict[str, int] = defaultdict(int)
    for ev in rec.get("evidence_array", []):
        desc = ev.get("description") or ""
        for m in re.finditer(r"declared in Java package `([^`]+)`", desc):
            counts[m.group(1)] += 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], -len(kv[0])))


def _propose_non_ble(records: list[dict], scope: set[str]) -> list[tuple[str, str]]:
    """Return (uuid, justification) pairs for records that Phase 5 marked as
    false-positives. Skip ones already in KNB.

    Note: false-positives are scanned across the WHOLE CLUES file, not just
    session-new scope. Reason: a single APK version (e.g. com.gatehousemedia.id3161
    v7.3.0) may contribute false-positive UUIDs that Phase 1 picked up in an
    earlier session and Phase 5 only got around to marking in a later session.
    Either way, every NOT_A_BLE_UUID_FALSE_POSITIVE marker is a deliberate
    Phase-5 attribution and worth caching. The `scope` arg is kept for
    symmetry but is no longer used here."""
    del scope  # intentionally unused — see docstring
    out = []
    for rec in records:
        uuid = (rec.get("UUID") or "").lower()
        if not uuid:
            continue
        name = rec.get("UUID_name") or ""
        if FALSE_POSITIVE_MARKER not in name:
            continue
        if uuid in KNB:
            continue
        # Pull the cited reason out of the most recent evidence note
        justification = "Phase-5 confirmed non-BLE"
        for ev in reversed(rec.get("evidence_array", [])):
            desc = ev.get("description") or ""
            if "Phase-5" in desc and "false-positive" in desc.lower():
                # Take the first sentence after the marker for a short note.
                trimmed = desc.replace("Phase-5 UUID-name resolution: ", "")
                justification = trimmed[:240]
                break
        out.append((uuid, justification))
    return out


def _propose_sdk_packages(
    records: list[dict],
    scope: set[str],
) -> list[tuple[str, str, int, str]]:
    """Return (java_package, company, uuid_count, example_uuid) tuples for
    Java packages that hosted ≥1 UUID whose company was upgraded from the
    Phase-1 third-party-SDK placeholder. Group by (java_pkg, company) and
    require ≥1 supporting UUID in the session scope."""
    grouped: dict[tuple[str, str], list[str]] = defaultdict(list)
    for rec in records:
        uuid = (rec.get("UUID") or "").lower()
        if not uuid or uuid not in scope:
            continue
        company = rec.get("company") or ""
        # Skip records still carrying the Phase-1 placeholder or false-positives.
        if THIRD_PARTY_MARKER_RE.search(company):
            continue
        if FALSE_POSITIVE_MARKER in (rec.get("UUID_name") or ""):
            continue
        # Skip records that are already cached via KNOWN_SDK_UUIDS — those
        # already work without the Java-package cache.
        # (We can't easily tell from the record alone, so we just emit and
        # let the de-dupe in the apply step handle it.)
        candidate_pkgs = _extract_java_pkgs_from_evidence(rec)
        if not candidate_pkgs:
            continue
        # Pick the most-common declaring package whose tokens overlap with
        # the company name. Falling back to the most-common (regardless of
        # overlap) would let merge-bug attributions through (see the
        # `com.ihealth.communication -> WeCo Batteries` case from folders
        # 0008+0009). Falling back to the longest-pkg would silently drop
        # good attributions when the same UUID is seen under multiple SDK
        # names (the Allegion / com.brivo.sdk.ble case from 0010..0013).
        company_tokens = _tokens(company)
        chosen_pkg: str | None = None
        for pkg, _count in candidate_pkgs:
            # Don't propose generic packages or single-letter obfuscated ones
            # — those aren't safe to use as SDK identifiers.
            if len(pkg) < 8 or "." not in pkg:
                continue
            pkg_tokens = _tokens(pkg)
            if pkg_tokens & company_tokens:
                chosen_pkg = pkg
                break
        if chosen_pkg is None:
            continue
        # Skip packages already covered by an existing KSJP prefix.
        already_covered = False
        for prefix in KSJP:
            if chosen_pkg == prefix or chosen_pkg.startswith(prefix + "."):
                already_covered = True
                break
        if already_covered:
            continue
        grouped[(chosen_pkg, company)].append(uuid)

    # Pick the most distinctive Java-package prefix for each company.
    # If the same company appears under multiple packages, keep them all —
    # an SDK can legitimately span sub-packages (e.g. com.contec.spo2.code +
    # com.contec.bp.code share company but are distinct prefixes).
    out: list[tuple[str, str, int, str]] = []
    for (pkg, company), uuids in sorted(grouped.items()):
        # Shorten the prefix to the deepest 3 components — that's typically
        # the SDK root (com.vendor.sdk) rather than a deep internal subpkg.
        parts = pkg.split(".")
        if len(parts) > 3:
            shortened = ".".join(parts[:3])
        else:
            shortened = pkg
        # Check that the shortened form doesn't accidentally collide with the
        # host APK's package id by being too generic (e.g. `com.app`).
        if shortened in {"com.android", "com.google", "androidx", "kotlin"}:
            continue
        # Token-overlap is already enforced in the per-candidate loop above,
        # so by the time a (pkg, company) pair reaches `grouped`, the pkg
        # tokens already share with the company tokens. We re-verify after
        # truncation, though, because shortening to 3 components can drop
        # a token (e.g. `com.foo.sdk.beacons` truncates to `com.foo.sdk`,
        # which is fine, but `com.android.databinding.foo` would truncate
        # to `com.android.databinding`, which is generic).
        pkg_tokens = _tokens(shortened)
        company_tokens = _tokens(company)
        if not (pkg_tokens & company_tokens):
            sys.stderr.write(
                f"  rejected after truncation (lost token overlap): "
                f"{shortened!r} -> {company!r}\n"
            )
            continue
        out.append((shortened, company, len(uuids), uuids[0]))
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write(
            f"usage: {sys.argv[0]} CLUES.json session-output.json\n"
        )
        return 2
    clues_path, session_path = argv
    from clues_io import load_clues
    records = load_clues(clues_path)
    scope = _session_uuids(session_path)
    sys.stderr.write(f"[*] Session scope: {len(scope)} UUIDs\n")

    non_ble = _propose_non_ble(records, scope)
    sdk_pkgs = _propose_sdk_packages(records, scope)

    if not non_ble and not sdk_pkgs:
        sys.stdout.write("# Phase 6: no new lessons learned from this session.\n")
        sys.stdout.write("# Nothing to add to KNOWN_NON_BLE_UUIDS or KNOWN_SDK_JAVA_PACKAGES.\n")
        return 0

    sys.stdout.write(
        "# ============================================================\n"
        "# Phase-6 suggested additions to extract_clues.py\n"
        "# ============================================================\n"
        "# The agent should paste each block inside the corresponding\n"
        "# dict/set in extract_clues.py, then re-run --self-test.\n"
        "# Each entry is a load-bearing claim — every future Phase-1\n"
        "# run will rely on it, so cite the evidence in a code comment.\n\n"
    )

    if non_ble:
        sys.stdout.write(
            "# -- KNOWN_NON_BLE_UUIDS additions --\n"
            "# Paste these inside the KNOWN_NON_BLE_UUIDS set.\n"
            "# Evidence: Phase 5 confirmed each token is a non-BLE\n"
            "# UUID-shaped string (URL agent_id, topic_id, etc.).\n\n"
        )
        for uuid, justification in non_ble:
            # Wrap the justification onto a single comment line.
            comment = justification.replace("\n", " ").strip()
            sys.stdout.write(f"    # {comment}\n")
            sys.stdout.write(f"    {uuid!r},\n")
        sys.stdout.write("\n")

    if sdk_pkgs:
        sys.stdout.write(
            "# -- KNOWN_SDK_JAVA_PACKAGES additions --\n"
            "# Paste these inside the KNOWN_SDK_JAVA_PACKAGES dict.\n"
            "# Each entry maps a Java-package prefix to the SDK's company.\n"
            "# Match is on dot boundaries: a key `com.foo.sdk` matches\n"
            "# both `com.foo.sdk` exactly and any subpackage of it.\n\n"
        )
        for pkg, company, n, example in sdk_pkgs:
            sys.stdout.write(
                f"    # Phase-5 attribution from {n} UUID(s) in this session, e.g. {example}\n"
                f"    {pkg!r}: {company!r},\n"
            )
        sys.stdout.write("\n")

    sys.stdout.write(
        "# After pasting:\n"
        "#   1. Re-run `extract_clues.py --self-test` to confirm no regressions.\n"
        "#   2. Re-run `check-jsonschema` on the CLUES output (no schema impact, but a smoke test).\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
