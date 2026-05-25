#!/usr/bin/env python3
"""Sanitize `company` field values before they get written into CLUES data.

The `company` field is meant to hold the **bare company name** — nothing else.
Anything descriptive (the country of origin, app name, what BLE is used for,
acquisition history, brand notes) belongs in `evidence_array[].description`
or, when it's truly UUID-specific, in `UUID_purpose`.

This module exists because three Phase apply-scripts ingest agent-provided
mappings and write whatever string is in there:

  - `apply_company_enrichment.py`     (Phase 2: package-id -> company)
  - `apply_sdk_identification.py`     (Phase 4: SDK cluster -> company)
  - `apply_uuid_name_resolution.py`   (Phase 5: UUID -> {company?, note?})

Historically the agent would helpfully embed context next to the name, e.g.
`"Canon Inc. (Japan) - Camera Connect app; BLE for EOS cameras"`. That
violates the schema's intent (the `company` field's description literally
says "Name of company associated with this UUID."). On 2026-05-19 we did a
one-shot cleanup of the existing data; this sanitizer prevents the leak
from recurring.

Public API:
  - `is_preserved_marker(s)`        - True iff `s` is a system placeholder
                                       that must NOT be stripped (Phase-1's
                                       "(inferred from package id)" and the
                                       two Phase-4 cluster markers).
  - `clean_company(s) -> (cleaned, stripped_commentary)`
                                       Returns the bare name and the stripped
                                       text. `stripped_commentary` is None
                                       when no change was needed.
  - `sanitize_for_write(company, *, source) -> (cleaned, evidence_entry|None)`
                                       Drop-in helper for apply_*.py: emits
                                       a stderr warning when stripping happens
                                       and returns a ready-to-append evidence
                                       entry (or None if no stripping).

Self-test: `python3 company_sanitizer.py --self-test`.
"""
from __future__ import annotations

import argparse
import re
import sys

# System markers we must NEVER strip — downstream tooling treats these as
# placeholders / cluster-identity tokens (see
# `apply_company_enrichment.py::_company_is_replaceable` and friends).
_PRESERVE_PATTERNS = [
    re.compile(r" \(inferred from package id\)$"),
    re.compile(r"^Third-party SDK code \(declared in Java package"),
    re.compile(r"^Unidentified shared SDK \(cluster "),
]

# A parenthetical of this shape is treated as a name-acronym (part of the
# formal company name), not commentary. Examples kept: (IBV), (CSR), (ELC).
# Examples stripped: (Japan), (Xplova), (now Digital Dream Labs).
_ACRONYM_RE = re.compile(r"^[A-Z0-9]{2,6}$")

# Em-dash or en-dash surrounded by spaces marks the start of a commentary
# continuation, e.g. "ABB - Electronic Line Manager (ELM) app".
_EM_DASH_MARKERS = (" — ", " – ")  # em-dash, en-dash


def is_preserved_marker(c: str) -> bool:
    """True iff `c` is a system placeholder that must NOT be sanitized."""
    if not c:
        return False
    return any(p.search(c) for p in _PRESERVE_PATTERNS)


def _find_em_dash(c: str) -> int:
    best = -1
    for marker in _EM_DASH_MARKERS:
        i = c.find(marker)
        if i >= 0 and (best == -1 or i < best):
            best = i
    return best


def _find_first_commentary_paren(c: str) -> int:
    """Return index of the SPACE before the first opening paren whose
    contents are NOT a short ALL-CAPS acronym; -1 if no such paren exists."""
    pos = 0
    while True:
        m = re.search(r" \(", c[pos:])
        if not m:
            return -1
        space_idx = pos + m.start()
        open_idx = space_idx + 1
        # Find matching close paren (handle nested parens defensively)
        depth = 0
        close_idx = -1
        for i in range(open_idx + 1, len(c)):
            if c[i] == "(":
                depth += 1
            elif c[i] == ")":
                if depth == 0:
                    close_idx = i
                    break
                depth -= 1
        if close_idx == -1:
            return -1  # malformed; bail
        contents = c[open_idx + 1:close_idx]
        if _ACRONYM_RE.match(contents):
            # Skip past the acronym and keep searching.
            pos = close_idx + 1
            continue
        return space_idx


def clean_company(c: str) -> tuple[str, str | None]:
    """Return `(cleaned, stripped_commentary)`.

    If no stripping is needed (already clean, empty, or a preserved marker),
    returns `(c, None)`."""
    if not c:
        return c, None
    if is_preserved_marker(c):
        return c, None
    em_idx = _find_em_dash(c)
    paren_idx = _find_first_commentary_paren(c)
    candidates = [i for i in (em_idx, paren_idx) if i >= 0]
    if not candidates:
        return c, None
    boundary = min(candidates)
    cleaned = c[:boundary].rstrip(" ")
    if not cleaned:
        return c, None  # would leave empty company; keep original
    stripped = c[boundary:].strip()
    if not stripped:
        return c, None
    return cleaned, stripped


def sanitize_for_write(
    company: str,
    *,
    source: str,
    submitter: str = "Claude (Opus 4.7)",
    warn: bool = True,
) -> tuple[str, dict | None]:
    """Drop-in helper for apply_*.py scripts.

    Returns `(cleaned_company, evidence_entry_to_append)`:
      - `cleaned_company`: the company string to write into the record.
      - `evidence_entry_to_append`: a ready-to-append `evidence_array_item`
        dict carrying the stripped commentary verbatim, or `None` if no
        stripping was needed.

    When stripping happens, a single stderr warning is emitted (unless
    `warn=False`) so the agent can see they shouldn't put commentary in
    the `company` field next time.

    `source` is a short label (e.g. "Phase-2 package_id mapping",
    "Phase-4 SDK cluster", "Phase-5 UUID resolution") used in the warning
    and in the evidence entry's description so the trail is auditable.
    """
    cleaned, stripped = clean_company(company)
    if stripped is None:
        return cleaned, None
    if warn:
        sys.stderr.write(
            f"[sanitize] {source}: stripped commentary from company field\n"
            f"            before: {company!r}\n"
            f"             after: {cleaned!r}\n"
            f"           moved to evidence_array: {stripped!r}\n"
        )
    evidence = {
        "URL": "None",
        "submitter": submitter,
        "description": (
            f"Original 'company'-field commentary moved here (company field "
            f"is now the bare company name; source: {source}): {stripped}"
        ),
    }
    return cleaned, evidence


def _self_test() -> None:
    cases = [
        # (input, expected_clean, expected_stripped_is_not_None)
        (
            "Canon Inc. (Japan) — Camera Connect app; BLE / Wi-Fi pairing for EOS / PowerShot cameras",
            "Canon Inc.",
            True,
        ),
        (
            "Broadlink (Chinese smart-home gateway/IR-blaster vendor; BLE for device-onboarding to WiFi)",
            "Broadlink",
            True,
        ),
        ("Anki (now Digital Dream Labs)", "Anki", True),
        ("August Home (now part of ASSA ABLOY)", "August Home", True),
        ("Cypress Semiconductor (Infineon)", "Cypress Semiconductor", True),
        (
            "Asocíación Instituto de Biomecánica de Valencia (IBV) (Spain; biomechanical lab)",
            "Asocíación Instituto de Biomecánica de Valencia (IBV)",
            True,
        ),
        ("Microchip / ISSC (Transparent UART proprietary service variants)", "Microchip / ISSC", True),
        (
            "Chipsea Technologies / Careyou — smart-scale BLE SDK (LEAONE)",
            "Chipsea Technologies / Careyou",
            True,
        ),
        # Preserved system markers — must NOT change
        ("Cypress (inferred from package id)", "Cypress (inferred from package id)", False),
        (
            "Third-party SDK code (declared in Java package `zk` — distinct)",
            "Third-party SDK code (declared in Java package `zk` — distinct)",
            False,
        ),
        (
            "Unidentified shared SDK (cluster c5, 14 hosts)",
            "Unidentified shared SDK (cluster c5, 14 hosts)",
            False,
        ),
        # Already clean
        ("Apple Inc.", "Apple Inc.", False),
        ("Garmin", "Garmin", False),
        ("IBM", "IBM", False),
        # Acronym in parens is part of the formal name
        ("Asociación Foo (AF)", "Asociación Foo (AF)", False),
        # Edge: empty input
        ("", "", False),
    ]
    failures = []
    for original, expected_clean, expected_changed in cases:
        cleaned, stripped = clean_company(original)
        if cleaned != expected_clean:
            failures.append(
                f"clean_company({original!r}) -> {cleaned!r}, expected {expected_clean!r}"
            )
        if expected_changed != (stripped is not None):
            failures.append(
                f"clean_company({original!r}) changed-flag={stripped is not None}, expected {expected_changed}"
            )
    # sanitize_for_write should produce an evidence entry on a dirty input
    cleaned, ev = sanitize_for_write(
        "Canon Inc. (Japan) — commentary",
        source="self-test",
        warn=False,
    )
    if cleaned != "Canon Inc." or ev is None or ev.get("URL") != "None":
        failures.append(f"sanitize_for_write dirty: got ({cleaned!r}, {ev!r})")
    cleaned, ev = sanitize_for_write("Apple Inc.", source="self-test", warn=False)
    if cleaned != "Apple Inc." or ev is not None:
        failures.append(f"sanitize_for_write clean: got ({cleaned!r}, {ev!r})")
    if failures:
        print("company_sanitizer self-test FAIL:")
        for f in failures:
            print("  -", f)
        sys.exit(2)
    print("company_sanitizer self-test OK")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        _self_test()
        return 0
    p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
