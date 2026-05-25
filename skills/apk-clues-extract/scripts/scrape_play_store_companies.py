#!/usr/bin/env python3
"""Phase-2 automation helper: for every package_id in the
`needs_enrichment` list emitted by `list_inferred_companies.py`, hit the
public Play Store details page and extract the developer / publisher name
from the static HTML.

Why Play Store: it's the only source with a reliably-structured developer
field that:
  - works without authentication
  - works from a CLI (no JS gating beyond the visible HTML)
  - is the authoritative attribution per Google's signing requirements

Extraction is regex over the static HTML — the Play Store ships the
developer name in a `<meta itemprop="author">` (mobile DOM) and as a
JSON-LD blob (`"author":{"@type":"Organization","name":"..."}` ) so one of
those two patterns usually matches. When neither matches, the script
reports `not_found` and the agent should fall back to a free-form web
search (the original Phase-2 manual loop).

Bulk-fills mappings consumable by `apply_company_enrichment.py`.

Usage — input mode 1 (from stdin, one package_id per line):
    python3 list_inferred_companies.py CLUES.json \\
        | jq -r '.needs_enrichment[].package_id' \\
        | python3 scrape_play_store_companies.py > mapping.json

Usage — input mode 2 (explicit packages on argv):
    python3 scrape_play_store_companies.py com.foo.bar com.baz.qux > mapping.json
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request


BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
)


def _fetch(url: str, timeout: int = 15) -> bytes | None:
    req = urllib.request.Request(url)
    req.add_header("User-Agent", BROWSER_UA)
    req.add_header("Accept-Language", "en-US,en;q=0.9")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(2 * 1024 * 1024)
    except (urllib.error.URLError, OSError):
        return None


# Patterns that surface the developer name in the Play Store HTML.
# `meta itemprop="author"` shows on the mobile-DOM variant. JSON-LD
# `"author":{"@type":"Organization","name":"..."}` shows in the head <script>
# block on the desktop variant. The href-link pattern catches the older
# `<a href="/store/apps/dev?id=Developer Name">` form.
_AUTHOR_PATTERNS = [
    re.compile(rb'<meta itemprop="author" content="([^"]+)"'),
    re.compile(rb'"author"\s*:\s*\{[^}]*"name"\s*:\s*"([^"]+)"', re.DOTALL),
    re.compile(rb'/store/apps/dev\?id=([^"&]+)"', re.IGNORECASE),
    re.compile(rb'/store/apps/developer\?id=([^"&]+)"', re.IGNORECASE),
]


def scrape_one(package_id: str) -> dict:
    url = f"https://play.google.com/store/apps/details?id={package_id}&hl=en"
    body = _fetch(url)
    if body is None:
        return {"package_id": package_id, "status": "unreachable"}
    if b"We're sorry, the requested URL was not found on this server." in body \
       or b"The requested URL /store/apps/details was not found" in body:
        return {"package_id": package_id, "status": "not_listed"}
    for pat in _AUTHOR_PATTERNS:
        m = pat.search(body)
        if m:
            raw = m.group(1).decode("utf-8", errors="replace")
            raw = (
                raw.replace("&amp;", "&")
                   .replace("&#39;", "'")
                   .replace("&quot;", '"')
                   .replace("&lt;", "<")
                   .replace("&gt;", ">")
                   .replace("+", " ")
                   .strip()
            )
            if raw:
                return {
                    "package_id": package_id,
                    "status": "ok",
                    "company": raw,
                    "source": url,
                }
    return {"package_id": package_id, "status": "no_author_field"}


def main(argv: list[str]) -> int:
    if argv:
        package_ids = argv
    else:
        package_ids = [line.strip() for line in sys.stdin if line.strip()]
    if not package_ids:
        sys.stderr.write(
            "usage: scrape_play_store_companies.py [package_id ...]\n"
            "       or pipe package_ids on stdin (one per line)\n"
        )
        return 2

    # Output is a single JSON object {package_id: "Company Name"}, ready to be
    # fed straight to `apply_company_enrichment.py`. Failures are surfaced on
    # stderr so the agent knows to fall back to a free-form WebSearch.
    mapping: dict[str, str] = {}
    for pid in package_ids:
        res = scrape_one(pid)
        if res["status"] == "ok":
            mapping[pid] = res["company"]
            sys.stderr.write(f"  ok        {pid:50s} -> {res['company']!r}\n")
        else:
            sys.stderr.write(
                f"  {res['status']:12s}{pid:50s} (Play Store lookup failed; "
                f"fall back to free-form WebSearch)\n"
            )

    json.dump(mapping, sys.stdout, indent=4, ensure_ascii=False)
    sys.stdout.write("\n")
    sys.stderr.write(
        f"\n[*] Scraped {len(mapping)}/{len(package_ids)} packages OK.\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
