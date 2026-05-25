#!/usr/bin/env python3
"""Phase-3 helper: verify that an APK-cache URL is reachable and looks
plausible. CLI-friendly so the agent can call it on each candidate URL
before committing to it.

Strategy:
  1. `urllib` HEAD with a real-browser User-Agent. If we get 200/30x and
     the Content-Type is HTML, the *page* exists — meaning the apkpure /
     apkcombo / apkmirror / archive.org listing for that package+version
     is live. (The actual .apk download from these sites is JavaScript-
     gated; this script does NOT attempt to follow that.)
  2. If we get a direct .apk Content-Type (`application/vnd.android.package-archive`
     or `application/octet-stream`), great — it's a direct download URL,
     which is the *ideal* case (F-Droid, archive.org, some mirrors).
  3. If HEAD returns 405 (Method Not Allowed), retry with a small ranged
     GET. Some CDNs disallow HEAD.
  4. If the server clearly bot-blocks (403 with a Cloudflare-style body,
     503, etc.), report `browser_required` so the agent can confirm via a
     Chrome navigation instead.

Exit codes:
  0 — URL verified as a working page or direct download
  1 — URL is reachable but content looks wrong (404 page disguised as 200,
      wrong package id in the URL, etc.) — caller should pick a different URL
  2 — URL is unreachable
  3 — Bot-blocked / needs a real browser to confirm
  4 — Usage error

Stdout is a one-line JSON status object:
    {"status": "ok",    "http": 200, "content_type": "text/html",
     "direct_download": false, "url": "..."}
    {"status": "bot_blocked", "http": 403, "url": "..."}
    {"status": "unreachable", "http": null, "error": "...",  "url": "..."}
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
)


def _make_req(url: str, method: str) -> urllib.request.Request:
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", BROWSER_UA)
    req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    req.add_header("Accept-Language", "en-US,en;q=0.9")
    return req


def _classify(content_type: str | None) -> tuple[bool, bool]:
    """Returns (is_html, is_direct_apk)."""
    ct = (content_type or "").lower()
    is_html = "text/html" in ct or "application/xhtml" in ct
    is_apk = (
        "application/vnd.android.package-archive" in ct
        or ct == "application/octet-stream"
        or "application/zip" in ct  # some mirrors mislabel XAPKs
    )
    return is_html, is_apk


def _content_sanity(body: bytes, expected_substr: str | None) -> tuple[bool, str | None]:
    """Heuristic: does this body look like a real APK-cache app page?

    apkpure.net / apkcombo etc. return HTTP 200 even for URLs that
    correspond to an app slug but a version that was never archived
    — the body is a tiny (~1KB) JS-only bot-fingerprint stub with no
    HTML structure. A real page is 50KB+ and contains <!DOCTYPE html>
    and a <title> somewhere in the document.

    Returns (passes, reason_if_failed).
    """
    if len(body) < 5_000:
        return False, f"body too small ({len(body)} bytes); likely a bot-fingerprint stub or empty"
    decoded = body[:300_000].decode("utf-8", errors="replace").lower()
    head = decoded[:8192]
    if "<!doctype html" not in head and "<html" not in head:
        return False, "no HTML document tag in first 8KB"
    # Some sites (Play Store) inject the <title> via JS so it doesn't
    # appear in the first 8KB. A large body (≥50KB) with an <html> tag
    # is already strong evidence — only enforce a <title> check on
    # smaller pages where it would still be near the top if real.
    if "<title" not in decoded and len(body) < 50_000:
        return False, "no <title> in document"
    if expected_substr and expected_substr.lower() not in decoded:
        return False, f"page body does not contain expected substring {expected_substr!r}"
    return True, None


# Hosts whose pages are entirely JS-loaded (Play Store, etc.) — for these,
# a 200 response is sufficient evidence the URL works; do not enforce the
# document-body sanity check.
JS_HEAVY_HOSTS = ("play.google.com",)


def verify(url: str, timeout: int = 15, expected_substr: str | None = None) -> dict:
    out: dict = {"url": url, "status": None, "http": None}
    skip_body_check = any(h in url for h in JS_HEAVY_HOSTS)
    try:
        # First try HEAD.
        req = _make_req(url, "HEAD")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                out["http"] = resp.status
                ct = resp.headers.get("Content-Type")
                out["content_type"] = ct
                is_html, is_apk = _classify(ct)
                # Direct .apk download — HEAD is authoritative, no body check.
                if is_apk:
                    out["status"] = "ok"
                    out["direct_download"] = True
                    return out
                # Real HTML page needs a body sanity check — fall through.
        except urllib.error.HTTPError as he:
            if he.code == 405:
                pass  # HEAD not allowed; do a GET
            elif he.code in (403, 503):
                out["http"] = he.code
                out["status"] = "bot_blocked"
                return out
            elif he.code == 404:
                out["http"] = 404
                out["status"] = "not_found"
                return out
            else:
                out["http"] = he.code
                out["status"] = "http_error"
                return out

        # Full GET (need the body for sanity check).
        req = _make_req(url, "GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            out["http"] = resp.status
            ct = resp.headers.get("Content-Type")
            out["content_type"] = ct
            is_html, is_apk = _classify(ct)
            if is_apk:
                out["status"] = "ok"
                out["direct_download"] = True
                return out
            # Cap to avoid loading enormous bodies (APK landing pages are <500KB).
            body = resp.read(512 * 1024)
            out["body_size"] = len(body)
            out["direct_download"] = False
            if skip_body_check:
                # JS-heavy host: 200 + non-trivial body is enough.
                if len(body) >= 5_000:
                    out["status"] = "ok"
                else:
                    out["status"] = "page_invalid"
                    out["reason"] = f"body too small ({len(body)} bytes)"
                return out
            ok, reason = _content_sanity(body, expected_substr)
            if ok:
                out["status"] = "ok"
            else:
                out["status"] = "page_invalid"
                out["reason"] = reason
            return out
    except urllib.error.HTTPError as he:
        out["http"] = he.code
        out["status"] = (
            "bot_blocked" if he.code in (403, 503)
            else "not_found" if he.code == 404
            else "http_error"
        )
        return out
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        out["status"] = "unreachable"
        out["error"] = str(e)
        return out


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("url", nargs="?", help="URL to verify")
    p.add_argument("--from-stdin", action="store_true",
                   help="Read one `URL [\\t expected_substring]` per line from stdin; emit one JSON line per URL")
    p.add_argument("--expect", help="Optional substring that must appear in the page body (e.g. the version_name)")
    p.add_argument("--timeout", type=int, default=15)
    args = p.parse_args(argv)

    if args.from_stdin:
        exit_code = 0
        for raw in sys.stdin:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split("\t", 1)
            u = parts[0].strip()
            expect = parts[1].strip() if len(parts) > 1 else None
            res = verify(u, args.timeout, expected_substr=expect)
            json.dump(res, sys.stdout, ensure_ascii=False)
            sys.stdout.write("\n")
            sys.stdout.flush()
            if res["status"] not in ("ok",):
                exit_code = max(exit_code, _status_to_exit(res["status"]))
        return exit_code

    if not args.url:
        p.error("supply a URL or --from-stdin")
    res = verify(args.url, args.timeout, expected_substr=args.expect)
    json.dump(res, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return _status_to_exit(res["status"])


def _status_to_exit(status: str) -> int:
    return {
        "ok":            0,
        "not_found":     1,
        "http_error":    1,
        "page_invalid":  1,
        "unreachable":   2,
        "bot_blocked":   3,
    }.get(status, 1)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
