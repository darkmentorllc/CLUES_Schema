#!/usr/bin/env python3
"""Stage reusable non-Java APK inputs beside the normal jadx cache entry.

The sidecar stores decoded Xamarin DLLs (including assembly-store payloads)
and the raw React Native bundle when present. It does not claim that a DLL or
Hermes bytecode has been decompiled to source.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import lzma
import os
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

import predecompiled_cache as pc

SCHEMA = 1
EXT = ".nonjava.tar.xz"
META = "nonjava.json"
BUNDLE = "assets/index.android.bundle"
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_ASSEMBLIES = 512 * 1024 * 1024


def sidecar_path(apk_path: str, base: str) -> Path:
    root = pc.root_for_base(base)
    return Path(root) / (os.path.relpath(os.path.abspath(apk_path), base) + EXT)


def candidate_sidecars(apk_path: str):
    seen = set()
    for entry in pc.candidate_entries(apk_path):
        for suffix in (".jadx.tar.xz", ".jadx"):
            if entry.endswith(suffix):
                path = entry[: -len(suffix)] + EXT
                if path not in seen:
                    seen.add(path)
                    yield Path(path)
                break


def _first_meta(path: Path) -> dict | None:
    try:
        with tarfile.open(path, "r:xz") as archive:
            first = archive.next()
            if first is None or first.name != META or not first.isfile() or first.size > 1024 * 1024:
                return None
            value = json.load(archive.extractfile(first))
            return value if isinstance(value, dict) else None
    except (OSError, ValueError, EOFError, tarfile.TarError, lzma.LZMAError):
        return None


def _matches(meta: dict | None, apk_path: str, fingerprint: str | None = None) -> bool:
    if not meta or meta.get("schema") != SCHEMA:
        return False
    try:
        size = os.path.getsize(apk_path)
    except OSError:
        return False
    return (meta.get("apk_name") == os.path.basename(apk_path)
            and meta.get("apk_size") == size
            and meta.get("apk_fingerprint") ==
            (fingerprint if fingerprint is not None else pc.apk_fingerprint(apk_path)))


def find_sidecar(apk_path: str) -> Path | None:
    fingerprint = None
    for path in candidate_sidecars(apk_path):
        if not path.is_file():
            continue
        if fingerprint is None:
            fingerprint = pc.apk_fingerprint(apk_path)
        if _matches(_first_meta(path), apk_path, fingerprint):
            return path
    return None


def load_assemblies(apk_path: str) -> list[tuple[str, bytes]] | None:
    """Return staged DLLs, or None so callers can fall back to the APK."""
    path = find_sidecar(apk_path)
    if path is None:
        return None
    try:
        with tarfile.open(path, "r:xz") as archive:
            first = archive.next()
            meta = json.load(archive.extractfile(first))
            expected = {item["member"]: item for item in meta.get("assemblies", [])}
            if meta.get("bundle"):
                expected[meta["bundle"]["member"]] = meta["bundle"]
            result = []
            total = 0
            for member in archive:
                item = expected.pop(member.name, None)
                if item is None:
                    continue
                cap = MAX_BUNDLE_BYTES if member.name == BUNDLE else MAX_ASSEMBLIES
                if not member.isfile() or member.size != item["size"] or member.size > cap:
                    return None
                data = archive.extractfile(member).read()
                total += len(data)
                if total > MAX_ASSEMBLIES + MAX_BUNDLE_BYTES or hashlib.sha256(data).hexdigest() != item["sha256"]:
                    return None
                if "name" in item:
                    result.append((item["name"], data))
            return result if not expected else None
    except (OSError, ValueError, EOFError, KeyError, tarfile.TarError, lzma.LZMAError):
        return None


def stage_apk(apk_path: str, base: str, work_dir: str = "/tmp") -> dict:
    """Write one atomic sidecar only when managed code or a JS bundle exists."""
    dest = sidecar_path(apk_path, base)
    fingerprint = pc.apk_fingerprint(apk_path)
    if _matches(_first_meta(dest), apk_path, fingerprint) and load_assemblies(apk_path) is not None:
        meta = _first_meta(dest)
        return {"apk": apk_path, "status": "cached", "kind": meta.get("managed_kind"),
                "assemblies": len(meta.get("assemblies", [])), "bundle": bool(meta.get("bundle"))}

    import managed_clues  # lazy import avoids a cycle in the CLUES reader

    try:
        with zipfile.ZipFile(apk_path) as apk:
            names = set(apk.namelist())
            kind = ("store" if "assemblies/assemblies.blob" in names else
                    "direct" if any(n.startswith("assemblies/") and n.lower().endswith(".dll")
                                    for n in names) else "absent")
            bundle = apk.read(BUNDLE) if BUNDLE in names and apk.getinfo(BUNDLE).file_size <= MAX_BUNDLE_BYTES else None
            if BUNDLE in names and bundle is None:
                return {"apk": apk_path, "status": "error:oversized_bundle"}
        if kind == "absent" and bundle is None:
            return {"apk": apk_path, "status": "absent"}
        assemblies = managed_clues._assemblies(apk_path) if kind != "absent" else []
        if sum(len(data) for _, data in assemblies) > MAX_ASSEMBLIES:
            return {"apk": apk_path, "status": "error:oversized_assemblies"}
        with tempfile.TemporaryDirectory(prefix="nonjava_", dir=work_dir) as tmp:
            tmp = Path(tmp)
            records = []
            for index, (name, data) in enumerate(assemblies):
                member = f"assemblies/{index:04d}.dll"
                p = tmp / member
                p.parent.mkdir(exist_ok=True)
                p.write_bytes(data)
                records.append({"name": name, "member": member, "size": len(data),
                                "sha256": hashlib.sha256(data).hexdigest()})
            if bundle is not None:
                p = tmp / BUNDLE
                p.parent.mkdir(exist_ok=True)
                p.write_bytes(bundle)
            meta = {"schema": SCHEMA, "apk_name": os.path.basename(apk_path),
                    "apk_size": os.path.getsize(apk_path), "apk_fingerprint": fingerprint,
                    "managed_kind": kind, "assemblies": records,
                    "bundle": ({"member": BUNDLE, "size": len(bundle),
                                "sha256": hashlib.sha256(bundle).hexdigest()}
                               if bundle is not None else None)}
            (tmp / META).write_text(json.dumps(meta, indent=2) + "\n")
            packed = tmp / "entry.tar.xz"
            with tarfile.open(packed, "w:xz", preset=3) as archive:
                archive.add(tmp / META, arcname=META)
                for record in records:
                    archive.add(tmp / record["member"], arcname=record["member"])
                if bundle is not None:
                    archive.add(tmp / BUNDLE, arcname=BUNDLE)
            dest.parent.mkdir(parents=True, exist_ok=True)
            pending_path = None
            try:
                with tempfile.NamedTemporaryFile(prefix=".nonjava_", suffix=".tmp", dir=dest.parent,
                                                 delete=False) as pending:
                    pending_path = Path(pending.name)
                    with packed.open("rb") as source:
                        shutil.copyfileobj(source, pending, 1024 * 1024)
                    pending.flush()
                    os.fsync(pending.fileno())
                os.replace(pending_path, dest)
            finally:
                if pending_path is not None:
                    pending_path.unlink(missing_ok=True)
        return {"apk": apk_path, "status": "staged", "kind": kind,
                "assemblies": len(assemblies), "bundle": bundle is not None}
    except zipfile.BadZipFile as exc:
        # A truncated corpus APK cannot contain usable DLLs or a JS bundle.
        # Record it for the audit without retrying the whole shard forever.
        return {"apk": apk_path, "status": "invalid_apk", "reason": str(exc)[:180]}
    except Exception as exc:
        return {"apk": apk_path, "status": f"error:{type(exc).__name__}:{str(exc)[:180]}"}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", help="APK files to stage")
    parser.add_argument("--paths-file", help="Text file with one APK path per line")
    parser.add_argument("--base", required=True, help="APK corpus root mirrored by BASE_jadx")
    parser.add_argument("--work-dir", default="/tmp", help="SSD staging directory")
    parser.add_argument("--jobs", type=int, default=2, help="Concurrent APK reads (default 2)")
    args = parser.parse_args(argv)
    paths = list(args.paths)
    if args.paths_file:
        with open(args.paths_file, encoding="utf-8") as source:
            paths.extend(line.strip() for line in source if line.strip())
    expanded = []
    for path in paths:
        p = Path(path)
        if p.is_dir():
            expanded.extend(str(apk) for apk in sorted(p.rglob("*.apk")))
            expanded.extend(str(apk) for apk in sorted(p.rglob("*.xapk")))
        else:
            expanded.append(str(p))
    paths = list(dict.fromkeys(expanded))
    if not paths or args.jobs < 1:
        parser.error("provide APK paths/--paths-file and a positive --jobs")
    base = os.path.abspath(args.base)
    if any(os.path.commonpath((base, os.path.abspath(path))) != base for path in paths):
        parser.error("every APK must be under --base")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda apk: stage_apk(apk, args.base, args.work_dir), paths))
    counts: dict[str, int] = {}
    for result in results:
        status = result["status"].split(":", 1)[0]
        counts[status] = counts.get(status, 0) + 1
        if status in {"error", "invalid_apk"}:
            print(json.dumps(result), file=sys.stderr)
    print(json.dumps({"total": len(paths), "counts": counts}))
    return 2 if counts.get("error") else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
