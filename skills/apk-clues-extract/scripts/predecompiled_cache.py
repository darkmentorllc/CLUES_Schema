#!/usr/bin/env python3
"""Where pre-decompiled jadx output lives, and how to find it again.

`predecompile_apks.py` writes it; `extract_clues.py` and the per-unit agent
prompt in `run_unit_agents.py` read it, so a corpus decompiled once is never
decompiled again.

Layout. A predecompile run over a corpus directory BASE writes the sibling
directory BASE + "_jadx", mirroring BASE's tree, with one entry per APK:

    /media/user/8TB_APKs/AndroZoo/apks/00/<name>.apk               <- the APK
    /media/user/8TB_APKs/AndroZoo/apks_jadx/                       <- root (holds ROOT_MARKER)
    /media/user/8TB_APKs/AndroZoo/apks_jadx/00/<name>.apk.jadx.tar.xz
        predecompile.json                                          <- provenance + sizes (first member)
        sources/...                                                <- the `jadx -d` output

An entry is either that archive (the default) or a plain directory
`<name>.apk.jadx/` holding the same two things (`predecompile_apks.py
--format dir`). Archives exist because a jadx tree is tens of thousands of
small files per APK: ~4-5x the APK's size on disk once every file rounds up to
a block, versus ~0.2x as one xz-compressed tar, and writing millions of small
files stalls drive-managed SMR disks like the corpus's 8 TB Seagates (the
journal checkpoint falls to a few writes per second). Readers turn an archive
into a directory with materialize(), which unpacks it into a scratch directory
the caller owns.

`--show-bad-code` output (used by the deep Phase-5 pass) goes in a sibling
`<name>.apk.jadx-show-bad-code[.tar.xz]` entry, since it is a different
decompilation.

Lookup never needs to know BASE: `find_predecompiled()` tries
`<ancestor>_jadx/<rest of the path><suffix>` for every ancestor directory of
the APK, so it finds the entry whichever directory the predecompile run was
pointed at, and still finds it when the drive is mounted somewhere else. Roots
kept elsewhere are named with `--predecompiled-dir` or
$APK_CLUES_PREDECOMPILED_DIRS and searched by path suffix.

An entry is used only if its predecompile.json describes a file with the same
name, size and fingerprint as the APK being processed, decompiled with the
same --show-bad-code setting. Entries are renamed into place only after jadx
has finished, so an interrupted run never leaves a valid-looking half entry.

CLI (for agents and shell scripts):
    predecompiled_cache.py [--show-bad-code] [--predecompiled-dir DIR ...]
                           [--extract-to DIR] APK [APK ...]
prints each APK's entry (a directory, or an archive) and exits 1 if any APK
has none. With --extract-to (one APK only) it prints a directory holding
`sources/` instead: a directory entry itself, or DIR with the archive unpacked
into it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Iterable

ROOT_SUFFIX = "_jadx"
ROOT_MARKER = "_PREDECOMPILED_JADX_ROOT.json"
META_NAME = "predecompile.json"
ROOTS_ENV = "APK_CLUES_PREDECOMPILED_DIRS"
SCHEMA_VERSION = 1
ARCHIVE_EXT = ".tar.xz"
XZ_PRESET = 6

# jadx exits non-zero when some methods fail to decompile but still writes the
# rest; extract_clues.run_jadx() accepts that ("partial"), so the cache does
# too. Timeouts, OOMs and runs with no sources/ never become entries.
USABLE_STATUSES = ("ok", "partial")

_ARCHIVE_ERRORS = (OSError, ValueError, EOFError, tarfile.TarError, lzma.LZMAError)


def entry_suffix(show_bad_code: bool = False) -> str:
    return ".jadx-show-bad-code" if show_bad_code else ".jadx"


def is_archive(entry: str) -> bool:
    return entry.endswith(ARCHIVE_EXT)


def entry_forms(entry: str) -> tuple[str, str]:
    """The two shapes an entry can take at one location: directory, archive."""
    return entry, entry + ARCHIVE_EXT


def apk_fingerprint(apk_path: str) -> str:
    """SHA-1 of the first 4 MiB plus the file size: the same cheap recipe
    extract_clues uses for its checkpoint (APKs differ in their header)."""
    h = hashlib.sha1()
    try:
        with open(apk_path, "rb") as f:
            h.update(f.read(4 * 1024 * 1024))
        h.update(str(os.path.getsize(apk_path)).encode())
    except OSError:
        return ""
    return h.hexdigest()


def root_for_base(base: str) -> str:
    return os.path.normpath(os.path.abspath(base)) + ROOT_SUFFIX


def entry_path(root: str, base: str, apk_path: str, show_bad_code: bool = False) -> str:
    """The entry's location, in directory form; entry_forms() adds the archive."""
    rel = os.path.relpath(os.path.abspath(apk_path), os.path.abspath(base))
    return os.path.join(root, rel + entry_suffix(show_bad_code))


def configured_roots(extra: Iterable[str] = ()) -> list[str]:
    roots = list(extra or ())
    roots += [r for r in os.environ.get(ROOTS_ENV, "").split(os.pathsep) if r]
    out: list[str] = []
    for r in roots:
        r = os.path.abspath(os.path.expanduser(r))
        if r not in out and os.path.isdir(r):
            out.append(r)
    return out


def candidate_entries(
    apk_path: str, show_bad_code: bool = False, extra_roots: Iterable[str] = ()
) -> Iterable[str]:
    parts = os.path.abspath(apk_path).split(os.sep)
    suffix = entry_suffix(show_bad_code)
    locations: list[str] = []
    # Explicitly configured roots first, matched on ever-longer path suffixes
    # so they work regardless of where the corpus was mounted when decompiled.
    for root in configured_roots(extra_roots):
        for k in range(1, len(parts)):
            locations.append(os.path.join(root, *parts[-k:]) + suffix)
    # Then the "<ancestor>_jadx" convention, nearest ancestor first. parts[0]
    # is "" (the filesystem root), which never gets a sibling.
    for i in range(len(parts) - 1, 1, -1):
        locations.append(os.path.join(os.sep.join(parts[:i]) + ROOT_SUFFIX, *parts[i:]) + suffix)
    for loc in locations:
        yield from entry_forms(loc)    # a directory needs no unpacking, so it goes first


def read_meta(entry: str) -> dict | None:
    """The entry's predecompile.json. In an archive it is the first member, so
    only the start of the xz stream is decompressed."""
    try:
        if is_archive(entry):
            with tarfile.open(entry, "r:xz") as t:
                m = t.next()
                if m is None or m.name != META_NAME or not m.isfile():
                    return None
                meta = json.load(t.extractfile(m))
        else:
            with open(os.path.join(entry, META_NAME), encoding="utf-8") as f:
                meta = json.load(f)
    except _ARCHIVE_ERRORS:
        return None
    return meta if isinstance(meta, dict) else None


def entry_is_valid(
    entry: str,
    apk_path: str,
    *,
    show_bad_code: bool = False,
    apk_size: int | None = None,
    fingerprint: str | None = None,
) -> bool:
    meta = read_meta(entry)
    if not meta or meta.get("schema") != SCHEMA_VERSION:
        return False
    if meta.get("status") not in USABLE_STATUSES:
        return False
    if bool(meta.get("show_bad_code")) != bool(show_bad_code):
        return False
    if meta.get("apk_name") != os.path.basename(apk_path):
        return False
    try:
        size = os.path.getsize(apk_path) if apk_size is None else apk_size
    except OSError:
        return False
    if meta.get("apk_size") != size:
        return False
    fp = apk_fingerprint(apk_path) if fingerprint is None else fingerprint
    if not fp or meta.get("apk_fingerprint") != fp:
        return False
    if is_archive(entry):
        return os.path.isfile(entry)
    return os.path.isdir(os.path.join(entry, "sources"))


def find_predecompiled(
    apk_path: str, *, show_bad_code: bool = False, extra_roots: Iterable[str] = ()
) -> str | None:
    """Return the APK's trustworthy entry (a directory holding `sources/`, or
    an archive to hand to materialize()), or None if it has none. Never
    returns a path the caller should delete."""
    try:
        size = os.path.getsize(apk_path)
    except OSError:
        return None
    fingerprint = None
    for entry in candidate_entries(apk_path, show_bad_code, extra_roots):
        if not (os.path.isfile(entry) if is_archive(entry)
                else os.path.isfile(os.path.join(entry, META_NAME))):
            continue
        if fingerprint is None:
            fingerprint = apk_fingerprint(apk_path)
        if entry_is_valid(entry, apk_path, show_bad_code=show_bad_code,
                          apk_size=size, fingerprint=fingerprint):
            return entry
    return None


def _normalize(ti: tarfile.TarInfo) -> tarfile.TarInfo:
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    return ti


def write_archive(out_dir: str, path: str, preset: int = XZ_PRESET) -> None:
    """Pack a finished jadx output directory (META_NAME + sources/) into an
    archive entry at `path`, META_NAME first (see read_meta)."""
    with tarfile.open(path, "w:xz", preset=preset) as t:
        t.add(os.path.join(out_dir, META_NAME), arcname=META_NAME, filter=_normalize)
        t.add(os.path.join(out_dir, "sources"), arcname="sources", filter=_normalize)


def _plain_members(t: tarfile.TarFile):
    """Fallback for Pythons without extraction filters: regular files and
    directories with relative, non-escaping names only."""
    for m in t:
        if (m.isfile() or m.isdir()) and not m.name.startswith("/") \
                and ".." not in m.name.split("/"):
            yield m


def _unpack(archive: str, into: str) -> None:
    """Unpack an archive entry into the empty directory `into`. The tar
    program (GNU tar or bsdtar, both refuse absolute and `..` member names)
    takes ~1/3 of tarfile's time on ~20k small files; tarfile, with its "data"
    filter, is the fallback. Raises on failure."""
    tar = shutil.which("tar")
    if tar:
        try:
            if subprocess.run([tar, "-xJf", archive, "-C", into], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=3600).returncode == 0:
                return
        except (OSError, subprocess.SubprocessError):
            pass
        for name in os.listdir(into):     # start the fallback from empty
            path = os.path.join(into, name)
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
    with tarfile.open(archive, "r:xz") as t:
        if hasattr(tarfile, "data_filter"):
            t.extractall(into, filter="data")
        else:
            t.extractall(into, members=_plain_members(t))


def materialize(entry: str, dest: str) -> str | None:
    """The directory holding `sources/` for an entry find_predecompiled()
    returned: a directory entry itself (shared; read it, never delete it), or
    `dest` with an archive entry unpacked into it (the caller's to delete).
    The archive is unpacked into a scratch sibling and `sources/` is renamed
    into place whole, so `dest/sources` never exists half-written; one that
    already exists is reused. Returns None if the archive can't be unpacked."""
    if not is_archive(entry):
        return entry
    if os.path.isdir(os.path.join(dest, "sources")):
        return dest
    parent = os.path.dirname(os.path.abspath(dest))
    scratch = None
    try:
        os.makedirs(parent, exist_ok=True)
        scratch = tempfile.mkdtemp(prefix=".unpack_", dir=parent)
        _unpack(entry, scratch)
        if not os.path.isdir(os.path.join(scratch, "sources")):
            return None
        os.makedirs(dest, exist_ok=True)
        try:
            os.rename(os.path.join(scratch, "sources"), os.path.join(dest, "sources"))
        except OSError:
            # Another reader unpacked the same entry into dest first.
            if not os.path.isdir(os.path.join(dest, "sources")):
                return None
        if os.path.isfile(os.path.join(scratch, META_NAME)):
            os.replace(os.path.join(scratch, META_NAME), os.path.join(dest, META_NAME))
        return dest
    except _ARCHIVE_ERRORS:
        return None
    finally:
        if scratch:
            shutil.rmtree(scratch, ignore_errors=True)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Print the pre-decompiled jadx output entry for each APK "
                    "(exit 1 if any APK has none)."
    )
    p.add_argument("apk", nargs="+")
    p.add_argument("--show-bad-code", action="store_true",
                   help="Look for the --show-bad-code variant (deep Phase-5 pass).")
    p.add_argument("--predecompiled-dir", action="append", default=[],
                   help=f"Extra root to search (repeatable; also ${ROOTS_ENV}).")
    p.add_argument("--extract-to", metavar="DIR",
                   help="Print a directory holding sources/ instead of the entry: a "
                        "directory entry itself, or DIR with an archive unpacked into it "
                        "(one APK only).")
    args = p.parse_args(argv)
    if args.extract_to and len(args.apk) != 1:
        p.error("--extract-to takes exactly one APK")
    missing = 0
    for apk in args.apk:
        hit = find_predecompiled(apk, show_bad_code=args.show_bad_code,
                                 extra_roots=args.predecompiled_dir)
        if hit and args.extract_to:
            hit = materialize(hit, args.extract_to)
        if hit:
            print(hit)
        else:
            missing += 1
            print(f"no predecompiled output for {apk}", file=sys.stderr)
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
