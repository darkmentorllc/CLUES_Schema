#!/usr/bin/env python3
"""Decompile a corpus of APKs/XAPKs ahead of time, so extract_clues.py (and the
per-unit agents) reuse the jadx output instead of running jadx per APK.

    predecompile_apks.py /media/user/8TB_APKs/AndroZoo/apks/00 \\
        --base /media/user/8TB_APKs/AndroZoo/apks
    -> /media/user/8TB_APKs/AndroZoo/apks_jadx/00/<name>.apk.jadx.tar.xz

The layout and lookup rules are in predecompiled_cache.py. jadx runs with
extract_clues.jadx_command() on the same target extract_clues would use (the
base APK of an XAPK), so an entry is what a live run would have produced.

jadx writes its tree into --work-dir (default: the system temp directory,
which should be a local SSD), and only the finished entry, one xz-compressed
tar per APK, is written to the output root. A jadx tree is tens of thousands
of small files: written straight to the corpus drive, shard 00 stalled a
drive-managed SMR disk within half an hour (every jadx waiting on the ext4
journal checkpoint at ~6 writes/s), and the trees take ~20x the archives'
space. `--format dir` keeps plain directory entries, written in place on the
output root, for SSD or CMR storage.

Scheduling keeps a many-core box full without over-committing RAM: APKs run
largest-DEX first, each jadx gets a thread count and heap sized from its DEX,
and jobs start while the CPU-slot and heap budgets allow (smaller APKs backfill
while the next big one doesn't fit, until it has waited too long). A jadx that
runs out of heap is retried with twice the heap. Re-running skips APKs that
already have a valid entry, so an interrupted run simply resumes.

At the end (or with --report) it prints size ratios for the APKs under each
path: decompiled sources vs APK bytes vs DEX bytes, for all APKs and for the
Bluetooth-permission subset that extract_clues actually decompiles.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
import zlib
from dataclasses import dataclass

import extract_clues as ec
import predecompiled_cache as pc

DEX_RE = re.compile(r"^classes\d*\.dex$")
JVM_OVERHEAD_MB = 384          # metaspace, code cache, thread stacks, GC tables
MIN_HEAP_MB = 1024
FIRST_HEAP_CAP_MB = 16384
RETRY_HEAP_CAP_MB = 32768
HEAD_WAIT_SEC = 120            # stop backfilling once the biggest pending job waited this long
PROGRESS_SEC = 60
GZIP_SAMPLE_FILES = 400       # files compressed for the gzip estimate (--format dir)
RUNS_TSV = "_predecompile_runs.tsv"
SUMMARY_JSON = "_predecompile_summary.json"
TSV_COLUMNS = (
    "time", "rel_path", "status", "attempt", "threads", "heap_mb", "seconds", "rc",
    "apk_bytes", "dex_bytes", "bt_perm", "files", "sources_bytes", "disk_bytes",
    "gzip_bytes", "archive_bytes", "pack_seconds", "jadx_errors",
)

_stop = threading.Event()
_procs: set[subprocess.Popen] = set()
_procs_lock = threading.Lock()


@dataclass
class Job:
    apk: str
    root: str
    base: str
    entry: str
    size: int
    dex_bytes: int | None
    aapt_meta: dict | None
    threads: int
    heap_mb: int
    attempt: int = 1
    jadx_exited: bool = False   # set by the worker; its CPU/heap go back to the pool then
    released: bool = False

    @property
    def reserve_mb(self) -> int:
        return self.heap_mb + JVM_OVERHEAD_MB


@dataclass
class Settings:
    jadx: str
    aapt: str | None
    jadx_version: str
    timeout_sec: int
    show_bad_code: bool
    bt_only: bool
    gzip_estimate: bool
    fmt: str                    # "tar.xz" or "dir"
    xz_preset: int
    work_dir: str


def now_iso() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def cpu_count() -> int:
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


def mem_available_mb() -> int:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except OSError:
        pass
    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // (2 * 1024 * 1024)


def dex_bytes_of(apk_path: str) -> int | None:
    """Uncompressed size of classes*.dex: the code jadx actually decompiles."""
    try:
        with zipfile.ZipFile(apk_path) as z:
            return sum(i.file_size for i in z.infolist() if DEX_RE.match(i.filename))
    except Exception:
        return None


def size_job(dex_bytes: int | None, apk_size: int) -> tuple[int, int]:
    """(jadx threads, heap MB). jadx's memory and time scale with the DEX
    (AndroZoo apps reach 200 MB of it); big DEXes get more threads so they are
    not the long pole at the end. ParallelGC grows toward -Xmx, so an inflated
    guess idles cores, while a short one now fails fast (GC overhead limit ->
    ExitOnOutOfMemoryError) and is retried at 2x. On shard 00, 48 MB per DEX MB
    left several 120-165 MB DEXes thrashing at 99.99% old gen."""
    mb = (dex_bytes if dex_bytes is not None else apk_size // 3) / 1e6
    threads = 1 if mb < 10 else 2 if mb < 25 else 4 if mb < 80 else 6
    heap = int(min(FIRST_HEAP_CAP_MB, max(MIN_HEAP_MB + 512, 1024 + 72 * mb)))
    return threads, heap


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _on_signal(signum, _frame) -> None:
    _stop.set()
    with _procs_lock:
        for proc in list(_procs):
            _kill(proc)


def run_jadx_logged(
    s: Settings, target: str, out_dir: str, log_path: str, threads: int, heap_mb: int
) -> tuple[int | None, bool, float]:
    """Returns (exit code or None on timeout, timed_out, seconds)."""
    cmd = ec.jadx_command(s.jadx, target, out_dir, show_bad_code=s.show_bad_code,
                          threads=threads)
    env = dict(os.environ)
    # -Xmx overrides the launcher's MaxRAMPercentage=70 (fatal with dozens of
    # JVMs); ActiveProcessorCount stops each JVM sizing its JIT pools for all
    # CPUs. A short heap must fail fast for the retry instead of grinding in
    # full GCs for the whole timeout: the GC overhead limit (tightened from
    # 98%/2% to 50%/10%) turns thrashing into an OutOfMemoryError, and
    # ExitOnOutOfMemoryError turns that into exit code 3.
    env["JAVA_OPTS"] = " ".join(filter(None, [
        env.get("JAVA_OPTS", ""), f"-Xmx{heap_mb}m",
        f"-XX:ActiveProcessorCount={max(2, threads)}",
        "-XX:+UseParallelGC", "-XX:+UseGCOverheadLimit",
        "-XX:GCTimeLimit=50", "-XX:GCHeapFreeLimit=10",
        "-XX:+ExitOnOutOfMemoryError",
    ]))
    t0 = time.monotonic()
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, env=env, start_new_session=True)
        with _procs_lock:
            _procs.add(proc)
        try:
            rc: int | None = proc.wait(timeout=s.timeout_sec)
            timed_out = False
        except subprocess.TimeoutExpired:
            _kill(proc)
            proc.wait()
            rc, timed_out = None, True
        finally:
            with _procs_lock:
                _procs.discard(proc)
    return rc, timed_out, time.monotonic() - t0


def read_log(log_path: str) -> tuple[list[str], int, bool, bool]:
    """(last lines, number of ERROR lines, ran out of memory, jadx reported
    "finished with errors"). jadx 1.5 exits 3 both for that normal partial
    result and when the JVM dies of OutOfMemoryError, so only the text
    tells them apart."""
    try:
        with open(log_path, "rb") as f:
            data = f.read()
    except OSError:
        return [], 0, False, False
    lines = data.decode("utf-8", "replace").splitlines()
    errors = sum(1 for ln in lines if ln.startswith("ERROR"))
    # The JVM's own ExitOnOutOfMemoryError message, not just any mention:
    # jadx ERROR lines quote method signatures, which can name the class.
    oom = b"Terminating due to java.lang.OutOfMemoryError" in data
    return lines[-8:], errors, oom, b"ERROR - finished with errors, count:" in data


def measure(src_dir: str, gzip_estimate: bool) -> dict:
    """Apparent bytes, allocated bytes (small files round up to a block) and,
    optionally, a solid gzip -6 estimate scaled up from a sample of the files.
    Only the sample is read back: reading a whole tree back costs a disk seek
    per file once memory pressure has evicted it from the page cache."""
    files = dirs = apparent = disk = 0
    paths: list[str] = []
    for dp, dn, fns in os.walk(src_dir):
        dirs += len(dn)
        try:
            disk += os.lstat(dp).st_blocks * 512
        except OSError:
            pass
        for fn in fns:
            path = os.path.join(dp, fn)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            files += 1
            apparent += st.st_size
            disk += st.st_blocks * 512
            if gzip_estimate:
                paths.append(path)
    gz = None
    if paths:
        comp = zlib.compressobj(6)
        raw = packed = 0
        for path in paths[::max(1, len(paths) // GZIP_SAMPLE_FILES)]:
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except OSError:
                continue
            raw += len(data)
            packed += len(comp.compress(data))
        packed += len(comp.flush())
        gz = int(apparent * packed / raw) if raw else 0
    return {"files": files, "dirs": dirs, "sources_bytes": apparent,
            "disk_bytes": disk, "gzip_bytes": gz}


def publish(new: str, entry: str, archive: bool, trash: str) -> None:
    """Rename a finished entry (archive file or tree, already on the output
    filesystem) into place at `entry`'s location. An older entry there, in
    either form, is first moved into `trash` (deleted with it), so readers
    never see a half-written entry or a stale one shadowing the new one."""
    os.makedirs(os.path.dirname(entry), exist_ok=True)
    for i, old in enumerate(pc.entry_forms(entry)):
        if os.path.lexists(old):
            os.rename(old, os.path.join(trash, f"stale{i}"))
    os.rename(new, pc.entry_forms(entry)[1 if archive else 0])


def pack(out_dir: str, path: str, preset: int) -> None:
    """predecompiled_cache.write_archive() in a child interpreter. tarfile's
    per-file work holds the GIL, so packing threads inside this process
    shared ~8 cores between them (35 packing at once left a 48-core box
    half idle)."""
    code = ("import sys; sys.path.insert(0, sys.argv[1]); import predecompiled_cache as pc; "
            "pc.write_archive(sys.argv[2], sys.argv[3], int(sys.argv[4]))")
    subprocess.run([sys.executable, "-c", code, os.path.dirname(os.path.abspath(pc.__file__)),
                    out_dir, path, str(preset)], stdin=subprocess.DEVNULL, check=True)


def staging_dir(work_dir: str, root: str) -> str:
    """Per-root scratch space under --work-dir; the root's lock makes it ours."""
    return os.path.join(work_dir, "predecompile_" + hashlib.sha1(root.encode()).hexdigest()[:12])


def process(job: Job, s: Settings) -> dict:
    row = {"apk": job.apk, "root": job.root, "base": job.base, "attempt": job.attempt,
           "threads": job.threads, "heap_mb": job.heap_mb, "apk_bytes": job.size,
           "dex_bytes": job.dex_bytes, "rc": None, "seconds": 0.0, "jadx_errors": None}
    if _stop.is_set():
        return {**row, "status": "aborted"}
    archive = s.fmt != "dir"
    # out_tmp: on the output filesystem, for the atomic rename into place (and
    # for a stale entry on its way out). tmp: where jadx writes; for archives
    # that is the work dir, so the output root never sees the small files.
    out_tmp = tempfile.mkdtemp(prefix="job_", dir=os.path.join(job.root, ".tmp"))
    tmp = tempfile.mkdtemp(prefix="job_", dir=staging_dir(s.work_dir, job.root)) \
        if archive else out_tmp
    try:
        target, target_desc = job.apk, "apk"
        if job.apk.lower().endswith(".xapk"):
            base_apk = ec.extract_base_apk_from_xapk(job.apk, os.path.join(tmp, "xapk"))
            if base_apk:
                target = base_apk
                target_desc = "base APK inside XAPK: " + os.path.relpath(
                    base_apk, os.path.join(tmp, "xapk"))
            if job.dex_bytes is None:
                job.dex_bytes = row["dex_bytes"] = dex_bytes_of(target)
        if job.aapt_meta is None and s.aapt:
            job.aapt_meta = ec.get_apk_metadata(s.aapt, target)
        meta = job.aapt_meta or {}
        row["bt_perm"] = meta.get("has_bt_perm")
        if s.bt_only and row["bt_perm"] is False:
            return {**row, "status": "skipped_no_bt"}

        out = os.path.join(tmp, "out")
        log_path = os.path.join(tmp, "jadx.log")
        rc, timed_out, secs = run_jadx_logged(s, target, out, log_path, job.threads, job.heap_mb)
        job.jadx_exited = True
        tail, n_errors, oom, finished_with_errors = read_log(log_path)
        row.update(rc=rc, seconds=round(secs, 1), jadx_errors=n_errors)
        if _stop.is_set():
            return {**row, "status": "aborted"}
        if timed_out:
            status = "timeout"
        elif oom:
            status = "oom"
        elif not os.path.isdir(os.path.join(out, "sources")):
            status = "failed"
        elif rc == 0:
            status = "ok"
        elif finished_with_errors and rc > 0:
            status = "partial"     # jadx completed; some methods didn't decompile
        else:
            status = "failed"      # killed or crashed: the tree may be cut short
        row["status"] = status
        if status not in pc.USABLE_STATUSES:
            row["log_tail"] = tail
            return row

        # For an archive the tree is measured in the work dir: its disk_bytes
        # is what the tree would take as a directory entry.
        sizes = measure(os.path.join(out, "sources"), s.gzip_estimate and not archive)
        row.update(sizes)
        st = os.stat(job.apk)
        meta_out = {
            "schema": pc.SCHEMA_VERSION,
            "apk_name": os.path.basename(job.apk),
            "apk_size": job.size,
            "apk_fingerprint": pc.apk_fingerprint(job.apk),
            "apk_mtime": int(st.st_mtime),
            "apk_path": job.apk,
            "decompiled_target": target_desc,
            "package_id": meta.get("package_id"),
            "version_code": meta.get("version_code"),
            "version_name": meta.get("version_name"),
            "bt_perm": row["bt_perm"],
            "dex_bytes": job.dex_bytes,
            "show_bad_code": s.show_bad_code,
            "entry_format": s.fmt,
            "xz_preset": s.xz_preset if archive else None,
            "jadx_version": s.jadx_version,
            "jadx_args": ec.jadx_command("jadx", "APK", "OUT",
                                         show_bad_code=s.show_bad_code)[1:-3],
            "jadx_threads": job.threads,
            "heap_mb": job.heap_mb,
            "attempt": job.attempt,
            "status": status,
            "rc": rc,
            "seconds": round(secs, 1),
            "jadx_errors": n_errors,
            "log_tail": tail,
            **sizes,
            "created": now_iso(),
            "host": socket.gethostname(),
        }
        with open(os.path.join(out, pc.META_NAME), "w", encoding="utf-8") as f:
            json.dump(meta_out, f, indent=1)
        if archive:
            packed = os.path.join(out_tmp, "entry" + pc.ARCHIVE_EXT)
            t_pack = time.monotonic()
            try:
                pack(out, packed, s.xz_preset)
            except subprocess.CalledProcessError:
                if _stop.is_set():      # Ctrl-C reaches the packer too
                    return {**row, "status": "aborted"}
                raise
            row.update(archive_bytes=os.path.getsize(packed),
                       pack_seconds=round(time.monotonic() - t_pack, 1))
            publish(packed, job.entry, True, out_tmp)
        else:
            publish(out, job.entry, False, out_tmp)
        return row
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if out_tmp != tmp:
            shutil.rmtree(out_tmp, ignore_errors=True)


def survey_one(apk: str, root: str, base: str, s: Settings, force: bool) -> Job | None:
    """Job for an APK that still needs decompiling, None if it has a valid entry."""
    size = os.path.getsize(apk)
    entry = pc.entry_path(root, base, apk, s.show_bad_code)
    if not force and any(pc.entry_is_valid(e, apk, show_bad_code=s.show_bad_code, apk_size=size)
                         for e in pc.entry_forms(entry)):
        return None     # either form will do; --force replaces it with --format's
    is_xapk = apk.lower().endswith(".xapk")
    dex = None if is_xapk else dex_bytes_of(apk)
    aapt_meta = ec.get_apk_metadata(s.aapt, apk) if (s.aapt and not is_xapk) else None
    threads, heap = size_job(dex, size)
    return Job(apk, root, base, entry, size, dex, aapt_meta, threads, heap)


def lock_root(root: str, base: str, work_dir: str):
    os.makedirs(root, exist_ok=True)
    fh = open(os.path.join(root, ".lock"), "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit(f"ERROR: another predecompile run holds {root}/.lock")
    # Safe now that we hold the lock: leftovers of a killed run are garbage.
    for scratch in (os.path.join(root, ".tmp"), staging_dir(work_dir, root)):
        shutil.rmtree(scratch, ignore_errors=True)
        os.makedirs(scratch)
    marker = os.path.join(root, pc.ROOT_MARKER)
    if not os.path.exists(marker):
        with open(marker, "w", encoding="utf-8") as f:
            json.dump({"schema": pc.SCHEMA_VERSION, "tool": "predecompile_apks.py",
                       "base": base, "created": now_iso(),
                       "layout": "mirrors BASE; one <apk name>.jadx.tar.xz (or "
                                 "<apk name>.jadx/) entry per APK (see predecompiled_cache.py)"},
                      f, indent=1)
    return fh


def append_tsv(root: str, row: dict) -> None:
    path = os.path.join(root, RUNS_TSV)
    header = "\t".join(TSV_COLUMNS) + "\n"
    try:
        with open(path, encoding="utf-8") as f:
            if f.readline() != header:   # written by an older version: set it aside
                os.rename(path, path[:-4] + time.strftime(".%Y%m%d-%H%M%S.tsv"))
    except OSError:
        pass
    new = not os.path.exists(path)
    vals = {**row, "time": now_iso(), "rel_path": os.path.relpath(row["apk"], row["base"])}
    with open(path, "a", encoding="utf-8") as f:
        if new:
            f.write(header)
        f.write("\t".join("" if vals.get(c) is None else str(vals.get(c))
                          for c in TSV_COLUMNS) + "\n")


def _ratio(a: float, b: float) -> float | None:
    return round(a / b, 3) if b else None


def summarize(path: str, root: str, base: str, show_bad_code: bool) -> dict:
    """Size totals and ratios over the entries of every APK under `path`."""
    metas, missing = [], []
    for apk in ec.iter_input_paths(path):
        size = os.path.getsize(apk)
        for entry in pc.entry_forms(pc.entry_path(root, base, apk, show_bad_code)):
            meta = pc.read_meta(entry)
            if meta and meta.get("status") in pc.USABLE_STATUSES and meta.get("apk_size") == size:
                meta["archive_bytes"] = os.path.getsize(entry) if pc.is_archive(entry) else None
                metas.append(meta)
                break
        else:
            missing.append(os.path.basename(apk))

    def group(sel: list[dict]) -> dict:
        apk = sum(m["apk_size"] for m in sel)
        dex = sum(m.get("dex_bytes") or 0 for m in sel)
        src = sum(m["sources_bytes"] for m in sel)
        disk = sum(m["disk_bytes"] for m in sel)
        gz = sum(m.get("gzip_bytes") or 0 for m in sel)
        arc = [m for m in sel if m["archive_bytes"]]
        arc_bytes = sum(m["archive_bytes"] for m in arc)
        arc_apk = sum(m["apk_size"] for m in arc)
        arc_src = sum(m["sources_bytes"] for m in arc)
        # What the entries actually occupy: archives, plus directory entries' trees.
        stored = arc_bytes + sum(m["disk_bytes"] for m in sel if not m["archive_bytes"])
        per = sorted(m["sources_bytes"] / m["apk_size"] for m in sel if m["apk_size"])
        return {
            "apks": len(sel), "apk_bytes": apk, "dex_bytes": dex, "sources_bytes": src,
            "disk_bytes": disk, "gzip_bytes": gz or None,
            "archives": len(arc), "archive_bytes": arc_bytes or None, "stored_bytes": stored,
            "files": sum(m["files"] for m in sel),
            "jadx_seconds": round(sum(m["seconds"] for m in sel)),
            "sources_per_apk": _ratio(src, apk), "sources_per_dex": _ratio(src, dex),
            "disk_per_apk": _ratio(disk, apk), "gzip_per_apk": _ratio(gz, apk) if gz else None,
            # Over the archived entries only: compressed bytes per APK byte and per source byte.
            "archive_per_apk": _ratio(arc_bytes, arc_apk) if arc else None,
            "archive_per_sources": _ratio(arc_bytes, arc_src) if arc else None,
            "stored_per_apk": _ratio(stored, apk),
            "per_apk_sources_ratio_median": round(statistics.median(per), 3) if per else None,
            "per_apk_sources_ratio_p90": round(per[int(0.9 * (len(per) - 1))], 3) if per else None,
            "per_apk_sources_ratio_max": round(per[-1], 3) if per else None,
        }

    return {
        "path": os.path.abspath(path), "root": root, "show_bad_code": show_bad_code,
        "generated": now_iso(),
        "apks_without_entry": len(missing),
        "all": group(metas),
        "bt_perm": group([m for m in metas if m.get("bt_perm") is True]),
        "no_bt_perm": group([m for m in metas if m.get("bt_perm") is False]),
        "bt_perm_unknown": group([m for m in metas if m.get("bt_perm") is None]),
        "missing_sample": missing[:20],
    }


def print_summary(sm: dict) -> None:
    gb = lambda b: f"{(b or 0) / 1e9:,.2f} GB"
    print(f"\n=== {sm['path']}  ->  {sm['root']}")
    print(f"    {sm['apks_without_entry']} APK(s) have no usable entry")
    for key, label in (("all", "all APKs"), ("bt_perm", "BT-permission APKs"),
                       ("no_bt_perm", "non-BT APKs"), ("bt_perm_unknown", "aapt failed")):
        g = sm[key]
        if not g["apks"]:
            continue
        print(f"  {label}: {g['apks']} | APK {gb(g['apk_bytes'])} | DEX {gb(g['dex_bytes'])} | "
              f"sources {gb(g['sources_bytes'])} ({g['files']:,} files) | as trees "
              f"{gb(g['disk_bytes'])} | stored {gb(g['stored_bytes'])}"
              + (f" | {g['archives']} archives {gb(g['archive_bytes'])}" if g["archives"] else "")
              + (f" | gzip est. {gb(g['gzip_bytes'])}" if g["gzip_bytes"] else ""))
        print(f"      sources/APK {g['sources_per_apk']}  sources/DEX {g['sources_per_dex']}  "
              f"tree-on-disk/APK {g['disk_per_apk']}  stored/APK {g['stored_per_apk']}  "
              f"archive/APK {g['archive_per_apk']}  archive/sources {g['archive_per_sources']}  "
              f"gzip/APK {g['gzip_per_apk']}")
        print(f"      per-APK sources/APK median {g['per_apk_sources_ratio_median']} "
              f"p90 {g['per_apk_sources_ratio_p90']} max {g['per_apk_sources_ratio_max']}  "
              f"jadx time {g['jadx_seconds'] / 3600:.1f} h")


def main(argv: list[str]) -> int:
    ncpu = cpu_count()
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="+", help="APK/XAPK files or directories (walked recursively)")
    p.add_argument("--base", help="Corpus directory the output mirrors; output goes to BASE_jadx. "
                                  "Default: each directory argument itself (a file: its parent).")
    p.add_argument("--jadx", help="jadx launcher (default: jadx on PATH, else ~/.local/bin/jadx)")
    p.add_argument("--aapt", help="aapt (default: what extract_clues finds); used for the "
                                  "BT-permission split, metadata and --bt-only")
    p.add_argument("--jobs", type=int, default=ncpu, help=f"Max concurrent jadx (default {ncpu})")
    p.add_argument("--cpu-slots", type=int, default=int(ncpu * 1.25),
                   help="jadx threads allowed at once (default 1.25 x CPUs; jadx spends part "
                        "of its time in I/O and GC)")
    p.add_argument("--mem-budget-gb", type=float, default=None,
                   help="Heap + JVM overhead allowed at once (default 90%% of MemAvailable)")
    p.add_argument("--min-free-gb", type=float, default=50,
                   help="Stop starting jobs when the output filesystem has less free space")
    p.add_argument("--format", choices=("tar.xz", "dir"), default="tar.xz",
                   help="Entry format: one xz-compressed tar per APK (default), or a plain "
                        "directory tree written in place (SSD/CMR output roots only)")
    p.add_argument("--xz-preset", type=int, default=pc.XZ_PRESET, choices=range(10),
                   metavar="0-9", help=f"xz preset for archives (default {pc.XZ_PRESET})")
    p.add_argument("--work-dir", default=tempfile.gettempdir(),
                   help="Where jadx writes before the tree is packed, ideally a local SSD "
                        "(tar.xz format; default %(default)s)")
    p.add_argument("--min-work-free-gb", type=float, default=20,
                   help="Hold off starting jobs while --work-dir has less free space")
    p.add_argument("--timeout-sec", type=int, default=3600, help="Per-APK jadx timeout")
    p.add_argument("--show-bad-code", action="store_true",
                   help="Produce the --show-bad-code variant used by the deep Phase-5 pass")
    p.add_argument("--bt-only", action="store_true",
                   help="Skip APKs without Bluetooth permissions (extract_clues never decompiles them)")
    p.add_argument("--force", action="store_true", help="Redo APKs that already have an entry")
    p.add_argument("--no-gzip-estimate", action="store_true",
                   help="Skip the solid-gzip size estimate of each output tree (--format dir)")
    p.add_argument("--report", action="store_true", help="Only print/write the size summary")
    p.add_argument("--dry-run", action="store_true", help="Print the plan and exit")
    args = p.parse_args(argv)

    targets: list[tuple[str, str, str]] = []   # (path, base, root)
    for path in args.paths:
        path = os.path.abspath(path)
        if not os.path.exists(path):
            p.error(f"no such path: {path}")
        base = os.path.abspath(args.base) if args.base else (
            path if os.path.isdir(path) else os.path.dirname(path))
        if os.path.relpath(path, base).startswith(".."):
            p.error(f"{path} is not under --base {base}")
        targets.append((path, base, pc.root_for_base(base)))

    jadx = args.jadx or shutil.which("jadx") or os.path.expanduser("~/.local/bin/jadx")
    if not os.access(jadx, os.X_OK):
        p.error(f"jadx not found/executable: {jadx}")
    aapt = args.aapt
    if not aapt:
        try:
            aapt = ec.find_aapt()
        except SystemExit:
            aapt = None
    ver = subprocess.run([jadx, "--version"], capture_output=True, text=True).stdout.strip()
    s = Settings(jadx=jadx, aapt=aapt, jadx_version=ver.splitlines()[-1] if ver else "",
                 timeout_sec=args.timeout_sec, show_bad_code=args.show_bad_code,
                 bt_only=args.bt_only, gzip_estimate=not args.no_gzip_estimate,
                 fmt=args.format, xz_preset=args.xz_preset,
                 work_dir=os.path.abspath(args.work_dir))
    archive = s.fmt != "dir"

    if args.report:
        for path, base, root in targets:
            print_summary(summarize(path, root, base, s.show_bad_code))
        return 0

    locks = [] if args.dry_run else [lock_root(root, base, s.work_dir) for root, base in
                                     {(r, b) for _, b, r in targets}]
    for sig in (signal.SIGINT, signal.SIGTERM):   # not SIGHUP: leave nohup's SIG_IGN alone
        signal.signal(sig, _on_signal)

    apks: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for path, base, root in targets:
        for apk in ec.iter_input_paths(path):
            apk = os.path.abspath(apk)
            if apk not in seen:
                seen.add(apk)
                apks.append((apk, root, base))
    t_survey = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=ncpu) as ex:
        surveyed = list(ex.map(lambda a: survey_one(a[0], a[1], a[2], s, args.force), apks))
    jobs = [j for j in surveyed if j is not None]
    if args.bt_only:
        jobs = [j for j in jobs if not (j.aapt_meta and j.aapt_meta["has_bt_perm"] is False)]
    jobs.sort(key=lambda j: j.dex_bytes if j.dex_bytes is not None else j.size // 3, reverse=True)

    mem_budget_mb = int(args.mem_budget_gb * 1024) if args.mem_budget_gb else int(mem_available_mb() * 0.9)
    print(f"[*] {now_iso()} jadx={jadx} ({s.jadx_version}) aapt={aapt}", flush=True)
    print(f"[*] {len(apks)} APK(s); {surveyed.count(None)} already "
          f"have an entry; {len(jobs)} to decompile ({sum(j.size for j in jobs) / 1e9:.1f} GB); "
          f"survey took {time.monotonic() - t_survey:.0f}s", flush=True)
    print(f"[*] budgets: {args.jobs} jobs, {args.cpu_slots} jadx threads, "
          f"{mem_budget_mb / 1024:.0f} GB heap+overhead, timeout {args.timeout_sec}s, "
          f"min free {args.min_free_gb:.0f} GB; roots: "
          + ", ".join(sorted({r for _, _, r in targets})), flush=True)
    print(f"[*] entries: " + (f"tar.xz -{s.xz_preset}, jadx writes to {s.work_dir} "
                               f"(min free {args.min_work_free_gb:.0f} GB)"
                               if archive else "directory trees"), flush=True)
    if args.dry_run:
        for j in jobs[:15]:
            print(f"    dex {(j.dex_bytes or 0) / 1e6:7.1f} MB  apk {j.size / 1e6:7.1f} MB  "
                  f"-j {j.threads}  heap {j.heap_mb} MB  {os.path.basename(j.apk)}")
        return 0

    pending = list(jobs)
    running: dict[concurrent.futures.Future, Job] = {}
    cpu_used = mem_used = 0
    counts: dict[str, int] = {}
    head_blocked_since: float | None = None
    low_disk = False
    work_low = False
    t0 = last_progress = time.monotonic()

    def fits(job: Job) -> bool:
        active = sum(1 for j in running.values() if not j.released)
        if not active:
            return True     # anything may run alone, however big
        return (active < args.jobs and cpu_used + job.threads <= args.cpu_slots
                and mem_used + job.reserve_mb <= mem_budget_mb)

    # Extra workers: a job keeps its thread while it measures, packs and
    # publishes. Its JVM's heap and all but one of its CPU slots go back to the
    # pool when the JVM exits; the last slot is the packer's until it is done.
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs * 3) as ex:
        while running or (pending and not _stop.is_set() and not low_disk):
            for job in running.values():
                if job.jadx_exited and not job.released:
                    job.released = True
                    cpu_used -= job.threads - 1
                    mem_used -= job.reserve_mb
            if pending and not _stop.is_set() and not low_disk:
                free_gb = min(shutil.disk_usage(r).free for r in {j.root for j in pending}) / 1e9
                if free_gb < args.min_free_gb:
                    low_disk = True
                    print(f"[!] only {free_gb:.0f} GB free; not starting new jobs", flush=True)
                if archive:
                    # Running jobs free their work-dir trees as they finish,
                    # so this only pauses starts (and stops if nothing runs).
                    work_free_gb = shutil.disk_usage(s.work_dir).free / 1e9
                    if (work_free_gb < args.min_work_free_gb) != work_low:
                        work_low = not work_low
                        print(f"[!] {work_free_gb:.0f} GB free in {s.work_dir}; "
                              + ("holding new jobs" if work_low else "resuming"), flush=True)
                    if work_low and not running:
                        low_disk = True
                        print("[!] nothing left running to free it; not starting new jobs",
                              flush=True)
                i = 0
                while i < len(pending) and not low_disk and not work_low:
                    job = pending[i]
                    if fits(job):
                        pending.pop(i)
                        running[ex.submit(process, job, s)] = job
                        cpu_used += job.threads
                        mem_used += job.reserve_mb
                        if i == 0:
                            head_blocked_since = None
                        continue
                    if i == 0:
                        head_blocked_since = head_blocked_since or time.monotonic()
                        if time.monotonic() - head_blocked_since > HEAD_WAIT_SEC:
                            break   # let resources drain to the big job
                    i += 1
            done, _ = concurrent.futures.wait(
                running, timeout=5, return_when=concurrent.futures.FIRST_COMPLETED)
            for fut in done:
                job = running.pop(fut)
                if job.released:
                    cpu_used -= 1
                else:
                    cpu_used -= job.threads
                    mem_used -= job.reserve_mb
                try:
                    row = fut.result()
                except Exception as e:  # a bug in process(), not a jadx failure
                    row = {"apk": job.apk, "base": job.base, "attempt": job.attempt,
                           "status": f"exception:{type(e).__name__}:{e}"}
                status = row["status"]
                if status == "aborted":
                    continue
                append_tsv(job.root, row)
                if status == "oom" and job.heap_mb < RETRY_HEAP_CAP_MB and not _stop.is_set():
                    job.heap_mb = min(RETRY_HEAP_CAP_MB, job.heap_mb * 2)
                    job.attempt += 1
                    job.jadx_exited = job.released = False
                    pending.insert(0, job)
                    status = "oom_retry"
                counts[status] = counts.get(status, 0) + 1
                if status not in pc.USABLE_STATUSES:
                    print(f"[!] {status}: {os.path.basename(job.apk)} (attempt {job.attempt}, "
                          f"heap {job.heap_mb} MB) {row.get('log_tail', [])[-2:]}", flush=True)
            if time.monotonic() - last_progress >= PROGRESS_SEC:
                last_progress = time.monotonic()
                done_n = sum(v for k, v in counts.items() if k != "oom_retry")
                active = sum(1 for j in running.values() if not j.released)
                print(f"[*] {now_iso()} {done_n}/{len(jobs)} done {counts} | jadx {active} "
                      f"+ packing {len(running) - active} ({cpu_used} threads, "
                      f"{mem_used / 1024:.0f} GB) | "
                      f"pending {len(pending)} | {(time.monotonic() - t0) / 60:.0f} min", flush=True)

    print(f"[*] {now_iso()} finished in {(time.monotonic() - t0) / 60:.1f} min: {counts}"
          + (" (interrupted)" if _stop.is_set() else ""), flush=True)
    for path, base, root in targets:
        sm = summarize(path, root, base, s.show_bad_code)
        print_summary(sm)
        rel = os.path.relpath(path, base)
        out_dir = root if rel == "." or not os.path.isdir(path) else os.path.join(root, rel)
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, SUMMARY_JSON), "w", encoding="utf-8") as f:
            json.dump(sm, f, indent=1)
    for root in {r for _, _, r in targets}:
        shutil.rmtree(staging_dir(s.work_dir, root), ignore_errors=True)
    del locks
    return 130 if _stop.is_set() else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
