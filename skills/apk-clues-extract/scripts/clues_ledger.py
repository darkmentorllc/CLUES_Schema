#!/usr/bin/env python3
"""Per-repository processing ledger for apk-clues-extract.

PURPOSE
    Make "continue where we left off" work from a COLD START: a brand-new session
    with no memory, no transcript and no context can point this tool at an APK
    repository and learn exactly which APKs have been through which phases and what
    to run next. All state lives beside the APKs, not in a session.

LAYOUT (created by `init`, inside the repository root)
    <repo>/.clues_ledger/
        README.md       self-describing: what this is + the exact resume commands
        ledger.jsonl    APPEND-ONLY event log; the source of truth
        state.json      derived rollup (safe to delete; rebuild with `rollup`)

WHY APPEND-ONLY
    Phase work runs as many parallel `claude -p` sub-agents, on more than one host,
    writing concurrently. Appending one self-contained JSON line per event is safe
    under concurrency; rewriting a single state document is not.

COMMANDS
    init    --repo R                          create the ledger + README
    scan    --repo R                          register APKs found under R
    record  --repo R --apk SHA --phase P --status S [--detail JSON]
    status  --repo R                          per-phase completion summary
    next    --repo R --phase P [--limit N]    APKs still needing phase P (TSV)
    rollup  --repo R                          rebuild state.json from ledger.jsonl
"""
from __future__ import annotations
import argparse, collections, datetime, glob, hashlib, json, os, re, sys

LEDGER_DIRNAME = ".clues_ledger"
SCHEMA = 1
# 1-review checks one APK's Phase-1 records against its source; it is per-APK like 1.
PHASES = ["1", "1-review", "2", "3", "4", "5-local", "5-shared", "6"]
APK_RE = re.compile(r"([0-9a-fA-F]{64})")


def paths(repo: str) -> tuple[str, str, str, str]:
    d = os.path.join(repo, LEDGER_DIRNAME)
    return d, os.path.join(d, "ledger.jsonl"), os.path.join(d, "state.json"), os.path.join(d, "README.md")


def now() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


README_TMPL = """# CLUES processing ledger

This directory records which APKs in `{repo}` have been analysed by the
**apk-clues-extract** skill, and through which phases. It exists so that work can be
resumed from a **cold start** — a new session with no memory of previous runs.

## If you are an agent picking this up with no context, do this

```bash
SK={skill_dir}
REPO={repo}

# 1. What is done, and what is left?
python3 $SK/scripts/clues_ledger.py status --repo "$REPO"

# 2. Register any APKs added since the last run
python3 $SK/scripts/clues_ledger.py scan --repo "$REPO"

# 3. Take the next batch that still needs phase 1 (deterministic, oldest-first)
python3 $SK/scripts/clues_ledger.py next --repo "$REPO" --phase 1 --limit 20 > /tmp/batch.tsv

# 4. Phase 1 is offline Python (no LLM). Point it at just those APKs.
#    Then plan + dispatch the LLM phases, one sub-agent per work unit:
python3 $SK/scripts/plan_agent_work.py --target <CLUES data base path> --out /tmp/q.json
python3 $SK/scripts/run_unit_agents.py --queue /tmp/q.json --results-dir /tmp/results \\
        --apk-host local --apk-roots "$REPO" --max-parallel 12

# 5. Record what completed, so the next session knows
python3 $SK/scripts/clues_ledger.py record --repo "$REPO" --apk <sha256> --phase 2 --status ok
```

Read `$SK/SKILL.md` for the phase definitions and `$SK/config/agent_config.yaml` for
which model runs the sub-agents (and the refusal fallback).

## Files

| File | Role |
| --- | --- |
| `ledger.jsonl` | **Source of truth.** Append-only; one JSON event per line. Never rewrite it. |
| `state.json` | Derived rollup for fast reads. Safe to delete — rebuild with `rollup`. |
| `README.md` | This file. |

## Phase meanings

| Phase | What it does | LLM? |
| --- | --- | --- |
| `1` | `extract_clues.py` — decompile + harvest UUIDs | no |
| `2` | resolve the publishing company | yes |
| `3` | re-download URL evidence | yes (disabled by default — see config) |
| `4` | identify the SDK behind UUIDs shared by >=3 unrelated apps | yes, **batch-scoped** |
| `5-local` | name Unknown UUIDs whose only host is this APK | yes |
| `5-shared` | name Unknown UUIDs seen in several apps | yes, **not per-APK** |
| `6` | fold the run's lessons back into `extract_clues.py` | yes, **batch-scoped** |

Phases 4, 5-shared and 6 are recorded with `--scope batch` because their evidence spans
multiple APKs: a cluster is only visible once >=3 unrelated apps share a UUID, so they
cannot complete per-APK. Run them at a batch boundary.

Status values: `ok`, `pending`, `failed`, `refused`, `skipped`, `no_records`.
"""


def cmd_init(a) -> int:
    d, lj, st, rd = paths(a.repo)
    os.makedirs(d, exist_ok=True)
    if not os.path.exists(lj):
        open(lj, "a").close()
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(rd, "w") as fh:
        fh.write(README_TMPL.format(repo=os.path.abspath(a.repo), skill_dir=skill_dir))
    append(lj, {"ts": now(), "scope": "repo", "key": os.path.abspath(a.repo),
                "phase": "-", "status": "initialised", "schema": SCHEMA})
    print(f"[*] ledger ready: {d}")
    print(f"    README (read this first on a cold start): {rd}")
    return 0


def append(lj: str, obj: dict) -> None:
    with open(lj, "a") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")


def load_events(lj: str) -> list[dict]:
    out = []
    if not os.path.exists(lj):
        return out
    for line in open(lj, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def rollup(lj: str) -> dict:
    apks: dict[str, dict] = {}
    batches: list[dict] = []
    for e in load_events(lj):
        if e.get("scope") == "apk":
            k = (e.get("key") or "").upper()
            if not k:
                continue
            r = apks.setdefault(k, {"sha256": k, "phases": {}, "meta": {}})
            for mk in ("package_id", "version_code", "path"):
                if e.get(mk):
                    r["meta"][mk] = e[mk]
            ph = e.get("phase")
            if ph:
                r["phases"][ph] = {"status": e.get("status"), "ts": e.get("ts"),
                                   "detail": e.get("detail")}
        elif e.get("scope") == "batch":
            batches.append(e)
    return {"schema": SCHEMA, "generated": now(), "apks": apks, "batches": batches}


def cmd_scan(a) -> int:
    d, lj, st, _ = paths(a.repo)
    if not os.path.isdir(d):
        sys.exit(f"no ledger in {a.repo} — run `init` first")
    known = set(rollup(lj)["apks"])
    found = n = 0
    for p in glob.iglob(os.path.join(a.repo, "**", "*.apk"), recursive=True):
        found += 1
        m = APK_RE.search(os.path.basename(p))
        sha = m.group(1).upper() if m else None
        if not sha:
            # no hash in the filename: fall back to hashing the first 4 MiB
            h = hashlib.sha256()
            try:
                with open(p, "rb") as fh:
                    h.update(fh.read(4 << 20))
            except OSError:
                continue
            sha = ("NOHASH-" + h.hexdigest()[:56]).upper()
        if sha in known:
            continue
        pkg = os.path.basename(p).split("_")[0] if "_" in os.path.basename(p) else None
        append(lj, {"ts": now(), "scope": "apk", "key": sha, "phase": "1",
                    "status": "pending", "path": os.path.relpath(p, a.repo),
                    "package_id": pkg})
        known.add(sha)
        n += 1
    json.dump(rollup(lj), open(st, "w"), indent=1)
    print(f"[*] scanned {found:,} .apk files; registered {n:,} new; total tracked {len(known):,}")
    return 0


def cmd_record(a) -> int:
    d, lj, st, _ = paths(a.repo)
    if not os.path.isdir(d):
        sys.exit(f"no ledger in {a.repo} — run `init` first")
    ev = {"ts": now(), "scope": a.scope, "key": (a.apk or a.batch or "-"),
          "phase": a.phase, "status": a.status}
    if a.detail:
        try:
            ev["detail"] = json.loads(a.detail)
        except json.JSONDecodeError:
            ev["detail"] = a.detail
    for k in ("package_id", "version_code", "path"):
        v = getattr(a, k, None)
        if v:
            ev[k] = v
    append(lj, ev)
    print(f"[*] recorded {a.scope} {ev['key'][:20]} phase={a.phase} status={a.status}")
    return 0


def cmd_status(a) -> int:
    d, lj, st, rd = paths(a.repo)
    if not os.path.isdir(d):
        sys.exit(f"no ledger in {a.repo} — run `init` first")
    r = rollup(lj)
    json.dump(r, open(st, "w"), indent=1)
    apks = r["apks"]
    print(f"repo    : {os.path.abspath(a.repo)}")
    print(f"ledger  : {lj}")
    print(f"README  : {rd}   <- cold-start instructions")
    print(f"APKs tracked: {len(apks):,}\n")
    print(f"  {'phase':10} {'ok':>8} {'pending':>8} {'failed':>8} {'refused':>8} {'skipped':>8} {'untouched':>10}")
    for ph in PHASES:
        c = collections.Counter(
            (v["phases"].get(ph) or {}).get("status") or "untouched" for v in apks.values())
        print(f"  {ph:10} {c['ok']:>8,} {c['pending']:>8,} {c['failed']:>8,} "
              f"{c['refused']:>8,} {c['skipped']:>8,} {c['untouched']:>10,}")
    if r["batches"]:
        print("\n  batch-scoped events (phases 4 / 5-shared / 6):")
        for b in r["batches"][-6:]:
            print(f"    {b.get('ts','?')}  phase {b.get('phase')}  {b.get('status')}  {b.get('key')}")
    nxt = [k for k, v in apks.items() if (v["phases"].get("1") or {}).get("status") != "ok"]
    print(f"\n  next: {len(nxt):,} APK(s) still need phase 1")
    return 0


def cmd_next(a) -> int:
    d, lj, _, _ = paths(a.repo)
    if not os.path.isdir(d):
        sys.exit(f"no ledger in {a.repo} — run `init` first")
    apks = rollup(lj)["apks"]
    want = []
    for sha, v in apks.items():
        s = (v["phases"].get(a.phase) or {}).get("status")
        if s in (None, "pending", "failed"):
            if a.phase != "1" and (v["phases"].get("1") or {}).get("status") != "ok":
                continue          # cannot do an LLM phase before extraction
            want.append((sha, v))
    want.sort(key=lambda t: t[0])           # deterministic, so batches never overlap
    if a.limit:
        want = want[:a.limit]
    for sha, v in want:
        m = v["meta"]
        print(f"{sha}\t{m.get('package_id') or ''}\t{m.get('path') or ''}")
    print(f"# {len(want)} APK(s) needing phase {a.phase}", file=sys.stderr)
    return 0


def cmd_rollup(a) -> int:
    d, lj, st, _ = paths(a.repo)
    r = rollup(lj)
    json.dump(r, open(st, "w"), indent=1)
    print(f"[*] rebuilt {st} from {len(load_events(lj)):,} events "
          f"({len(r['apks']):,} APKs, {len(r['batches']):,} batch events)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("init", "scan", "status", "rollup"):
        p = sub.add_parser(name)
        p.add_argument("--repo", required=True)
    p = sub.add_parser("next")
    p.add_argument("--repo", required=True)
    p.add_argument("--phase", required=True, choices=PHASES)
    p.add_argument("--limit", type=int)
    p = sub.add_parser("record")
    p.add_argument("--repo", required=True)
    p.add_argument("--apk")
    p.add_argument("--batch")
    p.add_argument("--scope", default="apk", choices=["apk", "batch", "repo"])
    p.add_argument("--phase", required=True, choices=PHASES)
    p.add_argument("--status", required=True,
                   choices=["ok", "pending", "failed", "refused", "skipped", "no_records"])
    p.add_argument("--detail")
    p.add_argument("--package_id")
    p.add_argument("--version_code")
    p.add_argument("--path")
    a = ap.parse_args()
    return {"init": cmd_init, "scan": cmd_scan, "record": cmd_record,
            "status": cmd_status, "next": cmd_next, "rollup": cmd_rollup}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
