#!/usr/bin/env python3
"""Build the sub-agent work queue for phases 2-6.

Why this exists: the canonical corpus is ~150 MB across 16 shards. If each
sub-agent loaded it to find its own work, every agent would burn its context on
data it does not need. This script loads it ONCE, slices it into self-contained
work units, and writes a queue. A sub-agent then receives only its own brief.

Unit granularity is a correctness constraint, not a preference:
  apk      all APK-scoped work for one APK (phase 2 company, phase 3 URL, and any
           still-Unknown UUID whose ONLY host is that APK)  -> one sub-agent
  cluster  phase 4: a UUID family shared by >=3 UNRELATED apps. The evidence is
           inherently cross-APK, so a per-APK agent cannot do it.
  uuid     a still-Unknown UUID seen in several apps (likewise not per-APK)
  review   phase 1-review: one APK's Phase-1 records, checked against that APK's
           decompiled source. Planned on its own with --review-file, because it can
           drop or re-role records and so must finish before phases 2-5 see them.
Phase 6 is aggregate and stays in the orchestrator.

Semantics are delegated to the existing list_*.py scripts so the queue always
matches what the apply_*.py scripts expect.

Usage:
    plan_agent_work.py --target data/CLUES_data_LLM_Android_APK_search.json \
                       [--session-file session.json] [--scope-packages FILE] \
                       [--out work_queue.json] [--limit N]
    plan_agent_work.py --review-file session.json [--scope-packages FILE] \
                       [--out review_queue.json] [--limit N]
"""
from __future__ import annotations
import argparse, json, os, re, subprocess, sys, collections

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from agent_config import AgentConfig          # noqa: E402


def run_lister(script: str, *args: str) -> dict:
    p = subprocess.run([sys.executable, os.path.join(HERE, script), *args],
                       capture_output=True, text=True)
    if p.returncode != 0 or not p.stdout.strip():
        sys.stderr.write(f"[!] {script} failed rc={p.returncode}: {p.stderr[:300]}\n")
        return {}
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"[!] {script} produced non-JSON: {e}\n")
        return {}


MAX_HOSTS_IN_BRIEF = 8          # a cluster brief needs a few hosts to decompile, not 300
MAX_UNKNOWNS_PER_UNIT = 25      # com.ubnt.usurvey alone had 874 -> a 441 KB brief
MAX_FIELD_NAMES_IN_BRIEF = 40


def _trim_hosts(hosts: list) -> tuple[list, int]:
    """Keep the SMALLEST few hosts (cheapest to decompile) plus the true total.

    Without this, a widely-shared UUID drags several hundred host records into the
    sub-agent brief (~85 KB observed) — reintroducing the attention dilution that
    per-unit sub-agents exist to prevent.
    """
    total = len(hosts)
    if total <= MAX_HOSTS_IN_BRIEF:
        return hosts, total

    def sz(h):
        if isinstance(h, dict):
            for k in ("apk_size", "size", "local_size"):
                if isinstance(h.get(k), int):
                    return h[k]
            lp = h.get("local_path")
            if lp:
                try:
                    return os.path.getsize(lp)
                except OSError:
                    pass
        return 1 << 62
    return sorted(hosts, key=sz)[:MAX_HOSTS_IN_BRIEF], total


def hosts_of(entry: dict) -> list[str]:
    out = []
    for h in entry.get("host_packages") or []:
        out.append(h.get("package_id") if isinstance(h, dict) else h)
    return [h for h in out if h]


def _host_evidence(rec: dict, pkg: str) -> str:
    """The Phase-1 evidence line written for this host, which names the Java field
    and the classification source the extractor used."""
    descs = [e.get("description") or "" for e in rec.get("evidence_array") or []]
    for d in descs:
        if f" of {pkg} v" in d:
            return d
    return descs[0] if descs else ""


def review_units(path: str, scope: set | None, max_candidates: int) -> list[dict]:
    """One review unit per APK build (package_path) in a Phase-1 CLUES file.

    Each candidate is the extractor's own proposal (role, name, company, parent) for
    that APK, which the agent re-derives from source. A record with several hosts is
    reviewed once per host, because a UUID's role and parent are only established
    within one APK's code.
    """
    recs = json.load(open(path))
    by_apk: dict[str, dict] = {}
    for rec in recs:
        for ai in rec.get("android_info_array") or []:
            pp, pid = ai.get("package_path"), ai.get("package_id")
            if not pp or not pid or (scope is not None and pid not in scope):
                continue
            u = by_apk.setdefault(pp, {"package_id": pid, "package_path": pp,
                                       "version_name": ai.get("version_name"),
                                       "version_code": ai.get("version_code"),
                                       "candidates": [], "_seen": set()})
            if rec["UUID"] in u["_seen"]:
                continue
            u["_seen"].add(rec["UUID"])
            c = {"UUID": rec["UUID"],
                 "extractor_role": rec.get("UUID_usage_array"),
                 "extractor_name": rec.get("UUID_name"),
                 "extractor_company": rec.get("company")}
            if rec.get("parent_UUID"):
                c["extractor_parent_UUID"] = rec["parent_UUID"]
            c["extractor_note"] = _host_evidence(rec, pid)
            u["candidates"].append(c)
    units = []
    for pp, u in sorted(by_apk.items(), key=lambda kv: (kv[1]["package_id"], kv[0])):
        u.pop("_seen")
        m = re.search(r"([0-9A-Fa-f]{64})", os.path.basename(pp))
        tag = f"{u['package_id']}@{m.group(1)[:8].upper()}" if m else u["package_id"]
        cands = u.pop("candidates")
        chunks = [cands[i:i + max_candidates] for i in range(0, len(cands), max_candidates)]
        for ci, chunk in enumerate(chunks):
            uid = f"review:{tag}" if len(chunks) == 1 else f"review:{tag}#{ci + 1}of{len(chunks)}"
            units.append({"unit_id": uid, "unit_type": "review", "phases": ["1-review"],
                          **u, "candidates": chunk,
                          **({"chunk": [ci + 1, len(chunks)]} if len(chunks) > 1 else {})})
    return units


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="data/CLUES_data_LLM_Android_APK_search.json")
    ap.add_argument("--session-file")
    ap.add_argument("--scope-packages", help="file with one package_id per line; restrict apk units")
    ap.add_argument("--out", default="work_queue.json")
    ap.add_argument("--limit", type=int, help="cap units per type (smoke tests)")
    ap.add_argument("--review-file",
                    help="Phase-1 CLUES JSON (usually --session-output) to plan phase "
                         "1-review units for; plans ONLY those units")
    ap.add_argument("--config")
    a = ap.parse_args()

    cfg = AgentConfig(a.config) if a.config else AgentConfig()
    scope = None
    if a.scope_packages:
        scope = {l.strip() for l in open(a.scope_packages) if l.strip()}

    if a.review_file:
        if not cfg.phase_enabled("1-review"):
            sys.exit("phase 1-review is disabled in the agent config")
        spec = cfg.raw["units"].get("review") or {}
        units = review_units(a.review_file, scope, int(spec.get("max_candidates_per_unit", 50)))
        if a.limit:
            units = units[:a.limit]
        roles = cfg.roles_for_unit("review")
        queue = {"review_file": a.review_file, "config": cfg.path,
                 "agents": {r: {k: v for k, v in cfg.agent(r).items() if k != "backend_spec"}
                            for r in roles},
                 "refusal_marker": cfg.marker, "enabled_phases": ["1-review"],
                 "counts": {"review": len(units)}, "units": units}
        with open(a.out, "w") as fh:
            json.dump(queue, fh, indent=1, ensure_ascii=False)
        n = sum(len(u["candidates"]) for u in units)
        print(f"\n=== review queue -> {a.out} ===")
        print(f"  units          : {len(units):,} ({n:,} candidate records, "
              f"max_parallel={spec.get('max_parallel')})")
        print(f"  agent          : {cfg.agent(roles[0])['name']}   fallback: "
              f"{cfg.agent(roles[1])['name']}")
        return 0

    print("[*] running listers (semantics reused, not reimplemented)", file=sys.stderr)
    p2 = run_lister("list_inferred_companies.py", a.target)
    p3 = run_lister("list_apk_versions.py", a.target) if cfg.phase_enabled("3") else {}
    p4 = run_lister("list_shared_sdk_clusters.py", a.target) if cfg.phase_enabled("4") else {}
    p5args = [a.target] + (["--session-file", a.session_file] if a.session_file else [])
    p5 = run_lister("list_unknown_uuid_names.py", *p5args) if cfg.phase_enabled("5") else {}

    # --- bucket APK-scoped work by package ---
    apk_tasks: dict[str, dict] = collections.defaultdict(
        lambda: {"company": None, "urls": [], "local_unknowns": []})
    if cfg.phase_enabled("2"):
        for e in p2.get("needs_enrichment", []):
            pid = e.get("package_id")
            if pid and (scope is None or pid in scope):
                apk_tasks[pid]["company"] = e
    for e in p3.get("needs_url", []):
        pid = e.get("package_id")
        if pid and (scope is None or pid in scope):
            apk_tasks[pid]["urls"].append(e)

    uuid_units = []
    for e in p5.get("needs_naming", []):
        hs = hosts_of(e)
        if len(set(hs)) == 1:
            pid = hs[0]
            if scope is None or pid in scope:
                apk_tasks[pid]["local_unknowns"].append(e)
        else:
            uuid_units.append(e)

    units = []
    for pid, t in sorted(apk_tasks.items()):
        if not (t["company"] or t["urls"] or t["local_unknowns"]):
            continue
        # Split a package with many Unknown UUIDs across several units. One APK with
        # 874 unknowns produced a 441 KB brief, which defeats the point of per-unit
        # agents. Splitting (rather than truncating) means no work is dropped; the
        # phase-2/3 tasks ride on the first chunk only so they are not duplicated.
        unknowns = t["local_unknowns"] or []
        chunks = [unknowns[i:i + MAX_UNKNOWNS_PER_UNIT]
                  for i in range(0, len(unknowns), MAX_UNKNOWNS_PER_UNIT)] or [[]]
        for ci, chunk in enumerate(chunks):
            first = ci == 0
            comp = t["company"] if first else None
            urls = t["urls"] if first else []
            if not (comp or urls or chunk):
                continue
            uid = f"apk:{pid}" if len(chunks) == 1 else f"apk:{pid}#{ci + 1}of{len(chunks)}"
            units.append({
                "unit_id": uid, "unit_type": "apk", "package_id": pid,
                "phases": [p for p, ok in (("2", bool(comp)),
                                           ("3", bool(urls)),
                                           ("5-local", bool(chunk))) if ok],
                "company_task": comp, "url_tasks": urls,
                "unknown_uuid_tasks": chunk,
                **({"chunk": [ci + 1, len(chunks)]} if len(chunks) > 1 else {}),
            })
    for i, c in enumerate(p4.get("clusters", [])):
        units.append({
            "unit_id": f"cluster:c{i}", "unit_type": "cluster", "phases": ["4"],
            "cluster_index": i, "uuids": c.get("uuids", []),
            **(lambda hs: {"host_packages": hs[0], "host_packages_total": hs[1]})(
                _trim_hosts(c.get("host_packages", []))),
            "uuid_field_names": dict(list((c.get("uuid_field_names") or {}).items())[:MAX_FIELD_NAMES_IN_BRIEF]),
            "suggested_action": c.get("suggested_action"),
        })
    for e in uuid_units:
        units.append({
            "unit_id": f"uuid:{e.get('UUID')}", "unit_type": "uuid", "phases": ["5-shared"],
            "UUID": e.get("UUID"), "company": e.get("company"),
            **(lambda hs: {"host_packages": hs[0], "host_packages_total": hs[1]})(
                _trim_hosts(e.get("host_packages", []))),
            "UUID_usage_array": e.get("UUID_usage_array"),
            "parent_UUID": e.get("parent_UUID"),
        })

    if a.limit:
        keep, seen = [], collections.Counter()
        for u in units:
            if seen[u["unit_type"]] < a.limit:
                keep.append(u); seen[u["unit_type"]] += 1
        units = keep

    by_type = collections.Counter(u["unit_type"] for u in units)
    queue = {
        "target": a.target,
        "config": cfg.path,
        "agents": {r: {k: v for k, v in cfg.agent(r).items() if k != "backend_spec"}
                   for r in ("primary", "fallback")},
        "refusal_marker": cfg.marker,
        "enabled_phases": cfg.enabled_phases(),
        "counts": dict(by_type),
        "units": units,
    }
    with open(a.out, "w") as fh:
        json.dump(queue, fh, indent=1, ensure_ascii=False)

    print(f"\n=== work queue -> {a.out} ===")
    print(f"  enabled phases : {', '.join(cfg.enabled_phases())}")
    for p in ("2", "3", "4", "5", "6"):
        if not cfg.phase_enabled(p):
            r = (cfg.phase_reason(p) or "").strip().splitlines()
            print(f"  phase {p} SKIPPED: {r[0][:70] if r else 'disabled in config'}")
    print(f"  units          : {len(units):,}")
    for t in ("apk", "cluster", "uuid"):
        mp = (cfg.raw['units'].get(t) or {}).get('max_parallel')
        print(f"    {t:8}: {by_type.get(t,0):6,}   (max_parallel={mp})")
    print(f"  primary agent  : {cfg.agent('primary')['name']}   fallback: {cfg.agent('fallback')['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
