#!/usr/bin/env python3
"""Phase 1-review helper: apply the per-APK source-review results written by
run_unit_agents.py to the Phase-1 CLUES file they reviewed.

Usage:
    python3 apply_source_review.py REVIEWED_INPUT.json RESULTS_DIR [--out OUT.json]
        [--report REPORT.md] [--rejected REJECTED.json] [--proposals-prefix PREFIX]

REVIEWED_INPUT.json is the file the queue was planned from (plan_agent_work.py
--review-file), normally an extract_clues.py --session-output. It is never modified.
The script writes, next to OUT unless told otherwise:

  OUT.json                    the reviewed records (CLUES format), for merge_clues.py
  OUT.review_report.md        what changed and why, for the curator to read first
  OUT.review_rejected.json    records whose every reviewed host said not-GATT
  OUT.review_names.<who>.json UUID_name/company proposals, one file per reviewing model,
                              in apply_uuid_name_resolution.py's mapping format

Rules, per (APK build, UUID):
  * "Not Bluetooth" / "Other Bluetooth": that APK's android_info_array row and its
    Phase-1 evidence line are removed. A record with no host left goes to the rejected
    sidecar, not to OUT.
  * A GATT verdict counts only with role_basis direct_use or sdk_wrapper_flow. The
    record's UUID_usage_array becomes the union of the confirmed roles (plus the old
    roles when some host was not reviewed). Otherwise the extractor's role is kept and
    the evidence says it is unconfirmed.
  * parent_UUID is set only from a source-shown binding. Conflicting parents across
    APKs, a parent on a record that is no longer a characteristic, and an extractor
    parent that a full review did not confirm are all removed.
  * UUID_name and company are NOT applied here: they are proposals for the curator
    (CLUES keeps a human keep-or-drop step for both).
Each reviewed host gets one short evidence entry, credited to the model that reviewed it.
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import re
import sys

GATT_ROLES = {"GATT Service": ["GATT Service"],
              "GATT Characteristic": ["GATT Characteristic"],
              "GATT Service and Characteristic": ["GATT Service", "GATT Characteristic"]}
REJECT = {"Not Bluetooth", "Other Bluetooth"}
CONFIRMING = {"direct_use", "sdk_wrapper_flow"}
ROLE_ORDER = ["GATT Service", "GATT Characteristic"]
SIG_BASE = re.compile(r"^0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb$")
UUID128 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CITATION = re.compile(r"[\w$./-]+\.(?:java|kt|smali|cs)(?::[\d,\s-]*\d)?")
PLACEHOLDER_COMPANY = re.compile(r"^Unknown$|inferred from package id|Third-party SDK code|"
                                 r"Unidentified shared SDK", re.I)


def norm_uuid(u) -> str | None:
    """CLUES form: SIG-base UUIDs as 4 hex digits, all others as lowercase 128-bit."""
    if not isinstance(u, str):
        return None
    u = u.strip().lower()
    if u.startswith("0x"):
        u = u[2:]
    if re.fullmatch(r"[0-9a-f]{4}", u):
        return u
    m = SIG_BASE.match(u)
    if m:
        return m.group(1)
    return u if UUID128.match(u) else None


def plain_sentence(text: str, limit: int = 220) -> str:
    """The agent's evidence without its path:line citations, as one readable sentence."""
    t = CITATION.sub("", text or "")
    t = re.sub(r"\(\s*[;,\s]*\)", "", t)
    t = re.sub(r"\s*[;,]\s*(?=[;,.)]|$)", "", t)
    t = re.sub(r"\s{2,}", " ", t).strip(" ;,")
    t = re.sub(r"\s+([.,;:)])", r"\1", t)
    m = re.match(r"(.+?[.!?])(\s|$)", t)
    t = m.group(1) if m else t
    if len(t) > limit:
        t = t[:limit].rsplit(" ", 1)[0] + "…"
    return t


def role_phrase(roles: list[str]) -> str:
    return " and ".join(r if i == 0 else r.replace("GATT ", "") for i, r in enumerate(roles))


def load_results(results_dir: str) -> tuple[dict, list]:
    """{(package_path, uuid): decision}, plus every ok result (for the report)."""
    decisions, results = {}, []
    for f in sorted(glob.glob(os.path.join(results_dir, "*.json"))):
        try:
            r = json.load(open(f))
        except (OSError, ValueError):
            continue
        if r.get("_unit_type") != "review" or r.get("status") != "ok":
            continue
        results.append(r)
        for x in r.get("results") or []:
            k = norm_uuid(x.get("UUID"))
            if k:
                decisions[(r.get("_package_path"), k)] = dict(
                    x, _submitter=r.get("_submitter"), _package_id=r.get("_package_id"),
                    _version_name=r.get("_version_name"), _version_code=r.get("_version_code"))
    return decisions, results


def is_host_evidence(desc: str, pkg: str, ver, code) -> bool:
    """The Phase-1 line extract_clues.py wrote for this exact build."""
    if code is not None and ver is not None:
        return f" of {pkg} v{ver} (versionCode {code})" in (desc or "")
    return f" of {pkg} v" in (desc or "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="the Phase-1 CLUES file the review queue was planned from")
    ap.add_argument("results_dir")
    ap.add_argument("--out")
    ap.add_argument("--report")
    ap.add_argument("--rejected")
    ap.add_argument("--proposals-prefix")
    a = ap.parse_args()
    stem = os.path.splitext(a.out or a.input.replace(".json", ".reviewed.json"))[0]
    out = a.out or stem + ".json"
    report_p = a.report or stem + ".review_report.md"
    rejected_p = a.rejected or stem + ".review_rejected.json"
    prop_prefix = a.proposals_prefix or stem + ".review_names"
    if os.path.abspath(out) == os.path.abspath(a.input):
        sys.exit("refusing to overwrite the reviewed input; pass a different --out")

    records = json.load(open(a.input))
    decisions, results = load_results(a.results_dir)
    if not results:
        sys.exit(f"no ok review results in {a.results_dir}")

    kept, rejected = [], []
    rep = collections.defaultdict(list)
    proposals = collections.defaultdict(dict)
    n_hosts = collections.Counter()

    for rec in records:
        u = norm_uuid(rec.get("UUID")) or str(rec.get("UUID", "")).lower()
        old_roles = list(rec.get("UUID_usage_array") or [])
        old_parent = rec.get("parent_UUID")
        confirmed, parents, reviewed_notes = set(), set(), []
        unreviewed = False
        new_hosts, drop_evidence = [], []
        for ai in rec.get("android_info_array") or []:
            pkg, pp = ai.get("package_id"), ai.get("package_path")
            ver, code = ai.get("version_name"), ai.get("version_code")
            d = decisions.get((pp, u))
            if d is None:
                unreviewed = True
                n_hosts["unreviewed"] += 1
                new_hosts.append(ai)
                continue
            v, basis = d.get("verdict"), d.get("role_basis")
            who = d.get("_submitter") or "Claude"
            if v in REJECT:
                n_hosts["rejected"] += 1
                drop_evidence.append((pkg, ver, code))
                rep["host_rejected"].append((rec["UUID"], pkg, v, d.get("evidence", ""), who))
                continue
            new_hosts.append(ai)
            if v in GATT_ROLES and basis in CONFIRMING:
                n_hosts["confirmed"] += 1
                roles = GATT_ROLES[v]
                confirmed.update(roles)
                p = norm_uuid(d.get("parent_UUID"))
                if p and p != u and "GATT Characteristic" in roles:
                    parents.add(p)
                text = f"Source review of {pkg} v{ver}: used as a {role_phrase(roles)}"
                if p and p != u and "GATT Characteristic" in roles:
                    text += f" of service {p}"
                sent = plain_sentence(d.get("evidence", ""))
                reviewed_notes.append({"description": f"{text}. {sent}".strip(), "submitter": who})
            else:
                n_hosts["unconfirmed"] += 1
                why = ("only the identifier's name suggests a role" if basis == "naming_only"
                       else "no GATT use was found in the decompiled code")
                reviewed_notes.append({"description": f"Source review of {pkg} v{ver}: role not "
                                                      f"confirmed ({why}).", "submitter": who})
                rep["unconfirmed"].append((rec["UUID"], pkg, v, basis, d.get("evidence", ""), who))
            name, comp = d.get("UUID_name"), d.get("sdk_or_company")
            if name and (rec.get("UUID_name") in (None, "", "Unknown")) and v in GATT_ROLES:
                m = {"UUID_name": name, "note": f"Name from the source review of {pkg} v{ver}.",
                     "cache_in_sdk_table": False}
                if comp and PLACEHOLDER_COMPANY.search(rec.get("company") or "Unknown"):
                    m["company"] = comp
                proposals[who].setdefault(rec["UUID"], m)
            elif name and rec.get("UUID_name") not in (None, "", "Unknown") \
                    and name.lower().strip("_") != str(rec.get("UUID_name")).lower().strip("_"):
                rep["name_differs"].append((rec["UUID"], pkg, rec.get("UUID_name"), name, who))
            if comp and not PLACEHOLDER_COMPANY.search(rec.get("company") or "Unknown") \
                    and comp.lower().split()[0] not in (rec.get("company") or "").lower():
                rep["company_differs"].append((rec["UUID"], pkg, rec.get("company"), comp, who))

        if not new_hosts:
            rejected.append({"record": rec, "review": [x for x in rep["host_rejected"]
                                                       if x[0] == rec["UUID"]]})
            continue
        rec = json.loads(json.dumps(rec))           # never mutate the input objects
        rec["android_info_array"] = new_hosts
        rec["evidence_array"] = [e for e in rec.get("evidence_array") or []
                                 if not any(is_host_evidence(e.get("description"), *h)
                                            for h in drop_evidence)]
        rec["evidence_array"] += reviewed_notes

        roles = old_roles
        if confirmed:
            keep = set(old_roles) if unreviewed else set()
            roles = [r for r in ROLE_ORDER if r in confirmed | keep]
            if roles != old_roles:
                rep["role_changed"].append((rec["UUID"], old_roles, roles))
                rec["UUID_usage_array"] = roles
                purpose = rec.get("UUID_purpose") or ""
                rec["UUID_purpose"] = re.sub(r"^(Custom )?GATT (Service|Characteristic)( and Characteristic)?",
                                             lambda m: (m.group(1) or "") + role_phrase(roles),
                                             purpose, count=1)
        if "GATT Characteristic" not in roles:
            new_parent = None
        elif len(parents) == 1:
            new_parent = next(iter(parents))
        elif len(parents) > 1:
            new_parent = None
            rep["parent_conflict"].append((rec["UUID"], sorted(parents)))
        elif old_parent and confirmed and not unreviewed:
            new_parent = None                     # the full review did not bind it
        else:
            new_parent = old_parent
        if norm_uuid(old_parent) != new_parent:
            rep["parent_changed"].append((rec["UUID"], old_parent, new_parent))
        if new_parent:
            rec["parent_UUID"] = new_parent
        else:
            rec.pop("parent_UUID", None)
        kept.append(rec)

    for r in results:
        for x in r.get("missed") or []:
            rep["missed"].append((x.get("UUID"), r.get("_package_id"), x.get("verdict"),
                                  x.get("evidence", ""), r.get("_submitter")))

    with open(out, "w") as fh:
        json.dump(kept, fh, indent=1, ensure_ascii=False)
    with open(rejected_p, "w") as fh:
        json.dump(rejected, fh, indent=1, ensure_ascii=False)
    prop_files = []
    for who, m in proposals.items():
        p = f"{prop_prefix}.{re.sub(r'[^A-Za-z0-9.]+', '_', who).strip('_')}.json"
        json.dump(m, open(p, "w"), indent=1, ensure_ascii=False)
        prop_files.append((who, p, len(m)))

    cost = sum(r.get("_cost_usd") or 0 for r in results)
    models = collections.Counter(r.get("_submitter") for r in results)
    L = [f"# Source review of `{os.path.basename(a.input)}`", "",
         f"- {len(results)} review result(s) by {', '.join(f'{k} ×{v}' for k, v in models.items())}"
         f", ${cost:.2f} in all",
         f"- {len(records)} input records → {len(kept)} kept in `{os.path.basename(out)}`, "
         f"{len(rejected)} rejected to `{os.path.basename(rejected_p)}`",
         f"- hosts: {n_hosts['confirmed']} confirmed, {n_hosts['unconfirmed']} unconfirmed, "
         f"{n_hosts['rejected']} rejected, {n_hosts['unreviewed']} not reviewed",
         f"- roles changed: {len(rep['role_changed'])}; parents changed: "
         f"{len(rep['parent_changed'])} ({len(rep['parent_conflict'])} conflicts)", ""]
    for who, p, n in prop_files:
        L.append(f"- {n} name proposal(s) by {who}: `{os.path.basename(p)}`. To keep them, run "
                 f"`APK_CLUES_SUBMITTER=\"{who}\" python3 apply_uuid_name_resolution.py "
                 f"{os.path.basename(out)} {os.path.basename(p)}`")
    sections = [
        ("Rejected (not GATT in that APK)", "host_rejected", ["UUID", "APK", "verdict", "why", "by"]),
        ("Role changes", "role_changed", ["UUID", "was", "now"]),
        ("Parent changes", "parent_changed", ["UUID", "was", "now"]),
        ("Parent conflicts (parent omitted)", "parent_conflict", ["UUID", "parents seen"]),
        ("Role not confirmed (extractor role kept)", "unconfirmed",
         ["UUID", "APK", "verdict", "basis", "why", "by"]),
        ("Source name differs from the record's name (not changed)", "name_differs",
         ["UUID", "APK", "record", "source", "by"]),
        ("Company differs from the record's company (not changed)", "company_differs",
         ["UUID", "APK", "record", "review", "by"]),
        ("GATT UUIDs the extractor missed (not added)", "missed",
         ["UUID", "APK", "verdict", "evidence", "by"])]
    for title, key, cols in sections:
        rows = rep.get(key) or []
        L += ["", f"## {title} ({len(rows)})", ""]
        if not rows:
            L.append("None.")
            continue
        L += ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
        for row in rows:
            L.append("| " + " | ".join(str(c if not isinstance(c, list) else ", ".join(c) or "—")
                                       .replace("|", "\\|").replace("\n", " ") for c in row) + " |")
    open(report_p, "w").write("\n".join(L) + "\n")

    print(f"[*] {len(kept)} kept -> {out}")
    print(f"[*] {len(rejected)} rejected -> {rejected_p}")
    print(f"[*] report -> {report_p}")
    for who, p, n in prop_files:
        print(f"[*] {n} name proposals ({who}) -> {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
