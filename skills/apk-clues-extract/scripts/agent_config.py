#!/usr/bin/env python3
"""Loader for config/agent_config.yaml — the sub-agent roster used by phases 2-6.

Keeps model choice, refusal handling and backend selection OUT of the prose in
SKILL.md, so the skill can be repointed at a different model (or at Codex / GPT /
a local model) by editing one file.

CLI:
    agent_config.py                 # show the resolved configuration
    agent_config.py --check-refusal FILE
    agent_config.py --agent-for apk [--refused-before]
"""
from __future__ import annotations
import argparse, json, os, re, sys

try:
    import yaml
except ImportError:
    sys.exit("agent_config.py needs PyYAML (pip install pyyaml)")

DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "agent_config.yaml"
)


class AgentConfig:
    def __init__(self, path: str = DEFAULT_PATH):
        self.path = path
        with open(path) as fh:
            self.raw = yaml.safe_load(fh)
        self._validate()
        self._refusal_res = [re.compile(p) for p in self.raw["refusal"].get("patterns", [])]

    def _validate(self) -> None:
        for key in ("backends", "agents", "refusal", "units", "phases"):
            if key not in self.raw:
                raise ValueError(f"{self.path}: missing top-level key {key!r}")
        for role in ("primary", "fallback"):
            if role not in self.raw["agents"]:
                raise ValueError(f"{self.path}: agents.{role} is required")
        for role, spec in self.raw["agents"].items():
            b = spec.get("backend")
            if b not in self.raw["backends"]:
                raise ValueError(f"{self.path}: agents.{role}.backend={b!r} is not in backends")
        for ut, spec in self.raw["units"].items():
            for key in ("agent", "fallback_agent"):
                role = (spec or {}).get(key)
                if role is not None and role not in self.raw["agents"]:
                    raise ValueError(f"{self.path}: units.{ut}.{key}={role!r} is not in agents")

    # ---------- agents ----------
    def agent(self, role: str = "primary") -> dict:
        a = dict(self.raw["agents"][role])
        a["role"] = role
        a["backend_spec"] = dict(self.raw["backends"][a["backend"]])
        spec = a["backend_spec"]
        # Sub-agents are `claude -p` subprocesses, so a FULL model id and a
        # per-unit --effort are both honoured. (The in-process Agent tool would
        # only accept a model family and has no effort knob — which is why this
        # skill dispatches subprocesses instead.)
        a["kind"] = spec.get("kind", "subprocess")
        a["exact_model_selectable"] = True
        a["command_template"] = spec.get("command", [])
        a["error_markers"] = spec.get("error_markers", [])
        return a

    def roles_for_unit(self, unit_type: str) -> tuple[str, str]:
        """(primary, fallback) agent roles for a unit type. A unit may name its own
        (units.review does); otherwise the global agents.primary/fallback apply."""
        u = self.raw["units"].get(unit_type) or {}
        return u.get("agent", "primary"), u.get("fallback_agent", "fallback")

    def agent_for_unit(self, unit_type: str, refused_before: bool = False) -> dict:
        sticky = bool(self.raw["refusal"].get("sticky", True))
        primary, fallback = self.roles_for_unit(unit_type)
        a = self.agent(fallback if (refused_before and sticky) else primary)
        a["unit_type"] = unit_type
        u = self.raw["units"].get(unit_type, {})
        a["phases"] = u.get("phases", [])
        a["max_parallel"] = u.get("max_parallel", 1)
        return a

    def fallback_for_unit(self, unit_type: str) -> dict:
        return self.agent(self.roles_for_unit(unit_type)[1])

    # ---------- refusal ----------
    @property
    def marker(self) -> str:
        return self.raw["refusal"].get("marker", "REFUSED")

    def is_refusal(self, text: str) -> tuple[bool, str | None]:
        if not text:
            return False, None
        for rx in self._refusal_res:
            m = rx.search(text)
            if m:
                return True, m.group(0)
        return False, None

    # ---------- phases ----------
    def phase_enabled(self, phase: str) -> bool:
        return bool((self.raw["phases"].get(str(phase)) or {}).get("enabled", False))

    def phase_reason(self, phase: str) -> str | None:
        return (self.raw["phases"].get(str(phase)) or {}).get("reason")

    def enabled_phases(self) -> list[str]:
        return [p for p in self.raw["phases"] if self.phase_enabled(p)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=DEFAULT_PATH)
    ap.add_argument("--check-refusal", metavar="FILE")
    ap.add_argument("--agent-for", metavar="UNIT_TYPE")
    ap.add_argument("--refused-before", action="store_true")
    a = ap.parse_args()
    cfg = AgentConfig(a.config)

    if a.check_refusal:
        txt = open(a.check_refusal, encoding="utf-8", errors="replace").read()
        refused, hit = cfg.is_refusal(txt)
        print(json.dumps({"refused": refused, "matched": hit,
                          "marker": cfg.marker if refused else None}, ensure_ascii=False))
        return 1 if refused else 0

    if a.agent_for:
        print(json.dumps(cfg.agent_for_unit(a.agent_for, a.refused_before),
                         indent=2, ensure_ascii=False))
        return 0

    print(f"config          : {cfg.path}")
    for role in cfg.raw["agents"]:
        ag = cfg.agent(role)
        print(f"  {role:8}: {ag['name']:14} backend={ag['backend']:14} "
              f"model={ag.get('model'):20} effort={ag.get('effort')} max_turns={ag.get('max_turns')}")
        print(f"            cmd: {' '.join(ag['command_template'])}")
    print(f"refusal marker  : {cfg.marker}")
    print(f"  patterns      : {len(cfg._refusal_res)}   sticky={cfg.raw['refusal'].get('sticky')}")
    print("units           :")
    for u, spec in cfg.raw["units"].items():
        own = (f" agent={spec['agent']} fallback={spec.get('fallback_agent', 'fallback')}"
               if spec.get("agent") else "")
        print(f"  {u:9}: phases={spec.get('phases')} max_parallel={spec.get('max_parallel')}{own}")
    print("phases          :")
    for p in sorted(cfg.raw["phases"]):
        on = cfg.phase_enabled(p)
        extra = "" if on else f"  ({(cfg.phase_reason(p) or '').strip().splitlines()[0][:60]}…)"
        print(f"  phase {p}: {'ENABLED ' if on else 'disabled'}{extra}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
