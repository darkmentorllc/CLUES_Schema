#!/usr/bin/env python3
"""Resolve the CLUES `submitter` label: the model whose work an evidence entry records.

Claude Code does not tell child processes which model is running, so the label is
passed in through the environment. The first match wins:

  1. APK_CLUES_SUBMITTER / CLUES_SUBMITTER: a ready-made label, used verbatim, e.g.
     "Claude (Opus 5.5)". run_unit_agents.py sets it for every sub-agent it starts.
  2. APK_CLUES_MODEL: a model id such as claude-opus-5-5, turned into a label by
     model_label(). SKILL.md has the orchestrating agent set it to its own model id.
  3. FALLBACK_SUBMITTER, the model this skill is normally run with.

extract_clues.py's --submitter flag overrides all three for that one process.
"""
from __future__ import annotations

import os
import re

FALLBACK_SUBMITTER = "Claude (Opus 5.5)"

_EXPLICIT_SUBMITTER_ENV_VARS = ("APK_CLUES_SUBMITTER", "CLUES_SUBMITTER")
_MODEL_ENV_VAR = "APK_CLUES_MODEL"

_CLAUDE_FAMILIES = ("opus", "sonnet", "haiku", "fable")

# GPT labels carry the reasoning effort, the way the Codex copy of this skill writes them.
_EFFORT_LABELS = {
    "xhigh": "Extra High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "minimal": "Minimal",
}


def model_label(model: str, effort: str | None = None) -> str:
    """Turn a model id into the label the CLUES data uses.

    claude-opus-5-5 -> "Claude (Opus 5.5)", claude-haiku-4-5-20251001 -> "Claude (Haiku 4.5)",
    a bare alias such as opus -> "Claude (Opus)", gpt-5.5 with effort xhigh ->
    "GPT 5.5 (Extra High)". Any other id is returned unchanged.
    """
    raw = " ".join((model or "").split())
    m = re.sub(r"\[[^\]]*\]$", "", raw.lower())   # context-window suffix, e.g. [1m]
    m = re.sub(r"-\d{8}$", "", m)                  # dated snapshot ids
    parts = m.split("-")
    if parts[0] == "claude":
        family = [p for p in parts[1:] if p in _CLAUDE_FAMILIES]
        version = [p for p in parts[1:] if p.isdigit()]
        if len(family) == 1 and len(family) + len(version) == len(parts) - 1:
            return f"Claude ({' '.join([family[0].capitalize()] + ['.'.join(version)] * bool(version))})"
        return raw
    if m in _CLAUDE_FAMILIES:
        return f"Claude ({m.capitalize()})"
    if parts[0] == "gpt" and len(parts) > 1:
        label = "GPT " + " ".join(p.capitalize() for p in parts[1:])
        e = (effort or "").strip().lower()
        return f"{label} ({_EFFORT_LABELS.get(e, e)})" if e else label
    return raw


def resolve() -> tuple[str, str]:
    """(label, where it came from): an environment variable's name, or "fallback"."""
    for name in _EXPLICIT_SUBMITTER_ENV_VARS:
        value = " ".join(os.environ.get(name, "").split())
        if value:
            return value, name
    model = os.environ.get(_MODEL_ENV_VAR, "").strip()
    if model:
        return model_label(model), _MODEL_ENV_VAR
    return FALLBACK_SUBMITTER, "fallback"


DEFAULT_SUBMITTER, SUBMITTER_SOURCE = resolve()
