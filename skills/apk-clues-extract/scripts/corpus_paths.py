"""Portable paths for APKs stored in an AndroZoo corpus."""

from __future__ import annotations

import os
from pathlib import Path

_MARKER = "/AndroZoo/"
_PREFIX = "AndroZoo/"
_CORPUS_SUBDIRS = ("apks/", "apks_jadx/")


def compact_package_path(path: str) -> str:
    """Keep the corpus-relative identity instead of a machine's mount path."""
    if not path or not os.path.isabs(path):
        return path
    index = path.find(_MARKER)
    if index < 0:
        return path
    suffix = path[index + len(_MARKER):]
    return _PREFIX + suffix if suffix.startswith(_CORPUS_SUBDIRS) else path


def resolve_package_path(path: str) -> str:
    """Resolve a stored AndroZoo path for a later --search-unknown pass."""
    if not path.startswith(_PREFIX):
        return path
    suffix = path[len(_PREFIX):]
    if not suffix.startswith(_CORPUS_SUBDIRS) or ".." in Path(suffix).parts:
        return path
    roots = [
        os.environ.get("ANDROZOO_ROOT", ""),
        "/media/user/8TB_APKs/AndroZoo",
        "/home/user/AndroZoo",
        os.path.join(os.getcwd(), "AndroZoo"),
        os.path.join(os.path.dirname(os.getcwd()), "AndroZoo"),
    ]
    candidates = [os.path.abspath(os.path.join(root, suffix)) for root in roots if root]
    return next((candidate for candidate in candidates if os.path.isfile(candidate)),
                candidates[0] if candidates else path)
