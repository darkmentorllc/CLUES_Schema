"""Shared CLUES JSON load/save helpers with hex-bucket splitting.

A CLUES data file can live on disk in either of two equivalent forms:

1. **Single combined file** — `CLUES_data_foo.json` with all records.
2. **Hex-bucketed split** — 16 files `CLUES_data_foo_0.json` ... `CLUES_data_foo_f.json`
   where each record lives in the bucket matching its UUID's first hex
   character.

Whether a given file is single or split is a deliberate per-file choice
made by `SortCLUES.py` (the only script that decides layout). Every other
script (`extract_clues.py`, the Phase 2-6 helpers) just calls
`save_clues(data, path)` and the layout is preserved from whatever was on
disk before — the writer never decides to split or un-split on its own.

To opt a file into the split layout, pass `split=True` to `save_clues`
once (typically from SortCLUES). To opt it out, pass `split=False`. After
that, the default `split=None` keeps the same layout indefinitely.
"""

import json
import os

HEX_DIGITS = "0123456789abcdef"


def _split_paths(path: str) -> list[tuple[str, str]]:
    base, ext = os.path.splitext(path)
    return [(h, f"{base}_{h}{ext}") for h in HEX_DIGITS]


def is_split_form(path: str) -> bool:
    """True if `path` currently lives on disk as 16 hex-bucket shards
    (with no combined single file). Used by `save_clues(split=None)` to
    preserve the existing layout."""
    if os.path.isfile(path):
        return False
    return any(os.path.isfile(sp) for _, sp in _split_paths(path))


def load_clues(path: str) -> list[dict]:
    """Load CLUES records from `path` (single file) or its hex-bucketed
    split siblings `<base>_0<ext>` ... `<base>_f<ext>`.

    Returns a flat list. Returns `[]` if neither form exists (mirrors the
    previous behavior when a brand-new output path was used).
    Records preserve their on-disk order within each bucket; buckets are
    concatenated in hex order (0..f)."""
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
        except (OSError, json.JSONDecodeError):
            return []
        return []
    data: list[dict] = []
    for _, split_path in _split_paths(path):
        if not os.path.isfile(split_path):
            continue
        try:
            with open(split_path, "r", encoding="utf-8") as f:
                chunk = json.load(f)
            if isinstance(chunk, list):
                data.extend(chunk)
        except (OSError, json.JSONDecodeError):
            continue
    return data


def clues_exists(path: str) -> bool:
    if os.path.isfile(path):
        return True
    return any(os.path.isfile(sp) for _, sp in _split_paths(path))


def save_clues(data: list[dict], path: str, split: bool | None = None) -> None:
    """Write CLUES records.

    `split` controls layout:
      * `None` (default): preserve the on-disk layout — split if and only
        if the file currently exists as 16 hex shards (use this from any
        script that just wants to write what it loaded).
      * `True`: always write 16 hex-bucketed files by `UUID[0]` and delete
        the single combined file if it exists.
      * `False`: always write a single combined file and delete any
        leftover hex shards.

    Records with a non-hex first UUID character bucket to '0'. Writes are
    atomic: each output file is written to `.tmp` first and renamed."""
    if split is None:
        split = is_split_form(path)
    if not split:
        text = json.dumps(data, indent=4, ensure_ascii=False) + "\n"
        _atomic_write_text(path, text)
        for _, split_path in _split_paths(path):
            if os.path.isfile(split_path):
                os.remove(split_path)
        return
    buckets: dict[str, list[dict]] = {h: [] for h in HEX_DIGITS}
    for entry in data:
        uuid = (entry.get("UUID") or "").lower()
        first = uuid[:1]
        if first in buckets:
            buckets[first].append(entry)
        else:
            buckets["0"].append(entry)
    for h, split_path in _split_paths(path):
        bucket_text = json.dumps(buckets[h], indent=4, ensure_ascii=False) + "\n"
        _atomic_write_text(split_path, bucket_text)
    if os.path.isfile(path):
        os.remove(path)


def _atomic_write_text(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)
