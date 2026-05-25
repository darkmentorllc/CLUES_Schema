# CLUES data files

Every file here is a JSON array of records conforming to [`../CLUES_schema.json`](../CLUES_schema.json) (the **Custom Lightweight UUID Exchange Schema**). Records describe vendor-specific Bluetooth Low Energy GATT UUIDs that aren't covered by the [Bluetooth SIG's public assigned numbers](https://www.bluetooth.com/specifications/assigned-numbers/).

## Files

| File | Source | Trust |
| --- | --- | --- |
| `CLUES_data_human_verified.json` | Hand-curated by a human reviewer | **Highest** |
| `CLUES_data_LLM_Android_APK_search_{0..f}.json` | [`apk-clues-extract`](../skills/apk-clues-extract/) skill | Medium (auto-extracted; merged from many APKs) |
| `CLUES_data_LLM_web_search.json` | [`web-clues-search`](../skills/web-clues-search/) skill | Medium (auto-extracted; URL-cited) |

### `CLUES_data_human_verified.json`

The canonical hand-curated dataset. Entries here have been vetted by a human; downstream consumers should treat this file as the authoritative source when a UUID appears in multiple files. **Renamed from the legacy `CLUES_data.json`** when the data files moved under `data/`.

Tooling that auto-generates records (the two LLM skills) is required to *skip* UUIDs already present in this file so it can never be regressed by an automated overwrite.

### `CLUES_data_LLM_Android_APK_search_{0..f}.json`

Output of the [`apk-clues-extract`](../skills/apk-clues-extract/) skill, which decompiles Android APKs with `jadx` and pulls vendor-specific UUIDs out of the Java source — `UUID.fromString("…")`, `ParcelUuid.fromString("…")`, log strings, anonymous-object constructors, lowered Kotlin enums, etc.

**Split layout.** Records are sharded across 16 files by the first hex character of `UUID` (UUIDs starting with `0` live in `_0.json`, UUIDs starting with `a` live in `_a.json`, etc.). This keeps every shard under ~25 MB so they remain reviewable in git diffs and load quickly in editors. The split is purely a storage layout — the **global sort is across all 16 files combined** (see [`scripts/SortCLUES.py`](../scripts/SortCLUES.py)). To work with the full dataset, use the loader:

```python
import sys
sys.path.insert(0, "scripts")
from clues_io import load_clues
records = load_clues("data/CLUES_data_LLM_Android_APK_search.json")  # path uses the unsplit base name
```

`load_clues` returns a single flat list whether the file is sharded or not. `save_clues(records, path)` preserves whatever layout it finds on disk; only `SortCLUES.py` decides which files are sharded (via its `SPLIT_FILES` allowlist).

### `CLUES_data_LLM_web_search.json`

Output of the [`web-clues-search`](../skills/web-clues-search/) skill, which researches unidentified BLE/BTC UUID128 values from Blue2thprinting scan data using web search, GitHub Code Search, and ASCII/OUI/vendor-base-pattern analysis. Every record carries at least one URL in its `evidence_array` so a curator can verify the attribution.

## Transient files (not consumed, not committed)

- `*.bak_*` — timestamped backups made during in-place edits by the LLM skills. Safe to delete after verifying the run.
- `CLUES_data_LLM_Android_APK_search.json.processed.json` — sidecar checkpoint used by `extract_clues.py` to skip APKs it has already scanned (keyed by APK SHA-1). Not a CLUES record file.

## Tooling

From the repo root (with the `venv` activated):

```bash
# Re-sort all CLUES files in canonical order + re-shard the Android file.
python3 scripts/SortCLUES.py

# Validate every file against the schema.
check-jsonschema --base-uri ./CLUES_schema.json \
    --schemafile ./CLUES_schema.json \
    data/CLUES_data_*.json
```

The validate glob picks up both the 16 Android shards and the single-file CLUES outputs.
