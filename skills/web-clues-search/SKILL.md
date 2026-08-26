---
name: web-clues-search
description: Research previously-unidentified BLE/BTC UUID128 values from Blue2thprinting scan data via web search, GitHub Code Search (Chrome MCP), and ASCII/OUI/vendor-base-pattern analysis. Filters input UUIDs against existing CLUES files, runs parallel research, and appends new attributions to data/CLUES_data_LLM_web_search.json (validated against CLUES_schema.json).
---

# web-clues-search

Research UUID128 values that appear in real-world Blue2thprinting scans but are **not** attributed in any existing CLUES JSON file, then append findings to `data/CLUES_data_LLM_web_search.json`.

## When to invoke

The user provides one of:
1. A path to a list of unknown UUID128s (sorted by occurrence count, typically `count\tuuid` per line).
2. A directive to "search for the next batch" — re-derive the unknown set from `Tell_Me_Everything.py` output or equivalent.
3. The `--search-missing [N]` flag — fully automated end-to-end run; optional `N` selects how many of the highest-count unknowns to research (default 100). See the "`--search-missing` mode" section below.

This skill should NOT be invoked for SIG-base-aliased UUIDs (`0000XXXX-0000-1000-8000-00805F9B34FB`) — those are the responsibility of the stats/lookup code, not CLUES. Strip them from the input before running.

## `--search-missing` mode

When invoked with `--search-missing [N]` (or equivalent phrasings like "search the next 400 missing", "auto-find missing UUIDs"), the skill **auto-derives** its input rather than asking the user for a list. `N` defaults to 100 if omitted. Argument parsing:

- `--search-missing` → N = 100 (default)
- `--search-missing 400` → N = 400 (space-separated, canonical form)
- `--search-missing=400` → N = 400 (also accepted)
- `N` must be a positive integer. Reject 0, negatives, and non-numeric values with a clear error.
- For `N > 500`, print a one-line warning before starting — GitHub throttling makes batches above a few hundred take many hours, and the user may have meant a smaller number.

1. From the CLUES_Schema working directory, run:
   ```bash
   python3 ../Tell_Me_Everything.py --UUID128-stats > /tmp/u128_stats.txt
   ```
   (`Tell_Me_Everything.py` lives one level up at `Analysis/Tell_Me_Everything.py`; the CLUES JSON files live in `Analysis/CLUES_Schema/data/`, with `CLUES_Schema/` being the cwd. `CLUES_schema.json` and the helper scripts in `scripts/` stay at the repo root / `scripts/`.)

2. Parse the output. Each data row is tab-separated `count \t uuid_nodashes \t known_info` (with surrounding spaces around the tabs). The output has two sections — `----= BLUETOOTH CLASSIC RESULTS =----` and `----= BLUETOOTH LOW ENERGY RESULTS =----`. Process **both** and de-duplicate UUIDs across them (keep the higher count if the same UUID appears in both).

3. A UUID is **unattributed** iff the third column is empty (whitespace only). Anything starting with `Custom UUID128:` or `SIG-Base alias of` is already attributed and must be skipped.

4. Convert each 32-char hex UUID to dashed lowercase 8-4-4-4-12 form before filtering:
   ```python
   def to_dashed(h: str) -> str:
       h = h.lower()
       return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
   ```

5. Drop these noise UUIDs before any further work:
   - `00000000-0000-0000-0000-000000000000` (Nil)
   - `11223344-5566-7788-99aa-bbccddeeff00` (canonical placeholder)
   - Any UUID matching the SIG base pattern `0000xxxx-0000-1000-8000-00805f9b34fb`

6. Pass the remaining list through the standard `is_attributed()` filter from the "Input filtering" section below — defensive, because `Tell_Me_Everything.py`'s "Custom UUID128" annotation may load a different subset of CLUES files than this skill's filter requires.

7. Additionally exclude any UUID present in the **negative-result cache** (`web_search_unresolved.json` — see "Negative-result cache" section below). This prevents wasting effort re-searching UUIDs that were already investigated and produced no attribution.

8. Sort by descending count (already the case from the stats output, but re-sort after dedup across sections) and take the **first N** (default 100).

9. **Full-pass fallback**: if the unresolved-and-unsearched set produces fewer than N candidates, the "full pass over all unknowns" is effectively complete — top up to N by pulling from `web_search_unresolved.json` ordered by **oldest** `last_searched_iso` first (UUIDs without a date sort first). Mark the top-up entries in the report so the user can see we're now in re-search mode.

10. Write the final top-N list to `/tmp/u128_unknowns_topN.txt` (literal filename — don't substitute the number, this keeps it predictable for piping/inspection across runs). Format: one `count\tdashed_uuid` per line, with a `# top-up` comment line preceding any re-searched UUIDs. Then proceed with Phase 1 (parallel web research) and onward as usual.

## Negative-result cache

Path: `/Users/user/.claude/skills/web-clues-search/web_search_unresolved.json` (lives in the skill folder, **not** in `CLUES_Schema/` — it's research bookkeeping, not CLUES data).

Schema: JSON array of objects, one per UUID. If the file does not exist, treat as `[]`.

```json
[
  {
    "uuid": "6999f4e0-ee72-4d34-a4e5-611ba4e421cb",
    "last_searched_iso": "2026-05-15T14:30:00Z",
    "phases_run": ["web", "github"],
    "notes": "1 GitHub hit in an ESP32-RandomNerd tutorial; no vendor attribution."
  }
]
```

Field meanings:
- `uuid`: lowercase dashed 8-4-4-4-12.
- `last_searched_iso`: UTC ISO-8601 timestamp of the most recent attempt.
- `phases_run`: which research phases were tried — subset of `["web", "github", "chrome_blackbird", "chrome_navigate"]`.
- `notes`: short free-form description of what was seen (e.g., "0 GitHub hits", "1 hit but stale 2018 issue tracker, no firmware context", "blocked by throttling"). Helps a future pass decide whether the prior negative is trustworthy.

**Read behavior**: every invocation (manual list, "next batch", or `--search-missing`) must load this file and exclude listed UUIDs from research, except when `--search-missing` falls back to the full-pass-complete top-up state (see step 9 above), or when the user explicitly asks to re-research a specific UUID.

**Write behavior** (called from Phase 4 — see below):
- After research finishes, every UUID in the current batch that did **not** produce an acceptable attribution gets a new or updated entry in this file.
- If the UUID was already present, replace the existing entry (don't accumulate duplicates) — overwrite `last_searched_iso`, union `phases_run`, and replace `notes` (keep the most recent — old notes rot).
- If the UUID **did** produce an attribution and was added to `data/CLUES_data_LLM_web_search.json`, also **remove** it from `web_search_unresolved.json` if present (handles the "previously inconclusive, now resolved" case from the full-pass-complete top-up flow).

Atomic write: write to `web_search_unresolved.json.tmp` then `os.replace` — the file can get hundreds of entries and a half-written JSON would be unrecoverable.

## Input filtering (always first)

Before running any web search, deduplicate against the known sources:

1. `data/CLUES_data_human_verified.json` — the curated base file (552+ entries as of writing)
2. `data/CLUES_data_LLM_Android_APK_search.json` — vendor attributions mined from Android APKs
3. `data/CLUES_data_LLM_web_search.json` — prior web/GitHub findings (the file this skill writes to)

Then additionally filter against the **negative-result cache** (`web_search_unresolved.json` in the skill folder) — see the "Negative-result cache" section above for full semantics.

Include regex pattern matching: any entry with `regex: true` and `x` wildcards in `UUID` should be expanded to a Python regex (replace `x` with `[0-9a-f]`) and used to filter.

```python
import json, re

def is_attributed(uuid, files):
    u = uuid.lower()
    for fname in files:
        with open(fname) as f:
            data = json.load(f)
        for entry in data:
            pat = entry["UUID"].lower()
            if "x" not in pat:
                if pat == u:
                    return True
            else:
                rgx = pat.replace("x", "[0-9a-f]")
                if re.fullmatch(rgx, u):
                    return True
    return False
```

Don't add `00000000-0000-0000-0000-000000000000` (RFC 4122 Nil UUID) or `11223344-5566-7788-99aa-bbccddeeff00` (canonical placeholder) to research queues — note them in working notes but treat as known-noise.

## Strategy decisions before researching

Categorize remaining UUIDs by version nibble (third-group first char) **and** variant nibble (fourth-group first char):

| Version | Expected attribution yield | Action |
|---|---|---|
| **v1** (real OUI in node) | High (10–30%) | Top priority. Decode node MAC, look up IEEE OUI. |
| **v1** (Sun `0800200c9a66`, Docker `0242ac120002`, locally-administered) | Low | Useful only if other signals exist. |
| **v4** (random) | Medium (~5%) | Only resolvable via external publication. |
| **v5** (SHA-1 hash) | ~0% | Cryptographically irreversible. Skip in cost-constrained passes. |
| **v6/v8** (newer time-ordered) | Low | Treat like v4. |
| **Non-RFC-conformant** | Variable | Often the most interesting — vendor-customized base UUIDs. |

Always check for these structural signals **before** any network call (free wins):

- **ASCII bytes**: hex-decode the 16 bytes and look for printable substrings. Notable matches found in practice include `"WITH"` (Withings), `"BedJet"`, `"SDSHOMEIOT"`, `"LEICACAMERA"`, `"PELTORTIFService"`, `"EBTRON GTX"`, `"excelpoint.com"`, `"www.tempi.fi"`, `"LVS"` (Lovense), `"net.tpky."` (Tapkey), `"Willow"` (Yeelight), `"KinsaHealti"` (reversed Kinsa).
- **Byte-reversal**: decode the byte-reversed form for ASCII too — some firmware mis-encodes endianness.
- **Embedded OUI**: trailing 3 bytes of the UUID often match a real IEEE OUI (use `maclookup.app`). Examples: 00:24:E4 = Withings, 00:17:7A = ASSA ABLOY, 00:16:B7 = Seoul Commtech.
- **Vendor base UUID families** — search for the trailing suffix only, not the full UUID:
  - `-b5a3-f393-e0a9-e50e24dcca9e` = Nordic UART Service (NUS)
  - `-d102-11e1-9b23-00025b00a5aX` = CSR/Qualcomm GAIA
  - `-0002a5d5c51X` = BlueST SDK / CSR / Wurth / GoPro (multi-vendor, ambiguous)
  - `-f315-4f60-9fb8-838830daea5X` = Nordic Secure DFU
  - `-244c-11e2-b299-00a0c60077ad` = Qualcomm Labs
  - `-1212-efde-1523-785feabcd123` = Nordic LED-Button Service (LBS)
- **Hex vanity prefixes**: `c0ffee` (TopBrewer), `cafe`, `feed`, `dead`, `beef`, `1337`, `decaf`, `abcd`, `fade`. Often the rest of the UUID is meaningful.
- **`xxxx0001` patterns**: numbered service families; sibling characteristics usually share base.

Use `scripts/UUID_Search_Permutations.py` to generate alternate forms (no-dashes, byte-reversed, C-array literal) when web searching — vendor SDKs/decompiled apps may store UUIDs in any of these forms.

## Research workflow

### Phase 1 — Parallel web research (cheap, high yield for common UUIDs)

Dispatch parallel subagents using the `Agent` tool with `subagent_type: "Explore"` or generic. Each agent gets 40 UUIDs and is instructed to:

1. Use `WebSearch` for each UUID (dashed lowercase form first, then no-dashes if no hits)
2. For each UUID, also search `site:github.com "UUID"` via WebSearch (Google's index hits public GitHub)
3. Decode ASCII fragments and look them up
4. Decode UUIDv1 timestamp and OUI; cross-reference IEEE
5. Return per-UUID: COMPANY, NAME, PURPOSE, EVIDENCE_URL, EVIDENCE_DESC

Run 10–20 agents in parallel for batches of 40 UUIDs each. Set a clear "Unknown" template so the agent doesn't hallucinate attributions.

**Reject low-confidence attributions** — the agent must cite a URL with the UUID actually visible in the page. "Probably X based on naming convention" without external evidence is not enough.

### Phase 2 — Authenticated GitHub Code Search (for remaining unknowns)

For UUIDs that web search couldn't resolve, use Chrome MCP (`mcp__Claude_in_Chrome__*`). This requires the user's Chrome browser to be open and logged into GitHub.

**Connect**:
```
mcp__Claude_in_Chrome__list_connected_browsers
mcp__Claude_in_Chrome__select_browser <deviceId>
mcp__Claude_in_Chrome__tabs_context_mcp createIfEmpty=true
```

**Triage via `blackbird_count` endpoint** (returns JSON count, very fast but heavily throttled):

```javascript
fetch(`https://github.com/search/blackbird_count?q=%22${UUID}%22&type=code`,
      {credentials: 'include', headers: {'Accept': 'application/json'}})
  .then(r => r.json())  // {failed, count, mode}
```

Sustained rate observed: ~1 request per 3.5–4 seconds with single-threaded sequential calls. Bursts of 2+ parallel reliably trigger sustained throttling that takes 5–30 min to clear. Chunk size limit: ~10 UUIDs per `javascript_tool` call (CDP timeout is 45s).

If `blackbird_count` is throttled, fall back to **navigate-based search** (slower but uses a different limit pool):

```javascript
// After navigate to https://github.com/search?q=%22UUID%22&type=code, wait 3-4s for SPA to render
const items = document.querySelectorAll('[class*="codeResultWrapper"]');
// items.length = real result count; items[i].innerText has repo/path/snippet
const countMatch = document.body.innerText.match(/Code\s*\n([^\n]+)/);
// countMatch[1] is the displayed count, e.g. "0", "21", "2k", "1.5M"
```

Batch 6–8 navigates per `browser_batch` call. The displayed count format includes abbreviations like "2k" / "1.5M" — don't use a `\d+` regex.

**Be cautious about cached/stale results**: under heavy throttle, the search page sometimes shows "Search failed" with `0` count or returns stale prior-navigation state. Only record a hit when `codeResultWrapper` selectors yield non-empty entries with repo paths.

### Phase 3 — Confirm + classify each hit

For each UUID with hits, examine the top 3 results. Strong attribution requires either:
- A vendor's own repo/SDK explicitly defining the UUID as a service/characteristic
- A third-party reverse-engineering project where the vendor is clearly named (e.g., "OpenWorkoutTracker BluetoothServices.h lists this as CUSTOM_BT_SERVICE_KTV_LIGHT // Lezyne KTV Light")
- A decompiled APK path that includes the vendor's package (e.g., `jp/co/sony/reonpocket/...`)

Weak signals — do NOT add:
- Single-hit issue tracker mentions without firmware context
- Generic BLE example code (look for hobbyist patterns like Bleno tutorials, ESP32 RandomNerd UUIDs)
- Blocked-content placeholder results

### Phase 4 — Append to data/CLUES_data_LLM_web_search.json **and update the negative-result cache**

For every UUID in the batch, exactly one of two things must happen at the end of Phase 4:

- **Attributed** → append a new entry to `data/CLUES_data_LLM_web_search.json` (schema below), AND if the UUID was previously listed in `web_search_unresolved.json` (from an earlier full-pass-complete top-up), **remove** it from that file.
- **Not attributed** → upsert an entry into `/Users/user/.claude/skills/web-clues-search/web_search_unresolved.json` per the "Negative-result cache" section: set/replace `last_searched_iso` to now (UTC ISO-8601), union `phases_run`, and record a fresh one-line `notes` field about why it was inconclusive (e.g., "0 GitHub hits", "1 stale 2018 tutorial reference, no firmware context", "Chrome blackbird throttled — retry later").

The "Chrome throttled" case is a legitimate negative-cache entry only if the navigate-based fallback also produced no usable result. If both Chrome paths were throttled and no real search ran, do NOT cache — leave the UUID for the next pass.

Each new entry in `data/CLUES_data_LLM_web_search.json` must conform to `CLUES_schema.json`. Required fields:
- `UUID` (string, full 8-4-4-4-12 format, lowercase; or with lowercase `x` wildcards if regex)
- `company` (string) — **bare company name only.** Do NOT pack in country, product line, app name, what BLE is used for, acquisition history, or any other context. Bad: `"Canon Inc. (Japan) — Camera Connect app; BLE for EOS / PowerShot cameras"`. Good: `"Canon Inc."`. Bad: `"Anki (now Digital Dream Labs)"`. Good: `"Anki"` (historically-attributed name; rebrand notes go into evidence). The lone exceptions are: (a) the `(formerly OldName)` rebrand suffix that SIG-style entries also use, and (b) acronyms that are part of the formal name like `(IBV)`. Descriptive context belongs in `UUID_purpose` (if it's about how the UUID is used) or in an extra `evidence_array` entry (if it's about the company). Apply scripts in the sibling `apk-clues-extract` skill enforce this via `company_sanitizer`; the web-search skill writes records directly, so the responsibility is on the author here.
- `UUID_name` (string)
- `UUID_purpose` (string, prose)
- `UUID_usage_array` (array of strings, valid enum: `"GATT Service"`, `"GATT Characteristic"`, `"iBeacon"`, `"Eddystone"`, `"SDP Service"`, `"Advertisement"`)
- `evidence_array` (array of objects with `URL`, `description`, `submitter`)
- `regex` (boolean, optional — `true` for family-pattern entries)

When multiple UUIDs share a vendor base (e.g., 3+ from the Casio G-Shock `26eb00xx-...` family), add a **regex family entry** in addition to the individual entries. The regex entry uses **lowercase `x`** characters as wildcards.

**Wildcards must be lowercase `x`, not uppercase `X`** — even though `CLUES_schema.json`'s own prose says `X`. The consumer, `Analysis/TME/TME_helpers.py`, builds the pattern with `UUID_regex.replace('-','').replace('x','[0-9a-fA-F]')` and never lowercases first, so an uppercase-`X` entry compiles to a literal `X` that can never match a hex UUID: the entry loads and validates fine, and is silently dead. Every pre-existing regex entry in the data files uses lowercase. Before committing a family entry, verify it with that exact `replace` chain plus `re.match` against the no-dash UUID, and check it does not over-match. (Exact-match lookups are tried *before* the regex loop, so a family entry never masks a more specific entry.)

After every append, validate:

```python
import json, jsonschema
with open("CLUES_schema.json") as f: schema = json.load(f)
with open("data/CLUES_data_LLM_web_search.json") as f: data = json.load(f)
jsonschema.validate(instance=data, schema=schema)
```

Set `submitter` to `"Claude (Opus 4.7)"` (or whichever model is running).

### Phase 5 — Canonicalize sort order (always last)

After Phase 4 completes (validation passed, negative-result cache updated), run the in-repo sort script to re-sort all three CLUES data files in place:

```bash
python3 scripts/SortCLUES.py
```

The script (`scripts/SortCLUES.py`) iterates over `data/CLUES_data_human_verified.json`, `data/CLUES_data_LLM_Android_APK_search.json`, and `data/CLUES_data_LLM_web_search.json` and sorts each by company name (ascending), groups child UUIDs under their `parent_UUID`, and merges trivially-duplicate entries. It rewrites the files with `indent=4, ensure_ascii=False`.

Run it **once at the end** of the session, not after every individual append — sorting hundreds of times during a batch is wasteful, and the diff at the end is what reviewers actually look at. If the run is aborted mid-batch (e.g., GitHub throttling, user interrupt), still run `SortCLUES.py` before exiting so the partially-updated file is committable. After running, re-validate against the schema (Phase 4's `jsonschema.validate` call) — sorting shouldn't break the schema, but a defensive check catches accidental key drops from the merge logic.

## Output

- Updated `data/CLUES_data_LLM_web_search.json` (in `Analysis/CLUES_Schema/data/` — NOT in the skill directory). Re-sorted by `scripts/SortCLUES.py` per Phase 5; also touches `data/CLUES_data_human_verified.json` and `data/CLUES_data_LLM_Android_APK_search.json` if their sort orders need adjustment.
- Updated `web_search_unresolved.json` (in the skill directory at `/Users/user/.claude/skills/web-clues-search/`) — every batch UUID that didn't yield an attribution is upserted here.
- A brief report listing: total UUIDs triaged, new attributions added, count of negative-cache upserts, breakdown by vendor signal type (ASCII / OUI / GitHub / web), and (if `--search-missing` entered the full-pass-complete top-up state) how many re-searched UUIDs were attempted.

## Failure modes & guardrails

- **Don't add unverified attributions.** "Probably Apple because of naming" without an Apple-published reference is unacceptable. Mark as Unknown.
- **Don't trust stale page state.** During Chrome MCP work, navigations can leave the prior page's DOM partially visible. Always re-query selectors after `await new Promise(r => setTimeout(r, ≥3000))`.
- **Don't over-claim about UUIDv5.** The version nibble being `5` is a *guess* about the generator (it could just be a random nibble in a UUIDv4-but-without-version-set scheme). Even with the right version+variant bits, you cannot recover the namespace+name from the hash.
- **Respect GitHub rate limits.** Sustained throttling means waiting 30+ minutes; back off rather than hammering. Schedule a wakeup if needed.
- **Never delete `data/CLUES_data_LLM_web_search.json` entries** without explicit user approval, even if they look wrong — correct them in place (update fields, add evidence).
- **Don't run this skill on SIG-base-aliased UUIDs** (`0000XXXX-0000-1000-8000-00805F9B34FB`). Those should be resolved by SIG yaml lookup in `Tell_Me_Everything.py`, not added to CLUES.
