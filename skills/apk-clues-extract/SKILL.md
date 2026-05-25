---
name: apk-clues-extract
description: "Extract vendor-specific GATT Service and Characteristic UUIDs from Android APK / XAPK files and emit a CLUES-formatted JSON (`CLUES_data_LLM_Android.json`) that conforms to `CLUES_schema.json`. Use when the user asks to 'scan APKs for UUIDs', 'extract Bluetooth UUIDs from Android apps', 'build CLUES data from APKs', or 'find GATT services in a folder of APKs'. Takes a path to either an individual APK/XAPK or a directory which it walks recursively. Pre-flights each APK with `aapt dump permissions` and skips any package that does not declare BLUETOOTH / BLUETOOTH_ADMIN / BLUETOOTH_SCAN / BLUETOOTH_CONNECT — never wastes time decompiling a non-BT app. Uses `jadx --no-res --no-debug-info` to decompile DEX, deletes the temp output after each file. Do NOT use for iOS apps, for non-(X)APK files (e.g. raw .dex outside an APK), or when the goal is to add UUIDs already known from public sources rather than discover them from an APK."
version: 1.0
---

# APK CLUES UUID Extractor

## What this skill does

Given a path to a single Android `.apk` / `.xapk` file or a directory of them, this skill discovers every Bluetooth Low Energy GATT-related UUID referenced by the app's decompiled code, classifies each as **GATT Service** or **GATT Characteristic** from local code context, and emits an array of CLUES-format records to `CLUES_Schema/data/CLUES_data_LLM_Android_APK_search.json` (sibling of the hand-curated `CLUES_Schema/data/CLUES_data_human_verified.json`, both conforming to `CLUES_Schema/CLUES_schema.json`).

For each APK it:

1. **Verifies the package requests Bluetooth.** Runs `aapt dump permissions` and looks for `android.permission.BLUETOOTH`, `BLUETOOTH_ADMIN`, `BLUETOOTH_SCAN`, or `BLUETOOTH_CONNECT`. If none are present, the APK is logged as "no BT permissions; skipped" and the skill moves to the next file *without* running jadx — decompiling a non-BT app is wasted time.
2. **Extracts `package_id`, `version_code`, `version_name`** from `aapt dump badging`. These populate the `android_info_array` for every UUID found in the app.
3. **Decompiles to a temp dir.** `jadx --no-res --no-debug-info -d <tmpdir> <apk_or_xapk>` (jadx 1.5+ understands `.xapk` natively, so XAPKs do not need to be unzipped first). The `--no-res` flag skips XML resource decoding — UUIDs live in the code, not in the AndroidManifest.
4. **Scans decompiled `.java` files for UUID patterns** — regex finds the candidate sites, the script then *reads* the code around each hit rather than relying on the regex alone (per GreyNoise's "regex will not dynamically emulate DEX bytecode" warning):
   - Raw 128-bit UUID string literals (`"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`) — picks up `UUID.fromString("...")`, `ParcelUuid.fromString("...")`, log strings, JADX deobfuscation hints, etc.
   - For every literal, the script also captures the **LHS Java identifier** of the assignment (`public static final UUID LIBRE3_DATA_SERVICE = UUID.fromString(...)`) — this becomes the `UUID_name` after light cleanup (strip trailing `_UUID` / `Uuid`, drop Java `m`/`s` member prefixes). Minified jadx leftovers (`f7217p`, single-letter aliases) are rejected — those records get `UUID_name: "Unknown"` and a later APK that has the same UUID with a human-meaningful field name will overwrite it.
   - When JADX has moved the semantic label away from the literal, the scanner also recovers names from **lowered enum rows** (`WIFI_CONTROL = new TwinService("WIFI_CONTROL", …, "uuid")`), **nested sealed-object constructors** that pass a UUID temp into `super(...)`, **anonymous singleton-object fields** (`BulkTransfer = new e0() { … UUID.fromString("uuid") … }`), **constructor parameter roles** preserved in another class (`new BluetoothServiceConfiguration(uuid1, uuid2, uuid3, …)` → `notifyCharacteristicUUID` from the callee signature), and **assigned wrapper constructors** where the target field is the best surviving label (`writeCharacteristic = new BleCharacteristic(serviceId, id)`).
   - Then the script performs a **read-the-code usage trace**: for every `(field, uuid)` pair, it searches the whole file for `getService(field)` / `getCharacteristic(field)` / `setCharacteristicNotification(...)` / etc. A hit here is **authoritative** — those calls are how the Android API itself decides what a UUID is, so they beat any naming-convention heuristic.
5. **Decides at the file level whether a `.java` file is BLE-relevant.** Two ways a file qualifies (either is enough):
   - **Hard signal:** the file references one of `android.bluetooth.BluetoothGatt*` / `android.bluetooth.le.ScanFilter` / `android.os.ParcelUuid` anywhere.
   - **Constants-class fallback:** the file contains **≥3 `UUID.fromString("128-bit-literal")` calls** with no BLE imports. This catches "pure constants" classes like Abbott Libre3's `DCSGKSConstants.java` (15 UUIDs, zero `BluetoothGatt*` refs — the BLE-aware code lives in *other* classes that import this one) or Harman's `e2/d.java`. A non-BLE config class with a couple of analytics/telemetry UUIDs in URLs (Adobe Edge, Azure App Insights, OneTrust) won't trigger the fallback because those UUIDs sit inside string concatenations, not `UUID.fromString` calls. A file that hits neither signal is treated as "probably not BLE" — UUIDs in it only survive if a `BluetoothGatt*` identifier sits within ±8 lines of the literal.
6. **Filters Bluetooth-SIG standard UUIDs and already-published member UUIDs and curated CLUES UUIDs.** Any UUID matching the SIG base `0000XXXX-0000-1000-8000-00805F9B34FB` is collapsed to its 16-bit form. Then:
   - UUID16s in the SIG-allocated **standard** ranges (0x0000 / 0x0001–0x012F SDP protocols / 0x1000–0x12FF SDP service classes / 0x1800–0x18FF GATT services / 0x2800–0x29FF declarations & descriptors / 0x2A00–0x2BFF characteristics) are dropped — they are not vendor-specific.
   - UUID16s **already listed in `~/Blue2thprinting/Analysis/public/assigned_numbers/uuids/member_uuids.yaml`** (the SIG's public vendor-allocated UUID16 list) are also dropped from the output — they're already public, so there's no value re-recording them in CLUES_data_LLM. The hits *are* surfaced internally for the company-inference step below.
   - **UUIDs already in `~/Blue2thprinting/Analysis/CLUES_Schema/data/CLUES_data_human_verified.json`** (the hand-curated, human-verified canonical CLUES file — renamed from `CLUES_data.json` when data files moved under `CLUES_Schema/data/`) are dropped from the LLM output. Those entries are the project's highest-trust source; re-emitting an auto-extracted version risks a curator accepting a regression on merge. Configurable via `--curated-clues PATH` (pass an empty string to disable the skip-list). The startup log reports how many curated UUIDs were loaded.
   - UUID16s outside all three filters (typically vendor-internal IDs like `0xE104` or `0x8A21`) and all UUID128s not in curated CLUES are kept.
7. **Classifies each remaining UUID as Service vs Characteristic.** Cascading decision:
   - **Definitive usage trace (read-the-code):** if the captured field name is passed to `getService(...)` anywhere in the file → Service. Passed to `getCharacteristic(...)` / `writeCharacteristic(...)` / `setCharacteristicNotification(...)` / similar → Characteristic. This is the same authoritative sink set BLEScope uses for its value-set analysis.
   - **Anchor line:** if no definitive usage trace, look at the UUID's own source line for naming-convention hints (`_SERVICE` / `_CHAR_` / `BluetoothGattService` / `BluetoothGattCharacteristic`).
   - **Window fallback:** if the anchor line doesn't disambiguate, look at the surrounding ±8 lines.
   - **File-level last resort:** if everything is silent (minified field names, e.g. `f15558a`), classify based on whether the file overall mentions `BluetoothGattService`, `BluetoothGattCharacteristic`, or both. Files using only `BluetoothGattCharacteristic` default to Characteristic; otherwise default to Service.

8. **Infers the `company` field per APK.** Cascading resolution, in order of preference (always preferring SIG-official member names when they're a plausible match):
   - **`KNOWN_SDK_UUIDS` table hit (highest priority).** If the UUID is in the curated Phase-4 cache of third-party-SDK UUIDs, the table's entry wins — beats every other inference. This is how the skill auto-attributes well-known shared SDKs (Kubi/Zoom, Nordic UART, TI OAD, Microchip ISSC, HM-10, Ojmar/OCS-Smart) without per-host-app guessing.
   - **Single-APK third-party-SDK detection.** Each UUID literal is annotated with the Java `package …;` declaration of the `.java` file it was found in. If that declaring-package's tokens have **zero overlap** with the host APK's `package_id`, the UUID is flagged as `"Third-party SDK code (declared in Java package <pkg> — distinct from host <host>; Phase-4 identification needed)"`. This catches SDK leakage on a **single-APK basis** without waiting for ≥3 host apps to share the UUID (which is the Phase-4 cluster threshold). Example caught on the May 2026 corpus: `5301` (declared in `com.stidmobileid.developmentkit`) and `00009800-…-00177a000000` (declared in `com.assaabloy.mobilekeys.api.ble`) were flagged on the very first Sesame Smart Spaces scan, even though only one host APK was processed.
   - **`member_uuids.yaml` with token-overlap gate.** If the APK exposes a UUID16 that's listed in `member_uuids.yaml`, *and* that member name shares at least one ≥3-letter token with the package_id, the SIG-official member name wins. So `com.abbott.lingo.wellness` + UUID16 `0xFDE3` → "Abbott Diabetes Care" (token `abbott` matches). The overlap gate is essential: many apps reference UUIDs from shared SDKs (Amazon, Bose, Sony, Qualcomm, Taobao, …) and we **must not** mis-tag a fitness app as "Taobao" just because it links a Taobao-published UUID16. No overlap → fall through to the package heuristic.
   - **Package-name heuristic.** Hard-coded `KNOWN_VENDOR_PACKAGES` map covers ~50 common vendors (Abbott, Dexcom, Harman, Garmin, Withings, Nordic, etc.); fallback is the first non-TLD-like component capitalized (`com.proctur.app222423` → "Proctur (inferred from package id)"; `branded.com.publicansmanhasset` → "Publicansmanhasset (inferred from package id)"). TLD-like and whitelabel tokens (`com`, `co`, `branded`, `app`, `android`, …) are skipped.
   - **Last resort:** `"Unknown"` only when all sources are silent.

9. **Merges across APKs with semantic upgrades.** When the same UUID is seen in multiple APKs, the record's `UUID_name` is replaced whenever a new APK has a higher-scoring identifier (e.g., `LED_COLOR_UUID` beats `f7217p` beats `Unknown`). Same goes for `company` — a non-`Unknown` value replaces an `Unknown`. Each new APK appends a row to `android_info_array` and an entry to `evidence_array`, so the full provenance is preserved.

   **Evidence deduplication (`dedupe_evidence_array`).** Two evidence entries are treated as duplicates and collapsed into a single survivor when *any* of these holds:
   - They share the same `URL` (case-insensitive, after strip) — one URL evidence per Phase-3 mapping, no matter how many sibling records merged in.
   - Both descriptions begin with `Found in decompiled DEX of <pkg> v<ver> (versionCode <code>)` with identical `(package_id, version_name, version_code)`. This is the user-reported pattern where a single APK has the same UUID referenced from multiple Java files — Phase 1 would emit one evidence entry per file (each with a different `Classification source:` or Java field name), but the underlying fact ("this UUID is in this APK build") is one. The `android_info_array` already carries the unique-per-(pkg, version_code) view of the same fact, so multiple evidence rows are pure noise.
   - The full `(description, submitter)` tuple matches (and neither has a URL).

   When two entries collide, the **more informative survivor** wins — preferring entries that captured a Java field name, an authoritative `usage:` classification source, or a third-party-SDK declaring-package annotation. Order is preserved: the survivor lives at the position of the first occurrence, so curator-edited entries stay at the top.

   Dedup runs in three places, so re-running phases or merging on top of existing data is idempotent:
   - Inside `merge_records` after each per-UUID extend.
   - As a final pass in `save_output` before writing.
   - Inside `apply_apk_url_evidence.py` and `apply_uuid_name_resolution.py` after their append step, so re-running those scripts never restacks the same URL or Phase-5 note.
7. **Attempts to pair Characteristics with their parent Service** when the Service UUID appears within the same `.java` file. If no parent can be found locally, `parent_UUID` is omitted (allowed by the schema).
8. **Emits one CLUES record per unique UUID.** Each record carries an `android_info_array` entry tagging which package(s) it was found in. When the same UUID turns up in multiple APKs, the entries are merged: the UUID gets a single record with multiple `android_info_array` items.
9. **Deletes the temp jadx output dir.** Every APK's decompilation is removed before the next one starts. The persistent output is only the JSON file.

## Prerequisites — confirm before starting

- **`jadx` ≥ 1.5** must be installed. `brew install jadx`. Earlier versions don't understand `.xapk` and would need a manual `unzip → base.apk` step.
- **`aapt`** from the Android build-tools must be reachable. `brew install android-commandlinetools` installs it under `/opt/homebrew/share/android-commandlinetools/build-tools/<ver>/aapt`. The script auto-discovers the newest installed `aapt`.
- **`python3`** (any 3.9+).
- **Disk space for jadx output.** A single decompilation can produce 1–4× the APK size in `.java` files. The script writes to `$TMPDIR` (or `/tmp` if unset). Make sure the tmpfs has at least 4 GB free before pointing the skill at a folder of fat APKs (e.g. Dexcom Stelo 170 MB → ~600 MB of Java).

## How to invoke

### User-facing (Claude Code slash-command form)

End users trigger the skill through the standard slash-command. The arguments after the slash are interpreted as one or more paths (APK files, XAPK files, or directories), optionally followed by any of the Python CLI flags listed below:

```
/apk-clues-extract /Volumes/2TB_ExFAT/__BLUUID_APKS/0002 \
    /Volumes/2TB_ExFAT/__BLUUID_APKS/0003 \
    "/Users/user/Downloads/DexcomStelo/Stelo by Dexcom_2.1.0.2972_APKPure.xapk"
```

**Slash-arg pass-through.** The harness gives the agent the entire free-form argument string, so any flag of `extract_clues.py` (`--parallel`, `--output`, `--session-output`, `--no-resume`, `--submitter`, …) is valid directly on the slash command. The agent appends them verbatim to the Python invocation:

```
/apk-clues-extract /Volumes/2TB_ExFAT/__BLUUID_APKS/0002 --parallel 4 --output /tmp/clues.json --session-output /tmp/just-the-new-ones.json
```

**Append behavior (important).** With no flag changes, the skill **merges into the existing `--output` file** — it does NOT start fresh. New UUIDs append; UUIDs already in the file gain new `android_info_array` / `evidence_array` entries from this run. The checkpoint sidecar (`<output>.processed.json`) skips APKs whose SHA-1 is already recorded.

To start fresh: either point `--output` at a new path, delete the file beforehand, or pass `--no-resume` (which ignores the checkpoint but still merges into the existing JSON — usually not what you want for "start fresh").

**Capturing just-this-run changes.** When you want a separate file listing only the UUIDs that *this invocation* added to the corpus (so you can review or share what one APK / one folder contributed without diffing the whole file by hand), pass `--session-output`:

```
/apk-clues-extract /Volumes/2TB_ExFAT/__BLUUID_APKS/0004 \
    --output CLUES_data_LLM_Android_APK_search.json \
    --session-output /tmp/run-0004-new-uuids.json
```

After the run, `/tmp/run-0004-new-uuids.json` contains only records whose UUID was *not* present in the `--output` file at the start of the run. UUIDs that this run merely added new package observations to are NOT included — their full state is in `--output`, and they pre-date the session.

### What the agent runs internally

When the skill is invoked, the agent translates the user's paths into one call to `extract_clues.py`. The full command-line interface:

```bash
python3 /Users/user/.claude/skills/apk-clues-extract/scripts/extract_clues.py \
    <path1> [<path2> ...] \
    [--output CLUES_data_LLM_Android_APK_search.json] \
    [--session-output FILE.json]   # write only UUIDs not present in --output at start of run
    [--semantic-upgrades-output FILE.json]  # write Unknown->named / Unknown->company upgrades
    [--submitter "Claude (Opus 4.7)"] \
    [--parallel N]      # default 1 (serial). N=4 is a good fit for an 8-core box.
    [--progress-interval 100]  # checkpoint progress + Unknown-name count every N APKs
    [--no-resume]       # ignore checkpoint and re-process every APK from scratch
    [--search-unknown]  # re-process APKs that contributed UUID_name=='Unknown', then run deep Phase-5 RE
    [--phase5-deep-re]  # run only the deep Phase-5 RE pass on existing Unknown records
    [--phase5-deep-re-output FILE.json]  # optional mapping report from the deep Phase-5 RE pass
    [--keep-tmp]        # only for debugging; default is to wipe the tempdir after each file
```

`<pathN>` can be any mix of APK files, XAPK files, and directories — directories are walked recursively. Duplicates (same APK reached via multiple paths) are skipped via the checkpoint.

**Worked example** — the agent's bash translation of the slash-command above:

```bash
python3 /Users/user/.claude/skills/apk-clues-extract/scripts/extract_clues.py \
    /Volumes/2TB_ExFAT/__BLUUID_APKS/0002 \
    /Volumes/2TB_ExFAT/__BLUUID_APKS/0003 \
    "/Users/user/Downloads/DexcomStelo/Stelo by Dexcom_2.1.0.2972_APKPure.xapk" \
    --output /Users/user/Blue2thprinting/Analysis/CLUES_Schema/data/CLUES_data_LLM_Android_APK_search.json \
    --parallel 4
```

Equivalent serial form (each call accumulates into the same output file via the merge logic — useful when inputs arrive incrementally, e.g. the user pulls one APK at a time from a phone):

```bash
OUT=data/CLUES_data_LLM_Android_APK_search.json    # path is relative to CLUES_Schema/
python3 .../extract_clues.py /Volumes/2TB_ExFAT/__BLUUID_APKS/0002 --output "$OUT" --parallel 4
python3 .../extract_clues.py /Volumes/2TB_ExFAT/__BLUUID_APKS/0003 --output "$OUT" --parallel 4
python3 .../extract_clues.py "/Users/user/Downloads/DexcomStelo/Stelo by Dexcom_2.1.0.2972_APKPure.xapk" --output "$OUT"
```

The single-invocation form is preferred when the inputs are known upfront — the parallel pool stays warm across all paths. Both produce identical output because of the checkpoint + merge.

**Default behavior: all six phases + a final post-flight sort run.** After Phase 1, the agent **automatically** runs Phase 2 (Play Store company enrichment), Phase 3 (re-download URL evidence), Phase 4 (shared-SDK identification), Phase 5 (re-investigation of UUIDs still named "Unknown" in this session), Phase 6 (extract lessons learned from Phases 2–5 and patch `extract_clues.py` so the next first-pass benefits), and a final post-flight invocation of `CLUES_Schema/scripts/SortCLUES.py` that re-sorts every data file in `CLUES_Schema/data/` into the project's canonical (company, UUID_purpose, UUID) order so git diffs stay reviewable. These phases are agent-driven loops, not separate slash commands. The user gets a fully-resolved CLUES file *and* a smarter Phase-1 extractor from one invocation rather than having to remember 7 separate commands.

To opt out of one or more phases, pass any of these flags on the slash command and the agent will skip them:

- `--phase1-only` — stop after Phase 1 (raw, offline extraction; also skips the post-flight sort)
- `--no-phase-2` — skip Play Store company enrichment
- `--no-phase-3` — skip URL evidence
- `--no-phase-4` — skip shared-SDK cluster identification
- `--no-phase-5` — skip re-investigation of Unknown UUID names
- `--no-phase-6` — skip self-improvement (do not patch `extract_clues.py`)
- `--no-sort` — skip the post-flight `SortCLUES.py` re-sort (use when sibling data files have uncommitted hand-edits the user wants preserved)

Reasons to opt out:
- **Reproducibility-sensitive runs:** Phase 1 is the only deterministic phase (network-independent). If you need a result that's bit-stable across re-runs, pass `--phase1-only`.
- **1000+ APK corpora:** the Phase-4 loop is per-cluster O(decompile + WebSearch); 50 clusters can add 1-3 hours. If you'll do that curation later, pass `--no-phase-4`.
- **Read-only audit:** if the user is reviewing the skill without authorizing source edits, pass `--no-phase-6` so `extract_clues.py` is untouched.
- **Offline environment:** `--no-phase-2 --no-phase-3 --no-phase-4 --no-phase-5 --no-phase-6` is equivalent to `--phase1-only`.

The agent's flag-handling: it parses the slash-command args, peels off `--phase1-only / --no-phase-N`, passes the remaining args to `extract_clues.py`, then decides phase-by-phase whether to invoke the helpers below.

**Parallelism (`--parallel N`).** Each worker runs the per-APK pipeline (aapt + jadx + scan + classify) in its own process. The main thread serializes merge + output writes. jadx is internally multi-threaded (9 threads by default), so the practical ceiling is `min(cpu_count() // 2, len(targets))` — beyond that you'll thrash. On a 1,000-APK corpus this brings wall time from ~10h down to ~2.5h on an 8-core machine.

**Resumability (checkpoint).** A sidecar file `<output>.processed.json` records the SHA-1 + status of every APK the driver has seen. Re-running the same command will skip APKs already recorded with `status: ok:*`. To force a full re-scan, pass `--no-resume`. The checkpoint also survives Ctrl-C: at most the in-progress APKs are lost. SHA-1 is over the first 4 MiB of the APK + its size — fast and sufficient to detect a republished build.

**Targeted re-extraction + deep Phase-5 RE (`--search-unknown`).** Re-runs Phase 1 against only the APKs that originally yielded records with `UUID_name: "Unknown"` (or empty/missing) in the current `--output`, then runs the deep Phase-5 reverse-engineering pass over those same Unknown UUIDs. The target set is derived from each Unknown record's `android_info_array[].package_path` field, deduped to unique APK paths. For each derived APK, the checkpoint's `status: ok:*` is *ignored* (so the APK is re-processed even though it's already in the sidecar), but the rest of the checkpoint is preserved untouched — non-target APKs aren't re-scanned and aren't dropped from the sidecar. This is the right tool when Phase 1's classifier has improved or when the remaining names need behavioral recovery from decompiled code. Positional path args act as a filter when given — only Unknown-record APKs whose absolute path matches or sits under one of those paths are processed. Paths that no longer exist on disk are skipped with a warning. The flag makes the positional path argument optional. Example:

```bash
# retry every Unknown-yielding APK in the corpus
python3 .../extract_clues.py --search-unknown --output data/CLUES_data_LLM_Android_APK_search.json --parallel 4

# retry only Unknown-yielding APKs that live under one specific folder
python3 .../extract_clues.py /Volumes/2TB_ExFAT/__BLUUID_APKS/0998 --search-unknown --output data/CLUES_data_LLM_Android_APK_search.json --parallel 4
```

Idempotent + convergent: each invocation re-derives the Unknown set from the current `--output`, so successive runs queue progressively fewer APKs as names get resolved. In `--search-unknown` mode, `--session-output` can legitimately contain zero records because no UUIDs were newly discovered; use `--semantic-upgrades-output /tmp/upgrades.json` when you want the audit artifact that matters for this mode: existing records whose `UUID_name` or `company` improved. If `--search-unknown` and `--session-output` are both set but `--semantic-upgrades-output` is omitted, the extractor automatically writes a sibling `*_semantic_upgrades.json` report. Long runs emit built-in checkpoint progress every `--progress-interval` APKs (default 100), including the remaining `UUID_name: "Unknown"` count.

The deep Phase-5 portion of `--search-unknown` decompiles each target APK with `jadx --show-bad-code` in addition to the normal flags, because JADX often hides the callback/listener body that contains the useful BLE dataflow unless that flag is enabled. It then performs a targeted local reverse-engineering pass:

- Captures loose UUID assignments, including instance fields such as `this.avion_char_out_uuid = "..."`, not only `UUID.fromString(...)`.
- Traces obfuscated UUID constants through service-discovery comparisons into `BluetoothGattCharacteristic` alias fields.
- Classifies service UUIDs from `BluetoothGattService.getUuid().compareTo(...)` and `getService(...)`, correcting Phase-1 file-level defaults when needed.
- Reads alias behavior: write helpers, `writeCharacteristic`, `readCharacteristic`, `setCharacteristicNotification`, descriptor notification enables, and `onCharacteristicChanged`.
- Uses nearby UI/log/action strings (`BluConsole`, `EXTRAS_CONSOLE_TEXT`, send-button command paths, proxy PDU flow) to synthesize conservative names such as `ARUBA_BLUCONSOLE_INPUT_CHARACTERISTIC` or to preserve exact recovered field names such as `avion_char_out_uuid`.

Use `--phase5-deep-re` when you want **only** this deep Phase-5 pass against the current `--output` without re-running normal extraction first. It uses the same Unknown-record target derivation and accepts the same optional positional path filter:

```bash
python3 .../extract_clues.py /tmp/two-apks \
    --output data/CLUES_data_LLM_Android_APK_search.json \
    --phase5-deep-re \
    --phase5-deep-re-output /tmp/deep_phase5_mapping.json \
    --semantic-upgrades-output /tmp/deep_phase5_upgrades.json
```

- The default `--output` is `data/CLUES_data_LLM_Android_APK_search.json` (relative to whatever directory the script is run from — typically `CLUES_Schema/`, which is what the agent always passes explicitly). Pre-existing entries in that file are **loaded** at start so re-running on more APKs accumulates results.
- `--submitter` defaults to the active LLM model name (`Claude (Opus 4.7)` for this skill). Override only if running under a different model.
- `--keep-tmp` retains the per-APK jadx output (under `$TMPDIR/apk_clues_<pid>_<sha>/`) for manual inspection. Off by default — production runs should delete to save disk.

## Output format

The output JSON conforms to `CLUES_schema.json` and is a flat top-level array of records. A typical record looks like:

```json
{
    "UUID": "f8083535-849e-531c-c594-30f1f86a4ea5",
    "company": "Unknown",
    "UUID_name": "Unknown",
    "UUID_purpose": "Custom GATT Service observed in Android app com.dexcom.stelo (Stelo by Dexcom).",
    "UUID_usage_array": [ "GATT Service" ],
    "evidence_array": [
        {
            "description": "Found in decompiled DEX of com.dexcom.stelo v2.1.0.2972 (XAPK 'Stelo by Dexcom_2.1.0.2972_APKPure.xapk'). Referenced in BluetoothGattService construction.",
            "submitter": "Claude (Opus 4.7)"
        }
    ],
    "android_info_array": [
        {
            "package_id": "com.dexcom.stelo",
            "version_code": 2972,
            "version_name": "2.1.0.2972",
            "package_path": "/Users/user/Downloads/DexcomStelo/Stelo by Dexcom_2.1.0.2972_APKPure.xapk",
            "description": "Detected by apk-clues-extract scan; usage 'GATT Service'."
        }
    ]
}
```

Characteristics carry `parent_UUID` when the parent service was identifiable in the same Java file:

```json
{
    "UUID": "f8083536-849e-531c-c594-30f1f86a4ea5",
    "company": "Unknown",
    "UUID_name": "Unknown",
    "UUID_purpose": "GATT Characteristic under f8083535-849e-531c-c594-30f1f86a4ea5 in com.dexcom.stelo.",
    "UUID_usage_array": [ "GATT Characteristic" ],
    "parent_UUID": "f8083535-849e-531c-c594-30f1f86a4ea5",
    "evidence_array": [ ... ],
    "android_info_array": [ ... ]
}
```

Because the extractor cannot infer the marketing/legal company name from an APK alone (only the package_id), every record starts with `company: "Unknown"` and `UUID_name: "Unknown"`. A human reviewer (or a separate LLM pass) is expected to fill those in later by cross-referencing the `package_id` against the developer's public docs / store listing — that step is intentionally out of scope.

## Storage layout — single file or 16 hex-bucket shards

Once `data/CLUES_data_LLM_Android_APK_search.json` grows past ~100 MB it stops being a useful single file: git diffs become unreviewable, editors hang loading it, and GitHub rejects pushes that contain it (100 MB hard cap, no LFS). The skill solves this by sharding the output across 16 files named after the first hex character of each record's `UUID`:

```
data/CLUES_data_LLM_Android_APK_search_0.json    # UUIDs starting with "0"
data/CLUES_data_LLM_Android_APK_search_1.json    # UUIDs starting with "1"
…
data/CLUES_data_LLM_Android_APK_search_f.json    # UUIDs starting with "f"
```

The split is **storage only** — the global `(company, UUID_purpose, UUID)` sort order is preserved across the combined dataset; shards just hold contiguous slices of that order. Whether a given file is sharded or single-file is decided **exclusively by `CLUES_Schema/scripts/SortCLUES.py`** (via its `SPLIT_FILES` allowlist). Every script in this skill (`extract_clues.py`, all Phase 2–6 helpers) calls `clues_io.load_clues(path)` / `clues_io.save_clues(data, path)` — those helpers transparently read either form and **preserve whatever layout they find on disk** when writing back. No script in this skill ever decides to split or un-split on its own.

Implications:

- **For the agent.** Always pass the *unsplit base path* (`data/CLUES_data_LLM_Android_APK_search.json`) to every CLI in this skill, regardless of which form is actually on disk. The loaders DTRT. Never hand-edit individual shards — use the helper scripts or write your edits through `save_clues`, otherwise the next post-flight sort will reorder records across shard boundaries and your hand-edits may end up in a different shard than expected.
- **For schema validation.** `check-jsonschema` doesn't transparently combine shards. Glob the file pattern when the output is split: `data/CLUES_data_LLM_Android_APK_search_*.json` (see the [Validation](#validation) section below). The pattern works for either form because globs match the single-file basename too when no shards exist.
- **For child characteristics whose parent service has a UUID starting with a different hex letter.** The child still carries `parent_UUID`, but the parent's record lives in a different shard. This is intentional — the alternative (moving children to follow parents) would defeat the by-UUID bucketing and make `load_clues` non-trivial. Consumers that want parent/child pairing should follow `parent_UUID` after loading the combined dataset.
- **For Phase 6 self-improvement.** `KNOWN_NON_BLE_UUIDS` and `KNOWN_SDK_JAVA_PACKAGES` updates live in `scripts/extract_clues.py`, not in the data files, so the split doesn't affect Phase 6 at all.

## Phase 2 — web-enrichment of "(inferred from package id)" records

The static extractor (Phase 1) produces the strongest `company` value it can without a network. When neither `KNOWN_VENDOR_PACKAGES` nor a `member_uuids.yaml` overlap fires, the field falls back to a capitalized package component plus the marker `(inferred from package id)`. **In-APK strings are almost never enough to identify the publisher** — they describe the *product* or the *device family*, not the *developer account*. Example: `com.tntkhang.gtswatchface`. The APK contains zero strings mentioning the publisher; the closest in-APK hint is `amazfitwf-46c6d.firebaseio.com` (just says "Amazfit watch face" — the product). Only a web search of the package id reliably resolves the publisher (it returns Play Store / AppBrain / APKPure listings consistently crediting "SmartWatchCenter").

Phase 2 is a Claude Code agent loop that automates this lookup. The two helper scripts in `scripts/` make it a 3-step recipe — any agent with `WebSearch` plus the standard read/write/bash tools can run it without further code:

### Step 2.1 — list which packages still need enrichment

```bash
python3 /Users/user/.claude/skills/apk-clues-extract/scripts/list_inferred_companies.py \
    /path/to/CLUES_data_LLM_Android_APK_search.json
```

Stdout is a JSON document with two keys: `needs_enrichment` (a list of `{package_id, current_company, record_count}` for packages still tagged `(inferred from package id)`) and `already_resolved` (a list of package_ids that already have a curated company). Records the agent should focus on are the ones in `needs_enrichment`, sorted by `record_count` so high-impact packages go first.

### Step 2.2 — bulk-scrape the Play Store first

For most public apps, the publisher is in plain HTML on `play.google.com/store/apps/details?id=<package>`. There's a helper that scrapes that page (`<meta itemprop="author">` / JSON-LD `"author":{...,"name":"..."}` / `/store/apps/dev?id=...` patterns) for many package_ids in one shot:

```bash
python3 /Users/user/.claude/skills/apk-clues-extract/scripts/list_inferred_companies.py CLUES.json \
    | jq -r '.needs_enrichment[].package_id' \
    | python3 /Users/user/.claude/skills/apk-clues-extract/scripts/scrape_play_store_companies.py \
    > /tmp/scrape_mapping.json
```

Stdout is a flat `{package_id: company_name}` object — feed it straight to `apply_company_enrichment.py` (Step 2.3). Stderr reports per-package status (`ok` / `unreachable` / `not_listed` / `no_author_field`).

For packages the scraper couldn't resolve (typically: removed from Play Store, region-locked, never published publicly), fall back to a free-form WebSearch per the next paragraph.

### Step 2.2b — web-search any package_ids the scraper couldn't resolve

For each `package_id` in `needs_enrichment`, the agent should call `WebSearch` with a query like:

```
<package_id> developer publisher android app
```

and read the top 5–10 results. Reliable signals, in order of preference:

1. **Play Store listing** (`play.google.com/store/apps/details?id=<package_id>`) — the "developer" attribution is authoritative.
2. **AppBrain developer page** (`appbrain.com/dev/<DeveloperName>/`) — usually titles itself with the dev account name.
3. **APKPure / APKCombo / APKamp** — explicit "App by <Publisher>" lines in the page body.
4. **Microsoft 365 / Capterra / LinkedIn** — useful when the publisher rebranded (e.g. "Witco de MONBUILDING &CO" on Microsoft 365 disambiguates the rebrand history).

Special cases the agent should handle:

- **Rebrand history.** If the search results show a name change (`MonBuilding → Witco`, `St. Jude Medical → Abbott`, etc.), record the *current* legal name and the SIG-style `"<Current> (formerly <Old>)"` form so the value lines up with how Bluetooth SIG names absorbed members. Cross-check by also searching the old name to confirm it's the same legal entity.
- **White-label / customer-specific packages.** `com.monbuilding.app.legende` is a white-labeled instance of the Witco platform for the *Legende* building — the BLE UUIDs belong to Witco, not to "Legende". Use the platform publisher, not the customer name. `branded.com.<X>` is another common white-label pattern — `<X>` is the *customer*, and the publisher you want is the white-label-platform vendor (search the white-label vendor's site for a customer list to confirm).
- **Ambiguous results.** If two reasonable answers exist (e.g., the SDK vendor vs. the app publisher), prefer the *app publisher* — the UUIDs as-shipped in this APK are tied to the publisher's identity, not the SDK's.
- **No clear answer.** Leave the package out of the mapping — don't guess. Records stay as `(inferred from package id)` for a future curator.

The output is a single flat JSON object mapping resolved package_ids to confirmed company names, e.g.:

```json
{
    "com.foo.bar":          "Foo Corp",
    "com.legacy.app":       "NewName (formerly OldName)",
    "branded.com.acme":     "Acme Whitelabel Platforms"
}
```

Save it to disk (any path; `/tmp/enrichment.json` is fine).

> **Company-field rule.** Each value must be the **bare company name** — nothing else. Do NOT append country, product line, app name, what BLE is used for, acquisition history, or any other context inside the value. Bad: `"Canon Inc. (Japan) — Camera Connect app; BLE for EOS / PowerShot cameras"`. Good: `"Canon Inc."`. Bad: `"Anki (now Digital Dream Labs)"`. Good: `"Anki"` (use the historically-attributed name; acquisition notes go elsewhere). The lone exceptions are: (a) the `(formerly OldName)` rebrand suffix, which SIG-style member entries also use, and (b) acronyms that are part of the formal name like `(IBV)`. `apply_company_enrichment.py` runs the value through `company_sanitizer.sanitize_for_write` and will auto-strip any other parenthetical / em-dash commentary — appending the stripped text to the record's `evidence_array` and emitting a stderr `[sanitize]` warning — so the data ends up clean either way. The warning means "put it in evidence next time, not in the company field".

### Step 2.3 — apply the mapping

```bash
python3 /Users/user/.claude/skills/apk-clues-extract/scripts/apply_company_enrichment.py \
    /path/to/CLUES_data_LLM_Android_APK_search.json \
    /tmp/enrichment.json
```

This script:

- Replaces `company` on every record whose `android_info_array` references a mapped package — but **only** when the existing value is the `(inferred from package id)` placeholder or `Unknown`. A previously curated value is never overwritten.
- Re-sorts the JSON by UUID for stable diffs and writes it back atomically.
- Prints to stdout a suggested `KNOWN_VENDOR_PACKAGES` diff (one `"<vendor-key>": "<company>",` line per resolved package), keyed by the same first-non-TLD-like component the Phase-1 extractor uses for lookup. The agent should then `Edit` `scripts/extract_clues.py` to paste those lines into the dict — that way every future Phase-1 run hits the table directly and the same package never needs enrichment again. This is the **preferred** outcome over patching records ad hoc; it's reusable and benefits the entire CLUES community.

After applying, re-validate the schema and you're done:

```bash
cd /Users/user/Blue2thprinting/Analysis/CLUES_Schema/
source venv/bin/activate
check-jsonschema --base-uri ./CLUES_schema.json \
    --schemafile ./CLUES_schema.json ./data/CLUES_data_LLM_Android_APK_search.json
```

### Opt-out conditions (Phase 2)

Phase 2 runs by default. Skip it via `--no-phase-2` (or `--phase1-only`) when:

- The user only wants raw extraction (e.g., they're running on a corpus of 1,000+ APKs and will curate companies later). Phase 2 is per-package O(1 web search), which scales linearly with distinct unknown packages — fine for tens, costly for hundreds.
- The CLUES file is going to be reviewed by a human before merge — let the human do the lookups so the citations they leave in commit messages are theirs, not the agent's.
- Some `(inferred from package id)` entries are intentional placeholders pending more APK samples; the user should flag those explicitly so the enrichment loop skips them.

## Phase 3 — add a re-download URL to every record's `evidence_array`

A CLUES record without a re-download URL is hard to reproduce: another researcher who wants to validate a UUID has no way to grab the exact same APK build. Phase 3 closes that gap by finding an apkpure / apkcombo / archive.org / Play Store URL for each `(package_id, version_name)` pair in the output and adding it as a CLUES `evidence_array` item. **Every URL is CLI-verified before commit**, so the JSON never ships a dead link.

Three helpers in `scripts/` make this a 3-step loop, parallel in structure to Phase 2:

### Step 3.1 — list which APK versions still need a URL

```bash
python3 /Users/user/.claude/skills/apk-clues-extract/scripts/list_apk_versions.py \
    /path/to/CLUES_data_LLM_Android_APK_search.json
```

Stdout is a JSON document with `needs_url` (list of `{package_id, version_name, version_code, record_count, company, local_path}`, sorted by record_count so high-impact APKs go first) and `already_has_url` (list of `"<pkg>@<ver>"` keys that already carry an APK-cache URL in their `evidence_array`). The Phase-3 agent should only work on entries in `needs_url`.

### Step 3.2 — find a URL per APK version and CLI-verify

For each `(package_id, version_name)`, the agent should:

1. **Search the web** with a query like:
   ```
   <package_id> <version_name> apkpure OR apkcombo OR apkmirror download
   ```
   Read the top results and extract the canonical apkpure / apkcombo slug from any URL like `https://apkpure.com/<slug>/<package_id>` or `https://apkcombo.com/<slug>/<package_id>/`.

2. **Construct a candidate URL** in this preference order (apkpure.net is the same archive as apkpure.com but is *not* Cloudflare-protected, so CLI-verification works — always use `.net`):
   1. `https://apkpure.net/<slug>/<package_id>/download/<version_name>` — version-specific download page.
   2. `https://apkpure.net/<slug>/<package_id>/versions` — version-history page (use when the exact version isn't archived but the app has ≥2 archived versions).
   3. `https://apkpure.net/<slug>/<package_id>` — canonical app landing (use when the app has only 1 archived version, which makes `/versions` 404).
   4. `https://play.google.com/store/apps/details?id=<package_id>` — Play Store listing (use only when apkpure has no record of the package at all).
   5. `https://archive.org/details/<archived-id>` — Internet Archive entry (use when the APK is on archive.org; rare but those URLs serve direct .apk downloads).

   **Slug-agnostic trick:** apkpure.net resolves any plausible slug as long as the `<package_id>` part is real. `https://apkpure.net/anything/<package_id>` will redirect to the canonical page. So if you can't easily guess the slug, use the package's vendor token as a placeholder — the server will fix it.

3. **CLI-verify** with the bundled script (this is the step the user asked for explicitly — *"after you get the URL, make sure the skill explicitly confirms it can download from that URL"*):

   ```bash
   python3 /Users/user/.claude/skills/apk-clues-extract/scripts/verify_apk_url.py \
       --expect "<version_name or other expected substring>" \
       "<candidate URL>"
   ```

   Stdout is a single JSON line with `status` in `{ok, page_invalid, not_found, bot_blocked, unreachable, http_error}`. Only commit URLs whose status is `ok`. Specifically:

   - **`ok`** — page loads with non-trivial body and (if `--expect` was given) the expected substring appears. **This is the only acceptable status for committing.**
   - **`page_invalid`** — page returned 200 but the body is the ~1KB Cloudflare bot-fingerprint stub, *or* the version substring isn't in the body (meaning the specific version isn't archived even though the slug is correct). Walk back to the `/versions` URL and re-verify.
   - **`not_found`** — 404. Try a different slug, or move to the next preference tier.
   - **`bot_blocked`** — 403/503, typically the canonical `apkpure.com` (not `.net`) host. Switch to `.net` (or another mirror) and retry, OR fall back to Chrome navigation (see below).
   - **`unreachable`** / **`http_error`** — transient or wrong URL.

4. **Chrome-navigation fallback for bot-blocked hosts.** If the only available URL is on a host that bot-blocks CLI clients (`apkpure.com`, `m.apkpure.com`, and a few others all sit behind Cloudflare's `cf-mitigated: challenge`), the agent should fall back to the `mcp__Claude_in_Chrome__navigate` tool: open the URL in the user's Chrome tab and call `mcp__Claude_in_Chrome__get_page_text` to confirm the page renders an app-listing-shaped document (title contains the package name or version, body mentions "Download APK", etc.). Only commit a URL whose Chrome rendering is confirmed.

5. **Build the mapping JSON** as `{"<pkg>@<ver>": {"URL": "...", "verified": "ok", "direct_download": false}}` and save it (any path; `/tmp/url_mapping.json` is fine). `direct_download` should be `true` only when the verifier reported `application/vnd.android.package-archive` (most cache sites are HTML landing pages, not direct .apk URLs — that's the JS-gated download step they hide on purpose).

### Step 3.3 — apply the mapping

```bash
python3 /Users/user/.claude/skills/apk-clues-extract/scripts/apply_apk_url_evidence.py \
    /path/to/CLUES_data_LLM_Android_APK_search.json \
    /tmp/url_mapping.json
```

The script:

- Refuses to commit any mapping entry whose `verified` field isn't `ok` (so the verify gate from Step 3.2 is enforced).
- For every CLUES record whose `android_info_array` contains a mapped `(package_id, version_name)`, appends one `evidence_array` entry with the URL, the verification status, and a default human-readable description. **Idempotent**: if the URL is already present in `evidence_array`, the entry is skipped — safe to re-run.
- Inherits the `submitter` from the record's existing evidence entries when the mapping doesn't specify one, so the new URL evidence attributes the same way as the discovery evidence.
- Re-sorts the JSON by UUID and writes back atomically.

Re-validate the schema after applying — the `URL` and `description` fields are both in the CLUES `evidence_array_item` schema, so a clean run should still pass `check-jsonschema`.

### Empirical notes from the May 2026 test run

On the test corpus (Stelo + Lingo + 0000/ + 0001/ folders = 21 distinct APK versions):

- **17 of 21** got version-specific apkpure.net URLs (`/download/<version>`).
- **4 of 21** fell back to the version-history page (`/versions`) because the exact version isn't currently archived on apkpure.net — but the app and other versions are.
- **3 of 21** fell back to the canonical app URL (`apkpure.net/<slug>/<pkg>`) because apkpure had only one archived version (so `/versions` was 404).
- **1 of 21** fell back to the Play Store (`com.mcb.poranki`) — never archived on apkpure.

`apkpure.com` was unreachable from CLI throughout (Cloudflare bot-protection on every request) — `.net` is the workable mirror. `apkcombo.com` works in CLI but its version-specific URLs aren't easily constructible.

## Phase 4 — identify the SDK behind cross-app-shared UUIDs

A common pattern: dozens of unrelated Android apps include the same third-party SDK (Zoom, Firebase, an obscure BLE-device library, …) and that SDK ships BLE constants. To a static scanner those UUIDs look like they belong to whichever host app got processed first — a misattribution that scales badly across a 1,000-APK corpus.

The Phase-1 extractor already mitigates the worst case: when `save_output` sees a UUID present in ≥3 host packages with non-overlapping vendor tokens AND the UUID isn't already in the curated `KNOWN_SDK_UUIDS` table, it sets the record's `company` to `"Unidentified shared SDK (observed in N unrelated host apps — Phase-4 identification needed)"`. That's strictly more honest than picking a random host vendor.

Phase 4 is the agent loop that *identifies* the SDK behind each such cluster and upgrades the records (and seeds the curated table) so subsequent runs short-circuit the identification.

### Step 4.1 — list the clusters that need identification

```bash
python3 /Users/user/.claude/skills/apk-clues-extract/scripts/list_shared_sdk_clusters.py \
    /path/to/CLUES_data_LLM_Android_APK_search.json
```

Stdout JSON has `clusters` (multi-UUID clusters worth a single identification pass) and `single_uuid_outliers` (a UUID that's shared but doesn't cluster with siblings — typically a one-off SDK token, lower-priority). Each cluster carries:

- `uuids`: the UUIDs to identify
- `host_packages`: the apps that contain them (with `local_path` to the APK on disk)
- `uuid_field_names`: any semantic field names that survived merge across host apps (e.g. `LIBRE3_DATA_SERVICE`, `KUBI_SERVICE`)
- `suggested_action`: the recipe below, adapted to this cluster

The agent should work through clusters in size order (biggest cluster = most records improved per identification job).

### Step 4.2 — identify the SDK behind one cluster

Pick the smallest host APK from `host_packages` (smallest `local_path` filesize) and:

1. **Decompile** with jadx (`--no-res --no-debug-info`).
2. **Find the BLE-handling classes.** Grep the decompiled tree for one of the cluster's UUIDs; the file containing the UUID literal is almost always the SDK's BLE class. JADX leaves a comment `/* JADX INFO: compiled from: <OriginalName>.java */` near the top of every file — that's the unobfuscated source filename and it survives ProGuard. Unique-looking class names (`Kubi.java`, `KubiManager.java`, `LibrePatchService.java`, etc.) are the gold signal.
3. **Look at the surrounding package's imports.** If the SDK is a sub-library inside a larger framework (e.g. the Kubi BLE code is *inside* the Zoom Android SDK), that parent framework's package will be imported at the top of the BLE file. `import us.zoom.core.helper.ZMLog` is what told us Kubi shipped via Zoom.
4. **Check resources too.** If the host app uses a UI for the SDK (a "Kubi" checkbox, an "AiDot" toggle), the SDK's brand name will appear in `res/values/strings.xml` or as resource IDs in `R.java`.
5. **Web-search.** With the unique class names and (if needed) one of the unique UUIDs in hand, run `WebSearch` for `"<class name> Android SDK"` / `"<UUID> Bluetooth"` / `"<class name> github"`. The SDK vendor falls out of the first few results.
6. **Web-search again to confirm distribution.** If the SDK ships *inside* a bigger framework, confirm — e.g. `Zoom Android SDK Kubi integration`. This explains why N unrelated apps carry the UUID (they bundle the bigger framework).

### Step 4.3 — apply the identification + seed the cached table

Build a mapping JSON keyed by cluster_id:

```json
{
    "c0": {
        "company":    "Revolve Robotics",
        "note":       "Kubi SDK / Zoom Android SDK bundle for the Kubi telepresence robot",
        "uuid_names": { "9145": "SERVO_HORIZONTAL", "9146": "SERVO_VERTICAL", ... },
        "uuids":      [ "9145", "9146", "e001", ... ]
    },
    ...
}
```

> **Company-field rule.** `company` is the **bare company name**. Any descriptive context — product names, what BLE is used for, SDK ancestry, the cluster's blast radius — goes in `note` (folded into UUID_purpose and into KNOWN_SDK_UUIDS for future runs). Don't pack it into `company`. The apply script calls `company_sanitizer.sanitize_for_write` and will auto-strip parenthetical / em-dash commentary, append it to each record's `evidence_array`, and emit a stderr `[sanitize]` warning — the warning means "put it in `note` next time, not in `company`".

Then:

```bash
python3 /Users/user/.claude/skills/apk-clues-extract/scripts/apply_sdk_identification.py \
    /path/to/CLUES_data_LLM_Android_APK_search.json \
    sdk_mapping.json
```

The script:
- Replaces `company` on every record whose UUID is in any mapped cluster
- Upgrades `UUID_name` from "Unknown" when the mapping supplies a curated name
- Appends a `Phase-4 SDK identification: <note>.` line to `UUID_purpose`
- **Prints to stdout the Python diff to extend `KNOWN_SDK_UUIDS` in `extract_clues.py`** — pasting this into the file means every future Phase-1 run hits the table directly and never has to identify this SDK again.

### Worked example — Kubi / Zoom

The corpus included 7 unrelated apps (`co.diaz.srvol`, `com.proctur.app222423`, …) all sharing UUIDs `9141, 9142, 9145, 9146, e001, e101, e102, e103, e104, e105, e10a, 2a001800-2803-2801-2800-1d9ff2d5c442`. The cluster detector flagged them; the agent decompiled srvol, found:

- File `bt/c.java` (originally `Kubi.java`, per JADX comment) with `BluetoothGattService` and `BluetoothGattCharacteristic` fields, plus all the cluster's UUID literals.
- File `bt/a.java` (originally `GattInterface.java`) imports `us.zoom.core.helper.ZMLog` and `us.zoom.proguard.hl`.
- `R.java` references `btnKubi`, `chkEnableKubiRobot`, `panelAvailableKubis`.
- 5,679 `us.zoom.*` Java files in the decompiled tree.

Web search of "Zoom Android Kubi integration" returned [Zoom's 2015 announcement](https://blog.zoom.us/product-announcement-kubi-integrates-with-zoom-on-ios-android/) of Kubi telepresence-robot control. Conclusion: the UUIDs belong to **Revolve Robotics** (the Kubi maker); they're seen in 7 unrelated Indian education / LMS apps because those apps all bundle the Zoom Android SDK for video-conferencing.

The Kubi UUIDs are now in `KNOWN_SDK_UUIDS` — any future scan that hits one of them in a fresh APK will short-circuit straight to the correct vendor.

### Opt-out conditions (Phase 4)

Phase 4 runs by default. Skip it via `--no-phase-4` (or `--phase1-only`) when:

- The "Unidentified shared SDK" marker is acceptable for a research-only run that won't be merged into the canonical CLUES dataset — curators can identify SDKs later.
- The cluster is a known-bad pattern (e.g. all hosts in the cluster are *all* fork-of-the-same-template apps that genuinely share a private SDK between themselves and a curator says "yes that's intentional, don't normalize it"). The agent should respect that flag.
- The corpus produced an unusually large number of clusters (>10 or so) and the per-cluster decompile + WebSearch budget would dominate wall-clock time. In that case the cluster detector's JSON output is still useful as a to-do list for a later run.

### Opt-out conditions (Phase 3)

Phase 3 runs by default. Skip it via `--no-phase-3` (or `--phase1-only`) when:

- The CLUES file is being merged into a CC-BY-SA dataset where the curator prefers an `archive.org` URL for permanence — third-party APK caches sometimes pull listings after a takedown request, which would silently dead-link the records. For high-stakes records, prefer manually pushing the APK to archive.org and using that URL.
- The APK was obtained from an internal source the user controls (e.g., a private firmware mirror) and a public URL is intentionally absent — the user should annotate the records with that decision rather than have Phase 3 invent a URL.

## Phase 5 — re-investigate UUIDs whose `UUID_name` is still "Unknown"

Phase 1 captures the LHS field name of the assignment that produced each UUID literal — that becomes `UUID_name`. But a lot of UUIDs slip through with `UUID_name: "Unknown"`:

- The literal sits in an obfuscated identifier (jadx leftovers like `f7217p`, `f15558a`, single-letter aliases) that the field-name sanitizer rejects.
- The literal isn't assigned at all — it's a method argument, a return value, an array element, or it lives in an annotation/manifest string.
- The UUID belongs to an identified third-party SDK (e.g. Phase 4 set `company: "Estimote Inc. ..."`) but the SDK constants class was minified out of recognition before the static extractor saw it.

Phase 5 is the agent loop that takes a second pass at these records using context Phase 1 didn't have: the **company** Phase 2/4 just resolved, the **shape of the UUID** (UUID16 vs. UUID128 namespace, OUI-derived suffix, well-known public-SDK patterns), and **public documentation / GitHub** for the identified SDK. Two helpers in `scripts/` make this a 3-step loop, parallel in structure to Phases 2/3/4.

### Step 5.1 — list which UUIDs still need a name

```bash
python3 /Users/user/.claude/skills/apk-clues-extract/scripts/list_unknown_uuid_names.py \
    /path/to/CLUES_data_LLM_Android_APK_search.json \
    --session-file /tmp/run-<corpus>-new-uuids.json
```

The `--session-file` argument is **strongly recommended** when this is part of an end-to-end skill invocation — it constrains the work to UUIDs this run actually added, instead of the entire historical corpus. Omit it only when the user explicitly asks for a full re-investigation pass over all "Unknown" entries.

Stdout JSON has `needs_naming` (list of `{UUID, company, UUID_usage_array, host_packages: [...], parent_UUID?, record_count_in_array}`, sorted by host-app blast radius descending) and `already_named_count`.

### Step 5.2 — investigate each Unknown, in priority order

For each entry in `needs_naming`, the agent should follow this cascade — **stop at the first signal that produces a confident name**, don't run every step:

1. **Public-SDK lookup (cheapest).** If `company` names a public SDK with documented UUIDs (Estimote, Nordic NUS, TI OAD, Microchip ISSC, Tuya/Thingclips, CONTEC SpO2, Skidata MobileFlow, ETI thermalib, …), the SDK's GitHub repo or developer docs almost always has the UUID-to-name mapping. WebSearch for `"<UUID> <SDK name>"` or grep the SDK's public Android repository.
2. **UUID-shape inference.**
   - **UUID16 patterns:** 0xFFE0..0xFFE3 are TI SimpleProfile defaults (already cached in `KNOWN_SDK_UUIDS`); 0x18xx and 0x2Axx that escaped the SIG filter often signal a vendor mis-using SIG-reserved ranges and the name follows the SIG convention.
   - **UUID128 OUI suffix:** the last 6 hex chars of a UUID128 base often embed an IEEE OUI (e.g. ASSA ABLOY's `00177a`, Sony's `0917cf`). Search the IEEE OUI registry; if the OUI is known, the UUID is almost certainly that vendor's and the name follows the position within their base.
   - **UUID128 family patterns:** when several UUIDs share a fixed suffix (`-xxxx-xxxx-xxxx-aabbccddeeff`), they're a family from one vendor. If the family has 8–32 members, the first 16 bits of the variable segment usually encode `(service<<8 | characteristic)` — and 0x0000/0x0001 endings suggest the canonical Service+TX/RX trio.
3. **Decompile + grep (most expensive, highest signal).** Pick the smallest `local_path` from `host_packages`, decompile with jadx (`--no-res --no-debug-info -d <tmpdir> <apk>`), and grep the decompiled tree for the UUID literal:
   ```bash
   grep -rln "<uuid>" /tmpdir/sources/ | head -5
   ```
   For each hit, read the surrounding 20 lines. Even when the LHS identifier itself was minified, **nearby comments, string literals, or sibling-field names** will frequently reveal the semantic role (`"Set generator RPM"`, `LOG.d("write to TX_CHAR")`, an adjacent `BluetoothGattCharacteristic.PROPERTY_NOTIFY` constant, etc.). The JADX `compiled from: <Name>.java` comment that survives ProGuard is gold — it gives the SDK's original filename.
4. **Last resort — leave it.** If after all three steps the agent has no confident name, **do NOT guess**. The record stays `UUID_name: "Unknown"` and a future curator with more APK samples or vendor contact can fill it in. Inventing names ("DATA_CHARACTERISTIC_1") is strictly worse than honest Unknown.

### Step 5.3 — apply the mapping

Build a `{UUID: {UUID_name, UUID_purpose?, company?, note?, cache_in_sdk_table?}}` mapping, save to disk (any path; `/tmp/uuid_name_mapping.json` is fine), then apply:

```bash
python3 /Users/user/.claude/skills/apk-clues-extract/scripts/apply_uuid_name_resolution.py \
    /path/to/CLUES_data_LLM_Android_APK_search.json \
    /tmp/uuid_name_mapping.json
```

The script:

- Replaces `UUID_name` **only** when the current value is `"Unknown"` — a previously-curated name is never overwritten.
- Replaces `UUID_purpose` when supplied (always — the static-extractor-generated purpose is intentionally low-quality, so a curator's better description wins).
- Replaces `company` when supplied **and** the current value is `"Unknown"` / `(inferred from package id)` / a Phase-4 `Unidentified shared SDK` or `Third-party SDK code (declared in Java package ...)` marker. Curated values are protected. The supplied `company` must be the **bare company name**; commentary belongs in `note` (which becomes an evidence entry) or in `UUID_purpose`. `company_sanitizer.sanitize_for_write` auto-strips any parenthetical / em-dash commentary that slips in, emits a stderr `[sanitize]` warning, and tucks the stripped text into a fresh evidence entry — so the data ends up clean even if the mapping wasn't.
- Appends a `"Phase-5 UUID-name resolution: <note>"` evidence entry when `note` is supplied (attribution inherited from the record's existing evidence_array submitter).
- Re-sorts the JSON by UUID and writes back atomically.
- **Prints the Python diff for `KNOWN_SDK_UUIDS`** so a curator can paste the new entries into `extract_clues.py`. Every future Phase-1 run then hits the table directly and never has to re-resolve these UUIDs — preferred over per-record patches, exactly as in Phase 4.

Re-validate the schema after applying (`check-jsonschema` — see the Validation section).

### Opt-out conditions (Phase 5)

Phase 5 runs by default. Skip it via `--no-phase-5` (or `--phase1-only`) when:

- The corpus is large (≥500 APKs) and the agent's Phase-5 budget would dominate wall-clock time. Phase 5 is per-Unknown O(decompile + WebSearch); if Phase 1 left 200+ Unknowns, the loop can add 30–90 minutes. A curator can run Phase 5 separately later via `--no-phase-1 --no-phase-2 --no-phase-3 --no-phase-4 ...` (or just by re-invoking these helpers directly).
- The user explicitly wants only the static-extraction names (some compliance / audit workflows require pure regex-derived data with no LLM-inferred fields). In that case `--no-phase-5` plus the Phase-2/3/4 opt-outs gives a fully-deterministic Phase-1-only output.
- The Unknowns are concentrated under an SDK the curator has already decided to identify by hand (e.g. they have non-public vendor docs). The agent should ask before doing redundant work in this case.

## Phase 6 — self-improve from the session's findings

Phases 2–5 produce a lot of value *for this session* (records get companies, URLs, names) but nothing about that improvement persists into the next first-pass on a fresh APK. Phase 6 closes that loop: it diffs the session's post-Phase-5 state against the Phase-1 placeholders and proposes additions to two caches inside `extract_clues.py` so the next first-pass starts smarter:

- **`KNOWN_NON_BLE_UUIDS`** — a set of UUID-shaped tokens Phase 5 confirmed are NOT BLE (Google Business Messages agent IDs in URLs, news-content topic IDs, Salesforce session IDs, etc.). Phase 1 drops these inside `filter_vendor_specific` before record creation. Empirically: this directly prevents the next scan of the same APK (or any APK that imports the same SDK / uses the same URL) from re-creating the false-positive record that Phase 5 just cleaned up.
- **`KNOWN_SDK_JAVA_PACKAGES`** — a dict mapping Java-package-prefix → SDK-company. When Phase 1 sees a UUID declared inside a Java package matching one of these prefixes (matched on dot boundaries, so `com.bluecats.sdk` matches `com.bluecats.sdk.beacons.internal` too), it attributes the UUID to the cached company on a single-APK basis — without waiting for the Phase-4 ≥3-host cluster threshold to fire. Each entry in this dict means "the next time we see a UUID in this Java package, we already know who shipped it."

Neither cache modifies `KNOWN_SDK_UUIDS` (that one is per-UUID and Phase 4/5 already maintain it). Phase 6 is one level above: it captures the *shape* of what Phase 5 just learned (this UUID isn't BLE; this Java package belongs to this SDK) and applies it as a deterministic rule for next time.

One helper script in `scripts/` makes this a 2-step recipe — propose + apply — parallel in structure to Phases 2/3/4/5:

### Step 6.1 — generate the proposed diff

```bash
python3 /Users/user/.claude/skills/apk-clues-extract/scripts/generate_phase6_improvements.py \
    /path/to/CLUES_data_LLM_Android_APK_search.json \
    /tmp/run-<corpus>-new-uuids.json
```

The script:

- Reads the session-output file to scope work to UUIDs *this run* added.
- For each session UUID whose `UUID_name` contains `NOT_A_BLE_UUID_FALSE_POSITIVE` (the standard marker Phase 5 sets for shape-but-not-BLE tokens) → proposes adding the UUID to `KNOWN_NON_BLE_UUIDS`, with the Phase-5 evidence note included as a code comment for future-curator context.
- For each session UUID whose `company` was upgraded out of the Phase-1 `"Third-party SDK code (declared in Java package `<pkg>`…)"` placeholder by Phase 4/5 → proposes adding (`<pkg>` → `<company>`) to `KNOWN_SDK_JAVA_PACKAGES`. The package prefix is trimmed to its deepest three components (`com.bluecats.sdk.beacons` → `com.bluecats.sdk`) so the prefix-match covers sub-packages.
- Skips entries already in either cache (no duplicates).
- Skips Java-package prefixes that are too generic to be safe identifiers (single-letter packages, `com.android.*`, `androidx.*`, etc.).
- Prints to stdout a Python-snippet diff the agent pastes into `extract_clues.py`.

### Step 6.2 — apply the diff to `extract_clues.py`

The agent uses the Edit tool to insert each suggested entry into the corresponding dict/set in `extract_clues.py`. Two things to verify before pasting:

1. The Phase-5 evidence for any `NOT_A_BLE_UUID_FALSE_POSITIVE` entry is **explicitly cited** in the Phase-5 mapping JSON for this session (don't take Phase 5's word for it — re-read the cited line). False-positives caught in the wrong context (e.g., a UUID that's used both as a BLE characteristic AND as a URL fragment) would break future scans.
2. The Java-package prefix is **distinctively the SDK**, not a host-app pattern. `com.bluecats.sdk` is fine; `com.app.ble` is not — the latter is a generic name any app could declare.

After pasting, the agent runs `python3 extract_clues.py --self-test` to confirm no regressions and `check-jsonschema` on the CLUES output to confirm the JSON still validates (it should, because the new caches only affect *future* Phase-1 runs, not the current output).

### Worked example — what Phase 6 would have done on the 0008+0009 session

On the May 2026 0008+0009 corpus, Phase 5 marked two records as `NOT_A_BLE_UUID_FALSE_POSITIVE` and identified ~10 distinct third-party SDK Java packages. Without Phase 6, the next scan of `com.simplisafe.mobile` would re-create the same `226cc854-…` false-positive record, and the next scan of an APK bundling BlueCats would re-emit "Third-party SDK code (Phase-4 identification needed)" for every BlueCats UUID. With Phase 6:

- The two false-positive UUIDs go into `KNOWN_NON_BLE_UUIDS` — `filter_vendor_specific` drops them at the source, no record is created.
- `com.bluecats.sdk` → `BlueCats …`, `com.tesa.tesalocklibrary` → `TESA …`, `com.elatec.mobilebadge` → `Elatec …`, etc. go into `KNOWN_SDK_JAVA_PACKAGES` — the next BlueCats-bundling host app gets the BlueCats company name on its UUIDs *immediately*, with no Phase-4 cluster needed.

### Opt-out conditions (Phase 6)

Phase 6 runs by default. Skip it via `--no-phase-6` (or `--phase1-only`) when:

- The user is doing a **read-only audit** of the skill and doesn't want `extract_clues.py` modified.
- The session ran on **a single APK** the user doesn't trust enough to generalize from (e.g., a custom in-house build that uses non-standard Java-package conventions). Phase 6's cache entries are load-bearing — every future scan relies on them — so quality > quantity.
- The user wants **strict reproducibility** of the skill's behavior across runs (e.g., for a research paper comparing different extractor versions). Phase 6 mutates the extractor, so re-running on the same APK after Phase 6 may produce slightly different output (fewer false-positives, better SDK attribution). In that case, snapshot `extract_clues.py` before running the experiment.

## Post-flight — canonical sort with `SortCLUES.py`

After Phase 6 finishes (and before the final schema validation), the agent runs the project-standard sort script that normalizes every CLUES data file in `CLUES_Schema/data/`:

```bash
python3 /Users/user/Blue2thprinting/Analysis/CLUES_Schema/scripts/SortCLUES.py
```

This script takes no arguments — it sorts all three data files in `CLUES_Schema/data/` in-place:

- `CLUES_data_human_verified.json` (the hand-curated canonical file)
- `CLUES_data_LLM_Android_APK_search.json` (this skill's output)
- `CLUES_data_LLM_web_search.json` (the sibling web-search skill's output)

What it does (per the script header):

1. Lowercases every `UUID` and `parent_UUID`.
2. Sorts entries by `(company, UUID_purpose, UUID)` — so all of a vendor's records appear together, in the same order across files.
3. Groups child characteristics under their `parent_UUID` service, with children sub-sorted by UUID.
4. Re-writes each file with `indent=4`, `ensure_ascii=False`.

Why run it from this skill at all (it lives in a sibling repo): the project's git diffs become much smaller and more reviewable when every commit lands in the same canonical order. Without the sort, every Phase-2/4/5 patch leaves entries in arbitrary apply-order, making `git diff` noisy and merge-conflict-prone. The sort is idempotent — re-running on already-sorted files is a no-op on disk content (just touches mtime).

**Concurrency caveat.** The script overwrites the same files Phase 1's worker pool writes to. Run it **only after Phase 6 completes**, never concurrently with an active Phase-1 run, or you may overwrite in-progress data with a stale sort.

**Opt-out.** Skip via `--no-sort` (or `--phase1-only`) when:
- You're going to manually edit the file before commit and don't want the script's grouping to interfere.
- The sibling files (`CLUES_data_human_verified.json` / `CLUES_data_LLM_web_search.json`) have uncommitted hand-edits the user wants preserved as-is — `SortCLUES.py` would re-sort them too.

## Validation

After running on any set of APKs, validate the output against the schema:

```bash
cd /Users/user/Blue2thprinting/Analysis/CLUES_Schema/
source venv/bin/activate
check-jsonschema --verbose --base-uri ./CLUES_schema.json \
    --schemafile ./CLUES_schema.json ./data/CLUES_data_LLM_Android_APK_search.json
```

A clean run prints `ok -- validation done`. Failures usually indicate either a malformed UUID (e.g. a 16-byte UUID that lost a hex digit during regex extraction) or a record missing one of the required fields. The script's unit-test mode (`--self-test`) exercises the regex and classifier on synthetic input — run it once after editing the extractor to catch regressions before pointing at real APKs.

## Things that intentionally do NOT happen

- **No iOS `.ipa` support.** The schema's `android_info_array` is Android-only; iOS UUID extraction is a different skill.
- **No automatic company-name guessing.** The package_id is captured verbatim into `android_info_array`; populating `company` / `UUID_name` is a human task.
- **No advertisement-data scraping.** Even though `adv_data_type_array` / `adv_data_type_str_array` are in the schema, the extractor has no way to know from static decompilation whether a UUID actually shows up on the air. Those fields are omitted.
- **No deobfuscation beyond jadx's defaults.** Heavily obfuscated apps (ProGuard / R8 / DexGuard with string encryption) may hide UUIDs entirely. The script logs the file as "0 UUIDs found" rather than guessing.
- **No value-set analysis / call-graph reconstruction.** UTDallas's [BLEScope](https://github.com/zuosi/BLE-Scope) (Soot-based VSA + backward slicing, ~2019) can recover a UUID that is assembled at runtime from string concatenation, `getString(R.string.foo)` resource lookups, or a `new UUID(longHi, longLo)` constructor. This skill cannot — it is a regex pass over decompiled source. Empirical comparison on `/Volumes/2TB_ExFAT/__BLUUID_APKS/0000` (12 APKs): this skill matched BLEScope on every package where BLEScope produced output, while also picking up the 5 packages where BLEScope crashed (e.g. on kotlinx-coroutine class shapes Soot 2.5 doesn't understand). If you ever encounter an APK that hides UUIDs behind `StringBuilder` concatenation, you'll want BLEScope; for everything else, jadx + regex + file-level scope is faster and more robust.
- **No mutation of `CLUES_data_human_verified.json`.** The skill only writes `data/CLUES_data_LLM_Android_APK_search.json`. Merging back into the canonical hand-curated file (`data/CLUES_data_human_verified.json`) is a separate review step.

## Failure modes & resume

- **jadx hangs or OOMs.** Some pathological APKs (very large dex, native obfuscators) make jadx burn 4 GB of heap. The script invokes jadx with a wall-clock timeout (default 30 minutes per APK; configurable via `--jadx-timeout-sec`). Timed-out APKs are logged with `status: jadx_timeout` and skipped.
- **aapt missing.** The script prints `ERROR: aapt not found on PATH or under /opt/homebrew/share/android-commandlinetools/build-tools/*/aapt` and exits 2. Install with `brew install android-commandlinetools`.
- **Output file already has entries.** The extractor loads them, de-dupes by UUID, and merges `android_info_array`. Re-running the skill on the same folder is safe and idempotent.
- **Interrupted mid-folder.** The script writes the output file **after each APK**, so killing it (Ctrl-C, OOM, lid-close) loses at most the in-progress APK. The next invocation will re-process that APK because there's no per-package checkpoint other than the JSON itself — and that re-processing is cheap because the merge is idempotent.
