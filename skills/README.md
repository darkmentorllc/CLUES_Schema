# CLUES generation skills

These are the agent **skills** used to auto-generate the `CLUES_data_LLM_*` datasets in [`../data/`](../data/). They're published here so the data's provenance is reproducible: each skill is the exact tooling that produced its dataset.

| Skill | What it does | Produces |
| --- | --- | --- |
| [`apk-clues-extract/`](apk-clues-extract/) | Decompiles Android APKs with `jadx` and extracts vendor-specific GATT UUIDs from the Java source. | `data/CLUES_data_LLM_Android_APK_search_{0..f}.json` |
| [`web-clues-search/`](web-clues-search/) | Researches unidentified BLE/BTC UUID128 values via web search, GitHub Code Search, and OUI/vendor-pattern analysis. | `data/CLUES_data_LLM_web_search.json` |

## Installing

Agents load skills from a per-tool skills directory, so copy the skill folder(s) into the directory for the agent you use:

- **Claude Code** → `~/.claude/skills/`
- **OpenAI Codex** → `~/.codex/skills/`

Run the commands below from this `skills/` directory.

For **Claude Code**:

```bash
mkdir -p ~/.claude/skills
cp -R apk-clues-extract web-clues-search ~/.claude/skills/
```

For **OpenAI Codex**:

```bash
mkdir -p ~/.codex/skills
cp -R apk-clues-extract web-clues-search ~/.codex/skills/
```

Then start a new agent session so the skills are picked up.

To understand the usage of each skill, read the SKILL.md file.
