#!/usr/bin/env python3
"""
CLUES → nRF Connect UUID JSON converter

Usage:
    python3 script.py <input.json> <output.json>

Limitations and Behavior:
- Produces a list of objects with nrf-connect required fields: uuid, name, identifier, source.
- For any input keys that are not mapped into the nRF format, their VALUES are
  appended into the `source` string. 
- UUIDs with non hex are dropped for time being.

Author: Abdullah Ada <A@d4ha.com>
Created:       2025-09-19
Last Modified: 2025-09-21
"""

import sys
import json
import re
from typing import Any, Dict, List, Tuple, Optional

UUID16_RE = re.compile(r'^[0-9a-fA-F]{4}$')
UUID128_RE = re.compile(
    r'^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$'
)

def load_entries(obj: Any) -> List[Dict[str, Any]]:
    """Flatten common CLUES-like containers into a list of entries."""
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        for key in ("data", "uuids", "entries", "items", "attributes"):
            if key in obj and isinstance(obj[key], list):
                return [x for x in obj[key] if isinstance(x, dict)]
        # dict keyed by UUID
        if all(isinstance(k, str) and isinstance(v, dict) for k, v in obj.items()):
            out = []
            for k, v in obj.items():
                v = dict(v)
                v.setdefault("uuid", k)
                out.append(v)
            return out
    return []

def extract_uuid(entry: Dict[str, Any]) -> Optional[str]:
    """Return raw UUID string if present, else None."""
    for k in ("uuid", "UUID", "Uuid", "uuid128", "UUID128", "uuid_128",
              "uuid16", "UUID16", "uuid_16", "id", "gatt_uuid", "gattUuid"):
        if k in entry:
            v = entry[k]
            if v is None:
                continue
            s = str(v).strip().strip("{}")
            return s
    return None

def normalize_uuid_key(raw: str) -> Tuple[str, str]:
    """
    Normalize a UUID into a (kind, key) pair:
      kind = "uuid16" or "uuid128"
      key  = 4-digit UPPER hex (16-bit) or 32-digit lower hex without dashes (128-bit)
    """
    s = raw.strip()
    s_hex = re.sub(r'[^0-9a-fA-F]', '', s)

    # 16-bit if exactly 4 hex nibbles
    if len(s_hex) == 4:
        return "uuid16", s_hex.upper()

    # 128-bit (32 hex nibbles)
    if len(s_hex) == 32:
        return "uuid128", s_hex.lower()

    # Try to coerce e.g., hyphenated 128-bit to 32 hex
    if UUID128_RE.match(s):
        s_hex = re.sub(r'[^0-9a-fA-F]', '', s)
        return "uuid128", s_hex.lower()

    # If it's a number like 0x2A00 or decimal, try to coerce down to 16-bit when possible
    try:
        n = int(s, 0)  # auto base
        if 0 <= n <= 0xFFFF:
            return "uuid16", f"{n:04X}"
    except Exception:
        pass

    # Fallback: treat as 128-bit-like key (strip dashes), truncate/pad cautiously
    s_hex = (s_hex + "0"*32)[:32]
    return "uuid128", s_hex.lower()

def pick_name(entry: Dict[str, Any]) -> str:
    """Prefer 'UUID_name', else 'name'/'title'/'label' variants; default 'unknown'."""
    for k in ("UUID_name", "uuid_name", "name", "Name", "title", "label", "display_name"):
        if k in entry and entry[k] is not None:
            s = str(entry[k]).strip()
            if s:
                return s
    return "unknown"

def detect_format(entry: Dict[str, Any]) -> Optional[str]:
    """
    Return 'TEXT' if the entry suggests textual data; otherwise None.
    Looks at common hints: 'format', 'value_format', 'encoding', 'data_type'.
    """
    checks = []
    for k in ("format", "value_format", "encoding", "data_type"):
        if k in entry and entry[k] is not None:
            checks.append(str(entry[k]).strip().lower())
    joined = " ".join(checks)
    if any(tok in joined for tok in ("text", "string", "utf-8", "utf8", "ascii")):
        return "TEXT"
    return None

def explicit_type_hint(entry: Dict[str, Any]) -> Optional[str]:
    """Return 'service'/'characteristic'/'descriptor' if clearly indicated by fields."""
    for k in ("gatt_type", "type", "kind", "attribute_type"):
        if k in entry and entry[k]:
            v = str(entry[k]).lower()
            if "service" in v or v == "srv":
                return "service"
            if "characteristic" in v or v in ("char", "chrc"):
                return "characteristic"
            if "descriptor" in v or v in ("descr", "desc"):
                return "descriptor"
    return None

def classify(uuid_kind: str, uuid_key: str, name: str, entry: Dict[str, Any]) -> str:
    """
    Classify as 'service' | 'characteristic' | 'descriptor'.
    Priority: explicit field hint → 16-bit ranges → name keyword → defaults.
    """
    hint = explicit_type_hint(entry)
    if hint:
        return hint

    if uuid_kind == "uuid16":
        try:
            n = int(uuid_key, 16)
            if 0x2900 <= n <= 0x29FF:
                return "descriptor"
            if 0x2A00 <= n <= 0x2AFF:
                return "characteristic"
            if (0x1800 <= n <= 0x18FF) or (0xFD00 <= n <= 0xFEFF):
                return "service"
        except Exception:
            pass
        # reasonable default for other 0x2xxx is 'characteristic'
        if uuid_key.upper().startswith("2"):
            return "characteristic"
        return "service"

    # 128-bit: infer from name if possible
    lname = (name or "").lower()
    if "descriptor" in lname:
        return "descriptor"
    if "characteristic" in lname:
        return "characteristic"
    if "service" in lname:
        return "service"
    # default custom 128-bit to service
    return "service"

def build_output_skeleton() -> Dict[str, Any]:
    return {
        "_comment": [
            "Testing comment."
        ],
        "uuid16bitServiceDefinitions": {},
        "uuid128bitServiceDefinitions": {},
        "uuid16bitCharacteristicDefinitions": {},
        "uuid128bitCharacteristicDefinitions": {},
        "uuid16bitDescriptorDefinitions": {},
        "uuid128bitDescriptorDefinitions": {}
    }

def place_item(dst: Dict[str, Any], category: str, uuid_kind: str, uuid_key: str, name: str, fmt: Optional[str]) -> None:
    """Insert the item into the appropriate map."""
    record: Dict[str, Any] = {"name": name}
    if fmt == "TEXT":
        record["format"] = "TEXT"

    if category == "service":
        if uuid_kind == "uuid16":
            dst["uuid16bitServiceDefinitions"][uuid_key] = record
        else:
            dst["uuid128bitServiceDefinitions"][uuid_key] = record
    elif category == "characteristic":
        if uuid_kind == "uuid16":
            dst["uuid16bitCharacteristicDefinitions"][uuid_key] = record
        else:
            dst["uuid128bitCharacteristicDefinitions"][uuid_key] = record
    else:  # descriptor
        if uuid_kind == "uuid16":
            dst["uuid16bitDescriptorDefinitions"][uuid_key] = record
        else:
            dst["uuid128bitDescriptorDefinitions"][uuid_key] = record

def convert(obj: Any) -> Dict[str, Any]:
    out = build_output_skeleton()
    entries = load_entries(obj)
    for e in entries:
        raw_uuid = extract_uuid(e)
        if not raw_uuid:
            continue  # skip entries without UUID

        uuid_kind, uuid_key = normalize_uuid_key(raw_uuid)
        name = pick_name(e)
        fmt = detect_format(e)
        cat = classify(uuid_kind, uuid_key, name, e)
        place_item(out, cat, uuid_kind, uuid_key, name, fmt)
    return out

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.json> <output.json>", file=sys.stderr)
        sys.exit(1)
    input_path, output_path = sys.argv[1], sys.argv[2]
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out = convert(data)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=3)
    print(f"Wrote definitions-style JSON to: {output_path}")

if __name__ == "__main__":
    main()
