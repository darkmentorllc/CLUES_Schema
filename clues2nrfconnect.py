#!/usr/bin/env python3
"""
Simple CLUES → nRF Connect UUID JSON converter.

Edit the two variables under the CONFIG section:
  INPUT_FILE  — path to your CLUES-style JSON file
  OUTPUT_FILE — path where you want the nRF UUID JSON written

Limitations and Behavior:
- Produces a list of objects with nrf-connect required fields: uuid, name, identifier, source.
- For any input keys that are not mapped into the nRF format, their VALUES are
  appended into the `source` string. 
- UUIDs with non hex are dropped for time being.

Author: Abdullah Ada <A@d4ha.com>
Created:       2025-09-19
Last Modified: 2025-09-20
"""

# --- CONFIG: set your paths here ---
INPUT_FILE = "CLUES_data.json"
OUTPUT_FILE = "nrf_uuids.json"
# -----------------------------------

import json
import re
from typing import Any, Dict, Iterable, List, Tuple, Union

Scalar = Union[str, int, float, bool]

UUID16_RE = re.compile(r'^[0-9a-fA-F]{4}$')
UUID128_RE = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)

def load_entries(obj: Any) -> List[Dict[str, Any]]:
    """
    Normalize various CLUES-like containers into a flat list of entry dicts.
    Handles:
      - top-level list of entries
      - top-level dict with array under: data/uuids/entries/items/attributes
      - top-level dict keyed by UUID (value is entry dict)
    """
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        for key in ("data", "uuids", "entries", "items", "attributes"):
            if key in obj and isinstance(obj[key], list):
                return [x for x in obj[key] if isinstance(x, dict)]
        # dict keyed by uuid
        if all(isinstance(k, str) and isinstance(v, dict) for k, v in obj.items()):
            out = []
            for k, v in obj.items():
                v = dict(v)
                v.setdefault("uuid", k)
                out.append(v)
            return out
    return []

def normalize_uuid(entry: Dict[str, Any]) -> Tuple[str | None, List[str]]:
    """
    Extract and normalize a UUID string (accepts common field variants).
    Returns (uuid, keys_used).
    """
    candidates_keys = [
        "uuid", "UUID", "Uuid",
        "uuid128", "UUID128", "uuid_128",
        "uuid16", "UUID16", "uuid_16",
        "id", "gatt_uuid", "gattUuid",
    ]
    found_key = None
    val = None
    for k in candidates_keys:
        if k in entry:
            found_key = k
            val = entry[k]
            break
    if val is None:
        return None, []

    if isinstance(val, int):
        s = f"{val:04x}" if val <= 0xFFFF else str(val)
    else:
        s = str(val).strip()

    s = s.strip("{}").lower()

    # Compact hex only? Normalize to either 16-bit or hyphenated 128-bit.
    s_hex = re.sub(r'[^0-9a-fA-F]', '', s)
    if len(s_hex) == 4 and all(c in "0123456789abcdef" for c in s_hex):
        s = s_hex
    elif len(s_hex) == 32 and "-" not in s:
        s = f"{s_hex[0:8]}-{s_hex[8:12]}-{s_hex[12:16]}-{s_hex[16:20]}-{s_hex[20:32]}"

    return s, ([found_key] if found_key else [])

def pick_name(entry: Dict[str, Any]) -> Tuple[str | None, List[str]]:
    """Choose a human-friendly name."""
    for k in ("name", "Name", "label", "title", "short_name", "display_name", "names"):
        if k in entry:
            v = entry[k]
            if isinstance(v, list) and v:
                return str(v[0]), [k]
            return str(v), [k]
    for k in ("description", "desc", "info"):
        if k in entry and isinstance(entry[k], str):
            text = entry[k].strip().splitlines()[0][:64]
            return text, [k]
    return None, []

def slugify(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r'[^a-z0-9]+', '.', s)
    s = re.sub(r'\.+', '.', s).strip('.')
    return s or "unknown"

def reverse_dns_from(entry: Dict[str, Any]) -> Tuple[str | None, List[str]]:
    """
    Derive a reverse-DNS base from common vendor/domain hints.
    """
    for k in ("identifier_base", "reverse_domain", "reverse_dns", "namespace",
              "domain", "org", "organization", "company", "vendor"):
        if k in entry and isinstance(entry[k], str) and entry[k].strip():
            base = entry[k].strip().lower()
            # If forward domain like example.com, flip to com.example
            if re.match(r'^[a-z0-9-]+\.[a-z0-9-.]+$', base) and not base.startswith(
                ("com.", "org.", "net.", "io.", "edu.")
            ):
                parts = [p for p in base.split(".") if p]
                base = ".".join(reversed(parts))
            base = re.sub(r'[^a-z0-9.]+', '', base)
            return base, [k]
    return None, []

def pick_type(entry: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Guess attribute type: service | characteristic | descriptor | attribute."""
    for k in ("gatt_type", "type", "kind", "attribute_type"):
        if k in entry:
            v = str(entry[k]).lower()
            if any(t in v for t in ("service", "srv")):
                return "service", [k]
            if any(t in v for t in ("characteristic", "char", "chrc")):
                return "characteristic", [k]
            if any(t in v for t in ("descriptor", "descr", "desc")):
                return "descriptor", [k]
            return slugify(v), [k]
    return "attribute", []

def pick_generic(entry: Dict[str, Any]) -> Tuple[str | None, List[str]]:
    for k in ("category", "use", "role", "purpose", "profile", "group"):
        if k in entry and isinstance(entry[k], str):
            return slugify(entry[k]), [k]
    return None, []

def pick_identifier(entry: Dict[str, Any], name: str | None, ty: str) -> Tuple[str, List[str]]:
    """Use provided identifier if present; otherwise synthesize one."""
    for k in ("identifier", "uti", "uniform_type_identifier"):
        if k in entry and isinstance(entry[k], str) and entry[k].strip():
            return entry[k], [k]
    base, used1 = reverse_dns_from(entry)
    gen, used2 = pick_generic(entry)
    specific = slugify(name or "") if name else None
    if not base:
        base = "com.unknown"
    if not gen:
        gen = "generic"
    if not specific:
        specific = ty
    ident = f"{base}.{ty}.{gen}.{specific}"
    return ident, (used1 + used2)

def pick_source(entry: Dict[str, Any]) -> Tuple[str | None, List[str]]:
    for k in ("source", "origin", "spec", "specification", "defined_by"):
        if k in entry and entry[k]:
            return str(entry[k]), [k]
    return None, []

def is_valid_uuid(s: str) -> bool:
    return bool(UUID16_RE.match(s) or UUID128_RE.match(s))

def flatten_scalar_values(value: Any) -> List[str]:
    """
    Collect values (str/int/float/bool) from nested structures,
    returning them as strings. 
    """
    out: List[str] = []
    if isinstance(value, (str, int, float, bool)):
        out.append(str(value))
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(flatten_scalar_values(v))
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            out.extend(flatten_scalar_values(v))
    # Ignore other types (None, objects)
    return out

def sanitize_piece(s: str) -> str:
    """
    Clean separator characters so the source field stays a simple string.
    """
    s = s.replace("\n", " ").replace("\r", " ")
    s = s.replace(";", " ").strip()
    return re.sub(r"\s+", " ", s)

def convert_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    used_keys: List[str] = []
    out: Dict[str, Any] = {}

    uuid, ukeys = normalize_uuid(entry)
    used_keys += ukeys
    out["uuid"] = uuid or ""

    name, nkeys = pick_name(entry)
    used_keys += nkeys
    out["name"] = name or (uuid or "unknown")

    ty, tkeys = pick_type(entry)
    used_keys += tkeys

    ident, ikeys = pick_identifier(entry, name, ty)
    used_keys += ikeys
    out["identifier"] = ident

    src, skeys = pick_source(entry)
    used_keys += skeys
    base_source = src or "unknown"

    # Collect *unmapped* fields and append ONLY THEIR VALUES into source.
    extras_values: List[str] = []
    for k, v in entry.items():
        if k not in set(used_keys):
            extras_values.extend(flatten_scalar_values(v))

    pieces = [sanitize_piece(str(base_source))] if base_source else []
    pieces += [sanitize_piece(s) for s in extras_values if s is not None and str(s).strip() != ""]

    if not pieces:
        pieces = ["unknown"]

    out["source"] = "; ".join(pieces)
    return out

def convert(obj: Any) -> List[Dict[str, Any]]:
    entries = load_entries(obj)
    return [convert_entry(e) for e in entries]

def convert_file(input_path: str, output_path: str) -> None:
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out_list = convert(data)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(out_list, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    convert_file(INPUT_FILE, OUTPUT_FILE)
    print(f"Wrote nRF UUID definitions to: {OUTPUT_FILE}")
