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
from typing import Any, Dict, List, Tuple, Union

Scalar = Union[str, int, float, bool]

UUID16_RE = re.compile(r'^[0-9a-fA-F]{4}$')
UUID128_RE = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)

def load_entries(obj: Any) -> List[Dict[str, Any]]:
    """Normalize common CLUES-like containers into a flat list of entry dicts."""
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
    """Extract and normalize a UUID string (accepts common field variants)."""
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

def slugify(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r'[^a-z0-9]+', '.', s)
    s = re.sub(r'\.+', '.', s).strip('.')
    return s or "unknown"

def reverse_dns_from(entry: Dict[str, Any]) -> Tuple[str | None, List[str]]:
    """Derive a reverse-DNS base from common vendor/domain hints."""
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
    """Use provided identifier if present; otherwise synthesize reverse-DNS identifier."""
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
    """Prefer explicit 'source', but accept a few common synonyms."""
    for k in ("source", "origin", "spec", "specification", "defined_by"):
        if k in entry and entry[k]:
            return str(entry[k]), [k]
    return None, []

def flatten_scalar_values(value: Any) -> List[str]:
    """Collect scalar values (str/int/float/bool) from nested structures."""
    out: List[str] = []
    if isinstance(value, (str, int, float, bool)):
        out.append(str(value))
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(flatten_scalar_values(v))
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            out.extend(flatten_scalar_values(v))
    return out

def sanitize_piece(s: str) -> str:
    """Keep `source` human-readable & single-line without JSON or delimiters."""
    s = s.replace("\n", " ").replace("\r", " ")
    s = s.replace(";", " ").strip()
    return re.sub(r"\s+", " ", s)

def convert_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    used_keys: List[str] = []
    out: Dict[str, Any] = {}

    # UUID
    uuid, ukeys = normalize_uuid(entry)
    used_keys += ukeys
    out["uuid"] = uuid or ""

    # NAME: from "UUID_name" (or "uuid_name"); if missing/empty → "unknown"
    name_val = None
    for nk in ("UUID_name", "uuid_name"):
        if nk in entry:
            raw = entry.get(nk)
            used_keys.append(nk)  # mark as used even if empty
            if raw is not None:
                s = str(raw).strip()
                if s != "":
                    name_val = s
            break
    out["name"] = name_val if name_val is not None else "unknown"

    # IDENTIFIER (use provided or synthesize)
    ty, tkeys = pick_type(entry)
    used_keys += tkeys
    ident, ikeys = pick_identifier(entry, out["name"] or None, ty)
    used_keys += ikeys
    out["identifier"] = ident

    # SOURCE (build without ever including "unknown")
    src, skeys = pick_source(entry)
    used_keys += skeys
    base_source = src.strip() if isinstance(src, str) else ""

    pieces: List[str] = []
    if base_source and base_source.lower() != "unknown":
        pieces.append(sanitize_piece(base_source))

    # Insert "Author" followed by submitter value(s), if any
    if "submitter" in entry:
        used_keys.append("submitter")
        submit_vals = [
            sanitize_piece(v) for v in flatten_scalar_values(entry["submitter"])
            if str(v).strip() and str(v).strip().lower() != "unknown"
        ]
        if submit_vals:
            pieces.append("Author")
            pieces.extend(submit_vals)

    # Append VALUES of all *unmapped* fields (excluding submitter), skipping "unknown"
    used_set = set(used_keys)
    for k, v in entry.items():
        if k not in used_set:
            for s in flatten_scalar_values(v):
                s = sanitize_piece(s)
                if s and s.lower() != "unknown":
                    pieces.append(s)

    # Deduplicate while preserving order
    seen = set()
    uniq_pieces: List[str] = []
    for p in pieces:
        if p not in seen:
            uniq_pieces.append(p)
            seen.add(p)

    out["source"] = "; ".join(uniq_pieces)

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

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.json> <output.json>", file=sys.stderr)
        sys.exit(1)
    input_path, output_path = sys.argv[1], sys.argv[2]
    convert_file(input_path, output_path)
    print(f"Wrote nRF UUID definitions to: {output_path}")

if __name__ == "__main__":
    main()
