#!/usr/bin/env python3
"""
CLUES → nRF Connect UUID JSON converter

Usage:
    python3 script.py <input.json> <output.json>


Converts Clues data into a NRF Connect json format.

Author: Abdullah Ada <A@d4ha.com>
Created:       2025-09-19
Last Modified: 2026-01-07
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
    out: List[Dict[str, Any]] = []

    if isinstance(obj, list):
        for x in obj:
            if isinstance(x, dict):
                out.append(x)
        return out

    if isinstance(obj, dict):
        container_keys = (
            "services", "service", "service_uuids", "serviceUuids",
            "characteristics", "characteristic", "characteristic_uuids", "characteristicUuids",
            "descriptors", "descriptor", "descriptor_uuids", "descriptorUuids",
            "data", "uuids", "entries", "items", "attributes",
        )

        for key in container_keys:
            if key in obj and isinstance(obj[key], list):
                for x in obj[key]:
                    if isinstance(x, dict):
                        y = dict(x)
                        y.setdefault("__container_key", key)
                        out.append(y)

        if out:
            return out

        if all(isinstance(k, str) and isinstance(v, dict) for k, v in obj.items()):
            for k, v in obj.items():
                v = dict(v)
                v.setdefault("uuid", k)
                out.append(v)
            return out

    return []

def extract_uuid(entry: Dict[str, Any]) -> Optional[str]:
    """Return raw UUID string if present, else None."""
    for k in ("uuid", "UUID", "Uuid", "uuid128", "UUID128", "uuid_128",
              "uuid16", "UUID16", "uuid_16", "id", "gatt_uuid", "gattUuid", "uuidValue", "uuid_value"):
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

    if len(s_hex) == 4:
        return "uuid16", s_hex.upper()

    if len(s_hex) == 32:
        return "uuid128", s_hex.lower()

    if UUID128_RE.match(s):
        s_hex = re.sub(r'[^0-9a-fA-F]', '', s)
        return "uuid128", s_hex.lower()

    try:
        n = int(s, 0)
        if 0 <= n <= 0xFFFF:
            return "uuid16", f"{n:04X}"
    except Exception:
        pass

    s_hex = (s_hex + "0"*32)[:32]
    return "uuid128", s_hex.lower()

def pick_name(entry: Dict[str, Any]) -> str:
    """
    pick a readable/user friendly output name
    """
    company_raw = (entry.get("company") or "").strip()
    if not company_raw:
        company_raw = "Unknown company"

    uuid_name_raw = (entry.get("UUID_name") or "").strip()
    if not uuid_name_raw:
        uuid_name_raw = "Unknown"

    return f"{company_raw} - {uuid_name_raw}"

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

def usage_array_type_hint(entry: Dict[str, Any]) -> Optional[str]:
    ua = entry.get("UUID_usage_array")
    if not isinstance(ua, list):
        return None
    tokens: List[str] = []
    for x in ua:
        if x is None:
            continue
        s = str(x).strip().lower()
        if s:
            tokens.append(s)
    joined = " | ".join(tokens)
    if "gatt descriptor" in joined or "descriptor" in joined:
        return "descriptor"
    if "gatt characteristic" in joined or "characteristic" in joined:
        return "characteristic"
    if "gatt service" in joined or "service" in joined:
        return "service"
    if "advert" in joined or "adv" in joined or "broadcast" in joined:
        return "service"
    return None

def declaration_type_hint(entry: Dict[str, Any]) -> Optional[str]:
    for k in (
        "declaration_uuid", "declarationUuid", "declaration", "att_type", "attType",
        "att_uuid", "attUuid", "attribute_type_uuid16", "attributeTypeUuid16",
        "attribute_type", "attributeType", "attribute_uuid", "attributeUuid",
        "gatt_declaration_uuid", "gattDeclarationUuid",
    ):
        if k in entry and entry[k] is not None and str(entry[k]).strip():
            raw = str(entry[k]).strip().strip("{}")
            kind, key = normalize_uuid_key(raw)
            if kind != "uuid16":
                continue
            try:
                n = int(key, 16)
            except Exception:
                continue
            if n in (0x2800, 0x2801):
                return "service"
            if n == 0x2803:
                return "characteristic"
            if 0x2900 <= n <= 0x29FF:
                return "descriptor"
    return None

def explicit_type_hint(entry: Dict[str, Any]) -> Optional[str]:
    """Return 'service'/'characteristic'/'descriptor' if clearly indicated by fields."""
    uh = usage_array_type_hint(entry)
    if uh:
        return uh

    dh = declaration_type_hint(entry)
    if dh:
        return dh

    if entry.get("parent_UUID") or entry.get("parent_uuid") or entry.get("parentUuid"):
        return "characteristic"

    container = (entry.get("__container_key") or "")
    if container:
        c = str(container).lower()
        if "char" in c:
            return "characteristic"
        if "desc" in c:
            return "descriptor"
        if "serv" in c:
            return "service"

    for k in ("gatt_type", "type", "kind", "attribute_type", "uuid_type", "UUID_type", "category", "gattCategory", "profile", "profile_type"):
        if k in entry and entry[k]:
            v = str(entry[k]).lower()
            if "org.bluetooth.service" in v or ".service." in v or v.endswith(".service") or "service" in v or v == "srv":
                return "service"
            if "org.bluetooth.characteristic" in v or ".characteristic." in v or v.endswith(".characteristic") or "characteristic" in v or v in ("char", "chrc"):
                return "characteristic"
            if "org.bluetooth.descriptor" in v or ".descriptor." in v or v.endswith(".descriptor") or "descriptor" in v or v in ("descr", "desc"):
                return "descriptor"
    return None

def characteristic_field_hint(entry: Dict[str, Any]) -> bool:
    for k in (
        "properties", "props", "characteristic_properties", "characteristicProperties",
        "flags", "permissions", "perm", "security",
        "read", "write", "notify", "indicate", "broadcast", "write_without_response", "writeWithoutResponse",
        "readable", "writable", "notifiable", "indicatable",
        "value_format", "valueFormat", "value_type", "valueType",
    ):
        if k in entry and entry[k] not in (None, "", [], {}):
            return True
    return False

def service_field_hint(entry: Dict[str, Any]) -> bool:
    for k in (
        "primary", "secondary", "is_primary", "isPrimary", "service_type", "serviceType",
        "included_services", "includedServices", "includes", "include", "characteristics",
        "start_handle", "startHandle", "end_handle", "endHandle",
    ):
        if k in entry and entry[k] not in (None, "", [], {}):
            return True
    return False

def classify(uuid_kind: str, uuid_key: str, name: str, entry: Dict[str, Any]) -> str:
    """
    Classify as 'service' | 'characteristic' | 'descriptor'.
    Priority: explicit field hint → 16-bit ranges → field heuristics → name keyword → defaults.
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
        if uuid_key.upper().startswith("2"):
            return "characteristic"
        return "service"

    if characteristic_field_hint(entry) and not service_field_hint(entry):
        return "characteristic"
    if service_field_hint(entry) and not characteristic_field_hint(entry):
        return "service"

    lname = (name or "").lower()
    if "descriptor" in lname:
        return "descriptor"
    if "characteristic" in lname:
        return "characteristic"
    if "service" in lname:
        return "service"

    return "characteristic"

def build_output_skeleton() -> Dict[str, Any]:
    return {
        "_comment": [
            "CLUES converted to nrfconnect format."
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
    else:
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
            continue

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
