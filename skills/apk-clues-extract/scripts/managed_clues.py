#!/usr/bin/env python3
"""Bounded .NET/Xamarin APK follow-up for the Java/JADX CLUES extractor.

This is deliberately a second pass: it inspects managed assemblies only when
the APK contains them, and emits records only when C# source connects a UUID
to a BLE service or characteristic. It does not run or load APK code.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import uuid as uuidlib
import zipfile

from corpus_paths import compact_package_path
import predecompiled_nonjava


UUID_TEXT_RE = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
GUID_DECL_RE = re.compile(
    r"\b(?P<field>[A-Za-z_][A-Za-z_0-9]*)\s*=\s*"
    r"(?:new\s+Guid|Guid\.Parse|Guid\.ParseExact)\s*\(\s*\"(?P<uuid>[0-9a-fA-F-]{36})\""
)
BYTE_SERVICE_RE = re.compile(
    r"\b(?:byte\[\]|byte\s*\[\s*\])\s+"
    r"(?P<field>[A-Za-z_][A-Za-z_0-9]*SERVICE_UUID)\s*=\s*"
    r"new\s+byte\s*\[\s*16\s*\]\s*\{(?P<values>[^}]+)\}",
    re.IGNORECASE | re.DOTALL,
)
BLE_CONTEXT_RE = re.compile(
    r"ICharacteristic|IService|BluetoothGatt|GetServices?Async|"
    r"GetCharacteristics?Async|AdvertisementRecord|ScanRecord|Plugin\.BLE",
    re.IGNORECASE,
)
CHAR_USE_RE = re.compile(r"ICharacteristic|GetCharacteristic|Characteristic\.Id|CharacteristicsAsync", re.I)
SERVICE_USE_RE = re.compile(r"IService|GetService|ServicesAsync|UuidsComplete128Bit", re.I)
ASCII_UUID_RE = re.compile(rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
UTF16_UUID_RE = re.compile(
    b"".join(b"[0-9a-fA-F]\\x00" if c == ord("0") else bytes((c, 0))
             for c in b"00000000-0000-0000-0000-000000000000")
)
MAX_DLL_BYTES = 256 * 1024 * 1024
MAX_TOTAL_ASSEMBLY_BYTES = 512 * 1024 * 1024
MAX_DECOMPILED_ASSEMBLIES = 48
FRAMEWORK_ASSEMBLY_PREFIXES = (
    "system.", "microsoft.", "xamarin.", "mono.", "netstandard", "java.",
    "androidx.", "google.", "firebase", "newtonsoft.", "syncfusion.",
    "bitmiracle.", "skia", "sqlite", "zxing", "communitytoolkit.",
)


class ManagedScanError(Exception):
    pass


def managed_kind(apk_path: str) -> str:
    """Return absent, direct, store, or invalid without extracting files."""
    try:
        with zipfile.ZipFile(apk_path) as apk:
            names = set(apk.namelist())
    except (OSError, zipfile.BadZipFile):
        return "invalid"
    if "assemblies/assemblies.blob" in names:
        return "store"
    if any(n.startswith("assemblies/") and n.lower().endswith(".dll") for n in names):
        return "direct"
    return "absent"


def _lz4_decompress(data: bytes, expected: int) -> bytes:
    if expected < 1 or expected > MAX_DLL_BYTES:
        raise ManagedScanError(f"unreasonable LZ4 output size {expected}")
    paths = [ctypes.util.find_library("lz4"), "/opt/homebrew/lib/liblz4.dylib",
             "/usr/local/lib/liblz4.so", "/usr/lib/x86_64-linux-gnu/liblz4.so.1"]
    lib = None
    for path in paths:
        if not path:
            continue
        try:
            lib = ctypes.CDLL(path)
            break
        except OSError:
            pass
    if lib is None:
        raise ManagedScanError("liblz4 is required to read compressed Xamarin assemblies")
    fn = lib.LZ4_decompress_safe
    fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    fn.restype = ctypes.c_int
    out = ctypes.create_string_buffer(expected)
    src = ctypes.create_string_buffer(data)
    got = fn(src, out, len(data), expected)
    if got != expected:
        raise ManagedScanError(f"LZ4 decompression returned {got}, expected {expected}")
    return out.raw


def _store_assemblies(apk: zipfile.ZipFile) -> list[tuple[str, bytes]]:
    names = set(apk.namelist())
    if "assemblies/assemblies.manifest" not in names:
        raise ManagedScanError("assemblies.blob has no assemblies.manifest")
    manifest: dict[tuple[int, int], str] = {}
    for line in apk.read("assemblies/assemblies.manifest").decode("utf-8", "replace").splitlines():
        parts = line.split(maxsplit=4)
        if len(parts) != 5 or parts[0] == "Hash":
            continue
        try:
            manifest[(int(parts[2]), int(parts[3]))] = parts[4]
        except ValueError:
            continue
    if not manifest:
        raise ManagedScanError("assemblies.manifest has no assembly entries")
    result: list[tuple[str, bytes]] = []
    for member in sorted(n for n in names if n.startswith("assemblies/") and n.endswith(".blob")):
        if apk.getinfo(member).file_size > MAX_TOTAL_ASSEMBLY_BYTES:
            raise ManagedScanError(f"oversized Xamarin store {member}")
        raw = apk.read(member)
        if len(raw) < 20 or raw[:4] != b"XABA":
            raise ManagedScanError(f"unsupported Xamarin store header in {member}")
        version, local_count, _global_count, store_id = struct.unpack_from("<IIII", raw, 4)
        if version > 1 or local_count > 10000 or 20 + 24 * local_count > len(raw):
            raise ManagedScanError(f"unsupported Xamarin store layout in {member}")
        for idx in range(local_count):
            name = manifest.get((store_id, idx))
            if not name:
                continue
            offset, size, _do, _ds, _co, _cs = struct.unpack_from("<IIIIII", raw, 20 + idx * 24)
            if size > MAX_DLL_BYTES or offset + size > len(raw):
                raise ManagedScanError(f"invalid assembly bounds for {name}")
            dll = raw[offset:offset + size]
            if dll[:4] == b"XALZ":
                if len(dll) < 12:
                    raise ManagedScanError(f"short compressed assembly {name}")
                dll = _lz4_decompress(dll[12:], struct.unpack_from("<I", dll, 8)[0])
            if dll[:2] != b"MZ":
                raise ManagedScanError(f"assembly {name} is not a PE DLL")
            result.append((name + ".dll", dll))
            if sum(len(data) for _name, data in result) > MAX_TOTAL_ASSEMBLY_BYTES:
                raise ManagedScanError("decoded managed assemblies exceed memory cap")
    if not result:
        raise ManagedScanError("no DLLs decoded from Xamarin assembly store")
    return result


def _assemblies(apk_path: str) -> list[tuple[str, bytes]]:
    staged = predecompiled_nonjava.load_assemblies(apk_path)
    if staged is not None:
        return staged
    with zipfile.ZipFile(apk_path) as apk:
        names = apk.namelist()
        if "assemblies/assemblies.blob" in names:
            return _store_assemblies(apk)
        result = []
        for n in names:
            if not (n.startswith("assemblies/") and n.lower().endswith(".dll")):
                continue
            if apk.getinfo(n).file_size > MAX_DLL_BYTES:
                raise ManagedScanError(f"oversized managed assembly {n}")
            result.append((n.removeprefix("assemblies/"), apk.read(n)))
            if sum(len(data) for _name, data in result) > MAX_TOTAL_ASSEMBLY_BYTES:
                raise ManagedScanError("managed assemblies exceed memory cap")
        return result


def _ilspy_path() -> str | None:
    override = os.environ.get("APK_CLUES_ILSPYCMD")
    if override:
        return override if os.path.isfile(override) and os.access(override, os.X_OK) else None
    return shutil.which("ilspycmd")


def _dotnet_env() -> dict[str, str]:
    env = os.environ.copy()
    if sys.platform == "darwin":
        # ILSpy uses .NET parallel work and otherwise sees all Mac cores.
        # Keep one managed scan small while the independent JADX worker runs.
        env.setdefault("DOTNET_PROCESSOR_COUNT", "2")
    if env.get("DOTNET_ROOT"):
        return env
    dotnet = shutil.which("dotnet")
    if dotnet:
        resolved = pathlib.Path(dotnet).resolve()
        homebrew_root = resolved.parent.parent / "libexec"
        if (homebrew_root / "shared").is_dir():
            env["DOTNET_ROOT"] = str(homebrew_root)
    return env


def _binary_has_guid(data: bytes) -> bool:
    return bool(ASCII_UUID_RE.search(data) or UTF16_UUID_RE.search(data))


def _app_tokens(package_id: str) -> set[str]:
    return {p.lower() for p in package_id.split(".")
            if len(p) >= 4 and p.lower() not in {"android", "mobile", "application"}}


# Narrow fallback for non-framework assemblies with explicit BLE API strings.
# `IService` alone is intentionally omitted: it is common in Microsoft DI APIs.
BLE_BINARY_MARKERS = (
    b"BluetoothGatt", b"GattCharacteristic", b"GattService",
    b"BluetoothLe", b"Plugin.BLE",
)

def _binary_has_ble_api(data: bytes) -> bool:
    lowered = data.lower()
    for marker in BLE_BINARY_MARKERS:
        value = marker.lower()
        if value in lowered or value.decode("ascii").encode("utf-16le") in lowered \
                or value.decode("ascii").encode("utf-16be") in lowered:
            return True
    return False

def _select_assemblies(assemblies: list[tuple[str, bytes]], package_id: str) -> list[tuple[str, bytes]]:
    tokens = _app_tokens(package_id)
    selected = []
    for name, data in assemblies:
        stem = pathlib.PurePosixPath(name).stem.lower()
        own = any(t in stem for t in tokens)
        framework = stem.startswith(FRAMEWORK_ASSEMBLY_PREFIXES)
        if not own and framework:
            continue
        # Keep existing app-name/UUID selection. As a conservative fallback,
        # include only non-framework assemblies with specific BLE API markers;
        # the existing 48-assembly cap still fails closed on broad matches.
        if own or _binary_has_guid(data) or (not framework and _binary_has_ble_api(data)):
            selected.append((name, data))
    selected.sort(key=lambda item: (not any(t in pathlib.PurePosixPath(item[0]).stem.lower()
                                             for t in tokens), item[0]))
    if len(selected) > MAX_DECOMPILED_ASSEMBLIES:
        raise ManagedScanError(
            f"{len(selected)} candidate assemblies exceed the {MAX_DECOMPILED_ASSEMBLIES} assembly cap"
        )
    return selected


def _record(value: str, field: str, role: str, assembly: str, source: str,
            meta: dict, apk_path: str, submitter: str, classification_source: str) -> dict:
    clean_name = re.sub(r"_UUID$", "", field, flags=re.I)
    pkg = meta["package_id"]
    return {
        "UUID": value.lower(),
        "company": meta.get("inferred_company", "Unknown"),
        "UUID_name": clean_name or "Unknown",
        "UUID_purpose": (
            f"{role} observed in .NET managed assembly {assembly} of Android app {pkg}; "
            f"C# field `{field}`. Classification source: {classification_source}."
        ),
        "UUID_usage_array": [role],
        "evidence_array": [{
            "description": (
                f"Found in decompiled .NET assembly `{assembly}` of {pkg} "
                f"v{meta['version_name']} (versionCode {meta['version_code']}), "
                f"source `{source}`, field `{field}`. {classification_source}."
            ),
            "submitter": submitter,
        }],
        "android_info_array": [{
            "package_id": pkg,
            "version_code": meta["version_code"],
            "version_name": meta["version_name"],
            "package_path": compact_package_path(apk_path),
            "description": f"Detected by apk-clues-extract managed-code scan; usage '{role}'; C# field `{field}`.",
        }],
    }


def _ble_field_use(text: str, field: str, role: str, declaration_end: int) -> bool:
    """Require a use of this field near a role-specific BLE API or object."""
    for match in re.finditer(r"\b" + re.escape(field) + r"\b", text):
        if match.start() < declaration_end:
            continue
        context = text[max(0, match.start() - 260):match.end() + 180]
        if role == "GATT Service" and SERVICE_USE_RE.search(context):
            return True
        if role == "GATT Characteristic" and CHAR_USE_RE.search(context):
            return True
    return False


def _scan_sources(source_root: pathlib.Path, assembly: str, meta: dict,
                  apk_path: str, submitter: str, curated: set[str]) -> list[dict]:
    result: dict[str, dict] = {}
    for source in source_root.rglob("*.cs"):
        try:
            text = source.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not BLE_CONTEXT_RE.search(text):
            continue
        relative = str(source.relative_to(source_root))
        for match in GUID_DECL_RE.finditer(text):
            value = match.group("uuid").lower()
            if not UUID_TEXT_RE.fullmatch(value) or value in curated:
                continue
            field = match.group("field")
            if re.search(r"SERVICE|\bSVC\b", field, re.I) and _ble_field_use(
                text, field, "GATT Service", match.end()
            ):
                role = "GATT Service"
            elif re.search(
                r"CHAR|COMMAND|RESPONSE|CONTROL|PACKET|NOTIFY|WRITE|READ|TX|RX", field, re.I
            ) and _ble_field_use(text, field, "GATT Characteristic", match.end()):
                role = "GATT Characteristic"
            else:
                continue
            result.setdefault(value, _record(value, field, role, assembly, relative,
                                              meta, apk_path, submitter,
                                              "C# Guid field and BLE usage"))
        for match in BYTE_SERVICE_RE.finditer(text):
            field = match.group("field")
            if not (re.search(r"\b" + re.escape(field) + r"\b", text[match.end():])
                    and re.search(r"(?:Type\s*==\s*7|UuidsComplete128Bit|GetService)", text, re.I)):
                continue
            try:
                values = [int(part.strip(), 0) if part.strip().lower().startswith("0x")
                          else int(part.strip()) for part in match.group("values").split(",") if part.strip()]
                if len(values) != 16 or any(not 0 <= v <= 255 for v in values):
                    continue
                # This pattern is a canonical-order advertisement UUID byte
                # array (not the mixed-endian byte layout of new Guid(byte[])).
                value = str(uuidlib.UUID(bytes=bytes(values)))
            except (ValueError, TypeError):
                continue
            if value in curated:
                continue
            result.setdefault(value, _record(value, field, "GATT Service", assembly,
                                              relative, meta, apk_path, submitter,
                                              "16-byte advertisement service UUID and BLE use"))
    return list(result.values())


def scan_managed_apk(apk_path: str, meta: dict, submitter: str,
                     curated_uuids: set[str], tmp_root: str) -> tuple[str, list[dict]]:
    """Return (coverage status, records); never treat a failed managed pass as zero."""
    kind = managed_kind(apk_path)
    if kind == "absent":
        return "absent", []
    if kind == "invalid":
        return "error:invalid_zip", []
    ilspy = _ilspy_path()
    if not ilspy:
        return "unavailable:ilspycmd", []
    try:
        assemblies = _select_assemblies(_assemblies(apk_path), meta["package_id"])
        if not assemblies:
            return "unavailable:no_candidate_assembly", []
        work = pathlib.Path(tmp_root) / "managed"
        work.mkdir(parents=True, exist_ok=True)
        records: dict[str, dict] = {}
        for index, (name, data) in enumerate(assemblies):
            dll = work / f"{index:03d}.dll"
            dll.write_bytes(data)
            out = work / f"source_{index:03d}"
            proc = subprocess.run(
                [ilspy, "-p", "-o", str(out), str(dll)],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                text=True, timeout=max(1, int(os.environ.get("APK_CLUES_ILSPY_TIMEOUT_SEC", "180"))), env=_dotnet_env(), check=False,
            )
            if proc.returncode != 0:
                raise ManagedScanError(
                    f"ILSpy failed on {name}: {proc.stderr.strip()[:180]}"
                )
            for rec in _scan_sources(out, name, meta, apk_path, submitter,
                                     {u.lower() for u in curated_uuids}):
                records.setdefault(rec["UUID"], rec)
        return f"complete:{len(records)} assemblies={len(assemblies)}", list(records.values())
    except (ManagedScanError, OSError, zipfile.BadZipFile, subprocess.TimeoutExpired) as exc:
        return f"error:{type(exc).__name__}:{str(exc)[:160]}", []


def self_test() -> None:
    sample = b"\x00" + "6780bbd8-b910-4000-8bf5-09422a88992e".encode("utf-16le")
    assert _binary_has_guid(sample)
    assert not _binary_has_guid(b"ordinary managed library")
    assert len(BYTE_SERVICE_RE.findall(
        "byte[] GATEWAY_SERVICE_UUID = new byte[16] { 190, 152, 7, 110, 142, 141, 17, 232, 158, 182, 82, 146, 105, 251, 20, 89 };"
    )) == 1
