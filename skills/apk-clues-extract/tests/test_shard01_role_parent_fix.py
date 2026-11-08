import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


class RoleAndParentFixTests(unittest.TestCase):
    def test_setec_late_alias_roles_and_no_manufacturer_parent_guess(self):
        service = "0000fe0e-0000-1000-8000-00805f9b34fb"
        named_char = "03ab8a01-86f1-4094-bab8-f2882cdf255a"
        neutral_char_1 = "46ba2d15-b16a-11e8-96f8-529269fb1459"
        neutral_char_2 = "46ba2d1a-b16a-11e8-96f8-529269fb1459"
        source = f'''package fixture;
import java.util.UUID;
public final class GattCharacteristicsKt {{
    static UUID uuidManufacturerService;
    static UUID uuidCharacteristicRVCDiagnostic;
    static UUID uuidGeneralPurposeSwitchInputs;
    static UUID uuidSystemStatusState;
    static {{
        UUID uuidFromString = UUID.fromString("{service}");
        uuidManufacturerService = uuidFromString;
        UUID uuidFromString2 = UUID.fromString("{named_char}");
        uuidCharacteristicRVCDiagnostic = uuidFromString2;
        UUID uuidFromString3 = UUID.fromString("{neutral_char_1}");
        uuidGeneralPurposeSwitchInputs = uuidFromString3;
        UUID uuidFromString4 = UUID.fromString("{neutral_char_2}");
        uuidSystemStatusState = uuidFromString4;
    }}
}}
'''
        with tempfile.TemporaryDirectory(prefix="clues-setec-role-") as tmp:
            path = Path(tmp) / "GattCharacteristicsKt.java"
            path.write_text(source, encoding="utf-8")
            found = extractor.scan_one_file(str(path))

        self.assertEqual(found[service]["classification"], "GATT Service")
        self.assertEqual(found[named_char]["classification"], "GATT Characteristic")
        self.assertEqual(found[neutral_char_1]["classification"], "GATT Characteristic")
        self.assertEqual(found[neutral_char_2]["classification"], "GATT Characteristic")
        self.assertEqual(found[named_char]["parent_candidates"], [])
        self.assertEqual(found[neutral_char_1]["parent_candidates"], [])
        self.assertEqual(found[neutral_char_2]["parent_candidates"], [])

    def test_digitax_service_field_beats_weak_characteristic_fallback(self):
        service = "0003cdd0-0000-1000-8000-00805f9b0131"
        read_char = "0003cdd1-0000-1000-8000-00805f9b0131"
        write_char = "0003cdd2-0000-1000-8000-00805f9b0131"
        with tempfile.TemporaryDirectory(prefix="clues-digitax-role-") as tmp:
            root = Path(tmp)
            sources = root / "sources"
            weak = sources / "n8" / "c.java"
            typed = sources / "com" / "digitax" / "BluetoothLEChannel.java"
            weak.parent.mkdir(parents=True)
            typed.parent.mkdir(parents=True)
            weak.write_text(f'''package n8;
import android.bluetooth.BluetoothGattCharacteristic;
class c {{
    String F;
    BluetoothGattCharacteristic I;
    void init() {{ this.F = "{service}"; }}
}}
''', encoding="utf-8")
            typed.write_text(f'''package com.digitax;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothGattCharacteristic;
import java.util.UUID;
class BluetoothLEChannel {{
    static final String TAXIMETER_GATT_SERVICE = "{service}";
    static final String READ_GATT_CHARACTERISTIC = "{read_char}";
    static final String WRITE_GATT_CHARACTERISTIC = "{write_char}";
    // Keep the declarations outside the scanner's non-GATT context window.
    // The production source has a much larger class between constants/use.
    // spacer 1
    // spacer 2
    // spacer 3
    // spacer 4
    // spacer 5
    // spacer 6
    // spacer 7
    // spacer 8
    // spacer 9
    // spacer 10
    void discovered(BluetoothGattService next) {{
        if (next.getUuid().toString().equals(TAXIMETER_GATT_SERVICE)) {{
            next.getCharacteristic(UUID.fromString(READ_GATT_CHARACTERISTIC));
            next.getCharacteristic(UUID.fromString(WRITE_GATT_CHARACTERISTIC));
        }}
    }}
}}
''', encoding="utf-8")
            found = extractor.scan_jadx_output(str(root))

        self.assertEqual(found[service]["classification"], "GATT Service")
        self.assertEqual(found[read_char]["classification"], "GATT Characteristic")
        self.assertEqual(found[write_char]["classification"], "GATT Characteristic")
        # A matching TAXIMETER stem plus a getService call in this source file
        # is not enough to assign either characteristic to this service.
        for char_uuid in (read_char, write_char):
            self.assertEqual(found[char_uuid]["parent_candidates"], [])
        # The source-backed correction can still carry an explicit pair into
        # record construction; its target is checked against resolved roles.
        for char_uuid in (read_char, write_char):
            entry = dict(found[char_uuid], parent_candidates=[service])
            record = extractor.build_record(
                char_uuid, entry,
                {"package_id": "fixture", "version_name": "1", "version_code": 1},
                "fixture.apk", "test", "fixture",
                resolved_roles=extractor._resolved_uuid_roles(found),
            )
            self.assertEqual(record.get("parent_UUID"), service)

    def test_parent_candidate_must_resolve_to_final_service(self):
        char_uuid = "12345678-1234-5678-1234-567812345678"
        bad_parent = "22345678-1234-5678-1234-567812345678"
        entry = {
            "classification": "GATT Characteristic",
            "classification_source": "usage:getCharacteristic",
            "field_name": "DATA_CHARACTERISTIC",
            "parent_candidates": [bad_parent],
        }
        record = extractor.build_record(
            char_uuid, entry,
            {"package_id": "fixture", "version_name": "1", "version_code": 1},
            "fixture.apk", "test", "fixture",
            resolved_roles={bad_parent: "GATT Characteristic"},
        )
        self.assertNotIn("parent_UUID", record)

    @staticmethod
    def record(uuid, role, parent=None):
        rec = {
            "UUID": uuid,
            "company": "Fixture",
            "UUID_name": "DATA_CHARACTERISTIC" if role == "GATT Characteristic" else "DATA_SERVICE",
            "UUID_purpose": f"Custom {role} observed in fixture.",
            "UUID_usage_array": [role],
            "evidence_array": [{"description": "fixture evidence", "submitter": "test"}],
            "android_info_array": [{
                "package_id": "fixture", "version_code": 1,
                "version_name": "1", "package_path": "fixture.apk",
                "description": f"usage '{role}'",
            }],
        }
        if parent:
            rec["parent_UUID"] = parent
        return rec

    def test_merge_preserves_existing_parent_and_filters_invalid_new_parent(self):
        service = "b6e60001-e2e3-bc82-4c72-929d0d29ca17"
        char_one = "b6e60002-e2e3-bc82-4c72-929d0d29ca17"
        char_two = "b6e60003-e2e3-bc82-4c72-929d0d29ca17"
        existing = [
            self.record(service, "GATT Service"),
            self.record(char_one, "GATT Characteristic", service),
            self.record(char_two, "GATT Characteristic", char_one),
        ]
        cleaned = extractor.merge_records(existing, [])
        cleaned_char = next(r for r in cleaned if r["UUID"] == char_two)
        # Merging an empty batch must not rewrite a pre-existing record.
        self.assertEqual(cleaned_char.get("parent_UUID"), char_one)

        fresh = [
            self.record(service, "GATT Service"),
            self.record(char_one, "GATT Characteristic", service),
            self.record(char_two, "GATT Characteristic"),
        ]
        rejected = extractor.merge_records(
            fresh,
            [self.record(char_two, "GATT Characteristic", char_one)],
        )
        rejected_char = next(r for r in rejected if r["UUID"] == char_two)
        self.assertNotIn("parent_UUID", rejected_char)

        repaired = extractor.merge_records(
            fresh,
            [self.record(char_two, "GATT Characteristic", service)],
        )
        repaired_char = next(r for r in repaired if r["UUID"] == char_two)
        self.assertEqual(repaired_char.get("parent_UUID"), service)

    def test_ambiguous_role_evidence_is_not_overridden_by_a_weak_hint(self):
        entry = {
            "classification": "GATT Service",
            "classification_source": "ambiguous-usage",
        }
        extractor.merge_role_evidence(entry, "GATT Characteristic", "field-name:DATA_CHARACTERISTIC")
        self.assertEqual(entry["classification"], "GATT Service")
        self.assertEqual(entry["classification_source"], "ambiguous-usage")

    def test_minew_eee1_sdk_cache_role_and_name_are_service(self):
        hit = extractor.KNOWN_SDK_UUIDS["eee1"]
        self.assertIn("SERVICE", hit["name"])
        self.assertIn("service", hit["note"].lower())
        entry = {
            "classification": "GATT Characteristic",
            "classification_source": "file-level-default",
            "field_name": "f8933j",
            "parent_candidates": [],
        }
        record = extractor.build_record(
            "eee1", entry,
            {"package_id": "fixture", "version_name": "1", "version_code": 1},
            "fixture.apk", "test", "fixture",
        )
        self.assertEqual(record["UUID_usage_array"], ["GATT Service"])
        self.assertEqual(record["UUID_name"], "MINEW_DEVICE_SERVICE_EEE1")


if __name__ == "__main__":
    unittest.main()
