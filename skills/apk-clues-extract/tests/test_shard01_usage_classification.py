"""Regression coverage for the 2026-10-28 shard01 audit (GPT-6 Luna review)."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


class Shard01UsageClassificationTests(unittest.TestCase):
    def scan_one(self, source: str) -> dict[str, dict]:
        with tempfile.TemporaryDirectory(prefix="shard01-role-") as tmp:
            path = Path(tmp) / "BleSource.java"
            path.write_text(source, encoding="utf-8")
            return extractor.scan_one_file(str(path))

    def test_dineout_service_uuid_fields_follow_typed_gatt_service_uuid(self):
        source = '''package uc;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothGattCharacteristic;
class c {
    private static String f23512l = "064247ae-9857-4afc-ae59-119119067076";
    private static String f23513m = "76700619-9111-59ae-fc4a-5798ae474206";














    void discover() {
        BluetoothGattService next;
        String string = next.getUuid().toString();
        if (string.compareToIgnoreCase(f23512l) == 0 ||
            string.compareToIgnoreCase(f23513m) == 0) { }
    }
}
'''
        found = self.scan_one(source)
        for uuid in (
            "064247ae-9857-4afc-ae59-119119067076",
            "76700619-9111-59ae-fc4a-5798ae474206",
        ):
            with self.subTest(uuid=uuid):
                self.assertEqual(found[uuid]["classification"], "GATT Service")
                self.assertEqual(found[uuid]["classification_source"], "usage:getService")

    def test_truma_constructor_instance_uuid_reaches_get_service(self):
        source = '''package td;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothGattCharacteristic;
import java.util.UUID;
class h {
    final String f18041o;
    h() { this.f18041o = "0000fff0-0000-1000-8000-00805f9b34fb"; }
    BluetoothGattService connect(BluetoothGatt gatt) {
        return gatt.getService(UUID.fromString(this.f18041o));
    }
}
'''
        found = self.scan_one(source)
        uuid = "0000fff0-0000-1000-8000-00805f9b34fb"
        self.assertEqual(found[uuid]["classification"], "GATT Service")
        self.assertEqual(found[uuid]["field_name"], "f18041o")
        self.assertEqual(found[uuid]["classification_source"], "usage:getService")

    def test_truma_string_uuid_alias_reaches_characteristic_sink(self):
        service = "0000fff0-0000-1000-8000-00805f9b34fb"
        local_characteristic = "0000fff6-0000-1000-8000-00805f9b34fb"
        profile = f'''package td;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
class Profile {{
    final String serviceField;
    final String localCharField;
    Profile() {{
        this.serviceField = "{service}";
        this.localCharField = "{local_characteristic}";
    }}
    void connect(BluetoothGatt gatt) {{
        BluetoothGattService service = gatt.getService(UUID.fromString(this.serviceField));
        String alias = this.localCharField;
        UUID characteristicUuid = UUID.fromString(alias);
        service.getCharacteristic(characteristicUuid);
    }}
}}
'''
        with tempfile.TemporaryDirectory(prefix="shard01-truma-params-") as tmp:
            root = Path(tmp)
            (root / "sources/td").mkdir(parents=True)
            (root / "sources/td/Profile.java").write_text(profile, encoding="utf-8")
            found = extractor.scan_jadx_output(str(root))

        self.assertEqual(found[service]["classification"], "GATT Service")
        self.assertEqual(found[local_characteristic]["classification"], "GATT Characteristic")

    def test_cross_file_gate_accepts_lowercase_gatt_role_references(self):
        service = "abcde031-1111-2222-3333-444455556677"
        characteristic = "abcde032-1111-2222-3333-444455556677"
        unused = "abcde033-1111-2222-3333-444455556677"
        constants = f'''package sdk;
import java.util.UUID;
class Constants {{
    static final UUID f0 = UUID.fromString("{service}");
    static final UUID f1 = UUID.fromString("{characteristic}");
    static final UUID f2 = UUID.fromString("{unused}");
}}
'''
        service_consumer = '''package sdk;
class ServiceConsumer {
    void inspect(GattRef bluetoothGattService) {
        if (bluetoothGattService.getUuid().equals(Constants.f0));
    }
}
class GattRef {
    Object getUuid() { return null; }
}
'''
        characteristic_consumer = '''package sdk;
class CharacteristicConsumer {
    void inspect(GattRef bluetoothGattCharacteristic) {
        if (bluetoothGattCharacteristic.getUuid().equals(Constants.f1));
    }
}
class GattRef {
    Object getUuid() { return null; }
}
'''
        with tempfile.TemporaryDirectory(prefix="shard01-lowercase-gatt-") as tmp:
            root = Path(tmp)
            (root / "sources/sdk").mkdir(parents=True)
            (root / "sources/sdk/Constants.java").write_text(constants, encoding="utf-8")
            (root / "sources/sdk/ServiceConsumer.java").write_text(service_consumer, encoding="utf-8")
            (root / "sources/sdk/CharacteristicConsumer.java").write_text(characteristic_consumer, encoding="utf-8")
            found = extractor.scan_jadx_output(str(root))

        self.assertEqual(found[service]["classification"], "GATT Service")
        self.assertEqual(found[service]["classification_source"], "cross-file usage:getService(f0)")
        self.assertEqual(found[characteristic]["classification"], "GATT Characteristic")
        self.assertEqual(
            found[characteristic]["classification_source"],
            "cross-file usage:getCharacteristic(f1)",
        )

    def test_dspread_ff01_string_comparison_uses_characteristic_type(self):
        source = '''package com.dspread.xpos.bt2mode.dbridge4;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothGattCharacteristic;
class d {
    static final String zE = "0000ff01-0000-1000-8000-00805f9b34fb";











    void inspect(BluetoothGattService service) {
        for (BluetoothGattCharacteristic bluetoothGattCharacteristic : service.getCharacteristics()) {
            String string2 = bluetoothGattCharacteristic.getUuid().toString();
            if (string2.equals(zE)) { }
        }
    }
}
'''
        found = self.scan_one(source)
        uuid = "0000ff01-0000-1000-8000-00805f9b34fb"
        self.assertEqual(found[uuid]["classification"], "GATT Characteristic")
        self.assertEqual(found[uuid]["classification_source"], "usage:getCharacteristic")

        self.assertNotIn("ff01", extractor.KNOWN_SDK_UUIDS)
        self.assertNotIn(uuid, extractor.KNOWN_SDK_UUIDS)
        record = extractor.build_record(
            "ff01",
            found[uuid],
            {"package_id": "vn.mpos", "version_code": 499, "version_name": "4"},
            "AndroZoo/apks/01/vn.mpos.apk",
            "GPT-6 Luna",
            "Dspread",
        )
        self.assertEqual(record["UUID_usage_array"], ["GATT Characteristic"])
        self.assertNotIn("Contec", record["company"])
        self.assertNotEqual(record["UUID_name"], "CONTEC_MEDICAL_DEVICE_SERVICE")

    def test_conflicting_typed_gatt_roles_are_flagged_as_ambiguous(self):
        source = '''package sdk;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
class ConflictingUse {
    static final String bleUuid = "abcde021-1111-2222-3333-444455556677";












    void connect(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic) {
        gatt.getService(java.util.UUID.fromString(bleUuid));
        String observed = characteristic.getUuid().toString();
        if (observed.equals(bleUuid)) { }
    }
}
'''
        uuid = "abcde021-1111-2222-3333-444455556677"
        found = self.scan_one(source)
        self.assertEqual(found[uuid]["classification_source"], "ambiguous-usage")

    def test_heaton_cha_suffix_means_characteristic(self):
        for name in ("uuid_write_cha", "uuid_notify_cha", "uuid_ota_notify_cha"):
            with self.subTest(name=name):
                self.assertEqual(
                    extractor.classify_via_field_name(name),
                    "GATT Characteristic",
                )

    def test_indexed_profile_roles_are_traced_through_helper_parameter(self):
        service = "abcde001-1111-2222-3333-444455556677"
        char_a = "abcde002-1111-2222-3333-444455556677"
        char_b = "abcde003-1111-2222-3333-444455556677"
        constant_source = f'''package sdk;
import java.util.UUID;
class Profiles {{
    static final UUID[][] profiles;
    static {{
        UUID uuidFromString = UUID.fromString("{service}");
        UUID uuidFromString2 = UUID.fromString("{char_a}");
        UUID uuidFromString3 = UUID.fromString("{char_b}");
        UUID[] uuidArr = {{uuidFromString, uuidFromString2, uuidFromString3}};
        profiles = new UUID[][]{{uuidArr}};
    }}
}}
'''
        consumer_source = '''package sdk;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothGattCharacteristic;
import java.util.UUID;
class Connector {
    public void connect(BluetoothGatt gatt) {
        UUID[][] profilesLocal = Profiles.profiles;
        for (BluetoothGattService bluetoothGattService : gatt.getServices()) {
            UUID uuid = bluetoothGattService.getUuid();
            for (int i = 0; i < profilesLocal.length; i++) {
                UUID[] uuidArr2 = profilesLocal[i];
                if (uuidArr2[0].equals(uuid)) {
                    useProfile(uuidArr2);
                }
            }
        }
    }
    private void useProfile(UUID[] uuidArr) {
        for (BluetoothGattCharacteristic bluetoothGattCharacteristic : service.getCharacteristics()) {
            UUID uuid = bluetoothGattCharacteristic.getUuid();
            if (uuidArr[1].equals(uuid) || uuidArr[2].equals(uuid)) { }
        }
    }
}
'''
        with tempfile.TemporaryDirectory(prefix="shard01-array-role-") as tmp:
            root = Path(tmp)
            (root / "sources/sdk").mkdir(parents=True)
            (root / "sources/sdk/Profiles.java").write_text(constant_source, encoding="utf-8")
            (root / "sources/sdk/Connector.java").write_text(consumer_source, encoding="utf-8")
            found = extractor.scan_jadx_output(str(root))

        self.assertEqual(found[service]["classification"], "GATT Service")
        self.assertEqual(found[service]["classification_source"], "indexed-array-usage")
        for uuid in (char_a, char_b):
            with self.subTest(uuid=uuid):
                self.assertEqual(found[uuid]["classification"], "GATT Characteristic")
                self.assertEqual(found[uuid]["classification_source"], "indexed-array-usage")

    def test_conflicting_profile_slot_and_scan_filter_is_flagged_not_overridden(self):
        service = "abcde011-1111-2222-3333-444455556677"
        conflicted = "abcde012-1111-2222-3333-444455556677"
        third = "abcde013-1111-2222-3333-444455556677"
        constant_source = f'''package sdk;
import java.util.UUID;
class Profiles {{
    static final UUID[][] profiles;
    static {{
        UUID uuidFromString = UUID.fromString("{service}");
        UUID uuidFromString2 = UUID.fromString("{conflicted}");
        UUID uuidFromString3 = UUID.fromString("{third}");
        UUID[] uuidArr = {{uuidFromString, uuidFromString2, uuidFromString3}};
        profiles = new UUID[][]{{uuidArr}};
    }}
}}
'''
        consumer_source = f'''package sdk;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.le.ScanFilter;
import android.os.ParcelUuid;
import java.util.UUID;
import java.util.ArrayList;
class Connector {{
    void connect(BluetoothGatt gatt) {{
        UUID[][] profilesLocal = Profiles.profiles;
        for (BluetoothGattService bluetoothGattService : gatt.getServices()) {{
            UUID uuid = bluetoothGattService.getUuid();
            for (int i = 0; i < profilesLocal.length; i++) {{
                UUID[] uuidArr2 = profilesLocal[i];
                if (uuidArr2[0].equals(uuid)) {{ useProfile(uuidArr2); }}
            }}
        }}
        ArrayList<ScanFilter> filters = new ArrayList<>();
        filters.add(new ScanFilter.Builder().setServiceUuid(ParcelUuid.fromString("{conflicted}")).build());
    }}
    private void useProfile(UUID[] uuidArr) {{
        for (BluetoothGattCharacteristic bluetoothGattCharacteristic : service.getCharacteristics()) {{
            UUID uuid = bluetoothGattCharacteristic.getUuid();
            if (uuidArr[1].equals(uuid) || uuidArr[2].equals(uuid)) {{ }}
        }}
    }}
}}
'''
        with tempfile.TemporaryDirectory(prefix="shard01-array-conflict-") as tmp:
            root = Path(tmp)
            (root / "sources/sdk").mkdir(parents=True)
            (root / "sources/sdk/Profiles.java").write_text(constant_source, encoding="utf-8")
            (root / "sources/sdk/Connector.java").write_text(consumer_source, encoding="utf-8")
            found = extractor.scan_jadx_output(str(root))

        self.assertEqual(found[conflicted]["classification"], "GATT Service")
        self.assertEqual(
            found[conflicted]["classification_source"],
            "ambiguous-indexed-array-usage",
        )

    def test_known_sdk_cache_does_not_override_authoritative_usage_role(self):
        uuid = "12345678-1234-5678-9abc-def012345678"
        entry = {
            "classification": "GATT Characteristic",
            "classification_source": "usage:getCharacteristic",
            "field_name": "C",
            "declaring_packages": {"com.example.sdk"},
        }
        with patch.dict(
            extractor.KNOWN_SDK_UUIDS,
            {uuid: {"company": "Example", "name": "EXAMPLE_SERVICE", "note": "test"}},
        ):
            record = extractor.build_record(
                uuid,
                entry,
                {"package_id": "com.host.app", "version_code": 1, "version_name": "1"},
                "AndroZoo/apks/00/example.apk",
                "GPT-6 Luna",
                "Host App",
            )
        self.assertEqual(record["UUID_usage_array"], ["GATT Characteristic"])

    def test_known_sdk_cache_does_not_hide_ambiguous_usage(self):
        uuid = "12345678-1234-5678-9abc-def012345678"
        entry = {
            "classification": "GATT Service",
            "classification_source": "ambiguous-usage",
            "field_name": "C",
            "declaring_packages": {"com.example.sdk"},
        }
        with patch.dict(
            extractor.KNOWN_SDK_UUIDS,
            {uuid: {"company": "Example", "name": "EXAMPLE_CHARACTERISTIC", "note": "test"}},
        ):
            record = extractor.build_record(
                uuid,
                entry,
                {"package_id": "com.host.app", "version_code": 1, "version_name": "1"},
                "AndroZoo/apks/00/example.apk",
                "GPT-6 Luna",
                "Host App",
            )
        self.assertEqual(record["UUID_usage_array"], ["GATT Service"])
        self.assertIn("Classification source: ambiguous-usage.", record["evidence_array"][0]["description"])

    def test_issc_cache_uses_microchip_official_name(self):
        hit = extractor.KNOWN_SDK_UUIDS["49535343-6daa-4d02-abf6-19569aca69fe"]
        self.assertEqual(hit["company"], "Microchip Technology Inc.")
        self.assertEqual(hit["name"], "ISSC_UPDATE_CONNECTION_PARAMETER")
        self.assertIn("IS1678S", hit["note"])


if __name__ == "__main__":
    unittest.main()
