import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


class ScopedFalsePositiveTests(unittest.TestCase):
    def scan(self, source: str) -> dict[str, dict]:
        with tempfile.TemporaryDirectory(prefix="clues-fpfix-") as tmp:
            path = Path(tmp) / "Synthetic.java"
            path.write_text(source, encoding="utf-8")
            return extractor.scan_one_file(str(path))

    def test_onesignal_otel_error_ids_are_filtered_by_field_context(self):
        ids = [
            "00000000-0000-4000-a000-000000000000",
            "e1100000-0000-4000-a000-000000000000",
            "e1100000-0000-4000-a000-000000000001",
            "e1100000-0000-4000-a000-000000000002",
            "e1100000-0000-4000-a000-000000000003",
            "e1100000-0000-4000-a000-000000000004",
        ]
        constants = "\n".join(
            f'    private static final String ERROR_APP_ID_SENTINEL_{i} = "{uuid}";'
            for i, uuid in enumerate(ids)
        )
        source = (
            "package com.onesignal.debug.internal.logging.otel.android;\n"
            "final class AppIdResolver {\n"
            f"{constants}\n"
            "}\n"
        )

        # Six assigned UUID strings trigger the broad constants-file fallback.
        self.assertGreaterEqual(
            len(extractor.UUID_STRING_ASSIGNMENT_RE.findall(source)),
            extractor.MIN_UUID_FROMSTRING_FOR_BLE_FALLBACK,
        )
        self.assertEqual(self.scan(source), {})

    def test_onesignal_field_does_not_hide_nearby_real_gatt_service(self):
        source = '''package com.example.ble;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
final class BleConfig {
    private static final String KLIPSCH_ONESIGNAL_APP_ID = "ae30e7f9-04dc-40bb-8e43-a06d05f75b45";
    private static final UUID DEVICE_SERVICE_UUID = UUID.fromString("00000000-0000-4000-a000-000000000000");
    void connect(BluetoothGatt gatt) {
        BluetoothGattService service = gatt.getService(DEVICE_SERVICE_UUID);
    }
}
'''

        found = self.scan(source)
        self.assertNotIn("ae30e7f9-04dc-40bb-8e43-a06d05f75b45", found)
        service_uuid = "00000000-0000-4000-a000-000000000000"
        self.assertIn(service_uuid, found)
        self.assertEqual(found[service_uuid]["classification"], "GATT Service")

    def test_investa_customer_id_is_filtered_without_global_uuid_drop(self):
        customer_uuid = "25289cfc-2c2c-4969-aee0-53f5c83813c3"
        source = f'''package io.bakerystud.login_insite.server.usecase;
final class SignUpUseCase {{
    public static final String INVESTA_CUSTOMER_ID = "{customer_uuid}";
    void fetchBuildings(Api api) {{ api.requestBuildingList(INVESTA_CUSTOMER_ID); }}
}}
'''

        self.assertEqual(self.scan(source), {})
        self.assertNotIn(customer_uuid, extractor.KNOWN_NON_BLE_UUIDS)
        # The generic classifier remains intact; the source-scoped field hint
        # is what suppresses this confirmed API customer ID.
        self.assertEqual(
            extractor.classify_via_field_name("INVESTA_CUSTOMER_ID"),
            "GATT Characteristic",
        )

    def test_banno_client_id_filter_requires_network_package_and_class(self):
        client_id = "e7e7098d-7c63-4c99-9b0c-37c51a2bd66c"
        source = f'''package com.banno.android.network;
final class ApiServiceVariables {{
    public static final String CLIENT_ID = "{client_id}";
    public static final String CLIENT_SECRET = "00000000-0000-4000-8000-000000000001";
}}
'''

        self.assertNotIn(client_id, self.scan(source))
        self.assertNotIn(client_id, extractor.KNOWN_NON_BLE_UUIDS)

    def test_banno_client_id_value_survives_when_used_as_a_real_gatt_service(self):
        client_id = "e7e7098d-7c63-4c99-9b0c-37c51a2bd66c"
        source = f'''package com.banno.android.network;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
final class ApiServiceVariables {{
    public static final String CLIENT_ID = "{client_id}";
    BluetoothGattService findService(BluetoothGatt gatt) {{
        return gatt.getService(UUID.fromString(CLIENT_ID));
    }}
}}
'''

        found = self.scan(source)
        self.assertIn(client_id, found)
        self.assertEqual(found[client_id]["classification"], "GATT Service")

    def test_same_banno_id_value_in_other_gatt_class_is_not_suppressed(self):
        client_id = "e7e7098d-7c63-4c99-9b0c-37c51a2bd66c"
        source = f'''package com.example.ble;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
final class DeviceBleClient {{
    private static final UUID CLIENT_ID = UUID.fromString("{client_id}");
    BluetoothGattService findService(BluetoothGatt gatt) {{
        return gatt.getService(CLIENT_ID);
    }}
}}
'''

        found = self.scan(source)
        self.assertIn(client_id, found)
        self.assertEqual(found[client_id]["classification"], "GATT Service")

    def test_uppercase_id_classifier_preserves_existing_catalog_coverage(self):
        for name in (
            "SENSOR_FIFO_ID",
            "TEMPERATURE_VALUE_ID",
            "SAMPLE_LATEST_ID",
            "CLIENT_ID",
            "CUSTOMER_ID",
        ):
            with self.subTest(name=name):
                self.assertEqual(
                    extractor.classify_via_field_name(name), "GATT Characteristic"
                )

    def test_ffa0_to_ffa3_keep_gatt_roles_without_global_ti_attribution(self):
        source = '''package com.qingniu.scale.wsp.ble;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
final class ScaleNewWspBleManager {
    private static final UUID WSP_SERVICE_UUID = UUID.fromString("0000ffa0-0000-1000-8000-00805f9b34fb");
    private static final UUID WSP_NOTIFY_CHAR_UUID = UUID.fromString("0000ffa1-0000-1000-8000-00805f9b34fb");
    private static final UUID WSP_WRITE_CHAR_UUID = UUID.fromString("0000ffa2-0000-1000-8000-00805f9b34fb");
    private static final UUID WSP_READ_CHAR_UUID = UUID.fromString("0000ffa3-0000-1000-8000-00805f9b34fb");
    void connect(BluetoothGatt gatt) {
        BluetoothGattService service = gatt.getService(WSP_SERVICE_UUID);
        BluetoothGattCharacteristic notify = service.getCharacteristic(WSP_NOTIFY_CHAR_UUID);
        BluetoothGattCharacteristic write = service.getCharacteristic(WSP_WRITE_CHAR_UUID);
        BluetoothGattCharacteristic read = service.getCharacteristic(WSP_READ_CHAR_UUID);
    }
}
'''
        found = self.scan(source)
        full = {
            "ffa0": "0000ffa0-0000-1000-8000-00805f9b34fb",
            "ffa1": "0000ffa1-0000-1000-8000-00805f9b34fb",
            "ffa2": "0000ffa2-0000-1000-8000-00805f9b34fb",
            "ffa3": "0000ffa3-0000-1000-8000-00805f9b34fb",
        }
        expected = {
            "ffa0": ("GATT Service", "WSP_SERVICE_UUID"),
            "ffa1": ("GATT Characteristic", "WSP_NOTIFY_CHAR_UUID"),
            "ffa2": ("GATT Characteristic", "WSP_WRITE_CHAR_UUID"),
            "ffa3": ("GATT Characteristic", "WSP_READ_CHAR_UUID"),
        }
        for short, uuid in full.items():
            with self.subTest(uuid=short):
                self.assertIn(uuid, found)
                self.assertEqual(
                    (found[uuid]["classification"], found[uuid]["field_name"]),
                    expected[short],
                )

        for short in ("ffa0", "ffa1", "ffa2", "ffa3"):
            self.assertNotIn(short, extractor.KNOWN_SDK_UUIDS)
        self.assertFalse({"ffe0", "ffe1", "fff0", "fff1", "fff2", "fff3", "fff4", "fff5", "fff6"} & extractor.KNOWN_SDK_UUIDS.keys())

        meta = {"package_id": "com.example.fit", "version_code": 1, "version_name": "1"}
        record = extractor.build_record(
            "ffa0",
            found[full["ffa0"]],
            meta,
            "AndroZoo/apks/00/example.apk",
            "GPT-6 Luna",
            "Example Fitness",
        )
        self.assertEqual(record["UUID_usage_array"], ["GATT Service"])
        self.assertEqual(record["UUID_name"], "WSP_SERVICE")
        self.assertNotIn("Texas Instruments", record["company"])

    def test_new_ffa_observation_preserves_existing_curated_record(self):
        old = {
            "UUID": "ffa0",
            "company": "Human Curated Company",
            "UUID_name": "Human Verified UUID Name",
            "UUID_purpose": "human-verified source record",
            "UUID_usage_array": ["GATT Service"],
            "android_info_array": [],
            "evidence_array": [],
        }
        new = {
            "UUID": "ffa0",
            "company": "Third-party SDK code (declared in Java package `com.qingniu.scale.wsp.ble`)",
            "UUID_name": "WSP_SERVICE",
            "UUID_purpose": "GATT Service with source context",
            "UUID_usage_array": ["GATT Service"],
            "android_info_array": [],
            "evidence_array": [],
        }

        merged = extractor.merge_records([old], [new])
        self.assertEqual(merged[0]["company"], "Human Curated Company")
        self.assertEqual(
            merged[0]["UUID_name"].split(" / ", 1)[0],
            "Human Verified UUID Name",
        )


if __name__ == "__main__":
    unittest.main()
