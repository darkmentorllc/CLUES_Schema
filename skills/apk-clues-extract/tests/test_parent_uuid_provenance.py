import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


SERVICE_A = "e1a00001-1111-4111-8111-111111111111"
SERVICE_B = "e1a00002-2222-4222-8222-222222222222"
CHARACTERISTIC = "e1a00010-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def service_source(class_name: str, field_name: str, uuid: str) -> str:
    return f'''package com.enphaseenergy.ble;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
final class {class_name} {{
    private static final UUID {field_name} = UUID.fromString("{uuid}");
    BluetoothGattService find(BluetoothGatt gatt) {{
        return gatt.getService({field_name});
    }}
}}
'''


def characteristic_source(class_name: str, uuid: str) -> str:
    return f'''package com.enphaseenergy.ble;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
final class {class_name} {{
    private static final UUID TELEMETRY_CHARACTERISTIC = UUID.fromString("{uuid}");
    BluetoothGattCharacteristic find(BluetoothGattService service) {{
        return service.getCharacteristic(TELEMETRY_CHARACTERISTIC);
    }}
}}
'''


class ParentUuidProvenanceTests(unittest.TestCase):
    def scan_sources(self, sources: dict[str, str]) -> dict[str, dict]:
        with tempfile.TemporaryDirectory(prefix="clues-parent-provenance-") as tmp:
            source_root = Path(tmp) / "sources"
            source_root.mkdir()
            for name, source in sources.items():
                (source_root / name).write_text(source, encoding="utf-8")
            return extractor.scan_jadx_output(tmp)

    def build_record(self, uuid: str, entry: dict) -> dict:
        return extractor.build_record(
            uuid,
            entry,
            {
                "package_id": "com.enphaseenergy.app",
                "version_code": 1,
                "version_name": "1.0",
            },
            "Enphase/test.apk",
            "Codex test",
            "Enphase",
        )

    def test_enphase_services_from_other_files_do_not_become_a_parent(self):
        """An APK-wide service list is not evidence of a parent relationship."""
        found = self.scan_sources({
            "GatewayService.java": service_source("GatewayService", "GATEWAY_SERVICE", SERVICE_A),
            "CommissioningService.java": service_source(
                "CommissioningService", "COMMISSIONING_SERVICE", SERVICE_B
            ),
            "TelemetryCharacteristics.java": characteristic_source(
                "TelemetryCharacteristics", CHARACTERISTIC
            ),
        })

        self.assertEqual(
            found[CHARACTERISTIC]["classification"], "GATT Characteristic"
        )
        self.assertEqual(found[CHARACTERISTIC]["parent_candidates"], [])
        self.assertNotIn(
            "parent_UUID", self.build_record(CHARACTERISTIC, found[CHARACTERISTIC])
        )

    def test_single_local_service_remains_a_parent(self):
        source = f'''package com.enphaseenergy.ble;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
final class OneProfile {{
    private static final UUID PROFILE_SERVICE = UUID.fromString("{SERVICE_A}");
    private static final UUID PROFILE_DATA_CHARACTERISTIC = UUID.fromString("{CHARACTERISTIC}");
    void connect(BluetoothGatt gatt) {{
        BluetoothGattService service = gatt.getService(PROFILE_SERVICE);
        BluetoothGattCharacteristic data = service.getCharacteristic(PROFILE_DATA_CHARACTERISTIC);
    }}
}}
'''
        found = self.scan_sources({"OneProfile.java": source})

        self.assertEqual(found[CHARACTERISTIC]["parent_candidates"], [SERVICE_A])
        self.assertEqual(
            self.build_record(CHARACTERISTIC, found[CHARACTERISTIC])["parent_UUID"],
            SERVICE_A,
        )

    def test_services_and_characteristics_in_separate_methods_do_not_pair(self):
        found = self.scan_sources({
            "ProfileOne.java": service_source("ProfileOne", "PROFILE_ONE_SERVICE", SERVICE_A)
            + characteristic_source("ProfileOne", CHARACTERISTIC),
            "ProfileTwo.java": service_source("ProfileTwo", "PROFILE_TWO_SERVICE", SERVICE_B)
            + characteristic_source("ProfileTwo", CHARACTERISTIC),
        })

        self.assertEqual(found[CHARACTERISTIC]["parent_candidates"], [])
        self.assertNotIn(
            "parent_UUID", self.build_record(CHARACTERISTIC, found[CHARACTERISTIC])
        )


if __name__ == "__main__":
    unittest.main()
