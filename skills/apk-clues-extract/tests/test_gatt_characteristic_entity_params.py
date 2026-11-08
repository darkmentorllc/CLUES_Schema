"""Regression tests for roles carried by typed GATT characteristic entities."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


SERVICE = "f1000060-1234-5678-9abc-def012340060"
WRITE = "f1000061-1234-5678-9abc-def012340061"
NOTIFY = "f1000062-1234-5678-9abc-def012340062"
OTA_WRITE = "f1000063-1234-5678-9abc-def012340063"
OTA_NOTIFY = "f1000064-1234-5678-9abc-def012340064"


class GattCharacteristicEntityParamTests(unittest.TestCase):
    def scan(self, source: str) -> dict[str, dict]:
        with tempfile.TemporaryDirectory(prefix="gatt-entity-param-") as tmp:
            path = Path(tmp) / "AqaraBleManager.java"
            path.write_text(source, encoding="utf-8")
            return extractor.scan_one_file(str(path))

    @staticmethod
    def entity_source(extra_use: str = "") -> str:
        return f'''package sdk.ble;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
class AqaraBleManager {{
    private static UUID SERVICE_UUID;
    private static UUID WRITE_UUID;
    private static UUID NOTIFY_UUID;
    private static UUID OTA_WRITE_UUID;
    private static UUID OTA_NOTIFY_UUID;
    static {{
        UUID uuidFromString = UUID.fromString("{SERVICE}");
        SERVICE_UUID = uuidFromString;
        UUID uuidFromString2 = UUID.fromString("{WRITE}");
        WRITE_UUID = uuidFromString2;
        UUID uuidFromString3 = UUID.fromString("{NOTIFY}");
        NOTIFY_UUID = uuidFromString3;
        UUID uuidFromString4 = UUID.fromString("{OTA_WRITE}");
        OTA_WRITE_UUID = uuidFromString4;
        UUID uuidFromString5 = UUID.fromString("{OTA_NOTIFY}");
        OTA_NOTIFY_UUID = uuidFromString5;
    }}
    static final class BluetoothGattCharacteristicEntity {{
        private BluetoothGattCharacteristic readCharacteristic;
        private UUID readUUID;
        private UUID serviceUUID;
        private BluetoothGattCharacteristic writeCharacteristic;
        private UUID writeUUID;
        public BluetoothGattCharacteristicEntity(UUID serviceUUID, UUID writeUUID, UUID readUUID, int writeType) {{
            this.serviceUUID = serviceUUID;
            this.writeUUID = writeUUID;
            this.readUUID = readUUID;
        }}
    }}
    void register() {{
        new BluetoothGattCharacteristicEntity(SERVICE_UUID, WRITE_UUID, NOTIFY_UUID, 0, 8, null);
        new BluetoothGattCharacteristicEntity(SERVICE_UUID, OTA_WRITE_UUID, OTA_NOTIFY_UUID, 0, 8, null);
        {extra_use}
    }}
}}
'''

    def test_constructor_slots_resolve_service_and_characteristic_fields(self):
        found = self.scan(self.entity_source())
        self.assertEqual(found[SERVICE]["classification"], "GATT Service")
        self.assertEqual(found[SERVICE]["classification_source"],
                         "constructor-param:BluetoothGattCharacteristicEntity.serviceUUID")
        for uuid, param in (
            (WRITE, "writeUUID"),
            (NOTIFY, "readUUID"),
            (OTA_WRITE, "writeUUID"),
            (OTA_NOTIFY, "readUUID"),
        ):
            with self.subTest(uuid=uuid):
                self.assertEqual(found[uuid]["classification"], "GATT Characteristic")
                self.assertEqual(
                    found[uuid]["classification_source"],
                    f"constructor-param:BluetoothGattCharacteristicEntity.{param}",
                )

    def test_direct_android_gatt_usage_remains_stronger(self):
        source = self.entity_source(
            "BluetoothGatt gatt = null; gatt.getService(WRITE_UUID);"
        )
        found = self.scan(source)
        self.assertEqual(found[WRITE]["classification"], "GATT Service")
        self.assertEqual(found[WRITE]["classification_source"], "usage:getService")

    def test_unrelated_constructor_name_does_not_adopt_entity_parameter_rule(self):
        source = f'''package sdk.ble;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
class ProfileSettings {{
    static final UUID SERVICE_UUID = UUID.fromString("{SERVICE}");
    static final UUID WRITE_UUID = UUID.fromString("{WRITE}");
    static final UUID NOTIFY_UUID = UUID.fromString("{NOTIFY}");
    ProfileSettings(UUID serviceUUID, UUID writeUUID, UUID readUUID) {{}}
    void register() {{ new ProfileSettings(SERVICE_UUID, WRITE_UUID, NOTIFY_UUID); }}
}}
'''
        found = self.scan(source)
        self.assertNotIn("constructor-param:", found[WRITE]["classification_source"])
        self.assertNotIn("constructor-param:", found[NOTIFY]["classification_source"])


if __name__ == "__main__":
    unittest.main()
