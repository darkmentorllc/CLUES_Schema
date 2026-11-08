"""Regression coverage for typed GATT sinks reached through local UUID aliases."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402

SERVICE = "a0000001-1234-5678-9abc-def012340001"
CHARACTERISTIC = "a0000002-1234-5678-9abc-def012340002"
UNUSED = "a0000003-1234-5678-9abc-def012340003"


class CrossFileUuidAliasTests(unittest.TestCase):
    def scan(self, manager_body: str) -> dict[str, dict]:
        constants = f'''package sdk;
import java.util.UUID;
class Constants {{
    static final UUID serviceUuid = UUID.fromString("{SERVICE}");
    static final UUID f123a = UUID.fromString("{CHARACTERISTIC}");
    static final UUID f123b = UUID.fromString("{UNUSED}");
}}
'''
        manager = f'''package sdk;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
class Manager {{
{manager_body}
}}
'''
        with tempfile.TemporaryDirectory(prefix="cross-file-uuid-alias-") as tmp:
            root = Path(tmp) / "sources/sdk"
            root.mkdir(parents=True)
            (root / "Constants.java").write_text(constants, encoding="utf-8")
            (root / "Manager.java").write_text(manager, encoding="utf-8")
            return extractor.scan_jadx_output(str(Path(tmp)))

    def test_method_local_uuid_alias_to_typed_characteristic_sink(self):
        found = self.scan('''    public void discover(BluetoothGatt gatt) {
        BluetoothGattService service = gatt.getService(Constants.serviceUuid);
        UUID candidate;
        candidate = Constants.f123a;
        BluetoothGattCharacteristic characteristic = service.getCharacteristic(candidate);
    }
''')
        self.assertEqual(found[SERVICE]["classification"], "GATT Service")
        self.assertEqual(found[CHARACTERISTIC]["classification"], "GATT Characteristic")
        self.assertEqual(
            found[CHARACTERISTIC]["classification_source"],
            "cross-file usage:getCharacteristic(f123a)",
        )

    def test_alias_is_scoped_to_method_and_conflicting_sink_remains_ambiguous(self):
        found = self.scan('''    public void discover(BluetoothGatt gatt) {
        BluetoothGattService service = gatt.getService(Constants.serviceUuid);
        UUID candidate;
        candidate = Constants.f123a;
        service.getCharacteristic(candidate);
    }
    public void otherPath(BluetoothGatt gatt) {
        UUID candidate = UUID.randomUUID();
        gatt.getService(candidate);
    }
''')
        self.assertEqual(found[CHARACTERISTIC]["classification"], "GATT Characteristic")
        self.assertEqual(
            found[CHARACTERISTIC]["classification_source"],
            "cross-file usage:getCharacteristic(f123a)",
        )

        conflicting = self.scan('''    public void discover(BluetoothGatt gatt) {
        BluetoothGattService service = gatt.getService(Constants.serviceUuid);
        UUID candidate = Constants.f123a;
        service.getCharacteristic(candidate);
    }
    public void otherPath(BluetoothGatt gatt) {
        UUID reused = Constants.f123a;
        gatt.getService(reused);
    }
''')
        self.assertEqual(
            conflicting[CHARACTERISTIC]["classification_source"],
            "ambiguous-usage",
        )


if __name__ == "__main__":
    unittest.main()
