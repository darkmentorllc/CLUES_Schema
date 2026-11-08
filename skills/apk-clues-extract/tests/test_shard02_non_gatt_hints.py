import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


class Shard02NonGattHintTests(unittest.TestCase):
    def scan(self, source: str) -> dict[str, dict]:
        with tempfile.TemporaryDirectory(prefix="clues-shard02-fp-") as tmp:
            path = Path(tmp) / "Synthetic.java"
            path.write_text(source, encoding="utf-8")
            return extractor.scan_one_file(str(path))

    def test_newrelic_build_id_is_scoped_non_gatt(self):
        app_build_id = "6810a607-ac68-44d4-951c-842ca3a1b7c1"
        source = f'''package com.newrelic.agent.android;
final class NewRelicConfig {{
    static final String BUILD_ID = "{app_build_id}";
    static String getBuildId() {{ return BUILD_ID; }}
}}
'''
        self.assertNotIn(app_build_id, self.scan(source))
        self.assertNotIn(app_build_id, extractor.KNOWN_NON_BLE_UUIDS)

    def test_newrelic_build_id_hint_yields_to_explicit_gatt_sink(self):
        app_build_id = "6810a607-ac68-44d4-951c-842ca3a1b7c1"
        source = f'''package com.newrelic.agent.android;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
final class NewRelicConfig {{
    static final String BUILD_ID = "{app_build_id}";
    BluetoothGattService find(BluetoothGatt gatt) {{
        return gatt.getService(UUID.fromString(BUILD_ID));
    }}
}}
'''
        found = self.scan(source)
        self.assertIn(app_build_id, found)
        self.assertEqual(found[app_build_id]["classification"], "GATT Service")

    def test_newrelic_build_id_hint_does_not_match_other_packages(self):
        app_build_id = "6810a607-ac68-44d4-951c-842ca3a1b7c1"
        source = f'''package example.unrelated.sdk;
final class NewRelicConfig {{
    static final String BUILD_ID = "{app_build_id}";
}}
'''
        found = self.scan(source)
        self.assertIn(app_build_id, found)
        self.assertNotIn(app_build_id, extractor.KNOWN_NON_BLE_UUIDS)

    def test_cordova_bluetoothserial_rfcomm_service_uuids_are_not_gatt(self):
        secure = "7a9c3b55-78d0-44a7-a94e-a93e3fe118ce"
        insecure = "23f18142-b389-4772-93bd-52bdbb2c03e9"
        # Three UUID.fromString fields trigger the constants-file BLE fallback.
        source = f'''package com.megster.cordova;
import android.bluetooth.BluetoothAdapter;
import java.util.UUID;
final class BluetoothSerialService {{
    static final UUID MY_UUID_SECURE = UUID.fromString("{secure}");
    static final UUID MY_UUID_INSECURE = UUID.fromString("{insecure}");
    static final UUID UUID_SPP = UUID.fromString("00001101-0000-1000-8000-00805f9b34fb");
    void listen(BluetoothAdapter adapter) throws Exception {{
        adapter.listenUsingRfcommWithServiceRecord("secure", MY_UUID_SECURE);
        adapter.listenUsingInsecureRfcommWithServiceRecord("insecure", MY_UUID_INSECURE);
    }}
}}
'''
        found = self.scan(source)
        self.assertNotIn(secure, found)
        self.assertNotIn(insecure, found)
        self.assertNotIn(secure, extractor.KNOWN_NON_BLE_UUIDS)
        self.assertNotIn(insecure, extractor.KNOWN_NON_BLE_UUIDS)

    def test_cordova_rfcomm_hint_yields_to_explicit_gatt_sink(self):
        secure = "7a9c3b55-78d0-44a7-a94e-a93e3fe118ce"
        source = f'''package com.megster.cordova;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
final class BluetoothSerialService {{
    static final UUID MY_UUID_SECURE = UUID.fromString("{secure}");
    BluetoothGattService find(BluetoothGatt gatt) {{
        return gatt.getService(MY_UUID_SECURE);
    }}
}}
'''
        found = self.scan(source)
        self.assertIn(secure, found)
        self.assertEqual(found[secure]["classification"], "GATT Service")

    def test_cordova_rfcomm_hint_does_not_match_unrelated_class(self):
        secure = "7a9c3b55-78d0-44a7-a94e-a93e3fe118ce"
        source = f'''package example.unrelated.sdk;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
final class BluetoothSerialService {{
    static final UUID MY_UUID_SECURE = UUID.fromString("{secure}");
    BluetoothGattService find(BluetoothGatt gatt) {{
        return gatt.getService(MY_UUID_SECURE);
    }}
}}
'''
        found = self.scan(source)
        self.assertIn(secure, found)
        self.assertEqual(found[secure]["classification"], "GATT Service")
        self.assertNotIn(secure, extractor.KNOWN_NON_BLE_UUIDS)


if __name__ == "__main__":
    unittest.main()
