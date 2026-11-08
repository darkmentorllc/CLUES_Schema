import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


class Shard03Ae00SdkScopeTests(unittest.TestCase):
    @staticmethod
    def write_java(root: Path, relative: str, source: str) -> Path:
        path = root / "sources" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    @staticmethod
    def record_for(root: Path, host_package: str) -> dict:
        found = extractor.scan_jadx_output(str(root))
        kept, _ = extractor.filter_vendor_specific(found)
        entry = kept["ae00"]
        return extractor.build_record(
            "ae00",
            entry,
            {
                "package_id": host_package,
                "version_name": "1.0",
                "version_code": 1,
            },
            "example.apk",
            "test",
            "Host vendor",
            resolved_roles=extractor._resolved_uuid_roles(found),
        )

    def test_jieli_ae00_is_not_attributed_to_suprema_by_uuid_value(self):
        self.assertNotIn("ae00", extractor.KNOWN_SDK_UUIDS)
        self.assertIn("ae1a", extractor.KNOWN_SDK_UUIDS)
        self.assertIn("ae1b", extractor.KNOWN_SDK_UUIDS)

        uuid = "0000ae00-0000-1000-8000-00805f9b34fb"
        with tempfile.TemporaryDirectory(prefix="clues-shard03-jieli-ae00-") as tmp:
            root = Path(tmp)
            self.write_java(root, "p058j5/c.java", f'''package p058j5;
class c {{
    static final String JIE_LI_SERVICE_AE00 = "{uuid}";
}}
''')
            self.write_java(root, "M4/a.java", f'''package M4;
import android.bluetooth.BluetoothGatt;
import java.util.UUID;
class a {{
    BluetoothGatt bluetoothGatt;
    void connect() {{ bluetoothGatt.getService(UUID.fromString(p058j5.c.JIE_LI_SERVICE_AE00)); }}
}}
''')
            record = self.record_for(root, "com.drshikha.drshikhasnutrihealth.vediquediet")

        self.assertEqual(record["UUID_usage_array"], ["GATT Service"])
        self.assertNotIn("Suprema", record["company"])

    def test_suprema_attribution_stays_bound_to_its_sdk_package(self):
        uuid = "0000ae00-0000-1000-8000-00805f9b34fb"
        with tempfile.TemporaryDirectory(prefix="clues-shard03-suprema-ae00-") as tmp:
            root = Path(tmp)
            self.write_java(
                root,
                "com/supremainc/android/libsupremaac/SupremaAc.java",
                f'''package com.supremainc.android.libsupremaac;
import android.bluetooth.BluetoothGatt;
import java.util.UUID;
class SupremaAc {{
    static final String SERVICE_UUID = "{uuid}";
    BluetoothGatt gatt;
    void connect() {{ gatt.getService(UUID.fromString(SERVICE_UUID)); }}
}}
''',
            )
            record = self.record_for(root, "eu.sharry.swp.green167")

        self.assertEqual(record["UUID_usage_array"], ["GATT Service"])
        self.assertIn("Suprema", record["company"])


if __name__ == "__main__":
    unittest.main()
