import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


class SkidataRegionOccurrenceFilterTests(unittest.TestCase):
    @staticmethod
    def write_java(root: Path, relative: str, source: str) -> Path:
        path = root / "sources" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def test_region_occurrence_is_removed_but_same_literal_gatt_sink_survives(self):
        shared_uuid = "11112222-3333-4444-aaaa-bbbbccccdddd"
        unrelated_scan_filter_uuid = "77778888-9999-aaaa-bbbb-ccccddddeeee"
        with tempfile.TemporaryDirectory(prefix="clues-skidata-region-occurrence-") as tmp:
            root = Path(tmp)
            skidata = self.write_java(
                root,
                "com/skidata/mobileflow_plugin/service/LocalizationBeaconServiceImpl.java",
                f'''package com.skidata.mobileflow_plugin.service;
import android.bluetooth.BluetoothGatt;
import com.external.altbeacon.beacon.Identifier;
import com.external.altbeacon.beacon.Region;
import java.util.UUID;
class LocalizationBeaconServiceImpl {{
    BluetoothGatt gatt;
    void setup() {{
        Region region = new Region("SKIDATA_V3_FG_1", Identifier.fromUuid(UUID.fromString("{shared_uuid}")), null, null);
        gatt.getService(UUID.fromString("{shared_uuid}"));
    }}
}}
''',
            )
            self.write_java(
                root,
                "com/skidata/mobileflow_plugin/service/GattBeaconServiceImpl.java",
                f'''package com.skidata.mobileflow_plugin.service;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.le.ScanFilter;
import android.os.ParcelUuid;
import java.util.UUID;
class GattBeaconServiceImpl {{
    BluetoothGatt gatt;
    void scanAndConnect() {{
        new ScanFilter.Builder().setServiceUuid(new ParcelUuid(UUID.fromString("{shared_uuid}")));
        new ScanFilter.Builder().setServiceUuid(new ParcelUuid(UUID.fromString("{unrelated_scan_filter_uuid}")));
        gatt.getService(UUID.fromString("{shared_uuid}"));
    }}
}}
''',
            )
            self.write_java(
                root,
                "example/IndependentGattProfile.java",
                f'''package example;
import android.bluetooth.BluetoothGatt;
import java.util.UUID;
class IndependentGattProfile {{
    BluetoothGatt gatt;
    void connect() {{ gatt.getService(UUID.fromString("{shared_uuid}")); }}
}}
''',
            )
            local = extractor.scan_one_file(str(skidata))
            found = extractor.scan_jadx_output(str(root))
            kept, _ = extractor.filter_vendor_specific(found)

        # The only occurrence in the Skidata file that can contribute this
        # UUID is the direct GATT sink; its Region occurrence was skipped.
        self.assertIn(shared_uuid, local)
        self.assertEqual(local[shared_uuid]["classification"], "GATT Service")
        self.assertIn(shared_uuid, kept)
        self.assertEqual(found[shared_uuid]["classification"], "GATT Service")
        self.assertIn(unrelated_scan_filter_uuid, kept)

    def test_filter_requires_the_exact_skidata_region_source_scope_and_shape(self):
        uuid = "22223333-4444-5555-aaaa-bbbbccccdddd"
        with tempfile.TemporaryDirectory(prefix="clues-skidata-region-scope-") as tmp:
            root = Path(tmp)
            other_class = self.write_java(
                root,
                "com/skidata/mobileflow_plugin/service/OtherBeaconService.java",
                f'''package com.skidata.mobileflow_plugin.service;
import android.bluetooth.BluetoothGatt;
import com.external.altbeacon.beacon.Identifier;
import com.external.altbeacon.beacon.Region;
import java.util.UUID;
class OtherBeaconService {{
    BluetoothGatt gatt;
    void setup() {{ new Region("other", Identifier.fromUuid(UUID.fromString("{uuid}")), null, null); }}
}}
''',
            )
            unrelated_scope = self.write_java(
                root,
                "example/LocalizationBeaconServiceImpl.java",
                f'''package example;
import android.bluetooth.BluetoothGatt;
import com.external.altbeacon.beacon.Identifier;
import com.external.altbeacon.beacon.Region;
import java.util.UUID;
class LocalizationBeaconServiceImpl {{
    BluetoothGatt gatt;
    void setup() {{ new Region("other", Identifier.fromUuid(UUID.fromString("{uuid}")), null, null); }}
}}
''',
            )
            other_candidates = extractor.scan_one_file(str(other_class))
            unrelated_candidates = extractor.scan_one_file(str(unrelated_scope))

        self.assertIn(uuid, other_candidates)
        self.assertIn(uuid, unrelated_candidates)

    def test_scan_region_cache_entries_are_removed_but_gatt_variants_remain(self):
        names = {entry.get("name", "") for entry in extractor.KNOWN_SDK_UUIDS.values()}
        self.assertFalse(any(name.startswith("SKIDATA_FG_LOC_BEACON_") for name in names))
        self.assertFalse(any(name.startswith("SKIDATA_FM_LOC_BEACON_") for name in names))
        self.assertEqual(
            extractor.KNOWN_SDK_UUIDS[
                "21523cc0-8504-e17a-8bad-ed14b483d139"
            ]["name"],
            "SKIDATA_GATT_BEACON_SERVICE_B",
        )


if __name__ == "__main__":
    unittest.main()
