import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor


class KryoFeaturePairTests(unittest.TestCase):
    def test_characteristic_pair_component_requires_matching_gatt_resolver(self):
        uuid = "6aa46711-a29d-4f8a-88e2-044ca1fd03ff"
        profile = (
            'package com.kryoinc.devices.ooler; import java.util.UUID; '
            'class d { Object x = BluetoothFeatures.TARGET; '
            f'Object y = new Pair(this.service, UUID.fromString("{uuid}")); }}'
        )
        manager = (
            'class OolerManager { void f() { '
            'for (Map.Entry entry : new d().c().entrySet()) { '
            'BluetoothGattService service = gatt.getService((UUID) ((Pair) entry.getValue()).c()); '
            'service.getCharacteristic((UUID) ((Pair) entry.getValue()).d()); } } }'
        )
        files = {
            "/tmp/sources/com/kryoinc/devices/ooler/d.java": profile,
            "/tmp/sources/com/kryoinc/devices/ooler/OolerManager.java": manager,
        }
        self.assertEqual(extractor._kryo_ooler_feature_characteristics(files), {uuid})
        files["/tmp/sources/com/kryoinc/devices/ooler/OolerManager.java"] = manager.replace(
            "getCharacteristic", "getDescriptor"
        )
        self.assertEqual(extractor._kryo_ooler_feature_characteristics(files), set())


if __name__ == "__main__":
    unittest.main()
