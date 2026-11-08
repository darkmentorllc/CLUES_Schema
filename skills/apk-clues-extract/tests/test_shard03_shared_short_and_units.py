import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor


class SharedShortAndUnitTests(unittest.TestCase):
    def test_shared_short_ids_have_no_value_only_vendor_mapping(self):
        for uuid in ("ffe2", "ffe3", "ffa4", "ffe5"):
            self.assertNotIn(uuid, extractor.KNOWN_SDK_UUIDS)

    def test_serving_units_filtered_only_in_their_declaring_class(self):
        gram = "229e75c8-0a97-4a0c-bb14-a302c1bf56d2"
        ml = "92df1acd-a6c3-4d8d-bda3-3a750b674f53"
        default = "ebba5d00-2e36-4c70-b294-6369d1c9eb0a"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "sources"
            unit = root / "com/appstreet/repository/util/UnitUtilsKt.java"
            unit.parent.mkdir(parents=True)
            unit.write_text(f'''package com.appstreet.repository.util;
import android.bluetooth.BluetoothGatt;
public final class UnitUtilsKt {{
  public static final String DEFAULT_SERVING_ID = "{default}";
  public static final String SERVING_UNIT_GRAM_ID = "{gram}";
  public static final String SERVING_UNIT_ML_ID = "{ml}";
}}
''')
            other = root / "example/Gatt.java"
            other.parent.mkdir(parents=True)
            other.write_text(f'''package example;
import android.bluetooth.BluetoothGatt;
import java.util.UUID;
class Gatt {{
  BluetoothGatt gatt;
  void connect() {{ gatt.getService(UUID.fromString("{gram}")); }}
}}
''')
            local = extractor.scan_one_file(str(unit))
            found = extractor.scan_jadx_output(str(root.parent))
            key = ("com.appstreet.repository.util", "UnitUtilsKt")
            old_hint = extractor.NON_GATT_CLASS_FIELD_HINTS.pop(key)
            try:
                without_hint = extractor.scan_one_file(str(unit))
            finally:
                extractor.NON_GATT_CLASS_FIELD_HINTS[key] = old_hint
        self.assertNotIn(gram, local)
        self.assertNotIn(ml, local)
        self.assertNotIn(default, local)
        self.assertIn(gram, without_hint)
        self.assertIn(ml, without_hint)
        self.assertIn(default, without_hint)
        self.assertIn(gram, found)
        self.assertEqual(found[gram]["classification"], "GATT Service")


if __name__ == "__main__":
    unittest.main()
