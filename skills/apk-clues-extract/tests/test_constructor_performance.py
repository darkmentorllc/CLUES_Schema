import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor


class ConstructorScanTests(unittest.TestCase):
    def test_non_gatt_scope_ignores_other_packages_before_scanning_source(self):
        source = "class ApiServiceVariables { String CLIENT_ID; }" * 10000
        with patch.object(extractor.re, "search", side_effect=AssertionError("unrelated source was scanned")):
            self.assertEqual(extractor._matching_non_gatt_class_field_names("com.nhncloud.android.indicator.data", source), set())
        self.assertIn("CLIENT_ID", extractor._matching_non_gatt_class_field_names(
            "com.banno.android.network.client", "class ApiServiceVariables {}"
        ))

    def test_many_uuids_on_one_line_share_the_source_context(self):
        uuids = [f"{n:08x}-1111-2222-3333-444444444444" for n in range(1, 16)]
        source = 'import android.bluetooth.BluetoothGatt;\nclass Demo { String x = "' + ",".join(uuids) + '"; }\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Demo.java"
            path.write_text(source)
            with patch.object(extractor, "_nearby_ble_log_label", wraps=extractor._nearby_ble_log_label) as context, \
                 patch.object(extractor, "classify", wraps=extractor.classify) as classification:
                result = extractor.scan_one_file(str(path))
            self.assertEqual(len(result), len(uuids))
            self.assertEqual(context.call_count, 1)
            self.assertEqual(classification.call_count, 1)

    def test_cached_parenthesis_lookup_matches_original(self):
        lines = [
            r'writeCharacteristic = new BleCharacteristic(serviceId, new Nested(UUID.fromString("12345678-1234-5678-1234-567812345678"), "paren ) ("));',
            'String x = "new Fake(unmatched("; value = new Real(arg);',
            "value = new Real('text ) (', nested());",
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(list(extractor._iter_constructor_calls_on_line(line)), list(extractor._iter_constructor_calls_on_line(line, [None])))
                self.assertEqual(list(extractor._iter_assigned_constructor_calls_on_line(line)), list(extractor._iter_assigned_constructor_calls_on_line(line, [None])))

    def test_no_uuid_large_file_has_no_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "Large.java"
            p.write_text("class Demo { int value = -1; " + "new Nested(call(1, 2)); " * 1000 + "}")
            self.assertEqual(extractor.scan_one_file(str(p)), {})

if __name__ == "__main__":
    unittest.main()
