import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor


class ConstructorScanTests(unittest.TestCase):
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
