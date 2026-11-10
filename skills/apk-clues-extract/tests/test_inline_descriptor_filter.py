import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor


class InlineDescriptorFilterTests(unittest.TestCase):
    uuid = "0000dead-0000-1000-8000-00805f9b34fb"

    def scan(self, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Descriptor.java"
            path.write_text("import android.bluetooth.BluetoothGattDescriptor;\n" + source)
            return extractor.scan_one_file(str(path))

    def test_inline_descriptor_uuid_is_not_a_characteristic(self):
        source = f'class Demo {{ void read() {{ state.getDescriptor(UUID.fromString("{self.uuid}")); }} }}'
        self.assertNotIn(self.uuid, self.scan(source))

    def test_multiline_inline_descriptor_is_also_excluded(self):
        source = f'class Demo {{ void read() {{ state.getDescriptor(\n UUID.fromString(\n "{self.uuid}")); }} }}'
        self.assertNotIn(self.uuid, self.scan(source))

    def test_independent_service_use_of_same_uuid_survives(self):
        source = (f'class Demo {{ void read() {{ state.getDescriptor(UUID.fromString("{self.uuid}")); '
                  f'gatt.getService(UUID.fromString("{self.uuid}")); }} }}')
        self.assertIn(self.uuid, self.scan(source))


if __name__ == "__main__":
    unittest.main()
