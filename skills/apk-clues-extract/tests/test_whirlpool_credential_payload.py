import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import extract_clues as extractor

UUID = 'b2732a5c-9069-4ec4-b49e-a5864a429d2f'


def scan(package, class_name, body):
    source = f'''package {package};
import java.util.UUID;
class {class_name} {{
  private String accessCredentials;
  android.bluetooth.BluetoothGattService service;
  {body}
}}
'''
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / (class_name + '.java')
        path.write_text(source)
        return extractor.scan_one_file(str(path))


class WhirlpoolCredentialPayloadTest(unittest.TestCase):
    def test_scoped_credential_value_is_not_gatt(self):
        body = f'void f() {{ this.accessCredentials = "{UUID}"; }}'
        self.assertNotIn(UUID, scan('com.whirlpool.blegattclient', 'GattClient', body))
        self.assertIn(UUID, scan('other.package', 'GattClient', body))
        self.assertIn(UUID, scan('com.whirlpool.blegattclient', 'OtherClient', body))

    def test_direct_gatt_use_overrides_hint(self):
        body = f'''android.bluetooth.BluetoothGatt gatt;
void f() {{ this.accessCredentials = "{UUID}"; gatt.getService(UUID.fromString(accessCredentials)); }}'''
        self.assertIn(UUID, scan('com.whirlpool.blegattclient', 'GattClient', body))
