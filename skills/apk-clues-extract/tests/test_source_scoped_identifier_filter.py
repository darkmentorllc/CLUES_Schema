import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
import extract_clues as extractor


class CreditcallReceiptScopeTests(unittest.TestCase):
    def scan(self, source):
        with tempfile.TemporaryDirectory(prefix='creditcall-scope-') as directory:
            path = Path(directory) / 'Input.java'
            path.write_text(source)
            return extractor.scan_one_file(str(path))

    def test_receipt_ids_are_excluded_in_all_verified_classes(self):
        values = ['6987c6a7-28c7-db11-8109-0014222200e5',
                  '37954670-5f04-4eb2-9c61-7eb9c85c6ee7']
        for cls in ('ChaseReceiptData', 'ElavonReceiptData', 'FirstDataReceiptData',
                    'GlobalReceiptData', 'TsysReceiptData', 'UsHeartlandReceiptData',
                    'UsWorldpayReceiptData'):
            source = f'''package com.creditcall.chipdnamobile;
class {cls} {{
 static String a = "{values[0]}";
 static String b = "{values[1]}";
 static String c = "{values[0]}";
 static String d = "{values[1]}";
}}
'''
            with self.subTest(cls=cls):
                self.assertFalse(set(values) & set(self.scan(source)))

    def test_same_field_and_uuid_in_real_gatt_class_are_retained(self):
        value = '37954670-5f04-4eb2-9c61-7eb9c85c6ee7'
        source = f'''package com.creditcall.chipdnamobile;
import java.util.UUID;
import android.bluetooth.BluetoothGattService;
class BluetoothLePortComms {{
 static UUID c = UUID.fromString("{value}");
 void go(BluetoothGattService service) {{ service.getCharacteristic(c); }}
}}
'''
        found = self.scan(source)
        self.assertIn(value, found)
        self.assertEqual(found[value]['classification'], 'GATT Characteristic')

    def test_source_verified_descriptor_is_not_called_a_characteristic(self):
        value = '41a1396a-aec3-4ee5-8c63-3f6f25687c77'
        source = f'''package com.starkey.android.bluetooth;
class BluetoothConstantsKt {{
 static final String SSI_LONG_SIZE_DESCRIPTOR = "{value}";
 static final String SSI_LONG_SIZE_DESCRIPTOR2 = "296fd2f1-77cb-4b2f-9461-6c30181b6b16";
 static final String SSI_LONG_SIZE_DESCRIPTOR3 = "96aa43a5-1768-4328-9df6-c4269cb6c1cc";
}}
'''
        self.assertNotIn(value, self.scan(source))

    def test_openkey_test_app_id_is_not_a_gatt_uuid(self):
        value = '9e7a1f63-49b0-4b3a-ac5c-7c9e1a8c4dcb'
        source = f'''package com.keypr.mobilesdk.digitalkey.openkey.internal;
class OpenKeyMaterial {{
 static final String TEST_APP_ID = "{value}";
 static final String OTHER_APP_ID = "296fd2f1-77cb-4b2f-9461-6c30181b6b16";
 static final String OTHER_TEST_ID = "96aa43a5-1768-4328-9df6-c4269cb6c1cc";
}}
'''
        self.assertNotIn(value, self.scan(source))

    def test_same_receipt_class_in_another_package_is_not_filtered(self):
        value = '37954670-5f04-4eb2-9c61-7eb9c85c6ee7'
        source = f'''package com.example.ble;
import java.util.UUID;
import android.bluetooth.BluetoothGattService;
class ChaseReceiptData {{
 static UUID c = UUID.fromString("{value}");
 void go(BluetoothGattService service) {{ service.getCharacteristic(c); }}
}}
'''
        self.assertIn(value, self.scan(source))

if __name__ == '__main__':
    unittest.main()
