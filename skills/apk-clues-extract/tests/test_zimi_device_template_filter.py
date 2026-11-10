import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import extract_clues

TEMPLATE = '5b3b98a1-4381-48d9-a2f1-cd43aea57385'
SERVICE = '77992fb9-e6bc-4872-8ab7-f5707802ac12'
SOURCE = f'''package life.zimi.domain.util;
import android.bluetooth.BluetoothGatt;
public final class DomainConstants {{
  public static final String claytonDeviceTemplateId = "{TEMPLATE}";
  public static final String OTHER_SERVICE_UUID = "{SERVICE}";
  public static final byte UUID_1 = -15;
}}
'''


def scan(files):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / 'sources'
        root.mkdir()
        for name, text in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return extract_clues.scan_jadx_output(tmp)


class ZimiDeviceTemplateTests(unittest.TestCase):
    def test_only_unreferenced_template_is_filtered(self):
        found = scan({'DomainConstants.java': SOURCE})
        self.assertNotIn(TEMPLATE, found)
        self.assertIn(SERVICE, found)

    def test_independent_gatt_field_use_is_preserved(self):
        consumer = '''package example;
import life.zimi.domain.util.DomainConstants;
class Client { Object go(android.bluetooth.BluetoothGatt g) {
 return g.getService(java.util.UUID.fromString(DomainConstants.claytonDeviceTemplateId));
}}
'''
        found = scan({'DomainConstants.java': SOURCE, 'Client.java': consumer})
        self.assertIn(TEMPLATE, found)
        self.assertEqual('GATT Service', found[TEMPLATE]['classification'])

    def test_independent_literal_and_non_gatt_field_use_are_preserved(self):
        for consumer in [f'class Other {{ String id = "{TEMPLATE}"; }}',
                         'class Other { Object id = DomainConstants.claytonDeviceTemplateId; }']:
            with self.subTest(consumer=consumer):
                found = scan({'DomainConstants.java': SOURCE, 'Other.java': consumer})
                self.assertIn(TEMPLATE, found)

    def test_other_package_and_gatt_alias_are_not_filtered(self):
        for source in [SOURCE.replace('life.zimi.domain.util', 'example'),
                       SOURCE.replace('public static final byte UUID_1',
                           f'public static final String SERVICE_UUID = "{TEMPLATE}";\n  public static final byte UUID_1')]:
            with self.subTest(source=source):
                self.assertIn(TEMPLATE, scan({'DomainConstants.java': source}))

    def test_same_class_non_gatt_use_is_preserved(self):
        source = SOURCE.replace('public static final byte UUID_1',
                                'String getId() { return claytonDeviceTemplateId; }\n  public static final byte UUID_1')
        self.assertIn(TEMPLATE, scan({'DomainConstants.java': source}))


if __name__ == '__main__':
    unittest.main()
