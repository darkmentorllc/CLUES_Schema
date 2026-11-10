import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
import extract_clues as e

S1 = '98bd0010-0b0e-421a-84e5-ddbf75dc6de4'
C1 = '98bd0011-0b0e-421a-84e5-ddbf75dc6de4'
S2 = '98bd0100-0b0e-421a-84e5-ddbf75dc6de4'
C2 = '98bd0101-0b0e-421a-84e5-ddbf75dc6de4'

def fixture(package='com.gardena.libraries.bluetooth_watering.api', assignments=None):
    assignments = assignments or 'this.serviceUUID = uuid; this.characteristicUUID = uuid2;'
    return f'''package {package};
import java.util.UUID;
abstract class ReadCharacteristic<T> {{
 private ReadCharacteristic(UUID uuid, UUID uuid2) {{ {assignments} }}
 static class Value extends ReadCharacteristic<Integer> {{
  private Value() {{
   UUID temp = UUID.fromString("{S1}");
   UUID temp2 = UUID.fromString("{C1}");
   super(temp, temp2, null);
  }}
 }}
 static class Status extends ReadCharacteristic<Integer> {{
  private Status() {{
   UUID temp = UUID.fromString("{S2}");
   UUID temp2 = UUID.fromString("{C2}");
   super(temp, temp2, null);
  }}
 }}
}}
'''

class GardenaSuperPairTests(unittest.TestCase):
    def scan(self, source):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'ReadCharacteristic.java'
            p.write_text(source)
            return e.scan_one_file(str(p))

    def test_constructor_local_temps_keep_each_objects_parent(self):
        got = self.scan(fixture())
        for service, char in [(S1,C1),(S2,C2)]:
            self.assertEqual(got[service]['classification'], 'GATT Service')
            self.assertEqual(got[service]['parent_candidates'], [])
            self.assertEqual(got[char]['classification'], 'GATT Characteristic')
            self.assertEqual(got[char]['parent_candidates'], [service])

    def test_write_constructor_allows_byte_array_payload(self):
        text = fixture().replace('ReadCharacteristic', 'WriteCharacteristic')
        text = text.replace('UUID uuid2) {', 'UUID uuid2, byte[] data) {')
        text = text.replace('super(temp, temp2, null);', 'super(temp, temp2, new byte[]{1}, null);')
        self.assertEqual(set(e._gardena_api_super_uuid_pairs(text)), {(S1,C1),(S2,C2)})

    def test_wrong_package_is_not_assigned_gardena_roles(self):
        self.assertEqual(e._gardena_api_super_uuid_pairs(fixture('example')), [])

    def test_base_assignment_order_must_be_proven(self):
        text = fixture(assignments='this.characteristicUUID = uuid; this.serviceUUID = uuid2;')
        self.assertEqual(e._gardena_api_super_uuid_pairs(text), [])

    def test_reassigned_temp_fails_closed(self):
        text = fixture().replace('super(temp, temp2, null);', 'temp = other; super(temp, temp2, null);')
        self.assertEqual(e._gardena_api_super_uuid_pairs(text), [])

    def test_unrelated_subclass_does_not_inherit_slot_convention(self):
        text = fixture().replace('extends ReadCharacteristic<Integer>', 'extends Other<Integer>')
        self.assertEqual(e._gardena_api_super_uuid_pairs(text), [])

    def test_direct_characteristic_usage_remains_stronger(self):
        text = fixture() + f'\nclass OtherUsage {{ static UUID OWN = UUID.fromString("{S1}"); void run() {{ gatt.getCharacteristic(OWN); }} }}'
        got = self.scan(text)
        self.assertEqual(got[S1]['classification'], 'GATT Characteristic')
        self.assertTrue(got[S1]['classification_source'].startswith('usage:'))

if __name__ == '__main__': unittest.main()
