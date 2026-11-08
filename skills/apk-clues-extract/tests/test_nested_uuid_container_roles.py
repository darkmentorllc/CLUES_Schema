import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


class NestedUuidContainerRoleTests(unittest.TestCase):
    def scan(self, source: str) -> dict[str, dict]:
        with tempfile.TemporaryDirectory(prefix="clues-nested-uuid-role-") as tmp:
            path = Path(tmp) / "Profile.java"
            path.write_text(source, encoding="utf-8")
            return extractor.scan_one_file(str(path))

    def test_characteristics_member_type_overrides_service_only_file_default(self):
        uuid = "d0123456-1234-4abc-8def-0123456789ab"
        found = self.scan(f'''package example;
import java.util.UUID;
import android.bluetooth.BluetoothGattService;
class BleProfile {{
    interface Characteristics {{
        UUID DATA = UUID.fromString("{uuid}");
    }}
}}
''')
        self.assertEqual(found[uuid]["classification"], "GATT Characteristic")
        self.assertEqual(found[uuid]["classification_source"], "nested-type:Characteristics")

    def test_gatt_services_member_type_overrides_characteristic_only_file_default(self):
        uuid = "d1123456-1234-4abc-8def-0123456789ab"
        found = self.scan(f'''package example;
import java.util.UUID;
import android.bluetooth.BluetoothGattCharacteristic;
class BleProfile {{
    interface GattServices {{
        UUID PROFILE = UUID.fromString("{uuid}");
    }}
}}
''')
        self.assertEqual(found[uuid]["classification"], "GATT Service")
        self.assertEqual(found[uuid]["classification_source"], "nested-type:GattServices")

    def test_unrelated_nested_type_does_not_inherit_sibling_role(self):
        uuid = "d2123456-1234-4abc-8def-0123456789ab"
        found = self.scan(f'''package example;
import java.util.UUID;
import android.bluetooth.BluetoothGattService;
class BleProfile {{
    interface Characteristics {{ UUID CHAR = UUID.fromString("d3123456-1234-4abc-8def-0123456789ab"); }}
    interface Metadata {{ UUID DATA = UUID.fromString("{uuid}"); }}
}}
''')
        self.assertEqual(found[uuid]["classification"], "GATT Service")
        self.assertNotEqual(found[uuid]["classification_source"], "nested-type:Characteristics")
        self.assertNotEqual(found[uuid]["classification_source"], "nested-type:Metadata")

    def test_top_level_role_named_type_is_not_a_nested_container(self):
        uuid = "d4123456-1234-4abc-8def-0123456789ab"
        found = self.scan(f'''package example;
import java.util.UUID;
import android.bluetooth.BluetoothGattService;
interface Characteristics {{ UUID DATA = UUID.fromString("{uuid}"); }}
''')
        self.assertEqual(found[uuid]["classification"], "GATT Service")
        self.assertNotEqual(found[uuid]["classification_source"], "nested-type:Characteristics")

    def test_direct_usage_overrides_conflicting_nested_type_name(self):
        uuid = "d5123456-1234-4abc-8def-0123456789ab"
        found = self.scan(f'''package example;
import java.util.UUID;
import android.bluetooth.BluetoothGattService;
class BleProfile {{
    interface Characteristics {{ UUID DATA = UUID.fromString("{uuid}"); }}
    void read(android.bluetooth.BluetoothGatt gatt) {{ gatt.getService(DATA); }}
}}
''')
        self.assertEqual(found[uuid]["classification"], "GATT Service")
        self.assertEqual(found[uuid]["classification_source"], "usage:getService")

    def test_explicit_field_name_wins_over_conflicting_nested_type_name(self):
        uuid = "d7123456-1234-4abc-8def-0123456789ab"
        found = self.scan(f'''package example;
import java.util.UUID;
import android.bluetooth.BluetoothGattService;
class BleProfile {{
    interface Characteristics {{
        UUID SERVICE_UUID = UUID.fromString("{uuid}");
    }}
}}
''')
        self.assertEqual(found[uuid]["classification"], "GATT Service")
        self.assertEqual(found[uuid]["classification_source"], "field-name:SERVICE_UUID")

    def test_conflicting_role_named_containers_abstain(self):
        uuid = "d8123456-1234-4abc-8def-0123456789ab"
        found = self.scan(f'''package example;
import java.util.UUID;
import android.bluetooth.BluetoothGattService;
class BleProfile {{
    interface Characteristics {{ UUID FIRST = UUID.fromString("{uuid}"); }}
    interface GattServices {{ UUID SECOND = UUID.fromString("{uuid}"); }}
}}
''')
        self.assertNotEqual(found[uuid]["classification_source"], "nested-type:Characteristics")
        self.assertNotEqual(found[uuid]["classification_source"], "nested-type:GattServices")

    def test_nested_role_source_is_protected_from_weaker_sdk_value_hint(self):
        uuid = "d6123456-1234-4abc-8def-0123456789ab"
        with patch.dict(extractor.KNOWN_SDK_UUIDS, {uuid: {"name": "TEST_SERVICE"}}):
            self.assertEqual(
                extractor._classification_with_sdk_cache(
                    uuid, "GATT Characteristic", "nested-type:Characteristics"
                ),
                "GATT Characteristic",
            )


if __name__ == "__main__":
    unittest.main()
