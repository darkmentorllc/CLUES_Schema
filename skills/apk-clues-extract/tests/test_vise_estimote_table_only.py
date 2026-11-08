import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
import extract_clues

ESTIMOTE = "b9403000-f5f8-466e-aff9-25556b57fe6d"
RESOLVER_SOURCE = '''package com.vise.baseble.model.resolver;
import android.bluetooth.BluetoothGattService;
public class GattAttributeResolver {
  public static final String ESTIMOTE_AUTHENTICATION_SERVICE = "b9402000-f5f8-466e-aff9-25556b57fe6d";
  public static final String ESTIMOTE_SERVICE = "b9403000-f5f8-466e-aff9-25556b57fe6d";
  public static final String ESTIMOTE_MAJOR = "b9403001-f5f8-466e-aff9-25556b57fe6d";
  public static final String ESTIMOTE_VERSION_SERVICE = "b9404000-f5f8-466e-aff9-25556b57fe6d";
  public static final String VISE_DEVICE_PROFILE = "b9405000-f5f8-466e-aff9-25556b57fe6d";
  static {
    sGattAttributesMap.put(ESTIMOTE_AUTHENTICATION_SERVICE, "Estimote Authentication Service");
    sGattAttributesMap.put(ESTIMOTE_SERVICE, "Estimote Service");
    sGattAttributesMap.put(ESTIMOTE_MAJOR, "Estimote Major");
    sGattAttributesMap.put(ESTIMOTE_VERSION_SERVICE, "Estimote Version Service");
    sGattAttributesMap.put(VISE_DEVICE_PROFILE, "Vise Device Profile");
  }
}
'''


def scan_sources(sources):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "sources"
        root.mkdir()
        for name, source in sources.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        return extract_clues.scan_jadx_output(tmp)


class ViseEstimoteTableOnlyTests(unittest.TestCase):
    def test_table_only_estimote_entries_are_suppressed_but_other_entry_stays(self):
        found = scan_sources({
            "com/vise/baseble/model/resolver/GattAttributeResolver.java": RESOLVER_SOURCE,
        })
        self.assertNotIn(ESTIMOTE, found)
        self.assertIn("b9405000-f5f8-466e-aff9-25556b57fe6d", found)
        self.assertTrue(all(
            ESTIMOTE not in entry["parent_candidates"] for entry in found.values()
        ))

    def test_cross_file_direct_gatt_field_use_keeps_estimote(self):
        consumer = f'''package app;
class BeaconClient {{
  Object connect(Object gatt) {{
    return gatt.getService(com.vise.baseble.model.resolver.GattAttributeResolver.ESTIMOTE_SERVICE);
  }}
}}
'''
        found = scan_sources({
            "com/vise/baseble/model/resolver/GattAttributeResolver.java": RESOLVER_SOURCE,
            "app/BeaconClient.java": consumer,
        })
        self.assertIn(ESTIMOTE, found)
        self.assertIn("getService", found[ESTIMOTE]["classification_source"])

    def test_cross_file_direct_characteristic_use_keeps_estimote(self):
        uuid = "b9403001-f5f8-466e-aff9-25556b57fe6d"
        consumer = '''package app;
class BeaconClient {
  Object connect(Object service) {
    return service.getCharacteristic(com.vise.baseble.model.resolver.GattAttributeResolver.ESTIMOTE_MAJOR);
  }
}
'''
        found = scan_sources({
            "com/vise/baseble/model/resolver/GattAttributeResolver.java": RESOLVER_SOURCE,
            "app/BeaconClient.java": consumer,
        })
        self.assertIn(uuid, found)
        self.assertEqual("GATT Characteristic", found[uuid]["classification"])
        self.assertIn("getCharacteristic", found[uuid]["classification_source"])

    def test_same_uuid_in_other_profile_is_not_globally_excluded(self):
        other_profile = f'''package app.profile;
import android.bluetooth.BluetoothGattService;
class EstimoteProfile {{
  static final java.util.UUID BEACON_SERVICE = java.util.UUID.fromString("{ESTIMOTE}");
  Object connect(Object gatt) {{ return gatt.getService(BEACON_SERVICE); }}
}}
'''
        found = scan_sources({
            "com/vise/baseble/model/resolver/GattAttributeResolver.java": RESOLVER_SOURCE,
            "app/profile/EstimoteProfile.java": other_profile,
        })
        self.assertIn(ESTIMOTE, found)

    def test_inline_literal_gatt_sink_keeps_estimote(self):
        consumer = f'''package app;
class BeaconClient {{
  Object connect(Object gatt) {{
    return gatt.getService(java.util.UUID.fromString("{ESTIMOTE}"));
  }}
}}
'''
        found = scan_sources({
            "com/vise/baseble/model/resolver/GattAttributeResolver.java": RESOLVER_SOURCE,
            "app/BeaconClient.java": consumer,
        })
        self.assertIn(ESTIMOTE, found)

    def test_non_sink_use_in_another_file_is_not_table_only(self):
        other_profile = f'''package app.profile;
class EstimoteProfile {{
  static final String PROFILE_UUID = "{ESTIMOTE}";
  String description() {{ return PROFILE_UUID; }}
}}
'''
        found = scan_sources({
            "com/vise/baseble/model/resolver/GattAttributeResolver.java": RESOLVER_SOURCE,
            "app/profile/EstimoteProfile.java": other_profile,
        })
        self.assertIn(ESTIMOTE, found)


if __name__ == "__main__":
    unittest.main()
