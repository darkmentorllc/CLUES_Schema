import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
import extract_clues

HOTEL_UUID = "95b8d689-f3da-47fd-bf69-4c2c56083ed6"
OTHER_UUID = "f6d3a8d2-45b7-4ad2-9f22-2a7440b8c3c1"

BUILD_CONFIG = f'''package com.shhotels;
public final class BuildConfig {{
  public static final String BACCARAT_NEWYORK = "{HOTEL_UUID}";
  public static final String BROOKLYN_BRIDGE_HOTEL_ID = "{HOTEL_UUID}";
  public static final String CENTRAL_PARK_HOTEL_ID = "{HOTEL_UUID}";
  public static final String MARKETING_CLOUD_ID = "{OTHER_UUID}";
}}
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


class BuildConfigHotelUuidFilterTests(unittest.TestCase):
    def test_hotel_id_uuid_only_in_build_config_is_suppressed(self):
        found = scan_sources({"com/shhotels/BuildConfig.java": BUILD_CONFIG})
        self.assertNotIn(HOTEL_UUID, found)
        self.assertIn(OTHER_UUID, found)

    def test_hotel_id_uuid_used_as_gatt_service_is_preserved(self):
        consumer = '''package app;
class HotelBleClient {
  Object connect(Object gatt) {
    return gatt.getService(com.shhotels.BuildConfig.BROOKLYN_BRIDGE_HOTEL_ID);
  }
}
'''
        found = scan_sources({
            "com/shhotels/BuildConfig.java": BUILD_CONFIG,
            "app/HotelBleClient.java": consumer,
        })
        self.assertIn(HOTEL_UUID, found)
        self.assertEqual("GATT Service", found[HOTEL_UUID]["classification"])
        self.assertIn("getService", found[HOTEL_UUID]["classification_source"])

    def test_hotel_id_uuid_with_external_literal_gatt_use_is_preserved(self):
        consumer = f'''package app;
class HotelBleClient {{
  Object connect(Object gatt) {{
    return gatt.getCharacteristic(java.util.UUID.fromString("{HOTEL_UUID}"));
  }}
}}
'''
        found = scan_sources({
            "com/shhotels/BuildConfig.java": BUILD_CONFIG,
            "app/HotelBleClient.java": consumer,
        })
        self.assertIn(HOTEL_UUID, found)

    def test_gatt_semantic_build_config_name_is_not_suppressed(self):
        source = f'''package app;
public final class BuildConfig {{
  public static final String GATT_SERVICE_HOTEL_ID = "{HOTEL_UUID}";
}}
'''
        found = scan_sources({"app/BuildConfig.java": source})
        self.assertIn(HOTEL_UUID, found)

    def test_gatt_named_alias_sharing_hotel_uuid_is_not_suppressed(self):
        source = f'''package app;
public final class BuildConfig {{
  public static final String HOTEL_ID = "{HOTEL_UUID}";
  public static final String CUSTOM_SERVICE_UUID = "{HOTEL_UUID}";
}}
'''
        found = scan_sources({"app/BuildConfig.java": source})
        self.assertIn(HOTEL_UUID, found)


if __name__ == "__main__":
    unittest.main()
