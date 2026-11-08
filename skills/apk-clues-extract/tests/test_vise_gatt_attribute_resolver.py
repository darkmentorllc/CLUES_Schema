import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


PAN = "00001300-0000-1000-8000-00805f9b34fb"
LAP = "00001301-0000-1000-8000-00805f9b34fb"
L2CAP = "00001302-0000-1000-8000-00805f9b34fb"
ESTIMOTE_SERVICE = "b9403000-f5f8-466e-aff9-25556b57fe6d"


def resolver_source(with_gatt_sinks: bool = False) -> str:
    sink_methods = ""
    imports = ""
    if with_gatt_sinks:
        imports = '''import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
'''
        sink_methods = '''
    BluetoothGattService findPan(BluetoothGatt gatt) {
        return gatt.getService(UUID.fromString(ESDP_UPNP_IP_PAN));
    }
    BluetoothGattService findEstimote(BluetoothGatt gatt) {
        return gatt.getService(UUID.fromString(ESTIMOTE_SERVICE));
    }
'''
    return f'''package com.vise.baseble.model.resolver;
{imports}import java.util.HashMap;
import java.util.Map;
final class GattAttributeResolver {{
    public static final String ESDP_UPNP_IP_PAN = "{PAN}";
    public static final String ESDP_UPNP_IP_LAP = "{LAP}";
    public static final String ESDP_UPNP_L2CAP = "{L2CAP}";
    public static final String ESTIMOTE_SERVICE = "{ESTIMOTE_SERVICE}";
    private static final Map<String, String> sGattAttributesMap = populateGattAttributesMap();
    private static Map<String, String> populateGattAttributesMap() {{
        HashMap map = new HashMap();
        map.put(ESDP_UPNP_IP_PAN, "ESDP UPnP IP PAN");
        map.put(ESDP_UPNP_IP_LAP, "ESDP UPnP IP LAP");
        map.put(ESDP_UPNP_L2CAP, "ESDP UPnP L2CAP");
        map.put(ESTIMOTE_SERVICE, "Estimote Service");
        return map;
    }}
{sink_methods}
}}
'''


class ViseGattAttributeResolverTests(unittest.TestCase):
    def scan(self, source: str) -> dict[str, dict]:
        with tempfile.TemporaryDirectory(prefix="clues-vise-resolver-") as tmp:
            path = Path(tmp) / "GattAttributeResolver.java"
            path.write_text(source, encoding="utf-8")
            return extractor.scan_one_file(str(path))

    def test_classic_sdp_service_class_ids_are_filtered_in_resolver_table(self):
        found = self.scan(resolver_source())
        for value in (PAN, LAP, L2CAP):
            with self.subTest(uuid=value):
                self.assertNotIn(value, found)
                self.assertNotIn(value, extractor.KNOWN_NON_BLE_UUIDS)
        # The exact same table also contains an actual GATT service UUID.
        self.assertIn(ESTIMOTE_SERVICE, found)

    def test_explicit_gatt_sink_overrides_vise_field_hint(self):
        found = self.scan(resolver_source(with_gatt_sinks=True))
        self.assertIn(PAN, found)
        self.assertEqual(found[PAN]["classification"], "GATT Service")
        self.assertNotIn(LAP, found)
        self.assertNotIn(L2CAP, found)
        self.assertIn(ESTIMOTE_SERVICE, found)

    def test_same_value_remains_eligible_outside_vise_lookup_table(self):
        source = f'''package com.example.ble;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
final class DeviceProfile {{
    private static final String SERVICE_UUID = "{PAN}";
    BluetoothGattService find(BluetoothGatt gatt) {{
        return gatt.getService(UUID.fromString(SERVICE_UUID));
    }}
}}
'''
        found = self.scan(source)
        self.assertIn(PAN, found)
        self.assertEqual(found[PAN]["classification"], "GATT Service")
        self.assertNotIn(PAN, extractor.KNOWN_NON_BLE_UUIDS)


if __name__ == "__main__":
    unittest.main()
