import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


class Shard03ScopedNonGattContextTests(unittest.TestCase):
    @staticmethod
    def write_java(root: Path, relative: str, source: str) -> Path:
        path = root / "sources" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def test_kisi_scan_region_array_is_scoped_and_same_value_gatt_use_survives(self):
        beacon = "11112222-3333-4444-aaaa-bbbbccccdddd"
        other_beacon = "22223333-4444-5555-aaaa-bbbbccccdddd"
        unrelated_beacon = "33334444-5555-6666-aaaa-bbbbccccdddd"
        with tempfile.TemporaryDirectory(prefix="clues-shard03-kisi-region-") as tmp:
            root = Path(tmp)
            tracker = self.write_java(root, "de/kisi/android/nearby/KisiBeaconTracker.java", f'''package de.kisi.android.nearby;
import java.util.UUID;
import org.altbeacon.beacon.Region;
class KisiBeaconTracker {{
    static final UUID[] KISI_BEACON_UUIDS = {{ UUID.fromString("{beacon}"), UUID.fromString("{other_beacon}"), UUID.fromString("{unrelated_beacon}") }};
    void configure(Region.Builder region) {{ region.addUuidField(KISI_BEACON_UUIDS[0]); }}
}}
''')
            self.write_java(root, "example/GattProfile.java", f'''package example;
import android.bluetooth.BluetoothGatt;
import java.util.UUID;
class GattProfile {{
    static final UUID SERVICE = UUID.fromString("{beacon}");
    BluetoothGatt gatt;
    void connect() {{ gatt.getService(SERVICE); }}
}}
''')
            tracker_candidates = extractor.scan_one_file(str(tracker))
            found = extractor.scan_jadx_output(str(root))

        self.assertNotIn(beacon, tracker_candidates)
        self.assertNotIn(other_beacon, tracker_candidates)
        self.assertEqual(found[beacon]["classification"], "GATT Service")

    def test_feasy_proximity_field_does_not_suppress_gatt_fields_in_same_class(self):
        beacon = "44445555-6666-7777-aaaa-bbbbccccdddd"
        service = "55556666-7777-8888-aaaa-bbbbccccdddd"
        characteristic = "66667777-8888-9999-aaaa-bbbbccccdddd"
        with tempfile.TemporaryDirectory(prefix="clues-shard03-feasy-region-") as tmp:
            root = Path(tmp)
            source_path = self.write_java(root, "com/kastle/kastlesdk/ble/util/constant/KSBLEConstants.java", f'''package com.kastle.kastlesdk.ble.util.constant;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
class KSBLEConstants {{
    static final String FEASY_BEACON_PROXIMITY_UUID = "{beacon}";
    static final UUID DEVICE_SERVICE = UUID.fromString("{service}");
    static final UUID WRITE_CHAR = UUID.fromString("{characteristic}");
    static final UUID OTHER = UUID.fromString("77778888-9999-aaaa-bbbb-ccccddddeeee");
    BluetoothGatt gatt;
    void connect() {{ BluetoothGattService svc = gatt.getService(DEVICE_SERVICE); svc.getCharacteristic(WRITE_CHAR); }}
}}
''')
            found = extractor.scan_jadx_output(str(root))
            local = extractor.scan_one_file(str(source_path))

        self.assertNotIn(beacon, local)
        self.assertEqual(found[service]["classification"], "GATT Service")
        self.assertEqual(found[characteristic]["classification"], "GATT Characteristic")

    def test_appconst_signing_keys_are_filtered_without_hiding_printer_gatt(self):
        keys = {
            "FORMALKEY": "88889999-aaaa-bbbb-cccc-ddddeeeeffff",
            "SMSKEY": "9999aaaa-bbbb-cccc-dddd-eeeeffff0000",
            "PERMISSIONKEY": "aaaa1111-bbbb-cccc-dddd-eeeeffff0000",
            "NETTYKEY": "bbbb2222-cccc-dddd-eeee-ffff00001111",
            "EMAILKEY": "cccc3333-dddd-eeee-ffff-000011112222",
        }
        duplicate_gatt = keys["FORMALKEY"]
        service = "0000ff00-0000-1000-8000-00805f9b34fb"
        read_char = "0000ff01-0000-1000-8000-00805f9b34fb"
        write_char = "0000ff02-0000-1000-8000-00805f9b34fb"
        with tempfile.TemporaryDirectory(prefix="clues-shard03-appconst-") as tmp:
            root = Path(tmp)
            appconst = "\n".join(
                ["package com.yhk.rabbit.print.utils;", "class AppConst {"]
                + [f'    static String {name} = "{uuid}";' for name, uuid in keys.items()]
                + ["}"]
            )
            self.write_java(root, "com/yhk/rabbit/print/utils/AppConst.java", appconst)
            self.write_java(root, "com/printer/psdk/device/bluetooth/ble/ConnectionImplBle.java", f'''package com.printer.psdk.device.bluetooth.ble;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
class ConnectionImplBle {{
    static final String SERVICE = "{service}";
    static final String CHARACTERISTIC_READ = "{read_char}";
    static final String CHARACTERISTIC_WRITE = "{write_char}";
    // Spacer lines keep the source context distinct from the literal rows.
    // Actual ConnectionImplBle places its GATT traversal well below constants.
    // 1
    // 2
    // 3
    // 4
    // 5
    // 6
    // 7
    // 8
    // 9
    // 10
    // 11
    // 12
    BluetoothGatt gatt;
    void onServicesDiscovered() {{
        for (BluetoothGattService svc : gatt.getServices()) {{
            if (svc.getUuid().toString().equalsIgnoreCase(SERVICE)) {{
                for (BluetoothGattCharacteristic ch : svc.getCharacteristics()) {{
                    if (ch.getUuid().toString().equalsIgnoreCase(CHARACTERISTIC_READ)) {{ }}
                    if (ch.getUuid().toString().equalsIgnoreCase(CHARACTERISTIC_WRITE)) {{ }}
                }}
            }}
        }}
    }}
}}
''')
            self.write_java(root, "example/OtherGattProfile.java", f'''package example;
import android.bluetooth.BluetoothGatt;
import java.util.UUID;
class OtherGattProfile {{
    static final UUID SERVICE = UUID.fromString("{duplicate_gatt}");
    BluetoothGatt gatt;
    void connect() {{ gatt.getService(SERVICE); }}
}}
''')
            appconst_candidates = extractor.scan_one_file(
                str(root / "sources/com/yhk/rabbit/print/utils/AppConst.java")
            )
            found = extractor.scan_jadx_output(str(root))

        for uuid in keys.values():
            self.assertNotIn(uuid, appconst_candidates)
        self.assertEqual(found[service]["classification"], "GATT Service")
        self.assertEqual(found[read_char]["classification"], "GATT Characteristic")
        self.assertEqual(found[write_char]["classification"], "GATT Characteristic")
        # FORMALKEY's value is still available when an independent GATT class
        # uses that same UUID as a real service identifier.
        self.assertEqual(found[duplicate_gatt]["classification"], "GATT Service")

    def test_brand_oauth_client_id_hints_are_exact_package_and_class_scoped(self):
        properties = [
            (
                "com.ce.android.brand.jerusalemcafe",
                "JerusalemCafeProperties",
                "3bf86445-023d-45d8-a178-b7bbe1a18a19",
            ),
            (
                "com.ce.android.brand.rubinsteinbagels",
                "RubinsteinBagelsProperties",
                "ed4a2481-54fb-4e16-8aa1-4b357722ce06",
            ),
            (
                "com.ce.android.brand.bellacinos",
                "BellacinosProperties",
                "cecbe765-7d08-4479-ba71-b33f01ed7fa5",
            ),
            (
                "com.ce.android.brand.icebergdriveinn",
                "IcebergDriveInnProperties",
                "dbc163cb-9a5e-400c-9d28-4a8ea92703d9",
            ),
        ]
        with tempfile.TemporaryDirectory(prefix="clues-shard03-brand-client-id-") as tmp:
            root = Path(tmp)
            scoped_candidates = []
            for package, class_name, uuid in properties:
                relative = package.replace(".", "/") + "/" + class_name + ".java"
                source_path = self.write_java(
                    root,
                    relative,
                    f'''package {package};
class {class_name} {{
    private static final String CLIENT_ID = "{uuid}";
    String getClientIdProd() {{ return CLIENT_ID; }}
}}
''',
                )
                scoped_candidates.append(extractor.scan_one_file(str(source_path)))

            # Identical field name in unrelated app code is not covered by the
            # source-specific OAuth hint and still reaches a typed GATT sink.
            duplicate = properties[0][2]
            other = self.write_java(root, "example/OtherProfile.java", f'''package example;
import android.bluetooth.BluetoothGatt;
import java.util.UUID;
class OtherProfile {{
    static final UUID CLIENT_ID = UUID.fromString("{duplicate}");
    BluetoothGatt gatt;
    void connect() {{ gatt.getService(CLIENT_ID); }}
}}
''')
            found = extractor.scan_jadx_output(str(root))
            other_candidates = extractor.scan_one_file(str(other))

        for (package, class_name, uuid), candidates in zip(properties, scoped_candidates):
            self.assertNotIn(uuid, candidates, (package, class_name))
        self.assertIn(duplicate, other_candidates)
        self.assertEqual(found[duplicate]["classification"], "GATT Service")


if __name__ == "__main__":
    unittest.main()
