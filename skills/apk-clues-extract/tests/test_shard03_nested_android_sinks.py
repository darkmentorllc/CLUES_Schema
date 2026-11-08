import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


class Shard03NestedAndroidSinkTests(unittest.TestCase):
    @staticmethod
    def write_java(root: Path, relative: str, source: str) -> None:
        path = root / "sources" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    def test_wrapped_direct_and_chained_get_characteristic_bind_to_android_types(self):
        service = "11223344-1234-5678-9abc-def012345678"
        direct_char = "22334455-1234-5678-9abc-def012345678"
        chained_char = "33445566-1234-5678-9abc-def012345678"
        with tempfile.TemporaryDirectory(prefix="clues-shard03-nested-sink-") as tmp:
            root = Path(tmp)
            self.write_java(root, "example/Ids.java", f'''package example;
public final class Ids {{
    public static final String PROFILE = "{service}";
    public static final String DIRECT = "{direct_char}";
    public static final String CHAINED = "{chained_char}";
}}
''')
            self.write_java(root, "example/GattClient.java", '''package example;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
class GattClient {
    BluetoothGatt gatt;
    void discover() {
        BluetoothGattService service = gatt.getService(UUID.fromString(Ids.PROFILE));
        service.getCharacteristic(UUID.fromString(Ids.DIRECT));
        gatt.getService(UUID.fromString(Ids.PROFILE)).getCharacteristic(UUID.fromString(Ids.CHAINED));
    }
}
''')
            found = extractor.scan_jadx_output(str(root))

        self.assertEqual(found[service]["classification"], "GATT Service")
        self.assertEqual(found[direct_char]["classification"], "GATT Characteristic")
        self.assertEqual(found[chained_char]["classification"], "GATT Characteristic")
        self.assertEqual(found[direct_char]["classification_source"], "cross-file usage:getCharacteristic(DIRECT)")
        self.assertEqual(found[chained_char]["classification_source"], "cross-file usage:getCharacteristic(CHAINED)")

    def test_typed_android_characteristic_constructor_accepts_uuid_from_string(self):
        characteristic = "44556677-1234-5678-9abc-def012345678"
        with tempfile.TemporaryDirectory(prefix="clues-shard03-ctor-sink-") as tmp:
            root = Path(tmp)
            self.write_java(root, "example/Ids.java", f'''package example;
public final class Ids {{
    public static final String SERVICE = "55667788-1234-5678-9abc-def012345678";
            public static final String CHARACTERISTIC = "{characteristic}";
    public static final String OTHER = "66778899-1234-5678-9abc-def012345678";
}}
''')
            self.write_java(root, "example/Server.java", '''package example;
import android.bluetooth.BluetoothGattCharacteristic;
import java.util.UUID;
class Server {
    void configure() {
        BluetoothGattCharacteristic ch = new BluetoothGattCharacteristic(UUID.fromString(Ids.CHARACTERISTIC), 2, 1);
    }
}
''')
            found = extractor.scan_jadx_output(str(root))

        self.assertEqual(found[characteristic]["classification"], "GATT Characteristic")
        self.assertEqual(
            found[characteristic]["classification_source"],
            "cross-file constructor:new BluetoothGattCharacteristic(CHARACTERISTIC)",
        )

    def test_same_simple_class_and_field_in_another_package_do_not_cross_bind(self):
        good_uuid = "77889900-1234-5678-9abc-def012345678"
        bad_uuid = "88990011-1234-5678-9abc-def012345678"
        with tempfile.TemporaryDirectory(prefix="clues-shard03-owner-scope-") as tmp:
            root = Path(tmp)
            self.write_java(root, "com/good/GattIds.java", f'''package com.good;
public final class GattIds {{
    public static final String DATA = "{good_uuid}";
    public static final String OTHER1 = "99001122-1234-5678-9abc-def012345678";
    public static final String OTHER2 = "a0112233-1234-5678-9abc-def012345678";
}}
''')
            self.write_java(root, "com/bad/GattIds.java", f'''package com.bad;
public final class GattIds {{
    public static final String DATA = "{bad_uuid}";
    public static final String OTHER1 = "b0112233-1234-5678-9abc-def012345678";
    public static final String OTHER2 = "c0112233-1234-5678-9abc-def012345678";
}}
''')
            self.write_java(root, "com/bad/client/Reader.java", '''package com.bad.client;
import android.bluetooth.BluetoothGattService;
import com.bad.GattIds;
import java.util.UUID;
class Reader {
    void read(BluetoothGattService service) {
        service.getCharacteristic(UUID.fromString(GattIds.DATA));
    }
}
''')
            found = extractor.scan_jadx_output(str(root))

        self.assertEqual(found[bad_uuid]["classification"], "GATT Characteristic")
        # The reference resolves to com.bad.GattIds.CHAR only. The unrelated
        # com.good.GattIds.CHAR must keep its weak constants-file default.
        self.assertEqual(found[good_uuid]["classification"], "GATT Service")
        self.assertEqual(found[good_uuid]["classification_source"], "file-level-default")


if __name__ == "__main__":
    unittest.main()
