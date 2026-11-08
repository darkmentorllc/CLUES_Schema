import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


class CrossFileGattConstructorRoleTests(unittest.TestCase):
    def scan_sources(self, files: dict[str, str]) -> dict[str, dict]:
        with tempfile.TemporaryDirectory(prefix="clues-typed-gatt-ctor-") as tmp:
            root = Path(tmp) / "sources"
            for relative, text in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            return extractor.scan_jadx_output(tmp)

    def test_cross_file_uuid_aliases_take_role_from_android_gatt_constructors(self):
        service = "30e3a361-87be-46db-b76b-fdd4925200eb"
        characteristic = "7c9772e1-b768-4154-a6fc-5d39ef87156d"
        found = self.scan_sources(
            {
                "com/utc/fs/trframework/k.java": f'''package com.utc.fs.trframework;
import java.util.UUID;
public abstract class k {{
    static final UUID a = UUID.fromString("0000fea7-0000-1000-8000-00805f9b34fb");
    static final UUID b = UUID.fromString("{service}");
    static final UUID c = UUID.fromString("{characteristic}");
}}
''',
                "com/utc/fs/trframework/TRFramework.java": '''package com.utc.fs.trframework;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothGattCharacteristic;
import java.util.UUID;
class TRFramework {
    private void configure() {
        UUID uuid2 = k.b;
        UUID uuid3 = k.c;
        BluetoothGattService service = new BluetoothGattService(uuid2, 0);
        service.addCharacteristic(new BluetoothGattCharacteristic(uuid3, 12, 16));
    }
}
''',
            }
        )
        self.assertEqual(found[service]["classification"], "GATT Service")
        self.assertEqual(
            found[service]["classification_source"],
            "cross-file constructor:new BluetoothGattService(b)",
        )
        self.assertEqual(found[characteristic]["classification"], "GATT Characteristic")
        self.assertEqual(
            found[characteristic]["classification_source"],
            "cross-file constructor:new BluetoothGattCharacteristic(c)",
        )

    def test_unqualified_custom_class_name_does_not_create_constructor_role(self):
        characteristic = "7c9772e1-b768-4154-a6fc-5d39ef87156d"
        found = self.scan_sources(
            {
                "com/example/ProfileIds.java": f'''package com.example;
import java.util.UUID;
public class ProfileIds {{
    static final UUID a = UUID.fromString("0000fea7-0000-1000-8000-00805f9b34fb");
    static final UUID b = UUID.fromString("30e3a361-87be-46db-b76b-fdd4925200eb");
    static final UUID c = UUID.fromString("{characteristic}");
}}
''',
                "com/example/ProfileBuilder.java": '''package com.example;
import java.util.UUID;
class BluetoothGattCharacteristic { BluetoothGattCharacteristic(UUID id, int p, int q) {} }
class ProfileBuilder {
    private void configure() {
        UUID uuid3 = ProfileIds.c;
        new BluetoothGattCharacteristic(uuid3, 12, 16);
    }
}
''',
            }
        )
        # The API-shaped local class isn't Android's GATT type; the UUID remains
        # on the weak constants-file default and receives no constructor source.
        self.assertEqual(found[characteristic]["classification"], "GATT Service")
        self.assertEqual(found[characteristic]["classification_source"], "file-level-default")


    def test_fully_qualified_constructor_does_not_bless_another_simple_name_call(self):
        service = "30e3a361-87be-46db-b76b-fdd4925200eb"
        characteristic = "7c9772e1-b768-4154-a6fc-5d39ef87156d"
        found = self.scan_sources({
            "com/utc/fs/trframework/k.java": f'''package com.utc.fs.trframework;
import java.util.UUID;
public abstract class k {{
    static final UUID a = UUID.fromString("0000fea7-0000-1000-8000-00805f9b34fb");
    static final UUID b = UUID.fromString("{service}");
    static final UUID c = UUID.fromString("{characteristic}");
}}
''',
            "com/utc/fs/trframework/TRFramework.java": '''package com.utc.fs.trframework;
import java.util.UUID;
class TRFramework {
    static class BluetoothGattCharacteristic { BluetoothGattCharacteristic(UUID u, int p, int q) {} }
    private void configure() {
        UUID uuid2 = k.b;
        UUID uuid3 = k.c;
        new android.bluetooth.BluetoothGattService(uuid2, 0);
        new BluetoothGattCharacteristic(uuid3, 12, 16);
    }
}
''',
        })
        self.assertEqual(found[service]["classification_source"], "cross-file constructor:new BluetoothGattService(b)")
        self.assertEqual(found[characteristic]["classification"], "GATT Service")
        self.assertEqual(found[characteristic]["classification_source"], "file-level-default")

    def test_imported_constructor_type_shadowed_by_local_nested_class_is_ignored(self):
        characteristic = "7c9772e1-b768-4154-a6fc-5d39ef87156d"
        found = self.scan_sources({
            "com/example/ProfileIds.java": f'''package com.example;
import java.util.UUID;
public class ProfileIds {{
    static final UUID a = UUID.fromString("0000fea7-0000-1000-8000-00805f9b34fb");
    static final UUID b = UUID.fromString("30e3a361-87be-46db-b76b-fdd4925200eb");
    static final UUID c = UUID.fromString("{characteristic}");
}}
''',
            "com/example/ProfileBuilder.java": '''package com.example;
import android.bluetooth.BluetoothGattCharacteristic;
import java.util.UUID;
class ProfileBuilder {
    static class BluetoothGattCharacteristic { BluetoothGattCharacteristic(UUID u, int p, int q) {} }
    private void configure() {
        UUID uuid3 = ProfileIds.c;
        new BluetoothGattCharacteristic(uuid3, 12, 16);
    }
}
''',
        })
        self.assertEqual(found[characteristic]["classification"], "GATT Service")
        self.assertEqual(found[characteristic]["classification_source"], "file-level-default")

    def test_wildcard_import_shadowed_by_local_class_is_ignored(self):
        characteristic = "7c9772e1-b768-4154-a6fc-5d39ef87156d"
        found = self.scan_sources({
            "com/example/ProfileIds.java": f'''package com.example;
import java.util.UUID;
public class ProfileIds {{
    static final UUID a = UUID.fromString("0000fea7-0000-1000-8000-00805f9b34fb");
    static final UUID b = UUID.fromString("30e3a361-87be-46db-b76b-fdd4925200eb");
    static final UUID c = UUID.fromString("{characteristic}");
}}
''',
            "com/example/ProfileBuilder.java": '''package com.example;
import android.bluetooth.*;
import java.util.UUID;
class ProfileBuilder {
    static class BluetoothGattCharacteristic { BluetoothGattCharacteristic(UUID u, int p, int q) {} }
    private void configure() {
        UUID uuid3 = ProfileIds.c;
        new BluetoothGattCharacteristic(uuid3, 12, 16);
    }
}
''',
        })
        self.assertEqual(found[characteristic]["classification"], "GATT Service")
        self.assertEqual(found[characteristic]["classification_source"], "file-level-default")

    def test_cross_file_constructor_source_is_authoritative_over_sdk_role_cache(self):
        source = "cross-file constructor:new BluetoothGattCharacteristic(c)"
        self.assertEqual(
            extractor._classification_with_sdk_cache("ffb0", "GATT Characteristic", source),
            "GATT Characteristic",
        )


if __name__ == "__main__":
    unittest.main()
