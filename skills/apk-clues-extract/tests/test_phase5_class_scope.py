from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

TARGET = "6a24eeab-4b65-4693-986b-3c26c352264f"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as new


def write_source(root: Path, relative: str, text: str) -> None:
    p = root / "sources" / relative
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


class Phase5ClassScopeRegression(unittest.TestCase):
    def test_duplicate_obfuscated_field_does_not_borrow_other_class_gatt_role(self):
        with tempfile.TemporaryDirectory(prefix="phase5_scope_collision_") as td:
            root = Path(td)
            write_source(root, "com/sdk/SppTransport.java", f'''\
package com.sdk;
import android.bluetooth.BluetoothSocket;
import java.util.UUID;
public class SppTransport {{
    public static final UUID d = UUID.fromString("{TARGET}");
    public boolean connect(BluetoothSocket socket) {{ return socket != null && d != null; }}
}}
''')
            write_source(root, "com/other/ForeignGatt.java", '''\
package com.other;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
public class ForeignGatt {
    BluetoothGattCharacteristic d;
    void configure(BluetoothGatt g) { g.setCharacteristicNotification(d, true); }
    void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic c) { if (d != null) {} }
}
''')
            new_result = new._phase5_deep_re_jadx(td, {TARGET}, "com.acme.app")
            self.assertEqual(new_result, {})

    def test_same_helper_name_does_not_transfer_write_behavior_across_classes(self):
        with tempfile.TemporaryDirectory(prefix="phase5_scope_helper_collision_") as td:
            root = Path(td)
            write_source(root, "com/sdk/SppTransport.java", f'''\
package com.sdk;
import android.bluetooth.BluetoothSocket;
import java.util.UUID;
public class SppTransport {{
    public static final UUID d = UUID.fromString("{TARGET}");
    public boolean connect(BluetoothSocket socket) {{ return a(socket, d); }}
    boolean a(BluetoothSocket socket, UUID uuid) {{ return socket != null && uuid != null; }}
}}
''')
            write_source(root, "com/other/ForeignGatt.java", '''\
package com.other;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
public class ForeignGatt {
    BluetoothGatt g;
    void a(BluetoothGattCharacteristic c) { g.writeCharacteristic(c); }
}
''')
            new_result = new._phase5_deep_re_jadx(td, {TARGET}, "com.acme.app")
            self.assertEqual(new_result, {})

    def test_same_simple_class_name_in_other_package_does_not_alias(self):
        with tempfile.TemporaryDirectory(prefix="phase5_scope_class_collision_") as td:
            root = Path(td)
            write_source(root, "com/sdk/Peripheral.java", f'''\
package com.sdk;
import android.bluetooth.BluetoothSocket;
import java.util.UUID;
public class Peripheral {{
    public static final UUID d = UUID.fromString("{TARGET}");
    boolean connect(BluetoothSocket s) {{ return s != null && d != null; }}
}}
''')
            write_source(root, "com/other/Peripheral.java", '''\
package com.other;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
public class Peripheral {
    BluetoothGattCharacteristic d;
    void configure(BluetoothGatt g) { g.setCharacteristicNotification(d, true); }
    void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic c) { if (d != null) {} }
}
''')
            result = new._phase5_deep_re_jadx(td, {TARGET}, "com.acme.app")
            self.assertEqual(result, {})

    def test_same_simple_class_name_foreign_write_helper_does_not_match(self):
        with tempfile.TemporaryDirectory(prefix="phase5_scope_helper_class_collision_") as td:
            root = Path(td)
            write_source(root, "com/sdk/SppTransport.java", f'''\
package com.sdk;
import android.bluetooth.BluetoothSocket;
import java.util.UUID;
public class SppTransport {{
    public static final UUID d = UUID.fromString("{TARGET}");
    public static boolean connect(BluetoothSocket socket) {{ return SppTransport.a(socket, d); }}
    static boolean a(BluetoothSocket socket, UUID uuid) {{ return socket != null && uuid != null; }}
}}
''')
            write_source(root, "com/other/SppTransport.java", '''\
package com.other;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
public class SppTransport {
    BluetoothGatt g;
    void a(BluetoothGattCharacteristic c) { g.writeCharacteristic(c); }
}
''')
            new_result = new._phase5_deep_re_jadx(td, {TARGET}, "com.acme.app")
            self.assertEqual(new_result, {})

    def test_same_class_uuid_to_characteristic_alias_still_resolves(self):
        with tempfile.TemporaryDirectory(prefix="phase5_scope_same_class_") as td:
            root = Path(td)
            write_source(root, "com/acme/Target.java", f'''\
package com.acme;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import java.util.UUID;
public class Target {{
    static final UUID d = UUID.fromString("{TARGET}");
    BluetoothGattCharacteristic output;
    void discover(BluetoothGatt g, BluetoothGattCharacteristic ch) {{
        if (ch.getUuid().compareTo(d) == 0) this.output = ch;
        g.setCharacteristicNotification(output, true);
    }}
    void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic ch) {{ if (output != null) {{}} }}
}}
''')
            result = new._phase5_deep_re_jadx(td, {TARGET}, "com.acme.app")
            self.assertNotIn("UUID_name", result[TARGET])
            self.assertEqual(result[TARGET]["UUID_usage_array"], ["GATT Characteristic"])

    def test_imported_qualified_alias_and_write_helper_still_resolve(self):
        with tempfile.TemporaryDirectory(prefix="phase5_scope_qualified_helper_") as td:
            root = Path(td)
            write_source(root, "com/device/Target.java", f'''\
package com.device;
import android.bluetooth.BluetoothGattCharacteristic;
import java.util.UUID;
public class Target {{
    static final UUID d = UUID.fromString("{TARGET}");
    public static BluetoothGattCharacteristic output;
    static void discovered(BluetoothGattCharacteristic ch) {{
        if (ch.getUuid().compareTo(d) == 0) Target.output = ch;
    }}
}}
''')
            write_source(root, "com/helpers/Writer.java", '''\
package com.helpers;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
public class Writer {
    static BluetoothGatt gatt;
    public static void a(BluetoothGattCharacteristic c) { gatt.writeCharacteristic(c); }
}
''')
            write_source(root, "com/calls/Use.java", '''\
package com.calls;
import android.bluetooth.BluetoothGattCharacteristic;
import com.device.Target;
import com.helpers.Writer;
public class Use {
    void send() { Writer.a(Target.output); }
}
''')
            result = new._phase5_deep_re_jadx(td, {TARGET}, "com.acme.app")
            self.assertNotIn("UUID_name", result[TARGET])
            self.assertEqual(result[TARGET]["UUID_usage_array"], ["GATT Characteristic"])

    def test_explicit_owner_qualified_reference_still_resolves_cross_file(self):
        with tempfile.TemporaryDirectory(prefix="phase5_scope_qualified_") as td:
            root = Path(td)
            write_source(root, "com/acme/Target.java", f'''\
package com.acme;
import java.util.UUID;
public class Target {{ public static final UUID d = UUID.fromString("{TARGET}"); }}
''')
            write_source(root, "com/acme/BleUse.java", '''\
package com.other;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import com.acme.Target;
import static com.acme.Target.d;
public class BleUse {
    BluetoothGattCharacteristic select(BluetoothGattService service) {
        return service.getCharacteristic(com.acme.Target.d);
    }
    BluetoothGattCharacteristic selectImported(BluetoothGattService service) {
        return service.getCharacteristic(Target.d);
    }
    BluetoothGattCharacteristic selectStaticImported(BluetoothGattService service) {
        return service.getCharacteristic(d);
    }
}
''')
            result = new._phase5_deep_re_jadx(td, {TARGET}, "com.acme.app")
            self.assertNotIn("UUID_name", result[TARGET])
            self.assertEqual(result[TARGET]["UUID_usage_array"], ["GATT Characteristic"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
