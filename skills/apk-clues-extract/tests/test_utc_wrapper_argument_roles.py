import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402

SERVICE = "30e3a361-87be-46db-b76b-fdd4925200eb"
CHAR = "7c9772e1-b768-4154-a6fc-5d39ef87156d"


class UtcWrapperArgumentRoleTests(unittest.TestCase):
    def scan(self, files):
        with tempfile.TemporaryDirectory(prefix="clues-utc-wrapper-") as tmp:
            root = Path(tmp)
            for relative, text in files.items():
                path = root / "sources" / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            return extractor.scan_jadx_output(str(root))

    def test_cross_file_unique_typed_wrapper_arguments_and_parent(self):
        found = self.scan({
            "com/utc/fs/trframework/k.java": f'''package com.utc.fs.trframework;
import java.util.UUID;
public class k {{
    static final UUID a = UUID.fromString("0000fea7-0000-1000-8000-00805f9b34fb");
    static final UUID b = UUID.fromString("{SERVICE}");
    static final UUID c = UUID.fromString("{CHAR}");
}}
''',
            "com/utc/fs/trframework/TRFramework.java": '''package com.utc.fs.trframework;
import java.util.UUID;
class TRFramework {
    private void send() {
        u1 helper = getHelper();
        UUID uuid = k.b;
        UUID uuid2 = k.c;
        helper.a(uuid, uuid2, new a2() { public void done() {} });
    }
    private u1 getHelper() { return null; }
}
''',
            "com/utc/fs/trframework/u1.java": '''package com.utc.fs.trframework;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
class u1 {
    public void a(UUID uuid, UUID uuid2, a2 callback) {
        BluetoothGattService service = new BluetoothGattService(uuid, 0);
        service.addCharacteristic(new BluetoothGattCharacteristic(uuid2, 12, 16));
    }
    public void a(UUID uuid, String value, int flags) {}
}
''',
            # Same simple class name in another package must not influence
            # the receiver binding in TRFramework.
            "com/other/u1.java": '''package com.other;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
class u1 {
    public void a(UUID uuid, UUID uuid2) {
        BluetoothGattCharacteristic characteristic = new BluetoothGattCharacteristic(uuid, 12, 16);
        BluetoothGattService service = new BluetoothGattService(uuid2, 0);
    }
}
''',
        })
        self.assertEqual(found[SERVICE]["classification"], "GATT Service")
        self.assertEqual(found[CHAR]["classification"], "GATT Characteristic")
        self.assertEqual(found[CHAR]["parent_candidates"], [SERVICE])
        self.assertTrue(found[CHAR]["classification_source"].startswith("cross-file usage:helper-method:"))

    def test_callsite_aliases_stop_at_each_call(self):
        service_one = "30e3a363-87be-46db-b76b-fdd4925200eb"
        service_two = "30e3a364-87be-46db-b76b-fdd4925200eb"
        char_one = "7c9772e2-b768-4154-a6fc-5d39ef87156d"
        char_two = "7c9772e3-b768-4154-a6fc-5d39ef87156d"
        found = self.scan({
            "com/example/Ids.java": f'''package com.example;
import java.util.UUID;
class Ids {{
    static final UUID PAD = UUID.fromString("0000fea7-0000-1000-8000-00805f9b34fb");
    static final UUID SERVICE_ONE = UUID.fromString("{service_one}");
    static final UUID SERVICE_TWO = UUID.fromString("{service_two}");
    static final UUID CHAR_ONE = UUID.fromString("{char_one}");
    static final UUID CHAR_TWO = UUID.fromString("{char_two}");
}}
''',
            "com/example/Caller.java": '''package com.example;
import java.util.UUID;
class Caller {
    private void send() {
        Builder builder = null;
        UUID serviceId = Ids.SERVICE_ONE;
        UUID characteristicId = Ids.CHAR_ONE;
        builder.configure(serviceId, characteristicId);
        serviceId = Ids.SERVICE_TWO;
        characteristicId = Ids.CHAR_TWO;
        builder.configure(serviceId, characteristicId);
    }
}
''',
            "com/example/Builder.java": '''package com.example;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
class Builder {
    public void configure(UUID serviceId, UUID characteristicId) {
        BluetoothGattService service = new BluetoothGattService(serviceId, 0);
        service.addCharacteristic(new BluetoothGattCharacteristic(characteristicId, 12, 16));
    }
}
''',
        })
        self.assertEqual(found[char_one]["classification"], "GATT Characteristic")
        self.assertEqual(found[char_two]["classification"], "GATT Characteristic")
        self.assertEqual(found[char_one]["parent_candidates"], [service_one])
        self.assertEqual(found[char_two]["parent_candidates"], [service_two])

    def test_helper_role_without_same_service_attachment_has_no_parent(self):
        other_service = "30e3a362-87be-46db-b76b-fdd4925200eb"
        found = self.scan({
            "com/example/Ids.java": f'''package com.example;
import java.util.UUID;
class Ids {{
    static final UUID PAD = UUID.fromString("0000fea7-0000-1000-8000-00805f9b34fb");
    static final UUID SERVICE = UUID.fromString("{SERVICE}");
    static final UUID CHAR = UUID.fromString("{CHAR}");
}}
''',
            "com/example/Caller.java": '''package com.example;
import java.util.UUID;
class Caller {
    private void call() {
        Builder builder = null;
        UUID s = Ids.SERVICE;
        UUID c = Ids.CHAR;
        builder.configure(s, c);
    }
}
''',
            "com/example/Builder.java": f'''package com.example;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
class Builder {{
    public void configure(UUID serviceUuid, UUID characteristicUuid) {{
        BluetoothGattService service = new BluetoothGattService(serviceUuid, 0);
        BluetoothGattService unrelated = new BluetoothGattService(UUID.fromString("{other_service}"), 0);
        unrelated.addCharacteristic(new BluetoothGattCharacteristic(characteristicUuid, 12, 16));
    }}
}}
''',
        })
        self.assertEqual(found[SERVICE]["classification"], "GATT Service")
        self.assertEqual(found[CHAR]["classification"], "GATT Characteristic")
        self.assertEqual(found[CHAR]["parent_candidates"], [])

    def test_same_file_typed_getservice_alias_and_parent(self):
        service_default = "37b40001-42ab-4add-b2dc-e178c20d7deb"
        service_alv3 = "37b40000-42ab-4add-b2dc-e178c20d7deb"
        tx = "37b40002-42ab-4add-b2dc-e178c20d7deb"
        found = self.scan({
            "com/miwa/alv2core/ble/MiwaSppService.java": f'''package com.miwa.alv2core.ble;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothGattCharacteristic;
import java.util.UUID;
class MiwaSppService {{
    static final UUID MIWA_SPP_SV = UUID.fromString("{service_default}");
    static final UUID MIWA_SPP_ALV3_SV = UUID.fromString("{service_alv3}");
    static final UUID MIWA_SPP_TX = UUID.fromString("{tx}");
    private void connect(BluetoothGatt bluetoothGatt) {{
        UUID uuid = MiwaSppService.MIWA_SPP_ALV3_SV;
        UUID uuid2 = MiwaSppService.MIWA_SPP_TX;
        BluetoothGattService service = bluetoothGatt.getService(uuid);
        BluetoothGattCharacteristic ch = service.getCharacteristic(uuid2);
    }}
}}
''',
        })
        self.assertEqual(found[service_alv3]["classification"], "GATT Service")
        self.assertEqual(found[tx]["classification"], "GATT Characteristic")
        self.assertEqual(found[tx]["parent_candidates"], [service_alv3])

    def test_conditional_service_alias_does_not_create_ambiguous_parent(self):
        service_default = "37b40001-42ab-4add-b2dc-e178c20d7deb"
        service_alv3 = "37b40000-42ab-4add-b2dc-e178c20d7deb"
        tx = "37b40100-42ab-4add-b2dc-e178c20d7deb"
        found = self.scan({
            "com/miwa/alv2core/ble/MiwaSppService.java": f'''package com.miwa.alv2core.ble;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothGattCharacteristic;
import java.util.UUID;
class MiwaSppService {{
    static final UUID MIWA_SPP_SV = UUID.fromString("{service_default}");
    static final UUID MIWA_SPP_ALV3_SV = UUID.fromString("{service_alv3}");
    static final UUID MIWA_SPP_TX = UUID.fromString("{tx}");
    private void connect(BluetoothGatt bluetoothGatt, boolean alv3) {{
        UUID uuid = MiwaSppService.MIWA_SPP_SV;
        UUID uuid2 = MiwaSppService.MIWA_SPP_TX;
        if (alv3) {{ uuid = MiwaSppService.MIWA_SPP_ALV3_SV; }}
        BluetoothGattService service = bluetoothGatt.getService(uuid);
        BluetoothGattCharacteristic ch = service.getCharacteristic(uuid2);
    }}
}}
''',
        })
        self.assertEqual(found[service_alv3]["classification"], "GATT Service")
        self.assertEqual(found[tx]["classification"], "GATT Characteristic")
        # The two possible service values share one characteristic object, but
        # no single CLUES parent_UUID can represent both control-flow paths.
        self.assertEqual(found[tx]["parent_candidates"], [])


if __name__ == "__main__":
    unittest.main()
