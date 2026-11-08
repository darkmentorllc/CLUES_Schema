import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import extract_clues

UUID = "6a24eeab-4b65-4693-986b-3c26c352264f"


def put(root: Path, rel: str, text: str) -> None:
    path = root / "sources" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def spp_owner(root: Path) -> None:
    put(root, "com/realsil/sdk/bbpro/core/transportlayer/SppTransportLayer.java", f"""
package com.realsil.sdk.bbpro.core.transportlayer;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothSocket;
import java.util.UUID;
class SppTransportLayer {{
  static final UUID o = UUID.fromString("{UUID}");
  BluetoothSocket connect(BluetoothDevice device) throws Exception {{
    return device.createRfcommSocketToServiceRecord(o);
  }}
}}
""")


class Phase1CrossFileOwnerScopeTests(unittest.TestCase):
    def test_actual_umeng_shape_does_not_bind_class_o_context_to_uuid_field_o(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spp_owner(root)
            put(root, "com/umeng/analytics/pro/o.java", """
package com.umeng.analytics.pro;
import android.bluetooth.BluetoothGatt;
import android.content.Context;
class o {
  static Context f50121a;
  BluetoothGatt gatt;
  void check() { ABTest.getService(o.f50121a); }
}
""")
            found = extract_clues.scan_jadx_output(str(root))
            entry = found.get(UUID, {})
            self.assertNotEqual(
                entry.get("classification_source"),
                "cross-file usage:getService(o)",
                entry,
            )

    def test_non_gatt_get_service_does_not_count_even_for_explicit_uuid_owner_ref(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spp_owner(root)
            put(root, "com/umeng/analytics/pro/AnalyticsBridge.java", """
package com.umeng.analytics.pro;
import android.bluetooth.BluetoothGatt;
import com.realsil.sdk.bbpro.core.transportlayer.SppTransportLayer;
class AnalyticsBridge {
  BluetoothGatt gatt;
  void check() { ABTest.getService(SppTransportLayer.o); }
}
""")
            found = extract_clues.scan_jadx_output(str(root))
            entry = found.get(UUID, {})
            self.assertNotEqual(
                entry.get("classification_source"),
                "cross-file usage:getService(o)",
                entry,
            )

    def test_imported_real_gatt_service_reference_is_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            put(root, "com/realsil/sdk/dfu/DfuConstants.java", f"""
package com.realsil.sdk.dfu;
import android.bluetooth.BluetoothGatt;
import java.util.UUID;
class DfuConstants {{ static final UUID o = UUID.fromString("{UUID}"); }}
""")
            put(root, "com/realsil/sdk/dfu/ota/DfuDiscovery.java", """
package com.realsil.sdk.dfu.ota;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import com.realsil.sdk.dfu.DfuConstants;
class DfuDiscovery {
  BluetoothGattService find(BluetoothGatt gatt) { return gatt.getService(DfuConstants.o); }
}
""")
            found = extract_clues.scan_jadx_output(str(root))
            entry = found.get(UUID, {})
            self.assertEqual(entry.get("classification"), "GATT Service", entry)
            self.assertEqual(entry.get("classification_source"), "cross-file usage:getService(o)", entry)


if __name__ == "__main__":
    unittest.main(verbosity=2)
