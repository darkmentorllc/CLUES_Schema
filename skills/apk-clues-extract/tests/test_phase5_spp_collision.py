import os
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
    put(root, "com/realsil/sdk/bbpro/core/transportlayer/SppTransportLayer.java", f'''\
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
''')


class Phase5SppCollisionTests(unittest.TestCase):
    def test_umeng_same_simple_o_and_context_are_not_the_uuid_field(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spp_owner(root)
            put(root, "com/umeng/analytics/pro/o.java", f'''\
package com.umeng.analytics.pro;
import android.bluetooth.BluetoothGatt;
import android.content.Context;
class o {{
  static Context f50121a;
  BluetoothGatt gatt; // makes this file BLE-relevant, but not a GATT UUID sink
  void check() {{ ABTest.getService(o.f50121a); }}
}}
''')
            result = extract_clues._phase5_deep_re_jadx(str(root), {UUID}, "com.example.host")
            self.assertNotIn(UUID, result)

    def test_non_gatt_get_service_helper_does_not_match_imported_owner_field(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spp_owner(root)
            put(root, "com/umeng/analytics/pro/AnalyticsBridge.java", f'''\
package com.umeng.analytics.pro;
import android.bluetooth.BluetoothGatt;
import com.realsil.sdk.bbpro.core.transportlayer.SppTransportLayer;
class AnalyticsBridge {{
  BluetoothGatt gatt;
  void check() {{ ABTest.getService(SppTransportLayer.o); }}
}}
''')
            result = extract_clues._phase5_deep_re_jadx(str(root), {UUID}, "com.example.host")
            self.assertNotIn(UUID, result)

    def test_typed_real_gatt_get_service_is_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            put(root, "com/realsil/sdk/dfu/ota/RealSilDfu.java", f'''\
package com.realsil.sdk.dfu.ota;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
class RealSilDfu {{
  static final UUID a = UUID.fromString("{UUID}");
  BluetoothGattService discover(BluetoothGatt bluetoothGatt) {{
    return bluetoothGatt.getService(a);
  }}
}}
''')
            result = extract_clues._phase5_deep_re_jadx(str(root), {UUID}, "com.realsil.sdk.dfu")
            self.assertEqual(result[UUID]["UUID_usage_array"], ["GATT Service"])

    def test_qualified_cross_file_owner_with_typed_gatt_is_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spp_owner(root)
            put(root, "com/realsil/sdk/dfu/ota/DfuDiscovery.java", f'''\
package com.realsil.sdk.dfu.ota;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import com.realsil.sdk.bbpro.core.transportlayer.SppTransportLayer;
class DfuDiscovery {{
  BluetoothGattService discover(BluetoothGatt gatt) {{
    return gatt.getService(SppTransportLayer.o);
  }}
}}
''')
            result = extract_clues._phase5_deep_re_jadx(str(root), {UUID}, "com.realsil.sdk.dfu")
            self.assertEqual(result[UUID]["UUID_usage_array"], ["GATT Service"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
