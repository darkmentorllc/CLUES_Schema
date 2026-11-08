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


def make_fixture(root: Path, foreign_helper: bool) -> None:
    owner_helper_package = "com.realsil.sdk.dfu.helper"
    caller_package = "com.umeng.analytics.pro" if foreign_helper else owner_helper_package
    caller_dir = caller_package.replace(".", "/")
    put(root, "com/realsil/sdk/dfu/DfuConstants.java", f"""
package com.realsil.sdk.dfu;
import java.util.UUID;
class DfuConstants {{ static final UUID o = UUID.fromString("{UUID}"); }}
""")
    put(root, "com/realsil/sdk/dfu/helper/WriteHelper.java", f"""
package {owner_helper_package};
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
class WriteHelper {{
  static void write(BluetoothGatt gatt, BluetoothGattCharacteristic ch) {{ gatt.writeCharacteristic(ch); }}
}}
""")
    if foreign_helper:
        put(root, f"{caller_dir}/WriteHelper.java", f"""
package {caller_package};
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
class WriteHelper {{
  static void write(BluetoothGatt gatt, BluetoothGattCharacteristic ch) {{ /* analytics helper; no GATT write */ }}
}}
""")
    helper_import = "import com.realsil.sdk.dfu.helper.WriteHelper;\n" if not foreign_helper else ""
    put(root, f"{caller_dir}/BleManager.java", f"""
package {caller_package};
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import com.realsil.sdk.dfu.DfuConstants;
{helper_import}class BleManager {{
  BluetoothGattCharacteristic matched;
  void discover(BluetoothGattCharacteristic candidate) {{
    if (candidate.getUuid().compareTo(DfuConstants.o) == 0) {{ matched = candidate; }}
  }}
  void send(BluetoothGatt gatt) {{ WriteHelper.write(gatt, matched); }}
}}
""")


class WriteHelperScopeTests(unittest.TestCase):
    def test_explicitly_imported_write_helper_is_followed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_fixture(root, foreign_helper=False)
            result = extract_clues._phase5_deep_re_jadx(str(root), {UUID}, "com.example")
            self.assertIn("write path", result[UUID]["note"])

    def test_same_simple_name_foreign_write_helper_is_not_followed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_fixture(root, foreign_helper=True)
            result = extract_clues._phase5_deep_re_jadx(str(root), {UUID}, "com.example")
            self.assertNotIn("write path", result[UUID]["note"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
