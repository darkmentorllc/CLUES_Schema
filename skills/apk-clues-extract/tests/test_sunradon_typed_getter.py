import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor


class SunradonTypedGetterTests(unittest.TestCase):
    def test_actual_characteristic_use_beats_unused_service_alias(self):
        uuid = "626b87c9-39ce-491b-a871-5b9a209eedc8"
        utility = (
            'String service = "626b8801-39ce-491b-a871-5b9a209eedc8"; '
            f'String SERVICE_UPPER_BOUND = "{uuid}"; '
            f'UUID CHARACTERISTIC_HOUR_RESULT_UPPER_BOUND = UUID.fromString("{uuid}"); '
            'UUID getCHARACTERISTIC_HOUR_RESULT_UPPER_BOUND() { '
            'return CHARACTERISTIC_HOUR_RESULT_UPPER_BOUND; }'
        )
        device = ('void read(BluetoothGattCharacteristic characteristic) { '
                  'Intrinsics.areEqual(characteristic.getUuid(), '
                  'BluetoothUtil.INSTANCE.getCHARACTERISTIC_HOUR_RESULT_UPPER_BOUND()); }')
        files = {"/tmp/com/app/utility/bluetooth/BluetoothUtil.java": utility,
                 "/tmp/com/app/service/DeviceService.java": device}
        self.assertEqual(extractor._sunradon_typed_characteristics(files), {uuid})
        files["/tmp/com/app/service/DeviceService.java"] = device.replace(
            "BluetoothGattCharacteristic", "BluetoothGattService"
        )
        self.assertEqual(extractor._sunradon_typed_characteristics(files), set())


if __name__ == "__main__":
    unittest.main()
