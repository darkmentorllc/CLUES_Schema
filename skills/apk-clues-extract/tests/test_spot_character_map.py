import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor


class SpotCharacterMapTests(unittest.TestCase):
    def test_aliases_are_classified_only_with_typed_gatt_resolver(self):
        service = "42240002-7f35-44f4-8879-1971ae94cc6f"
        characteristic = "42240021-7f35-44f4-8879-1971ae94cc6f"
        root = "/tmp/sources/com/pvimaging/spotdemo/spot/gatt/"
        constants = (
            f'UUID tmp = UUID.fromString("{service}"); SERVICE_ALARM = tmp; '
            f'ALARM_SELECT = UUID.fromString("{characteristic}");'
        )
        model = (
            'class SpotModel { void x() { put$default(this, AlarmKt.SERVICE_ALARM, '
            'AlarmKt.ALARM_SELECT, "alarm", 0); } '
            'CharacterMap put(UUID service, UUID uuid, String name) { '
            'SERVICE_REVERSE_MAPPING.put(uuid, service); } }'
        )
        device = (
            'UUID serviceUuid = SpotModel.getServiceUuid(uuid); '
            'BluetoothGattService service = connectedGatt.getService(serviceUuid); '
            'service.getCharacteristic(uuid);'
        )
        files = {root + "model/AlarmKt.java": constants, root + "model/SpotModel.java": model,
                 root + "BtSpotDevice.java": device}
        self.assertEqual(extractor._spot_model_characteristics(files), {characteristic})
        files[root + "BtSpotDevice.java"] = device.replace("getCharacteristic", "getDescriptor")
        self.assertEqual(extractor._spot_model_characteristics(files), set())


if __name__ == "__main__":
    unittest.main()
