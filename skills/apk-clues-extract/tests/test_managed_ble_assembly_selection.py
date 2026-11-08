import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
import managed_clues as m
class BleAssemblySelectionTest(unittest.TestCase):
 def test_specific_ble_markers_and_generic_negatives(self):
  for v in (b'BluetoothGatt',b'GattCharacteristic',b'GattService',b'BluetoothLe',b'Plugin.BLE','Plugin.BLE'.encode('utf-16le')):
   with self.subTest(value=v):self.assertTrue(m._binary_has_ble_api(v))
  for v in (b'IService',b'ICharacteristic',b'GetServiceAsync',b'GetServicesAsync',b'AdvertisementRecord',b'ScanRecord'):
   with self.subTest(value=v):self.assertFalse(m._binary_has_ble_api(v))
 def test_select_app_assembly_and_exclude_framework(self):
  selected=m._select_assemblies([('AccuBarMobile.dll',b'BluetoothGatt'),('Mono.Android.dll',b'BluetoothGatt'),('Other.dll',b'GetServiceAsync')],'com.birchstreetsystems.synergy')
  self.assertEqual([x[0] for x in selected],['AccuBarMobile.dll'])
 def test_cap_remains_fail_closed(self):
  with self.assertRaises(m.ManagedScanError):m._select_assemblies([(f'lib{i}.dll',b'BluetoothGatt') for i in range(m.MAX_DECOMPILED_ASSEMBLIES+1)],'com.example.host')
