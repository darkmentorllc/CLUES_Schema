import pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
import extract_clues as e
class ScopedNonGattHintsTest(unittest.TestCase):
 def scan(self,package,cls,field,uuid,extra=''):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/f'{cls}.java';p.write_text(f'package {package};\nimport java.util.UUID;\nclass {cls} {{ static final String {field} = "{uuid}"; {extra} }}\n');return e.scan_one_file(str(p))
 def test_scoped_ids_are_not_gatt(self):
  for pkg,cls,field in [('com.alibaba.ailabs.iot.aisbase','Constants','UUID_RFCOMM'),('com.appsgeyser.sdk.configuration','Constants','APP_METRICA_ID'),('oneapp.framework.network','f','MSAL_CLIENT_ID')]:
   with self.subTest(field=field):
    u='3a7a90bd-356d-4a66-a000-f3f79f67966f';self.assertNotIn(u,self.scan(pkg,cls,field,u))
 def test_other_package_and_direct_gatt_are_not_suppressed(self):
  u='3a7a90bd-356d-4a66-a000-f3f79f67966f'
  self.assertIn(u,self.scan('example.app','Constants','APP_METRICA_ID',u))
  x=self.scan('com.appsgeyser.sdk.configuration','Constants','APP_METRICA_ID',u,'android.bluetooth.BluetoothGattService g; void f(){ g.getCharacteristic(APP_METRICA_ID); }')
  self.assertEqual(x[u]['classification'],'GATT Characteristic')
