import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import extract_clues as e

class RiddellWriterTest(unittest.TestCase):
 def test_requires_uuid_flow_to_characteristic_sink(self):
  uuid='12345678-1234-4321-abcd-1234567890ab'
  files={'/tmp/com/riddell/alertmonitor/view/utils/CommonUUID.java':f'class CommonUUID {{ static String SETTING_UUID="{uuid}"; }}',
   '/tmp/com/riddell/alertmonitor/view/activities/BaseBLEActivity.java':'setPUBLEValues(UUID.fromString(CommonUUID.SETTING_UUID), value, true, address);',
   '/tmp/com/riddell/alertmonitor/livestreaming/LiveStreamingService.java':'void setPUBLEValues(UUID uuid, String value) { service = gatt.getService(UUID.fromString(CommonUUID.CONFIG_SERVICE_UUID)); service.getCharacteristic(uuid); }'}
  self.assertEqual(e._riddell_set_pu_characteristics(files),{uuid})
  files['/tmp/com/riddell/alertmonitor/livestreaming/LiveStreamingService.java']=files['/tmp/com/riddell/alertmonitor/livestreaming/LiveStreamingService.java'].replace('getCharacteristic(uuid)','getCharacteristic(other)')
  self.assertEqual(e._riddell_set_pu_characteristics(files),set())
