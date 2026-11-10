import pathlib, sys, tempfile, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import extract_clues as e
U='51ddbb28-e1cf-4558-87ac-ce49950c09c1'

def scan(pkg, cls, field, use=''):
    with tempfile.TemporaryDirectory() as d:
        p=pathlib.Path(d)/(cls+'.java')
        p.write_text(f'''package {pkg};
import java.util.UUID;
class {cls} {{
 android.bluetooth.BluetoothGatt gatt;
 static final String {field} = "{U}";
 {use}
}}
''')
        return e.scan_one_file(str(p))

class ScopedFilterTest(unittest.TestCase):
    def test_embedded_feature_key_is_scoped_and_gatt_use_wins(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/"BuildConfig.java"
            code=f"""package com.totem;
import java.util.UUID;
class BuildConfig {{
 android.bluetooth.BluetoothGatt gatt;
 static final String LAUNCH_DARKLY_MOBILE_KEY = \"mob-{U}\";
}}
"""
            p.write_text(code)
            self.assertNotIn(U,e.scan_one_file(str(p)))
            p.write_text(code.replace('\n}', '\n void f(){gatt.getService(UUID.fromString(LAUNCH_DARKLY_MOBILE_KEY));}\n}'))
            self.assertIn(U,e.scan_one_file(str(p)))

    def test_embedded_sendbird_hostname_is_scoped(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/"GlobalUtil.java"
            code=f"""package com.belico.simpelapp.utils;
class GlobalUtil {{
 android.bluetooth.BluetoothGatt gatt;
 String str3 = \"https://api-{U}.sendbird.com/v3/users/\" + name;
}}
"""
            p.write_text(code)
            self.assertNotIn(U,e.scan_one_file(str(p)))
            p.write_text(code.replace('com.belico.simpelapp.utils', 'unrelated.example'))
            self.assertIn(U,e.scan_one_file(str(p)))

    def test_sendbird_host_does_not_hide_separate_gatt_use(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/"AutoConnectStores.java"
            code=f"""package com.seashels.discover.utility;
import java.util.UUID;
class AutoConnectStores {{
 android.bluetooth.BluetoothGatt gatt;
 String host = \"api-{U}.calls.sendbird.com\";
 static UUID device = UUID.fromString(\"{U}\");
 void f() {{ gatt.getService(device); }}
}}
"""
            p.write_text(code)
            self.assertIn(U,e.scan_one_file(str(p)))
            p.write_text(code.replace(' static UUID device = UUID.fromString(\"'+U+'\");','').replace(' void f() { gatt.getService(device); }',''))
            self.assertNotIn(U,e.scan_one_file(str(p)))

    def test_equiem_inline_argument_preserves_gatt_use(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/"MainActivity.java"
            code=f"""package com.equiem.equiemandroid;
import java.util.UUID;
class MainActivity {{
 android.bluetooth.BluetoothGatt gatt;
 void f() {{ enqueueRegisterMessagingWorker(ctx, \"{U}\", opts); }}
}}
"""
            p.write_text(code)
            self.assertNotIn(U,e.scan_one_file(str(p)))
            p.write_text(code.replace('enqueueRegisterMessagingWorker(ctx,', 'gatt.getService(UUID.fromString(\"'+U+'\")); enqueueRegisterMessagingWorker(ctx,'))
            self.assertIn(U,e.scan_one_file(str(p)))

    def test_pushd_demo_author_does_not_hide_gatt_use(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/"py1.java"
            code=f"""package defpackage;
import java.util.UUID;
class py1 {{
 // com.pushd.client.ui.birthday.gift.ComposableSingletons$SlideshowItemsGridKt
 android.bluetooth.BluetoothGatt gatt;
 Object x = new TextSlideshowItem(\"example\", UUID.fromString(\"{U}\"), name);
}}
"""
            p.write_text(code)
            self.assertNotIn(U,e.scan_one_file(str(p)))
            p.write_text(code.replace(' Object x =', ' void f() {{ gatt.getService(UUID.fromString(\"'+U+'\")); }} Object x ='))
            self.assertIn(U,e.scan_one_file(str(p)))

    def test_known_menu_and_oauth_fields_only(self):
        for pkg, cls, field in [
            ('com.saj.connection.net.us','NetRemoteConfig','MENU_ID_US_PARALLEL'),
            ('it.appmynet','BuildConfig','COMPANY_ID'),
            ('com.eegees.app','EegeesProperties','CLIENT_ID'),
            ('com.allegion.accesssdk.nfc','BuildConfig','INTEGRATION_ID'),
            ('com.allegion.accesssdk.nfc','BuildConfig','EXPECTED_CONNECTED_ACCOUNT'),
            ('com.inetech.cns.omenu.device.polar','Polar','clientId'),
            ('com.inetech.cns.omenu.device.polar','Polar','clientSecret'),
            ('com.clientmobileapp','BuildConfig','SENDBIRD_APP_ID'),
            ('com.equiem.equiemandroid','BuildConfig','EQUIEM_EDITION_ID'),
            ('com.equiem.equiemandroid','Config','editionId'),
            ('com.seashels.discover','Singleton','APP_ID'),
            ('com.ce.android.brand.gshmakbakery','GshmakBakeryProperties','CLIENT_ID'),
            ('com.browan.freeppmobile.jni','AudioDeviceEffect','EFFECT_TYPE_NULL'),
            ('com.kakao.adfit','AdfitSdk','BUILD_ID'),
            ('com.ce.android.brand.beechrestaurants','BEECHRestaurantsProperties','CLIENT_ID'),
            ('io.te2.defaults','BaseNavigationActivity','TREMBLANT_ACTIVITIES_CATEGORY'),
            ('com.io.wearlynxtracking','WearLynxModule','SNOW_VALLEY_RESORT_GUID'),
            ('com.wearlynx.slandroidalterrawl.resortdata','SLResortSnowValley','guid'),
            ('com.totem','BuildConfig','LAUNCH_DARKLY_MOBILE_KEY'),
            ('com.totem','BuildConfig','CRISP_WEBSITE_ID_INFORMA'),
            ('ro.digibank.fgo.ui.screens.efactura','FgoTransactionToSend','SPENDING_CATEGORY_ID'),
            ('ro.itom.fgoro.salt.fgolibrary.domain.model','Registry','INVOICE_REGISTRY_ID'),
            ('ro.itom.fgoro.salt.fgolibrary.domain.model','Client','ROMANIA_ID'),
            ('com.dexcom.common.service.internal.model','Constants','TEST_ACCOUNT_ID'),
            ('com.dexcom.common.service.internal.model','Constants','TEST_APP_ID'),
            ('com.hufsm.secureaccess.api','LeaseToken','leaseTokenId'),
            ('com.hufsm.secureaccess.ble.model.lease','LeaseToken','leaseId'),
            ('app.theranica.fragments.main.settings.preventive.calendar.outlook','OutlookAuthManager','CLIENT_ID'),
            ('app.theranica.fragments.main.settings.preventive.calendar.outlook','OutlookAuthRedirectActivity','SCHEME'),
        ]:
            with self.subTest(field=field):
                self.assertNotIn(U,scan(pkg,cls,field))
                self.assertIn(U,scan('unrelated.package',cls,field))
                self.assertIn(U,scan(pkg,cls,field,f'void f() {{ gatt.getService(UUID.fromString({field})); }}'))
