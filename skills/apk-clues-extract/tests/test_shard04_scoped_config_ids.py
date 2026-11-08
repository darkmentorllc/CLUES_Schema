import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import extract_clues as extractor


class ScopedConfigIdentifiersTest(unittest.TestCase):
    def scan(self, package, cls, field, uuid, extra=''):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / (cls + '.java')
            path.write_text(f'package {package};\nimport android.os.ParcelUuid;\nclass {cls} {{ static final String {field} = "{uuid}"; {extra} }}\n')
            return extractor.scan_one_file(str(path))

    def test_confirmed_config_identifiers_are_not_gatt(self):
        for package, cls, field in (
            ('com.abbemobility.terraconfig', 'BuildConfig', 'API_CLIENT_ID'),
            ('com.auctionmobility.auctions.util', 'OTTypeFaceKeys', 'PROD_DOMAIN_ID'),
            ('com.szte.griffin', 'BuildConfig', 'AUTH_CONFIG_APP_ID'),
            ('com.gifites.payes.config', 'Config', 'ONE_SIGNAL_ID'),
            ('com.ce.android.brand.ellielous', 'EllieLousProperties', 'CLIENT_ID'),
            ('com.ce.android.brand.antiochpizzashop', 'AntiochPizzashopProperties', 'CLIENT_ID'),
            ('com.ce.android.brand.rodrigosmexicangrill', 'RodrigosMexicanGrillProperties', 'CLIENT_ID'),
            ('com.ce.android.brand.healthinhand', 'HealthInHandProperties', 'CLIENT_ID'),
            ('com.ce.android.brand.hangryjoes', 'HangryJoesProperties', 'CLIENT_ID'),
            ('com.misa.amis.screen.loginsso', 'LoginSSOManager', 'CLIENT_ID'),
            ('vn.com.misa.tms.viewcontroller.sso', 'LoginSSOManager', 'CLIENT_ID'),
            ('com.misa.amis.screen.main.personal.mail.addaccount', 'MailAddAccountPresenter', 'OUTLOOK_CLIENT_ID'),
            ('ca.journie.dev', 'BuildConfig', 'BRAZE_API_KEY_IOS'),
            ('ca.journie.dev', 'BuildConfig', 'BRAZE_API_KEY_ANDROID'),
            ('com.urbanasolutions.toolkit', 'BuildConfig', 'TRADUORA_CLIENT_ID'),
            ('ru.tensor.sbis.catalog.generated', 'AttributeConst', 'MANUFACTURER'),
            ('ru.tensor.sbis.catalog.generated', 'ServiceCategoryUuids', 'CATEGORY_HOTEL_ROOM'),
            ('ru.tensor.sbis.regulation.generated', 'VirtualPhases', 'APPROVAL_ACCEPTED'),
        ):
            with self.subTest(field=field):
                uuid = '12345678-1234-4321-9876-123456789abc'
                self.assertNotIn(uuid, self.scan(package, cls, field, uuid))
                self.assertIn(uuid, self.scan('other.package', cls, field, uuid))
                direct_use = f'android.bluetooth.BluetoothGatt g; void f() {{ g.getService({field}); }}'
                self.assertEqual(self.scan(package, cls, field, uuid, direct_use)[uuid]['classification'], 'GATT Service')

    def test_display_only_lookup_rows_are_scoped_to_the_source_occurrence(self):
        uuid = '12345678-1234-4321-9876-123456789abc'
        def scan_lookup(package, add_direct_use=False):
            with tempfile.TemporaryDirectory() as tmp:
                path = pathlib.Path(tmp) / 'DeviceServices.java'
                sink = f'android.bluetooth.BluetoothGatt g; void f() {{ g.getService(java.util.UUID.fromString("{uuid}")); }}' if add_direct_use else ''
                path.write_text(f'''package {package};
import android.os.ParcelUuid;
class DeviceServices {{
    java.util.Map<String, String> services;
    void labels() {{ services.put("{uuid}".toLowerCase(), "label"); }}
    {sink}
}}
''')
                return extractor.scan_one_file(str(path))
        self.assertNotIn(uuid, scan_lookup('com.bluetooth.pc.mouse.keyboard.bluetooth'))
        self.assertIn(uuid, scan_lookup('other.package'))
        self.assertIn(uuid, scan_lookup('com.bluetooth.pc.mouse.keyboard.bluetooth', True))

    def test_scoped_sbis_temp_alias_and_documentation_url(self):
        uuid = '12345678-1234-4321-9876-123456789abc'
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'AttributeConst.java'
            path.write_text(f'''package ru.tensor.sbis.catalog.generated;
import android.os.ParcelUuid;
import java.util.UUID;
class AttributeConst {{
    static UUID MANUFACTURER;
    static {{ UUID temp = UUID.fromString("{uuid}"); MANUFACTURER = temp; }}
}}
''')
            self.assertNotIn(uuid, extractor.scan_one_file(str(path)))
            path.write_text(f'''package ru.tensor.sbis.profile_service.models.person;
import android.os.ParcelUuid;
@Deprecated(message="https://online.sbis.ru/opendoc.html?guid={uuid}")
class Person {{}}
''')
            self.assertNotIn(uuid, extractor.scan_one_file(str(path)))


if __name__ == '__main__':
    unittest.main()
