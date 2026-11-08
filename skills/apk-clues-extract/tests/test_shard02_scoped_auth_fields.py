import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor


class ScopedAuthFieldsTests(unittest.TestCase):
    def test_source_specific_auth_fields_do_not_suppress_independent_gatt(self):
        cases = [
            ("com.ce.android.brand.auberginekitchen", "AubergineKitchenProperties", "CLIENT_ID"),
            ("com.ce.android.brand.wingiton", "WingItOnProperties", "CLIENT_ID"),
            ("com.ce.android.brand.thehungrycowgirlcocina", "TheHungryCowgirlCocinaProperties", "CLIENT_ID"),
            ("com.ce.android.brand.breadzeppelin", "BreadZeppelinProperties", "CLIENT_ID"),
            ("com.htc.hubble.hwsetup.account", "AccountClientKt", "VRS_CLIENT_ID"),
            ("com.qst.mswift", "BuildConfig", "AUTHKEY"),
            ("com.qst.mswift", "BuildConfig", "CLIENT_REQUEST_ENCRYPTION_KEY"),
            ("com.qst.mswift.constant", "AppConstant", "AUTHKEY"),
            ("com.qst.mswift.constant", "AppConstant", "CLIENT_REQUEST_ENCRYPTION_KEY"),
            ("com.sefam.sefamaccess", "BuildConfig", "ANDROID_HOCKEYAPP_APP_ID"),
            ("life.league.login", "LoginFragment", "PLATFORM_ID"),
            ("com.rootexplorer.forandroidfiles", "KpDocumentsApplication", "ONESIGNAL_APP_ID"),
            ("com.microsoft.office.watson", "Utils", "OFFICEMOBILE_APP_NON_PROD_APP_ID"),
            ("com.microsoft.office.watson", "Utils", "OFFICESUITE_APP_HA_ID"),
            ("com.microsoft.office.watson", "Utils", "OFFICEMOBILE_APP_HA_ID"),
            ("com.microsoft.office.watson", "Utils", "OFFICEMOBILE_APP_HA_ID_CPP"),
            ("com.microsoft.office.watson", "Utils", "MICROSOFT_TENANT_ID"),
            ("com.microsoft.office.docsui.common", "AccountTransferController", "APPGROUP_REDIRECT_WORD"),
            ("com.microsoft.office.docsui.common", "AccountTransferController", "APPGROUP_REDIRECT_EXCEL"),
            ("com.microsoft.office.docsui.common", "AccountTransferController", "APPGROUP_REDIRECT_PPT"),
            ("com.p002newrelic.agent.android", "NewRelicConfig", "BUILD_ID"),
            ("fi.kansalliskirjasto.ekirjasto.testing", "TestingOverrides", "TEST_LOGIN_LIBRARY_PROVIDER_ID"),
            ("fi.ekirjasto.testing", "BuildConfig", "TEST_LOGIN_LIBRARY_PROVIDER_ID"),
            ("fi.kansalliskirjasto.ekirjasto", "BuildConfig", "LIBRARY_PROVIDER_ID"),
        ]
        uuid = "11223344-1234-4567-89ab-abcdef123456"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index, (package, cls, field) in enumerate(cases):
                path = root / str(index) / (cls + ".java")
                path.parent.mkdir(parents=True)
                path.write_text(f'''package {package};
import android.bluetooth.BluetoothGatt;
class {cls} {{ static final String {field} = "{uuid}"; }}
''')
                self.assertNotIn(uuid, extractor.scan_one_file(str(path)), (package, cls, field))
                other = path.parent / "Other.java"
                other.write_text(f'''package unrelated;
import android.bluetooth.BluetoothGatt;
import java.util.UUID;
class Other {{ BluetoothGatt g; void run() {{ g.getService(UUID.fromString("{uuid}")); }} }}
''')
                self.assertIn(uuid, extractor.scan_one_file(str(other)))

    def test_htc_static_block_oauth_ids_are_filtered_but_same_values_can_be_gatt(self):
        vrs = "63167f50-0e63-4086-9cf8-69449133e521"
        ca = "283ff443-658d-4646-8904-c08450cdfc03"
        with tempfile.TemporaryDirectory(prefix="clues-htc-static-oauth-") as tmp:
            root = Path(tmp)
            account = root / "sources/com/htc/hubble/hwsetup/account/AccountClientKt.java"
            account.parent.mkdir(parents=True)
            account.write_text(f'''package com.htc.hubble.hwsetup.account;
class AccountClientKt {{
    private static final String VRS_CLIENT_ID;
    private static final String CA_CLIENT_ID;
    private static AccountClient CLIENT_VRS;
    private static AccountClient CLIENT_CA;
    static {{
        VRS_CLIENT_ID = "{vrs}";
        String vrsAuthorize = "/OAuth/Authorize?client_id={vrs}";
        CLIENT_VRS = new AccountClient("{vrs}", "secret", "scope", vrsAuthorize, "");
        CA_CLIENT_ID = "{ca}";
        String caAuthorize = "/OAuth/Authorize?client_id={ca}";
        CLIENT_CA = new AccountClient("{ca}", "secret", "scope", caAuthorize, "");
    }}
}}
''')
            # Exact package, different class: same UUID values are genuine
            # GATT identifiers when passed to typed Android API receivers.
            other = root / "sources/com/htc/hubble/hwsetup/account/OtherGattProfile.java"
            other.write_text(f'''package com.htc.hubble.hwsetup.account;
import android.bluetooth.BluetoothGatt;
import java.util.UUID;
class OtherGattProfile {{
    static final UUID VRS_CLIENT_ID = UUID.fromString("{vrs}");
    static final UUID CA_CLIENT_ID = UUID.fromString("{ca}");
    BluetoothGatt gatt;
    void connect() {{
        gatt.getService(VRS_CLIENT_ID);
        gatt.getService(VRS_CLIENT_ID).getCharacteristic(CA_CLIENT_ID);
    }}
}}
''')

            account_candidates = extractor.scan_one_file(str(account))
            self.assertNotIn(vrs, account_candidates)
            self.assertNotIn(ca, account_candidates)
            self.assertIn(
                "VRS_CLIENT_ID",
                extractor._assigned_fields_for_uuid_on_line(
                    f'        VRS_CLIENT_ID = "{vrs}";', vrs
                ),
            )

            apk_candidates = extractor.scan_jadx_output(str(root))
            self.assertEqual(apk_candidates[vrs]["classification"], "GATT Service")
            self.assertEqual(apk_candidates[ca]["classification"], "GATT Characteristic")


if __name__ == "__main__":
    unittest.main()
