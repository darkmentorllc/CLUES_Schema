#!/usr/bin/env python3
"""
APK / XAPK -> CLUES_data_LLM_Android.json extractor.

Pipeline per APK:
    1. aapt dump permissions  (skip if no BLUETOOTH* permission)
    2. aapt dump badging      (capture package_id, version_code, version_name)
    3. jadx --no-res --no-debug-info -d <tmp> <apk>
    4. grep .java for UUIDs and classify
    5. if the APK packages .NET assemblies, inspect their decompiled C# too
    6. merge into output JSON, delete tmp

See SKILL.md (in the parent directory) for the full design.
"""
from __future__ import annotations

import argparse
import copy
import glob
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Iterable

from clues_io import load_clues, save_clues
from corpus_paths import compact_package_path, resolve_package_path
from submitter import DEFAULT_SUBMITTER
import managed_clues

try:
    import predecompiled_cache
except ImportError:  # extract_clues.py copied without its sibling: run jadx every time
    predecompiled_cache = None

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Data files live under CLUES_Schema/data/ — this default is relative so the
# script "just works" when run from the CLUES_Schema/ directory, but the agent
# always passes --output explicitly (see SKILL.md) for unambiguous paths.
DEFAULT_OUTPUT = "data/CLUES_data_LLM_Android_APK_search.json"
DEFAULT_JADX_TIMEOUT_SEC = 1800

# Canonical hand-curated CLUES file (renamed from CLUES_data.json to
# CLUES_data_human_verified.json when data moved under data/). UUIDs already
# present here have been manually verified by humans and are the highest-trust
# source of truth in the project — we never emit them again into the
# LLM-extracted output (it'd only add noise and risk degrading curated entries
# on a merge).
DEFAULT_CURATED_CLUES = os.path.expanduser(
    "~/Blue2thprinting/Analysis/CLUES_Schema/data/CLUES_data_human_verified.json"
)

BT_PERMS = {
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
}

# Bluetooth SIG base: 0000XXXX-0000-1000-8000-00805F9B34FB
SIG_BASE_RE = re.compile(
    r"^0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb$",
    re.IGNORECASE,
)

# Any 128-bit UUID with or without dashes (but we normalize to with-dashes,
# lowercased, before doing anything else).
UUID128_LITERAL_RE = re.compile(
    r"\b([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})\b"
)

# Standard SIG-allocated UUID16 ranges we DROP because they aren't vendor-specific.
# Reference: https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/uuids/
#   0x0000             reserved / pseudo-NULL (just the SIG base alone, junk)
#   0x0001..0x012F     SDP protocol identifiers (SDP, UDP, RFCOMM, OBEX, L2CAP, ...)
#   0x1000..0x12FF     SDP service class UUIDs (A2DP/AVRCP/HFP/HSP/HID/OBEX-OPP/...)
#   0x1800..0x18FF     GATT service UUIDs (GAP, GATT, Battery, Device Info, ...)
#   0x2800..0x29FF     GATT declaration/descriptor UUIDs
#   0x2A00..0x2BFF     GATT characteristic UUIDs
# We KEEP the member-UUID range 0xFC00..0xFFFF because those are vendor-allocated
# and squarely in scope for "vendor-specific GATT".
def is_standard_sig_uuid16(u16_hex: str) -> bool:
    try:
        v = int(u16_hex, 16)
    except ValueError:
        return False
    if v == 0x0000:
        return True
    if 0x0001 <= v <= 0x012F:
        return True
    if 0x1000 <= v <= 0x12FF:
        return True
    if 0x1800 <= v <= 0x18FF:
        return True
    if 0x2800 <= v <= 0x29FF:
        return True
    if 0x2A00 <= v <= 0x2BFF:
        return True
    return False

# The notorious all-zeros placeholder — workmanager + a thousand tutorials use it.
DROP_OUTRIGHT_UUIDS = {
    "00000000-0000-0000-0000-000000000000",
    # All-1s sentinel — typically a ScanFilter mask passed as the 2nd
    # argument to ScanFilter.Builder.setServiceUuid(uuid, uuidMask). The
    # all-ones mask means "match all bits"; it's a bitmask, not a UUID.
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    # Android WorkManager NULL_STRING_V1 sentinel embedded in a constant
    "androidx.work.data-95ed6082-b8e9-46e8-a73f-ff56f00f5d9d".lower(),
    # UTC Fire & Security TRFramework SDK — `TRFrameworkInstallationGuid`
    # sentinel hex-decoded to bytes and stored in SharedPreferences (NOT a
    # BLE UUID). Observed in com.monbuilding.app.legende.
    "ac44f0a1-1b35-455f-8141-123785934c69",
    # Single-digit-repeated sentinels — observed as placeholder UUIDs in
    # SDK code (e.g. com.harman.akgn20lt's e2/d.java declares
    # `f15565h = "66666666-6666-6666-6666-666666666666"` and `f15566i =
    # "77777777-7777-7777-7777-777777777777"` alongside the real UUIDs).
    # They are test fixtures / placeholder constants — not BLE UUIDs.
    "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222",
    "33333333-3333-3333-3333-333333333333",
    "44444444-4444-4444-4444-444444444444",
    "55555555-5555-5555-5555-555555555555",
    "66666666-6666-6666-6666-666666666666",
    "77777777-7777-7777-7777-777777777777",
    "88888888-8888-8888-8888-888888888888",
    "99999999-9999-9999-9999-999999999999",
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    "cccccccc-cccc-cccc-cccc-cccccccccccc",
    "dddddddd-dddd-dddd-dddd-dddddddddddd",
    "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
    "12345678-1234-5678-1234-567812345678",
    # DRM "System ID" constants used in MPEG-CENC PSSH (Protection System
    # Specific Header) boxes by org.mp4parser and the broader DASH-IF
    # ecosystem. These look like BLE UUIDs because the spec encoded each
    # DRM scheme as a UUID, but they're DRM identifiers, not GATT services.
    # Documented at https://dashif.org/identifiers/content_protection/ —
    # any APK that bundles mp4parser will surface these.
    "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed",  # Widevine
    "9a04f079-9840-4286-ab92-e65be0885f95",  # Microsoft PlayReady
    "a2b55680-6f43-11e0-9a3f-0002a5d5c51b",  # OMA2 / Open Mobile Alliance DRM
    "1077efec-c0b2-4d02-ace3-3c1e52e2fb4b",  # W3C ClearKey
    "94ce86fb-07ff-4f43-adb8-93d2fa968ca2",  # Apple FairPlay
    "5e629af5-38da-4063-8977-97ffbd9902d4",  # Marlin DRM (Intertrust)
    "f239e769-efa3-4850-9c16-a903c6932efb",  # Adobe Primetime
    "adb41c24-2dbf-4a6d-958b-4457c0d27b95",  # Adobe Access (older Primetime)
    "80a6be7e-1448-4c37-9e70-d5aebe04c8d2",  # Irdeto
    "279fe473-512c-48fe-ade8-d176fee6b40f",  # ARRIS Titanium
    "a68129d3-575b-4f1a-9cba-3223846cf7c3",  # Synamedia
    "afbcb50e-bdad-49a4-8190-1f5a3f7d3a1c",  # Mobitv
    "29701fe4-3cc7-4a34-8c5b-ae90c7439a47",  # Apple FairPlay (alt id)
    "6dd8b3c3-45f4-4a68-bf3a-64168d01a4a6",  # ABV/Olympusat
    "3d5e6d35-9b9a-41a8-b9f2-50e9c2c40db0",  # CMLA
    "3ea8778f-7742-4bf9-b18b-e834b2acbd47",  # ChinaDRM
    "be58615b-19c4-4684-88b3-c8c57e99e957",  # Verimatrix
}

# Patterns that mean a UUID is being constructed/used in a way unrelated to BLE.
# We don't outright drop these — but they suppress the GATT classification.
NON_GATT_HINT_RE = re.compile(
    r"androidx\.work|WorkSpec|WorkerParameters|UUID\.randomUUID|"
    r"java\.util\.UUID\s*\(|toString\(\)|Crashlytics|Firebase|"
    r"FCM|GoogleAuth|"
    # Crash-reporting / analytics SDKs that take an app-instance GUID as a
    # config argument (NOT a Bluetooth UUID). Catches false positives like
    # AppCenter.start(application, "e45eb716-...", Analytics.class, ...)
    # which the file-level BLE detection would otherwise let through
    # because the surrounding file (BleService.java) has real BLE code.
    r"AppCenter|Sentry|BugSnag|Bugsnag|Datadog|Mixpanel|Amplitude|"
    r"Segment\.|com\.segment|Branch\.io|AppsFlyer|Adjust\.|Smartlook|"
    r"AdobeAnalytics|InstrumentationKey|"
    r"AppCenterAnalytics|AppCenterCrashes|MSAnalytics|"
    # Adobe Edge / Azure Application Insights / OneTrust patterns we saw
    # in com.abbott.lingo.wellness BuildConfig.
    r"AppInsights|AdobeEdge|OneTrust",
    re.IGNORECASE,
)

# Semantically non-GATT identifiers confirmed in source. Unlike the broader
# contextual hints above, these patterns are checked against the field name
# assigned to the UUID on that line, so a nearby app-ID constant cannot mask
# a real GATT UUID elsewhere in the same file. A direct GATT API use of the
# same field also takes precedence.
NON_GATT_FIELD_HINT_RE = re.compile(
    # OneSignal app/channel IDs appear both as ONESIGNAL_* and ONE_SIGNAL_*;
    # keep the names narrow enough to avoid treating generic notification IDs
    # as non-GATT. `CHNNEL` preserves the spelling observed in Apporio's SDK.
    r"\b[A-Z0-9_]*(?:ONE_?SIGNAL)_(?:APP|ORG|CHANNEL|CHNNEL)_ID\b|"
    r"\bERROR_APP_ID_[A-Z0-9_]+\b|"
    r"\bINVESTA_CUSTOMER_ID\b",
    re.IGNORECASE,
)

# `CLIENT_ID` and similar names are ambiguous. Suppress only confirmed
# non-GATT fields in their exact declaring package/class; an explicit GATT
# sink use of the same field still wins. These are source-backed shard-01
# findings, not UUID-value exclusions.
NON_GATT_CLASS_FIELD_HINTS: dict[tuple[str, str], frozenset[str]] = {
    ("com.banno.android.network", "ApiServiceVariables"): frozenset({"CLIENT_ID"}),
    ("com.microsoft.identity.common.adal.internal", "Broker"): frozenset({"WEBCP_CLIENT_ID"}),
    ("com.ce.android.brand.havajava", "HavaJavaProperties"): frozenset({"CLIENT_ID"}),
    ("zendesk.android.internal.frontendevents", "FrontendEventsRepository"): frozenset({"CLIENT_ID"}),
    ("zendesk.analyticskit.android.model", "AnalyticsSettings"): frozenset({"CLIENT_ID"}),
    ("com.zebra.sdk.comm.internal", "BluetoothUuids"): frozenset({"STATUS_CHANNEL_ID"}),
    # Whirlpool onboarding credential text is characteristic payload, not an attribute UUID.
    ("com.whirlpool.blegattclient", "GattClient"): frozenset({"accessCredentials"}),
    # Dexcom Share development registration values, not Bluetooth attributes.
    ("com.dexcom.common.service.internal.model", "Constants"): frozenset({"TEST_ACCOUNT_ID", "TEST_APP_ID"}),
    # Allegion test integration values and Polar OAuth client credentials.
    ("com.allegion.accesssdk.nfc", "BuildConfig"): frozenset({"EXPECTED_CONNECTED_ACCOUNT", "EXPECTED_ACCESS_RIGHT_RESPONSE_ID", "INTEGRATION_ID"}),
    ("com.inetech.cns.omenu.device.polar", "Polar"): frozenset({"clientId", "clientSecret"}),
    # Huf lease-token demo document identifiers are payload fields, not GATT UUIDs.
    ("com.hufsm.secureaccess.api", "LeaseToken"): frozenset({"leaseTokenId", "leaseId", "sorcId"}),
    ("com.hufsm.secureaccess.ble.model.lease", "LeaseToken"): frozenset({"leaseTokenId", "leaseId", "sorcId"}),
    # A source-traced GATT descriptor, outside the service/characteristic schema.
    ("com.starkey.android.bluetooth", "BluetoothConstantsKt"): frozenset({"SSI_LONG_SIZE_DESCRIPTOR"}),
    # OpenKey uses this as a test application ID in key material.
    ("com.keypr.mobilesdk.digitalkey.openkey.internal", "OpenKeyMaterial"): frozenset({"TEST_APP_ID"}),
    # ANTLR's parser ATN serialization versions are UUID-shaped protocol
    # markers. JADX emits each literal into a uuidFromString temp, then
    # assigns that temp to the named constant in a separate statement.
    ("org.antlr.v4.runtime.atn", "ATNDeserializer"): frozenset({
        "BASE_SERIALIZED_UUID",
        "ADDED_PRECEDENCE_TRANSITIONS",
        "ADDED_LEXER_ACTIONS",
        "SERIALIZED_UUID",
    }),
    # Source-verified authentication, analytics, and classic RFCOMM IDs.
    # Restrict by defining class/field; direct GATT use can still override.
    ("com.alibaba.ailabs.iot.aisbase", "Constants"): frozenset({"UUID_RFCOMM", "RFCOMM_UUID"}),
    ("com.appsgeyser.sdk.configuration", "Constants"): frozenset({"APP_METRICA_ID"}),
    ("oneapp.framework.network", "f"): frozenset({"MSAL_CLIENT_ID"}),
    # New Relic embeds a UUID-shaped application BUILD_ID for telemetry.
    # The `_ID` catalog convention would otherwise call it a characteristic.
    # Keep this source-backed exclusion scoped to NewRelicConfig; direct GATT
    # use of the same field still overrides the hint in scan_one_file.
    ("com.newrelic.agent.android", "NewRelicConfig"): frozenset({"BUILD_ID"}),
    # Cordova BluetoothSerial's MY_UUID_* values are RFCOMM service-record
    # UUIDs passed to listenUsing*RfcommWithServiceRecord, not GATT UUIDs.
    ("com.megster.cordova", "BluetoothSerialService"): frozenset({
        "MY_UUID_INSECURE",
        "MY_UUID_SECURE",
    }),
}

# Source-reviewed eSolar menu keys and Nerivio Outlook OAuth identifiers.
NON_GATT_CLASS_FIELD_HINTS.update({
    ('app.theranica.fragments.main.settings.preventive.calendar.outlook', 'OutlookAuthManager'): frozenset(['CLIENT_ID', 'REDIRECT_URI', 'redirect_uri']),
    ('app.theranica.fragments.main.settings.preventive.calendar.outlook', 'OutlookAuthRedirectActivity'): frozenset(['SCHEME']),
    ('com.saj.connection.net.us', 'NetRemoteConfig'): frozenset(['MENU_ID_BATTERY_ADVANCED_SETTING_AS3', 'MENU_ID_BATTERY_ADVANCED_SETTING_H1', 'MENU_ID_BATTERY_ADVANCED_SETTING_H2', 'MENU_ID_BATTERY_ADVANCED_SETTING_HS3', 'MENU_ID_SELF_TEST_REPORT', 'MENU_ID_US_HIGH_DIESEL_GENERATOR', 'MENU_ID_US_LOW_CHECK_DEVICE', 'MENU_ID_US_LOW_GEN_PORT_SETTING', 'MENU_ID_US_LOW_PARALLEL_SETTING', 'MENU_ID_US_PARALLEL', 'MENU_ID_US_WORK_MODE_LOW_VOLT', 'MENU_ID_YA_FEI_LA_GEN_PORT_SETTING', 'MENU_ID_YA_FEI_LA_PARALLEL_SETTING']),
})

# Scoped app feature-flag/chat and invoice/country configuration IDs.
NON_GATT_CLASS_FIELD_HINTS.update({
    ('com.totem', 'BuildConfig'): frozenset(['CRISP_WEBSITE_ID_EQT', 'CRISP_WEBSITE_ID_INFORMA', 'CRISP_WEBSITE_ID_TOTEM', 'LAUNCH_DARKLY_MOBILE_KEY']),
    ('ro.digibank.fgo.ui.screens.efactura', 'FgoTransactionToSend'): frozenset(['SPENDING_CATEGORY_ID']),
    ('ro.itom.fgoro.salt.fgolibrary.domain.model', 'Client'): frozenset(['ROMANIA_ID']),
    ('ro.itom.fgoro.salt.fgolibrary.domain.model', 'Registry'): frozenset(['INVOICE_REGISTRY_ID', 'PROFORMA_REGISTRY_ID']),
})

# App-specific messaging, venue, ad SDK and restaurant backend IDs.
NON_GATT_CLASS_FIELD_HINTS.update({
    ('com.belico.simpelapp', 'BuildConfig'): frozenset(['SENDBIRD_APP_ID']),
    ('com.belico.simpelapp.utils', 'GlobalUtil'): frozenset(['str3']),
    ('com.ce.android.brand.beechrestaurants', 'BEECHRestaurantsProperties'): frozenset(['CLIENT_ID']),
    ('com.ce.android.brand.minutemanburgers', 'MinuteManBurgersProperties'): frozenset(['CLIENT_ID']),
    ('com.ce.android.brand.southernroost', 'SouthernRoostProperties'): frozenset(['CLIENT_ID']),
    ('com.clientmobileapp', 'BuildConfig'): frozenset(['BRAZE_API_KEY_ANDROID', 'BRAZE_API_KEY_IOS', 'SENDBIRD_APP_ID']),
    ('com.io.wearlynxtracking', 'WearLynxModule'): frozenset(['BLUE_MOUNTAIN_SUMMER_RESORT_GUID', 'SNOW_VALLEY_RESORT_GUID']),
    ('com.kakao.adfit', 'AdfitSdk'): frozenset(['BUILD_ID']),
    ('com.wearlynx.slandroidalterrawl', 'SLAndroidAlterraWL'): frozenset(['BLUE_MOUNTAIN_SUMMER_RESORT_GUID', 'SNOW_VALLEY_RESORT_GUID']),
    ('com.wearlynx.slandroidalterrawl.resortdata', 'SLAlterraWLBots'): frozenset(['mpResortGuid']),
    ('com.wearlynx.slandroidalterrawl.resortdata', 'SLResortBlueMountainONSummer'): frozenset(['guid']),
    ('com.wearlynx.slandroidalterrawl.resortdata', 'SLResortSnowValley'): frozenset(['guid']),
    ('io.te2.defaults', 'BaseNavigationActivity'): frozenset(['STRATTON_ACTIVITIES_CATEGORY', 'TREMBLANT_ACTIVITIES_CATEGORY']),
})

# Creditcall uses obfuscated a/b/c/d fields for payment processor receipt
# identifiers. The same short field names occur in unrelated BLE classes;
# restrict the exclusion to the exact source-backed receipt classes.
for _receipt_class in (
    "ChaseReceiptData", "ElavonReceiptData", "FirstDataReceiptData",
    "GlobalReceiptData", "TsysReceiptData", "UsHeartlandReceiptData",
    "UsWorldpayReceiptData",
):
    NON_GATT_CLASS_FIELD_HINTS[("com.creditcall.chipdnamobile", _receipt_class)] = frozenset({"a", "b", "c", "d"})

# Vise's `GattAttributeResolver` is a mixed Bluetooth lookup table. These three
# ESDP UUIDs are Classic SDP service-class identifiers, not GATT services; the
# remaining GATT/Estimote entries in that table stay eligible. A direct GATT
# sink use of one of these exact fields still overrides this scoped hint.
NON_GATT_CLASS_FIELD_HINTS.update({
    ("com.vise.baseble.model.resolver", "GattAttributeResolver"): frozenset({
        "ESDP_UPNP_IP_PAN",
        "ESDP_UPNP_IP_LAP",
        "ESDP_UPNP_L2CAP",
    }),
})

# Shard-03 source audit: these UUID-shaped values are used as advertisement
# region IDs or HTTP signing keys, not GATT attributes. Keep each exclusion
# bound to the declaring class and field so an equal UUID used by real GATT
# code elsewhere remains eligible. Direct GATT use of an exact hinted field
# still overrides the scoped exclusion in scan_one_file.
NON_GATT_CLASS_FIELD_HINTS.update({
    ("de.kisi.android.nearby", "KisiBeaconTracker"): frozenset({
        "KISI_BEACON_UUIDS",
    }),
    ("com.kastle.kastlesdk.ble.util.constant", "KSBLEConstants"): frozenset({
        "FEASY_BEACON_PROXIMITY_UUID",
    }),
    ("com.yhk.rabbit.print.utils", "AppConst"): frozenset({
        "FORMALKEY",
        "SMSKEY",
        "PERMISSIONKEY",
        "NETTYKEY",
        "EMAILKEY",
    }),
    # AppStreet meal-serving unit database IDs, not Bluetooth identifiers.
    ("com.appstreet.repository.util", "UnitUtilsKt"): frozenset({
        "DEFAULT_SERVING_ID",
        "SERVING_UNIT_GRAM_ID",
        "SERVING_UNIT_ML_ID",
    }),
    ("com.ce.android.brand.jerusalemcafe", "JerusalemCafeProperties"): frozenset({
        "CLIENT_ID",
    }),
    ("com.ce.android.brand.rubinsteinbagels", "RubinsteinBagelsProperties"): frozenset({
        "CLIENT_ID",
    }),
    ("com.ce.android.brand.bellacinos", "BellacinosProperties"): frozenset({
        "CLIENT_ID",
    }),
    ("com.ce.android.brand.icebergdriveinn", "IcebergDriveInnProperties"): frozenset({
        "CLIENT_ID",
    }),
    ("com.ce.android.brand.auberginekitchen", "AubergineKitchenProperties"): frozenset({"CLIENT_ID"}),
    ("com.ce.android.brand.wingiton", "WingItOnProperties"): frozenset({"CLIENT_ID"}),
    ("com.ce.android.brand.thehungrycowgirlcocina", "TheHungryCowgirlCocinaProperties"): frozenset({"CLIENT_ID"}),
    ("com.ce.android.brand.breadzeppelin", "BreadZeppelinProperties"): frozenset({"CLIENT_ID"}),
    ("com.htc.hubble.hwsetup.account", "AccountClientKt"): frozenset({"VRS_CLIENT_ID", "CA_CLIENT_ID"}),
    ("com.qst.mswift", "BuildConfig"): frozenset({"AUTHKEY", "CLIENT_REQUEST_ENCRYPTION_KEY"}),
    ("com.qst.mswift.constant", "AppConstant"): frozenset({"AUTHKEY", "CLIENT_REQUEST_ENCRYPTION_KEY"}),
    ("com.sefam.sefamaccess", "BuildConfig"): frozenset({"ANDROID_HOCKEYAPP_APP_ID"}),
    ("life.league.login", "LoginFragment"): frozenset({"PLATFORM_ID"}),
    ("com.rootexplorer.forandroidfiles", "KpDocumentsApplication"): frozenset({"ONESIGNAL_APP_ID"}),
    ("com.microsoft.office.watson", "Utils"): frozenset({
        "OFFICEMOBILE_APP_NON_PROD_APP_ID", "OFFICESUITE_APP_HA_ID", "OFFICEMOBILE_APP_HA_ID",
        "OFFICEMOBILE_APP_HA_ID_CPP", "MICROSOFT_TENANT_ID",
    }),
    ("com.microsoft.office.docsui.common", "AccountTransferController"): frozenset({
        "APPGROUP_REDIRECT_WORD", "APPGROUP_REDIRECT_EXCEL", "APPGROUP_REDIRECT_PPT",
    }),
    ("com.p002newrelic.agent.android", "NewRelicConfig"): frozenset({"BUILD_ID"}),
    ("fi.kansalliskirjasto.ekirjasto.testing", "TestingOverrides"): frozenset({"TEST_LOGIN_LIBRARY_PROVIDER_ID"}),
    ("fi.ekirjasto.testing", "BuildConfig"): frozenset({"TEST_LOGIN_LIBRARY_PROVIDER_ID"}),
    ("fi.kansalliskirjasto.ekirjasto", "BuildConfig"): frozenset({"LIBRARY_PROVIDER_ID"}),
    # Source-reviewed API authentication and OneTrust domain configuration.
    ("com.abbemobility.terraconfig", "BuildConfig"): frozenset({"API_CLIENT_ID"}),
    ("com.auctionmobility.auctions.util", "OTTypeFaceKeys"): frozenset({"PROD_DOMAIN_ID", "DOMAIN_ID"}),
    ("com.szte.griffin", "BuildConfig"): frozenset({"AUTH_CONFIG_APP_ID"}),
    ("com.gifites.payes.config", "Config"): frozenset({"ONE_SIGNAL_ID"}),
    ("com.ce.android.brand.ellielous", "EllieLousProperties"): frozenset({"CLIENT_ID"}),
    ("com.ce.android.brand.antiochpizzashop", "AntiochPizzashopProperties"): frozenset({"CLIENT_ID"}),
    ("com.ce.android.brand.rodrigosmexicangrill", "RodrigosMexicanGrillProperties"): frozenset({"CLIENT_ID"}),
    ("com.ce.android.brand.healthinhand", "HealthInHandProperties"): frozenset({"CLIENT_ID"}),
    ("com.ce.android.brand.hangryjoes", "HangryJoesProperties"): frozenset({"CLIENT_ID"}),
    ("com.misa.amis.screen.loginsso", "LoginSSOManager"): frozenset({"CLIENT_ID"}),
    ("vn.com.misa.tms.viewcontroller.sso", "LoginSSOManager"): frozenset({"CLIENT_ID"}),
    ("com.misa.amis.screen.main.personal.mail.addaccount", "MailAddAccountPresenter"): frozenset({"OUTLOOK_CLIENT_ID"}),
    ("ca.journie.dev", "BuildConfig"): frozenset({"BRAZE_API_KEY_IOS", "BRAZE_API_KEY_ANDROID"}),
    ("com.urbanasolutions.toolkit", "BuildConfig"): frozenset({"TRADUORA_CLIENT_ID"}),
    ("ru.tensor.sbis.catalog.generated", "AttributeConst"): frozenset({
        "SIMPLE", "TNVED", "OKPD2", "MANUFACTURER", "IMPORTER",
    }),
    ("ru.tensor.sbis.catalog.generated", "ServiceCategoryUuids"): frozenset({
        "CATEGORY_VEHICLE_MODEL", "CATEGORY_TOURIST_TAX", "CATEGORY_VEHICLE_TIRE", "CATEGORY_HOTEL_ROOM",
    }),
    ("ru.tensor.sbis.regulation.generated", "VirtualPhases"): frozenset({
        "APPROVAL_REQUEST", "APPROVAL", "APPROVAL_ACCEPTED", "APPROVAL_REJECTED",
        "SENDER_CANCELLATION", "RECEIVER_CANCELLATION",
    }),
})

# Hints used to classify a UUID match. Bigger weights win.
# Class/method names (BluetoothGatt*, addService, ...) are strong signals.
# Field-name conventions (_SERVICE, _CHAR_) are weaker but necessary on
# pure-constants classes with no android.bluetooth imports (e.g. Abbott
# Libre3's DCSGKSConstants.java — 3 services + 12 characteristics all under
# `LIBRE3_DATA_SERVICE` / `LIBRE3_CHAR_*`).
#
# Lookbehind/lookahead `(?<![A-Za-z])` / `(?![A-Za-z])` on bare SERVICE /
# CHARACTERISTIC tokens prevents the noisy case of matching package names
# (`serviceUUID`, `IBleServiceUUID`) and method-name substrings
# (`getReceiveCharacteristic`) — those false-positives caused 3 of 3 Rosslare
# AxTrax UUIDs to be mis-classified as Service when only 1 was.
SERVICE_HINT_RE = re.compile(
    r"BluetoothGattService|addService\s*\(|getService\s*\(|"
    r"PRIMARY_SERVICE|SECONDARY_SERVICE|ScanFilter\.Builder|"
    r"setServiceUuid|setServiceData|"
    # NOTE: bare `ParcelUuid` USED to be in this list, but it's a *type* signal,
    # not a *role* signal — a `ParcelUuid.fromString("...")` can equally hold a
    # service OR a characteristic UUID. Including it here biased
    # writeCharacteristicDevice / readCharacteristicDevice UUIDs (e.g. Tobit's
    # zimoscooterlibrary / omnilibrary) toward GATT Service, misclassifying
    # them. ParcelUuid remains in FILE_LEVEL_BLE_RE for BLE-relevance, which
    # is correct — `android.os.ParcelUuid` import does prove a file uses BLE.
    # `_SERVICE\b` is already bounded by the leading `_` so no further
    # lookbehind needed; this matches `LIBRE3_DATA_SERVICE` correctly.
    r"_SERVICE\b|SERVICE_UUID|SVC_UUID",
    re.IGNORECASE,
)
CHARACTERISTIC_HINT_RE = re.compile(
    r"BluetoothGattCharacteristic|addCharacteristic|getCharacteristic|"
    r"writeCharacteristic|readCharacteristic|setCharacteristicNotification|"
    r"_CHAR_|CHAR_UUID|"
    r"(?<![A-Za-z])CHARACTERISTIC(?![A-Za-z])",
    re.IGNORECASE,
)

# Whole-file BLE-relevance check. If a file imports or references any of the
# android.bluetooth.* classes that take UUIDs, treat every UUID literal in
# it as a BLE UUID — even if the literal is hundreds of lines away from any
# BluetoothGatt* identifier (the common case for classes that declare all
# UUIDs in one big block at the top, à la `bt/c.java` in co.diaz.srvol).
FILE_LEVEL_BLE_RE = re.compile(
    r"android\.bluetooth\.BluetoothGatt|"
    r"android\.bluetooth\.le\.ScanFilter|"
    r"android\.bluetooth\.BluetoothGattCharacteristic|"
    r"android\.bluetooth\.BluetoothGattService|"
    r"android\.bluetooth\.BluetoothGattDescriptor|"
    r"android\.os\.ParcelUuid",
    re.IGNORECASE,
)

# Fallback BLE-relevance check: some apps (e.g. com.harman.akgn20lt's
# `e2/d.java`) put all UUID constants into a plain Java class that doesn't
# itself import any android.bluetooth.* type — the BLE-aware classes import
# *this* class instead. To catch these, count how many full 128-bit-form
# `UUID.fromString("...")` literals appear. Three or more is a near-certain
# signal of a BLE-constants file. The "in URLs / connection strings" UUIDs
# in non-BLE config classes (Adobe Edge, Azure App Insights, OneTrust) sit
# inside string concatenations or as raw values, not inside UUID.fromString
# calls, so this heuristic doesn't catch them.
UUID_FROMSTRING_LITERAL_RE = re.compile(
    r'UUID\.fromString\(\s*"'
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    r'"\s*\)'
)
MIN_UUID_FROMSTRING_FOR_BLE_FALLBACK = 3
# Upper bound for the SAME fallback. A file with no android.bluetooth.* import and a
# very large number of UUID literals is a DATA TABLE, not a GATT catalog: a real GATT
# profile declares a service plus a handful of characteristics, so a high count is
# evidence AGAINST BLE rather than for it.
#
# Found 2026-09-27: com.ubnt.usurvey's xe/m.java (1,182 UUID literals, imports
# UiFirmwareBoard / UiFirmwarePlatform / UiDB / UispProductFirmware) and xe/f.java
# (477 literals) are Ubiquiti's product/firmware catalog. Neither references a single
# Bluetooth API, yet the unbounded fallback classified all of them "GATT Service" via
# file-level-default — 875 false-positive records from one app.
#
# Files that DO import android.bluetooth.* are unaffected by this cap, so a genuine
# BLE class with many UUIDs still works.
MAX_UUID_FROMSTRING_FOR_BLE_FALLBACK = 64

# Pull the LHS Java identifier that a UUID.fromString or
# ParcelUuid.fromString result is being assigned to. Matches:
#   public static final UUID LIBRE3_DATA_SERVICE = UUID.fromString("...");
#   UUID svc = UUID.fromString("...");
#   B = UUID.fromString("...");
#   ParcelUuid serviceUuidDevice = ParcelUuid.fromString("...");   # Tobit
# This is what gives us a human-meaningful UUID_name to replace "Unknown".
# Both fromString() callees yield the same UUID value at runtime, and apps
# routinely use ParcelUuid in the field type (it's what Android's ScanFilter
# and getServiceUuids() consume natively). Dropping the ParcelUuid form was
# silently masking real field names — observed in
# `com.Tobit.labs.zimoscooterlibrary.ScooterUtil` and
# `com.Tobit.labs.omnilibrary.Util.OmniBikeLockUtil`, where
# `writeCharacteristicDevice` / `readCharacteristicDevice` field names lived
# on the same line as the UUID literal but never made it into field_to_uuid.
UUID_ASSIGNMENT_RE = re.compile(
    r'(?:public\s+|private\s+|protected\s+|static\s+|final\s+|UUID\s+|ParcelUuid\s+)*'
    r'([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*'
    r'(?:UUID|ParcelUuid)\.fromString\(\s*"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"'
    # Allow chained transformer calls between the literal and the closing `)`,
    # e.g. `"<uuid>".toUpperCase()` / `"<uuid>".toLowerCase(Locale.US)`.
    # Observed in Tobit zimoscooterlibrary `serviceUuidPw` and
    # `notifyCharacteristicDevice_password` where the field-name regex
    # otherwise misses because the dot-call chain after the literal made the
    # original strict pattern fail. Each chained call is `.identifier(args)`
    # with bounded `[^()]*` args to keep the engine away from backtracking
    # on huge expressions.
    r'(?:\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\([^()]{0,80}\))*'
    r'\s*\)',
)

# Same idea but for `private static final String FOO_UUID = "uuid-string";`
# declarations (no UUID.fromString call — the literal is held as a String
# and passed to UUID.fromString elsewhere). Common in Android BLE tutorial
# code (see com.bsks.bsks_abookn's `CHAR_UUID_YOU_CAN_CHANGE` placeholder).
# The leading `String\s+` requires `String` to anchor the match so it
# doesn't fire on arbitrary string assignments — only ones the developer
# declared with the type word `String`.
UUID_STRING_ASSIGNMENT_RE = re.compile(
    r'(?:public\s+|private\s+|protected\s+|static\s+|final\s+)*'
    r'String\s+'
    r'([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*'
    r'"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"\s*;',
)

# Array-of-UUIDs declaration: `UUID[] mServiceUuids = { UUID.fromString("..."),
# UUID.fromString("..."), ... };`. The array variable name (e.g. mServiceUuids)
# applies to ALL elements; it's the best name we can attach to each UUID in
# the array. Common in BLE scan-filter setup.
UUID_ARRAY_ASSIGNMENT_RE = re.compile(
    r'(?:public\s+|private\s+|protected\s+|static\s+|final\s+)*'
    r'UUID\s*\[\s*\]\s+'
    r'([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\{([^}]+)\}',
)


# Enum-constant pattern. Java enums declare constants with one or more
# constructor arguments — the developer's *enum-constant identifier* is the
# best UUID name we have, but it lives in front of the constructor call
# rather than on the LHS of an assignment, so UUID_ASSIGNMENT_RE misses it
# entirely. Real-world examples from Kontakt's
# `com.kontakt.sdk.android.ble.spec.KontaktDeviceService` and
# `KontaktDeviceCharacteristic` use raw quoted UUID strings:
#
#   KONTAKT_DFU_SERVICE("1b314d70-6c97-43fc-b5dd-3d0e125e15fb",
#       "Kontakt DFU (KDFU) Service"),
#   KDFU_COMMAND("KDFU Command Characteristic",
#       "1b314d71-6c97-43fc-b5dd-3d0e125e15fb"),
#
# Other SDKs do wrap the UUID as UUID.fromString(...) / ParcelUuid.fromString(...),
# so the regex accepts either representation. The UUID may be any constructor
# argument — not always the first or last — so we anchor on the enum name and
# scan ahead (across newlines) for the first UUID-looking quoted literal,
# optionally preceded by a fromString wrapper.
#
# Constraints to keep this from over-matching ordinary method calls:
#   - Enum constant names are UPPER_SNAKE_CASE by convention. We require
#     the identifier to start with an uppercase letter and be at least two
#     chars long. This rejects `getService(` / `addFilter(` etc.
#   - We only run this pre-pass in files that actually declare an `enum`.
#   - The UUID literal must appear within ~300 chars of the opening `(` to
#     avoid matching across unrelated declarations.
#
# Multiple enum constants can share one UUID via the same enum class, and
# multiple UUIDs can appear in one constructor arg list (rare); we only
# capture the *first* UUID per enum constant — that's the semantic one.
ENUM_CONSTANT_UUID_RE = re.compile(
    r'\b([A-Z][A-Z0-9_]{1,})\s*\('
    r'[^()]{0,300}?'
    r'(?:(?:UUID|ParcelUuid)\.fromString\(\s*)?"'
    r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"',
    re.DOTALL,
)


# Constructor-label catalogs. JADX often lowers Kotlin enum/data-object
# tables into a static-init block where the human label and UUID no longer
# live on the same assignment:
#
#   UUID uuidFromString21 = UUID.fromString("00001335-...");
#   LOCK = new GattUuid("LOCK", 20, uuidFromString21);          # Bird
#
#   f fVar = new f("PAX_SERVICE_NOTIFICATION", 0, svc,
#       uuidFromString, uuidFromString2);                       # PAX
#
#   new b("bikeType", uuidFromString, metadata)                 # Lovens
#
# The UUID assignment pass already knows `uuidFromString21 -> UUID`, but
# that temp is intentionally rejected as a UUID_name. The semantic name is
# inside the constructor call instead. Regex alone is brittle here because
# real rows often contain nested calls after the UUID argument, so the
# consumer uses a tiny quote/paren-aware line parser rather than trying to
# fake balanced parentheses with regex.
NEW_CONSTRUCTOR_START_RE = re.compile(
    r'\bnew\s+([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\('
)
ASSIGNED_NEW_CONSTRUCTOR_RE = re.compile(
    r'\b(?:this\.)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*'
    r'new\s+([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\('
)

# Constructor-body map used only when one label row carries multiple UUID
# arguments. PAX's notification enum is the motivating example:
#
#   private f(String str, int i2, g gVar, UUID uuid, UUID uuid2) {
#       this.dataReadyCharacteristicUUID = uuid;
#       this.readCharacteristicUUID = uuid2;
#   }
#
# Once we know argument slot 3 feeds `dataReadyCharacteristicUUID` and slot 4
# feeds `readCharacteristicUUID`, the extractor can emit distinct names such
# as `PAX_SERVICE_NOTIFICATION_dataReadyCharacteristicUUID` instead of
# ambiguously applying the same label to both UUIDs.
CONSTRUCTOR_DEF_RE = re.compile(
    r'\b(?:private|public|protected)\s+'
    r'([A-Za-z_$][A-Za-z0-9_$]*)\s*'
    r'\(([^()]{0,500})\)\s*\{([^{}]{0,1200})\}',
    re.DOTALL,
)
CONSTRUCTOR_SIG_RE = re.compile(
    r'\b(?:private|public|protected)\s+'
    r'([A-Za-z_$][A-Za-z0-9_$]*)\s*'
    r'\(([^()]{0,500})\)\s*\{',
    re.DOTALL,
)
THIS_FIELD_ASSIGN_RE = re.compile(
    r'\bthis\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*'
    r'([A-Za-z_$][A-Za-z0-9_$]*)\s*;'
)

# Anonymous singleton/object row pattern. Kotlin often lowers sealed-object
# characteristic catalogs into fields like:
#
#   public static final e0 BulkTransfer = new e0() {
#       { UUID.fromString("0ec9a5a3-..."); ... }
#   };
#
# The outer field name is the only semantic label left in the decompile.
# Keep the window bounded and require an actual anonymous `new ...() {`
# body so this does not drift across unrelated constructor calls.
ANON_OBJECT_FIELD_UUID_RE = re.compile(
    r'\b(?:public|private|protected)\s+static\s+final\s+'
    r'[A-Za-z_$][A-Za-z0-9_$<>, ?.\[\]]*\s+'
    r'([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*'
    r'new\s+[A-Za-z_$][A-Za-z0-9_$<>, ?.\[\]]*\s*\([^;{}]{0,120}\)\s*\{'
    r'(?:(?!\n\s*};).){0,1600}?'
    r'(?:UUID|ParcelUuid)\.fromString\(\s*"'
    r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"',
    re.DOTALL,
)

# Strong nearby BLE-log labels. Some apps have no useful source identifier
# at the UUID site but immediately log the vendor's own symbolic constant:
#
#   } else if (isUuid(ch, "00030021-...")) {
#       log("... -BLE_UUID_IC_RC_BTN_EVT_STATE");
#   }
#
# The all-caps `BLE_UUID_*` shape is intentionally narrow; ordinary prose
# logs ("after getting model", "service connected") are too ambiguous to
# promote into UUID_name automatically.
BLE_LOG_LABEL_RE = re.compile(r'\b(BLE_UUID_[A-Z0-9_]{3,})\b')


# Alias-propagation pattern. When a Kotlin `let { … }` / `apply { … }`
# block is lowered by the compiler, jadx renders the UUID as a temp
# variable that's then assigned to the real field:
#
#   ParcelUuid parcelUuidFromString = ParcelUuid.fromString("0000BAF0-…");
#   Intrinsics.checkNotNullExpressionValue(parcelUuidFromString, …);
#   serviceUUID = parcelUuidFromString;
#
# Without alias propagation, `UUID_ASSIGNMENT_RE` captures the temp as
# `field_name`, which then gets rejected by `uuid_name_from_field` (in the
# REJECT_FIELD_NAMES list) — and the merge step leaves UUID_name as
# "Unknown". The terminal `serviceUUID = parcelUuidFromString;` line tells
# us the real field name, but we have to (a) recognize the *target* of the
# alias and (b) propagate it back to the UUID.
#
# Captures (terminal_field, source_field). We then look up `source_field`
# in `field_to_uuid` and, if it's a temp/rejectable name, replace the entry
# with the terminal field. Excludes cases where the RHS itself looks like a
# UUID expression (UUID.fromString / ParcelUuid.fromString / "uuid-literal")
# — those are direct assignments handled elsewhere.
ALIAS_PROPAGATION_RE = re.compile(
    # LHS can be any identifier — `serviceUUID` (camelCase) or
    # `SERVICE_UUID` (upper-snake). The temp-name filter applied at use
    # time (must be in REJECT_FIELD_NAMES) is what keeps this from
    # matching arbitrary `i = j;` noise.
    r'\b([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*'
    r'([A-Za-z_$][A-Za-z0-9_$]*)\s*;'
)


# Nested-subclass catalog pattern. Kotlin `sealed class` / Java abstract
# class with nested `static final class` children, each holding a UUID
# constant in its parent-super call. Observed in Climax's
# `com.climax.fourSecure.services.bluetooth.uuid.BL3Characteristic`:
#
#   public abstract class BL3Characteristic extends CommonCharacteristic { …
#       public static final class FlashLight extends BL3Characteristic {
#           public static final FlashLight INSTANCE = new FlashLight();
#           private FlashLight() {
#               super("08dea137-9666-45c6-9f20-131620ed63dc", "BLE 紅燈閃爍五次", null);
#           }
#       }
#       public static final class History extends BL3Characteristic { … }
#       public static final class Unbind   extends BL3Characteristic { … }
#       …
#   }
#
# Each subclass is the semantic name. Anchor on the constructor — in Java
# the constructor name IS the class name, so `private FlashLight() { super("uuid"`
# directly gives us (FlashLight, UUID). This is much tighter than anchoring
# on `class … extends …` (which would greedily catch the outer wrapper
# class's super call from one of its inner classes).
NESTED_SUBCLASS_UUID_RE = re.compile(
    # Require an access modifier so the engine can't try this at every token
    # boundary in a large file (catastrophic-backtracking guard). Bound the
    # constructor parameter list to a reasonable length. Don't use re.DOTALL
    # — constructor signature + opening brace + super() call all fit on a
    # few lines.
    r'\b(?:private|public|protected)\s+'
    r'([A-Z][A-Za-z0-9_$]*)\s*\([^)\n]{0,200}\)\s*\{\s*'
    r'super\s*\(\s*"'
    r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"',
)


# Untyped string-UUID assignment, common in static-init blocks where the
# field is declared at class-level and the value is set later:
#
#   public class SampleGattAttributes {
#       public static String HEART_RATE_MEASUREMENT;
#       public static String Test_Cooker;
#       static {
#           HEART_RATE_MEASUREMENT = "00002a37-0000-1000-8000-00805f9b34fb";
#           Test_Cooker            = "00010203-0405-0607-0809-0a0b0c0d2b19";
#       }
#   }
#
# `UUID_STRING_ASSIGNMENT_RE` already covers `String FIELD = "uuid";` on
# one line. This regex covers the bare `FIELD = "uuid";` form inside
# static blocks, gated on the LHS looking like a constant identifier
# (starts uppercase OR all-uppercase with `_`). We deliberately do NOT
# match lowercase camelCase LHS — those would catch `str = "uuid";` style
# noise and the `UUID_ASSIGNMENT_RE` already handles the typed case.
UUID_RAW_STRING_ASSIGNMENT_RE = re.compile(
    r'\b([A-Z][A-Za-z0-9_$]{1,})\s*=\s*"'
    r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"\s*;',
)

# Instance-field UUID strings assigned in constructors often survive JADX only
# as `this.f123 = "..."`. Unlike a loose local `str = "..."`, the explicit
# `this.` receiver is reliable field provenance and enables usage tracing.
UUID_INSTANCE_STRING_ASSIGNMENT_RE = re.compile(
    r'\bthis\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"'
    r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"\s*;',
)


# GATT-sink LHS pattern. Captures the field name on the LHS of an assignment
# whose RHS is a `service.getCharacteristic(UUID.fromString("uuid"))` or
# `gatt.getService(UUID.fromString("uuid"))` lookup. The LHS field is the
# developer's semantic label for the *fetched* characteristic/service —
# usually a more meaningful identifier than the inline UUID expression.
# Verbatim from the user-cited Tobit example:
#
#   this.characteristicAppComm =
#       service.getCharacteristic(UUID.fromString("57420002-..."));
#
# Captures (lhs_field, uuid, kind) where kind is "service" or "characteristic".
# Allows `this.` prefix on LHS and the transformed-fromString chain on the
# UUID literal. re.DOTALL so the LHS and the call can span multiple lines.
GATT_SINK_LHS_RE = re.compile(
    r'\b(?:this\.)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*'
    r'[^=;]{0,200}?'
    r'\.(getService|getCharacteristic)\s*\(\s*'
    r'(?:UUID|ParcelUuid)\.fromString\(\s*"'
    r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"'
    r'(?:\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\([^()]{0,80}\))*'
    r'\s*\)',
    re.DOTALL,
)


# BLE catalog / label map pattern. Many BLE apps ship a `BleNamesResolver`-
# style class or in-line `mServices.put(uuid, "Human Readable Name")` map
# that the developer hand-curated. The label is the most accurate UUID name
# available — better than any heuristic. Observed in the user audit:
#
#   mServices.put("0000fde3-…", "(Propr: Xiaomi MiLi Service)");
#   mServices.put(SERVICE_ONBOARDING_UUID, "SERVICE_ONBOARDING");
#   mCharacteristics.put("00002a87-…", "Scale User Info");
#
# Captures (map_name, key_str_or_ident, label). When `key` is a quoted UUID
# we resolve directly; when it's an identifier we resolve via the file's
# local-constant map built from UUID_STRING_ASSIGNMENT_RE /
# UUID_RAW_STRING_ASSIGNMENT_RE. The map_name (`mServices` vs
# `mCharacteristics`) is also a classification hint.
#
# To avoid mis-matching general object registries (e.g. analytics SDKs that
# .put(eventId, "EventName")), the consumer code applies a BLE-context gate:
# the surrounding file must mention BleNamesResolver / BluetoothGatt* /
# mServices / mCharacteristics / etc. — see BLE_CATALOG_FILE_GATE_RE.
BLE_CATALOG_MAP_PUT_RE = re.compile(
    r'\b(\w+)\.put\s*\(\s*'
    r'(?:"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"'
    r'|([A-Za-z_$][A-Za-z0-9_$]*))'
    r'\s*,\s*"([^"\n]{1,80})"\s*\)',
)

# File-level gate: only treat `.put(...)` rows as a BLE catalog when the
# file shows clear Bluetooth-domain context. Without this, generated
# resource registries (R$id, analytics event tables, etc.) would feed
# nonsense labels into UUID_name.
BLE_CATALOG_FILE_GATE_RE = re.compile(
    r"\bBleNamesResolver\b"
    r"|\bBluetoothGatt(?:Service|Characteristic|Descriptor)\b"
    r"|\bmServices\b|\bmCharacteristics\b|\bmDescriptors\b"
    r"|\battributes\.put\b"  # SampleGattAttributes pattern from Picooc/Fanlight
)

# Method that returns a UUID string from its body. Captures (method_name, uuid).
# Pattern is widespread in BLE Android code that doesn't use field constants:
#
#   public String getService() { return "d973f2e0-..."; }
#   public UUID   getReceiveCharacteristic() { return UUID.fromString("d973f2e1-..."); }
#
# The method name is then THE strongest hint for classification — much
# stronger than scanning ±8 lines of surrounding code (which can pick up
# unrelated `getService(` references from sibling methods).
UUID_METHOD_RETURN_RE = re.compile(
    r'\b(?:public|private|protected|static|final|synchronized)\s+'
    r'(?:String|UUID|ParcelUuid)\s+'
    r'([A-Za-z_$][A-Za-z0-9_$]*)\s*\(\s*\)\s*\{'
    r'[^{}]*?'
    r'return\s+(?:UUID\.fromString\(\s*)?"'
    r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"',
    re.DOTALL,
)


# Kotlin @Metadata annotation parser. When jadx decompiles a Kotlin class
# that the obfuscator has minified, it preserves the `@Metadata(d1=…, d2=…)`
# annotation verbatim — d2 is a human-readable string table that maps
# obfuscated JVM names back to the original Kotlin identifiers. Example
# from `t3/a.java`:
#
#   @Metadata(bv={}, d1={"…compressed binary…"},
#       d2={"Lt3/a$c;", "", "", "a", "()Ljava/lang/String;", "CHARACTERISTIC_UUID",
#           "b", "DESCRIPTOR_UUID", "<init>", "()V", "infrastructure_release"},
#       k=1, mv={1, 7, 1})
#   public static final class c {
#       public final String a() { return "fb282a37-…"; }
#       public final String b() { return "fb282902-…"; }
#   }
#
# Reading d2 left-to-right with a small state machine:
#   "a" — looks like a JVM method name        → remember as last_method
#   "()Ljava/lang/String;" — JVM signature    → ignore
#   "CHARACTERISTIC_UUID" — looks like a      → emit (a -> CHARACTERISTIC_UUID)
#                          Kotlin property
#   "b" — JVM method name                     → remember
#   "DESCRIPTOR_UUID" — Kotlin property       → emit (b -> DESCRIPTOR_UUID)
#                       (signature deduped)
#
# This recovers ground-truth names that no other mechanism can: the only
# place the property name exists in the .class file is inside this
# annotation. Critical for Kotlin BLE wrappers that use property syntax
# (`val CHARACTERISTIC_UUID get() = "…"`) which the compiler lowers to
# `String a() { return "…"; }`.
KOTLIN_METADATA_D2_RE = re.compile(
    r'@Metadata\s*\([^)]*?\bd2\s*=\s*\{([^}]*)\}',
    re.DOTALL,
)
# A quoted string literal (with escape-sequence support) inside the d2 body.
KOTLIN_D2_STRING_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
# A unified d2 tokenizer that yields either a quoted string or a Java
# constant reference (e.g. `HtmlTags.ANCHOR`). jadx replaces short
# string literals in `@Metadata.d2` with their known-constant equivalents
# from imported libraries; without resolving those, the JVM method names
# (single chars like "a", "b") disappear from the string-only parse and
# their property names lose their anchor. JADX_CONSTANT_VALUES below
# maps each known constant back to its string value.
KOTLIN_D2_TOKEN_RE = re.compile(
    r'"((?:\\.|[^"\\])*)"'                                # quoted string
    r'|'
    r'\b([A-Z][A-Za-z0-9_]*(?:\.[A-Z][A-Za-z0-9_]*)+)\b'  # constant ref
)

# Known Java constants that jadx substitutes for short string literals when
# it decompiles a class. The values come from public sources:
#   iText HtmlTags:        https://github.com/itext/itext-java
#   Nimbus JOSE JWKs:      RFC 7517/7518 field codes
#   AndroidX support libs: NotificationCompat categories, etc.
JADX_CONSTANT_VALUES: dict[str, str] = {
    # iText HtmlTags — the single-letter tag-name constants.
    "HtmlTags.A":       "a",
    "HtmlTags.ANCHOR":  "a",
    "HtmlTags.B":       "b",
    "HtmlTags.BOLD":    "b",
    "HtmlTags.BODY":    "body",
    "HtmlTags.BR":      "br",
    "HtmlTags.DIV":     "div",
    "HtmlTags.EM":      "em",
    "HtmlTags.HR":      "hr",
    "HtmlTags.I":       "i",
    "HtmlTags.ITALIC":  "i",
    "HtmlTags.P":       "p",
    "HtmlTags.PARAGRAPH": "p",
    "HtmlTags.S":       "s",
    "HtmlTags.SPAN":    "span",
    "HtmlTags.STRONG":  "strong",
    "HtmlTags.U":       "u",
    # Nimbus JOSE JWKParameterNames (RFC 7517/7518 field codes).
    "JWKParameterNames.CURVE":                       "crv",
    "JWKParameterNames.ELLIPTIC_CURVE_X_COORDINATE": "x",
    "JWKParameterNames.ELLIPTIC_CURVE_Y_COORDINATE": "y",
    "JWKParameterNames.OCT_KEY_VALUE":               "k",
    "JWKParameterNames.RSA_EXPONENT":                "e",
    "JWKParameterNames.RSA_FIRST_PRIME_FACTOR":      "p",
    "JWKParameterNames.RSA_MODULUS":                 "n",
    "JWKParameterNames.RSA_PRIVATE_EXPONENT":        "d",
    "JWKParameterNames.RSA_SECOND_PRIME_FACTOR":     "q",
    # AndroidX NotificationCompat categories.
    "NotificationCompat.CATEGORY_ALARM":         "alarm",
    "NotificationCompat.CATEGORY_CALL":          "call",
    "NotificationCompat.CATEGORY_EMAIL":         "email",
    "NotificationCompat.CATEGORY_ERROR":         "err",
    "NotificationCompat.CATEGORY_MESSAGE":       "msg",
    "NotificationCompat.CATEGORY_PROGRESS":      "progress",
    "NotificationCompat.CATEGORY_SERVICE":       "service",
    "NotificationCompat.CATEGORY_SOCIAL":        "social",
    "NotificationCompat.CATEGORY_STATUS":        "status",
    # Misc — observed in Bluetooth-related decompiles.
    "ConnectionComponent.NamedBooleans.AUTO_CONNECT":  "autoConnect",
    "ServiceSpecificExtraArgs.CastExtraArgs.LISTENER": "listener",
}


def _looks_like_jvm_obfuscated_name(s: str) -> bool:
    """A short Java identifier that the obfuscator emitted in place of an
    original Kotlin name: 1–6 chars, lowercase-leading, or `f<digits>...`
    forms that jadx produces for synthetic accessors."""
    if not s or len(s) > 8:
        return False
    if re.fullmatch(r"[a-z][a-zA-Z0-9]{0,5}", s):
        return True
    if re.fullmatch(r"f\d+[a-zA-Z]?[a-zA-Z0-9]*", s):
        return True
    return False


def _looks_like_kotlin_property_name(s: str) -> bool:
    """An identifier that's plausibly the original Kotlin property name —
    longer than 3 chars, contains semantic structure (underscore, uppercase
    transitions, or all-uppercase tokens)."""
    if not s or len(s) < 4:
        return False
    if s.startswith(("L", "(")):  # JVM class signature or method signature
        return False
    if s in {"<init>", "<clinit>"}:
        return False
    if "/" in s:  # package-path-like (e.g. "infrastructure_release")
        return False
    # Must contain at least one uppercase letter OR underscore — a pure
    # lowercase word would not have survived Kotlin->JVM lowering as a
    # property identifier (it'd be a method name).
    if "_" not in s and not any(c.isupper() for c in s):
        return False
    return True


def _resolve_d2_token(kind: str, value: str) -> str | None:
    """Convert a d2 token to its effective string value. Quoted strings
    pass through. Java constant references resolve via JADX_CONSTANT_VALUES
    when known. Unknown constants return None (the parser treats them as
    an unparseable token and resets its method-name anchor)."""
    if kind == "str":
        return value
    if kind == "const":
        return JADX_CONSTANT_VALUES.get(value)
    return None


def parse_kotlin_metadata_property_map(text: str) -> dict[str, str]:
    """Return a `{jvm_method_name: kotlin_property_name}` map extracted from
    all `@Metadata(... d2={…})` annotations in `text`. Multiple annotations
    contribute independently; conflicts resolve "first match wins."

    Handles both quoted-string and jadx-substituted-constant tokens. Example:
        d2 = {"Lt3/a$c;", "", "", HtmlTags.ANCHOR, "()Ljava/lang/String;",
              "CHARACTERISTIC_UUID", HtmlTags.B, "DESCRIPTOR_UUID", ...}
        -> {"a": "CHARACTERISTIC_UUID", "b": "DESCRIPTOR_UUID"}
    """
    out: dict[str, str] = {}
    for m in KOTLIN_METADATA_D2_RE.finditer(text):
        d2_body = m.group(1)
        # Tokenize d2 body into ordered (kind, value) tokens.
        tokens: list[tuple[str, str]] = []
        for tm in KOTLIN_D2_TOKEN_RE.finditer(d2_body):
            if tm.group(1) is not None:
                tokens.append(("str", tm.group(1)))
            else:
                tokens.append(("const", tm.group(2)))
        last_method: str | None = None
        for kind, raw in tokens:
            s = _resolve_d2_token(kind, raw)
            if s is None:
                # Unresolved constant — reset anchor so we don't pair it
                # with an unrelated property name later.
                last_method = None
                continue
            # Class signature / JVM signature / known noise reset state.
            if s.startswith("L") and s.endswith(";"):
                last_method = None
                continue
            if s.startswith("("):  # JVM method signature like "()Ljava/lang/String;"
                continue
            if s in ("<init>", "<clinit>", ""):
                last_method = None
                continue
            if _looks_like_jvm_obfuscated_name(s):
                last_method = s
                continue
            if last_method and _looks_like_kotlin_property_name(s):
                out.setdefault(last_method, s)
                last_method = None
    return out


# Scan-filter builder pattern. Many BLE apps wire scan filters inline,
# without ever naming the UUID as a constant:
#
#   this.dfuScanFilters.add(new ScanFilter.Builder()
#       .setServiceUuid(ParcelUuid.fromString("9F492A41-...")).build());
#
# The closest descriptive identifier is the *enclosing field name* (e.g.
# `dfuScanFilters`). That's not a UUID name in the strict sense — it's the
# name of a List<ScanFilter> the UUID was added to — but it's the only
# semantic label the developer left in the code, so it beats "Unknown".
# Same precedent as UUID_ARRAY_ASSIGNMENT_RE (array variable → per-UUID name).
SCAN_FILTER_BUILDER_RE = re.compile(
    r'\b(?:this\.)?([A-Za-z_$][A-Za-z0-9_$]*)\.add\s*\(\s*'
    r'new\s+ScanFilter\.Builder\s*\(\s*\)\s*'
    r'\.\s*setServiceUuid\s*\(\s*ParcelUuid\.fromString\s*\(\s*"'
    r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"',
)


# SQL INSERT catalog pattern. Some BLE apps (e.g. Belwith SecuRemoteSmartApp,
# com.belwith.pdqsmart) embed the device's GATT structure as SQLite seed data
# inside the app's onCreate(SQLiteDatabase). Example row:
#
#   sQLiteDatabase.execSQL(
#       "INSERT INTO Characteristics (ID, CharUUID, CharName, ServiceId, "
#       "DeviceId, IsObservable, CharReturnType) VALUES "
#       "(18, '60312c08-45a2-4d08-9863-70c41a134cf5', 'InformationStatus', 3, 1, 1, 'data')"
#   );
#
# We extract (UUID, Name, classification_hint) tuples by:
#   1. Recognizing column-name conventions (CharUUID / ServiceUUID / Name).
#   2. Aligning column-list and values-list indices.
#   3. Inferring class from the table name (Characteristics → Char, Services
#      → Service) when the column names don't fully disambiguate.
UUID_SQL_INSERT_RE = re.compile(
    r'INSERT\s+INTO\s+(\w+)\s*\(([^)]+)\)\s+VALUES\s*\((.+?)\)\s*[\";]',
    re.IGNORECASE | re.DOTALL,
)


def _split_sql_values(vals_str: str) -> list[str]:
    """Tokenize a SQL VALUES tuple body, respecting single-quoted strings.
    Returns a flat list of value tokens (strings, integers, NULLs). Naive
    split on commas would break on values like "I, Robot".
    """
    out: list[str] = []
    cur: list[str] = []
    in_quote = False
    i = 0
    while i < len(vals_str):
        ch = vals_str[i]
        if ch == "'" and (i == 0 or vals_str[i-1] != "\\"):
            in_quote = not in_quote
            cur.append(ch)
        elif ch == "," and not in_quote:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    if cur:
        out.append("".join(cur).strip())
    return out


_SQL_UUID_COL_NAMES = {
    "uuid", "charuuid", "char_uuid", "characteristicuuid", "characteristic_uuid",
    "serviceuuid", "service_uuid", "svcuuid",
}
_SQL_NAME_COL_NAMES = {
    "name", "charname", "char_name", "characteristicname", "characteristic_name",
    "servicename", "service_name", "svcname",
}


def parse_sql_insert(table: str, cols_str: str, vals_str: str) -> list[tuple[str, str, str]]:
    """Returns list of (uuid_lower, name, classification) tuples from one
    INSERT statement. Classification is 'GATT Service' / 'GATT Characteristic'
    /Unknown, inferred from column name first, then table name.
    """
    cols = [c.strip().strip("`\"'") for c in cols_str.split(",")]
    vals = _split_sql_values(vals_str)
    if not cols or len(cols) != len(vals):
        return []
    uuid_idx: int | None = None
    name_idx: int | None = None
    uuid_col_name: str | None = None
    for i, c in enumerate(cols):
        cl = c.lower()
        if uuid_idx is None and cl in _SQL_UUID_COL_NAMES:
            uuid_idx = i
            uuid_col_name = cl
        if name_idx is None and cl in _SQL_NAME_COL_NAMES:
            name_idx = i
    if uuid_idx is None:
        return []
    # Classification: prefer the column-name signal, fall back to the table name
    cls = "Unknown"
    if uuid_col_name and "char" in uuid_col_name:
        cls = "GATT Characteristic"
    elif uuid_col_name and ("service" in uuid_col_name or "svc" in uuid_col_name):
        cls = "GATT Service"
    elif "char" in table.lower():
        cls = "GATT Characteristic"
    elif "service" in table.lower() or "svc" in table.lower():
        cls = "GATT Service"
    uuid_val = vals[uuid_idx].strip().strip("'\"")
    name_val = vals[name_idx].strip().strip("'\"") if name_idx is not None else ""
    if not re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', uuid_val):
        return []
    return [(uuid_val.lower(), name_val, cls)]


def _split_top_level_java_args(args: str) -> list[str]:
    """Split a Java argument list on top-level commas only."""
    out: list[str] = []
    cur: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False
    for ch in args:
        if quote is not None:
            cur.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in {'"', "'"}:
            quote = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur).strip())
    return out


def _find_matching_paren_on_line(line: str, open_idx: int) -> int | None:
    """Return the matching close paren for a same-line constructor call."""
    depth = 0
    quote: str | None = None
    escaped = False
    for i in range(open_idx, len(line)):
        ch = line[i]
        if quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in {'"', "'"}:
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return None


def _matching_paren_indices_on_line(line: str) -> dict[int, int]:
    """Map each syntactic opening parenthesis to its matching close in O(n)."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    quote: str | None = None
    escaped = False
    for i, ch in enumerate(line):
        if quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in {'"', "'"}:
            quote = ch
        elif ch == "(":
            stack.append(i)
        elif ch == ")" and stack:
            pairs[stack.pop()] = i
    return pairs


def _matching_paren_for_constructor(
    line: str, open_idx: int, paren_cache: list[dict[int, int] | None] | None,
) -> int | None:
    if paren_cache is None:
        return _find_matching_paren_on_line(line, open_idx)
    if paren_cache[0] is None:
        paren_cache[0] = _matching_paren_indices_on_line(line)
    close_idx = paren_cache[0].get(open_idx)
    # A regex match inside a quoted or malformed fragment may not be visible
    # to the whole-line lexer. Preserve the legacy result for that edge case.
    return close_idx if close_idx is not None else _find_matching_paren_on_line(line, open_idx)


def _iter_constructor_calls_on_line(
    line: str, paren_cache: list[dict[int, int] | None] | None = None,
):
    """Yield `(simple_ctor_name, args)` for same-line `new Type(...)` calls."""
    for m in NEW_CONSTRUCTOR_START_RE.finditer(line):
        open_idx = line.find("(", m.start())
        if open_idx < 0:
            continue
        close_idx = _matching_paren_for_constructor(line, open_idx, paren_cache)
        if close_idx is None:
            continue
        ctor_name = m.group(1).split(".")[-1]
        yield ctor_name, _split_top_level_java_args(line[open_idx + 1:close_idx])


def _iter_assigned_constructor_calls_on_line(
    line: str, paren_cache: list[dict[int, int] | None] | None = None,
):
    """Yield `(lhs_field, simple_ctor_name, args)` for same-line
    `field = new Type(...)` constructor calls."""
    for m in ASSIGNED_NEW_CONSTRUCTOR_RE.finditer(line):
        open_idx = line.find("(", m.start())
        if open_idx < 0:
            continue
        close_idx = _matching_paren_for_constructor(line, open_idx, paren_cache)
        if close_idx is None:
            continue
        lhs = m.group(1)
        ctor_name = m.group(2).split(".")[-1]
        yield lhs, ctor_name, _split_top_level_java_args(line[open_idx + 1:close_idx])


def _java_param_name(param: str) -> str | None:
    """Best-effort final identifier from one Java parameter declaration."""
    ids = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", param)
    return ids[-1] if ids else None


def _constructor_param_maps(text: str) -> dict[tuple[str, int], list[str | None]]:
    """Map `(constructor_name, arity)` to ordered Java parameter names."""
    out: dict[tuple[str, int], list[str | None]] = {}
    for m in CONSTRUCTOR_SIG_RE.finditer(text):
        ctor_name = m.group(1)
        params = _split_top_level_java_args(m.group(2))
        out.setdefault((ctor_name, len(params)), [_java_param_name(p) for p in params])
    return out


def _index_constructor_param_maps(
    param_maps: dict[tuple[str, int], list[str | None]],
) -> dict[str, list[tuple[int, list[str | None]]]]:
    """Group signatures by constructor name, preserving source order."""
    by_name: dict[str, list[tuple[int, list[str | None]]]] = {}
    for (name, arity), params in param_maps.items():
        by_name.setdefault(name, []).append((arity, params))
    return by_name


def _is_generic_constructor_param_name(name: str | None) -> bool:
    """True for constructor arg labels that are role-free by themselves."""
    if not name:
        return True
    return name.lower() in {
        "id",
        "uuid",
        "serviceid",
        "characteristicid",
        "descriptorid",
    }


def _gatt_characteristic_entity_param_role(
    ctor_name: str, param_name: str | None
) -> str | None:
    """Classify semantic UUID parameters of a GATT characteristic entity.

    Kotlin data entities commonly package one service UUID alongside write,
    read, or notify characteristic UUIDs. The field declaration may be in a
    static initializer and the constructor call may be the only typed role
    evidence, so accept these names only on an explicitly GATT-characteristic
    entity/config/model constructor. This does not generalize write/read/notify
    words across arbitrary constructors or UUID values.
    """
    if not param_name or not re.fullmatch(
        r"(?:Bluetooth)?GattCharacteristic(?:Entity|Config|Configuration|Model)?",
        ctor_name,
        re.IGNORECASE,
    ):
        return None
    name = re.sub(r"[^a-z0-9]", "", param_name.lower())
    if "service" in name or name.startswith("svc"):
        return "GATT Service"
    # Descriptors are a separate GATT object role and should not be folded
    # into the two-role CLUES classification.
    if "descriptor" in name:
        return None
    if any(token in name for token in (
        "characteristic", "char", "write", "read", "notify", "indicate"
    )):
        return "GATT Characteristic"
    return None


def _best_constructor_params(
    ctor_name: str,
    arity: int,
    local_maps: dict[tuple[str, int], list[str | None]],
    external_maps: dict[tuple[str, int], list[str | None]],
    local_by_name: dict[str, list[tuple[int, list[str | None]]]],
    external_by_name: dict[str, list[tuple[int, list[str | None]]]],
) -> list[str | None] | None:
    """Pick the most semantic constructor signature without rescanning all signatures.

    Kotlin default-arg lowering adds synthetic overloads with trailing mask /
    marker parameters and decompiler-generic names (`uuid`, `uuid2`, ...).
    Prefer an exact-arity signature when it is informative; otherwise allow a
    shorter same-constructor prefix when it has strictly more semantic names.
    The external index preserves the corpus-wide map order. Local signatures
    override matching keys in place and new local keys follow them, matching
    `dict.update()` ordering from the original implementation.
    """
    key = (ctor_name, arity)
    exact = local_maps.get(key)
    if exact is None:
        exact = external_maps.get(key)
    exact_score = sum(not _is_generic_constructor_param_name(p) for p in (exact or []))
    best = exact
    best_score = exact_score
    for cand_arity, external_cand in external_by_name.get(ctor_name, ()):
        cand = local_maps.get((ctor_name, cand_arity), external_cand)
        if cand_arity > arity:
            continue
        score = sum(not _is_generic_constructor_param_name(p) for p in cand)
        if score > best_score:
            best = cand
            best_score = score
    for cand_arity, cand in local_by_name.get(ctor_name, ()):
        if (ctor_name, cand_arity) in external_maps or cand_arity > arity:
            continue
        score = sum(not _is_generic_constructor_param_name(p) for p in cand)
        if score > best_score:
            best = cand
            best_score = score
    return best


def _constructor_field_maps(text: str) -> dict[tuple[str, int], dict[int, str]]:
    """Map constructor arg slots to direct `this.field = arg` targets."""
    out: dict[tuple[str, int], dict[int, str]] = {}
    for m in CONSTRUCTOR_DEF_RE.finditer(text):
        ctor_name = m.group(1)
        params = _split_top_level_java_args(m.group(2))
        param_names = [_java_param_name(p) for p in params]
        by_param = {p: i for i, p in enumerate(param_names) if p}
        field_map: dict[int, str] = {}
        for am in THIS_FIELD_ASSIGN_RE.finditer(m.group(3)):
            field_name, param_name = am.group(1), am.group(2)
            if param_name in by_param:
                field_map[by_param[param_name]] = field_name
        if field_map:
            out.setdefault((ctor_name, len(params)), field_map)
    return out


UUID_PARAM_DECL_RE = re.compile(
    r"^\s*(?:final\s+)*(?:java\.util\.)?UUID\s+"
    r"([A-Za-z_$][A-Za-z0-9_$]*)\s*$"
)


def _constructor_definition_counts(text: str) -> dict[tuple[str, int], int]:
    """Count same-name/arity constructor-shaped definitions for fail-closed matching."""
    counts: dict[tuple[str, int], int] = {}
    for m in CONSTRUCTOR_DEF_RE.finditer(text):
        params = _split_top_level_java_args(m.group(2))
        key = (m.group(1), len(params))
        counts[key] = counts.get(key, 0) + 1
    return counts


def _typed_uuid_pair_constructor_roles(text: str) -> dict[tuple[str, int], dict[int, str]]:
    """Map unique constructor slots to roles from UUID-typed direct field assignments.

    A constructor qualifies only if two distinct UUID-typed parameters are
    assigned directly into fields whose names independently mean service and
    characteristic. The APK-wide caller drops same-name/arity definitions in
    other classes so simple JADX constructor names cannot create cross-class
    guesses.
    """
    result: dict[tuple[str, int], dict[int, str]] = {}
    counts = _constructor_definition_counts(text)
    for m in CONSTRUCTOR_DEF_RE.finditer(text):
        ctor_name = m.group(1)
        params = _split_top_level_java_args(m.group(2))
        key = (ctor_name, len(params))
        if counts.get(key) != 1:
            continue
        uuid_param_slots: dict[str, int] = {}
        for idx, param in enumerate(params):
            pm = UUID_PARAM_DECL_RE.fullmatch(param)
            if pm:
                uuid_param_slots[pm.group(1)] = idx
        role_slots: dict[str, set[int]] = {
            "GATT Service": set(),
            "GATT Characteristic": set(),
        }
        for am in THIS_FIELD_ASSIGN_RE.finditer(m.group(3)):
            field_name, param_name = am.group(1), am.group(2)
            slot = uuid_param_slots.get(param_name)
            role = classify_via_field_name(field_name)
            if slot is not None and role in role_slots:
                role_slots[role].add(slot)
        if all(len(role_slots[role]) == 1 for role in role_slots):
            service_slot = next(iter(role_slots["GATT Service"]))
            characteristic_slot = next(iter(role_slots["GATT Characteristic"]))
            if service_slot != characteristic_slot:
                result[key] = {
                    service_slot: "GATT Service",
                    characteristic_slot: "GATT Characteristic",
                }
    return result


def _gardena_api_super_uuid_pairs(text: str) -> list[tuple[str, str]]:
    """Follow Gardena API subclasses' UUID temporaries into their base slots.

    The scope and verified base assignments matter: adjacent UUID literals or
    an unrelated ``super`` call do not establish service/characteristic roles.
    """
    if _java_package_of(text) != "com.gardena.libraries.bluetooth_watering.api":
        return []
    top = re.search(r"\b(?:abstract\s+)?class\s+(ReadCharacteristic|WriteCharacteristic)\b", text)
    if not top:
        return []
    base = top.group(1)
    arity = 2 if base == "ReadCharacteristic" else 3
    roles = _typed_uuid_pair_constructor_roles(text).get((base, arity))
    if roles != {0: "GATT Service", 1: "GATT Characteristic"}:
        return []
    braces = dict(_java_brace_spans(text))
    result: set[tuple[str, str]] = set()
    for cls in re.finditer(
        r"\bclass\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+extends\s+"
        + re.escape(base) + r"\b[^\{;]*\{", text,
    ):
        start = cls.end() - 1
        end = braces.get(start)
        if end is None:
            continue
        for ctor in CONSTRUCTOR_SIG_RE.finditer(text, start + 1, end):
            if ctor.group(1) != cls.group(1):
                continue
            body_start = ctor.end() - 1
            body_end = braces.get(body_start)
            if body_end is None or body_end > end:
                continue
            body = text[body_start + 1:body_end]
            values: dict[str, str] = {}
            # Only simple local UUID assignments are resolved; conflicting
            # assignments fail closed instead of borrowing another object's temp.
            conflicts: set[str] = set()
            for assignment in re.finditer(
                r'\bUUID\s+(\w+)\s*=\s*UUID\.fromString\("([0-9a-fA-F-]{36})"\)\s*;', body,
            ):
                name, raw = assignment.groups()
                if name in values:
                    conflicts.add(name)
                values[name] = normalize_uuid(raw)
            calls = list(re.finditer(r"\bsuper\s*\(", body))
            if len(calls) != 1:
                continue
            opening = body.find("(", calls[0].start())
            closing = _find_matching_java_paren(body, opening)
            if closing is None:
                continue
            args = _split_top_level_java_args(body[opening + 1:closing])
            if len(args) not in {arity, arity + 1}:
                continue
            if len(args) == arity + 1 and args[-1].strip() != "null":
                continue
            names = [arg.strip() for arg in args[:2]]
            if any(name not in values or name in conflicts for name in names):
                continue
            # Reject mutation after the UUID literal, even if the replacement
            # is not another fromString assignment.
            if any(len(re.findall(r"\b" + re.escape(name) + r"\s*=", body)) != 1 for name in names):
                continue
            service, characteristic = (values[name] for name in names)
            if service != characteristic:
                result.add((service, characteristic))
    return sorted(result)


def _camel_tokens(name: str) -> list[str]:
    return re.findall(r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|\d+", name)


def _shared_field_suffix(field_names: list[str]) -> str | None:
    """Common lower-camel suffix for duplicate-UUID multi-arg rows."""
    token_lists = [_camel_tokens(n) for n in field_names if n]
    if len(token_lists) < 2:
        return None
    common_rev: list[str] = []
    for group in zip(*(reversed(toks) for toks in token_lists)):
        first = group[0]
        if any(tok.lower() != first.lower() for tok in group[1:]):
            break
        common_rev.append(first)
    if not common_rev:
        return None
    toks = list(reversed(common_rev))
    first = toks[0]
    first = first[:1].lower() + first[1:]
    return first + "".join(toks[1:])


_LABEL_TOKEN_RE = re.compile(r"^[A-Za-z0-9_]{3,80}$")


def _quoted_constructor_label(arg: str) -> str | None:
    """Return a conservative identifier-like label from arg #0."""
    m = re.fullmatch(r'"([^"\\]{3,80})"', arg.strip())
    if not m:
        return None
    label = m.group(1)
    return label if _LABEL_TOKEN_RE.fullmatch(label) else None


def _nearby_ble_log_label(lines: list[str], idx: int) -> str | None:
    """Return one immediate `BLE_UUID_*` label if the window is unambiguous."""
    found: set[str] = set()
    for line in lines[idx: min(len(lines), idx + 4)]:
        found.update(BLE_LOG_LABEL_RE.findall(line))
    if len(found) == 1:
        return next(iter(found))
    return None


def _nested_subclass_temp_super_names(text: str) -> dict[str, str]:
    """Recover nested sealed-object names when the UUID is first assigned
    to a temp and then passed into `super(temp, ...)`.

    Kotlin/JADX commonly lowers:
        private BinaryTransferData() {
            UUID uuidFromString = UUID.fromString("...");
            super(uuidFromString, null);
        }
    The constructor/class name is the semantic label; the temp is noise.
    """
    out: dict[str, str] = {}
    for m in CONSTRUCTOR_DEF_RE.finditer(text):
        ctor_name = m.group(1)
        body = m.group(3)
        if not ctor_name[:1].isupper() or "super(" not in body:
            continue
        local_uuid_by_temp: dict[str, str] = {}
        for am in UUID_ASSIGNMENT_RE.finditer(body):
            local_uuid_by_temp[am.group(1)] = normalize_uuid(am.group(2))
        sm = re.search(r'\bsuper\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\b', body)
        if not sm:
            continue
        temp = sm.group(1)
        target_uuid = local_uuid_by_temp.get(temp)
        if target_uuid:
            out.setdefault(target_uuid, ctor_name)
    return out


def classify_via_field_name(field_name: str | None) -> str | None:
    """Highest-priority classifier: substring search on a captured Java
    identifier (field or method name). Returns one of:
      'GATT Service'        — name contains 'service' but not 'char'/'descriptor'
      'GATT Characteristic' — name contains 'char'/'descriptor' but not 'service'
      None                  — name has both or neither (fall through to window)

    Strictly substring-based (case-insensitive) because field/method names
    are uniformly written for a specific role: `getService`, `lockService`,
    `mServiceUuid`, `LIBRE3_DATA_SERVICE` → service. `getReceiveCharacteristic`,
    `mWriteChar`, `LIBRE3_CHAR_*` → characteristic. The window-based classifier
    can't reliably distinguish those because the file usually contains BOTH
    `getService()` and `getXxxCharacteristic()` near every UUID literal.
    """
    if not field_name:
        return None
    n = field_name.lower()
    has_char = (
        "char" in n
        or "descriptor" in n
        or re.search(r"(?:^|_)cha(?:_|$)", n) is not None
    )
    has_svc = "service" in n or "_svc" in n or n.startswith("svc")
    if has_char and not has_svc:
        return "GATT Characteristic"
    if has_svc and not has_char:
        return "GATT Service"
    # Catalog-naming convention: when a GATT-catalog class declares
    # constants as `FOO_SERVICE_ID` for services and `FOO_*_ID` for
    # everything else, an absent SERVICE token combined with a `_ID`
    # suffix is a strong characteristic signal. Observed in
    # com.intellimec.telematics.pts (WedgeGattServices interface; mixes
    # `*_SERVICE_ID` (service) with `*_FIFO_ID`, `*_VALUE_ID`, `*_LATEST_ID`
    # (characteristics)). We gate on `_ID` (uppercase) so the rule only
    # fires on this specific convention — not on every lowercase identifier.
    if not has_char and not has_svc and field_name.endswith("_ID"):
        # Recognize the catalog-naming convention only when the whole name
        # is upper-snake-case (CONSTANT_LIKE_ID). Mixed/camel names slip out.
        if re.fullmatch(r"[A-Z][A-Z0-9_]*_ID", field_name):
            return "GATT Characteristic"
    return None


def classification_source_strength(source: str | None) -> int:
    """Order role evidence so weak file guesses cannot erase stronger clues.

    Direct GATT sinks and explicit catalog roles dominate semantic field names;
    semantic names and the narrowly named GattCharacteristics container then
    outrank local line/window and file-level defaults. Ambiguous sources are
    deliberately retained until stronger direct usage resolves them.
    """
    source = source or ""
    if source == "ambiguous-role-conflict":
        return 20
    if source.startswith("ambiguous-"):
        return 100
    if source.startswith(("usage:", "cross-file usage:")):
        return 90
    if source.startswith(("sql-catalog:", "catalog-map", "sink-lhs:", "indexed-array-usage", "constructor-param:")):
        return 80
    if source.startswith("constructor-pair:"):
        return 75
    if source.startswith(("field-name:", "method-name:")):
        return 70
    if source.startswith("nested-type:"):
        return 65
    if source.startswith("characteristics-container:"):
        return 60
    if source == "naming-convention":
        return 40
    if source == "file-level-default":
        return 10
    return 30


def merge_role_evidence(entry: dict, role: str, source: str | None) -> None:
    """Merge one conflicting role observation without preferring Char by fiat."""
    old_role = entry.get("classification")
    old_source = entry.get("classification_source", "")
    if old_role == role:
        if (not old_source.startswith("ambiguous-")
                and classification_source_strength(source)
                > classification_source_strength(old_source)):
            entry["classification_source"] = source
        return

    old_is_ambiguity = old_source.startswith("ambiguous-") and old_source != "ambiguous-role-conflict"
    new_is_ambiguity = (source or "").startswith("ambiguous-") and source != "ambiguous-role-conflict"
    if old_is_ambiguity or new_is_ambiguity:
        if not old_is_ambiguity:
            entry["classification_source"] = source
        return

    old_strength = classification_source_strength(old_source)
    new_strength = classification_source_strength(source)
    if new_strength > old_strength:
        entry["classification"] = role
        entry["classification_source"] = source
    elif new_strength == old_strength:
        entry["classification_source"] = "ambiguous-role-conflict"

# Definitive-classification patterns. Once we have a Java field name F (e.g.
# `LIBRE3_DATA_SERVICE`), we search the file for these patterns. A hit on
# `getService(F)` is *authoritative* — the field is a Service UUID by API
# contract, no need to guess from naming conventions. Same for characteristics.
def make_field_usage_re(field: str) -> dict:
    """Build the per-field service/char usage regexes for one Java identifier.

    Two flavors per role:
      "call":   getService(FIELD) / getCharacteristic(FIELD) — direct fetch.
      "equals": BluetoothGattCharacteristic.getUuid().equals(FIELD) — type-anchored
                comparison. Observed in com.zebra.scannercontrol BluetoothLEManager.
    """
    f = re.escape(field)
    return {
        "service": re.compile(
            rf"\b(?:getService|hasService|addService)\s*\(\s*[^)]*\b{f}\b"
            rf"|"
            rf"\bbluetoothGattService\b[^;]*\.equals\(\s*[^)]*\b{f}\b",
            re.IGNORECASE,
        ),
        "characteristic": re.compile(
            rf"\b(?:getCharacteristic|hasCharacteristic|addCharacteristic|"
            rf"writeCharacteristic|readCharacteristic|setCharacteristicNotification|"
            rf"setCharacteristicIndication)\s*\(\s*[^)]*\b{f}\b"
            rf"|"
            rf"\bbluetoothGattCharacteristic\b[^;]*\.equals\(\s*[^)]*\b{f}\b",
            re.IGNORECASE,
        ),
    }


def _assigned_fields_for_uuid_on_line(line: str, uuid: str) -> list[str]:
    """Return field identifiers directly assigned this UUID on the line."""
    fields: list[str] = []
    for assignment_re in (
        UUID_ASSIGNMENT_RE,
        UUID_STRING_ASSIGNMENT_RE,
        UUID_INSTANCE_STRING_ASSIGNMENT_RE,
        UUID_RAW_STRING_ASSIGNMENT_RE,
    ):
        for match in assignment_re.finditer(line):
            if normalize_uuid(match.group(2)) == uuid:
                fields.append(match.group(1))
    return fields


def _field_usage_roles(field: str, source: str) -> set[str]:
    """Return every GATT role supported by typed UUID comparisons or sinks.

    Existing direct API calls remain first. The additional path follows the
    common JADX lowering `String uuidText = gattObject.getUuid().toString();`
    followed by `uuidText.equals(field)` / `compareToIgnoreCase(field)`. The
    receiver's declared BluetoothGattService/Characteristic type supplies the
    role, so this does not infer from a UUID16 value or host app identity.
    """
    roles: set[str] = set()
    direct = make_field_usage_re(field)
    if direct["characteristic"].search(source):
        roles.add("GATT Characteristic")
    if direct["service"].search(source):
        roles.add("GATT Service")

    field_ref = rf"(?:this\s*\.\s*)?{re.escape(field)}"
    # Follow source-local String -> UUID aliases into a typed GATT API sink.
    # Truma's JADX output uses `String str = this.field; UUID uuid =
    # UUID.fromString(str); service.getCharacteristic(uuid)`.
    value_aliases = {field}
    value_aliases.update(re.findall(
        rf"\bString\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*{field_ref}\s*;",
        source,
        re.IGNORECASE,
    ))
    uuid_aliases: set[str] = set()
    for value_alias in value_aliases:
        uuid_aliases.update(re.findall(
            rf"\bUUID\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*UUID\s*\.\s*fromString\s*\(\s*"
            rf"(?:this\s*\.\s*)?{re.escape(value_alias)}\s*\)\s*;",
            source,
            re.IGNORECASE,
        ))
    sink_values = value_aliases | uuid_aliases
    for method_name, role in (
        ("getService", "GATT Service"),
        ("getCharacteristic", "GATT Characteristic"),
        ("hasService", "GATT Service"),
        ("hasCharacteristic", "GATT Characteristic"),
    ):
        for sink_value in sink_values:
            if re.search(
                rf"\b{method_name}\s*\(\s*(?:"
                rf"UUID\s*\.\s*fromString\s*\(\s*(?:this\s*\.\s*)?{re.escape(sink_value)}\s*\)"
                rf"|(?:this\s*\.\s*)?{re.escape(sink_value)})\s*\)",
                source,
                re.IGNORECASE,
            ):
                roles.add(role)

    # Some SDKs assign a profile constant to a local UUID (`UUID uuid =
    # Owner.SERVICE;`) and pass only that local to the typed GATT lookup.
    # Follow this one-file alias only within its containing method and only
    # when the receiver is declared as the Android GATT type. This preserves
    # typed API evidence without treating unrelated methods named
    # getService/getCharacteristic as BLE sinks.
    for method_name, params, body in _iter_java_method_defs(source):
        uuid_vars = set(re.findall(
            r"\b(?:java\.util\.)?UUID\s+([A-Za-z_$][A-Za-z0-9_$]*)\b", body
        ))
        aliases: set[str] = set()
        assign_re = re.compile(
            r"(?:(?:java\.util\.)?UUID\s+)?"
            r"([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([^;{}]+);"
        )
        depth = 0
        for line in body.splitlines():
            for assignment in assign_re.finditer(line):
                lhs, rhs = assignment.group(1), assignment.group(2)
                if lhs not in uuid_vars:
                    continue
                source_value = bool(re.search(field_ref, rhs)) or any(
                    re.search(rf"(?<![A-Za-z0-9_$]){re.escape(alias)}(?![A-Za-z0-9_$])", rhs)
                    for alias in aliases
                )
                nested = depth + line[:assignment.start()].count("{") - line[:assignment.start()].count("}") > 0
                if source_value:
                    aliases.add(lhs)
                elif not nested:
                    aliases.discard(lhs)
            depth = max(0, depth + line.count("{") - line.count("}"))

        if not aliases:
            continue
        explicit_imports = set(re.findall(
            r"(?m)^\s*import\s+(android\.bluetooth\.(?:BluetoothGatt|BluetoothGattServer|BluetoothGattService))\s*;",
            source,
        ))
        if not explicit_imports:
            continue
        android_type_names = {
            name.rsplit(".", 1)[-1] for name in explicit_imports
        }
        declared_types = set(re.findall(
            r"\b(?:class|interface|enum|record)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b",
            source,
        ))
        if android_type_names & declared_types:
            continue
        typed_receivers: dict[str, set[str]] = {}
        for type_name in android_type_names:
            for receiver in re.findall(
                rf"\b{re.escape(type_name)}\s+([A-Za-z_$][A-Za-z0-9_$]*)\b",
                source,
            ):
                typed_receivers.setdefault(receiver, set()).add(type_name)
        for line in body.splitlines():
            for sink in re.finditer(
                r"(?P<receiver>[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*"
                r"(?P<method>getService|getCharacteristic|hasService|hasCharacteristic)\s*\(",
                line,
            ):
                receiver = sink.group("receiver")
                method = sink.group("method")
                expected = (
                    {"BluetoothGatt", "BluetoothGattServer"}
                    if method in {"getService", "hasService"}
                    else {"BluetoothGattService"}
                )
                if not typed_receivers.get(receiver, set()) & expected:
                    continue
                open_idx = line.find("(", sink.start("method") + len(method))
                close_idx = _find_matching_paren_on_line(line, open_idx)
                if close_idx is None:
                    continue
                args = _split_top_level_java_args(line[open_idx + 1:close_idx])
                if not args:
                    continue
                if any(
                    re.search(rf"(?<![A-Za-z0-9_$]){re.escape(alias)}(?![A-Za-z0-9_$])", args[0])
                    for alias in aliases
                ):
                    roles.add(
                        "GATT Service" if method in {"getService", "hasService"}
                        else "GATT Characteristic"
                    )

    method_names = r"(?:equals|equalsIgnoreCase|compareTo|compareToIgnoreCase)"

    # Direct typed getter comparisons, including `.getUuid().toString()`.
    for java_type, role in (
        ("BluetoothGattCharacteristic", "GATT Characteristic"),
        ("BluetoothGattService", "GATT Service"),
    ):
        receivers = set(re.findall(rf"\b{java_type}\s+([A-Za-z_$][A-Za-z0-9_$]*)\b", source))
        if not receivers:
            continue
        for receiver in receivers:
            getter = rf"{re.escape(receiver)}\s*\.\s*getUuid\s*\(\s*\)"
            direct_compare = re.compile(
                rf"(?:{getter}(?:\s*\.\s*toString\s*\(\s*\))?\s*\.\s*{method_names}\s*\(\s*{field_ref}"
                rf"|{field_ref}\s*\.\s*{method_names}\s*\(\s*{getter})",
                re.IGNORECASE,
            )
            if direct_compare.search(source):
                roles.add(role)

            # Resolve local String/UUID values assigned from the typed getter,
            # then follow a comparison with the field within this source file.
            # Bound alias uses to standalone identifier comparators to avoid
            # accidental matches inside another identifier.
            aliases = re.findall(
                rf"\b(?:String|UUID)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*{getter}"
                rf"(?:\s*\.\s*toString\s*\(\s*\))?\s*;",
                source,
                re.IGNORECASE,
            )
            for alias in aliases:
                cmp = re.compile(
                    rf"(?:\b{re.escape(alias)}\s*\.\s*{method_names}\s*\(\s*{field_ref}"
                    rf"|{field_ref}\s*\.\s*{method_names}\s*\(\s*\b{re.escape(alias)}\b)",
                    re.IGNORECASE,
                )
                if cmp.search(source):
                    roles.add(role)
    return roles


def _buildconfig_hotel_id_fields(file_texts: dict[str, str]) -> dict[str, set[str]]:
    """Find UUIDs assigned to explicit hotel/location IDs in BuildConfig.java.

    BuildConfig constants can contain business identifiers that happen to use
    UUID syntax. Keep this evidence tightly scoped to names that explicitly
    identify a hotel, property, location, resort, or venue ID; this is not a
    UUID blacklist and does not apply to other source files.
    """
    id_name_re = re.compile(
        r"(?:HOTEL|PROPERTY|LOCATION|RESORT|VENUE)(?:_[A-Z0-9]+)*_ID$",
        re.IGNORECASE,
    )
    ble_name_re = re.compile(
        r"(?:^|_)(?:BLE|GATT|UUID|SERVICE|CHAR|CHARACTERISTIC|DESC|"
        r"NOTIFY|NOTIFICATION|READ|WRITE|ADVERT)(?:_|$)",
        re.IGNORECASE,
    )
    fields_by_uuid: dict[str, set[str]] = {}
    for path, text in file_texts.items():
        if os.path.basename(path) != "BuildConfig.java":
            continue
        if not re.search(r"\bclass\s+BuildConfig\b", text):
            continue
        for line in text.splitlines():
            for raw in UUID128_LITERAL_RE.finditer(line):
                uuid = normalize_uuid("-".join(raw.groups()))
                for field in _assigned_fields_for_uuid_on_line(line, uuid):
                    if id_name_re.search(field) and not ble_name_re.search(field):
                        fields_by_uuid.setdefault(uuid, set()).add(field)
    return fields_by_uuid


def _field_usage_role(field: str, source: str) -> str | None:
    """Return a single role only when source usage evidence is unambiguous."""
    roles = _field_usage_roles(field, source)
    return next(iter(roles)) if len(roles) == 1 else None


def _field_has_gatt_sink(field: str, source: str) -> bool:
    """Whether a field has direct or typed-getter GATT use."""
    return bool(_field_usage_roles(field, source))


def _mobilytics_owner_uuid_sources(file_texts: dict[str, str]) -> dict[str, set[str]]:
    """Analytics feature-owner IDs from the verified SOURCE annotation.

    This recognizes source shape, never UUID values or broad Amazon packages.
    Filtering runs after APK-wide typed GATT recovery so a real endpoint use
    of the same constant remains authoritative.
    """
    result: dict[str, set[str]] = {}
    for path, text in file_texts.items():
        if (_java_package_of(text) != "com.amazon.alexa.mobilytics"
                or not re.search(r"@interface\s+OwnerIdentifier\b", text)
                or not re.search(r"@Retention\(\s*RetentionPolicy\.SOURCE\s*\)", text)):
            continue
        for raw in re.findall(
            r'\bstatic\s+final\s+String\s+\w+\s*=\s*"([0-9A-Fa-f-]{36})"', text
        ):
            result.setdefault(normalize_uuid(raw), set()).add(path)
    return result


def _smartbear_ui_metadata_uuid_sources(
    file_texts: dict[str, str],
) -> dict[str, set[str]]:
    """Find source-verified SmartBear UI metadata catalogs, not GATT profiles.

    Alere PSTMobile embeds these obfuscated SmartBear recording classes:
    mu = event properties; bs/ry = UI control adapters; mx = event types;
    nw = Xamarin UI hook names; fh = serialized expression-node factories.
    Require both the exact package/class and the observed source shape.
    This is deliberately not a global UUID-value exclusion.
    """
    result: dict[str, set[str]] = {}
    for path, text in file_texts.items():
        if _java_package_of(text) != "com.smartbear.testing":
            continue
        matches: list[str] = []
        if re.search(r"\bclass\s+(?:mu|bs|ry|mx)\b", text):
            # The affected classes are UUID constant dictionaries. A real
            # Android GATT consumer of one of these fields is preserved by
            # the APK-wide filter after cross-file role recovery below.
            matches = re.findall(
                r'\b(?:static\s+final|final\s+static)\s+UUID\s+\w+\s*='
                r'\s*UUID\.fromString\(\s*"([0-9A-Fa-f-]{36})"\s*\)',
                text,
            )
            if len(matches) < 3:
                matches = []
        elif (re.search(r"\bclass\s+nw\s+implements\s+NotificationCallback\b", text)
                and "android.view.MotionEvent" in text
                and "android.view.View" in text):
            # Only hook keys compared as notification names, not arbitrary
            # UUID strings elsewhere in this otherwise larger recorder.
            for field, value in re.findall(
                r'\bstatic\s+final\s+String\s+(\w+)\s*=\s*"([0-9A-Fa-f-]{36})"',
                text,
            ):
                if re.search(
                    rf"equalsIgnoreCase\(\s*{re.escape(field)}\s*\)"
                    rf"|\b{re.escape(field)}\.equalsIgnoreCase\(", text,
                ):
                    matches.append(value)
        elif (re.search(r"\bclass\s+fh\s+implements\s+fo\b", text)
                and "getConstructor(fo.class)" in text
                and "newInstance(this)" in text):
            # UUID -> expression evaluator class, used by the serialized
            # left/right/operation tree factory; not a Bluetooth catalog.
            matches = re.findall(
                r'\.put\(\s*UUID\.fromString\(\s*"([0-9A-Fa-f-]{36})"\s*\)'
                r'\s*,\s*(?:fm|fl|fi)\.class\s*\)', text,
            )
        for raw in matches:
            result.setdefault(normalize_uuid(raw), set()).add(path)
    return result


def _sony_non_gatt_uuid_context(uuid: str, java_package: str | None, source: str) -> bool:
    """Source-scoped Sony Classic contracts and unmatched-UUID sentinels.

    These are not global value exclusions: an independent direct GATT sink
    still wins in scan_one_file. The contracts include reversed SDP UUIDs
    used only by Android's getUuids compatibility workaround.
    """
    if java_package == "com.sony.songpal.tandemfamily":
        return bool(
            re.search(r"\bclass\s+SppConnectionContract\$(?:Tandem|Fiestable)\b", source)
            and "SppConnectionContract$DevASpec" in source
            and "SppConnectionContract$DevBSpec" in source
        )
    if (java_package != "com.sony.songpal.ble.client"
            or uuid != "5b830000-6bc7-4802-8e9a-723ceca4bd8f"):
        return False
    if re.search(r"\benum\s+ServiceUuid\b", source):
        return bool(
            re.search(r'UNKNOWN_SERVICE\s*\(\s*UUID\.fromString\(\s*"'
                      + re.escape(uuid) + r'"', source, re.I)
            and re.search(r"return\s+UNKNOWN_SERVICE\s*;", source)
        )
    if not re.search(r"\bclass\s+CharacteristicUuid\b", source):
        return False
    # Lowered enum: UNKNOWN constructor -> local -> static enum field;
    # the lookup's unmatched path returns that field. Empty parent set is
    # required so a real characteristic merely named UNKNOWN is retained.
    sentinel = re.search(
        r'(\w+)\s*=\s*new CharacteristicUuid\(\s*"UNKNOWN"\s*,\s*\d+\s*,'
        r'\s*UUID\.fromString\(\s*"' + re.escape(uuid) + r'"\s*\)\s*,'
        r'\s*Unknown\.class\s*,\s*"Unknown"\s*,\s*ServiceUuid\.e\(\)\s*\)\s*;',
        source, re.I,
    )
    if not sentinel:
        return False
    alias = re.search(r"\b(\w+)\s*=\s*" + re.escape(sentinel.group(1)) + r"\s*;", source)
    return bool(alias and re.search(r"return\s+" + re.escape(alias.group(1)) + r"\s*;", source))


def _matching_non_gatt_class_field_names(
    java_package: str | None, source: str
) -> set[str]:
    """Return field hints whose exact package and class scope match this file."""
    matches: set[str] = set()
    for (package_prefix, class_name), field_names in NON_GATT_CLASS_FIELD_HINTS.items():
        package_matches = java_package == package_prefix or bool(
            java_package and java_package.startswith(package_prefix + ".")
        )
        if not package_matches:
            continue
        class_matches = bool(
            re.search(
                rf"\b(?:class|interface|object)\s+{re.escape(class_name)}\b",
                source,
            )
        )
        if class_matches:
            matches.update(field_names)
    return matches


def _non_gatt_scoped_fields_for_uuid(
    uuid: str, java_package: str | None, source: str
) -> set[str]:
    """Resolve UUID occurrences to known non-GATT fields in scoped classes.

    JADX can render `UUID.fromString(...)` into a temporary (`uuidFromString`)
    and assign that value to a semantic constant on a later line. Some SDKs
    also repeat that same constant inline at call sites. Restrict direct and
    alias recovery to the class-scoped hint table so this cannot create
    name-based exclusions for unrelated UUIDs or files.
    """
    known_fields = _matching_non_gatt_class_field_names(java_package, source)
    if not known_fields:
        return set()
    temp_fields: set[str] = set()
    scoped_fields: set[str] = set()
    # The feature-flag SDK embeds the UUID-shaped identifier in a mob- key,
    # so the standard exact-UUID assignment matcher cannot recover its field.
    if ("LAUNCH_DARKLY_MOBILE_KEY" in known_fields and re.search(
        r'\bLAUNCH_DARKLY_MOBILE_KEY\s*=\s*"mob-' + re.escape(uuid) + r'"',
        source, re.IGNORECASE,
    )):
        scoped_fields.add("LAUNCH_DARKLY_MOBILE_KEY")
    # Belico embeds its messaging app ID in a Sendbird API hostname.
    # Restrict this embedded-string case to the audited SDK class and field.
    if ("str3" in known_fields and java_package == "com.belico.simpelapp.utils"
            and re.search(r'\bstr3\s*=\s*"https://api-' + re.escape(uuid)
                          + r'\.sendbird\.com/v3/users/', source, re.IGNORECASE)):
        scoped_fields.add("str3")
    for line in source.splitlines():
        assigned = set(_assigned_fields_for_uuid_on_line(line, uuid))
        temp_fields.update(assigned)
        scoped_fields.update(assigned & known_fields)
    # UUID arrays keep the semantic field name on the array declaration, not
    # on each UUID.fromString assignment. Resolve those elements only for an
    # explicitly scoped non-GATT field such as Kisi's beacon Region list.
    for array_match in UUID_ARRAY_ASSIGNMENT_RE.finditer(source):
        array_name, array_body = array_match.groups()
        if array_name not in known_fields:
            continue
        if any(
            normalize_uuid("-".join(match.groups())) == uuid
            for match in UUID128_LITERAL_RE.finditer(array_body)
        ):
            scoped_fields.add(array_name)
    if temp_fields:
        for match in ALIAS_PROPAGATION_RE.finditer(source):
            target, source_field = match.groups()
            if target in known_fields and source_field in temp_fields:
                scoped_fields.add(target)
    return scoped_fields


def _is_non_gatt_field_hint(field: str, java_package: str | None, source: str) -> bool:
    """Match a confirmed non-GATT identifier in its semantic scope."""
    if NON_GATT_FIELD_HINT_RE.search(field):
        return True
    return field in _matching_non_gatt_class_field_names(java_package, source)


# ---------------------------------------------------------------------------
# Package → company mapping
# ---------------------------------------------------------------------------

# Hard-coded mapping of well-known second-level package components to the
# company that publishes them. Add to this as new vendors come up. Keys are
# lowercased package components (i.e. `abbott` in `com.abbott.lingo.wellness`).
KNOWN_VENDOR_PACKAGES: dict[str, str] = {
    "abbott": "Abbott",
    "adam": "Adam Health Limited",
    "amazon": "Amazon",
    "amazfit": "Zepp Health (Amazfit)",
    "apple": "Apple",
    "aristonthermo": "Ariston Thermo Group",
    "asus": "ASUS",
    "atmotech": "ATMOTECH",
    "audi": "Audi",
    "beats": "Beats Electronics",
    "bmw": "BMW",
    "bose": "Bose",
    "casio": "Casio",
    "dexcom": "Dexcom",
    "aexgroup": "AEX Group",          # via Play Store scrape 2026-05.
    "bsks": "xidsystem",              # com.bsks.bsks_abookn published by Korean dev "xidsystem"; via Play Store 2026-05.
    "cardapp": "CardApp.hk",          # via Play Store 2026-05.
    "clubassist": "DHC Specialty Corporation",  # com.clubassist.syncplus — DHC brand "Clubassist"; via Play Store 2026-05.
    "digifit": "Virtuagym Professional",  # digifit.android.virtuagym.* — Virtuagym's pro product line; via Play Store 2026-05.
    "mobitti": "Mobitti",             # com.mobitti.shaanan — via Play Store 2026-05.
    "proyecto": "Intelinova Software",  # com.proyecto.* — Intelinova's white-label fitness apps; via Play Store 2026-05.
    "sterilor": "ASPOOL",             # com.sterilor.app — via Play Store 2026-05.
    "techlife": "qh-tek",             # techlife.qh.com.techlifepro — via Play Store 2026-05.
    "facebook": "Meta Platforms",
    "ford": "Ford Motor Company",  # com.ford.fordpass — confirmed via web search 2026-05.
    "gannett": "USA TODAY Co.",       # com.gannett.local.* — Gannett's main Play Store publisher.
    "hidglobal": "HID Global",        # com.hidglobal.mobilekeys.* — via Play Store 2026-05.
    "hme": "Tsung Ping Lin",          # com.hme.hmeaquamaster_tmc — individual dev per Play Store 2026-05.
    "qgiv": "Qgiv, Inc.",             # com.qgiv.androidvt — via Play Store 2026-05.
    "segware": "Segware",             # br.com.segware.mysecurity.mxmsei — via Play Store 2026-05.
    # Via Phase-2 enrichment, folders 0031..0035 (2026-05):
    "conneqtech": "Conneqtech",                                                        # com.conneqtech.lovens — IoT connectivity for vehicles.
    "ufro": "Ufro",                                                                    # com.ufro.colorboard.
    "zwo": "Suzhou ZWO Co., Ltd.",                                                     # com.zwo.seestar — astronomy telescope/camera.
    # Via Phase-2 enrichment, folders 0026..0030 (2026-05):
    "alivecor": "AliveCor Inc.",                                                       # com.alivecor.aliveecg.clinical — KardiaMobile portable ECG.
    "dnm": "Harman International (HEOS multi-room audio; Denon/Marantz brands)",       # com.dnm.heos.phone — HEOS app (Denon/Marantz brands).
    "flitsmeister": "Flitsmeister",                                                    # nl.flitsmeister — Dutch driving-community app with BLE OBD support.
    "noke": "Nokē Inc (Bluetooth padlock; com.noke.publicstorage is the white-labeled Public Storage variant)",  # com.noke.* — Janus Nokē smart locks.
    "pqi": "Power Quotient International (PQI)",                                       # com.pqi.* — Taiwanese storage / IoT vendor.
    "smartvest": "SmartVest (Australian baby/elder monitor)",                          # com.smartvest.* — Goldilocks BLE wearable monitor.
    "softguard": "SoftGuard Technologies LLC",                                         # com.softguard.Android.* — Argentine alarm-monitoring SaaS.
    "sunkare": "Teranovo Tech",                                                        # com.sunkare.app.android.heater — Sunkare BLE heater.
    # Via Phase-2 enrichment, folders 0022..0025 (2026-05):
    "awox": "AwoX",                                                                    # com.awox.homecontrol — French smart-lighting/IoT vendor.
    "bird": "Blue Jay Transit Inc.",                                                   # co.bird.android — Bird scooters; acquired by Blue Jay Transit 2024.
    "byle": "nikey",                                                                   # com.byle.BTlink — generic Chinese BLE-module manufacturer app.
    "espressif": "Espressif",                                                          # com.espressif.provble — ESP32 BLE provisioning sample.
    "tech_bit_data": "tech_bit_data",                                                  # com.tech_bit_data.msreasyconnect — publisher really is named tech_bit_data on Play Store.
    "titan": "Titan Company Limited",                                                  # com.titan.reflexwav — Indian watchmaker.
    # Via Phase-2 enrichment, folders 0018..0021 (2026-05):
    "lge": "LG Electronics, Inc.",                                                     # com.lge.media.lgsoundbar — LG soundbar app.
    "spaceos": "SpaceOS (acquired by Equiem) — workplace experience / smart-building white-label platform",  # io.spaceos.* — workplace platform.
    # Via Phase-2 enrichment, folders 0014..0017 (2026-05):
    "fitphilia": "FITPHILIA SOLUTIONS PRIVATE LIMITED (FitWay white-label gym/fitness studio platform)",  # com.fitphilia.fitway.* — Indian gym management platform.
    "htbeyond": "HT Beyond Co., Ltd",                                                  # com.htbeyond.bybeyond.
    "moko": "MOKO Technology Ltd",                                                     # com.moko.mkscannerpro — Chinese BLE module vendor.
    "xfinity": "Comcast",                                                              # com.xfinity.digitalhome.
    # Via Phase-2 enrichment, folders 0010..0013 (2026-05):
    "icomon": "ICOMON",                                                                # com.icomon.starfit.starfit — smart-scale brand.
    "motorolasolutions": "Motorola Solutions",                                         # com.motorolasolutions.accessorymanager.
    "mynextbase": "Nextbase UK",                                                       # com.mynextbase.connect — dashcam connectivity.
    "readinsite": "Alosant",                                                           # com.readinsite.serenbe — Alosant builds residential community apps.
    "webmobi": "WebMobi (event-app white-label platform)",                             # com.webmobi.* — events/conferences platform.
    # Via Phase-2 enrichment, folders 0008+0009 (2026-05):
    "chipsea": "Shenzhen Careyou Health Science and Technology Co",                    # com.chipsea.btcontrol.en — Careyou smart-scale chips from Chipsea.
    "chipsguide": "Anker Innovations Limited (Roav SmartCharge FM transmitter)",       # com.chipsguide.app.roav.fmplayer — Anker Roav car-charger/FM app.
    "coachcare": "Selladore Inc.",                                                     # com.coachcare.mhjgoalsweightloss — Selladore-published CoachCare-platform app.
    "simplisafe": "SimpliSafe Home Security Systems",                                  # com.simplisafe.mobile.
    "universia": "Universia España",                                                   # net.universia.uspceu.
    "weco": "WeCo Batteries",                                                          # com.weco.bluetooth — WeCo lithium battery monitor.
    # Via Phase-2 enrichment, folders 0006+0007 (2026-05):
    "aitmed": "AiTmed",                                                                # com.aitmed.care — telemedicine.
    "belwith": "PDQ Manufacturing (a Belwith Products brand)",                         # com.belwith.pdqsmart — PDQ SecuRemote locks.
    "eventsrcsengland": "The Royal College of Surgeons of England",                    # com.EventsRCSEngland — RCS England events container app.
    "grameenphone": "Grameenphone Limited",                                            # com.grameenphone.alo — Bangladesh telco.
    "intellimec": "Trak Global Solutions Holdings (Canada) Inc.",                      # com.intellimec.telematics.pts — DriveSync connected-car app.
    "noise": "Nexxbase Marketing Private Limited",                                     # com.noise.sphere — NoiseFit fitness band.
    "publicansmanhasset": "Virtuagym B.V. (white-label fitness app platform)",         # branded.com.publicansmanhasset — Virtuagym version pattern + shared UUIDs with digifit.android.virtuagym.pro.*.
    "signify": "Signify Netherlands B.V.",                                             # com.signify.masterconnect — formerly Philips Lighting.
    "allegion": "Allegion plc (Ireland; Pure Access mobile-credentials BLE access-control system — manufacturer/MFR variant of Pure Access app)",
    "alterco": "Allterco Robotics (Bulgaria; MyKi Care BLE smart-thermometer / MyKi child-wearable tracker family — IoT and wearable tech vendor)",
    "aromega": "GLO Science Inc. (US; GLO Whitening app pairs via Bluetooth with GLO teeth-whitening devices — Smileware Technology)",
    "beeline": "Beeline Ltd. (UK — Beeline Velo 2 cycling navigation device + Beeline Moto II motorcycle GPS; Bluetooth-paired smart compass)",
    "bestofbees": "Best of Bees (custom-restaurant ordering-app developer; Hungry Hobo sandwich-chain mobile-ordering app — Bluetooth used for in-store beacons)",
    "abb": "ABB (Swiss-Swedish industrial automation) — Electronic Line Manager (ELM) app; BLE for ABB switchgear / circuit-breaker commissioning",
    "advantech": "Advantech Co., Ltd. (Taiwan; industrial IoT / digital signage) — EPD WiFi Connect BLE provisioning for electronic-paper displays",
    "afrogleap": "AfroGleap (Dutch agency) — MyEneco app for Eneco utility (Netherlands); BLE for smart-thermostat/energy-meter pairing",
    "alipay": "Ant Group (China) — Alipay HK wallet; BLE for proximity-based payment (Alipay Touch)",
    "anc": "ANC (Aonicare Aonicard ANC9100 BLE device; cn.anc.aonicardv white-label go-sure variant)",
    "anjos": "Anjos Ventilation (France; residential mechanical-ventilation systems; BLE control for VMC units)",
    "antheroiot": "AntHero IoT (Chinese BLE module vendor; generic OTA firmware-update app for whitelabel devices)",
    "asaelectronics": "ASA Electronics (US; marine/RV electronics — Jensen / Voyager / iN-Command brands; NCS-50 BLE smart-system app)",
    "asb": "ASB Bank (New Zealand) — ASB Mobile banking app; BLE used for FastNet Classic Token / branch wayfinding",
    "bbq": "BBQ Guru (US BBQ smoker temperature controllers; BLE pit-controller companion app)",
    "bluetees": "Bluetees (Korean motorcycle helmet Bluetooth intercom vendor; companion app for setup/firmware)",
    "bobwen": "Bobwen (Chinese white-label developer; Blue Battery BLE monitor)",
    "broadlink": "Broadlink (Chinese smart-home gateway/IR-blaster vendor; BLE for device-onboarding to WiFi)",
    "bryte": "Bryte (US; AI smart mattress for sleep tracking; BLE for sensor pairing with iOS/Android)",
    "birota": "Birota (Italian smart-cycling platform; Levelo BLE companion app for bike commute analytics)",
    "blastmotion": "Blast Motion Inc. (US; Blast Baseball BLE swing-tracking sensor for bat/club)",
    "blue": "Blue Social (US social-discovery beacon network; BLE for proximity-based contact exchange)",
    "bushnell": "Bushnell Outdoor Products (US) — Bushnell Golf laser rangefinders / GPS watches BLE companion app",
    "canon": "Canon Inc. (Japan) — Camera Connect app; BLE / Wi-Fi pairing for EOS / PowerShot cameras (remote shooting, transfer, geotag)",
    "cbd": "China Banking Corporation (Filipino bank) — CBD Mobile banking; BLE-paired NFC card readers for in-branch wayfinding",
    "cchip": "Cchip (Chinese white-label BLE chip vendor; UZao IoT companion)",
    "bydemes": "ByDemes (Spain; SmartHomeSec security app — uses Climax Technology BRPD panic-button SDK; com.climax.fourSecure)",
    "falconelectronics": "Falcon Electronics (Romania; reseller of Omega LINKR-MBT vehicle telematics BLE module — Excalibur / CrimeStopper remote-start systems)",
    "constellationlabs": "Constellation Labs LLC (US — Bi-Tapp anxiety-relief patented BLE bilateral-tapping device for nervous system calming)",
    "controlcompany": "Control Company (US scientific instruments — TraceableLIVE® WiFi/Bluetooth datalogging thermometers for labs/clinics; CDC/CAP/CLIA/ISO compliance)",
    "controlpointllp": "ControlPoint LLP (US; BlueBox BLE telematics for fleet vehicles)",
    "dciedge": "DCI Edge (US; dental-equipment manufacturer; DCI Edge Diagnostic Tool BLE app for Series 5 dental chairs — status, log history, real-time telemetry)",
    "dhc": "DHC (Taiwan; BTW350-WW BLE bathroom-scale / body-composition analyzer)",
    "dialog": "Dialog Axiata (Sri Lankan telecom) — Dialog SmartHome; BLE for smart-home device pairing",
    "dth": "DTH Group (Greenwich Bay Club / private membership BLE access app)",
    "dynamiccontrols": "Dynamic Controls (New Zealand) — DX-System power-wheelchair control electronics; MyLink BLE app for diagnostics/setup",
    "dewmobile": "DewMobile / Kuaiya (Chinese P2P file-transfer app; uses Bluetooth and Wi-Fi Direct for cross-device sharing)",
    "dorf21": "Dor Technologies Inc. (US; Dor BLE foot-traffic counter sensor — Dor Connect app is for sensor WiFi/BLE configuration)",
    "emplate": "Emplate (Italy; tourist-experience platform; Aalborg Denmark BLE wayfinding beacons)",
    "endel": "Endel Sound GmbH (Berlin; personalized soundscape generator; BLE-paired wearable for biometric input)",
    "engage": "Engage Technologies (Argentina; Cospacio VMS visitor-management for corporate buildings; BLE for badge / turnstile interaction)",
    "evn2go": "EVN Bulgaria (Bulgarian electricity utility; EVN2Go app — BLE for smart-meter pairing)",
    "fujifilm": "FUJIFILM Corporation (Japan) — XApp companion for X-series mirrorless cameras; BLE pairing & remote",
    "eybond": "Eybond Inc. (Chinese solar-monitoring vendor; SmartValue BLE app for solar-inverter pairing)",
    "epson": "Seiko Epson Corporation — SD-10 Spectrophotometer BLE color-measurement device (Pantone color matching) and other BLE-enabled Epson products",
    "eumhana": "Eumhana (Korean medical / brain stimulation device vendor; Hero BLE-controlled tDCS / TMS device)",
    "evechargers": "EVE Chargers (UK; charging-point installer/operator; CP app for BLE-based EV charger setup/diagnostics)",
    "eyeque": "EyeQue Corp. (US; Visual Acuity smartphone vision-testing via BLE add-on)",
    "fairphone": "Fairphone B.V. (Dutch sustainable-electronics manufacturer; Fairbuds true-wireless BLE earbuds companion app)",
    "fanlight": "FanLight Co., Ltd. (Seoul, South Korea) — wireless LED fanlight devices for K-pop concerts; PEB Light Stick BLE app",
    "fender": "Fender Musical Instruments — Fender Tone app; BLE for Mustang amplifier / Acoustic SFX modeling",
    "fitbark": "FitBark Inc. (US; dog-activity / GPS BLE tracker)",
    "fitmetrix": "Fitmetrix (US; gym/fitness performance-tracking platform — Pound Gym branded; BLE heart-rate monitors)",
    "flightscope": "Flightscope (US; Mevo/Mevo+ golf launch monitor; BLE pairing with phone)",
    "franceveloconnecte": "France Vélo Connecté / Grand Annecy (Vélonecy 60 min e-bike share service in Annecy — uses BLE for bike padlock unlock; Fifteen-built bikes)",
    "fitbit": "Fitbit",
    "gallagher": "Gallagher Group (New Zealand) — Mobile Connect access-control credential app (Bluetooth credentials for Gallagher Command Centre, FIDO Certified)",
    "g_zhang": "G. Zhang (iWFCam developer) — Wi-Fi camera mobile app (com.g_zhang.mywificam) with Bluetooth config support",
    "garagelink": "GarageLink (legacy Bluetooth garage-door opener accessory — pairs to phone via Bluetooth to actuate garage door; product discontinued)",
    "gogoro": "Gogoro Inc. (Taiwan; SmartWheel companion app for Eeyo electric bicycles — Bluetooth pairing)",
    "gregorydaenen": "Gregory Daenen (Belgian independent developer; KLJM Kdrankkaarten — BLE-paired card-payment ordering)",
    "govee": "Govee (Shenzhen Intellirocks Tech) — smart home LED lighting / sensors; Govee Home BLE app",
    "grohe": "GROHE AG (Germany; bath/kitchen fixtures) — Sensor App for Sense water-leak detector / Sense Guard smart-water-shutoff; BLE setup",
    "gamepadspace": "GamePad Space (Chinese mobile-game controller vendor; QX BLE gamepad pairing app)",
    "gullivernet": "GulliverNet (Italian transit/logistics; G-Apps G-Transport for Bluetooth driver-handset pairing)",
    "gyroor": "Gyroor (Chinese self-balancing hoverboard / scooter vendor; Bluetooth speaker + companion app for speed / battery / LED control)",
    "habitap": "Habitap (Singapore; smart-home access automation for residential developers; tablet-based UI with BLE)",
    "hali": "Shenzhen Hali-Power Industrial Co., Ltd. — MiLi Skinmate UV monitoring BLE wearable",
    "hhodata": "HHO Data (Chinese health-data/genetics testing; BLE-paired DNA collection kit reader)",
    "hertzaudiovideo": "Hertz Audio (Italian car-audio amplifier/DSP vendor; SS8 DSP BLE remote-tuning app)",
    "hammerhead": "Hammerhead Navigation Inc. (US) — Karoo cycling computer; companion app for Karoo BLE setup",
    "interstar": "INTERSTAR Automotive Technologies (Austria; PowerPedal Bluetooth throttle controller for cars/EVs/trucks)",
    "huma": "Huma Therapeutics Limited (UK; Huma Virtual remote patient monitoring app — bridges Bluetooth medical devices to clinical care; oncology / immunology / hematology / neurology / rare-disease programs)",
    "ibv": "Asociación Instituto de Biomecánica de Valencia (IBV) (Spain; biomechanical-evaluation lab; NedVEP app for BLE handheld dynamometer hand-strength measurement)",
    "icmcontrols": "ICM Controls (US HVAC controls) — RVP/Climate BLE thermostat & gas-valve diagnostic app",
    "imlabworld": "i-Lab World (Korean medical-training simulator vendor; HeartiSense BLE CPR-training manikin instructor app)",
    "ilunion": "ILUNION (Spain; Destino Accesible app — Bluetooth-beacon-based accessibility wayfinding for tourist destinations)",
    "intesis": "Intesis (HMS Networks subsidiary, Spain) — Intesis AC Cloud / IntesisHome HVAC gateways; Bluetooth used for AC Cloud Control device pairing",
    "intuit": "Intuit Inc. (US) — QuickBooks accounting app; BLE for paired Bluetooth credit-card readers (GoPayment)",
    "invixium": "Invixium Access Inc. (Canada; biometric access-control / time-attendance; Vitals BLE health-screening kiosk)",
    "irisconnect": "IRIS Connect (UK education-technology vendor; DiscoveryKit BLE camera/audio kit for classroom video coaching)",
    "janyun": "Janyun (Chinese smartwatch white-label; JYou BLE wearable companion)",
    "jhkj": "Neakasa (Chinese pet-tech brand of JHKJ; smart pet litter box / pet groomer with BLE companion)",
    "jnf": "JNF (Chinese white-label developer; Bluetooth fingerprint padlock companion app)",
    "jio": "Reliance Jio (India) — JioHome app for managing JioFiber set-top boxes; BLE for in-home device pairing",
    "kestrelinstruments": "Nielsen-Kellerman Co. (US; Kestrel Meters portable weather/ballistic stations; BLE for sensor data export)",
    "kindara": "Kindara (US fertility-tracking app; BLE-paired Wink basal-thermometer)",
    "klipsch": "Klipsch Audio Technologies (US; Klipsch Connect app for Klipsch wireless speakers/earbuds; BLE pairing & EQ)",
    "kyocera": "Kyocera Document Solutions (Japan) — KyoPrint mobile printing app; BLE for printer discovery/setup",
    "lean": "Lean Health (US; pediatric weight-management platform for healthcare providers; BLE-paired Bluetooth scales)",
    "lenovo": "Lenovo Group Ltd. — ThinkShield enterprise security; BLE-based smartphone-as-security-key for ThinkPad / ThinkBook",
    "levstone": "LEVstone (Trusted Elderly Care app — Bluetooth motion/fall sensors for elder monitoring)",
    "lhzl": "Tunze Aquarientechnik GmbH (German aquarium-equipment vendor; 7097 Bluetooth Multicontroller for Turbelle pumps and LEDs; com.lhzl.tunzefit Android app)",
    "linktop": "Xiamen Linktop Technology Co., Ltd. (Chinese telehealth device maker; Linktop 6-in-1 remote BLE health monitor — temp / BP / HR / SpO2 / ECG / glucose)",
    "lipusmart": "Lipusmart (Chinese smart-home BLE module vendor; cycling / fitness / iot devices)",
    "livly": "Livly Inc. (US PropTech; Livly Resident apartment tenant-experience app — BLE for smart access)",
    "maginon": "Maginon (German consumer electronics; Wildlife Camera Pro BLE companion app for trail cameras)",
    "medable": "Medable (US; clinical-trial platform) — AstraZeneca AZD4326 study app; BLE for trial device pairing",
    "medocity": "Medocity (US digital-health) — Cigna-branded remote-patient-monitoring app; BLE-paired medical devices",
    "mirion": "Mirion Technologies (US; radiation detection / dosimetry) — InstaLink BLE for personal dosimeter data sync",
    "mobi": "Nexar Inc. (Israel/US dashcam) — Nexar BLE companion for Beam dashcam pairing & video upload",
    "moqo": "MOQO (German carsharing platform; BLE-based vehicle access for carshare fleets)",
    "monese": "Monese Limited (UK digital bank) — Monese Mobile Banking; BLE used for in-branch beacon-based wayfinding",
    "monitex_ktr": "Monitex Inc. (Korean industrial-radiography vendor; KTR BLE companion for thickness gauges)",
    "move4mobile": "Move4Mobile (Dutch SRM golf-cart fleet-management; BLE for cart telemetry)",
    "myinfinity": "Carrier (HVAC; Infinity Touch wifi/BLE thermostat)",
    "smarttok": "SmartTok (Korean industrial-radio / push-to-talk; BLE handheld device companion)",
    "softel": "Softel (Mexico; CIR Wireless OTA firmware-update BLE app)",
    "softtechnetwork": "SoftTech Network (German automation; PSI Remote control app for Phoenix Contact PSI gateways via BLE)",
    "soundoasis": "Sound Oasis (US; S-6000 white-noise / sleep-therapy device with Bluetooth control)",
    "tcx": "TCX (Slovakia; TopScoreboard BLE timing app for sports tournaments)",
    "tdr3": "TDR3 / HotSchedules (now Fourth, US) — Chick-fil-A workforce app; BLE-based shift check-in beacons",
    "telogis": "Telogis (acquired by Verizon Connect; fleet-routing/dispatch — BLE-paired Bluetooth printers for delivery PoD)",
    "tempdrop": "Tempdrop Ltd. (Israeli femtech) — Tempdrop BLE basal-thermometer wearable for fertility tracking",
    "tenda": "Tenda Technology Co., Ltd. (Chinese networking/CCTV vendor; Tenda Security app — BLE for camera/router setup)",
    "tobit": "Tobit.Software AG (Germany; chayns® lifestyle/access app — uses Bluetooth for Tobit chayns location-based and unlock-sharing services)",
    "traegergrills": "Traeger Pellet Grills (US; WiFire-enabled wood-pellet grills; BLE for initial setup of WiFi credentials)",
    "traxxas": "Traxxas (US RC vehicle manufacturer) — Traxxas Link BLE app for telemetry/tuning of XL-5 / VXL / Spartan / X-Maxx ESC",
    "triologic": "Triologic Marketing (India) — JewelFlow Pro jewelry-store POS; BLE-paired barcode scanner / scale / printer",
    "vernier": "Vernier Science Education (Oregon, US) — STEM education sensors; Vernier Instrumental Analysis app for Go Direct Mini GC, Polarimeter, Cyclic Voltammetry via BLE",
    "vimar": "Vimar S.p.A. (Italian electrical-fittings vendor) — View BLE Pro app for home-automation switches",
    "vulog": "Vulog (French carsharing platform — provides BLE-based vehicle access to Modo carshare in Vancouver and other operators)",
    "waterdrop": "waterdrop GmbH (Austria; LUCY Smart Cap BLE smart-bottle hydration tracker; UV purification + sip measurement)",
    "webappclouds": "WebAppClouds (US salon/barbershop app developer; The Spot Barbershop branded BLE-beacon waiting-room app)",
    "wisa": "WiSA Technologies (US wireless-audio standards body) — WSRV companion for WiSA-Certified surround-sound; BLE for HDMI Wireless eARC adapters",
    "webscorer": "Webscorer (US race-timing app — Bluetooth-paired race-timing equipment)",
    "wooask": "Wooask (Chinese AI translation device vendor; recorder-pen BLE companion app)",
    "garmin": "Garmin",
    "google": "Google",
    "harman": "Harman International",
    "honor": "HONOR",
    "huawei": "Huawei",
    "ikf": "iKF Audio (Chinese audio brand; Bluetooth earphones with EQ/ANC/burn-in via iKF GLearPhone Android app)",
    "inuker": "Cymasol (Chinese device vendor; uses Apache-licensed com.inuker.bluetooth Android-BluetoothKit library by dingjikerbo)",
    "iotsolution": "People Center Inc. (AiDot smart-home product line)",  # com.iotsolution.aidot — confirmed via Play Store 2026-05.
    "jieli": "Zhuhai Jieli Technology Co., Ltd. (Chinese SoC vendor for Bluetooth/WiFi MCUs — chips in MP3 players, BT speakers, dash cams; IPC-Linker app for Jieli WiFi/BLE cameras)",
    "kakao": "Kakao Corp. (South Korea) — Hey Kakao app (com.kakao.i.connect) for KakaoMini smart speaker; Bluetooth used for device pairing in Kakao i ecosystem",
    "ledger": "Ledger",
    "lg": "LG Electronics",
    "logitech": "Logitech",
    "meta": "Meta Platforms",
    "microsoft": "Microsoft",
    "monbuilding": "Witco (formerly MonBuilding)",  # FR PropTech, founded 2016 as MonBuilding, rebranded to Witco in 2021. Confirmed via web search (witco.io, Capterra, LinkedIn) 2026-05.
    "meilancycling": "Shenzhen Meilan Technology Co., Ltd. (China; Navihood / MEILAN GPS bike computer + sensors — BLE 4.0 / ANT+ dual-wireless)",
    "moj": "Mojio Inc. (Connected-car telematics; Motion by Mojio app — works with OBD-II BLE dongles)",
    "namsung": "Namsung Corp (South Korean OEM electronics — Dual Electronics / Axxera / Jensen brands; TMC Monitor app for BSD/TPMS BLE sensors in RV vehicles)",
    "neeuro": "Neeuro Pte Ltd (Singapore brain-computer-interface vendor; Cogo attention-training program — uses SenzeBand 2 BLE EEG headband for ADHD/focus training)",
    "neolab": "NeoLAB Convergence Inc. (Korean smart-pen vendor; Neo Smartpen N2 / Neo Note 2 BLE digital pen with handwriting recognition)",
    "newlift": "NEW LIFT Steuerungsbau GmbH (German elevator-controller vendor; FST-2XT control system + LON Bluetooth Gateway for handheld terminal)",
    "motorola": "Motorola",
    "nekteck": "Nekteck (US accessories) — Clevast BLE shiatsu massager / heating pad companion app",
    "nespresso": "Nestlé Nespresso S.A. (Switzerland) — Nespresso companion app; BLE for Expert/Lattissima/Atelier coffee machine pairing",
    "nest": "Nest (Google)",
    "nianticlabs": "Niantic Labs (US) — Pokémon GO; BLE for Pokémon GO Plus / Pokémon GO Plus+ / Poké Ball Plus auto-spin/catch accessories",
    "nike": "Nike",
    "nikon": "Nikon Corporation — SnapBridge BLE / Wi-Fi camera-to-phone bridge for Nikon mirrorless/DSLR cameras (auto-sync photos, remote shooting)",
    "nintendo": "Nintendo",
    "nixsensor": "Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)",
    "nokia": "Nokia",
    "nordic": "Nordic Semiconductor",
    "nothing": "Nothing Technology Limited (UK) — CMF by Nothing Watch app; BLE pairing for CMF Watch Pro",
    "nordicsemi": "Nordic Semiconductor",
    "oneplus": "OnePlus",
    "parentalapp": "Parental App developer (consumer parental-control / child-monitoring app; uses BLE for child-device monitoring)",
    "pax": "PAX Technology Inc. (Android-based payment terminals — A920/A80/A8700 series with Bluetooth, Wi-Fi, 4G connectivity; com.pax.app is the PAX terminal management app)",
    "payrange": "PayRange Inc. (US; vending/laundromat mobile-pay platform — Bluetooth payment terminal)",
    "petgugu": "Petgugu (Korean pet-care AI vendor; smart litter box with BLE)",
    "philips": "Koninklijke Philips N.V. (Netherlands) — Service Tag app; BLE for warranty/service identification of Philips appliances",
    "oppo": "OPPO",
    "orangetheoryfitness": "Orangetheory Fitness (US franchise fitness brand; BLE-paired OTbeat heart-rate monitors)",
    "oneapp": "Verizon (US telecom) — OneApp launcher for retail-store workforce; BLE for inventory beacons",
    "orcbit": "ORCBIT (Chinese audio/wearable vendor; Oladance BLE open-ear true-wireless earphone — acquired by Anker)",
    "orqafpv": "Orqa (Croatia; FPV racing-drone goggles vendor; BLE companion app for OSD configuration)",
    "otodata": "Otodata Wireless Network Inc. (Canada; propane / fuel-tank IoT monitoring; NeevoTech BLE installer-tool app)",
    "panasonic": "Panasonic Corporation — Image App for LUMIX cameras / HDCam camcorders; BLE setup and remote control",
    "phyla": "Phyla Biotics (US biotechnology / probiotic skincare; BLE companion app — purpose unclear from public sources)",
    "picooc": "PICOOC (Chinese smart-scale / health-device vendor; PICOOC Bluetooth body-fat / weight scales — 19-metric body composition analyzer)",
    "pingwang": "Pingwang (Chinese BLE module vendor — eLink fingerprint padlocks / smart locks)",
    "pocketsuite": "PocketSuite (US; small-business app — Square-like; BLE for chip-card readers)",
    "polar": "Polar Electro",
    "prelectronics": "PR electronics (Denmark; industrial signal-conditioning; BLE for handheld PPS-26 process-signal calibration)",
    "prizmos": "Prizmos (Bulgarian OBD-II diagnostic-tool vendor; Carista BLE-OBD adapter for VW/BMW/Audi)",
    "qpython": "QPython (Chinese Python-IDE on Android; community plugin scans BLE devices via Bluetooth API exposure)",
    "qsmfg": "QualityStation Manufacturing (US; BBQ2 BLE-controlled grill smoker — temperature probes)",
    "ricoh": "Ricoh Company Ltd. (Japan) — Smart Device Connector for Ricoh multifunction printers; BLE for printer discovery/setup",
    "ricoh360": "Ricoh Company Ltd. (Japan) — Ricoh360 360-degree camera app (Theta series); BLE setup",
    "rxdrone": "RX Drone (Chinese RC vendor; BLE-tech remote-control car companion app)",
    "samsung": "Samsung Electronics",
    "scoremedia": "Scoremedia (Netherlands; Dryly bedwetting-alarm BLE wearable for pediatric enuresis training)",
    "sena": "Sena Technologies, Inc. (US/Korea — motorcycle/sports communicator helmets; Sena Neo Industrial app for industrial BLE intercoms)",
    "sennheiser": "Sennheiser",
    "sensortransport": "SensorTransport Inc. (US logistics IoT — ClockWork Delivery / National Delivery / SENATOR Driver / ESTES FM apps with BLE sensor monitoring for shippers / 3PLs / carriers)",
    "sensynehealth": "Sensyne Health Co Limited (UK; DBm-Health diabetes app developed with Chelsea and Westminster Hospital NHS Foundation Trust)",
    "sgtracker": "JLR Gear (Shenzhen, China) — SG Tracker anti-lost BLE device tracker",
    "shopify": "Shopify Inc. (Canada) — Point of Sale; BLE for chip-card readers and barcode-scanners",
    "sjty": "sjty2014 (Chinese developer; family of EMS BLE training-suit apps — MMK Impuls / YDSTRONG / Hintime EMS / EMS MAX for wireless electrical-muscle-stimulation training suits)",
    "snapiot": "snapIoT Inc. (digital clinical-trial app platform; HM-GCG-201 study app for Hanmi Pharmaceutical clinical trial — site/clinician-facing variant)",
    "tacx": "Tacx B.V. (Netherlands; Garmin-owned smart trainer / cycling power device vendor — Tacx Training app uses ANT+ and BLE)",
    "shimano": "Shimano",
    "sony": "Sony",
    "spaceflow": "Spaceflow s.r.o. (Czech tenant-experience platform; CERT Life building-access app — uses BLE for door access)",
    "spectra": "Spectra (Chinese BLE module vendor; BLE Admin Tool for OEM device commissioning)",
    "squareup": "Block Inc. (formerly Square) — Square for Restaurants POS app; BLE for chip-card readers and printer pairing",
    "stryd": "Stryd Inc. (US; Stryd running-power footpod; BLE companion for stride/power data)",
    "sujibfr": "Sujibfr (French BLE module developer; OEM smart-device companion app)",
    "switchmatehome": "Switchmate Home (US smart-switch / wall-plug vendor; BLE for on-the-wall switch retrofit)",
    "suunto": "Suunto",
    "swatchmate": "Swatchmate Pty Ltd (Australia; Cube BLE color-matching device for paint/design)",
    "tesla": "Tesla",
    "tiaa": "TIAA (Teachers Insurance and Annuity Association of America) — TIAA Mobile app; BLE for in-branch beacon-based service queuing",
    "timeteccloud": "TimeTec Cloud (Malaysia; biometric / smart-access platform; IPJH BLE access-control app)",
    "tile": "Tile",
    "tjd": "TJD (Chinese smartwatch / fitness band vendor; S2 BLE-paired wearable)",
    "tntkhang": "SmartWatchCenter",  # Play Store dev account behind com.tntkhang.* (Amazfit watch-face apps), confirmed via web search 2026-05.
    "tplink": "TP-Link",
    "ubiquiti": "Ubiquiti",
    "ubnt": "Ubiquiti Inc. (US) — UNMS / UISP Mobile; BLE for first-boot configuration of Ubiquiti AirMAX / EdgeRouter / UniFi devices",
    "vivo": "vivo",
    "withings": "Withings",
    "wowwee": "WowWee Group Limited (Hong Kong toy/robotics maker; RoboRemoteBlue Android app for BLE-controlled WowWee robotic toys)",
    "xiaomi": "Xiaomi",
    "xim5": "XIM Technologies (Hong Kong) — XIM 5 keyboard-mouse-to-controller converter; BLE companion for Xbox/PlayStation",
    "xkglow": "XKGlow (US automotive LED lighting; XKChrome Bluetooth color-control for car/motorcycle underbody/grille lights)",
    "yale": "Yale",
    "yesoulchina": "Yesoul (Chinese smart spin-bike vendor; BLE for cadence/resistance to phone app)",
    "youku": "Youku (Alibaba subsidiary, China) — Youku International video app with optional BLE-based set-top-box / Chromecast-style pairing",
    "zeiss": "Carl Zeiss AG (Germany) — Zeiss Hunting / Sports Optics; BLE rangefinder/binocular companion app",
    "zeninteractivelabs": "Zen Interactive Labs (Guadalajara, Mexico — creative technology agency; Atom gym-management app suite — Bluetooth used for fitness device integration)",
    # Apps published under tools / multi-vendor SDK namespaces — don't lie
    # by inferring a company from these.
    "android": None,
    "androidx": None,
    "kotlin": None,
}


def package_tokens(package_id: str) -> list[str]:
    """Return the meaningful tokens of a package_id, with the TLD-like first
    component dropped. `com.abbott.lingo.wellness` → ['abbott','lingo','wellness']."""
    parts = package_id.split(".")
    if parts and parts[0] in {"com", "co", "org", "net", "io", "us", "uk", "fr", "de", "cn", "br"}:
        parts = parts[1:]
    return [p.lower() for p in parts if p]


_TLDLIKE_COMPONENTS = {
    # Real TLDs apps commonly use as the leading component.
    "com", "co", "org", "net", "io", "us", "uk", "fr", "de", "cn", "br",
    # Generic Android-package-tree tokens that aren't a vendor name.
    "app", "apps", "android", "mobile", "the",
    # Whitelabel / generic app-platform prefixes seen in real packages.
    "branded", "white", "whitelabel",
}


def company_from_package(package_id: str) -> str:
    """Map an Android package_id (e.g. `com.abbott.lingo.wellness`) to a
    company name based on the hard-coded KNOWN_VENDOR_PACKAGES table or, as
    a last resort, the first-non-TLD-like component (the conventional brand
    position in reverse-DNS Java package naming). This is the *generic*
    fallback path — when an app also advertises a UUID16 in member_uuids.yaml,
    prefer the SIG-official member name via `company_from_member_uuids`."""
    parts = [p for p in package_id.split(".") if p]
    if not parts:
        return "Unknown"
    # First check every component against the hard-coded table.
    for c in (p.lower() for p in parts):
        if c in KNOWN_VENDOR_PACKAGES:
            mapped = KNOWN_VENDOR_PACKAGES[c]
            if mapped is not None:
                return mapped
    # Fallback: first non-TLD-like component with ≥3 chars and not all-digits.
    # `com.abbott.lingo.wellness` → abbott (skip com)
    # `com.proctur.app222423`      → proctur (skip com)
    # `branded.com.publicansmanhasset` → publicansmanhasset (skip branded, com)
    # `co.diaz.srvol`              → diaz (skip co)
    # `digifit.android.virtuagym.pro.forgefit24` → digifit
    for p in parts:
        if p.lower() in _TLDLIKE_COMPONENTS:
            continue
        if p.isdigit() or len(p) < 3:
            continue
        return p.capitalize() + " (inferred from package id)"
    return "Unknown"


# ---------------------------------------------------------------------------
# Known SDK / shared-library UUIDs (Phase-4 curated cache)
# ---------------------------------------------------------------------------

# UUIDs that ship inside a third-party SDK and therefore appear in many
# *unrelated* host apps. The host package_id is NOT the UUID owner — the SDK
# vendor is. This table lets a Phase-1 scan skip the per-package guesswork
# for known cases and attribute the record correctly even when only one host
# app is in the corpus.
#
# Keys are lowercased UUIDs (UUID16 short or full UUID128). Values describe
# the actual UUID owner. Phase-4 (scripts/list_shared_sdk_clusters.py +
# apply_sdk_identification.py) generates additions to this table from new
# cross-app cluster discoveries.
KNOWN_SDK_UUIDS: dict[str, dict[str, str]] = {
    # Kubi telepresence robot — Revolve Robotics, distributed inside the
    # Zoom Android SDK since 2015. Appears in every Android app that bundles
    # Zoom (commonly Indian education / e-learning apps).
    # https://blog.zoom.us/product-announcement-kubi-integrates-with-zoom-on-ios-android/
    "2a001800-2803-2801-2800-1d9ff2d5c442": {
        "company": "Revolve Robotics (Kubi telepresence robot; shipped via Zoom Android SDK)",
        "name": "SERVO_SERVICE",
        "note": "Kubi SDK / Zoom Android SDK bundle",
    },
    "9141": {"company": "Revolve Robotics (Kubi telepresence robot; shipped via Zoom Android SDK)", "name": "REGISTER_WRITE1P", "note": "Kubi SDK / Zoom Android SDK bundle"},
    "9142": {"company": "Revolve Robotics (Kubi telepresence robot; shipped via Zoom Android SDK)", "name": "REGISTER_WRITE2P", "note": "Kubi SDK / Zoom Android SDK bundle"},
    "9145": {"company": "Revolve Robotics (Kubi telepresence robot; shipped via Zoom Android SDK)", "name": "SERVO_HORIZONTAL", "note": "Kubi SDK / Zoom Android SDK bundle"},
    "9146": {"company": "Revolve Robotics (Kubi telepresence robot; shipped via Zoom Android SDK)", "name": "SERVO_VERTICAL",   "note": "Kubi SDK / Zoom Android SDK bundle"},
    "e001": {"company": "Revolve Robotics (Kubi telepresence robot; shipped via Zoom Android SDK)", "name": "KUBI_SERVICE",     "note": "Kubi SDK / Zoom Android SDK bundle"},
    "e101": {"company": "Revolve Robotics (Kubi telepresence robot; shipped via Zoom Android SDK)", "name": "BATTERY",          "note": "Kubi SDK / Zoom Android SDK bundle"},
    "e102": {"company": "Revolve Robotics (Kubi telepresence robot; shipped via Zoom Android SDK)", "name": "SERVO_ERROR",      "note": "Kubi SDK / Zoom Android SDK bundle"},
    "e103": {"company": "Revolve Robotics (Kubi telepresence robot; shipped via Zoom Android SDK)", "name": "SERVO_ERROR_ID",   "note": "Kubi SDK / Zoom Android SDK bundle"},
    "e104": {"company": "Revolve Robotics (Kubi telepresence robot; shipped via Zoom Android SDK)", "name": "LED_COLOR",        "note": "Kubi SDK / Zoom Android SDK bundle"},
    "e105": {"company": "Revolve Robotics (Kubi telepresence robot; shipped via Zoom Android SDK)", "name": "BATTERY_STATUS",   "note": "Kubi SDK / Zoom Android SDK bundle"},
    "e10a": {"company": "Revolve Robotics (Kubi telepresence robot; shipped via Zoom Android SDK)", "name": "BUTTON",           "note": "Kubi SDK / Zoom Android SDK bundle"},

    # Estimote (Poland/USA) — SECURE_UUIDS list, the rotating iBeacon
    # proximity-UUID set used by Estimote beacons in secure (anti-spoofing)
    # mode. These are *advertisement* UUIDs, not GATT services — they appear
    # as the iBeacon ProximityUUID inside the advertisement packet so the
    # Estimote SDK can filter out non-Estimote beacons. The full canonical
    # 16-UUID list is in com.estimote.sdk.internal.utils.EstimoteBeacons.
    # CORRECTION: an earlier Phase-4 pass mis-attributed several of these to
    # "Nordic Legacy DFU" — this was wrong; they belong to Estimote.
    "11600168-0029-fcd0-0d49-0c48c860fee7": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "48601148-0168-0029-fcd0-00217f22d202": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "4e5a3705-abc0-46ef-ba23-7ba0539f77ee": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "52dda4f4-913f-4f62-a1ca-f3868020c87a": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "6aa2ee50-d6dc-4348-ba3e-c9beb15b31e6": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "6b77de6f-9932-4f45-a800-77f80e3c523c": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "701eb593-43bb-4158-ac1c-54d9a09133e0": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "7f8c3c55-b802-4553-b77b-8833288ee744": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "9dc38ad4-3cc8-4665-a775-70c7b6e6e97f": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "b1a9d912-4846-4a6e-91f1-e78b4edf941d": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "b3ce1172-59be-4c8d-83c0-6856738afc92": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "bd29bde2-0f87-4a61-b951-725b78e64e41": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "c2090197-f40d-42e9-96b7-814dc8c55e18": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "d888d8fd-db03-457b-842a-20a6d5e1ee37": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "db960350-17fa-49c5-a9d2-ccd074cb5703": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "e3d159ef-4c85-46a3-bd6f-9a8094781f05": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "ef8286ad-9969-404b-9909-9c2326aecc49": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    "f8ef0630-f18f-4513-9a5d-fd5f3ce5142b": {"company": "Estimote (rotating iBeacon ProximityUUID — anti-spoofing 'SECURE_UUIDS' set)", "name": "ESTIMOTE_SECURE_BEACON_PROXIMITY_UUID", "note": "Estimote SECURE_UUIDS (advertisement-only, not GATT)"},
    # Estimote primary proximity UUIDs (the well-known iBeacon ProximityUUIDs
    # used by every Estimote default-config beacon). These are the only two
    # Estimote UUIDs in plain (non-rotating) mode.
    "b9407f30-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote (default iBeacon ProximityUUID — non-secure / non-rotating)", "name": "ESTIMOTE_DEFAULT_PROXIMITY_UUID",     "note": "Estimote default proximity (Android side)"},
    "8492e75f-4fd6-469d-b132-043fe94921d8": {"company": "Estimote (default iBeacon ProximityUUID — non-secure / non-rotating; iOS variant)", "name": "ESTIMOTE_IOS_PROXIMITY_UUID", "note": "Estimote default proximity (iOS variant)"},
    # Estimote GATT (connectable services) — service<<16 | characteristic encoded in the first segment,
    # canonical namespace -f5f8-466e-aff9-25556b57fe6d. Discovered Phase-4 from com.EventsRCSEngland /
    # com.LLE2023 / com.gogoagenda.main.retail (event-app SDK bundle).
    "b9401000-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_OTA_SERVICE",                    "note": "Estimote Beacon SDK OTA service"},
    "b9401001-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_OTA_COMMAND",                    "note": "Estimote Beacon SDK OTA service"},
    "b9401002-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_OTA_RESPONSE",                   "note": "Estimote Beacon SDK OTA service"},
    "b9401003-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_OTA_DATA",                       "note": "Estimote Beacon SDK OTA service"},
    "b9402000-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_AUTH_SERVICE",                   "note": "Estimote Beacon SDK auth service"},
    "b9402001-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_AUTH_SEED_CHAR",                 "note": "Estimote Beacon SDK auth service"},
    "b9402002-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_AUTH_VECTOR_CHAR",               "note": "Estimote Beacon SDK auth service"},
    "b9403000-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_SERVICE",                        "note": "Estimote Beacon SDK device service"},
    "b9403001-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_MAJOR_CHAR",                     "note": "Estimote Beacon SDK device service"},
    "b9403002-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_MINOR_CHAR",                     "note": "Estimote Beacon SDK device service"},
    "b9403003-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_UUID_NORMAL_CHAR",               "note": "Estimote Beacon SDK device service"},
    "b9403004-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_UUID_MOTION_CHAR",               "note": "Estimote Beacon SDK device service"},
    "b9403011-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_POWER_CHAR",                     "note": "Estimote Beacon SDK device service"},
    "b9403012-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_ADVERTISING_INTERVAL_CHAR",      "note": "Estimote Beacon SDK device service"},
    "b9403021-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_TEMP_CHAR",                      "note": "Estimote Beacon SDK device service"},
    "b9403031-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_ACCELEROMETER_STATE_CHAR",       "note": "Estimote Beacon SDK device service"},
    "b9403032-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_ACCELEROMETER_COUNTER_CHAR",     "note": "Estimote Beacon SDK device service"},
    "b9403041-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_BATTERY_CHAR",                   "note": "Estimote Beacon SDK device service"},
    "b9403051-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_SERVICE_CONFIGURATION_CHAR",     "note": "Estimote Beacon SDK device service"},
    "b9403061-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_REAL_ID",                        "note": "Estimote Beacon SDK device service"},
    "b9403071-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_EDDYSTONE_UID_NAMESPACE_CHAR",   "note": "Estimote Beacon SDK Eddystone config"},
    "b9403072-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_EDDYSTONE_UID_INSTANCE_CHAR",    "note": "Estimote Beacon SDK Eddystone config"},
    "b9403073-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_EDDYSTONE_URL_CHAR",             "note": "Estimote Beacon SDK Eddystone config"},
    "b9404000-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_VERSION_SERVICE",                "note": "Estimote Beacon SDK version service"},
    "b9404001-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_SOFTWARE_VERSION_CHAR",          "note": "Estimote Beacon SDK version service"},
    "b9404002-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_HARDWARE_VERSION_CHAR",          "note": "Estimote Beacon SDK version service"},
    "b9406000-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_CLOUD_AUTH_SERVICE",             "note": "Estimote Beacon SDK cloud-auth service"},
    "b9406001-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_CLOUD_AUTH_LEVEL_CHAR",          "note": "Estimote Beacon SDK cloud-auth service"},
    "b9406002-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_CLOUD_AUTH_CHALLENGE_CHAR",      "note": "Estimote Beacon SDK cloud-auth service"},
    "b9406003-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_CLOUD_AUTH_VECTOR_CHANGE_CHAR",  "note": "Estimote Beacon SDK cloud-auth service"},
    # ASSA ABLOY Seos / Mobile Keys SDK. UUID base ends in `-00177a000000`,
    # which embeds ASSA ABLOY's IEEE OUI 00:17:7A. Discovered Phase-4 from
    # com.hidglobal.mobilekeys.android.v3 (HID Global, part of ASSA ABLOY) /
    # com.informationapps.criton.belAirTremblant (Tremblant ski resort) /
    # sesame.smartspaces.d2i.co (Sesame mobile credentials, ASSA ABLOY Hospitality).
    "00009800-0000-1000-8000-00177a000000": {"company": "ASSA ABLOY AB (Seos / Mobile Keys SDK; IEEE OUI 00:17:7A is registered to ASSA ABLOY)", "name": "ASSAABLOY_LOCK_SERVICE_UUID_BASE",         "note": "ASSA ABLOY Seos / Mobile Keys SDK"},
    "0000aa00-0000-1000-8000-00177a000000": {"company": "ASSA ABLOY AB (Seos / Mobile Keys SDK; IEEE OUI 00:17:7A is registered to ASSA ABLOY)", "name": "ASSAABLOY_LOCK_CHARACTERISTIC_UUID_BASE",  "note": "ASSA ABLOY Seos / Mobile Keys SDK"},
    # Sony PlayMemories / Alpha BLE camera control — discovered Phase-5 via
    # com.sony.playmemories.mobile decompile (BluetoothGattUtil.findService).
    "8000cc00-cc00-ffff-ffff-ffffffffffff": {"company": "Sony Corporation (PlayMemories Mobile / Alpha BLE camera control)", "name": "SONY_CAMERA_CONTROL_SERVICE",  "note": "Sony PlayMemories camera-command service"},
    "8000dd00-dd00-ffff-ffff-ffffffffffff": {"company": "Sony Corporation (PlayMemories Mobile / Alpha BLE camera control)", "name": "SONY_CAMERA_LOCATION_SERVICE", "note": "Sony PlayMemories camera-geolocation service"},
    "8000ee00-ee00-ffff-ffff-ffffffffffff": {"company": "Sony Corporation (PlayMemories Mobile / Alpha BLE camera control)", "name": "SONY_CAMERA_PAIRING_SERVICE",  "note": "Sony PlayMemories camera-pairing service"},
    # Skidata MobileFlow's 12 FG/FM iBeacon ProximityUUIDs are removed from
    # this value-only table. LocalizationBeaconServiceImpl's inline Region
    # occurrences are filtered at their source spans below; equal UUIDs in
    # independent GATT calls remain eligible. Keep the three GATT service
    # variants below in the global SDK cache.
    "21523cc0-8504-e17a-8bad-ed14b483d139": {"company": "Skidata GmbH (MobileFlow ski-pass / access-control beacons)", "name": "SKIDATA_GATT_BEACON_SERVICE_B", "note": "Skidata MobileFlow GATT-beacon service variant"},
    "a1523cc0-8504-e17a-8bad-ed14b483d139": {"company": "Skidata GmbH (MobileFlow ski-pass / access-control beacons)", "name": "SKIDATA_GATT_BEACON_SERVICE_A", "note": "Skidata MobileFlow GATT-beacon service variant"},
    "c1523cc0-8504-e17a-8bad-ed14b483d139": {"company": "Skidata GmbH (MobileFlow ski-pass / access-control beacons)", "name": "SKIDATA_GATT_BEACON_SERVICE_C", "note": "Skidata MobileFlow GATT-beacon service variant"},
    # ETI thermalib (UK BLE thermometer SDK) — discovered Phase-5 via
    # com.saavi6.pod.royal decompile of uk.co.etiltd.thermalib.{g,h,BLEProtocolDelegate}.
    # UUID base ASCII decodes to "ETIBLUETHERM" + b87ad7XX vendor suffix.
    "45544942-4c55-4554-4845-524db87ad700": {"company": "Electronic Temperature Instruments Ltd (ETI) — thermalib BLE thermometer SDK", "name": "ETI_PRIVATE_SERVICE",              "note": "ETI thermalib private service"},
    "45544942-4c55-4554-4845-524db87ad701": {"company": "Electronic Temperature Instruments Ltd (ETI) — thermalib BLE thermometer SDK", "name": "ETI_SENSOR_1_READING_CHAR",        "note": "ETI thermalib Sensor 1 Reading"},
    "45544942-4c55-4554-4845-524db87ad703": {"company": "Electronic Temperature Instruments Ltd (ETI) — thermalib BLE thermometer SDK", "name": "ETI_SENSOR_2_READING_CHAR",        "note": "ETI thermalib Sensor 2 Reading"},
    "45544942-4c55-4554-4845-524db87ad705": {"company": "Electronic Temperature Instruments Ltd (ETI) — thermalib BLE thermometer SDK", "name": "ETI_COMMANDS_AND_NOTIFICATIONS_CHAR", "note": "ETI thermalib Commands+Notifications"},
    "45544942-4c55-4554-4845-524db87ad707": {"company": "Electronic Temperature Instruments Ltd (ETI) — thermalib BLE thermometer SDK", "name": "ETI_SENSOR_1_USER_SETTINGS_CHAR",  "note": "ETI thermalib Sensor 1 User Settings"},
    "45544942-4c55-4554-4845-524db87ad708": {"company": "Electronic Temperature Instruments Ltd (ETI) — thermalib BLE thermometer SDK", "name": "ETI_SENSOR_2_USER_SETTINGS_CHAR",  "note": "ETI thermalib Sensor 2 User Settings"},
    "45544942-4c55-4554-4845-524db87ad709": {"company": "Electronic Temperature Instruments Ltd (ETI) — thermalib BLE thermometer SDK", "name": "ETI_INSTRUMENT_SETTINGS_CHAR",     "note": "ETI thermalib Instrument Settings"},
    "45544942-4c55-4554-4845-524db87ad70a": {"company": "Electronic Temperature Instruments Ltd (ETI) — thermalib BLE thermometer SDK", "name": "ETI_TRIM_SETTINGS_CHAR",           "note": "ETI thermalib TrimSettings"},
    # Techtronic Industries (TTI) — ECHO / Ryobi generator BLE SDK
    # (com.ttigroup.generatorble). Discovered Phase-5 via com.echousa.echocommand
    # decompile of PreciseDeviceType.kt + BleCommandSenderGCE340.kt.
    # Prefix `4743` = ASCII 'GC' (Generator Command).
    "0000ff01-2018-0101-8010-78805f1b35fb": {"company": "Techtronic Industries / ECHO (TTI generatorble Android SDK)", "name": "TTI_GEN_PRECISE_DEVICE_TYPE_FF01", "note": "TTI generator device-type discriminator"},
    "0000ff02-2018-0101-8010-78805f1b35fb": {"company": "Techtronic Industries / ECHO (TTI generatorble Android SDK)", "name": "TTI_GEN_PRECISE_DEVICE_TYPE_FF02", "note": "TTI generator device-type discriminator"},
    "0000ff03-2018-0101-8010-78805f1b35fb": {"company": "Techtronic Industries / ECHO (TTI generatorble Android SDK)", "name": "TTI_GEN_PRECISE_DEVICE_TYPE_FF03", "note": "TTI generator device-type discriminator"},
    "0000ff04-2018-0101-8010-78805f1b35fb": {"company": "Techtronic Industries / ECHO (TTI generatorble Android SDK)", "name": "TTI_GEN_PRECISE_DEVICE_TYPE_FF04", "note": "TTI generator device-type discriminator"},
    "4743ff02-2018-0101-8010-78805f1b35fb": {"company": "Techtronic Industries / ECHO (TTI generatorble Android SDK)", "name": "TTI_GEN_TELEMETRY_NOTIFY_CHAR_1", "note": "TTI generator telemetry notify char 1"},
    "4743ff03-2018-0101-8010-78805f1b35fb": {"company": "Techtronic Industries / ECHO (TTI generatorble Android SDK)", "name": "TTI_GEN_TELEMETRY_NOTIFY_CHAR_2", "note": "TTI generator telemetry notify char 2"},
    # LoopKey (Brazilian smart-lock vendor; lklib Android SDK). Discovered
    # Phase-5 via com.informationapps.criton.belAirTremblant decompile of
    # br.com.loopkey.indigo.lklib.{LKBLEServices,LKBLECharacteristics}.
    "01ba": {"company": "LoopKey (Brazilian smart-lock manufacturer; lklib Android SDK)", "name": "LOOPKEY_LOOP_SERVICE",              "note": "LoopKey lklib LOOP_SERVICE"},
    "01bc": {"company": "LoopKey (Brazilian smart-lock manufacturer; lklib Android SDK)", "name": "LOOPKEY_ROLL_COUNT_CHARACTERISTIC", "note": "LoopKey lklib ROLL_COUNT_CHARACTERISTIC"},
    # Estimote packet/nearables — Phase-4 cluster c0 from folders 0008+0009
    # (com.EventsRCSEngland, com.LLE2023, com.OEUKDecarbConf2023). The 6c371xxx
    # set sits in the Nordic chip namespace (Estimote layers their own packet
    # service over Nordic's stack); b940500X is in the canonical Estimote namespace.
    "6c371000-d2cc-11e4-9a1f-0002a5d5c51b": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_PACKET_SERVICE",            "note": "Estimote Beacon SDK packet service"},
    "6c371001-d2cc-11e4-9a1f-0002a5d5c51b": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_PACKET_WRITE_CHAR",         "note": "Estimote Beacon SDK packet service"},
    "6c371002-d2cc-11e4-9a1f-0002a5d5c51b": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_PACKET_READ_CHAR",          "note": "Estimote Beacon SDK packet service"},
    "b9405000-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_NEARABLES_GENERIC_SERVICE", "note": "Estimote Beacon SDK Nearables service"},
    "b9405001-f5f8-466e-aff9-25556b57fe6d": {"company": "Estimote Inc. (Estimote Beacon SDK)", "name": "ESTIMOTE_NEARABLES_READ_WRITE_CHAR", "note": "Estimote Beacon SDK Nearables service"},
    # Qingniu Yolanda smart-scale SDK — Phase-4 cluster c1 from folders 0008+0009.
    # Reused across CoachCare/Selladore, Virtuagym Pro, Proyecto Intelinova, WeCo, etc.
    # UUID16s ffe2/ffe3 are HM-10 / TI-SimpleProfile defaults that Qingniu layered on top of.
    "abf2": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_HEIGHTSCALE_NOTIFY",  "note": "Qingniu height-scale notify char"},
    # ffe2/ffe3 also occur in the unrelated Pingwang AILink SDK. Do not
    # attribute these collision-prone UUID16s by value alone.
    # Qingniu extensions — Phase-4 cluster c0 from folders 0010..0013.
    # OTA service (8018/802X), Medisans / CP30A height-scale (78b2, 8a20-22, 8a81-83),
    # native height-scale (abf0/abf1), extra WSP chars (ffa4, ffe4, ffe5).
    "78b2": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_CP30A_HEIGHT_SCALE_SERVICE", "note": "Qingniu CP30A height-scale service"},
    "8018": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_OTA_SERVICE",                "note": "Qingniu OTA service"},
    "8020": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_OTA_CHAR1",                  "note": "Qingniu OTA service"},
    "8021": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_OTA_CHAR2",                  "note": "Qingniu OTA service"},
    "8022": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_OTA_CHAR3",                  "note": "Qingniu OTA service"},
    "8023": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_OTA_CHAR4",                  "note": "Qingniu OTA service"},
    "8a20": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_MEDISANS_CHAR_8A20",         "note": "Qingniu Medisans"},
    "8a21": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_MEDISANS_CHAR_8A21",         "note": "Qingniu Medisans"},
    "8a22": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_MEDISANS_CHAR_8A22",         "note": "Qingniu Medisans"},
    "8a81": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_MEDISANS_CHAR_8A81",         "note": "Qingniu Medisans"},
    "8a82": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_CP30A_HEIGHT_SCALE_READ",    "note": "Qingniu CP30A height-scale read"},
    "8a83": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_CP30A_HEIGHT_SCALE_WRITE",   "note": "Qingniu CP30A height-scale write"},
    "abf0": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_HEIGHT_SCALE_SERVICE",       "note": "Qingniu native height-scale service"},
    "abf1": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_HEIGHTSCALE_WRITE",          "note": "Qingniu native height-scale write"},
    # ffa4 is also used by BBPOS; retain source-specific names and ownership.
    "ffe4": {"company": "Qingniu Technology Co., Ltd. (Shanghai) — Yolanda smart-scale BLE SDK", "name": "QINGNIU_WSP_AUX_CHAR4",              "note": "Qingniu WSP aux char"},
    # ffe5 also appears as an unrelated Feican service, so is not unique to Qingniu.
    # Microchip ISSC variants — Phase-4 cluster c1 from folders 0010..0013.
    # LERD (Low-Energy Remote Device) variant + VP3320 example.
    "01fffec6-ba5e-f4ee-5ca1-eb1e5e4b1ce0": {"company": "Microchip / ISSC (Transparent UART proprietary service variants; RN4871 / IS18xx / IS19xx BLE modules)", "name": "ISSC_LERD_READ_CHAR",            "note": "Microchip ISSC LERD variant"},
    "01fffec8-ba5e-f4ee-5ca1-eb1e5e4b1ce0": {"company": "Microchip / ISSC (Transparent UART proprietary service variants; RN4871 / IS18xx / IS19xx BLE modules)", "name": "ISSC_LERD_WRITE_CHAR",           "note": "Microchip ISSC LERD variant"},
    "01fffee7-ba5e-f4ee-5ca1-eb1e5e4b1ce0": {"company": "Microchip / ISSC (Transparent UART proprietary service variants; RN4871 / IS18xx / IS19xx BLE modules)", "name": "ISSC_LERD_PROPRIETARY_SERVICE",  "note": "Microchip ISSC LERD variant"},
    "49535343-6daa-4d02-abf6-19569aca69fe": {"company": "Microchip Technology Inc.", "name": "ISSC_UPDATE_CONNECTION_PARAMETER", "note": "ISSC Update Connection Parameter characteristic; Microchip IS1678S application note and RN4678 documentation"},
    # Allegion ENGAGE BLE credential platform (shipped via Brivo Android SDK) —
    # Phase-4 cluster c2 from folders 0010..0013. 6 unrelated hosts (Nexudus
    # spaces, Rise CommaProperties, Sharry SWP).
    "52052c11-e701-4782-99f5-8ce88dbb1500": {"company": "Allegion plc (ENGAGE BLE credential platform; shipped via Brivo Android SDK com.brivo.sdk.ble — used in Schlage / LCN smart locks and Brivo-managed properties)", "name": "ALLEGION_BLE_CREDENTIAL_SERVICE", "note": "Allegion ENGAGE / Brivo SDK"},
    # Amazon AWS IoT 1-Click Button BLE setup SDK — Phase-5 from
    # com.amazonaws.oneclick (declared in obfuscated s0/a.java; imports
    # com.amazonaws.iotbutton.util.AwsLog).
    "06a720a0-a460-11e5-8d37-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_06A720A0", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "08feb2e0-4ad4-11e5-ac6a-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_08FEB2E0", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "11af6e20-4ad4-11e5-b150-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_11AF6E20", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "1223d920-6944-11e5-b3f7-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_1223D920", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "139e9449-0730-40cc-ad41-4d332bd13994": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_139E9449", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "1ac97280-4ad4-11e5-80a1-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_1AC97280", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "201df714-46e6-4170-b1dd-810caacd0b54": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_201DF714", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "23dd5c60-4ad4-11e5-a107-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_23DD5C60", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "2ae6dc80-05ae-11e6-9f92-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_2AE6DC80", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "2d4cd3c0-4ad4-11e5-b921-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_2D4CD3C0", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "31d84500-42e1-11e5-882e-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_31D84500", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "329725eb-ca0c-4bf4-8dca-98536b66cf3c": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_329725EB", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "34796c40-05ae-11e6-ac02-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_34796C40", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "3bff2ca6-31a6-4aeb-9d11-26f10b911e6e": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_3BFF2CA6", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "3f994680-4ad4-11e5-aad3-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_3F994680", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "47bda040-4ad4-11e5-99bb-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_47BDA040", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "59567ee0-0b0d-11e6-b7cc-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_59567EE0", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "608ccf20-0b0d-11e6-a9d1-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_608CCF20", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "6ab1baa0-05b9-11e6-9de4-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_6AB1BAA0", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "6c5da720-4ad3-11e5-a50d-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_6C5DA720", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "6e597760-42e1-11e5-ab57-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_6E597760", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "790777c0-05b9-11e6-b047-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_790777C0", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "7f84e14d-586a-4cd8-8b47-3144f25a2e92": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_7F84E14D", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "81e72700-4ad4-11e5-a108-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_81E72700", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "8306bd80-42e1-11e5-afd6-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_8306BD80", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "84936260-ec92-11e5-8613-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_84936260", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "85150f00-6a3c-11e5-bf8c-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_85150F00", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "8909a120-4ad4-11e5-a356-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_8909A120", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "8f12d880-4ad3-11e5-ba7f-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_8F12D880", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "92788880-05ae-11e6-86c5-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_92788880", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "943a57a0-ec92-11e5-8e2c-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_943A57A0", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "a04d2280-4ad4-11e5-a444-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_A04D2280", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "a3d26e20-4ad3-11e5-9212-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_A3D26E20", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "a567a2e0-05b9-11e6-9840-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_A567A2E0", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "ace7dea0-4ad3-11e5-bb2c-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_ACE7DEA0", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "b12af8e0-a45f-11e5-bff4-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_B12AF8E0", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "b5385220-05b7-11e6-bbfc-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_B5385220", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "b98ee580-6a3c-11e5-8e85-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_B98EE580", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "c060ea80-4ad3-11e5-9e26-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_C060EA80", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "c57ec5e9-262e-46e9-b251-8f7097a68f19": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_C57EC5E9", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "c8a9e340-4ad3-11e5-b9e6-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_C8A9E340", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "cf5651b5-e83f-42aa-a3e0-519b9bbdf1c5": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_CF5651B5", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "d2aa5000-4ad3-11e5-a0a1-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_D2AA5000", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "d68e08a0-05b9-11e6-8635-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_D68E08A0", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "dc0d9260-4ad3-11e5-a885-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_DC0D9260", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "dfe4a607-cd3e-4559-a5e0-0b537d697d61": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_DFE4A607", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "e4dfdf60-4ad3-11e5-9d83-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_E4DFDF60", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "e64da5c0-59b1-11e5-9138-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_E64DA5C0", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "ee9a1b60-4ad3-11e5-8f19-0002a5d5c51b": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_EE9A1B60", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "f1f06bf3-eb80-46c6-8d02-7bb93e67d8c9": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_F1F06BF3", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    "faf93c51-2d61-4ba3-9748-1acebf9e784d": {"company": "Amazon Web Services (AWS IoT 1-Click button BLE setup; com.amazonaws.iotbutton SDK)", "name": "AWS_IOT_BUTTON_UUID_FAF93C51", "note": "Amazon AWS IoT 1-Click Button BLE setup SDK"},
    # Polar Electro (com.polar.androidcommunications) — Phase-5 from PhlexSwim.
    # H7 = heart-rate H7 sensor; PFC = Polar Pedal Force; PMD = Polar Measurement
    # Data; PSFTP = Polar Storage File Transfer Protocol.
    "6217ff49-ac7b-547e-eecf-016a06970ba9": {"company": "Polar Electro (heart-rate / fitness sensor BLE protocol; com.polar.androidcommunications SDK)", "name": "POLAR_H7_SETTINGS_CHAR_FF49", "note": "Polar Electro Android communications SDK"},
    "6217ff4a-b07d-5deb-261e-2586752d942e": {"company": "Polar Electro (heart-rate / fitness sensor BLE protocol; com.polar.androidcommunications SDK)", "name": "POLAR_H7_SETTINGS_CHAR_FF4A", "note": "Polar Electro Android communications SDK"},
    "6217ff4b-fb31-1140-ad5a-a45545d7ecf3": {"company": "Polar Electro (heart-rate / fitness sensor BLE protocol; com.polar.androidcommunications SDK)", "name": "POLAR_PFC_CHAR_FF4B", "note": "Polar Electro Android communications SDK"},
    "6217ff4c-c8ec-b1fb-1380-3ad986708e2d": {"company": "Polar Electro (heart-rate / fitness sensor BLE protocol; com.polar.androidcommunications SDK)", "name": "POLAR_PFC_CHAR_FF4C", "note": "Polar Electro Android communications SDK"},
    "6217ff4d-91bb-91d0-7e2a-7cd3bda8a1f3": {"company": "Polar Electro (heart-rate / fitness sensor BLE protocol; com.polar.androidcommunications SDK)", "name": "POLAR_PFC_CHAR_FF4D", "note": "Polar Electro Android communications SDK"},
    "fb005c20-02e7-f387-1cad-8acd2d8df0c8": {"company": "Polar Electro (heart-rate / fitness sensor BLE protocol; com.polar.androidcommunications SDK)", "name": "POLAR_PMD_CHAR_FB20", "note": "Polar Electro Android communications SDK"},
    "fb005c21-02e7-f387-1cad-8acd2d8df0c8": {"company": "Polar Electro (heart-rate / fitness sensor BLE protocol; com.polar.androidcommunications SDK)", "name": "POLAR_PMD_CHAR_FB21", "note": "Polar Electro Android communications SDK"},
    "fb005c22-02e7-f387-1cad-8acd2d8df0c8": {"company": "Polar Electro (heart-rate / fitness sensor BLE protocol; com.polar.androidcommunications SDK)", "name": "POLAR_PMD_CHAR_FB22", "note": "Polar Electro Android communications SDK"},
    "fb005c26-02e7-f387-1cad-8acd2d8df0c8": {"company": "Polar Electro (heart-rate / fitness sensor BLE protocol; com.polar.androidcommunications SDK)", "name": "POLAR_PMD_CHAR_FB26", "note": "Polar Electro Android communications SDK"},
    "fb005c51-02e7-f387-1cad-8acd2d8df0c8": {"company": "Polar Electro (heart-rate / fitness sensor BLE protocol; com.polar.androidcommunications SDK)", "name": "POLAR_PSFTP_CHAR_FB51", "note": "Polar Electro Android communications SDK"},
    "fb005c52-02e7-f387-1cad-8acd2d8df0c8": {"company": "Polar Electro (heart-rate / fitness sensor BLE protocol; com.polar.androidcommunications SDK)", "name": "POLAR_PSFTP_CHAR_FB52", "note": "Polar Electro Android communications SDK"},
    "fb005c53-02e7-f387-1cad-8acd2d8df0c8": {"company": "Polar Electro (heart-rate / fitness sensor BLE protocol; com.polar.androidcommunications SDK)", "name": "POLAR_PSFTP_CHAR_FB53", "note": "Polar Electro Android communications SDK"},
    # MOKO Technology BLE module SDK — Phase-5 from com.moko.mkscannerpro.
    # Note `aa00` doubles as service (SERVICE_CUSTOM) and char (CHAR_PASSWORD).
    "aa00": {"company": "MOKO Technology Ltd (Chinese BLE module vendor; com.moko.support.* SDKs for mkscannerpro / mk107dpro35d / mkgw3 / remotegw)", "name": "MOKO_SERVICE_CUSTOM", "note": "MOKO BLE module SDK"},
    "aa01": {"company": "MOKO Technology Ltd (Chinese BLE module vendor; com.moko.support.* SDKs for mkscannerpro / mk107dpro35d / mkgw3 / remotegw)", "name": "MOKO_CHAR_DISCONNECTED_NOTIFY", "note": "MOKO BLE module SDK"},
    "aa03": {"company": "MOKO Technology Ltd (Chinese BLE module vendor; com.moko.support.* SDKs for mkscannerpro / mk107dpro35d / mkgw3 / remotegw)", "name": "MOKO_CHAR_PARAMS", "note": "MOKO BLE module SDK"},
    "aa0b": {"company": "MOKO Technology Ltd (Chinese BLE module vendor; com.moko.support.* SDKs for mkscannerpro / mk107dpro35d / mkgw3 / remotegw)", "name": "MOKO_SERVICE_ADV", "note": "MOKO BLE module SDK"},
    "aa0e": {"company": "MOKO Technology Ltd (Chinese BLE module vendor; com.moko.support.* SDKs for mkscannerpro / mk107dpro35d / mkgw3 / remotegw)", "name": "MOKO_CHAR_AA0E", "note": "MOKO BLE module SDK"},
    "aa0f": {"company": "MOKO Technology Ltd (Chinese BLE module vendor; com.moko.support.* SDKs for mkscannerpro / mk107dpro35d / mkgw3 / remotegw)", "name": "MOKO_SERVICE_AA0F", "note": "MOKO BLE module SDK"},
    # Networkr Click2Connect event-attendee proximity SDK — Phase-5 from
    # events.grip.dseshow / com.networkr.external.click2connect.ConnectSDK.
    # ConnectSDK.java declares 0001 as BT_GATT_SERVICE_UUID; GATT discovery
    # looks up the RX and TX characteristics (0002 and 0003) on that service.
    "66060001-c4d7-4c29-8f6b-60da20052147": {"company": "Networkr (event-networking platform; com.networkr.external.click2connect.ConnectSDK)", "name": "NETWORKR_CONNECT_SDK_SERVICE", "note": "Networkr Click2Connect SDK"},
    "66060002-c4d7-4c29-8f6b-60da20052147": {"company": "Networkr (event-networking platform; com.networkr.external.click2connect.ConnectSDK)", "name": "NETWORKR_CONNECT_SDK_RX_CHARACTERISTIC", "note": "Networkr Click2Connect SDK"},
    "66060003-c4d7-4c29-8f6b-60da20052147": {"company": "Networkr (event-networking platform; com.networkr.external.click2connect.ConnectSDK)", "name": "NETWORKR_CONNECT_SDK_TX_CHARACTERISTIC", "note": "Networkr Click2Connect SDK"},
    # Chileaf fitness sensor SDK — Phase-5 from FitWay / com.android.chileaf.fitness.FitnessManager.
    "aae28f00-71b5-42a1-8c3c-f9cf6ac969d0": {"company": "Chileaf (Chinese fitness/cardio device vendor; com.android.chileaf.fitness Android SDK)", "name": "CHILEAF_FITNESS_SERVICE", "note": "Chileaf fitness sensor SDK"},
    "aae28f01-71b5-42a1-8c3c-f9cf6ac969d0": {"company": "Chileaf (Chinese fitness/cardio device vendor; com.android.chileaf.fitness Android SDK)", "name": "CHILEAF_FITNESS_CHAR_01", "note": "Chileaf fitness sensor SDK"},
    "aae28f02-71b5-42a1-8c3c-f9cf6ac969d0": {"company": "Chileaf (Chinese fitness/cardio device vendor; com.android.chileaf.fitness Android SDK)", "name": "CHILEAF_FITNESS_CHAR_02", "note": "Chileaf fitness sensor SDK"},
    # Arduino BLE library default example UUIDs — common in DIY BLE devices.
    "19b10000-e8f2-537e-4f6c-d104768a1214": {"company": "Arduino BLE example / Arduino IDE default (commonly seen in DIY Arduino-based BLE devices)", "name": "ARDUINO_BLE_DEFAULT_SERVICE", "note": "Arduino BLE example UUIDs"},
    "19b10001-e8f2-537e-4f6c-d104768a1214": {"company": "Arduino BLE example / Arduino IDE default (commonly seen in DIY Arduino-based BLE devices)", "name": "ARDUINO_BLE_DEFAULT_CHAR", "note": "Arduino BLE example UUIDs"},
    # Wavelynx Technologies (US access-control reader vendor) — Phase-4 c3 from
    # folders 0022..0025. Shipped via Brivo SDK alongside Allegion ENGAGE.
    "3420d81a-af2c-11e5-bf7f-feff819cdc9f": {"company": "Wavelynx Technologies (US commercial access-control reader vendor; BLE credential service shipped via Brivo Android SDK com.brivo.sdk.ble)", "name": "WAVELYNX_BLE_CREDENTIAL_SERVICE", "note": "Wavelynx via Brivo SDK"},
    # Tuya Smart BLE config SDK — Phase-4 c2 from folders 0031..0035.
    # UUID base ASCII decodes to "tuyabl-config".
    "00000001-0000-1001-8001-00805f9b07d0": {"company": "Tuya Smart (Hangzhou) — BLE configuration SDK (com.thingclips.sdk.bluetooth Android SDK)", "name": "TUYA_BLE_CHAR_00000001",     "note": "Tuya BLE config"},
    "00000002-0000-1001-8001-00805f9b07d0": {"company": "Tuya Smart (Hangzhou) — BLE configuration SDK (com.thingclips.sdk.bluetooth Android SDK)", "name": "TUYA_BLE_CHAR_00000002",     "note": "Tuya BLE config"},
    "00001000-7475-7961-626c-636f6e666967": {"company": "Tuya Smart (Hangzhou) — BLE configuration SDK (com.thingclips.sdk.bluetooth Android SDK)", "name": "TUYA_BLE_CONFIG_SERVER",     "note": "Tuya BLE config"},
    "00001001-7475-7961-626c-636f6e666967": {"company": "Tuya Smart (Hangzhou) — BLE configuration SDK (com.thingclips.sdk.bluetooth Android SDK)", "name": "TUYA_BLE_CONFIG_WRITE",      "note": "Tuya BLE config"},
    "00001002-7475-7961-626c-636f6e666967": {"company": "Tuya Smart (Hangzhou) — BLE configuration SDK (com.thingclips.sdk.bluetooth Android SDK)", "name": "TUYA_BLE_CONFIG_NOTIFY",     "note": "Tuya BLE config"},
    "1910": {"company": "Tuya Smart (Hangzhou) — BLE configuration SDK (com.thingclips.sdk.bluetooth Android SDK)", "name": "TUYA_BLE_UUID16_1910", "note": "Tuya BLE"},
    "1912": {"company": "Tuya Smart (Hangzhou) — BLE configuration SDK (com.thingclips.sdk.bluetooth Android SDK)", "name": "TUYA_BLE_UUID16_1912", "note": "Tuya BLE"},
    "1920": {"company": "Tuya Smart (Hangzhou) — BLE configuration SDK (com.thingclips.sdk.bluetooth Android SDK)", "name": "TUYA_BLE_UUID16_1920", "note": "Tuya BLE"},
    "7fdd": {"company": "Telink Semiconductor (BLE chip vendor; mesh-test characteristic seen alongside Tuya SDK)",   "name": "TELINK_MESH_TEST_CHAR",  "note": "Telink chip mesh test"},
    # Brother P-touch / MFC printer SDK — Phase-4 c4 from folders 0031..0035.
    "a76eb9e0-f3ac-4990-84cf-3a94d2426b2b": {"company": "Brother Industries Ltd. (P-touch / MFC printer SDK; com.brother.ptouch.sdk.connectio* Android SDK)", "name": "BROTHER_PRINTER_TARGET_SERVICE", "note": "Brother printer SDK"},
    "a76eb9e1-f3ac-4990-84cf-3a94d2426b2b": {"company": "Brother Industries Ltd. (P-touch / MFC printer SDK; com.brother.ptouch.sdk.connectio* Android SDK)", "name": "BROTHER_PRINTER_READ_CHAR",      "note": "Brother printer SDK"},
    "a76eb9e2-f3ac-4990-84cf-3a94d2426b2b": {"company": "Brother Industries Ltd. (P-touch / MFC printer SDK; com.brother.ptouch.sdk.connectio* Android SDK)", "name": "BROTHER_PRINTER_WRITE_CHAR",     "note": "Brother printer SDK"},
    # Consmart / qh-tek BLE smart-home — Phase-4 c5 from folders 0031..0035.
    "ffd0": {"company": "Consmart / qh-tek (Chinese smart-home BLE module vendor)", "name": "CONSMART_BLE_NOTIFICATION_SERVICE_DATA",         "note": "Consmart smart-home"},
    "ffd4": {"company": "Consmart / qh-tek (Chinese smart-home BLE module vendor)", "name": "CONSMART_BLE_NOTIFICATION_CHARACTERISTICS_DATA", "note": "Consmart smart-home"},
    "ffd5": {"company": "Consmart / qh-tek (Chinese smart-home BLE module vendor)", "name": "CONSMART_BLE_WRITE_SERVICE_DATA",                "note": "Consmart smart-home"},
    # Flic Smart Button (Shortcut Labs, Sweden) — Phase-4 c3 from folders
    # 0026..0030. Used by 7 alarm-monitoring apps as panic-button accessory.
    "00420000-8f59-4420-870d-84f3b617e493": {"company": "Flic AB (Shortcut Labs, Sweden) — Flic Smart Button BLE service", "name": "FLIC_SERVICE",  "note": "Flic Smart Button"},
    "00420001-8f59-4420-870d-84f3b617e493": {"company": "Flic AB (Shortcut Labs, Sweden) — Flic Smart Button BLE service", "name": "FLIC_TX_CHAR", "note": "Flic Smart Button"},
    "00420002-8f59-4420-870d-84f3b617e493": {"company": "Flic AB (Shortcut Labs, Sweden) — Flic Smart Button BLE service", "name": "FLIC_RX_CHAR", "note": "Flic Smart Button"},
    # Yongse Heater / GeneralPowerControl / ProductInformation SDK — Phase-5 from
    # com.sunkare.app.android.heater (com.yongse.android.ble.service.* enum).
    "00008d01-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_HEATER_FEATURE_STATE_CHAR",            "note": "Yongse heater"},
    "00008d02-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_HEATER_POWER_CHAR",                    "note": "Yongse heater"},
    "00008d03-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_HEATER_COUNTDOWN_CHAR",                "note": "Yongse heater"},
    "00008d04-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_HEATER_RANDOM_PASSWORD_CHAR",          "note": "Yongse heater"},
    "00008d05-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_HEATER_RANDOM_PASSWORD_VALID_TIME_CHAR","note": "Yongse heater"},
    "00008d06-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_HEATER_ADMIN_PASSWORD_CHAR",           "note": "Yongse heater"},
    "00008d07-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_HEATER_SUPER_PASSWORD_CHAR",           "note": "Yongse heater"},
    "00008d08-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_HEATER_TEMPERATURE_CHAR",              "note": "Yongse heater"},
    "00008d0a-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_HEATER_DEVICE_NAME_CHAR",              "note": "Yongse heater"},
    "00008d10-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_HEATER_SWING_CHAR",                    "note": "Yongse heater"},
    "00008e0a-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_GENERAL_POWER_NOTIFICATION_CHAR",      "note": "Yongse general power"},
    "00008e0c-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_GENERAL_POWER_WORK_MODE_CHAR",         "note": "Yongse general power"},
    "00009f01-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_PRODUCT_FEATURE_STATE_CHAR",           "note": "Yongse product info"},
    "00009f02-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_PRODUCT_RANDOM_PASSWORD_CHAR",         "note": "Yongse product info"},
    "00009f03-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_PRODUCT_RANDOM_PASSWORD_VALID_TIME_CHAR","note": "Yongse product info"},
    "00009f04-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_PRODUCT_ADMIN_PASSWORD_CHAR",          "note": "Yongse product info"},
    "00009f05-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_PRODUCT_SUPER_PASSWORD_CHAR",          "note": "Yongse product info"},
    "00009f06-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_PRODUCT_DEVICE_NAME_CHAR",             "note": "Yongse product info"},
    "00009f07-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_PRODUCT_PRODUCTION_DATE_CHAR",         "note": "Yongse product info"},
    "00009f08-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_PRODUCT_FACTORY_COMMAND_CHAR",         "note": "Yongse product info"},
    "00009f09-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_PRODUCT_UP_TIME_CHAR",                 "note": "Yongse product info"},
    "f000ccc2-0451-4000-b000-000000000000": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_CONNECTION_CONTROL_REQUEST_CHAR",      "note": "Yongse connection control"},
    "0001e102-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_BASE_CHAR_E102",                      "note": "Yongse base profile"},
    "0001e103-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_BASE_CHAR_E103",                      "note": "Yongse base profile"},
    "0001e104-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_BASE_CHAR_E104",                      "note": "Yongse base profile"},
    "0001e105-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_BASE_CHAR_E105",                      "note": "Yongse base profile"},
    "0001e106-a37d-e411-bedb-50ed7800a5a5": {"company": "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK)", "name": "YONGSE_BASE_CHAR_E106",                      "note": "Yongse base profile"},
    # Harman HEOS multi-room audio BLE setup — Phase-5 from com.dnm.heos.phone.
    "00000001-62d1-11e7-8270-0005cd4610c1": {"company": "Harman International (HEOS multi-room audio; Denon/Marantz brands)", "name": "HEOS_BLE_SETUP_CHAR_01", "note": "HEOS BLE setup wizard"},
    "00000005-62d1-11e7-8270-0005cd4610c1": {"company": "Harman International (HEOS multi-room audio; Denon/Marantz brands)", "name": "HEOS_BLE_SETUP_CHAR_05", "note": "HEOS BLE setup wizard"},
    "00000006-62d1-11e7-8270-0005cd4610c1": {"company": "Harman International (HEOS multi-room audio; Denon/Marantz brands)", "name": "HEOS_BLE_SETUP_CHAR_06", "note": "HEOS BLE setup wizard"},
    "00000007-62d1-11e7-8270-0005cd4610c1": {"company": "Harman International (HEOS multi-room audio; Denon/Marantz brands)", "name": "HEOS_BLE_SETUP_CHAR_07", "note": "HEOS BLE setup wizard"},
    # SmartVest Goldilocks BLE wearable monitor — Phase-5 from com.smartvest.goldilocks.
    "43530b19-ef9f-4ed6-bf44-474a92b1de32": {"company": "SmartVest (Australian baby/elder monitor — Goldilocks BLE wearable)", "name": "SMARTVEST_GOLDILOCKS_CHAR_43530B19", "note": "SmartVest Goldilocks"},
    "43b59fd1-91d5-4b0e-932b-72dfb13ee1e7": {"company": "SmartVest (Australian baby/elder monitor — Goldilocks BLE wearable)", "name": "SMARTVEST_GOLDILOCKS_CHAR_43B59FD1", "note": "SmartVest Goldilocks"},
    "4d7d4ea7-4f5d-4584-a256-e9b0549f3d38": {"company": "SmartVest (Australian baby/elder monitor — Goldilocks BLE wearable)", "name": "SMARTVEST_GOLDILOCKS_CHAR_4D7D4EA7", "note": "SmartVest Goldilocks"},
    "854ed786-e054-410f-aea2-610c948f85c0": {"company": "SmartVest (Australian baby/elder monitor — Goldilocks BLE wearable)", "name": "SMARTVEST_GOLDILOCKS_CHAR_854ED786", "note": "SmartVest Goldilocks"},
    "c6f4a776-636f-48d6-97bd-8fc5c06a2e5a": {"company": "SmartVest (Australian baby/elder monitor — Goldilocks BLE wearable)", "name": "SMARTVEST_GOLDILOCKS_CHAR_C6F4A776", "note": "SmartVest Goldilocks"},
    "d9e6a330-1c73-4fdc-a884-c150fc218bb1": {"company": "SmartVest (Australian baby/elder monitor — Goldilocks BLE wearable)", "name": "SMARTVEST_GOLDILOCKS_CHAR_D9E6A330", "note": "SmartVest Goldilocks"},
    # Kontakt.io beacon SDK — Phase-5 from com.greencopper.android.burtonusopen
    # (com.kontakt.sdk.android.ble.spec.KontaktDeviceService enum).
    "a1ea8110-0e1b-d4a1-b840-63f88c8da1ea": {"company": "Kontakt.io (Polish BLE beacon vendor; com.kontakt.sdk.android Android SDK)", "name": "KONTAKT_PROXIMITY_SERVICE",             "note": "Kontakt.io beacon SDK"},
    "a1ea8120-0e1b-d4a1-b840-63f88c8da1ea": {"company": "Kontakt.io (Polish BLE beacon vendor; com.kontakt.sdk.android Android SDK)", "name": "KONTAKT_TIMERS_SERVICE",                "note": "Kontakt.io beacon SDK"},
    "a1ea8130-0e1b-d4a1-b840-63f88c8da1ea": {"company": "Kontakt.io (Polish BLE beacon vendor; com.kontakt.sdk.android Android SDK)", "name": "KONTAKT_CONTROL_SERVICE",               "note": "Kontakt.io beacon SDK"},
    "a1ea81f0-0e1b-d4a1-b840-63f88c8da1ea": {"company": "Kontakt.io (Polish BLE beacon vendor; com.kontakt.sdk.android Android SDK)", "name": "KONTAKT_SECURE_CONFIGURATION_SERVICE",  "note": "Kontakt.io beacon SDK"},
    "a1ea8210-0e1b-d4a1-b840-63f88c8da1ea": {"company": "Kontakt.io (Polish BLE beacon vendor; com.kontakt.sdk.android Android SDK)", "name": "KONTAKT_SENSORS_SERVICE",               "note": "Kontakt.io beacon SDK"},
    # AuthenTrend FIDO2 hardware key — Phase-5 from com.pqi.wallet
    # (com.authentrend.wallet.ATBleDevice). PQI distributes AuthenTrend hardware.
    "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb": {"company": "AuthenTrend Technology Inc. (Taiwanese FIDO2 hardware-key vendor; PQI Wallet partnership)", "name": "AUTHENTREND_FIDO_CHAR_FFF1", "note": "AuthenTrend FIDO2"},
    "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb": {"company": "AuthenTrend Technology Inc. (Taiwanese FIDO2 hardware-key vendor; PQI Wallet partnership)", "name": "AUTHENTREND_FIDO_CHAR_FFF2", "note": "AuthenTrend FIDO2"},
    "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb": {"company": "AuthenTrend Technology Inc. (Taiwanese FIDO2 hardware-key vendor; PQI Wallet partnership)", "name": "AUTHENTREND_FIDO_CHAR_FFF3", "note": "AuthenTrend FIDO2"},
    # Titan Reflexwav HotWatch BLE protocol — Phase-5 from com.titan.reflexwav
    # (com.titan.reflexwav.ble.HotWatchUUID enum).
    "e90a3562-34a4-4aaf-b26a-a1807701a001": {"company": "Titan Company Limited (Indian watchmaker — ReflexWav HotWatch BLE protocol)", "name": "TITAN_HOTWATCH_CALL_CTRL_SERVICE",   "note": "Titan HotWatch enum"},
    "9bd9696f-05b6-46fc-9e76-da95ebd99a5f": {"company": "Titan Company Limited (Indian watchmaker — ReflexWav HotWatch BLE protocol)", "name": "TITAN_HOTWATCH_CALL_INCOMING",       "note": "Titan HotWatch enum"},
    "53d3bcc3-39ee-4fd6-925c-7e342ab2f628": {"company": "Titan Company Limited (Indian watchmaker — ReflexWav HotWatch BLE protocol)", "name": "TITAN_HOTWATCH_CALL_OUTGOING",       "note": "Titan HotWatch enum"},
    "4a02ced0-16ee-45c4-a292-196095dafe07": {"company": "Titan Company Limited (Indian watchmaker — ReflexWav HotWatch BLE protocol)", "name": "TITAN_HOTWATCH_HOT_SPP_SERVICE",     "note": "Titan HotWatch enum"},
    "b4add229-d226-4008-86a2-d211fac43361": {"company": "Titan Company Limited (Indian watchmaker — ReflexWav HotWatch BLE protocol)", "name": "TITAN_HOTWATCH_HOT_SPP_CHAR",        "note": "Titan HotWatch enum"},
    "5f7b1b86-6b4d-4222-a2df-32f564455544": {"company": "Titan Company Limited (Indian watchmaker — ReflexWav HotWatch BLE protocol)", "name": "TITAN_HOTWATCH_HOT_BINARY_SERVICE",  "note": "Titan HotWatch enum"},
    "e344eeb7-3dc6-48b5-a057-f6a023a0f397": {"company": "Titan Company Limited (Indian watchmaker — ReflexWav HotWatch BLE protocol)", "name": "TITAN_HOTWATCH_HOT_BINARY_CHAR",     "note": "Titan HotWatch enum"},
    "765ef9f0-a4a7-4b24-9f12-da2356d219c4": {"company": "Titan Company Limited (Indian watchmaker — ReflexWav HotWatch BLE protocol)", "name": "TITAN_HOTWATCH_HOT_BINARY_HEADER",   "note": "Titan HotWatch enum"},
    "2e9dcb06-14a7-4aa9-9bda-8dba0f43406b": {"company": "Titan Company Limited (Indian watchmaker — ReflexWav HotWatch BLE protocol)", "name": "TITAN_HOTWATCH_HOT_BINARY_END",      "note": "Titan HotWatch enum"},
    "089d950f-8dca-458b-9c87-0a9ed000ffdd": {"company": "Titan Company Limited (Indian watchmaker — ReflexWav HotWatch BLE protocol)", "name": "TITAN_HOTWATCH_HOT_BINARY_SPEED",    "note": "Titan HotWatch enum"},
    "774ae774-5779-4db9-b682-2cbc1caeee9c": {"company": "Titan Company Limited (Indian watchmaker — ReflexWav HotWatch BLE protocol)", "name": "TITAN_HOTWATCH_HOT_CUR_BINARY_SPEED","note": "Titan HotWatch enum"},
    # Bird scooter Smartlock BLE — Phase-5 from co.bird.android (declared in
    # SmartlockManagerImpl + obfuscated defpackage variants).
    "36f5": {"company": "Blue Jay Transit Inc. (formerly Bird Rides) — scooter Smartlock BLE protocol", "name": "BIRD_SMARTLOCK_WRITE_CHAR",  "note": "Bird Smartlock"},
    "36f6": {"company": "Blue Jay Transit Inc. (formerly Bird Rides) — scooter Smartlock BLE protocol", "name": "BIRD_SMARTLOCK_NOTIFY_CHAR", "note": "Bird Smartlock"},
    # Espressif provisioning protocomm — Phase-5 from com.espressif.provble
    # (com.espressif.provisioning.transport.BLETransport).
    "ff52": {"company": "Espressif Systems (Shanghai) — ESP-IDF BLE provisioning (com.espressif.provisioning Android SDK)", "name": "ESPRESSIF_PROVISIONING_PROTOCOMM_CHAR", "note": "Espressif provisioning"},
    # Google Home / Chromecast BLE setup — Phase-5 from com.google.android.apps.chromecast.app
    # (defpackage/{tiw,tin,sgo,tiz}.java; alongside Google's SIG-allocated FE56 scan filter).
    "026dd092-cb00-45b2-8dbb-77d8897f0493": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_026DD092", "note": "Google Home / Chromecast BLE setup"},
    "0a68da69-c87a-4461-a68d-fb0dae115060": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_0A68DA69", "note": "Google Home / Chromecast BLE setup"},
    "22216033-f99b-412b-afca-670fd4bedff5": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_22216033", "note": "Google Home / Chromecast BLE setup"},
    "2dab7a51-4bc8-4349-9624-46f1411fd030": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_2DAB7A51", "note": "Google Home / Chromecast BLE setup"},
    "3c77ac08-464f-49d2-bc3c-ef2baa36db22": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_3C77AC08", "note": "Google Home / Chromecast BLE setup"},
    "3d26de21-5dd5-483e-9faf-fa1cec89a7de": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_3D26DE21", "note": "Google Home / Chromecast BLE setup"},
    "5b20cf8b-0d01-4c32-bf6b-f4fc9ff1dea0": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_5B20CF8B", "note": "Google Home / Chromecast BLE setup"},
    "658648bb-dab5-4d4d-8e1f-0a7e0a180403": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_658648BB", "note": "Google Home / Chromecast BLE setup"},
    "6dc0ec50-8b6a-4e47-bcf6-2c6495d6499b": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_6DC0EC50", "note": "Google Home / Chromecast BLE setup"},
    "6ea5992f-3dee-4481-929a-3dc73efa3c23": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_6EA5992F", "note": "Google Home / Chromecast BLE setup"},
    "70012fc8-1a6e-4fa1-b300-552528906093": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_70012FC8", "note": "Google Home / Chromecast BLE setup"},
    "7452d29f-5b88-4709-8776-6f4509d543b5": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_7452D29F", "note": "Google Home / Chromecast BLE setup"},
    "9ff50b39-76b6-499f-bebf-cc04b0ce8c18": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_9FF50B39", "note": "Google Home / Chromecast BLE setup"},
    "b5257ed2-12cc-4c83-84b8-c10b7ac80ba7": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_B5257ED2", "note": "Google Home / Chromecast BLE setup"},
    "bc596295-eb44-424e-9ee8-d3510863420a": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_BC596295", "note": "Google Home / Chromecast BLE setup"},
    "c3938289-de82-44f8-b11c-3773241502dc": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_C3938289", "note": "Google Home / Chromecast BLE setup"},
    "d3d14f85-133d-4f19-a1c1-a471b2c23826": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_D3D14F85", "note": "Google Home / Chromecast BLE setup"},
    "d89cb60a-cfce-4de5-a534-b021450b59ba": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_D89CB60A", "note": "Google Home / Chromecast BLE setup"},
    "e5b59e5a-774f-49d7-9de0-7504b099ec50": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_E5B59E5A", "note": "Google Home / Chromecast BLE setup"},
    "e64aa4c2-cf37-4fd3-8ec0-d4d6eac6e09e": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_E64AA4C2", "note": "Google Home / Chromecast BLE setup"},
    "f098507f-3ed2-45b5-84f9-824fad00ba40": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_F098507F", "note": "Google Home / Chromecast BLE setup"},
    "f0c3b13f-6aed-46ea-beaa-0c7a11b1f02d": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_F0C3B13F", "note": "Google Home / Chromecast BLE setup"},
    "f1cacd13-1fed-4a9d-87b7-fb4cfc526f3b": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_F1CACD13", "note": "Google Home / Chromecast BLE setup"},
    "f7aa99ff-7d27-4624-8ca7-c5b2760caa80": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_F7AA99FF", "note": "Google Home / Chromecast BLE setup"},
    "ff0c3832-19b0-447f-b444-9e20ca1254c9": {"company": "Google LLC (Google Home / Chromecast BLE setup)", "name": "GOOGLE_HOME_BLE_SETUP_UUID_FF0C3832", "note": "Google Home / Chromecast BLE setup"},
    # Android Studio BLE example template defaults — Phase-4 c2 from folders
    # 0022..0025. NOT a real vendor — these are the placeholder UUIDs from the
    # Android Studio BLE service-creation template that developers ship without
    # changing. Observed across multiple Korean abookn-template apps.
    "12345678-9012-3456-7890-123456789012": {"company": "Android Studio BLE example template (default placeholder UUIDs that developers commonly forget to replace before shipping)", "name": "ANDROID_STUDIO_BLE_TEMPLATE_SERVICE", "note": "Android Studio BLE template default"},
    "12345678-9012-3456-7890-123456789013": {"company": "Android Studio BLE example template (default placeholder UUIDs that developers commonly forget to replace before shipping)", "name": "ANDROID_STUDIO_BLE_TEMPLATE_CHAR",    "note": "Android Studio BLE template default"},
    # Leedarson body-fat scale subfamily — Phase-4 c1 from folders 0014..0017.
    "ffb0": {"company": "Leedarson IoT Technology (Wifi+BLE pairing/OTA SDK; com.leedarson.serviceimpl / com.leedarson.sender Android SDK)", "name": "LEEDARSON_BODYFAT_SERVICE",     "note": "Leedarson body-fat scale service"},
    "ffb1": {"company": "Leedarson IoT Technology (Wifi+BLE pairing/OTA SDK; com.leedarson.serviceimpl / com.leedarson.sender Android SDK)", "name": "LEEDARSON_BODYFAT_WRITE_CHAR",  "note": "Leedarson body-fat scale write"},
    "ffb2": {"company": "Leedarson IoT Technology (Wifi+BLE pairing/OTA SDK; com.leedarson.serviceimpl / com.leedarson.sender Android SDK)", "name": "LEEDARSON_BODYFAT_NOTIFY_CHAR", "note": "Leedarson body-fat scale notify"},
    # Suprema Inc. (Korean access-control vendor) — Phase-5 from Sharry SWP
    # (import com.supremainc.android.libsupremaac.SupremaAc).
    # AE00 is intentionally absent from this value-only table: Jieli uses it
    # as a GATT service too. Suprema attribution is package-scoped above.
    "ae1a": {"company": "Suprema Inc. (Korean biometric / access-control vendor; com.supremainc.android.libsupremaac SDK)", "name": "SUPREMA_AC_CHAR_AE1A", "note": "Suprema AC characteristic"},
    "ae1b": {"company": "Suprema Inc. (Korean biometric / access-control vendor; com.supremainc.android.libsupremaac SDK)", "name": "SUPREMA_AC_CHAR_AE1B", "note": "Suprema AC characteristic"},
    # Sharry SWP (Czech employee experience / smart-building platform) —
    # Phase-5 from eu.sharry.swp.green167. af00/afaa is Sharry's own service+char;
    # the remaining 11 UUIDs are scan-filter-only entries for the multi-vendor
    # access-control devices Sharry integrates with (Suprema covered above; the
    # rest are unattributed scan-list members).
    "af00": {"company": "Sharry s.r.o. (Sharry SWP workplace platform)",                                                                       "name": "SHARRY_SWP_PRIMARY_SERVICE",      "note": "Sharry SWP primary service"},
    "afaa": {"company": "Sharry s.r.o. (Sharry SWP workplace platform)",                                                                       "name": "SHARRY_SWP_PRIMARY_CHAR",         "note": "Sharry SWP primary characteristic"},
    "af0b": {"company": "Sharry s.r.o. (Sharry SWP workplace platform — multi-vendor BLE access-control scan filter)",                          "name": "SHARRY_SWP_SCAN_FILTER_AF0B",     "note": "Sharry SWP scan-only UUID"},
    "af1a": {"company": "Sharry s.r.o. (Sharry SWP workplace platform — multi-vendor BLE access-control scan filter)",                          "name": "SHARRY_SWP_SCAN_FILTER_AF1A",     "note": "Sharry SWP scan-only UUID"},
    "af1b": {"company": "Sharry s.r.o. (Sharry SWP workplace platform — multi-vendor BLE access-control scan filter)",                          "name": "SHARRY_SWP_SCAN_FILTER_AF1B",     "note": "Sharry SWP scan-only UUID"},
    "afbb": {"company": "Sharry s.r.o. (Sharry SWP workplace platform — multi-vendor BLE access-control scan filter)",                          "name": "SHARRY_SWP_SCAN_FILTER_AFBB",     "note": "Sharry SWP scan-only UUID"},
    "a001": {"company": "Sharry s.r.o. (Sharry SWP workplace platform — multi-vendor BLE access-control scan filter)",                          "name": "SHARRY_SWP_SCAN_FILTER_A001",     "note": "Sharry SWP scan-only UUID"},
    "a003": {"company": "Sharry s.r.o. (Sharry SWP workplace platform — multi-vendor BLE access-control scan filter)",                          "name": "SHARRY_SWP_SCAN_FILTER_A003",     "note": "Sharry SWP scan-only UUID"},
    "a004": {"company": "Sharry s.r.o. (Sharry SWP workplace platform — multi-vendor BLE access-control scan filter)",                          "name": "SHARRY_SWP_SCAN_FILTER_A004",     "note": "Sharry SWP scan-only UUID"},
    "4c88": {"company": "Sharry s.r.o. (Sharry SWP workplace platform — multi-vendor BLE access-control scan filter)",                          "name": "SHARRY_SWP_SCAN_FILTER_4C88",     "note": "Sharry SWP scan-only UUID"},
    "cafe": {"company": "Sharry s.r.o. (Sharry SWP workplace platform — multi-vendor BLE access-control scan filter)",                          "name": "SHARRY_SWP_SCAN_FILTER_CAFE",     "note": "Sharry SWP scan-only UUID"},
    "fffe": {"company": "Sharry s.r.o. (Sharry SWP workplace platform — multi-vendor BLE access-control scan filter)",                          "name": "SHARRY_SWP_SCAN_FILTER_FFFE",     "note": "Sharry SWP scan-only UUID"},
    # Minew Technology (Chinese BLE beacon vendor) — Phase-5 from Blappsta /
    # Jahns & Müller (com.minew.device.a.a).
    "eee1": {"company": "Minew Technology (Chinese BLE beacon / IoT module manufacturer)", "name": "MINEW_DEVICE_SERVICE_EEE1", "note": "Minew beacon SDK service; used with BluetoothGatt.getService(...)"},
    "eee2": {"company": "Minew Technology (Chinese BLE beacon / IoT module manufacturer)", "name": "MINEW_DEVICE_CHAR_EEE2", "note": "Minew beacon SDK characteristic"},
    "eee3": {"company": "Minew Technology (Chinese BLE beacon / IoT module manufacturer)", "name": "MINEW_DEVICE_CHAR_EEE3", "note": "Minew beacon SDK characteristic"},
    "eee5": {"company": "Minew Technology (Chinese BLE beacon / IoT module manufacturer)", "name": "MINEW_DEVICE_CHAR_EEE5", "note": "Minew beacon SDK characteristic"},
    # WebMobi attendee-proximity advertisement (NOT a GATT service) — Phase-5
    # from com.webmobi.annualclinicalproffessionalsconference.
    "00000000-e19a-4fb1-9706-de71d7e28e9b": {"company": "WebMobi (event-app white-label platform)", "name": "WEBMOBI_ATTENDEE_PROXIMITY_ADVERTISEMENT_SERVICE", "note": "WebMobi attendee-proximity advertise UUID (advertise + scan)"},
    # Salto Systems JustIN Mobile smart-lock SDK — Phase-4 cluster c2 from
    # folders 0008+0009. Shipped via com.saltosystems.justinmobile inside hotel /
    # co-working / student-housing apps (Tremblant, Wood Leisure, MonBuilding/Witco
    # Crous & Legende, Nexudus Hubco, Universia USPCEU).
    "b6e60001-e2e3-bc82-4c72-929d0d29ca17": {"company": "Salto Systems S.L. (Spain) — JustIN Mobile smart-lock BLE protocol (com.saltosystems.justinmobile Android SDK)", "name": "SALTO_JUSTIN_GATT_SERVICE",     "note": "Salto JustIN Mobile SDK"},
    "b6e60002-e2e3-bc82-4c72-929d0d29ca17": {"company": "Salto Systems S.L. (Spain) — JustIN Mobile smart-lock BLE protocol (com.saltosystems.justinmobile Android SDK)", "name": "SALTO_JUSTIN_WRITE_CHAR",      "note": "Salto JustIN Mobile SDK"},
    "b6e60003-e2e3-bc82-4c72-929d0d29ca17": {"company": "Salto Systems S.L. (Spain) — JustIN Mobile smart-lock BLE protocol (com.saltosystems.justinmobile Android SDK)", "name": "SALTO_JUSTIN_INDICATION_CHAR", "note": "Salto JustIN Mobile SDK"},
    # Chipsea / Careyou smart-scale BLE SDK — Phase-5 from com.chipsea.btcontrol.en
    # (com.chipsea.btlib.model.BtGattAttr).
    "a602": {"company": "Chipsea Technologies / Careyou — smart-scale BLE SDK (LX product line)",   "name": "CHIPSEA_LX_SERVICE_UUID",         "note": "Chipsea LX service"},
    "a620": {"company": "Chipsea Technologies / Careyou — smart-scale BLE SDK (LX product line)",   "name": "CHIPSEA_LX_UP_I_UUID",            "note": "Chipsea LX upstream input"},
    "a621": {"company": "Chipsea Technologies / Careyou — smart-scale BLE SDK (LX product line)",   "name": "CHIPSEA_LX_UP_N_UUID",            "note": "Chipsea LX upstream notify"},
    "a622": {"company": "Chipsea Technologies / Careyou — smart-scale BLE SDK (LX product line)",   "name": "CHIPSEA_LX_UP_ACK_UUID",          "note": "Chipsea LX upstream ack"},
    "a623": {"company": "Chipsea Technologies / Careyou — smart-scale BLE SDK (LX product line)",   "name": "CHIPSEA_LX_DOWN_WI_UUID",         "note": "Chipsea LX downstream w/indication"},
    "a624": {"company": "Chipsea Technologies / Careyou — smart-scale BLE SDK (LX product line)",   "name": "CHIPSEA_LX_DOWN_WO_UUID",         "note": "Chipsea LX downstream w/o indication"},
    "a625": {"company": "Chipsea Technologies / Careyou — smart-scale BLE SDK (LX product line)",   "name": "CHIPSEA_LX_DOWN_ACK_UUID",        "note": "Chipsea LX downstream ack"},
    "fa9c": {"company": "Chipsea Technologies / Careyou — smart-scale BLE SDK",                     "name": "CHIPSEA_BODY_COMPOSITION_HISTORY","note": "Chipsea history characteristic"},
    "faa0": {"company": "Chipsea Technologies / Careyou — smart-scale BLE SDK (LEAONE product line)", "name": "CHIPSEA_LEAONE_SERVICE_UUID",   "note": "Chipsea LEAONE service"},
    "faa1": {"company": "Chipsea Technologies / Careyou — smart-scale BLE SDK (LEAONE product line)", "name": "CHIPSEA_LEAONE_SCALE_WRITE_UUID","note": "Chipsea LEAONE write"},
    "faa2": {"company": "Chipsea Technologies / Careyou — smart-scale BLE SDK (LEAONE product line)", "name": "CHIPSEA_LEAONE_SCALE_READ_UUID", "note": "Chipsea LEAONE read"},
    "d618d000-6000-1000-8000-000000000000": {"company": "Chipsea Technologies / Careyou — smart-scale BLE SDK (JD product line)", "name": "CHIPSEA_JD_SERVICE_UUID",  "note": "Chipsea JD product line"},
    "d618d001-6000-1000-8000-000000000000": {"company": "Chipsea Technologies / Careyou — smart-scale BLE SDK (JD product line)", "name": "CHIPSEA_JD_CHAR_TX_UUID", "note": "Chipsea JD product line"},
    "d618d002-6000-1000-8000-000000000000": {"company": "Chipsea Technologies / Careyou — smart-scale BLE SDK (JD product line)", "name": "CHIPSEA_JD_CHAR_RX_UUID", "note": "Chipsea JD product line"},
    # Linkplay WiFi-audio module BLE-setup SDK — Phase-5 from com.wifiaudio.Yamaha
    # (com.i.a.b). OEM-shipped in Yamaha MusicCast, Wiim, etc.
    "0128fe40-002f-11e5-87d0-0002a5d5c51b": {"company": "Linkplay Technology (WiFi-audio module BLE setup SDK)", "name": "LINKPLAY_BLE_COUNTRY_WRITE",       "note": "Linkplay WiFi provisioning"},
    "0228fe40-002f-11e5-87d0-0002a5d5c51b": {"company": "Linkplay Technology (WiFi-audio module BLE setup SDK)", "name": "LINKPLAY_BLE_INIT_WRITE",          "note": "Linkplay WiFi provisioning"},
    "0c7c6160-fab2-11e4-9fbb-0002a5d5c51b": {"company": "Linkplay Technology (WiFi-audio module BLE setup SDK)", "name": "LINKPLAY_BLE_STATUS_READ",         "note": "Linkplay WiFi provisioning"},
    "0d7c6160-fab2-11e4-9fbb-0002a5d5c51b": {"company": "Linkplay Technology (WiFi-audio module BLE setup SDK)", "name": "LINKPLAY_BLE_VERSION_READ",        "note": "Linkplay WiFi provisioning"},
    "147c6160-fab2-11e4-9fbb-0002a5d5c51b": {"company": "Linkplay Technology (WiFi-audio module BLE setup SDK)", "name": "LINKPLAY_BLE_HOTSPOT_CONFIG_WRITE","note": "Linkplay WiFi provisioning"},
    "156c6160-fab2-11e4-9fbb-0002a5d5c51b": {"company": "Linkplay Technology (WiFi-audio module BLE setup SDK)", "name": "LINKPLAY_BLE_INDEX_WRITE",         "note": "Linkplay WiFi provisioning"},
    "157c6160-fab2-11e4-9fbb-0002a5d5c51b": {"company": "Linkplay Technology (WiFi-audio module BLE setup SDK)", "name": "LINKPLAY_BLE_INDEX_READ",          "note": "Linkplay WiFi provisioning"},
    "1a6c6160-fab2-11e4-9fbb-0002a5d5c51b": {"company": "Linkplay Technology (WiFi-audio module BLE setup SDK)", "name": "LINKPLAY_BLE_DATA_WRITE",          "note": "Linkplay WiFi provisioning"},
    "1a7c6160-fab2-11e4-9fbb-0002a5d5c51b": {"company": "Linkplay Technology (WiFi-audio module BLE setup SDK)", "name": "LINKPLAY_BLE_DATA_READ",           "note": "Linkplay WiFi provisioning"},
    # TESA Assa Abloy (Spain) — TESA Lock BLE SDK — Phase-5 from net.universia.uspceu
    # (com.tesa.tesalocklibrary.n).
    "9a0852ac-c541-11e7-abc4-cec278b6b50a": {"company": "TESA Assa Abloy (Spain) — TESA Lock BLE SDK (com.tesa.tesalocklibrary)", "name": "TESA_LOCK_SERVICE_UUID", "note": "TESA lock service"},
    "9a085658-c541-11e7-abc4-cec278b6b50a": {"company": "TESA Assa Abloy (Spain) — TESA Lock BLE SDK (com.tesa.tesalocklibrary)", "name": "TESA_LOCK_CHAR_5658",   "note": "TESA lock characteristic"},
    "9a085ad6-c541-11e7-abc4-cec278b6b50a": {"company": "TESA Assa Abloy (Spain) — TESA Lock BLE SDK (com.tesa.tesalocklibrary)", "name": "TESA_LOCK_CHAR_5AD6",   "note": "TESA lock characteristic"},
    "9a085d10-c541-11e7-abc4-cec278b6b50a": {"company": "TESA Assa Abloy (Spain) — TESA Lock BLE SDK (com.tesa.tesalocklibrary)", "name": "TESA_LOCK_CHAR_5D10",   "note": "TESA lock characteristic"},
    "9a085e14-c541-11e7-abc4-cec278b6b50a": {"company": "TESA Assa Abloy (Spain) — TESA Lock BLE SDK (com.tesa.tesalocklibrary)", "name": "TESA_LOCK_CHAR_5E14",   "note": "TESA lock characteristic"},
    "9a085f9a-c541-11e7-abc4-cec278b6b50a": {"company": "TESA Assa Abloy (Spain) — TESA Lock BLE SDK (com.tesa.tesalocklibrary)", "name": "TESA_LOCK_CHAR_5F9A",   "note": "TESA lock characteristic"},
    "9a08608a-c541-11e7-abc4-cec278b6b50a": {"company": "TESA Assa Abloy (Spain) — TESA Lock BLE SDK (com.tesa.tesalocklibrary)", "name": "TESA_LOCK_CHAR_608A",   "note": "TESA lock characteristic"},
    # BlueCats Beacon SDK (com.bluecats.sdk) — Phase-5 from io.navus.avc2022.
    "eb459771-c9d6-4841-8748-df477740ac0b": {"company": "BlueCats (Bluetooth beacon SDK — com.bluecats.sdk)", "name": "BLUECATS_BEACON_COMMAND_SERVICE", "note": "BlueCats beacon command"},
    "9993f233-ac1e-4139-84c2-62db29ea081c": {"company": "BlueCats (Bluetooth beacon SDK — com.bluecats.sdk)", "name": "BLUECATS_BEACON_COMMAND_CHAR_B",  "note": "BlueCats beacon command"},
    "233e302c-8bd5-42c7-9868-2f8d67555051": {"company": "BlueCats (Bluetooth beacon SDK — com.bluecats.sdk)", "name": "BLUECATS_BEACON_COMMAND_CHAR_C",  "note": "BlueCats beacon command"},
    "67a29537-ca4a-4536-abec-8b5c0a5b425b": {"company": "BlueCats (Bluetooth beacon SDK — com.bluecats.sdk)", "name": "BLUECATS_BEACON_COMMAND_CHAR_D",  "note": "BlueCats beacon command"},
    "fc2bfb4c-bc72-4382-8dfc-91fe7d05c335": {"company": "BlueCats (Bluetooth beacon SDK — com.bluecats.sdk)", "name": "BLUECATS_BEACON_COMMAND_CHAR_E",  "note": "BlueCats beacon command"},
    # iDO Smart Wearable BLE SDK (com.ido.ble) — Phase-5 from com.coachcare.mhjgoalsweightloss.
    "0af1": {"company": "iDO Smart Wearable BLE SDK (com.ido.ble)", "name": "IDO_BLE_CHAR_AF1", "note": "iDO BLE characteristic"},
    "0af2": {"company": "iDO Smart Wearable BLE SDK (com.ido.ble)", "name": "IDO_BLE_CHAR_AF2", "note": "iDO BLE characteristic"},
    "0af4": {"company": "iDO Smart Wearable BLE SDK (com.ido.ble)", "name": "IDO_BLE_CHAR_AF4", "note": "iDO BLE characteristic"},
    "0af6": {"company": "iDO Smart Wearable BLE SDK (com.ido.ble)", "name": "IDO_BLE_CHAR_AF6", "note": "iDO BLE characteristic"},
    "0af7": {"company": "iDO Smart Wearable BLE SDK (com.ido.ble)", "name": "IDO_BLE_CHAR_AF7", "note": "iDO BLE characteristic"},
    # Kisi mobile-access proximity beacons — Phase-5 from com.nexudusspaces.hubco.
    "6dfe2064-5186-11ea-8dfe-4b73218bf946": {"company": "Kisi (German cloud-based access-control company)", "name": "KISI_BEACON_UUID_1", "note": "Kisi beacon"},
    "6f9e62a8-5186-11ea-8ed0-4314341d01dd": {"company": "Kisi (German cloud-based access-control company)", "name": "KISI_BEACON_UUID_2", "note": "Kisi beacon"},
    "71fb9eb2-5186-11ea-b1f4-bb928fefb7fd": {"company": "Kisi (German cloud-based access-control company)", "name": "KISI_BEACON_UUID_3", "note": "Kisi beacon"},
    "73f789ec-5186-11ea-9973-87896ce82dd8": {"company": "Kisi (German cloud-based access-control company)", "name": "KISI_BEACON_UUID_4", "note": "Kisi beacon"},
    "74689eac-5186-11ea-be2d-27ec120c3b0f": {"company": "Kisi (German cloud-based access-control company)", "name": "KISI_BEACON_UUID_5", "note": "Kisi beacon"},
    # Elatec MobileBadge SDK (com.elatec.mobilebadge) — Phase-5 from com.nexudusspaces.hubco.
    # Note: non-standard SIG-base suffix (`34f0`/`34f1` instead of `34fb`).
    "0000b81d-0000-1000-8000-00805f9b34f0": {"company": "Elatec GmbH (Germany) — Mobile Badge SDK", "name": "ELATEC_MOBILEBADGE_SERVICE",     "note": "Elatec MobileBadge"},
    "0000b81d-0000-1000-8000-00805f9b34f1": {"company": "Elatec GmbH (Germany) — Mobile Badge SDK", "name": "ELATEC_MOBILEBADGE_WRITE_CHAR",  "note": "Elatec MobileBadge"},
    # Meross BLE smart-home SDK (com.meross.ble) — Phase-5 from com.refoss.refoss.
    "b002": {"company": "Meross Technology (com.meross.ble smart-home SDK; OEM-shipped in Refoss-brand devices)", "name": "MEROSS_BLE_CHAR_B002", "note": "Meross BLE characteristic"},
    "b003": {"company": "Meross Technology (com.meross.ble smart-home SDK; OEM-shipped in Refoss-brand devices)", "name": "MEROSS_BLE_CHAR_B003", "note": "Meross BLE characteristic"},
    # iSEO mobile-credentials SDK (com.iseo.io) — Phase-5 from net.universia.uspceu.
    "00001000-d102-11e1-9b23-00025b00a6a6": {"company": "Iseo Serrature S.p.A. (Italian smart-lock vendor) — CSR-based mobile credentials SDK", "name": "ISEO_DEFAULT_GATT_SERVICE", "note": "iSEO CSR-based mobile credentials"},
    # Anker Roav SmartCharge FM transmitter — Phase-5 from com.chipsguide.app.roav.fmplayer.
    # Field names obfuscated to single letters; names are placeholders.
    "6666": {"company": "Anker Innovations Limited (Roav SmartCharge FM transmitter)", "name": "ROAV_BLE_UUID_6666", "note": "Anker Roav SmartCharge BLE UUID16 (field name obfuscated)"},
    "7777": {"company": "Anker Innovations Limited (Roav SmartCharge FM transmitter)", "name": "ROAV_BLE_UUID_7777", "note": "Anker Roav SmartCharge BLE UUID16 (field name obfuscated)"},
    "8877": {"company": "Anker Innovations Limited (Roav SmartCharge FM transmitter)", "name": "ROAV_BLE_UUID_8877", "note": "Anker Roav SmartCharge BLE UUID16 (field name obfuscated)"},
    "8888": {"company": "Anker Innovations Limited (Roav SmartCharge FM transmitter)", "name": "ROAV_BLE_UUID_8888", "note": "Anker Roav SmartCharge BLE UUID16 (field name obfuscated)"},
    "6c372000-d2cc-11e4-9a1f-0002a5d5c51b": {"company": "Nordic Semiconductor (Legacy DFU service; shipped via Nordic Android-DFU-Library)", "name": "DFU_SERVICE", "note": "Nordic Android-DFU-Library"},
    "6c372001-d2cc-11e4-9a1f-0002a5d5c51b": {"company": "Nordic Semiconductor (Legacy DFU service; shipped via Nordic Android-DFU-Library)", "name": "DFU_PACKET", "note": "Nordic Android-DFU-Library"},
    "6c372002-d2cc-11e4-9a1f-0002a5d5c51b": {"company": "Nordic Semiconductor (Legacy DFU service; shipped via Nordic Android-DFU-Library)", "name": "DFU_CONTROL_POINT", "note": "Nordic Android-DFU-Library"},
    "6c372004-d2cc-11e4-9a1f-0002a5d5c51b": {"company": "Nordic Semiconductor (Legacy DFU service; shipped via Nordic Android-DFU-Library)", "name": "DFU_VERSION", "note": "Nordic Android-DFU-Library"},

    # Nordic UART Service (NUS). Universal transparent-UART pattern across
    # all Nordic BLE chips. https://infocenter.nordicsemi.com/topic/ble_sdk_app_nus_eval/UART/nus_eval_app.html
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": {"company": "Nordic Semiconductor (Nordic UART Service / NUS; shipped via Nordic Android-BLE-Library)", "name": "NUS_SERVICE", "note": "Nordic UART Service"},
    "6e400002-b5a3-f393-e0a9-e50e24dcca9e": {"company": "Nordic Semiconductor (Nordic UART Service / NUS; shipped via Nordic Android-BLE-Library)", "name": "NUS_TX_CHARACTERISTIC", "note": "Nordic UART Service"},
    "6e400003-b5a3-f393-e0a9-e50e24dcca9e": {"company": "Nordic Semiconductor (Nordic UART Service / NUS; shipped via Nordic Android-BLE-Library)", "name": "NUS_RX_CHARACTERISTIC", "note": "Nordic UART Service"},

    # Texas Instruments — OAD (Over-Air Download) bootloader for CC254x/CC264x BLE chips.
    "f000ffc0-0451-4000-b000-000000000000": {"company": "Texas Instruments (OAD — Over-Air Download / bootloader service)", "name": "OAD_SERVICE", "note": "TI OAD bootloader (CC254x/CC264x)"},
    "f000ffc1-0451-4000-b000-000000000000": {"company": "Texas Instruments (OAD — Over-Air Download / bootloader service)", "name": "OAD_IMAGE_IDENTIFY", "note": "TI OAD bootloader (CC254x/CC264x)"},
    "f000ffc2-0451-4000-b000-000000000000": {"company": "Texas Instruments (OAD — Over-Air Download / bootloader service)", "name": "OAD_IMAGE_BLOCK", "note": "TI OAD bootloader (CC254x/CC264x)"},

    # Microchip / ISSC Transparent UART proprietary service (RN4871, IS18xx/IS19xx chips).
    "49535343-fe7d-4ae5-8fa9-9fafd205e455": {"company": "Microchip / ISSC (Transparent UART proprietary service in RN4871 / IS1870 / IS1871 BLE modules)", "name": "ISSC_PROPRIETARY_SERVICE", "note": "Microchip RN-series / ISSC Transparent UART"},
    "49535343-8841-43f4-a8d4-ecbe34729bb3": {"company": "Microchip / ISSC (Transparent UART proprietary service in RN4871 / IS1870 / IS1871 BLE modules)", "name": "ISSC_WRITE_CHARACTERISTIC", "note": "Microchip RN-series / ISSC Transparent UART"},

    # FFAx, FFEx and FFFx UUID16s are reused across unrelated BLE profiles.
    # TI and HM-10 demo mappings are not sufficient to identify an owner or
    # name without supporting package, device, or source-code evidence.

    # Ojmar (Spain) — OCS Smart Bluetooth keypad locker locks. Android SDK
    # `com.ondo.ocssmartlibrary` by third-party "Ondo" wraps a repackaged
    # STMicroelectronics BlueSTSDK and ships with every integrator app.
    # Observed in sesame.smartspaces.d2i.co (May 2026 corpus).
    "0a2a9a41-5df6-11ea-bc55-0242ac130003": {"company": "Ojmar (OCS Smart Bluetooth lock product line; Android SDK by Ondo, built on STMicroelectronics BlueST SDK / STM32WB)", "name": "LockSendCommu",             "note": "Ojmar OCS Smart lock — Lock command channel (lock/unlock/changePIN/claimLock writes)"},
    "0a2a9a42-5df6-11ea-cb55-0242ac130003": {"company": "Ojmar (OCS Smart Bluetooth lock product line; Android SDK by Ondo, built on STMicroelectronics BlueST SDK / STM32WB)", "name": "FeatureRx",                "note": "Ojmar OCS Smart lock — BlueST RX feature (device-to-app notifications)"},
    "0a2a9a43-5df6-11ea-cb52-0242ac130003": {"company": "Ojmar (OCS Smart Bluetooth lock product line; Android SDK by Ondo, built on STMicroelectronics BlueST SDK / STM32WB)", "name": "FeatureReadPassHigh",      "note": "Ojmar OCS Smart lock — PIN/password high byte"},
    "0a2a9a44-5df6-11ea-cb51-0242ac130003": {"company": "Ojmar (OCS Smart Bluetooth lock product line; Android SDK by Ondo, built on STMicroelectronics BlueST SDK / STM32WB)", "name": "FeatureReadPassLow",       "note": "Ojmar OCS Smart lock — PIN/password low byte"},
    "0a2a9a45-5df6-11ea-cb51-0242ac130003": {"company": "Ojmar (OCS Smart Bluetooth lock product line; Android SDK by Ondo, built on STMicroelectronics BlueST SDK / STM32WB)", "name": "RebootOTAModeFeature",     "note": "Ojmar OCS Smart lock — reboot into OTA mode"},
    "f8a3d0fb-6771-11ea-bc55-0242ac130003": {"company": "Ojmar (OCS Smart Bluetooth lock product line; Android SDK by Ondo, built on STMicroelectronics BlueST SDK / STM32WB)", "name": "OTAControlFeature",        "note": "Ojmar OCS Smart lock — OTA control (write commands)"},
    "f8a3d0fc-6771-11ea-bc55-0242ac130003": {"company": "Ojmar (OCS Smart Bluetooth lock product line; Android SDK by Ondo, built on STMicroelectronics BlueST SDK / STM32WB)", "name": "OTABoardWillRebootFeature","note": "Ojmar OCS Smart lock — board-will-reboot notification during OTA"},
    "f8a3d0fd-6771-11ea-bc55-0242ac130003": {"company": "Ojmar (OCS Smart Bluetooth lock product line; Android SDK by Ondo, built on STMicroelectronics BlueST SDK / STM32WB)", "name": "OTAFileUpload",            "note": "Ojmar OCS Smart lock — OTA firmware data upload"},

    # RFduino BLE module — standard service + RX/TX characteristics published
    # by the RFduino SDK (now Particle); widely cloned by Chinese BLE module
    # makers. Defined explicitly in Blynk's `e2.a` BLE-module catalog enum
    # (cc.blynk.appexport.easitemp) as "RFDUINO".
    "2220": {"company": "RFduino LLC / Particle (BLE module — `RFDUINO` BLE Custom Service; cloned by many cheap BLE-Arduino dev boards)", "name": "RFDUINO_SERVICE",   "note": "RFduino BLE service"},
    "2221": {"company": "RFduino LLC / Particle (BLE module — `RFDUINO` BLE Custom Service; cloned by many cheap BLE-Arduino dev boards)", "name": "RFDUINO_RX_CHAR", "note": "RFduino RX (read) characteristic"},
    "2222": {"company": "RFduino LLC / Particle (BLE module — `RFDUINO` BLE Custom Service; cloned by many cheap BLE-Arduino dev boards)", "name": "RFDUINO_TX_CHAR", "note": "RFduino TX (write) characteristic"},

    # DFRobot Bluno / BLE-Link module — UART-bridge service. Named explicitly
    # in Blynk's `e2.a` catalog as "DFROBOT_BLELink".
    "dfb0": {"company": "DFRobot (BLE-Link / Bluno UART-bridge service; widely shipped in DFRobot's BLE-Arduino kits)", "name": "DFROBOT_BLE_SERVICE",   "note": "DFRobot BLE-Link service"},
    "dfb1": {"company": "DFRobot (BLE-Link / Bluno UART-bridge service; widely shipped in DFRobot's BLE-Arduino kits)", "name": "DFROBOT_BLE_RXTX_CHAR", "note": "DFRobot BLE-Link RX+TX characteristic"},
    "dfb2": {"company": "DFRobot (BLE-Link / Bluno UART-bridge service; widely shipped in DFRobot's BLE-Arduino kits)", "name": "DFROBOT_BLE_AT_CHAR",   "note": "DFRobot BLE-Link AT-command / config characteristic"},

    # Sparkfun Simblee BLE module (RFD22102 SoC). Named explicitly in Blynk's
    # `e2.a` catalog as "SIMBLEE".
    "2d30c082-f39f-4ce6-923f-3484ea480596": {"company": "Sparkfun / RF Digital (Simblee BLE module — RFD22102 SoC)", "name": "SIMBLEE_RX_CHAR", "note": "Simblee read characteristic"},
    "2d30c083-f39f-4ce6-923f-3484ea480596": {"company": "Sparkfun / RF Digital (Simblee BLE module — RFD22102 SoC)", "name": "SIMBLEE_TX_CHAR", "note": "Simblee write characteristic"},

    # Punch Through Design — LightBlue Bean / Bean+ BLE board. Named in
    # Blynk's `e2.a` catalog as "LIGHTBLUE_BEAN". The a495ff10..a495ff25
    # family includes both the standard scratch characteristics and the
    # extended Bean+ control surface.
    "a495ff10-c5b1-4b44-b512-1370f02d74de": {"company": "Punch Through Design (LightBlue Bean / Bean+ BLE board)", "name": "LIGHTBLUE_BEAN_SERVICE",   "note": "LightBlue Bean primary service"},
    "a495ff11-c5b1-4b44-b512-1370f02d74de": {"company": "Punch Through Design (LightBlue Bean / Bean+ BLE board)", "name": "LIGHTBLUE_BEAN_SCRATCH_CHAR", "note": "LightBlue Bean serial/scratch characteristic"},
    "a495ff20-c5b1-4b44-b512-1370f02d74de": {"company": "Punch Through Design (LightBlue Bean / Bean+ BLE board)", "name": "LIGHTBLUE_BEAN_AUX_SERVICE", "note": "LightBlue Bean auxiliary service"},
    "a495ff21-c5b1-4b44-b512-1370f02d74de": {"company": "Punch Through Design (LightBlue Bean / Bean+ BLE board)", "name": "LIGHTBLUE_BEAN_SCRATCH1",    "note": "LightBlue Bean scratch1 characteristic"},
    "a495ff22-c5b1-4b44-b512-1370f02d74de": {"company": "Punch Through Design (LightBlue Bean / Bean+ BLE board)", "name": "LIGHTBLUE_BEAN_SCRATCH2",    "note": "LightBlue Bean scratch2 characteristic"},
    "a495ff23-c5b1-4b44-b512-1370f02d74de": {"company": "Punch Through Design (LightBlue Bean / Bean+ BLE board)", "name": "LIGHTBLUE_BEAN_SCRATCH3",    "note": "LightBlue Bean scratch3 characteristic"},
    "a495ff24-c5b1-4b44-b512-1370f02d74de": {"company": "Punch Through Design (LightBlue Bean / Bean+ BLE board)", "name": "LIGHTBLUE_BEAN_SCRATCH4",    "note": "LightBlue Bean scratch4 characteristic"},
    "a495ff25-c5b1-4b44-b512-1370f02d74de": {"company": "Punch Through Design (LightBlue Bean / Bean+ BLE board)", "name": "LIGHTBLUE_BEAN_SCRATCH5",    "note": "LightBlue Bean scratch5 characteristic"},

    # ON Semiconductor / Avnera — AudioManager BLE SDK (com.avnera.audiomanager,
    # used in Harman/AKG audio products and ON-Semi-chip-based BT speakers).
    # The 6BCEBEE0..6BCEBEE5 family is one custom service + five characteristics
    # for the audio device's control/notification surface. The 58622534-...
    # ParcelUuid is the SCAN-FILTER service UUID used to identify Avnera audio
    # devices during BLE scan.
    # Roles inferred from o0.java field wiring: f7050f→getService, f7051g→
    # service.getCharacteristic; f7052h/f7053i/f7054j are matched in
    # `l0.g(uuid, ...)` inside onCharacteristicChanged → all Characteristics.
    # Observed in com.harman.akgn20lt (AKG N20LT wireless earbuds) in May 2026.
    "58622534-68b7-4304-aef2-0de6f02e2018": {"company": "ON Semiconductor / Avnera (AudioManager BLE SDK; com.avnera.audiomanager Android SDK; shipped in Harman/AKG-branded audio products)", "name": "AVNERA_AUDIO_SCAN_FILTER_SVC", "note": "Avnera audio device — scan-filter service UUID (advertised)"},
    "6bcebee0-fcf8-4ed7-88c6-b41c1f240b86": {"company": "ON Semiconductor / Avnera (AudioManager BLE SDK; com.avnera.audiomanager Android SDK; shipped in Harman/AKG-branded audio products)", "name": "AVNERA_AUDIO_SERVICE",         "note": "Avnera audio control service"},
    "6bcebee1-fcf8-4ed7-88c6-b41c1f240b86": {"company": "ON Semiconductor / Avnera (AudioManager BLE SDK; com.avnera.audiomanager Android SDK; shipped in Harman/AKG-branded audio products)", "name": "AVNERA_AUDIO_CMD_CHAR",        "note": "Avnera audio command/data characteristic (post-connect read)"},
    "6bcebee2-fcf8-4ed7-88c6-b41c1f240b86": {"company": "ON Semiconductor / Avnera (AudioManager BLE SDK; com.avnera.audiomanager Android SDK; shipped in Harman/AKG-branded audio products)", "name": "AVNERA_AUDIO_NOTIFY1_CHAR",    "note": "Avnera audio notify characteristic (matched in onCharacteristicChanged)"},
    "6bcebee3-fcf8-4ed7-88c6-b41c1f240b86": {"company": "ON Semiconductor / Avnera (AudioManager BLE SDK; com.avnera.audiomanager Android SDK; shipped in Harman/AKG-branded audio products)", "name": "AVNERA_AUDIO_NOTIFY2_CHAR",    "note": "Avnera audio notify characteristic"},
    "6bcebee4-fcf8-4ed7-88c6-b41c1f240b86": {"company": "ON Semiconductor / Avnera (AudioManager BLE SDK; com.avnera.audiomanager Android SDK; shipped in Harman/AKG-branded audio products)", "name": "AVNERA_AUDIO_NOTIFY3_CHAR",    "note": "Avnera audio notify characteristic"},
    "6bcebee5-fcf8-4ed7-88c6-b41c1f240b86": {"company": "ON Semiconductor / Avnera (AudioManager BLE SDK; com.avnera.audiomanager Android SDK; shipped in Harman/AKG-branded audio products)", "name": "AVNERA_AUDIO_AUX_CHAR",        "note": "Avnera audio auxiliary characteristic"},

    # Excelpoint Solutions Pte Ltd (Singapore) — semiconductor distributor that
    # ships a generic reference BLE stack ("excelpoint.com" + suffix); reused
    # by various OEMs in `e2.d` decompiled package (Harman AKG N20LT
    # observed May 2026 corpus). The ASCII-encoded UUID base reads:
    #   65786365 6c70 6f69 6e74 2e636f6d => "excelpoint.com"
    "65786365-6c70-6f69-6e74-2e636f6d0000": {"company": "Excelpoint Solutions Pte Ltd (Singapore; ASCII-encoded 'excelpoint.com' BLE OTA reference stack)", "name": "EXCELPOINT_OTA_SERVICE", "note": "Excelpoint OTA reference stack — service (suffix 0000)"},
    "65786365-6c70-6f69-6e74-2e636f6d0001": {"company": "Excelpoint Solutions Pte Ltd (Singapore; ASCII-encoded 'excelpoint.com' BLE OTA reference stack)", "name": "EXCELPOINT_OTA_CHAR1",   "note": "Excelpoint OTA reference stack — characteristic 1 (suffix 0001)"},
    "65786365-6c70-6f69-6e74-2e636f6d0002": {"company": "Excelpoint Solutions Pte Ltd (Singapore; ASCII-encoded 'excelpoint.com' BLE OTA reference stack)", "name": "EXCELPOINT_OTA_CHAR2",   "note": "Excelpoint OTA reference stack — characteristic 2 (suffix 0002)"},

    # Realtek Semiconductor — RealSil DFU SDK BLE OTA + DFU services.
    # Shipped via `com.realsil.sdk.dfu` (the Android side of Realtek's BLE
    # firmware-update library; bundled by every wearable/earbud/headset
    # vendor that uses a Realtek RTL87xx chip). Two service families:
    #   - OTA service (d0ff base) + the c.d=0000fff3 control point
    #   - DFU service (6287..6487 base) with Data + Control Point chars
    # Roles confirmed via DfuConfig.java getters:
    #   getOtaServiceUuid()       → 0000d0ff-...
    #   getDfuServiceUuid()       → 00006287-...
    #   getDfuDataUuid()          → 00006387-...
    #   getDfuControlPointUuid()  → 00006487-...
    # The ffd1/ffd2/ffd3/ffd8 family in com.realsil.sdk.dfu.{m,n,o}.h is
    # Realtek's HID-over-GATT OTA path used by HID-mode peripherals.
    # Observed in com.noise.sphere (Noise smartwatch app; May 2026 corpus).
    "0000d0ff-3c17-d293-8e48-14fe2e4da212": {"company": "Realtek Semiconductor (RealSil DFU SDK — OTA service for RTL87xx BLE chips; com.realsil.sdk.dfu Android SDK)", "name": "REALSIL_OTA_SERVICE",            "note": "RealSil OTA service (getOtaServiceUuid)"},
    "00006287-3c17-d293-8e48-14fe2e4da212": {"company": "Realtek Semiconductor (RealSil DFU SDK — OTA service for RTL87xx BLE chips; com.realsil.sdk.dfu Android SDK)", "name": "REALSIL_DFU_SERVICE",            "note": "RealSil DFU service (getDfuServiceUuid)"},
    "00006387-3c17-d293-8e48-14fe2e4da212": {"company": "Realtek Semiconductor (RealSil DFU SDK — OTA service for RTL87xx BLE chips; com.realsil.sdk.dfu Android SDK)", "name": "REALSIL_DFU_DATA_CHAR",          "note": "RealSil DFU data characteristic (getDfuDataUuid)"},
    "00006487-3c17-d293-8e48-14fe2e4da212": {"company": "Realtek Semiconductor (RealSil DFU SDK — OTA service for RTL87xx BLE chips; com.realsil.sdk.dfu Android SDK)", "name": "REALSIL_DFU_CONTROL_POINT_CHAR", "note": "RealSil DFU control point (getDfuControlPointUuid)"},
    "00006587-3c17-d293-8e48-14fe2e4da212": {"company": "Realtek Semiconductor (RealSil DFU SDK — OTA service for RTL87xx BLE chips; com.realsil.sdk.dfu Android SDK)", "name": "REALSIL_DFU_BUFFER_CHECK_CHAR",  "note": "RealSil DFU buffer-check / state characteristic (additional DFU char in g.java)"},
    "ffd1": {"company": "Realtek Semiconductor (RealSil DFU SDK — HID-over-GATT OTA path for HID peripherals on RTL87xx)", "name": "REALSIL_HOGP_OTA_FFD1", "note": "RealSil HID-OTA characteristic"},
    "ffd2": {"company": "Realtek Semiconductor (RealSil DFU SDK — HID-over-GATT OTA path for HID peripherals on RTL87xx)", "name": "REALSIL_HOGP_OTA_FFD2", "note": "RealSil HID-OTA characteristic"},
    "ffd3": {"company": "Realtek Semiconductor (RealSil DFU SDK — HID-over-GATT OTA path for HID peripherals on RTL87xx)", "name": "REALSIL_HOGP_OTA_FFD3", "note": "RealSil HID-OTA characteristic"},
    "ffd8": {"company": "Realtek Semiconductor (RealSil DFU SDK — HID-over-GATT OTA path for HID peripherals on RTL87xx)", "name": "REALSIL_HOGP_OTA_FFD8", "note": "RealSil HID-OTA characteristic"},

    # Midea Group (China) — Midea IoT SDK BLE provisioning protocol.
    # Shipped via the `com.midea.iot.sdk` Android SDK; bundled by many
    # white-label appliance integrator apps (air conditioners, water heaters,
    # etc.). The Midea SDK exposes two parallel BLE services:
    #   - FF80 service + FF81 write char + FF82 notify char (provisioning)
    #   - FF90 service + FF91 + FF92 (secondary config / status)
    # Roles inferred from com.midea.iot.sdk.l4 (base class) and m4 (subclass):
    # `bluetoothGatt.getService(this.a)` → str2 is service; subsequent
    # `service.getCharacteristic(this.c)` and `getCharacteristic(this.e)` →
    # str3 and str4 are characteristics. Same wiring pattern repeats for
    # V/W/X (FF90/91/92). Observed in com.aristonthermo.aristonclima
    # (a Midea-OEM rebrand for Ariston Thermo Group's HVAC line; May 2026 corpus).
    "ff80": {"company": "Midea Group (Midea IoT SDK BLE provisioning protocol; com.midea.iot.sdk Android SDK)", "name": "MIDEA_BLE_SERVICE",       "note": "Midea IoT SDK — primary provisioning service"},
    "ff81": {"company": "Midea Group (Midea IoT SDK BLE provisioning protocol; com.midea.iot.sdk Android SDK)", "name": "MIDEA_BLE_WRITE_CHAR",    "note": "Midea IoT SDK — provisioning write characteristic"},
    "ff82": {"company": "Midea Group (Midea IoT SDK BLE provisioning protocol; com.midea.iot.sdk Android SDK)", "name": "MIDEA_BLE_NOTIFY_CHAR",   "note": "Midea IoT SDK — provisioning notify characteristic"},
    "ff90": {"company": "Midea Group (Midea IoT SDK BLE provisioning protocol; com.midea.iot.sdk Android SDK)", "name": "MIDEA_BLE_CONFIG_SERVICE","note": "Midea IoT SDK — secondary config/status service"},
    "ff91": {"company": "Midea Group (Midea IoT SDK BLE provisioning protocol; com.midea.iot.sdk Android SDK)", "name": "MIDEA_BLE_CONFIG_CHAR1",  "note": "Midea IoT SDK — secondary config characteristic"},
    "ff92": {"company": "Midea Group (Midea IoT SDK BLE provisioning protocol; com.midea.iot.sdk Android SDK)", "name": "MIDEA_BLE_CONFIG_CHAR2",  "note": "Midea IoT SDK — secondary config characteristic"},
    "ffc0": {"company": "Midea Group (Midea IoT SDK BLE OTA service; com.midea.iot.sdk Android SDK)",          "name": "MIDEA_OTA_SERVICE",       "note": "Midea IoT SDK — OTA/firmware update service (mirrors TI OAD shape but on SIG base)"},
    "ffc1": {"company": "Midea Group (Midea IoT SDK BLE OTA service; com.midea.iot.sdk Android SDK)",          "name": "MIDEA_OTA_CHAR1",         "note": "Midea IoT SDK — OTA characteristic"},
    "ffc2": {"company": "Midea Group (Midea IoT SDK BLE OTA service; com.midea.iot.sdk Android SDK)",          "name": "MIDEA_OTA_CHAR2",         "note": "Midea IoT SDK — OTA characteristic (notify)"},

    # Zebra Technologies (USA) — RFD/CS family Bluetooth scanner control
    # service. Shipped via the `com.zebra.scannercontrol` Android SDK
    # ("ScannerSDK for Android"), built around the LE Serial Service
    # (a2f0037b-...) with characteristic pairs for control framing
    # (CONNECTION_REQUEST / CONNECTION_RESPONSE), credit flow control
    # (CREDIT_INPUT / CREDIT_OUTPUT), and out-of-band data movement
    # (INFO_INPUT / INFO_OUTPUT). Observed in net.aexgroup.aexdrivermobile
    # (May 2026 corpus), which integrates Zebra scanners for parking
    # enforcement scanning. The exact same UUIDs appear in any Android
    # integrator that bundles ScannerSDK.
    "a2f0037b-4e26-4981-8a2d-eda9e1689868": {"company": "Zebra Technologies (RFD/CS scanner LE Serial Service; com.zebra.scannercontrol Android SDK)", "name": "ZEBRA_LE_SERIAL_SERVICE", "note": "Zebra ScannerSDK — LE Serial Service (primary)"},
    "21f9e2b9-e59c-4e49-84e9-8cf2be479d0b": {"company": "Zebra Technologies (RFD/CS scanner LE Serial Service; com.zebra.scannercontrol Android SDK)", "name": "ZEBRA_CONNECTION_REQUEST_CHAR",  "note": "Zebra ScannerSDK — connection request (write)"},
    "256a0615-c232-4eec-8187-9afb38226a5a": {"company": "Zebra Technologies (RFD/CS scanner LE Serial Service; com.zebra.scannercontrol Android SDK)", "name": "ZEBRA_CONNECTION_RESPONSE_CHAR", "note": "Zebra ScannerSDK — connection response (notify)"},
    "f3ae6f04-8407-44b6-85a3-59c6feb21924": {"company": "Zebra Technologies (RFD/CS scanner LE Serial Service; com.zebra.scannercontrol Android SDK)", "name": "ZEBRA_CREDIT_INPUT_CHAR",       "note": "Zebra ScannerSDK — credit flow input characteristic"},
    "89ae8d0b-8905-45a7-a4b2-d61b94cb20de": {"company": "Zebra Technologies (RFD/CS scanner LE Serial Service; com.zebra.scannercontrol Android SDK)", "name": "ZEBRA_CREDIT_OUTPUT_CHAR",      "note": "Zebra ScannerSDK — credit flow output characteristic"},
    "4b0e1f59-c0f4-4eee-91ad-da9a1532ea00": {"company": "Zebra Technologies (RFD/CS scanner LE Serial Service; com.zebra.scannercontrol Android SDK)", "name": "ZEBRA_INFO_INPUT_CHAR",         "note": "Zebra ScannerSDK — info/data input characteristic (notify)"},
    "91a765f5-ec8f-4882-a9eb-cc0e5b0915af": {"company": "Zebra Technologies (RFD/CS scanner LE Serial Service; com.zebra.scannercontrol Android SDK)", "name": "ZEBRA_INFO_OUTPUT_CHAR",        "note": "Zebra ScannerSDK — info/data output characteristic (write)"},

    # Technogym S.p.A. (Italy) — TGEquipmentConnection BLE protocol for
    # gym-equipment login (gym uses these to identify a logged-in user
    # walking up to a treadmill / bike via Bluetooth). Shipped via the
    # `com.technogym.sdk.btlelogin` Android SDK. The service UUID is
    # advertised in scan responses; the two characteristics (login byte
    # stream + equipment identity) are read post-connect. Observed in
    # com.technogym.mywellness.minfysioterapi (May 2026 corpus).
    "ae4a2645-916e-4d6b-8884-500b6a2e244c": {"company": "Technogym S.p.A. (TGEquipment login BLE protocol; com.technogym.sdk.btlelogin Android SDK)", "name": "TG_EQUIPMENT_SERVICE", "note": "Technogym equipment login service (advertised in scan response)"},
    "cf69e44f-4f89-44eb-a642-773e3acdb2dc": {"company": "Technogym S.p.A. (TGEquipment login BLE protocol; com.technogym.sdk.btlelogin Android SDK)", "name": "TG_LOGIN_CHAR",       "note": "Technogym equipment login characteristic (read post-connect)"},
    "1d160b86-073b-11e8-ba89-0ed5f89f718b": {"company": "Technogym S.p.A. (TGEquipment login BLE protocol; com.technogym.sdk.btlelogin Android SDK)", "name": "TG_IDENTITY_CHAR",    "note": "Technogym equipment identity characteristic (notify)"},

    # Shortcut Labs AB (Sweden) — Flic 1 wireless button BLE protocol,
    # shipped via the `io.flic.poiclib` Android SDK (`FlicManager`,
    # `FlicScanWizard`, etc.). The three custom UUIDs below are the Flic
    # button's primary service + two characteristics (status/event notify).
    # Roles inferred from FlicManager.java usage: `g` appears in scan-result
    # pair.first (the advertised service); `h` and `i` appear in
    # `bluetoothGattCharacteristic.getUuid().equals(...)` callbacks (chars).
    # Observed in br.com.segware.mysecurity.mxmsei (May 2026 corpus, which
    # bundles flic-sdk for "panic button" integration).
    "f02adfc0-26e7-11e4-9edc-0002a5d5c51b": {"company": "Shortcut Labs (Flic 1 BLE button; shipped via io.flic.poiclib Android SDK)", "name": "FLIC_BUTTON_SERVICE", "note": "Flic 1 advertised service UUID"},
    "cc7efce0-26e8-11e4-8fd2-0002a5d5c51b": {"company": "Shortcut Labs (Flic 1 BLE button; shipped via io.flic.poiclib Android SDK)", "name": "FLIC_BUTTON_STATUS_CHAR", "note": "Flic 1 status/notification characteristic"},
    "06053ec0-26e9-11e4-adc2-0002a5d5c51b": {"company": "Shortcut Labs (Flic 1 BLE button; shipped via io.flic.poiclib Android SDK)", "name": "FLIC_BUTTON_EVENT_CHAR",  "note": "Flic 1 button-press event characteristic"},

    # Eddystone-GATT Configuration Service (Google) — well-known beacon
    # configuration interface published at
    # https://github.com/google/eddystone/blob/master/configuration-service/README.md
    # The `a3c87500` base UUID + a3c87501..a3c8750c suffixes define the
    # service + 12 standard characteristics for configuring an Eddystone
    # beacon over GATT (active slot, ADV interval, TX power, lock state,
    # EID identity key, etc.). Observed via `com.lg2.eddystone.EddystoneModule`
    # in br.com.segware.mysecurity.mxmsei (May 2026 corpus).
    "a3c87500-8ed3-4bdf-8a39-a01bebede295": {"company": "Google (Eddystone-GATT Configuration Service)", "name": "EDDYSTONE_CONFIG_SERVICE",     "note": "Eddystone-GATT configuration service (published spec)"},
    "a3c87501-8ed3-4bdf-8a39-a01bebede295": {"company": "Google (Eddystone-GATT Configuration Service)", "name": "EDDYSTONE_CAPABILITIES",       "note": "Eddystone-GATT — beacon capabilities"},
    "a3c87502-8ed3-4bdf-8a39-a01bebede295": {"company": "Google (Eddystone-GATT Configuration Service)", "name": "EDDYSTONE_ACTIVE_SLOT",        "note": "Eddystone-GATT — active slot selector"},
    "a3c87503-8ed3-4bdf-8a39-a01bebede295": {"company": "Google (Eddystone-GATT Configuration Service)", "name": "EDDYSTONE_ADV_INTERVAL",       "note": "Eddystone-GATT — advertising interval"},
    "a3c87504-8ed3-4bdf-8a39-a01bebede295": {"company": "Google (Eddystone-GATT Configuration Service)", "name": "EDDYSTONE_RADIO_TX_POWER",     "note": "Eddystone-GATT — radio TX power"},
    "a3c87505-8ed3-4bdf-8a39-a01bebede295": {"company": "Google (Eddystone-GATT Configuration Service)", "name": "EDDYSTONE_ADVERTISED_TX_POWER","note": "Eddystone-GATT — advertised TX power"},
    "a3c87506-8ed3-4bdf-8a39-a01bebede295": {"company": "Google (Eddystone-GATT Configuration Service)", "name": "EDDYSTONE_LOCK_STATE",         "note": "Eddystone-GATT — lock state"},
    "a3c87507-8ed3-4bdf-8a39-a01bebede295": {"company": "Google (Eddystone-GATT Configuration Service)", "name": "EDDYSTONE_UNLOCK",             "note": "Eddystone-GATT — unlock characteristic"},
    "a3c87508-8ed3-4bdf-8a39-a01bebede295": {"company": "Google (Eddystone-GATT Configuration Service)", "name": "EDDYSTONE_PUBLIC_ECDH_KEY",    "note": "Eddystone-GATT — public ECDH key"},
    "a3c87509-8ed3-4bdf-8a39-a01bebede295": {"company": "Google (Eddystone-GATT Configuration Service)", "name": "EDDYSTONE_EID_IDENTITY_KEY",   "note": "Eddystone-GATT — EID identity key"},
    "a3c8750a-8ed3-4bdf-8a39-a01bebede295": {"company": "Google (Eddystone-GATT Configuration Service)", "name": "EDDYSTONE_ADV_SLOT_DATA",      "note": "Eddystone-GATT — ADV slot data"},
    "a3c8750b-8ed3-4bdf-8a39-a01bebede295": {"company": "Google (Eddystone-GATT Configuration Service)", "name": "EDDYSTONE_FACTORY_RESET",      "note": "Eddystone-GATT — factory reset"},
    "a3c8750c-8ed3-4bdf-8a39-a01bebede295": {"company": "Google (Eddystone-GATT Configuration Service)", "name": "EDDYSTONE_REMAIN_CONNECTABLE", "note": "Eddystone-GATT — remain connectable"},

    # PhyPlus Inc. (Shanghai) — PHY6202 BLE 5.0 SoC's stock OAD (Over-the-Air
    # Download) service. Shipped as part of the `com.ble.ble.oad` SDK
    # (`com.ble.ble.oad.phy.PhyOADProxy`, declared alongside cc2541/cc2640
    # variants in `OADType.java`). Roles inferred from setWriteType + Notify
    # wiring in PhyOADProxy.b(): d.b is WriteType=2 (with response — control),
    # d.c is the notify char, d.d is WriteType=1 (no response — data block).
    # Observed in com.cardapp.sino.cm (May 2026 corpus).
    "5833ff01-9b8b-5191-6142-22a4536ef123": {"company": "PhyPlus Inc. (PHY6202 BLE 5.0 SoC OAD service; shipped via com.ble.ble.oad Android SDK)", "name": "PHY6202_OAD_SERVICE",       "note": "PhyPlus PHY6202 OAD service"},
    "5833ff02-9b8b-5191-6142-22a4536ef123": {"company": "PhyPlus Inc. (PHY6202 BLE 5.0 SoC OAD service; shipped via com.ble.ble.oad Android SDK)", "name": "PHY6202_OAD_IDENTIFY",      "note": "PhyPlus PHY6202 OAD image-identify / control (write with response; used to trigger OTA mode)"},
    "5833ff03-9b8b-5191-6142-22a4536ef123": {"company": "PhyPlus Inc. (PHY6202 BLE 5.0 SoC OAD service; shipped via com.ble.ble.oad Android SDK)", "name": "PHY6202_OAD_STATUS_NOTIFY", "note": "PhyPlus PHY6202 OAD status notify characteristic"},
    "5833ff04-9b8b-5191-6142-22a4536ef123": {"company": "PhyPlus Inc. (PHY6202 BLE 5.0 SoC OAD service; shipped via com.ble.ble.oad Android SDK)", "name": "PHY6202_OAD_IMAGE_BLOCK",   "note": "PhyPlus PHY6202 OAD image-block (write without response; large data transfer)"},

    # Huami / Zepp / Xiaomi Mi Band custom GATT UUID family. Every Huami
    # wearable since Mi Band 2 (also Amazfit GTS/GTR, Bip, Zepp E, etc.)
    # exposes characteristics under the `0000XXXX-0000-3512-2118-0009af100700`
    # base. The DFU sub-family (`00001530..00001532`) is Huami's port of the
    # Nordic Legacy DFU service onto Huami's own BLE stack. Documented in
    # Gadgetbridge's Huami protocol notes and freemyband.com reverse-engineering
    # writeups. Observed in com.tntkhang.gtswatchface (May 2026 corpus).
    "00000001-0000-3512-2118-0009af100700": {"company": "Huami / Zepp (Mi Band / Amazfit GTS/GTR/Bip BLE protocol)", "name": "HUAMI_AUTH",          "note": "Huami custom characteristic — authentication / device pairing"},
    "00000002-0000-3512-2118-0009af100700": {"company": "Huami / Zepp (Mi Band / Amazfit GTS/GTR/Bip BLE protocol)", "name": "HUAMI_DATA_REQUEST", "note": "Huami custom characteristic — data request"},
    "00000003-0000-3512-2118-0009af100700": {"company": "Huami / Zepp (Mi Band / Amazfit GTS/GTR/Bip BLE protocol)", "name": "HUAMI_CHUNKED_TRANSFER", "note": "Huami custom characteristic — chunked data transfer (notify)"},
    "00000004-0000-3512-2118-0009af100700": {"company": "Huami / Zepp (Mi Band / Amazfit GTS/GTR/Bip BLE protocol)", "name": "HUAMI_ACTIVITY_DATA_CONTROL", "note": "Huami custom characteristic — activity data control"},
    "00000005-0000-3512-2118-0009af100700": {"company": "Huami / Zepp (Mi Band / Amazfit GTS/GTR/Bip BLE protocol)", "name": "HUAMI_ACTIVITY_DATA", "note": "Huami custom characteristic — activity data stream"},
    "00001530-0000-3512-2118-0009af100700": {"company": "Huami / Zepp (Mi Band / Amazfit GTS/GTR/Bip BLE protocol)", "name": "HUAMI_DFU_SERVICE",  "note": "Huami port of Nordic Legacy DFU service"},
    "00001531-0000-3512-2118-0009af100700": {"company": "Huami / Zepp (Mi Band / Amazfit GTS/GTR/Bip BLE protocol)", "name": "HUAMI_DFU_CONTROL_POINT", "note": "Huami port of Nordic Legacy DFU control point"},
    "00001532-0000-3512-2118-0009af100700": {"company": "Huami / Zepp (Mi Band / Amazfit GTS/GTR/Bip BLE protocol)", "name": "HUAMI_DFU_PACKET",   "note": "Huami port of Nordic Legacy DFU packet"},

    # Rosslare Security Products (Israel) — AxTraxNG access-control system.
    # `com.rosslare.blelib.serviceUUID.AxTraxServiceUUIDs` declares one
    # service + two transparent-UART-style characteristics (RX + TX).
    # Observed in com.mobitti.shaanan (May 2026 corpus).
    "d973f2e0-b19e-11e2-9e96-0800200c9a66": {"company": "Rosslare Security Products (AxTraxNG access control; com.rosslare.blelib Android SDK)", "name": "getService",                "note": "Rosslare AxTraxNG service UUID (parent of the d973f2e1 RX + d973f2e2 TX characteristics)"},
    "d973f2e1-b19e-11e2-9e96-0800200c9a66": {"company": "Rosslare Security Products (AxTraxNG access control; com.rosslare.blelib Android SDK)", "name": "getReceiveCharacteristic",  "note": "Rosslare AxTraxNG receive (device-to-app) characteristic"},
    "d973f2e2-b19e-11e2-9e96-0800200c9a66": {"company": "Rosslare Security Products (AxTraxNG access control; com.rosslare.blelib Android SDK)", "name": "getTransmitCharacteristic", "note": "Rosslare AxTraxNG transmit (app-to-device) characteristic"},

    # Sifli Technology — Chinese BLE chip vendor; com.sifli.siflidfu Android SDK
    # for Device Firmware Update. UUID base last 12 hex `6473-5f696c666973`
    # decodes ASCII to `ds_iflis` ('sifli sd' reversed). Observed in batch 2
    # (folders 0031-0035) of the May 2026 corpus.
    "00000000-0000-0000-6473-5f696c666973": {"company": "Sifli Technology (Chinese BLE chip vendor; com.sifli.siflidfu Android SDK)", "name": "SIFLI_DFU_SERVICE",   "note": "Sifli DFU (Device Firmware Update) — declared in com.sifli.siflidfu. UUID base last 12 hex `6473-5f696c666973` decodes ASCII to `ds_iflis`."},
    "00000000-0000-0100-6473-5f696c666973": {"company": "Sifli Technology (Chinese BLE chip vendor; com.sifli.siflidfu Android SDK)", "name": "SIFLI_DFU_CHAR_0100", "note": "Sifli DFU characteristic — declared in com.sifli.siflidfu."},
    "00000000-0000-0200-6473-5f696c666973": {"company": "Sifli Technology (Chinese BLE chip vendor; com.sifli.siflidfu Android SDK)", "name": "SIFLI_DFU_CHAR_0200", "note": "Sifli DFU characteristic — declared in com.sifli.siflidfu."},

    # Suzhou ZWO Co., Ltd. — astronomy telescope/camera vendor; SeeStar smart-
    # telescope BLE characteristics in the 850e17xx-6ecf-49f1-a13f-f5c2d9174f9f
    # namespace. Observed in batch 2 of the May 2026 corpus.
    "850e1701-6ecf-49f1-a13f-f5c2d9174f9f": {"company": "Suzhou ZWO Co., Ltd. (astronomy telescope/camera vendor; SeeStar smart-telescope)", "name": "ZWO_SEESTAR_CHAR_850E1701", "note": "ZWO SeeStar smart-telescope BLE characteristic in the 850e17xx-6ecf-49f1-a13f-f5c2d9174f9f namespace."},
    "850e1703-6ecf-49f1-a13f-f5c2d9174f9f": {"company": "Suzhou ZWO Co., Ltd. (astronomy telescope/camera vendor; SeeStar smart-telescope)", "name": "ZWO_SEESTAR_CHAR_850E1703", "note": "ZWO SeeStar smart-telescope BLE characteristic in the 850e17xx-6ecf-49f1-a13f-f5c2d9174f9f namespace."},

    # Phase 5 v2 (2026-05-17): additional SDK UUIDs from cluster decompilation.
    '00000000-000e-11e1-9ab4-0002a5d5c51b': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'DEBUG_SERVICE_UUID', "note": 'ST BlueSTSDK debug service'},
    '00000000-000f-11e1-9ab4-0002a5d5c51b': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'CONFIG_CONTROL_SERVICE_UUID', "note": 'ST BlueSTSDK config-control service (BLENodeDefines.Services.Config.CONFIG_CONTROL_SERVICE_UUID)'},
    '00000001-000e-11e1-ac36-0002a5d5c51b': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'DEBUG_TERM_UUID', "note": 'ST BlueSTSDK debug terminal (stdin/stdout) characteristic'},
    '00000001-000f-11e1-ac36-0002a5d5c51b': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'REGISTERS_ACCESS_UUID', "note": 'ST BlueSTSDK registers-access characteristic'},
    '00000002-000e-11e1-ac36-0002a5d5c51b': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'DEBUG_STDERR_UUID', "note": 'ST BlueSTSDK debug stderr characteristic'},
    '00000002-000f-11e1-ac36-0002a5d5c51b': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'FEATURE_COMMAND_UUID', "note": 'ST BlueSTSDK feature-command characteristic (BLENodeDefines.Services.Config.FEATURE_COMMAND_UUID)'},
    '000001ff-3c17-d293-8e48-14fe2e4da212': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'HTSMART_WRISTBAND_PRIVATE', "note": 'HTSmart wristband2 (private base) main UUID; from com.htsmart.wristband2.a.c.a.f2852p (only constant name suffix is a single letter so kept the meaningful class context)'},
    '00001530-1212-efde-1523-785feabcd123': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'DFU_SERVICE', "note": "Tacx legacy Nordic-DFU service base (1530); not Garmin-proprietary but Tacx's own constant"},
    '00001531-1212-efde-1523-785feabcd123': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'CONTROL_CHARACTERISTIC', "note": 'Tacx legacy Nordic-DFU control characteristic'},
    '00001532-1212-efde-1523-785feabcd123': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'PACKET_CHARACTERISTIC', "note": 'Tacx legacy Nordic-DFU packet characteristic'},
    '00007889-0000-1000-8000-00805f9b34fb': {"company": 'Coolkit (Chinese smart-home cloud platform — eWeLink) — Sonoff and OEM smart-plug / smart-switch BLE provisioning', "name": 'BP_MANAGER_0634_SERVICE_UUID', "note": 'DMD-Brands Bp0603 BP Monitor model-0634 service'},
    '00008a81-0000-1000-8000-00805f9b34fb': {"company": 'Coolkit (Chinese smart-home cloud platform — eWeLink) — Sonoff and OEM smart-plug / smart-switch BLE provisioning', "name": 'BP_MANAGER_BP_MONITOR_DOWNLOAD_CHARACTERISTIC', "note": 'DMD-Brands BP monitor download characteristic'},
    '00008a82-0000-1000-8000-00805f9b34fb': {"company": 'Coolkit (Chinese smart-home cloud platform — eWeLink) — Sonoff and OEM smart-plug / smart-switch BLE provisioning', "name": 'BP_MANAGER_BP_MONITOR_UPLOAD_CHARACTERISTIC', "note": 'DMD-Brands BP monitor upload characteristic'},
    '00008a91-0000-1000-8000-00805f9b34fb': {"company": 'Coolkit (Chinese smart-home cloud platform — eWeLink) — Sonoff and OEM smart-plug / smart-switch BLE provisioning', "name": 'BP_MANAGER_BP_MONITOR_MEASUREMENT_CHARACTERISTIC', "note": 'DMD-Brands BP monitor measurement characteristic'},
    '00008a92-0000-1000-8000-00805f9b34fb': {"company": 'Coolkit (Chinese smart-home cloud platform — eWeLink) — Sonoff and OEM smart-plug / smart-switch BLE provisioning', "name": 'BP_MANAGER_BP_MONITOR_INTERMEDIATE_MEASUREMENT_CHARACTERISTIC', "note": 'DMD-Brands BP monitor intermediate-measurement characteristic'},
    '00008b09-0000-1000-8000-00805f9b34fb': {"company": 'Coolkit (Chinese smart-home cloud platform — eWeLink) — Sonoff and OEM smart-plug / smart-switch BLE provisioning', "name": 'BP_MANAGER_0604_SERVICE_UUID', "note": 'DMD-Brands Bp0603 BP Monitor model-0604 service (com.dmdbrands.bpmtapi.Bp0603Manager); RPM Healthcare aggregator'},
    '0000a500-0000-1000-8000-00805f9b34fb': {"company": 'Coolkit (Chinese smart-home cloud platform — eWeLink) — Sonoff and OEM smart-plug / smart-switch BLE provisioning', "name": 'SERVICE_UUID_PEDOMETER_A5', "note": 'LifeSense pedometer A5 service used in RPM-Healthcare aggregator app (cluster tag may be misnamed; actual SDK is com.lifesense.plugin.ble)'},
    '0000ae00-0000-1000-8000-00805f9b34fb': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'UUID_SERVICE', "note": 'Jieli AC chipset BLE service base (0xAE00); used by both Jieli BluetoothConstant and Veepoo protocol stack inside the OPlayer fitness app'},
    '0000ae01-0000-1000-8000-00805f9b34fb': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'UUID_WRITE', "note": 'Jieli AC chipset write characteristic; from jieli.bluetooth_connect.constant.BluetoothConstant'},
    '0000ae02-0000-1000-8000-00805f9b34fb': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'UUID_NOTIFICATION', "note": 'Jieli AC chipset notify characteristic; from jieli.bluetooth_connect.constant.BluetoothConstant'},
    '0000fe11-8e22-4541-9d4c-21edae82ed19': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'STM32_OTA_RebootOTAModeFeature', "note": 'STM32WB OTA RebootOTAModeFeature characteristic (com.st.STM32WB.fwUpgrade.feature.STM32OTASupport)'},
    '0000fe22-8e22-4541-9d4c-21edae82ed19': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'STM32_OTA_OTAControlFeature', "note": 'STM32WB OTA control-point characteristic'},
    '0000fe23-8e22-4541-9d4c-21edae82ed19': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'STM32_OTA_OTABoardWillRebootFeature', "note": 'STM32WB OTA board-will-reboot notification characteristic'},
    '0000fe24-8e22-4541-9d4c-21edae82ed19': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'STM32_OTA_OTAFileUpload', "note": 'STM32WB OTA file-upload characteristic'},
    '0000fe41-8e22-4541-9d4c-21edae82ed19': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'STM32WB_P2P_ControlLed_RadioReboot', "note": 'STM32WB Peer2Peer demo led-control + radio-reboot characteristic (FeatureControlLed + FeatureProtocolRadioReboot)'},
    '0000fe42-8e22-4541-9d4c-21edae82ed19': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'STM32WB_P2P_SwitchStatus', "note": 'STM32WB Peer2Peer demo switch-status characteristic'},
    '0000fe51-8e22-4541-9d4c-21edae82ed19': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'STM32WB_P2P_NetworkStatus', "note": 'STM32WB Peer2Peer demo network-status characteristic'},
    '0000ff02-0000-1000-8000-00805f9b34fb': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'PO60_NOTIFY_CHARACTERISTIC_UUID', "note": 'Cross-cluster overlap; PO60 SpO2 notify characteristic and crrepa wristband notify; same value used as htsmart wristband notify'},
    '0000ff03-0000-1000-8000-00805f9b34fb': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'UUID_BP_SEND / UUID_BP_RECEIVE_iHealth', "note": 'crrepa wristband control char; also used by htsmart wristband and iHealth BP send'},
    '0000ff04-0000-1000-8000-00805f9b34fb': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'WRISTBAND_CHAR_FF04', "note": 'From com.crrepa.c.a.x (UUID const, the only non-minified name suffix); fitness-band data characteristic'},
    '0000ff12-0000-1000-8000-00805f9b34fb': {"company": 'Coolkit (Chinese smart-home cloud platform — eWeLink) — Sonoff and OEM smart-plug / smart-switch BLE provisioning', "name": 'PO60_SERVICE_UUID', "note": 'Berry Med Po60 SpO2 service (com.rpmhealthcare.rpm365.core.ble.spo2.po60.Po60ServiceHelper)'},
    '0dde73a3-89dc-49d8-970a-ca43079209f5': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'MAIN_SOFTWARE_VERSION_UUID / MAIN_SW_VERSION_CHARACTERISTIC_UUID', "note": 'Continental KAAS Mouse SW-version characteristic'},
    '122e8cc0-8508-11e3-baa7-0800200c9a66': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'BlueNRG_OTA_ImageFeature', "note": 'BlueNRG OTA ImageFeature characteristic (com.st.BlueNRG.fwUpgrade.feature.BlueNRGOTASupport)'},
    '1258387b-8c06-45cc-9938-4ec602c94bfa': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'MAIN_TIMESET_UUID / MAIN_TIME_CHARACTERISTIC_UUID', "note": 'Continental KAAS Mouse time-set characteristic'},
    '1608635f-35c7-42e0-9218-dd18c9347a3c': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'MAIN_SYNTHESIS2_UUID', "note": 'Continental KAAS Mouse synthesis-2 characteristic'},
    '210f99f0-8508-11e3-baa7-0800200c9a66': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'BlueNRG_OTA_NewImageFeature', "note": 'BlueNRG OTA NewImageFeature characteristic'},
    '2691aa80-8508-11e3-baa7-0800200c9a66': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'BlueNRG_OTA_NewImageTUContentFeature', "note": 'BlueNRG OTA NewImageTUContentFeature characteristic'},
    '2bdc5760-8508-11e3-baa7-0800200c9a66': {"company": 'STMicroelectronics — BlueNRG / BlueMS / SmartTag SDKs for the BlueNRG-1/2/MS/M0/MS sensor demo apps', "name": 'BlueNRG_OTA_ExpectedImageTUSeqNumberFeature', "note": 'BlueNRG OTA ExpectedImageTUSeqNumberFeature characteristic'},
    '3a03bd28-45ce-48ae-8451-acf26f28396b': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'MAIN_TOKEN_1_UUID / MAIN_TOKEN_ONE_CHARACTERISTIC_UUID', "note": 'Continental KAAS Mouse auth token-1 characteristic'},
    '4a385da3-6680-4bf9-89b2-83ea70589d95': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'MAIN_REFLASH_UUID', "note": 'Continental KAAS Mouse reflash/firmware-update characteristic'},
    '5f973ccc-5105-41c7-9fe4-de6b614a66d7': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'MAIN_GPS_UUID / MAIN_GPS_CHARACTERISTIC_UUID', "note": 'Continental KAAS Mouse GPS characteristic (vehicle location)'},
    '60480001-df91-4bf6-83ad-4fdbad53c68a': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'MAGNUM_LOG_SERVICE', "note": 'Tacx Magnum (high-end trainer) logging service'},
    '60480002-df91-4bf6-83ad-4fdbad53c68a': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'MAGNUM_LOG_COMMAND', "note": 'Tacx Magnum logging command characteristic'},
    '60480003-df91-4bf6-83ad-4fdbad53c68a': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'MAGNUM_LOG_RESPONSE', "note": 'Tacx Magnum logging response characteristic'},
    '636f6d2e-6a69-7561-6e2e-414d56313000': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_AM3_Qualcomm_SERVICE', "note": 'iHealth AM3 (Qualcomm chip variant) service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-414d56313100': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_AM3S_SERVICE', "note": 'iHealth AM3S Activity Monitor service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-414d56313200': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_AM4_SERVICE', "note": 'iHealth AM4 Activity Monitor service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-424653563232': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_HS2S_SERVICE', "note": 'iHealth HS2S body-composition scale service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-424756343200': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_BG5S_SERVICE', "note": 'iHealth Blood Glucose BG5S meter service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-424756343300': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_BG1S_SERVICE', "note": 'iHealth Blood Glucose BG1S meter service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-424c45303100': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_BTM_Primary_SERVICE / UUID_BTM_READ_DATA_SERVICE / UUID_BTM_WRITE_DATA_SERVICE', "note": "iHealth BTM (Bluetooth Module) primary service (BLE01 device family); shared by 'BTM_Primary', 'BTM_READ_DATA', 'BTM_WRITE_DATA' constants in BleConfig.java"},
    '636f6d2e-6a69-7561-6e2e-425041563130': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_AV10_SERVICE', "note": 'iHealth Air Pulse AV10 service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-425041563231': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_AV21_SERVICE', "note": 'iHealth Air Pulse AV21 service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-425042563130': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_ABPM_SERVICE', "note": 'iHealth Ambulatory BP Monitor (ABPM) service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-425056323400': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_BP3L_SERVICE', "note": 'iHealth BP3L Blood Pressure monitor service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-425056323500': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_AV25_SERVICE', "note": 'iHealth Air Pulse AV25 service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-425753563031': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_HS4_SERVICE', "note": 'iHealth HS4 body scale service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-425753563032': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_HS2_SERVICE', "note": 'iHealth HS2 body scale service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-454347563130': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_ECG3_SERVICE', "note": 'iHealth ECG3 (single-lead ECG, model V10) service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-504f31000000': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_PO1_SERVICE', "note": 'iHealth PO1 pulse oximeter service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-504f56313100': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_PO3_SERVICE_128', "note": 'iHealth PO3 pulse oximeter (model V11) 128-bit service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-505433534254': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_PT3_SERVICE', "note": 'iHealth PT3 thermometer service; from BleConfig.java'},
    '636f6d2e-6a69-7561-6e2e-646576000000': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_BG5S_SERVICE_NEW', "note": 'iHealth Blood Glucose BG5S meter (new/dev variant) service; from BleConfig.java'},
    '669aa205-0c08-969e-e211-86ad5062675f': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'GENIUS_BRAKE_SERVICE', "note": 'Tacx Genius smart-trainer brake service'},
    '669aa305-0c08-969e-e211-86ad5062675f': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'VORTEX_BRAKE_SERVICE', "note": 'Tacx Vortex smart-trainer brake service'},
    '669aa405-0c08-969e-e211-86ad5062675f': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'BUSHIDO_BRAKE_SERVICE', "note": 'Tacx Bushido smart-trainer brake service'},
    '669aa501-0c08-969e-e211-86ad5062675f': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'BOOT_SERVICE', "note": 'Tacx bootloader service'},
    '669aa505-0c08-969e-e211-86ad5062675f': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'FLOW_BRAKE_SERVICE', "note": 'Tacx Flow smart-trainer brake service'},
    '669aa605-0c08-969e-e211-86ad5062675f': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'FLUX_BRAKE_SERVICE / FLUX_BRAKE_2_SERVICE', "note": 'Tacx Flux/Flux-2 smart-trainer brake service (shared UUID for both FLUX_BRAKE_SERVICE and FLUX_BRAKE_2_SERVICE)'},
    '669aab01-0c08-969e-e211-86ad5062675f': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'ANT_CHANNEL0_INPUT', "note": 'Tacx ANT+ channel-0 input characteristic (BLE-bridged ANT+)'},
    '669aab02-0c08-969e-e211-86ad5062675f': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'ANT_CHANNEL0_OUTPUT', "note": 'Tacx ANT+ channel-0 output characteristic'},
    '669aab21-0c08-969e-e211-86ad5062675f': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'ANT_C0_BURST_INPUT', "note": 'Tacx ANT+ channel-0 burst input'},
    '669aac01-0c08-969e-e211-86ad5062675f': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'BOOT_CHARACTERISTIC', "note": 'Tacx bootloader characteristic'},
    '6a4e2800-667b-11e3-949a-0800200c9a66': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'MULTI_LINK_SERVICE_UUID', "note": 'Tacx Multi-Link service'},
    '6e40fec1-b5a3-f393-e0a9-e50e24dcca9e': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'FEC_BRAKE_SERVICE', "note": 'Tacx FE-C (ANT+ Fitness Equipment Control) over BLE service; Nordic-UART-base'},
    '6e40fec2-b5a3-f393-e0a9-e50e24dcca9e': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'FEC_RX', "note": 'Tacx FE-C-over-BLE receive characteristic'},
    '6e40fec3-b5a3-f393-e0a9-e50e24dcca9e': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'FEC_TX', "note": 'Tacx FE-C-over-BLE transmit characteristic'},
    '6e40ff02-b5a3-f393-e0a9-e50e24dcca9e': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'NORDIC_UART_LIKE_FF02', "note": 'Nordic-UART-base-UUID variant used by crrepa wristband (com.crrepa.c.a.f252u)'},
    '6e40ff03-b5a3-f393-e0a9-e50e24dcca9e': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'NORDIC_UART_LIKE_FF03', "note": 'Nordic-UART-base-UUID variant used by crrepa wristband (com.crrepa.c.a.f253v)'},
    '6e87b30f-dbf8-4e17-b990-6838744802f1': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'MAIN_TOKEN_2_UUID / MAIN_TOKEN_TWO_CHARACTERISTIC_UUID', "note": 'Continental KAAS Mouse auth token-2 characteristic'},
    '7265632e-6a69-7561-6e2e-424c45303100': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_BTM_WRITE_DATA_CHARACTERISTIC', "note": "iHealth BTM write-data characteristic ('rec.juan.BLE01' ASCII); from BleConfig.java"},
    '7265632e-6a69-7561-6e2e-454347563130': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_ECG3_CHRASTERISTIC_SEND', "note": 'iHealth ECG3 send characteristic; from BleConfig.java'},
    '7265632e-6a69-7561-6e2e-504f31000000': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_PO1_CHRASTERISTIC_SEND', "note": 'iHealth PO1 send characteristic; from BleConfig.java'},
    '7265632e-6a69-7561-6e2e-505433534254': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_PT3_CHRASTERISTIC_SEND', "note": 'iHealth PT3 send characteristic; from BleConfig.java'},
    '7365642e-6a69-7561-6e2e-424c45303100': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_BTM_READ_DATA_CHARACTERISTIC', "note": "iHealth BTM read-data characteristic ('sed.juan.BLE01' ASCII); from BleConfig.java"},
    '7365642e-6a69-7561-6e2e-454347563130': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_ECG3_CHRASTERISTIC_REC', "note": 'iHealth ECG3 receive characteristic; from BleConfig.java'},
    '7365642e-6a69-7561-6e2e-504f31000000': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_PO1_CHRASTERISTIC_REC', "note": 'iHealth PO1 (pulse oximeter) receive characteristic; from BleConfig.java'},
    '7365642e-6a69-7561-6e2e-505433534254': {"company": 'iHealth Labs Inc. (US/Chinese subsidiary of Jiuan Andon Medical) — BLE-connected glucose meters, BP monitors, scales, pulse oximeters; SDK ships in com.ihealth.communication.base.ble', "name": 'UUID_PT3_CHRASTERISTIC_REC', "note": "iHealth PT3 (peak-flow / thermometer 'PT3SBT') receive characteristic; from BleConfig.java"},
    '78053ddb-b876-43d1-8e46-fe8a045f4153': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'MAIN_SYNTHESIS1_UUID / MAIN_SYNTHESIS_CHARACTERISTIC_UUID', "note": 'Continental KAAS Mouse synthesis (vehicle-state aggregate) characteristic'},
    '8ec90001-f315-4f60-9fb8-838830daea50': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'SECURE_DFU_CONTROL_POINT_CHARACTERISTIC', "note": 'Tacx secure-DFU control point characteristic'},
    '8ec90002-f315-4f60-9fb8-838830daea50': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'SECURE_DFU_PACKET_CHARACTERISTIC', "note": 'Tacx secure-DFU packet characteristic'},
    '8ec90003-f315-4f60-9fb8-838830daea50': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'SECURE_BOOT_CHARACTERISTIC', "note": 'Tacx secure-boot characteristic (Nordic Secure DFU 0x8EC9 base)'},
    '937ff18a-5d1c-4c4a-8eaf-d8a1813a12bd': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'BRIDGE_TX_UUID / TFS_FILE_TX_CHARACTERISTIC_UUID', "note": 'Continental KAAS bridge / transfer-file-service TX characteristic'},
    '93b831a8-8335-44b6-8e94-356477aefbbc': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'MAIN_EVENTBYTE_UUID', "note": 'Continental KAAS Mouse event-byte characteristic'},
    'a0db54b8-1582-4c96-beca-d0e3678abd5b': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'BRIDGE_RX_UUID / TFS_FILE_RX_CHARACTERISTIC_UUID', "note": 'Continental KAAS bridge / transfer-file-service RX characteristic'},
    'a57fec9a-1a9b-c0d3-2ebd-1d5c1903befc': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'BLOB_TX_CHARACTERISTIC_UUID', "note": 'Continental KAAS Blob TX characteristic'},
    'a6ed0401-d344-460a-8075-b9e8ec90d71b': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'VEEPOO_DFU_CHAR', "note": 'Veepoo DFU characteristic (com.veepoo.protocol.g.a.f7623h)'},
    'ac010001-328c-a28f-9846-5a8aa212661b': {"company": 'AliveCor Inc. (US; KardiaMobile single-lead ECG; com.alivecor.aliveecg)', "name": 'KARDIA_CARD_SINGLE_LEAD_SERVICE_UUID', "note": 'AliveCor KardiaMobile Card single-lead ECG service'},
    'ac010001-f0a3-a691-444e-2a8ac9345d06': {"company": 'AliveCor Inc. (US; KardiaMobile single-lead ECG; com.alivecor.aliveecg)', "name": 'KARDIA_6L_SINGLE_LEAD_SERVICE_UUID', "note": 'AliveCor KardiaMobile 6L (single-lead mode) ECG service'},
    'ac010002-328c-a28f-9846-5a8aa212661b': {"company": 'AliveCor Inc. (US; KardiaMobile single-lead ECG; com.alivecor.aliveecg)', "name": 'KARDIA_CARD_SINGLE_LEAD_CMD_CHARACTERISTIC_UUID', "note": 'AliveCor KardiaMobile Card single-lead CMD characteristic'},
    'ac010002-f0a3-a691-444e-2a8ac9345d06': {"company": 'AliveCor Inc. (US; KardiaMobile single-lead ECG; com.alivecor.aliveecg)', "name": 'KARDIA_6L_SINGLE_LEAD_CHARACTERISTIC_UUID', "note": 'AliveCor KardiaMobile 6L single-lead ECG characteristic'},
    'ac010003-328c-a28f-9846-5a8aa212661b': {"company": 'AliveCor Inc. (US; KardiaMobile single-lead ECG; com.alivecor.aliveecg)', "name": 'KARDIA_CARD_SINGLE_LEAD_ECG_CHARACTERISTIC_UUID', "note": 'AliveCor KardiaMobile Card single-lead ECG-stream characteristic'},
    'ac060001-328c-a28f-9846-5a8aa212661b': {"company": 'AliveCor Inc. (US; KardiaMobile single-lead ECG; com.alivecor.aliveecg)', "name": 'KARDIA_6L_SIX_LEAD_SERVICE_UUID', "note": 'AliveCor KardiaMobile 6L (six-lead mode) ECG service'},
    'ac060002-328c-a28f-9846-5a8aa212661b': {"company": 'AliveCor Inc. (US; KardiaMobile single-lead ECG; com.alivecor.aliveecg)', "name": 'KARDIA_6L_SIX_LEAD_CMD_CHARACTERISTIC_UUID', "note": 'AliveCor KardiaMobile 6L six-lead CMD characteristic'},
    'ac060003-328c-a28f-9846-5a8aa212661b': {"company": 'AliveCor Inc. (US; KardiaMobile single-lead ECG; com.alivecor.aliveecg)', "name": 'KARDIA_6L_SIX_LEAD_ECG_CHARACTERISTIC_UUID', "note": 'AliveCor KardiaMobile 6L six-lead ECG-stream characteristic'},
    'ac14cd20-5dc9-4b87-3ff6-dc2008be14f8': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'BLOB_SERVICE_UUID', "note": 'Continental KAAS Blob service for RCK device profile'},
    'ad1903e0-1923-dc14-beca-c1d2678aba5b': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'BLOB_RX_CHARACTERISTIC_UUID', "note": 'Continental KAAS Blob RX characteristic'},
    'b4d1dce6-7f8e-4798-a237-b201df522a7e': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'MAIN_SERVICE_UUID', "note": "Continental KAAS (Key-as-a-Service) 'Mouse' main service; SDK package com.continental.kaas.ble.KaasBleProfile.Mouse.MainService; licensed by OTA Keys (Continental subsidiary) to Hyre/Vulog-like car-sharing operators"},
    'c31544c8-92fd-4817-a99b-980284752471': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'SCS_AUTH_TX_CHARACTERISTIC_UUID', "note": 'Continental KAAS SCS auth TX characteristic'},
    'c42c072c-130a-4865-a393-c800d6087abe': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'MAIN_KEY_UUID / MAIN_KEY_CHARACTERISTIC_UUID', "note": 'Continental KAAS Mouse main-key characteristic (digital-key payload)'},
    'cd1903e0-1923-dc14-beca-c1d2678aba5b': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'VDS_RX_CHARACTERISTIC_UUID', "note": 'Continental KAAS VDS RX characteristic'},
    'cf7716ec-e048-44f3-a6b3-995e80b274b9': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'SCS_AUTH_RX_CHARACTERISTIC_UUID', "note": 'Continental KAAS SCS auth RX characteristic'},
    'd2fbdd80-b334-4e4b-9f7b-3ac76cc08b28': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'SCS_SERVICE_UUID', "note": 'Continental KAAS Secure-Channel-Service (SCS) for the Cat / RCK device profiles'},
    'd57fec9a-1a9b-c0d3-2ebd-1d5c1903befc': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'VDS_TX_CHARACTERISTIC_UUID', "note": 'Continental KAAS VDS TX characteristic'},
    'd8a7ae19-4df8-4c1e-9fe4-d47097ad10f7': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'BRIDGE_SERVICE_UUID / TFS_SERVICE_UUID', "note": 'Continental KAAS bridge/transfer-file service (used as Bridge in OtaBleService, as TFS in KaasBleProfile)'},
    'dc14cd20-5dc9-4b87-3ff6-dc2008be14f8': {"company": 'Vulog / Hyre / fleet-mobility SDK (BLE-based vehicle unlock for car-sharing operators; identify the actual vendor from the SDK Java package)', "name": 'VDS_SERVICE_UUID', "note": 'Continental KAAS Vehicle-Data-Service (VDS) for Cat profile'},
    'f0020001-0451-4000-b000-000000000000': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'VEEPOO_SERVICE_F002', "note": 'Veepoo service (com.veepoo.protocol.g.a.f7619d)'},
    'f0030001-0451-4000-b000-000000000000': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'VEEPOO_SERVICE_F003', "note": 'Veepoo service (com.veepoo.protocol.g.a.f7624i)'},
    'f0080001-0451-4000-b000-000000000000': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'VEEPOO_SERVICE_F008', "note": 'Veepoo wristband service (com.veepoo.protocol.g.a.a); TI-base-UUID derivative'},
    'f0080002-0451-4000-b000-000000000000': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'VEEPOO_CHAR_F008_2', "note": 'Veepoo characteristic (com.veepoo.protocol.g.a.f7617b)'},
    'f0080003-0451-4000-b000-000000000000': {"company": 'OPlayer / Crrepa (Chinese fitness-band white-label SDK; covers Crrepo / Maxcio / Smart Vict / similar BLE wearables)', "name": 'VEEPOO_CHAR_F008_3', "note": 'Veepoo characteristic (com.veepoo.protocol.g.a.f7618c)'},
    'fe031000-17d0-470a-8798-4ad3e1c1f35b': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'TACX_TRAINER_SERVICE', "note": 'Tacx Trainer Service (TTS) base'},
    'fe031001-17d0-470a-8798-4ad3e1c1f35b': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'TTS_FEATURE_FLAGS', "note": 'TTS feature-flags characteristic'},
    'fe031002-17d0-470a-8798-4ad3e1c1f35b': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'TTS_GENERAL_STATUS', "note": 'TTS general-status characteristic'},
    'fe031003-17d0-470a-8798-4ad3e1c1f35b': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'TTS_GEAR_STATUS', "note": 'TTS gear-status characteristic'},
    'fe031004-17d0-470a-8798-4ad3e1c1f35b': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'TTS_BUTTON_STATUS', "note": 'TTS button-status characteristic'},
    'fe031005-17d0-470a-8798-4ad3e1c1f35b': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'TTS_BREAKING_STATUS', "note": "TTS breaking-status characteristic (typo 'breaking' is in source; intended 'braking')"},
    'fe031006-17d0-470a-8798-4ad3e1c1f35b': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'TTS_STEERING_ANGLE', "note": 'TTS steering-angle characteristic'},
    'fe03100f-17d0-470a-8798-4ad3e1c1f35b': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'TTS_CONTROL_POINT', "note": 'TTS control-point characteristic'},
    'fe03a000-17d0-470a-8798-4ad3e1c1f35b': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'TACX_PRIVATE_SERVICE', "note": 'Tacx Private Service (TPS) base'},
    'fe03a001-17d0-470a-8798-4ad3e1c1f35b': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'TPS_FEATURE_FLAGS', "note": 'TPS feature-flags characteristic'},
    'fe03a002-17d0-470a-8798-4ad3e1c1f35b': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'TPS_DEBUG_DATA', "note": 'TPS debug-data characteristic'},
    'fe03a003-17d0-470a-8798-4ad3e1c1f35b': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'TPS_SYSTEM_STATUS', "note": 'TPS system-status characteristic'},
    'fe03a00f-17d0-470a-8798-4ad3e1c1f35b': {"company": 'Garmin / Tacx B.V. (Netherlands, Garmin subsidiary) — Tacx smart-trainer SDK / Garmin Connect IQ BLE for fitness equipment', "name": 'TPS_CONTROL_POINT', "note": 'TPS control-point characteristic'},

    # Tuya Smart (Hangzhou) — BLE configuration SDK (com.thingclips.sdk.bluetooth
    # Android SDK; rebranded from Thingclips). UUID base `7475-7961-626c-636f6e666967`
    # decodes ASCII to `tu` `ya` `bl` `config`. Field names SERVER / WRITE / NOTIFY
    # observed in 6 hosts (May 2026 batch 2).
    "00000001-0000-1001-8001-00805f9b07d0": {"company": "Tuya Smart (Hangzhou) — BLE configuration SDK (com.thingclips.sdk.bluetooth Android SDK; rebranded from Thingclips)", "name": "TUYA_BLE_CHAR_00000001", "note": "Tuya BLE config SDK characteristic"},
    "00000002-0000-1001-8001-00805f9b07d0": {"company": "Tuya Smart (Hangzhou) — BLE configuration SDK (com.thingclips.sdk.bluetooth Android SDK; rebranded from Thingclips)", "name": "TUYA_BLE_CHAR_00000002", "note": "Tuya BLE config SDK characteristic"},
    "00001000-7475-7961-626c-636f6e666967": {"company": "Tuya Smart (Hangzhou) — BLE configuration SDK (com.thingclips.sdk.bluetooth Android SDK; rebranded from Thingclips)", "name": "TUYA_BLE_CONFIG_SERVER", "note": "Tuya BLE config service — UUID base `7475-7961-626c-636f6e666967` decodes ASCII to `tu` `ya` `bl` `config`"},
    "00001001-7475-7961-626c-636f6e666967": {"company": "Tuya Smart (Hangzhou) — BLE configuration SDK (com.thingclips.sdk.bluetooth Android SDK; rebranded from Thingclips)", "name": "TUYA_BLE_CONFIG_WRITE",  "note": "Tuya BLE config write characteristic"},
    "00001002-7475-7961-626c-636f6e666967": {"company": "Tuya Smart (Hangzhou) — BLE configuration SDK (com.thingclips.sdk.bluetooth Android SDK; rebranded from Thingclips)", "name": "TUYA_BLE_CONFIG_NOTIFY", "note": "Tuya BLE config notify characteristic"},

    # Brother Industries Ltd. — P-touch label-printer + MFC multi-function-printer
    # BLE service. 3-UUID family in the a76eb9eX-f3ac-4990-84cf-3a94d2426b2b
    # namespace, declared in com.brother.ptouch.sdk.connectio*.
    "a76eb9e0-f3ac-4990-84cf-3a94d2426b2b": {"company": "Brother Industries Ltd. (P-touch / MFC printer SDK; com.brother.ptouch.sdk.connectio* Android SDK)", "name": "BROTHER_PRINTER_TARGET_SERVICE", "note": "Brother P-touch / MFC printer target service"},
    "a76eb9e1-f3ac-4990-84cf-3a94d2426b2b": {"company": "Brother Industries Ltd. (P-touch / MFC printer SDK; com.brother.ptouch.sdk.connectio* Android SDK)", "name": "BROTHER_PRINTER_READ_CHAR",     "note": "Brother P-touch / MFC printer read characteristic"},
    "a76eb9e2-f3ac-4990-84cf-3a94d2426b2b": {"company": "Brother Industries Ltd. (P-touch / MFC printer SDK; com.brother.ptouch.sdk.connectio* Android SDK)", "name": "BROTHER_PRINTER_WRITE_CHAR",    "note": "Brother P-touch / MFC printer write characteristic"},

    # Flic AB (Shortcut Labs, Sweden) — Flic Smart Button BLE service.
    # 00420000-…-8f59-4420-870d-84f3b617e493 namespace; SERVICE / TX / RX.
    # Observed in 7 hosts (5 Segware MySecurity variants, euShield, SoftGuard
    # TeMonitoreo) — alarm-monitoring apps using Flic as panic button.
    "00420000-8f59-4420-870d-84f3b617e493": {"company": "Flic AB (Shortcut Labs, Sweden) — Flic Smart Button BLE service", "name": "FLIC_SERVICE", "note": "Flic Smart Button service UUID"},
    "00420001-8f59-4420-870d-84f3b617e493": {"company": "Flic AB (Shortcut Labs, Sweden) — Flic Smart Button BLE service", "name": "FLIC_TX_CHAR", "note": "Flic Smart Button TX characteristic"},
    "00420002-8f59-4420-870d-84f3b617e493": {"company": "Flic AB (Shortcut Labs, Sweden) — Flic Smart Button BLE service", "name": "FLIC_RX_CHAR", "note": "Flic Smart Button RX characteristic"},

    # Wavelynx Technologies — US commercial access-control reader vendor; BLE
    # credential service shipped via Brivo Android SDK com.brivo.sdk.ble.
    # Observed in 11 unrelated host apps (Nexudus, Sharry, Alarm.com, Rise...).
    "3420d81a-af2c-11e5-bf7f-feff819cdc9f": {"company": "Wavelynx Technologies (US commercial access-control reader vendor; BLE credential service shipped via Brivo Android SDK com.brivo.sdk.ble)", "name": "WAVELYNX_BLE_CREDENTIAL_SERVICE", "note": "Wavelynx BLE credential service — single-UUID service declared in com.brivo.sdk.ble (the same Brivo SDK that bundles Allegion ENGAGE)"},

    # Consmart / qh-tek — Chinese smart-home BLE module vendor. 3-UUID family
    # ffd0/ffd4/ffd5. Used by Noise Sphere, Ryze, and Techlife Pro apps.
    # NOTE: ffd0/ffd4/ffd5 are also used by various other Chinese BLE module
    # vendors; this mapping is suggestive but the host-app context still wins.

    # Android Studio BLE example template — default placeholder UUIDs that
    # developers commonly forget to replace before shipping. Field names
    # SERVICE_UUID_YOU_CAN_CHANGE / CHAR_UUID_YOU_CAN_CHANGE come verbatim
    # from the template's TODO comments. Observed in 4 unrelated Korean
    # abookn-template apps published by xidsystem.
    "12345678-9012-3456-7890-123456789012": {"company": "Android Studio BLE example template (default placeholder UUIDs that developers commonly forget to replace before shipping)", "name": "ANDROID_STUDIO_BLE_TEMPLATE_SERVICE", "note": "Default service UUID from Android Studio's BLE template — `SERVICE_UUID_YOU_CAN_CHANGE`"},
    "12345678-9012-3456-7890-123456789013": {"company": "Android Studio BLE example template (default placeholder UUIDs that developers commonly forget to replace before shipping)", "name": "ANDROID_STUDIO_BLE_TEMPLATE_CHAR",    "note": "Default characteristic UUID from Android Studio's BLE template — `CHAR_UUID_YOU_CAN_CHANGE`"},

    # UniKey Technologies — US smart-lock SDK; com.unikey.sdk Android library
    # used by DMP Joule and other locks. UUID16s 0959/0979/0989/0999 are
    # declared in obfuscated com.unikey.sdk.b.a.c. Phase-5 batch 3 (folders
    # 0036-0040), May 2026.
    "0959": {"company": "UniKey Technologies (US smart-lock SDK; com.unikey.sdk Android library, used by DMP Joule and other locks)", "name": "UNIKEY_SDK_CHAR_0959", "note": "UniKey BLE characteristic"},
    "0979": {"company": "UniKey Technologies (US smart-lock SDK; com.unikey.sdk Android library, used by DMP Joule and other locks)", "name": "UNIKEY_SDK_CHAR_0979", "note": "UniKey BLE characteristic"},
    "0989": {"company": "UniKey Technologies (US smart-lock SDK; com.unikey.sdk Android library, used by DMP Joule and other locks)", "name": "UNIKEY_SDK_CHAR_0989", "note": "UniKey BLE characteristic"},
    "0999": {"company": "UniKey Technologies (US smart-lock SDK; com.unikey.sdk Android library, used by DMP Joule and other locks)", "name": "UNIKEY_SDK_CHAR_0999", "note": "UniKey BLE characteristic"},

    # Nordic UART Service vendor extensions — 6e400004/6e400005 are outside
    # Nordic's officially-published 0001/0002/0003 set. Treated as vendor
    # characteristics in the same namespace. Observed in com.new.eld (ELD).
    "6e400004-b5a3-f393-e0a9-e50e24dcca9e": {"company": "Nordic Semiconductor — Nordic UART Service (NUS) vendor extension (6e400004 is outside Nordic's officially-published 0001/0002/0003 set)", "name": "NORDIC_UART_VENDOR_EXT_6E400004", "note": "Vendor extension of Nordic UART namespace"},
    "6e400005-b5a3-f393-e0a9-e50e24dcca9e": {"company": "Nordic Semiconductor — Nordic UART Service (NUS) vendor extension (6e400005 is outside Nordic's officially-published 0001/0002/0003 set)", "name": "NORDIC_UART_VENDOR_EXT_6E400005", "note": "Vendor extension of Nordic UART namespace"},

    # Govee (Shenzhen Intellirocks Tech) — UUID base `494e5445-4c4c-495f-524f-434b53`
    # decodes ASCII to `INTE` `LLI_` `ROCK` `S_` = `INTELLI_ROCKS_` (Govee parent
    # company is Intellirocks). Phase-5 batch 5 (folders 0046-0050), May 2026.
    "494e5445-4c4c-495f-524f-434b535f2011": {"company": "Govee (Shenzhen Intellirocks Tech) — smart home LED lighting / sensors; Govee Home BLE app", "name": "GOVEE_INTELLIROCKS_CHAR_2011", "note": "Govee BLE characteristic — UUID base decodes ASCII to `INTELLI_ROCKS`"},
    "494e5445-4c4c-495f-524f-434b535f2012": {"company": "Govee (Shenzhen Intellirocks Tech) — smart home LED lighting / sensors; Govee Home BLE app", "name": "GOVEE_INTELLIROCKS_CHAR_2012", "note": "Govee BLE characteristic"},
    "494e5445-4c4c-495f-524f-434b535f2013": {"company": "Govee (Shenzhen Intellirocks Tech) — smart home LED lighting / sensors; Govee Home BLE app", "name": "GOVEE_INTELLIROCKS_CHAR_2013", "note": "Govee BLE characteristic"},
    "494e5445-4c4c-495f-524f-434b535f2014": {"company": "Govee (Shenzhen Intellirocks Tech) — smart home LED lighting / sensors; Govee Home BLE app", "name": "GOVEE_INTELLIROCKS_CHAR_2014", "note": "Govee BLE characteristic"},
    "494e5445-4c4c-495f-524f-434b535f2015": {"company": "Govee (Shenzhen Intellirocks Tech) — smart home LED lighting / sensors; Govee Home BLE app", "name": "GOVEE_INTELLIROCKS_CHAR_2015", "note": "Govee BLE characteristic"},
    "494e5445-4c4c-495f-524f-434b535f4857": {"company": "Govee (Shenzhen Intellirocks Tech) — smart home LED lighting / sensors; Govee Home BLE app", "name": "GOVEE_INTELLIROCKS_CHAR_4857", "note": "Govee BLE characteristic"},

    # Phase 5 / 6 (2026-05): SDK UUIDs recovered by manual decompilation of
    # representative APKs for clusters detected by list_shared_sdk_clusters.
    # Covers HP printer wifi-setup, TZONE temperature loggers, Nix Sensor
    # color devices, June Smart Oven, and ISAAC BoosterControl motorcycle
    # ECU. Each UUID's note field cites the Java source file the name came
    # from.
    '0000fdb4-0000-1000-8000-00805f9b34fb': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'UUID_HP_WIFI_SETUP_SERVICE2', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (HP Wifi Setup Service2)'},
    '0000fe77-0000-1000-8000-00805f9b34fb': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'UUID_HP_WIFI_SETUP_SERVICE', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (HP Wifi Setup Service)'},
    '0000fe78-0000-1000-8000-00805f9b34fb': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'UUID_HP_WIFI_PROXIMITY_SERVICE', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (HP Proximity Service)'},
    '01014a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'ApplianceService', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.ApplianceService - primary appliance/oven service UUID)'},
    '03034a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'JOTAService', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.JOTAService - June OTA Update service UUID)'},
    '0e9a6052-722d-4fcf-b8b7-1b9e2c33617d': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_NETWORK_LAYER_STATUS', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Network Layer Status)'},
    '17d096e0-ea1f-11e5-9dbc-0002a5d5c51b': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_MICRO_AP_CONFIGURATION', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Micro AP Configuration)'},
    '19065dfb-dd4d-47d4-95ca-3fe870e2a193': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_SETUP2_SIGNED_PUBLIC_KEY', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Setup2 Signed Public Key)'},
    '1c7cfacb-7818-c09c-9345-04602070e0cc': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_SCAN_CONTROL_POINT', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Scan Control Point)'},
    '262040ed-6f79-41bb-b657-bff4cb49195a': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_IPV6_ADDRESS', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (IPv6 Address)'},
    '27763b10-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'TZONE_TEMPERATURE_SERVICE', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/OTAService.java (Primary TZONE temperature-logger service; used as service-UUID switch anchor at line 246)'},
    '27763b11-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'SN', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.SN - Serial Number)'},
    '27763b12-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'Interval', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.Interval - advertising interval)'},
    '27763b13-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'Token', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.Token - authentication token)'},
    '27763b14-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'TransmitPower', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.TransmitPower - TX power level)'},
    '27763b15-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'SamplingInterval', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.SamplingInterval)'},
    '27763b16-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'SaveInterval', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.SaveInterval)'},
    '27763b17-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'IsSaveOverwrite', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.IsSaveOverwrite)'},
    '27763b18-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'SavaCount', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.SavaCount - sic, developer typo for SaveCount)'},
    '27763b19-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'Alarm', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.Alarm - high/low temperature alarm thresholds)'},
    '27763b20-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'UTC', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.UTC - UTC time sync)'},
    '27763b21-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'Sysn', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.Sysn - sic, developer typo for Sync)'},
    '27763b22-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'Trip', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.Trip - trip status)'},
    '27763b23-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'ModelVersion', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.ModelVersion)'},
    '27763b24-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'LDOVoltage', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.LDOVoltage - battery voltage)'},
    '27763b25-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'LDOTemp', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.LDOTemp)'},
    '27763b26-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'LDOPower', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.LDOPower)'},
    '27763b27-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'OtherBytes1', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.OtherBytes1)'},
    '27763b28-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'OtherBytes2', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.OtherBytes2)'},
    '27763b29-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'OtherBytes3', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.OtherBytes3)'},
    '27763b2a-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'OtherBytes4', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.OtherBytes4)'},
    '27763b2b-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'OtherBytes5', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.OtherBytes5)'},
    '27763b31-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'SyncMode', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.SyncMode)'},
    '27763b40-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'Name', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.Name - device name)'},
    '27763b41-999c-4d6a-9fc4-c7272be10900': {"company": 'TZONE Digital Technology (Chinese environmental sensor vendor; Bluetooth Temperature/Humidity loggers)', "name": 'Light', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_tzone/sources/com/TZONE/Bluetooth/Temperature/Model/CharacteristicHandle.java (CharacteristicType.Light - light sensor)'},
    '2ef1d671-3628-4879-be74-7d0d9bd31f20': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_WIFI_SCAN_STATE', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Wi-Fi Scan State)'},
    '31014a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'ApplianceService.Status', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.ApplianceService.Status)'},
    '31024a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'ApplianceService.Notification', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.ApplianceService.Notification)'},
    '31034a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'ApplianceService.Command', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.ApplianceService.Command)'},
    '31044a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'ApplianceService.Session', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.ApplianceService.Session)'},
    '31084a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'ApplianceService.Response', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.ApplianceService.Response)'},
    '3475dd00-6c62-4e39-ba7b-92e738bea500': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CHARACTERISTIC_SUCTION_SIDE (duijvelaar)', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (suction-side pressure characteristic)'},
    '3475dd00-6c62-4e39-ba7b-92e738bea501': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CHARACTERISTIC_SUCTION_SIDE', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (suction-side pressure characteristic)'},
    '3475dd01-6c62-4e39-ba7b-92e738bea500': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CHARACTERISTIC_PUMP_STATUS_VALUES (duijvelaar)', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (pump status values)'},
    '3475dd01-6c62-4e39-ba7b-92e738bea501': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CHARACTERISTIC_PUMP_STATUS_VALUES', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (pump status values)'},
    '3475dd02-6c62-4e39-ba7b-92e738bea500': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CHARACTERISTIC_DISCHARGE_SIDE (duijvelaar)', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (discharge-side pressure characteristic)'},
    '3475dd02-6c62-4e39-ba7b-92e738bea501': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CHARACTERISTIC_DISCHARGE_SIDE', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (discharge-side pressure characteristic)'},
    '3475dd03-6c62-4e39-ba7b-92e738bea500': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CHARACTERISTIC_METADATA_VALUES (duijvelaar)', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (metadata values)'},
    '3475dd03-6c62-4e39-ba7b-92e738bea501': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CHARACTERISTIC_METADATA_VALUES', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (metadata values)'},
    '3475dd04-6c62-4e39-ba7b-92e738bea500': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CHARACTERISTIC_CONFIGURATION_DATA (duijvelaar)', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (configuration data)'},
    '3475dd04-6c62-4e39-ba7b-92e738bea501': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CHARACTERISTIC_CONFIGURATION_DATA', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (configuration data)'},
    '3475dd05-6c62-4e39-ba7b-92e738bea500': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CHARACTERISTIC_MESSAGES (duijvelaar)', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (messages characteristic)'},
    '3475dd05-6c62-4e39-ba7b-92e738bea501': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CHARACTERISTIC_MESSAGES', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (messages characteristic)'},
    '3475dd06-6c62-4e39-ba7b-92e738bea500': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CHARACTERISTIC_IO_STATUS (duijvelaar)', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (I/O status)'},
    '3475dd06-6c62-4e39-ba7b-92e738bea501': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CHARACTERISTIC_IO_STATUS', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (I/O status)'},
    '3475f00d-6c62-4e39-ba7b-92e738bea500': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CUSTOM_SERVICE_UUID_STRING (duijvelaar build flavor)', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (Edna pump service - 'duijvelaar' build flavor)"},
    '3475f00d-6c62-4e39-ba7b-92e738bea501': {"company": 'ISAAC (Netherlands; BoosterControl BLE motorcycle ECU controller)', "name": 'EDNA_CUSTOM_SERVICE_UUID_STRING', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_isaac/sources/nl/isaac/boostercontrol/connection/BluetoothLeService.java (Edna pump service - default build flavor)'},
    '361e118a-5524-29b6-0345-b15e12e25b34': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'RestartApplianceService.RestartApplianceCharacteristic', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.RestartApplianceService.RestartApplianceCharacteristic)'},
    '37f5daf8-feb7-427b-a75e-c03faced79e1': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_WIFI_SCAN_SERVICE2', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (HP Wifi Scan Service2)'},
    '380c09f8-9665-417a-bb2b-06cb6a76e784': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_P2P_ID', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (P2P ID)'},
    '43014a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'JOTAService.Begin', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.JOTAService.Begin - June OTA Update Begin)'},
    '43024a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'JOTAService.Data', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.JOTAService.Data - OTA payload)'},
    '43034a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'JOTAService.Complete', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.JOTAService.Complete - OTA complete)'},
    '43044a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'JOTAService.Abort', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.JOTAService.Abort - June OTA Update Abort)'},
    '43054a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'JOTAService.Status', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.JOTAService.Status - OTA status)'},
    '43064a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'JOTAService.BufferSize', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.JOTAService.BufferSize)'},
    '43074a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'JOTAService.Manifest', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.JOTAService.Manifest)'},
    '43094a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'JOTAService.PackageId', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.JOTAService.PackageId)'},
    '430a4a75-6e65-81de-a4b2-940b4c6f6b69': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'JOTAService.VersionVector', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.JOTAService.VersionVector)'},
    '4a21865e-6316-4117-98a1-caabe26e49c8': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_SETUP2_PRINTER_PROPERTIES_EX', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Setup2 Printer Properties (Ex))'},
    '4b804997-afb9-4b27-8155-0c320482076a': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_WIFI_SCAN_RESULT_V2', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Wi-Fi Scan Result - second instance for V2 scan service)'},
    '557fa98c-9a9c-419a-8ae9-729b567bac2b': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_FIRMWARE_VERSION', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Firmware Version)'},
    '562c4b55-087b-4692-b024-4b745c32c95c': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_SCAN_CONTROL_POINT_V2', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Scan Control Point - second instance for V2 scan service)'},
    '58633f16-5cad-46bd-978d-fa0ad01a45ea': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_DEVICE_UUID', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Device UUID)'},
    '72d51000-b0da-4368-952f-dd2a64db5b61': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SPECTRO_SERVICE', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixSpectroDevice.java (primary GATT service for Nix spectrometer devices; switch-case anchor for spectro service)'},
    '72d51001-b0da-4368-952f-dd2a64db5b61': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SPECTRO_USB_NOTIFICATION', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixSpectroDevice.java (developer error string: 'Error registering USB notification')"},
    '72d51106-b0da-4368-952f-dd2a64db5b61': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SPECTRO_FAST_MULTISCAN_1', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixSpectroDevice.java (presence required for 'Device supports fast multi-scan mode' branch)"},
    '72d51107-b0da-4368-952f-dd2a64db5b61': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SPECTRO_FAST_MULTISCAN_2', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixSpectroDevice.java (presence required for 'Device supports fast multi-scan mode' branch)"},
    '72d51108-b0da-4368-952f-dd2a64db5b61': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SPECTRO_FAST_MULTISCAN_3', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixSpectroDevice.java (presence required for 'Device supports fast multi-scan mode' branch)"},
    '72d511fe-b0da-4368-952f-dd2a64db5b61': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SPECTRO_SPECTRAL_DATA', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixSpectroDevice.java (developer error string: 'Error registering spectral data notification')"},
    '72d512ff-b0da-4368-952f-dd2a64db5b61': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SPECTRO_COLOR_DATA', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixSpectroDevice.java (developer error string: 'Error registering color data notification')"},
    '72d513ff-b0da-4368-952f-dd2a64db5b61': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SPECTRO_SETTING_STATUS', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixSpectroDevice.java (developer error string: 'Error registering setting status notification')"},
    '72d51f01-b0da-4368-952f-dd2a64db5b61': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SPECTRO_CONTROL', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixSpectroDevice.java (companion control characteristic to NIX_SPECTRO_SERVICE used in measurement control flow)'},
    '7365a0ae-e596-129d-d84a-88db1ffbcc04': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_WIFI_SCAN_SERVICE', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (HP Wifi Scan Service)'},
    '73fd8f50-626c-4f9b-a52e-b1d226efcf8d': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_IPV4_ADDRESS', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (IPv4 Address)'},
    '776f71f0-91aa-4aaf-8d02-c577a378a301': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_SETUP2_PRINTER_WIRELESS_CONFIGURATION', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Setup2 Printer Wireless Configuration)'},
    '7b74d0f0-c041-4748-a8fb-62cc6422d40b': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_WIFI_CONNECTION_STATUS', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Wifi Connection Status)'},
    '8832ab08-ba2d-0184-004c-68c08e2190bf': {"company": 'June Life Inc. (US; June Smart Oven - acquired by Weber-Stephen)', "name": 'RestartApplianceService', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_june/sources/com/junelife/sdk/cloud/ble/SaberInterpreter.java (SaberInterpreter.RestartApplianceService - restart-oven service)'},
    '8b2dfe37-09f8-4d3e-8871-4dbdb398921e': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_DPP_URI', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Hp Dpp Uri)'},
    '8cec8341-c2b8-4744-b491-6826c665f187': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_SETUP1_NETWORK_CONFIGURATION', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Setup1 Network Configuration)'},
    '8fe0b1c0-ea32-11e5-a4fc-0002a5d5c51b': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_WIFI_INFRASTRUCTURE', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Wifi Infrastructure)'},
    'aec832f7-7dff-4d6e-9b65-5b5bcf753941': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_SETUP1_RSA_PUBLIC_KEY', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Setup1 RSA Public Key)'},
    'b26b9d96-34c8-4fb6-b658-5aa130c78d15': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_ETHERNET_CONNECTION_STATUS', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Ethernet Connection Status)'},
    'bebc4000-c4ba-e4a6-4422-dbb176d3a537': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SENSOR_SERVICE', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixDevice.java (primary GATT service for non-spectro Nix devices; switch-case anchor)'},
    'bebc4001-c4ba-e4a6-4422-dbb176d3a537': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SENSOR_MEASURE', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixDevice.java (paired with NIX_SENSOR_SERVICE in measurement flow at line 474-475)'},
    'bebc4002-c4ba-e4a6-4422-dbb176d3a537': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SENSOR_COLOR_DATA', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixDevice.java (developer error string: 'Error registering color data notification')"},
    'bebc4003-c4ba-e4a6-4422-dbb176d3a537': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SENSOR_LED_CONTROL', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixDevice.java (used inside a(short) which logs 'Error setting device LEDs')"},
    'bebc4004-c4ba-e4a6-4422-dbb176d3a537': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SENSOR_USB_NOTIFICATION', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixDevice.java (developer error string: 'Error registering USB notification')"},
    'bebc4005-c4ba-e4a6-4422-dbb176d3a537': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SENSOR_CONTROL', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixDevice.java (paired with NIX_SENSOR_SERVICE in method l() control flow at line 313-314)'},
    'bebc400b-c4ba-e4a6-4422-dbb176d3a537': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SENSOR_X_COEFFICIENTS', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixDevice.java (developer error string: 'X coefficients characteristic not found')"},
    'bebc400c-c4ba-e4a6-4422-dbb176d3a537': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SENSOR_Y_COEFFICIENTS', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixDevice.java (developer error string: 'Y coefficients characteristic not found')"},
    'bebc400d-c4ba-e4a6-4422-dbb176d3a537': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SENSOR_Z_COEFFICIENTS', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixDevice.java (developer error string: 'Z coefficients characteristic not found')"},
    'bebc400e-c4ba-e4a6-4422-dbb176d3a537': {"company": 'Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)', "name": 'NIX_SENSOR_SERIAL', "note": "Recovered via Phase 5 manual investigation of /tmp/jadx_nix/sources/com/nix/nixsensor_lib/NixDevice.java (developer error string: 'Serial characteristic not found')"},
    'c04e2282-9a2e-47c7-883b-783373f71781': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_PRODUCT_NUMBER', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Product Number)'},
    'c4be737a-c1ed-44a4-b115-b28bddba8f45': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_SETUP1_CONNECTION_STATUS', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Setup1 Connection Status)'},
    'd87a143d-16f7-4c20-9b73-2e24a8dfbcac': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_SETUP1_PRINTER_PROPERTIES', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Setup1 Printer Properties)'},
    'ddbb8ffd-d1b6-bbb5-0f47-87a23630038b': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_WIFI_SCAN_RESULT', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Wi-Fi Scan Result)'},
    'e3e03e12-b51a-4834-836a-916a34e4bc36': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_DNS_SD_DOMAIN_NAME', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (DNS_SD_Domain_Name)'},
    'f5fe7b6c-555b-4627-befe-914af6894519': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_SETUP2_CONNECTION_STATE', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Setup2 Connection State)'},
    'f9f3dad8-2798-44e1-90dd-ebf29c860000': {"company": 'HP Inc. - Smart printer onboarding (HP Smart app uses BLE to bootstrap printer WiFi credentials)', "name": 'HP_DPP_JWT', "note": 'Recovered via Phase 5 manual investigation of /tmp/jadx_radius/sources/com/hp/sdd/wifisetup/ble_rx/rx_gatt_kt/GattAttributes.java (Hp Dpp JWT)'},
    # ------------------------------------------------------------
    # Phase-4/5 identifications (AndroZoo BLUETOOTH_SCAN batch 1, 2026-09):
    '06d1e5e7-79ad-4a71-8faa-373789f7d93c': {"company": 'SumUp', "name": 'DATA_CHARACTERISTIC', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    '0d9ad298-29ad-493b-b2cd-09a96c3ef209': {"company": 'Square', "name": 'UUID_CHARACTERISTIC_READ_ACK_VECTOR', "note": 'Square Reader BLE GATT profile, declared in com.squareup.cardreader.ble.R12Gatt (R12 contactless+chip reader). Appears in unrelated apps because they bundle the Square Reader SDK.'},
    '0f38f03d-d91c-49c1-a8b0-1b2ba0f01e3a': {"company": 'Square', "name": 'UUID_CHARACTERISTIC_READ_MTU', "note": 'Square Reader BLE GATT profile, declared in com.squareup.cardreader.ble.R12Gatt (R12 contactless+chip reader). Appears in unrelated apps because they bundle the Square Reader SDK.'},
    '11a7a236-d841-42d1-a99c-061c6e909bf9': {"company": 'SumUp', "name": 'GMX_PIN_LITE_SERVICE', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    '11a7a236-d841-42d1-a99c-061c6e909bfa': {"company": 'SumUp', "name": 'GMX_PIN_LITE_V2_SERVICE', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    '11a7a236-d841-42d1-a99c-061c6e909bfb': {"company": 'SumUp', "name": 'GMX_PIN_CLESS_SERVICE', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    '134441a1-384e-4100-9c1d-d0cff27c5a60': {"company": 'SumUp', "name": 'SOLO_SERVICE', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    '1581ee61-0815-4b7c-b117-bed8758fee7c': {"company": 'Square', "name": 'Unknown', "note": 'Square Reader BLE GATT profile, declared in com.squareup.cardreader.ble.R12Gatt (R12 contactless+chip reader). Appears in unrelated apps because they bundle the Square Reader SDK.'},
    '1610': {"company": 'Sciener', "name": 'UUID_SERVICE_DOOR_SENSOR', "note": "TTLock smart-lock SDK (com.ttlock.bl.sdk); UUIDs declared in BluetoothImpl.java and the bundled Telink BLE stack. The UUID 73631912-6965-6e65-7269-736669727374 is ASCII for 'scienerisfirst', confirming the vendor."},
    '1710': {"company": 'Sciener', "name": 'UUID_SERVICE', "note": "TTLock smart-lock SDK (com.ttlock.bl.sdk); UUIDs declared in BluetoothImpl.java and the bundled Telink BLE stack. The UUID 73631912-6965-6e65-7269-736669727374 is ASCII for 'scienerisfirst', confirming the vendor."},
    '1911': {"company": 'Sciener', "name": 'UUID_SERVICE', "note": "TTLock smart-lock SDK (com.ttlock.bl.sdk); UUIDs declared in BluetoothImpl.java and the bundled Telink BLE stack. The UUID 73631912-6965-6e65-7269-736669727374 is ASCII for 'scienerisfirst', confirming the vendor."},
    '1f6b14c9-97fa-4f1e-aaa6-7e152fdd04f4': {"company": 'SumUp', "name": 'READ_FROM_PERIPHERAL_CHARACTERISTIC', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    '22ffc547-1bef-48e2-aa87-b87e23ac0bbd': {"company": 'SumUp', "name": 'POWER_STATE_CHARACTERISTIC', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    '2d9d68c9-52fa-407b-8a8f-ca406ac390b7': {"company": 'SumUp', "name": 'SOLO_UL_SERVICE', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    '3da610ae-e21a-415b-a030-d1a21a693805': {"company": 'SumUp', "name": 'WRITE_TO_PERIPHERAL_CHARACTERISTIC', "note": 'SumUp Solo reader characteristic set, declared in com.sumup.reader.core.pinplus.transport.BtSmartSoloTransport. Same SDK as the larger SumUp cluster.'},
    '4e6efab4-7028-49d4-8458-95e69a93607d': {"company": 'SumUp', "name": 'PINCSR_WAKE_CHARACTERISTIC', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    '55ff336e-df4b-46c5-a49d-7403a537a101': {"company": 'Kogenta', "name": 'KETTLE_BEACON_ADVERTISING_UUID', "note": "Identified by decompiling Kolumbus.Sanntid.Android: literal appears in p014b3/q.java building an iBeacon-shaped advert, alongside com/kogenta/kettle/core/model/config/BeaconHardwareFilterConfiguration.java. Kogenta's Kettle is a documented Android/iOS beacon-proximity SDK (developer.kogenta.com)."},
    '55ff336e-df4b-46c5-a49d-7403a537a108': {"company": 'Kogenta', "name": 'KETTLE_BEACON_SCAN_FILTER_UUID', "note": 'Identified by decompiling Kolumbus.Sanntid.Android: hardcoded default in com/kogenta/kettle/core/model/config/BeaconHardwareFilterConfiguration.java and used as a ScanFilter in i5/k.java next to the Eddystone service UUID 0000feaa-0000-1000-8000-00805f9b34fb.'},
    '59b935ad-c2d4-465c-9683-9cbb9c5181cb': {"company": 'Square', "name": 'UUID_CHARACTERISTIC_READ_DATA', "note": 'Square Reader BLE GATT profile, declared in com.squareup.cardreader.ble.R12Gatt (R12 contactless+chip reader). Appears in unrelated apps because they bundle the Square Reader SDK.'},
    '6e400001-b5a3-f393-e0a9-e50e24dcca1e': {"company": 'Sciener', "name": 'BONG_SERVICE', "note": "TTLock smart-lock SDK (com.ttlock.bl.sdk); UUIDs declared in BluetoothImpl.java and the bundled Telink BLE stack. The UUID 73631912-6965-6e65-7269-736669727374 is ASCII for 'scienerisfirst', confirming the vendor."},
    '6e400002-b5a3-f393-e0a9-e50e24dcca1e': {"company": 'Sciener', "name": 'BONG_WRITE', "note": "TTLock smart-lock SDK (com.ttlock.bl.sdk); UUIDs declared in BluetoothImpl.java and the bundled Telink BLE stack. The UUID 73631912-6965-6e65-7269-736669727374 is ASCII for 'scienerisfirst', confirming the vendor."},
    '6e400003-b5a3-f393-e0a9-e50e24dcca1e': {"company": 'Sciener', "name": 'BONG_READ', "note": "TTLock smart-lock SDK (com.ttlock.bl.sdk); UUIDs declared in BluetoothImpl.java and the bundled Telink BLE stack. The UUID 73631912-6965-6e65-7269-736669727374 is ASCII for 'scienerisfirst', confirming the vendor."},
    '73631912-6965-6e65-7269-736669727374': {"company": 'Sciener', "name": 'SERVICE_UUID', "note": "TTLock smart-lock SDK (com.ttlock.bl.sdk); UUIDs declared in BluetoothImpl.java and the bundled Telink BLE stack. The UUID 73631912-6965-6e65-7269-736669727374 is ASCII for 'scienerisfirst', confirming the vendor."},
    '73632b12-6965-6e65-7269-736669727374': {"company": 'Sciener', "name": 'CHARACTERISTIC_UUID_WRITE', "note": "TTLock smart-lock SDK (com.ttlock.bl.sdk); UUIDs declared in BluetoothImpl.java and the bundled Telink BLE stack. The UUID 73631912-6965-6e65-7269-736669727374 is ASCII for 'scienerisfirst', confirming the vendor."},
    '83668364-6e2e-11e5-b8fe-24a074e98014': {"company": 'Square', "name": 'UUID_CHARACTERISTIC_COMMS_VERSION', "note": 'Square Reader BLE GATT profile, declared in com.squareup.cardreader.ble.R12Gatt (R12 contactless+chip reader). Appears in unrelated apps because they bundle the Square Reader SDK.'},
    '9276298f-ada0-4eee-b5fd-ffb7ee974d61': {"company": 'SumUp', "name": 'POWER_STATE_CHARACTERISTIC', "note": 'SumUp Solo reader characteristic set, declared in com.sumup.reader.core.pinplus.transport.BtSmartSoloTransport. Same SDK as the larger SumUp cluster.'},
    '928a1007-c7b4-431e-b240-490bc916bdc5': {"company": 'Square', "name": 'UUID_CHARACTERISTIC_WRITE_DATA', "note": 'Square Reader BLE GATT profile, declared in com.squareup.cardreader.ble.R12Gatt (R12 contactless+chip reader). Appears in unrelated apps because they bundle the Square Reader SDK.'},
    'b378db85-4ec3-4daa-828e-1b99607bd6a0': {"company": 'SumUp', "name": 'WRITE_TO_PERIPHERAL_CHARACTERISTIC', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    'bc2f4cc6-aaef-4351-9034-d66268e328f0': {"company": 'SumUp', "name": 'Unknown', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    'bc2f4cc6-aaef-4351-9034-d66268e328f1': {"company": 'SumUp', "name": 'GMX_WUBLE_SERVICE_UUID', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    'd1f4c2d0-f8c2-4565-9349-e0312effd1ee': {"company": 'SumUp', "name": 'PINCSR_DATA_CHARACTERISTIC', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    'd329a8cb-b872-4c13-971b-72bca85ef0cd': {"company": 'SumUp', "name": 'PINCSR_STATE_CHARACTERISTIC', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    'd839fc3c-84dd-4c36-9126-187b07255125': {"company": 'SumUp', "name": 'BP_55_PIN_SERVICE', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    'd839fc3c-84dd-4c36-9126-187b07255126': {"company": 'SumUp', "name": 'UUID_SERVICE_DATECS', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    'd839fc3c-84dd-4c36-9126-187b07255127': {"company": 'SumUp', "name": 'AIR_PIN_SERVICE', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    'd839fc3c-84dd-4c36-9126-187b07255128': {"company": 'SumUp', "name": 'AIR_LITE_V2_SERVICE', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    'd839fc3c-84dd-4c36-9126-187b07255129': {"company": 'SumUp', "name": 'AIR_V3_SERVICE', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    'd839fc3c-84dd-4c36-9126-187b07255130': {"company": 'SumUp', "name": 'AIR_V4_SERVICE', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    'dc13a2d0-94e7-4f03-985e-74ff2f786aba': {"company": 'SumUp', "name": 'READ_FROM_PERIPHERAL_CHARACTERISTIC', "note": 'SumUp Solo reader characteristic set, declared in com.sumup.reader.core.pinplus.transport.BtSmartSoloTransport. Same SDK as the larger SumUp cluster.'},
    'e0ab0dd2-88bf-11e5-a9da-24a074e98014': {"company": 'Square', "name": 'UUID_CHARACTERISTIC_SERVICE_VERSION', "note": 'Square Reader BLE GATT profile, declared in com.squareup.cardreader.ble.R12Gatt (R12 contactless+chip reader). Appears in unrelated apps because they bundle the Square Reader SDK.'},
    'e0c56d1c-be88-4ada-ae89-42feb563f4e9': {"company": 'Square', "name": 'UUID_CHARACTERISTIC_CONNECTION_CONTROL', "note": 'Square Reader BLE GATT profile, declared in com.squareup.cardreader.ble.R12Gatt (R12 contactless+chip reader). Appears in unrelated apps because they bundle the Square Reader SDK.'},
    'e3bbc0ac-6ab5-4d40-a86c-f6ab146c9b4b': {"company": 'SumUp', "name": 'GMX_PINCSR_SERVICE', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    'e3bbc0ac-6ab5-4d40-a86c-f6ab146c9b4c': {"company": 'SumUp', "name": 'GMX_PINCSR_WAKE_FIX_SERVICE', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    'eee76878-4864-47ab-b5d7-3d6791a5725b': {"company": 'Square', "name": 'UUID_CHARACTERISTIC_BOND_STATUS', "note": 'Square Reader BLE GATT profile, declared in com.squareup.cardreader.ble.R12Gatt (R12 contactless+chip reader). Appears in unrelated apps because they bundle the Square Reader SDK.'},
    'f421aa0b-55a5-4073-86f9-458139ef2c71': {"company": 'SumUp', "name": 'CONNECT_CHARACTERISTIC', "note": 'SumUp Solo reader characteristic set, declared in com.sumup.reader.core.pinplus.transport.BtSmartSoloTransport. Same SDK as the larger SumUp cluster.'},
    'f953144b-e33a-4079-b202-e3d7c1f3dbb0': {"company": 'SumUp', "name": 'CONNECT_CHARACTERISTIC', "note": 'SumUp card-reader SDK (com.sumup.reader.core.pinplus.transport); UUIDs declared in BtSmartPinPlusTransport/BtSmartAirTransport/BtSmartSoloTransport for the SumUp Air, Solo and PIN+ readers. Appears in unrelated apps because they bundle the SumUp payments SDK.'},
    'fb973fb2-e496-4954-8fdc-cc49455a5ca7': {"company": 'Square', "name": 'UUID_CHARACTERISTIC_READ_CONN_INTERVAL', "note": 'Square Reader BLE GATT profile, declared in com.squareup.cardreader.ble.R12Gatt (R12 contactless+chip reader). Appears in unrelated apps because they bundle the Square Reader SDK.'},
}


# ---------------------------------------------------------------------------
# Bluetooth SIG member_uuids.yaml integration
# ---------------------------------------------------------------------------

# Where the Bluetooth SIG public assigned-numbers tree lives on this machine.
# member_uuids.yaml is the canonical list of SIG-allocated UUID16s assigned
# to specific vendor companies (e.g. 0xFDE3 → "Abbott Diabetes Care").
DEFAULT_SIG_ASSIGNED_NUMBERS = os.path.expanduser(
    "~/Blue2thprinting/Analysis/public/assigned_numbers/uuids/member_uuids.yaml"
)


def load_curated_clues_uuids(path: str | None) -> set[str]:
    """Read a curated CLUES_data_human_verified.json and return the set of UUIDs it
    already documents (lowercased). The skill skips any UUID in this set
    on output — those entries are human-verified and authoritative; we
    never want to risk degrading them by re-emitting auto-extracted
    versions for the same UUIDs.

    Returns an empty set if the file is missing or unreadable; the skill
    then operates without the safety net (logged at startup)."""
    p = path or DEFAULT_CURATED_CLUES
    if not p:
        return set()
    data = load_clues(p)
    out: set[str] = set()
    for rec in data:
        u = rec.get("UUID")
        if isinstance(u, str):
            out.add(u.lower())
    return out


def load_member_uuids(yaml_path: str | None) -> dict[str, str]:
    """Parse member_uuids.yaml into a dict {uuid16_hex_lower: company_name}.

    Doesn't pull in a YAML library — the file is shaped simply enough that a
    50-line regex parse is fine, and the script otherwise has zero non-stdlib
    deps. Returns an empty dict if the file is missing.
    """
    path = yaml_path or DEFAULT_SIG_ASSIGNED_NUMBERS
    if not os.path.isfile(path):
        return {}
    out: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return {}
    # The file has blocks like:
    #    - uuid: 0xFDE3
    #      name: Abbott Diabetes Care
    # or
    #    - uuid: 0xFDE2
    #      name: "Abbott Diabetes Care"
    # Use a flat regex over the whole text — order matters and pairs are
    # always uuid-then-name on consecutive lines per the SIG file.
    block_re = re.compile(
        r"-\s*uuid:\s*0x([0-9A-Fa-f]{4})\s*\n\s*name:\s*(?:\"([^\"]+)\"|([^\n]+))",
        re.MULTILINE,
    )
    for m in block_re.finditer(text):
        u = m.group(1).lower()
        name = (m.group(2) or m.group(3) or "").strip()
        if name:
            out[u] = name
    return out


def company_from_member_uuids(
    package_id: str,
    found_uuid16s: set[str],
    member_uuids: dict[str, str],
) -> str | None:
    """Pick the best SIG-official member name for this app based on the
    UUID16s found in it — but only when the candidate name shares at least
    one significant word with the package id's tokens.

    Why the overlap gate matters: many 16-bit UUIDs in the member range
    belong to companies whose SDK / GATT profile gets embedded in unrelated
    apps. A fitness app (`digifit.android.virtuagym.pro.forgefit24`) that
    happens to reference a Taobao-registered UUID16 should not be tagged
    as "Taobao" — that UUID came from a shared library, not from the app's
    real vendor. Without the overlap gate we'd misattribute apps to Amazon,
    Bose, Sony, Qualcomm, Taobao, etc. whenever they happen to include
    those vendors' SDKs.

    Strategy:
      1. Collect every member_uuids name corresponding to a UUID16 the app
         actually contains.
      2. Compute set intersection between the name's tokens (≥3-letter
         alpha words) and the package id's tokens. Require ≥1 overlapping
         token.
      3. Among the candidates that survive the overlap gate, pick the one
         with the largest overlap (tie-break: longest name — preferring the
         most-specific official member name, e.g. "Abbott Diabetes Care"
         over just "Abbott").
      4. If no candidate survives the overlap gate → return None (caller
         falls back to the package-name heuristic, which is the right
         choice when the only member_uuids hits are shared-library UUIDs).
    """
    pkg_tokens = set(package_tokens(package_id))
    if not pkg_tokens:
        return None
    candidate_overlaps: list[tuple[int, str]] = []
    seen: set[str] = set()
    for u16 in found_uuid16s:
        u = u16.lower()
        if u not in member_uuids:
            continue
        name = member_uuids[u]
        if name in seen:
            continue
        seen.add(name)
        name_tokens = set(re.findall(r"[A-Za-z]{3,}", name.lower()))
        overlap = len(name_tokens & pkg_tokens)
        if overlap >= 1:
            candidate_overlaps.append((overlap, name))
    if not candidate_overlaps:
        return None
    # Highest overlap wins; tie-break by longest name (prefer the more
    # specific official subsidiary like "Abbott Diabetes Care" over "Abbott").
    candidate_overlaps.sort(key=lambda x: (-x[0], -len(x[1]), x[1]))
    return candidate_overlaps[0][1]


def name_semantic_score(name: str | None) -> int:
    """Heuristic score for how human-meaningful a candidate UUID_name is.
    Used when the same UUID is seen in multiple APKs with different Java
    field names — we want `LED_COLOR_UUID` to win over `f15558a` or `I`.

    Score ranges 0..100. Higher is better:
      0    : missing / placeholder ("Unknown", "", None)
      1-5  : looks like a minified jadx alias (single letter, `f` + digits,
             all-numeric, or 1-2 chars). These are leftovers of an
             obfuscator that stripped the original identifier.
      6-20 : short but plausible word, no separators.
      20-50: has at least one word boundary (underscore, dot, camelCase
             transition).
      50+  : long, multi-word, contains domain-specific tokens
             (SERVICE / CHARACTERISTIC / UUID / VENDOR_*).
    """
    if not name or name == "Unknown":
        return 0
    s = name.strip()
    if not s:
        return 0
    # Kotlin-decomp temp variables score zero — they look syntactically
    # plausible (camelCase, multi-word) but carry no semantic content. If a
    # better name reaches the merge step it must win unconditionally.
    # Catches both exact-match temps (`parcelUuidFromString`) and numbered
    # variants (`parcelUuidFromString2/3/…`).
    if _is_rejected_field_name(s):
        return 0
    # Minified jadx alias detector.
    if re.fullmatch(r"[a-z]", s.lower()):
        return 1
    if re.fullmatch(r"f\d+[A-Za-z]?", s):
        return 2
    if s.isdigit():
        return 3
    if len(s) <= 2:
        return 5
    # Count word-boundary signals.
    word_boundaries = (
        s.count("_") + s.count("-") + s.count(" ") + s.count(".")
        + len(re.findall(r"(?<=[a-z])(?=[A-Z])", s))
    )
    has_domain_tokens = bool(re.search(
        r"\b(SERVICE|CHARACTERISTIC|CHAR|DESC|DESCRIPTOR|UUID|UUID16|UUID128"
        r"|GATT|ADVERT|SCAN|BEACON|VENDOR|MFG|MANUFACTURER)\b",
        s, re.IGNORECASE,
    ))
    base = 6 + min(len(s), 30)
    if word_boundaries:
        base += 15 + min(word_boundaries * 3, 15)
    if has_domain_tokens:
        base += 20
    return min(base, 100)


# Names that look like Java identifiers but carry no semantic content — they
# are decompiler artifacts (temp variables generated by the Kotlin compiler
# when it lowers `let { … }` blocks; jadx exposes them verbatim). Observed in
# Intesis BLEManager and many Kotlin BLE wrappers:
#
#   ParcelUuid parcelUuidFromString = ParcelUuid.fromString("0000BAF0-…");
#   Intrinsics.checkNotNullExpressionValue(parcelUuidFromString, …);
#   serviceUUID = parcelUuidFromString;
#
# `parcelUuidFromString` is the LHS the assignment regex captures first, but
# the *real* name is `serviceUUID` on the next line. Rejecting these temp
# names lets the alias-propagation pass (below) substitute the terminal
# field. Pattern is case-insensitive; matches the whole identifier only
# (not a substring) so legitimate names like `myUuidFromString` would still
# need to contain the literal token to be rejected — which doesn't happen
# in real decompiled code.
REJECT_FIELD_NAMES = frozenset({
    # Kotlin-decomp temps (most common form):
    "uuidfromstring", "parceluuidfromstring",
    # Misc generic temps the compiler emits for boxed types:
    "stringbuilder", "tostring", "fromstring",
    # Things that show up as LHS but are actually method names or hashes:
    "hashcode", "getuuid", "geturl", "getbytes",
})

# Reject prefixes — when the Kotlin compiler lowers multiple `let { … }`
# blocks in the same scope it numbers the temps `parcelUuidFromString`,
# `parcelUuidFromString2`, `parcelUuidFromString3`, etc. These all carry
# the same lack of semantic content as the unnumbered form, so we reject
# any name that starts with a known prefix and ends in optional digits.
# Observed in real corpus on edfec62e-…-2a32 / 2a33 (Climax KPT32 BL3
# device families) and 6e400003-…-e80060 (Tobit OmniBike spiral-lock).
REJECT_FIELD_PREFIXES = (
    "uuidfromstring", "parceluuidfromstring",
)

# Bare GATT role words and their numbered variants — these are what
# decompiled Java often emits as the LHS of a `getCharacteristic(...)` /
# `getService(...)` sink call when the developer didn't name the field.
# They carry no semantic content beyond "this is a characteristic"; the
# UUID's role is already encoded in `UUID_usage_array`. Without rejecting
# them, the GATT-sink LHS recovery (and other backfill paths) would
# promote `characteristic`, `characteristic2`, `service`, etc. to
# UUID_name. Observed leakage on the May 2026 corpus when sink-LHS was
# first added.
REJECT_BARE_ROLE_WORDS = frozenset({
    "service", "characteristic", "char", "desc", "descriptor", "gatt",
})


def _is_rejected_field_name(name: str) -> bool:
    """True if `name` is in REJECT_FIELD_NAMES exact-match set OR is a
    numbered/decorated variant of a REJECT_FIELD_PREFIXES token OR is a
    bare GATT role word / numbered variant thereof. The decoration after
    the prefix must be only digits/letters that don't add semantic
    content."""
    if not name:
        return False
    n = name.lower()
    if n in REJECT_FIELD_NAMES:
        return True
    if n in REJECT_BARE_ROLE_WORDS:
        return True
    for pre in REJECT_FIELD_PREFIXES:
        if n.startswith(pre):
            tail = n[len(pre):]
            if tail == "" or tail.isdigit() or re.fullmatch(r"\d+[a-z]?", tail):
                return True
    # Numbered variants of bare role words: characteristic2, service3, char5.
    for role in REJECT_BARE_ROLE_WORDS:
        if n.startswith(role):
            tail = n[len(role):]
            if tail.isdigit() or re.fullmatch(r"\d+[a-z]?", tail):
                return True
    return False


def uuid_name_from_field(field_name: str | None) -> str | None:
    """Turn the Java identifier captured at the UUID's declaration site
    into the CLUES `UUID_name` value.

    Philosophy: prefer the developer's original name verbatim — `LED_COLOR_UUID`
    is more useful than `LED COLOR` because it's grep-able back to the source.
    Only do *minimal* cleanup: strip Java member-variable prefixes (`m` /
    `s` followed by a capital letter) and trailing `_UUID` / `Uuid`. Leave
    underscores, casing, and role words (SERVICE / CHARACTERISTIC) alone —
    they're semantically meaningful in the field name and the user can
    cross-reference back to the decompiled Java.

    Returns `None` for empty / 1-2 char / pure-numeric / minified-jadx
    aliases (caller will keep UUID_name as 'Unknown' for those and the
    merge step will replace it once a better candidate shows up).
    """
    if not field_name:
        return None
    s = field_name.strip()
    if not s:
        return None
    # Reject Kotlin-decomp temp variable names — they look like real
    # identifiers but the developer never wrote them; jadx generates them
    # when lowering `let { ... }` / `apply { ... }` blocks (and numbers
    # them parcelUuidFromString2/3/… when multiple appear in the same
    # scope). The alias-propagation pass should already have substituted
    # the terminal field before this point, but if it didn't, we must
    # not promote a temp to a CLUES UUID_name.
    if _is_rejected_field_name(s):
        return None
    # Strip Java member-variable / static-field prefixes.
    if re.fullmatch(r"m[A-Z][A-Za-z0-9_]*", s):
        s = s[1:]
    elif re.fullmatch(r"s[A-Z][A-Za-z0-9_]*", s):
        s = s[1:]
    # Strip the trailing `_UUID` / `Uuid` decoration — it's redundant with
    # the UUID itself being the record key, and the existing CLUES style
    # doesn't repeat it. BUT: if stripping leaves a single bare role word
    # (`service`, `char`, `descriptor`), keep the suffix so the name still
    # disambiguates — `serviceUUID` is meaningful, `service` alone is not.
    # Observed in Intesis BLEManager (`baf0 → serviceUUID`, ground truth).
    stripped = re.sub(r"[_-]?UUIDS?$", "", s, flags=re.IGNORECASE)
    stripped = re.sub(r"Uuids?$", "", stripped)
    stripped = stripped.strip("_-. ")
    if stripped and stripped.lower() not in {
        "service", "char", "characteristic", "desc", "descriptor", "gatt",
    }:
        s = stripped
    if not s:
        return None
    # Re-check after suffix-stripping; some names reduce to a reject token.
    if _is_rejected_field_name(s):
        return None
    # Reject obvious minified-jadx leftovers.
    if len(s) <= 2:
        return None
    if re.fullmatch(r"f\d+[A-Za-z]?", s):
        return None
    if s.isdigit():
        return None
    return s

# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

def find_aapt() -> str:
    """Return path to aapt, or raise SystemExit if not found."""
    p = shutil.which("aapt")
    if p:
        return p
    candidates = sorted(
        glob.glob("/opt/homebrew/share/android-commandlinetools/build-tools/*/aapt")
        + glob.glob("/usr/local/share/android-commandlinetools/build-tools/*/aapt")
        + glob.glob(
            os.path.expanduser("~/Library/Android/sdk/build-tools/*/aapt")
        ),
        reverse=True,
    )
    if candidates:
        return candidates[0]
    sys.exit(
        "ERROR: aapt not found on PATH or under "
        "/opt/homebrew/share/android-commandlinetools/build-tools/*/aapt. "
        "Install with `brew install android-commandlinetools`."
    )


def find_jadx() -> str:
    p = shutil.which("jadx")
    if p:
        return p
    sys.exit(
        "ERROR: jadx not found on PATH. Install with `brew install jadx` "
        "(needs version 1.5+ for native .xapk support)."
    )


# ---------------------------------------------------------------------------
# APK inspection (aapt)
# ---------------------------------------------------------------------------

def aapt_dump(aapt: str, cmd: str, apk_path: str) -> str:
    try:
        proc = subprocess.run(
            [aapt, "dump", cmd, apk_path],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ""
    return proc.stdout


def extract_base_apk_from_xapk(xapk_path: str, dest_dir: str) -> str | None:
    """For an XAPK, extract just the base APK (the one whose entry in
    manifest.json has id='base') into dest_dir and return that path.
    Returns None if it can't find a base APK."""
    import zipfile
    try:
        with zipfile.ZipFile(xapk_path) as z:
            names = z.namelist()
            # Try the official manifest.json route.
            if "manifest.json" in names:
                try:
                    manifest = json.loads(z.read("manifest.json").decode("utf-8"))
                    for entry in manifest.get("split_apks", []):
                        if entry.get("id") == "base":
                            inner = entry["file"]
                            if inner in names:
                                z.extract(inner, dest_dir)
                                return os.path.join(dest_dir, inner)
                except Exception:
                    pass
            # Fallback: take the largest .apk
            apk_entries = [n for n in names if n.endswith(".apk") and "config." not in n]
            if not apk_entries:
                apk_entries = [n for n in names if n.endswith(".apk")]
            if not apk_entries:
                return None
            largest = max(apk_entries, key=lambda n: z.getinfo(n).file_size)
            z.extract(largest, dest_dir)
            return os.path.join(dest_dir, largest)
    except (zipfile.BadZipFile, OSError):
        return None


def get_apk_metadata(aapt: str, apk_path: str) -> dict | None:
    """Returns dict with package_id, version_code (int), version_name (str),
    has_bt_perm (bool). Returns None if aapt failed."""
    badging = aapt_dump(aapt, "badging", apk_path)
    if not badging:
        return None
    pkg = vc = vn = None
    for line in badging.splitlines():
        if line.startswith("package: "):
            m = re.search(r"name='([^']+)'", line)
            if m: pkg = m.group(1)
            m = re.search(r"versionCode='([^']+)'", line)
            if m: vc = m.group(1)
            m = re.search(r"versionName='([^']+)'", line)
            if m: vn = m.group(1)
            break
    if pkg is None:
        return None
    # Cast version_code to int per schema; fall back to -1 if non-numeric.
    try:
        vc_int = int(vc) if vc else -1
    except ValueError:
        vc_int = -1
    perms = aapt_dump(aapt, "permissions", apk_path)
    has_bt = any(p in perms for p in BT_PERMS)
    return {
        "package_id": pkg,
        "version_code": vc_int,
        "version_name": vn or "Unknown",
        "has_bt_perm": has_bt,
    }


# ---------------------------------------------------------------------------
# Decompilation
# ---------------------------------------------------------------------------

def jadx_command(
    jadx: str,
    apk_path: str,
    out_dir: str,
    *,
    show_bad_code: bool = False,
    threads: int | None = None,
) -> list[str]:
    """The jadx invocation. predecompile_apks.py builds its command here too,
    so pre-decompiled output is what this script would have produced itself."""
    cmd = [
        jadx,
        "--no-res",
        "--no-debug-info",
        "--log-level", "error",
    ]
    if show_bad_code:
        # Phase-5 deep RE needs partially-decompiled methods too. JADX often
        # hides exactly the interesting callback/listener body behind an
        # UnsupportedOperationException unless this flag is enabled.
        cmd.append("--show-bad-code")
    if threads:
        cmd.extend(["-j", str(threads)])
    cmd.extend(["-d", out_dir, apk_path])
    return cmd


def run_jadx(
    jadx: str,
    apk_path: str,
    out_dir: str,
    timeout_sec: int,
    *,
    show_bad_code: bool = False,
) -> bool:
    """Returns True on success/partial-success, False if jadx aborted entirely."""
    cmd = jadx_command(jadx, apk_path, out_dir, show_bad_code=show_bad_code)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False
    output = "\n".join((proc.stdout or "", proc.stderr or ""))
    sources_exist = os.path.isdir(os.path.join(out_dir, "sources"))
    if not sources_exist:
        return False

    # Match predecompile_apks.py: JADX 1.5 uses exit code 3 both for its
    # normal completed-with-errors result and for a JVM OOM. The completion
    # line preserves valid partial output; a fatal JVM OOM or any other
    # non-zero exit can leave a `sources/` directory but is not reusable.
    if "Terminating due to java.lang.OutOfMemoryError" in output:
        return False
    if proc.returncode == 0:
        return True
    return (
        proc.returncode == 3
        and "ERROR - finished with errors, count:" in output
    )


def jadx_output_dir(
    jadx: str,
    apk_path: str,
    scan_target: str,
    tmp_root: str,
    timeout_sec: int,
    *,
    show_bad_code: bool = False,
    predecompiled: tuple[str, ...] | None = (),
) -> tuple[str | None, bool]:
    """Return (directory holding jadx's `sources/`, reused?).

    Reuses the APK's predecompile_apks.py entry when a valid one exists (looked
    up by the original APK/XAPK path, not the extracted base APK); otherwise
    runs jadx into tmp_root. `predecompiled` lists extra roots to search, or is
    None to never reuse. A directory entry is shared: callers only read it and
    must not delete it. An archive entry is unpacked into tmp_root, where jadx
    would have written, and goes when tmp_root does. Returns (None, False) if
    jadx failed."""
    if predecompiled is not None and predecompiled_cache is not None:
        hit = predecompiled_cache.find_predecompiled(
            apk_path, show_bad_code=show_bad_code, extra_roots=predecompiled)
        if hit:
            src = predecompiled_cache.materialize(
                hit, os.path.join(tmp_root, "jadx_predecompiled"))
            if src:
                return src, True
    jadx_out = os.path.join(tmp_root, "jadx_out")
    os.makedirs(jadx_out, exist_ok=True)
    if not run_jadx(jadx, scan_target, jadx_out, timeout_sec, show_bad_code=show_bad_code):
        return None, False
    return jadx_out, False


# ---------------------------------------------------------------------------
# UUID scanning
# ---------------------------------------------------------------------------

_THIRD_PARTY_PATH_FRAGMENTS = (
    # Library paths that contribute UUIDs we don't care about (workmanager,
    # firebase, google-play-services, kotlin stdlib, networking libs).
    f"{os.sep}androidx{os.sep}",
    f"{os.sep}com{os.sep}google{os.sep}",
    f"{os.sep}firebase{os.sep}",
    f"{os.sep}kotlinx{os.sep}",
    f"{os.sep}kotlin{os.sep}",
    f"{os.sep}okhttp3{os.sep}",
    f"{os.sep}okio{os.sep}",
    f"{os.sep}retrofit2{os.sep}",
    f"{os.sep}javax{os.sep}",
    f"{os.sep}org{os.sep}bouncycastle{os.sep}",
    f"{os.sep}_COROUTINE{os.sep}",
)


def iter_java_files(root: str) -> Iterable[str]:
    root_norm = os.path.normpath(root) + os.sep
    for dirpath, _dirnames, filenames in os.walk(root):
        # Normalize so the prefix-strip-by-root works.
        rel = dirpath[len(root_norm):] if dirpath.startswith(root_norm) else dirpath
        rel_padded = os.sep + rel + os.sep
        if any(frag in rel_padded for frag in _THIRD_PARTY_PATH_FRAGMENTS):
            continue
        for fn in filenames:
            if fn.endswith(".java"):
                yield os.path.join(dirpath, fn)


def classify(line_window: str, anchor_line: str | None = None) -> str:
    """Return 'GATT Service', 'GATT Characteristic', or 'Unknown'.

    If `anchor_line` is supplied (typically the single source line that holds
    the UUID literal we are classifying), evidence on that line is checked
    first and wins — only on a same-line tie do we fall back to the wider
    window. This matters for files that declare both services and
    characteristics next to each other (e.g. Abbott Libre3's DCSGKSConstants
    with 3 services + 12 characteristics in a 30-line block): the wider window
    is dominated by whichever is more numerous, but the field name on the
    UUID's own line is the authoritative source.
    """
    if anchor_line is not None:
        s_anchor = len(SERVICE_HINT_RE.findall(anchor_line))
        c_anchor = len(CHARACTERISTIC_HINT_RE.findall(anchor_line))
        if c_anchor > s_anchor:
            return "GATT Characteristic"
        if s_anchor > c_anchor:
            return "GATT Service"
    s_hits = len(SERVICE_HINT_RE.findall(line_window))
    c_hits = len(CHARACTERISTIC_HINT_RE.findall(line_window))
    if c_hits > s_hits:
        return "GATT Characteristic"
    if s_hits > 0:
        return "GATT Service"
    return "Unknown"


def normalize_uuid(u: str) -> str:
    return u.lower().strip()


_PACKAGE_DECL_RE = re.compile(r"^\s*package\s+([A-Za-z_][A-Za-z0-9_.]*)\s*;", re.MULTILINE)


def _java_package_of(text: str) -> str | None:
    """Return the `package x.y.z` declaration from a Java source string,
    or None if the file has no package line. Used by scan_one_file to
    record where each UUID literal was *declared* — separately from the
    host APK's package_id. The two are usually different when the UUID
    comes from a bundled third-party SDK (e.g. UUIDs declared in
    `com.ondo.ocssmartlibrary.*` while the host APK package_id is
    `sesame.smartspaces.d2i.co`)."""
    m = _PACKAGE_DECL_RE.search(text)
    return m.group(1) if m else None


_SKIDATA_REGION_UUID_ARG_RE = re.compile(
    r"\s*Identifier\s*\.\s*fromUuid\s*\(\s*UUID\s*\.\s*fromString\s*\(\s*"
    r"(?P<quote>['\"])(?P<uuid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?P=quote)\s*\)\s*\)\s*",
    re.DOTALL,
)


def _skidata_region_uuid_occurrences(
    source: str, java_package: str | None
) -> list[tuple[str, int, int]]:
    """Find only inline scan UUID literals in Skidata's AltBeacon Region calls.

    LocalizationBeaconServiceImpl passes these UUIDs to Identifier.fromUuid
    while constructing advertising Regions. Scope by the exact SDK package,
    class, and imported AltBeacon types; returning source spans lets a separate
    occurrence with the same UUID at a real GATT sink remain eligible.
    """
    if java_package != "com.skidata.mobileflow_plugin.service":
        return []
    if not re.search(r"\bclass\s+LocalizationBeaconServiceImpl\b", source):
        return []
    required_imports = (
        "com.external.altbeacon.beacon.Identifier",
        "com.external.altbeacon.beacon.Region",
    )
    if any(
        not re.search(rf"^\s*import\s+{re.escape(name)}\s*;", source, re.MULTILINE)
        for name in required_imports
    ):
        return []

    occurrences: list[tuple[str, int, int]] = []
    for region_call in re.finditer(r"\bnew\s+Region\s*\(", source):
        open_idx = region_call.end() - 1
        close_idx = _find_matching_paren_on_line(source, open_idx)
        if close_idx is None:
            continue
        args = _split_top_level_java_args(source[open_idx + 1:close_idx])
        if len(args) < 2:
            continue
        uuid_arg = _SKIDATA_REGION_UUID_ARG_RE.fullmatch(args[1])
        if not uuid_arg:
            continue
        arg_start = source.find(args[1], open_idx + 1, close_idx)
        if arg_start < 0:
            continue
        occurrences.append((
            normalize_uuid(uuid_arg.group("uuid")),
            arg_start + uuid_arg.start("uuid"),
            arg_start + uuid_arg.end("uuid"),
        ))
    return occurrences


_SKIDATA_SCAN_FILTER_UUID_ARG_RE = re.compile(
    r"\s*new\s+ParcelUuid\s*\(\s*UUID\s*\.\s*fromString\s*\(\s*"
    r"(?P<quote>['\"])(?P<uuid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?P=quote)\s*\)\s*\)\s*",
    re.DOTALL,
)


def _skidata_scan_filter_occurrence_spans(
    source: str,
    java_package: str | None,
    region_uuid_values: set[str],
) -> set[tuple[int, int]]:
    """Find same-valued Skidata advertisement-filter occurrences only.

    GattBeaconServiceImpl also places six Region identifiers into Android
    ScanFilter.Builder.setServiceUuid calls. Match those values against the
    sibling Region source facts and exclude only these ScanFilter argument
    spans; other occurrences in this class remain eligible for GATT tracing.
    """
    if not region_uuid_values or java_package != "com.skidata.mobileflow_plugin.service":
        return set()
    if not re.search(r"\bclass\s+GattBeaconServiceImpl\b", source):
        return set()
    required_imports = (
        "android.bluetooth.le.ScanFilter",
        "android.os.ParcelUuid",
    )
    if any(
        not re.search(rf"^\s*import\s+{re.escape(name)}\s*;", source, re.MULTILINE)
        for name in required_imports
    ):
        return set()

    spans: set[tuple[int, int]] = set()
    call_re = re.compile(
        r"\bnew\s+ScanFilter\s*\.\s*Builder\s*\(\s*\)\s*"
        r"\.\s*setServiceUuid\s*\("
    )
    for filter_call in call_re.finditer(source):
        open_idx = filter_call.end() - 1
        close_idx = _find_matching_paren_on_line(source, open_idx)
        if close_idx is None:
            continue
        args = _split_top_level_java_args(source[open_idx + 1:close_idx])
        if len(args) != 1:
            continue
        uuid_arg = _SKIDATA_SCAN_FILTER_UUID_ARG_RE.fullmatch(args[0])
        if not uuid_arg or normalize_uuid(uuid_arg.group("uuid")) not in region_uuid_values:
            continue
        arg_start = source.find(args[0], open_idx + 1, close_idx)
        if arg_start < 0:
            continue
        spans.add((
            arg_start + uuid_arg.start("uuid"),
            arg_start + uuid_arg.end("uuid"),
        ))
    return spans


def _java_brace_spans(text: str) -> list[tuple[int, int]]:
    """Return Java brace pairs while ignoring braces inside comments/strings."""
    stack: list[int] = []
    spans: list[tuple[int, int]] = []
    i = 0
    state = "code"
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "line-comment":
            if ch == "\n":
                state = "code"
        elif state == "block-comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 1
        elif state in {"string", "char"}:
            if ch == "\\":
                i += 1
            elif (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                state = "code"
        elif ch == "/" and nxt == "/":
            state = "line-comment"
            i += 1
        elif ch == "/" and nxt == "*":
            state = "block-comment"
            i += 1
        elif ch == '"':
            state = "string"
        elif ch == "'":
            state = "char"
        elif ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            spans.append((stack.pop(), i))
        i += 1
    return spans


def _mask_java_source(text: str, *, preserve_literals: bool) -> str:
    """Mask comments (and optionally literals) without changing source offsets."""
    out = list(text)
    i = 0
    state = "code"
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state in {"line-comment", "block-comment"}:
            if ch != "\n":
                out[i] = " "
            if state == "line-comment" and ch == "\n":
                state = "code"
            elif state == "block-comment" and ch == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                state = "code"
                i += 1
        elif state in {"string", "char"}:
            if not preserve_literals and ch != "\n":
                out[i] = " "
            if ch == "\\":
                if not preserve_literals and i + 1 < len(text) and text[i + 1] != "\n":
                    out[i + 1] = " "
                i += 1
            elif (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                state = "code"
        elif ch == "/" and nxt == "/":
            out[i] = out[i + 1] = " "
            state = "line-comment"
            i += 1
        elif ch == "/" and nxt == "*":
            out[i] = out[i + 1] = " "
            state = "block-comment"
            i += 1
        elif ch == '"':
            if not preserve_literals:
                out[i] = " "
            state = "string"
        elif ch == "'":
            if not preserve_literals:
                out[i] = " "
            state = "char"
        i += 1
    return "".join(out)


def _nested_uuid_type_roles(text: str) -> dict[str, tuple[str, str]]:
    """Infer weak UUID roles from their immediate nested Java type name.

    This is limited to UUID assignments directly declared in a member nested
    class/interface whose own name unambiguously says Service or Characteristic.
    It does not inherit a sibling/outer type name, inspect method locals, or
    override stronger direct GATT evidence.
    """
    # Most UUID-bearing files are unrelated to this structural hint. Keep
    # them on the existing fast path with a cheap regex prefilter; files
    # without a role-bearing class/interface name need no character scans.
    candidate_type_names = re.findall(
        r"(?<!@)\b(?:class|interface)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b",
        text,
        re.IGNORECASE,
    )
    if not any(classify_via_field_name(name) for name in candidate_type_names):
        return {}
    code = _mask_java_source(text, preserve_literals=False)
    source = _mask_java_source(text, preserve_literals=True)
    brace_spans = _java_brace_spans(text)
    close_by_open = {opening: closing for opening, closing in brace_spans}
    type_re = re.compile(
        r"(?<!@)\b(?:class|interface)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b[^{};]*\{",
        re.DOTALL,
    )
    type_spans: list[tuple[int, int, int, str]] = []
    for declaration in type_re.finditer(code):
        opening = declaration.end() - 1
        closing = close_by_open.get(opening)
        if closing is not None:
            type_spans.append((declaration.start(), opening, closing, declaration.group(1)))

    role_names_by_uuid: dict[str, dict[str, set[str]]] = {}
    assignment_patterns = (
        UUID_ASSIGNMENT_RE,
        UUID_STRING_ASSIGNMENT_RE,
        UUID_INSTANCE_STRING_ASSIGNMENT_RE,
        UUID_RAW_STRING_ASSIGNMENT_RE,
    )
    for assignment_re in assignment_patterns:
        for assignment in assignment_re.finditer(source):
            try:
                literal_offset = assignment.start(2)
                uuid = normalize_uuid(assignment.group(2))
            except (IndexError, AttributeError):
                continue
            enclosing_types = [
                span for span in type_spans
                if span[1] < literal_offset < span[2]
            ]
            if not enclosing_types:
                continue
            owner = min(enclosing_types, key=lambda span: span[2] - span[1])
            owner_open, owner_close, owner_name = owner[1], owner[2], owner[3]
            role = classify_via_field_name(owner_name)
            if role not in {"GATT Service", "GATT Characteristic"}:
                continue
            # The literal must be a direct field initializer in the named
            # type, not a local inside a method/initializer or an array body.
            enclosing_braces = [
                span for span in brace_spans
                if span[0] < literal_offset < span[1]
            ]
            if not enclosing_braces:
                continue
            literal_scope = min(enclosing_braces, key=lambda span: span[1] - span[0])
            if literal_scope != (owner_open, owner_close):
                continue
            # Only a direct member nested type qualifies. A local type inside
            # a method or an anonymous block is deliberately out of scope.
            parents = [
                span for span in type_spans
                if span[1] < owner[0] < span[2]
            ]
            if not parents:
                continue
            parent = min(parents, key=lambda span: span[2] - span[1])
            declaration_scope = [
                span for span in brace_spans
                if span[0] < owner[0] < span[1]
            ]
            if not declaration_scope:
                continue
            if min(declaration_scope, key=lambda span: span[1] - span[0])[0] != parent[1]:
                continue
            role_names_by_uuid.setdefault(uuid, {}).setdefault(role, set()).add(owner_name)

    result: dict[str, tuple[str, str]] = {}
    for uuid, role_names in role_names_by_uuid.items():
        if len(role_names) != 1:
            continue
        role, names = next(iter(role_names.items()))
        result[uuid] = (role, f"nested-type:{','.join(sorted(names))}")
    return result


def _uuid_field_in_expression(expression: str, field_to_uuid: dict[str, str]) -> str | None:
    """Resolve an expression only when it names exactly one known UUID field."""
    uuids = {
        field_to_uuid[name]
        for name in re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", expression)
        if name in field_to_uuid
    }
    return next(iter(uuids)) if len(uuids) == 1 else None


def _find_matching_java_paren(source: str, open_index: int) -> int | None:
    """Return a balanced parenthesis in Java source, respecting comments/strings."""
    depth = 0
    state = "code"
    escaped = False
    i = open_index
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if state == "line-comment":
            if ch == "\n":
                state = "code"
        elif state == "block-comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 1
        elif state in {"string", "char"}:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                state = "code"
        elif ch == "/" and nxt == "/":
            state = "line-comment"
            i += 1
        elif ch == "/" and nxt == "*":
            state = "block-comment"
            i += 1
        elif ch == '"':
            state = "string"
        elif ch == "'":
            state = "char"
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


JAVA_METHOD_HEADER_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:public|protected|private)\s+)?"
    r"(?:(?:static|final|synchronized|abstract|native|default|strictfp)\s+)*"
    r"(?:<[^>\n]+>\s*)?[\w.$<>?,\[\]]+\s+"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\("
)


def _java_param_type(param: str) -> str | None:
    """Return a simple Java parameter type when the declaration is clear."""
    clean = re.sub(r"@[\w.$]+(?:\([^)]*\))?\s*", "", param).strip()
    clean = re.sub(r"\b(?:final|volatile|transient)\b\s*", "", clean)
    match = re.search(r"([\w.$<>?,\[\]...]+)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*$", clean)
    if not match:
        return None
    typ = match.group(1).replace("...", "[]")
    typ = re.sub(r"<.*>", "", typ)
    return typ.rsplit(".", 1)[-1].strip()


def _iter_java_method_defs(source: str):
    """Yield (name, params, body) for ordinary braced Java methods."""
    brace_close = dict(_java_brace_spans(source))
    for header in JAVA_METHOD_HEADER_RE.finditer(source):
        name = header.group("name")
        open_index = source.find("(", header.start("name") + len(name))
        if open_index < 0:
            continue
        close_index = _find_matching_java_paren(source, open_index)
        if close_index is None:
            continue
        after = close_index + 1
        while after < len(source) and source[after].isspace():
            after += 1
        if source.startswith("throws", after):
            body_open = source.find("{", after)
            semicolon = source.find(";", after)
            if body_open < 0 or (semicolon >= 0 and semicolon < body_open):
                continue
        else:
            body_open = after if after < len(source) and source[after] == "{" else -1
        body_close = brace_close.get(body_open)
        if body_open < 0 or body_close is None:
            continue
        params = _split_top_level_java_args(source[open_index + 1:close_index])
        yield name, params, source[body_open + 1:body_close]


def _local_uuid_alias_values(body: str, field_to_uuid: dict[str, str]) -> dict[str, set[str]]:
    """Resolve UUID locals to source fields within one method body.

    Branch assignments accumulate possible values; straight-line assignments
    replace them. This is intentionally a small source trace, not general Java
    control-flow or interprocedural analysis.
    """
    ident = r"[A-Za-z_$][A-Za-z0-9_$]*"
    var_types = set(re.findall(rf"\b(?:java\.util\.)?UUID\s+({ident})\b", body))
    aliases: dict[str, set[str]] = {name: set() for name in var_types}
    assignment_re = re.compile(
        rf"(?<![A-Za-z0-9_$])(?:(?:java\.util\.)?UUID\s+)?"
        rf"(?P<lhs>{ident})\s*=\s*(?P<rhs>[^;{{}}]+);"
    )

    def values(expr: str) -> set[str]:
        found = {
            uuid for field, uuid in field_to_uuid.items()
            if re.search(rf"(?<![A-Za-z0-9_$])(?:[A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*)*{re.escape(field)}(?![A-Za-z0-9_$])", expr)
        }
        for name in var_types:
            if aliases.get(name) and re.search(rf"(?<![A-Za-z0-9_$]){re.escape(name)}(?![A-Za-z0-9_$])", expr):
                found.update(aliases[name])
        return found

    depth = 0
    for line in body.splitlines():
        for assignment in assignment_re.finditer(line):
            lhs = assignment.group("lhs")
            if lhs not in var_types:
                continue
            rhs_values = values(assignment.group("rhs"))
            # An assignment inside a branch contributes another possible
            # reaching value. A top-level assignment kills previous values.
            nested = depth + line[:assignment.start()].count("{") - line[:assignment.start()].count("}") > 0
            if nested:
                aliases.setdefault(lhs, set()).update(rhs_values)
            else:
                aliases[lhs] = set(rhs_values)
        depth += line.count("{") - line.count("}")
        depth = max(0, depth)
    return aliases


def _uuid_values_in_expression(
    expression: str, field_to_uuid: dict[str, str], aliases: dict[str, set[str]]
) -> set[str]:
    """Resolve only fields and UUID locals visible in one method."""
    values = {
        uuid for field, uuid in field_to_uuid.items()
        if re.search(rf"(?<![A-Za-z0-9_$])(?:[A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*)*{re.escape(field)}(?![A-Za-z0-9_$])", expression)
    }
    for name, uuids in aliases.items():
        if uuids and re.search(rf"(?<![A-Za-z0-9_$]){re.escape(name)}(?![A-Za-z0-9_$])", expression):
            values.update(uuids)
    return values


def _direct_service_characteristic_pairs(
    text: str,
    field_to_uuid: dict[str, str],
    candidates: dict[str, dict],
) -> dict[str, list[str]]:
    """Pair a characteristic only with the service object used to fetch it.

    This deliberately requires a local BluetoothGattService variable returned
    by getService(...), followed by that same variable's getCharacteristic(...)
    call in the same innermost brace scope. A service lookup elsewhere in a
    file is not parent evidence.
    """
    pairs: dict[str, list[str]] = {}
    assignment_re = re.compile(
        r"\bBluetoothGattService\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
        r"[^;{}]*?\.\s*getService\s*\(\s*([^;{}]*)\)\s*;",
        re.DOTALL,
    )
    for _method_name, _params, body in _iter_java_method_defs(text):
        aliases = _local_uuid_alias_values(body, field_to_uuid)
        spans = _java_brace_spans(body)
        for assignment in assignment_re.finditer(body):
            receiver = assignment.group(1)
            service_uuids = _uuid_values_in_expression(
                assignment.group(2), field_to_uuid, aliases
            )
            service_uuids = {
                uuid for uuid in service_uuids
                if candidates.get(uuid, {}).get("classification") == "GATT Service"
            }
            if len(service_uuids) != 1:
                continue
            enclosing = [
                span for span in spans
                if span[0] < assignment.start() < span[1]
            ]
            scope = (
                min(enclosing, key=lambda span: span[1] - span[0])
                if enclosing else (0, len(body))
            )
            call_re = re.compile(
                rf"\b{re.escape(receiver)}\s*\.\s*getCharacteristic\s*\(\s*([^;{{}}]*)\)",
                re.DOTALL,
            )
            for characteristic_call in call_re.finditer(body, assignment.end(), scope[1]):
                reassigned = re.search(
                    rf"\b{re.escape(receiver)}\s*=(?!=)",
                    body[assignment.end():characteristic_call.start()],
                )
                if reassigned:
                    continue
                char_uuids = _uuid_values_in_expression(
                    characteristic_call.group(1), field_to_uuid, aliases
                )
                if len(char_uuids) != 1:
                    continue
                for char_uuid in char_uuids:
                    char_entry = candidates.get(char_uuid or "")
                    if not char_entry or char_entry.get("classification") != "GATT Characteristic":
                        continue
                    parents = pairs.setdefault(char_uuid, [])
                    for service_uuid in sorted(service_uuids):
                        if service_uuid not in parents:
                            parents.append(service_uuid)
    return pairs


def _typed_gatt_method_models(source: str) -> list[dict]:
    """Describe UUID argument roles proven by typed GATT constructors in methods.

    This records only direct UUID parameters and a same-object relationship:
    a BluetoothGattService is constructed from one parameter, then that exact
    service variable receives a BluetoothGattCharacteristic constructed from
    another. It does not infer roles from method names or parameter names.
    """
    imports = set(re.findall(
        r"(?m)^\s*import\s+(android\.bluetooth\.(?:BluetoothGattService|BluetoothGattCharacteristic))\s*;",
        source,
    ))
    declared_types = set(re.findall(
        r"\b(?:class|interface|enum|record)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b",
        source,
    ))

    def is_android_ctor(type_name: str, simple: str) -> bool:
        return (
            type_name == f"android.bluetooth.{simple}"
            or (
                type_name == simple
                and f"android.bluetooth.{simple}" in imports
                and simple not in declared_types
            )
        )

    models: list[dict] = []
    for name, raw_params, body in _iter_java_method_defs(source):
        params = [_java_param_name(param) for param in raw_params]
        param_types = [_java_param_type(param) for param in raw_params]
        uuid_slots = {
            idx: param
            for idx, (param, typ) in enumerate(zip(params, param_types))
            if param and typ == "UUID"
        }
        if not uuid_slots:
            models.append({
                "name": name, "param_types": param_types,
                "roles": {}, "parent_pairs": set(),
            })
            continue

        slot_by_name = {param: idx for idx, param in uuid_slots.items()}
        local_uuid_vars = set(re.findall(
            r"\b(?:java\.util\.)?UUID\s+([A-Za-z_$][A-Za-z0-9_$]*)\b", body
        )) | set(slot_by_name)
        aliases: dict[str, set[int]] = {param: {idx} for param, idx in slot_by_name.items()}
        alias_assign_re = re.compile(
            r"(?:(?:java\.util\.)?UUID\s+)?"
            r"([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([^;{}]+);"
        )
        for line in body.splitlines():
            for assignment in alias_assign_re.finditer(line):
                lhs, rhs = assignment.group(1), assignment.group(2)
                if lhs not in local_uuid_vars or lhs in slot_by_name:
                    continue
                source_slots = {
                    idx for param, idx in slot_by_name.items()
                    if re.search(rf"(?<![A-Za-z0-9_$]){re.escape(param)}(?![A-Za-z0-9_$])", rhs)
                }
                for alias, slots in aliases.items():
                    if re.search(rf"(?<![A-Za-z0-9_$]){re.escape(alias)}(?![A-Za-z0-9_$])", rhs):
                        source_slots.update(slots)
                aliases.setdefault(lhs, set()).update(source_slots)

        def parameter_slots(expression: str) -> set[int]:
            found: set[int] = set()
            for param, idx in slot_by_name.items():
                if re.search(rf"(?<![A-Za-z0-9_$]){re.escape(param)}(?![A-Za-z0-9_$])", expression):
                    found.add(idx)
            for alias, slots in aliases.items():
                if alias not in slot_by_name and re.search(
                    rf"(?<![A-Za-z0-9_$]){re.escape(alias)}(?![A-Za-z0-9_$])", expression
                ):
                    found.update(slots)
            return found

        roles: dict[int, set[str]] = {}
        parent_pairs: set[tuple[int, int]] = set()
        service_constructions: list[tuple[str, set[int], int, int]] = []
        body_braces = _java_brace_spans(body)
        service_assignment_re = re.compile(
            r"\b(?P<decl>BluetoothGattService|android\.bluetooth\.BluetoothGattService)\s+"
            r"(?P<var>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*new\s+"
            r"(?P<ctor>[A-Za-z_$][A-Za-z0-9_$.]*)\s*\("
        )
        for match in service_assignment_re.finditer(body):
            ctor_type = match.group("ctor")
            if not is_android_ctor(ctor_type, "BluetoothGattService"):
                continue
            open_idx = body.find("(", match.start("ctor"))
            close_idx = _find_matching_java_paren(body, open_idx)
            if close_idx is None:
                continue
            args = _split_top_level_java_args(body[open_idx + 1:close_idx])
            service_slots = parameter_slots(args[0]) if args else set()
            if not service_slots:
                continue
            enclosing = [
                span for span in body_braces
                if span[0] < match.start() < span[1]
            ]
            assignment_scope = (
                min(enclosing, key=lambda span: span[1] - span[0])
                if enclosing else (0, len(body))
            )
            service_constructions.append((
                match.group("var"), service_slots, close_idx + 1, assignment_scope[1]
            ))
            for slot in service_slots:
                roles.setdefault(slot, set()).add("GATT Service")

        for match in NEW_CONSTRUCTOR_START_RE.finditer(body):
            ctor_type = match.group(1)
            ctor_name = ctor_type.rsplit(".", 1)[-1]
            if not is_android_ctor(ctor_type, "BluetoothGattCharacteristic"):
                continue
            open_idx = body.find("(", match.start())
            close_idx = _find_matching_java_paren(body, open_idx)
            if close_idx is None:
                continue
            args = _split_top_level_java_args(body[open_idx + 1:close_idx])
            char_slots = parameter_slots(args[0]) if args else set()
            for slot in char_slots:
                roles.setdefault(slot, set()).add("GATT Characteristic")

        for service_var, service_slots, service_end, scope_end in service_constructions:
            add_re = re.compile(
                rf"(?<![A-Za-z0-9_$]){re.escape(service_var)}\s*\.\s*addCharacteristic\s*\("
            )
            for add_call in add_re.finditer(body, service_end, scope_end):
                intervening = body[service_end:add_call.start()]
                reassigned_or_shadowed = re.search(
                    rf"\b(?:BluetoothGattService|android\.bluetooth\.BluetoothGattService)\s+"
                    rf"{re.escape(service_var)}\b|"
                    rf"(?<![A-Za-z0-9_$]){re.escape(service_var)}\s*=(?!=)",
                    intervening,
                )
                if reassigned_or_shadowed:
                    continue
                open_idx = body.find("(", add_call.start())
                close_idx = _find_matching_java_paren(body, open_idx)
                if close_idx is None:
                    continue
                add_args = _split_top_level_java_args(body[open_idx + 1:close_idx])
                if not add_args:
                    continue
                constructor = NEW_CONSTRUCTOR_START_RE.search(add_args[0])
                if not constructor or not is_android_ctor(
                    constructor.group(1), "BluetoothGattCharacteristic"
                ):
                    continue
                ctor_open = add_args[0].find("(", constructor.start())
                ctor_close = _find_matching_java_paren(add_args[0], ctor_open)
                if ctor_close is None:
                    continue
                ctor_args = _split_top_level_java_args(add_args[0][ctor_open + 1:ctor_close])
                char_slots = parameter_slots(ctor_args[0]) if ctor_args else set()
                for service_slot in service_slots:
                    for char_slot in char_slots:
                        if service_slot != char_slot:
                            parent_pairs.add((service_slot, char_slot))

        models.append({
            "name": name,
            "param_types": param_types,
            "roles": roles,
            "parent_pairs": parent_pairs,
        })
    return models


# Scoped messaging, audio effect and bakery configuration identifiers.
NON_GATT_CLASS_FIELD_HINTS.update({
    ("com.seashels.discover", "Singleton"): frozenset({"APP_ID"}),
    ("com.ce.android.brand.gshmakbakery", "GshmakBakeryProperties"): frozenset({"CLIENT_ID"}),
    ("com.browan.freeppmobile.jni", "AudioDeviceEffect"): frozenset({"EFFECT_TYPE_NULL"}),
    ("com.browan.freeppmobile.jni", "AudioDeviceAndroid"): frozenset({"EFFECT_TYPE_NULL"}),
    ("com.browan.freeppmobile.device.adapter", "LocalAudioDetector"): frozenset({"EFFECT_TYPE_NULL"}),
})

def _seashels_sendbird_hostname_occurrence(java_package, source, line, uuid):
    if java_package == "com.seashels.discover.utility" and re.search(r"\bclass\s+AutoConnectStores\b", source):
        return bool(re.search(r'api-' + re.escape(uuid) + r'\.calls\.sendbird\.com', line, re.I))
    if java_package == "com.seashels.discover.ui.shopper.account.accountDeletion" and re.search(r"\bclass\s+AccountDeletionActivity\b", source):
        return bool(re.search(r'https://api-' + re.escape(uuid) + r'\.sendbird\.com/v3/users/', line, re.I))
    return False

# Scoped edition and beacon-token configuration, not Bluetooth attributes.
NON_GATT_CLASS_FIELD_HINTS.update({
    ("com.equiem.equiemandroid", "BuildConfig"): frozenset({"EQUIEM_EDITION_ID", "UBIPARK_BEACON_TOKEN"}),
    ("com.equiem.equiemandroid", "Config"): frozenset({"editionId"}),
    ("com.equiem.equiemandroid.module.network", "BuildConfig"): frozenset({"EQUIEM_EDITION_ID"}),
    ("com.equiem.equiemandroid.module.network", "Config"): frozenset({"editionId"}),
})


def _equiem_edition_id_occurrence(java_package: str, source: str, line: str, uuid: str) -> bool:
    """Skip edition ID arguments only in the reviewed worker/API call sites."""
    if re.search(r"getService|getCharacteristic|addService|BluetoothGatt", line):
        return False
    scopes = {
        ("com.equiem.equiemandroid", "MainActivity"): "enqueueRegisterMessagingWorker",
        ("com.equiem.equiemandroid.repository", "ProfileRepositoryImpl"): "enqueueDeregisterMessagingWorker",
        ("com.equiem.equiemandroid.messaging", "MessagingService"): "enqueueRegisterMessagingWorker",
        ("com.equiem.equiemandroid.module.network.di", "ModulesKt"): "new API",
    }
    for (package, cls), call in scopes.items():
        if java_package == package and re.search(r"\bclass\s+" + re.escape(cls) + r"\b", source) and call in line:
            pattern = re.escape(call) + r'\([^,]+,\s*"' + re.escape(uuid) + r'"\s*,'
            return bool(re.search(pattern, line, re.I))
    return False


# Source-reviewed configuration and slideshow demo identifiers.
NON_GATT_CLASS_FIELD_HINTS.update({
    ("it.appmynet", "BuildConfig"): frozenset({"COMPANY_ID"}),
    ("com.eegees.app", "EegeesProperties"): frozenset({"CLIENT_ID"}),
})


def _pushd_demo_author_occurrence(java_package: str, source: str, line: str, literal_start: int) -> bool:
    """Skip only the reviewed slideshow example's author-ID argument."""
    if java_package != "defpackage" or not re.search(r"\bclass\s+py1\b", source):
        return False
    if "com.pushd.client.ui.birthday.gift.ComposableSingletons$SlideshowItemsGridKt" not in source:
        return False
    pattern = (r'new\s+TextSlideshowItem\s*\(\s*"[^"\n]*"\s*,\s*'
               r'(?:java\.util\.)?UUID\.fromString\(\s*"(?P<uuid>[0-9a-fA-F-]{36})"')
    return any(match.start("uuid") == literal_start for match in re.finditer(pattern, line))


def scan_one_file(
    path: str,
    external_constructor_param_maps: dict[tuple[str, int], list[str | None]] | None = None,
    external_constructor_param_index: dict[str, list[tuple[int, list[str | None]]]] | None = None,
    external_typed_uuid_pair_roles: dict[tuple[str, int], dict[int, str]] | None = None,
    external_skidata_region_uuid_values: set[str] | None = None,
) -> dict[str, dict]:
    """Returns map: uuid -> {classification, field_name, snippets, parent_candidates}.

    Pipeline:
      1. Whole-file BLE-relevance check (`FILE_LEVEL_BLE_RE` for imports, plus
         a ≥3-`UUID.fromString` fallback for pure-constants classes).
      2. First pass: collect every UUID literal in the file, capture the Java
         identifier it's being assigned to (when a `name = UUID.fromString(...)`
         pattern fits the line), and a local ±8-line context window for the
         classifier.
      3. **Read-the-code pass**: for each captured `name = uuid` pair, search
         the whole file for `getService(name)` / `getCharacteristic(name)` /
         related API calls. A hit here is *authoritative* — beats the
         line-name heuristic, since it's how the Android API actually uses
         the UUID at runtime.
      4. Fall back to the line-anchored / window classifier when no
         authoritative usage exists.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return {}
    # Every candidate below originates from a canonical UUID128 literal;
    # avoid expensive constructor parsing in unrelated Java source files.
    if UUID128_LITERAL_RE.search(text) is None:
        return {}

    gardena_super_pairs = _gardena_api_super_uuid_pairs(text)
    file_is_ble = bool(FILE_LEVEL_BLE_RE.search(text)) or bool(gardena_super_pairs)
    if not file_is_ble:
        n_fromstring = len(UUID_FROMSTRING_LITERAL_RE.findall(text))
        if (MIN_UUID_FROMSTRING_FOR_BLE_FALLBACK
                <= n_fromstring <= MAX_UUID_FROMSTRING_FOR_BLE_FALLBACK):
            file_is_ble = True
    if not file_is_ble:
        # Kotlin/Java "GATT catalog" interfaces commonly declare UUIDs as
        # `public static final String FOO_ID = "uuid-literal"` rather than
        # as UUID instances. Without this branch, the constants-only
        # WedgeGattServices.java pattern (Intellimec aar.sdk.wedge_release,
        # com.intellimec.telematics.pts in May 2026 corpus) would be
        # classified as non-BLE and its UUIDs lost.
        n_string_uuid = len(UUID_STRING_ASSIGNMENT_RE.findall(text))
        if (MIN_UUID_FROMSTRING_FOR_BLE_FALLBACK
                <= n_string_uuid <= MAX_UUID_FROMSTRING_FOR_BLE_FALLBACK):
            file_is_ble = True
    has_svc_class = "BluetoothGattService" in text or "ScanFilter" in text
    has_chr_class = "BluetoothGattCharacteristic" in text
    has_gatt_characteristics_container = bool(
        re.search(r"\b(?:class|interface|object)\s+GattCharacteristics(?:Kt)?\b", text)
    )
    java_package = _java_package_of(text)  # e.g. "com.ondo.ocssmartlibrary.utils"
    is_pc_mouse_device_services = (
        java_package == "com.bluetooth.pc.mouse.keyboard.bluetooth"
        and bool(re.search(r"\bclass\s+DeviceServices\b", text))
    )

    # Pre-pass: build uuid -> method_name map for the
    #   public X getY() { return "uuid"; }
    # pattern. This is the strongest signal we can get for classification:
    # the method name itself describes the UUID's role.
    uuid_to_method_name: dict[str, str] = {}
    for mm in UUID_METHOD_RETURN_RE.finditer(text):
        m_name = mm.group(1)
        m_uuid = normalize_uuid(mm.group(2))
        uuid_to_method_name.setdefault(m_uuid, m_name)

    # Pre-pass: Kotlin @Metadata d2 parser. Translates obfuscated getter
    # names (`a()`, `b()`, `f3812a()`, …) back to the original Kotlin
    # property names (`CHARACTERISTIC_UUID`, `DESCRIPTOR_UUID`, …). Only
    # runs if the file actually contains an `@Metadata(` annotation —
    # cheap gate to avoid the regex+parser on non-Kotlin files. When a
    # mapping exists, rewrite uuid_to_method_name so downstream uses
    # already get the semantic name.
    if "@Metadata(" in text:
        method_to_property = parse_kotlin_metadata_property_map(text)
        if method_to_property:
            for uuid, jvm in list(uuid_to_method_name.items()):
                prop = method_to_property.get(jvm)
                if prop:
                    uuid_to_method_name[uuid] = prop

    # Pre-pass: enum-constant UUIDs.
    #   KONTAKT_DFU_SERVICE("name", UUID.fromString("uuid"))
    #   KDFU_COMMAND(KONTAKT_DFU_SERVICE, UUID.fromString("uuid"), CHAR)
    # The enum constant identifier is the strongest UUID_name signal in
    # SDKs that tabulate their GATT registry as a Java enum class (Kontakt,
    # many others). Done as a whole-text pre-pass because the enum constant
    # often spans multiple lines (per-line scan would miss it). Stored in
    # the same field_to_uuid map as plain assignments, so all downstream
    # name/classification logic just works.
    enum_uuid_to_name: dict[str, str] = {}
    if re.search(r"\benum\s+[A-Za-z_$][A-Za-z0-9_$]*", text):
        for em in ENUM_CONSTANT_UUID_RE.finditer(text):
            e_name = em.group(1)
            e_uuid = normalize_uuid(em.group(2))
            # Don't let a generic enum constant in a non-UUID-y position
            # accidentally clobber a more specific name later — first wins.
            enum_uuid_to_name.setdefault(e_uuid, e_name)

    # Pre-pass: nested-subclass catalog (Climax BL3Characteristic-style).
    #   public static final class FlashLight extends BL3Characteristic {
    #       private FlashLight() { super("uuid-…", "…", null); } }
    # The subclass name IS the semantic UUID name. Cheap gate: file must
    # mention both `super(` and `class … extends`, otherwise no chance.
    subclass_uuid_to_name: dict[str, str] = {}
    if "super(" in text and "extends" in text:
        for sm in NESTED_SUBCLASS_UUID_RE.finditer(text):
            sub_name = sm.group(1)
            sub_uuid = normalize_uuid(sm.group(2))
            subclass_uuid_to_name.setdefault(sub_uuid, sub_name)
    # Kotlin/JADX sometimes inserts a temp before the super-call, so the
    # literal is no longer inside `super("uuid", ...)`:
    #   UUID uuidFromString = UUID.fromString("...");
    #   super(uuidFromString, null);
    # The constructor name is still the sealed-object/subclass label.
    for sub_uuid, sub_name in _nested_subclass_temp_super_names(text).items():
        subclass_uuid_to_name.setdefault(sub_uuid, sub_name)

    # Anonymous singleton/object catalog rows. SleepIQ's decompiled
    # GattProfile.kt lowers `Auth`, `TransferInfo`, and `BulkTransfer`
    # into outer static fields whose anonymous-object bodies contain the
    # only UUID literal.
    anon_object_uuid_to_name: dict[str, str] = {}
    for am in ANON_OBJECT_FIELD_UUID_RE.finditer(text):
        anon_object_uuid_to_name.setdefault(normalize_uuid(am.group(2)), am.group(1))

    # Pre-pass: Kotlin alias propagation. Build a map of
    # `terminal_field <- temp_field` assignments so that after the
    # UUID_ASSIGNMENT_RE pass attaches `parcelUuidFromString` (or similar
    # decomp-temp) to the UUID, we can swap in the terminal field name.
    # Only register aliases where the source name looks like a temp (in
    # REJECT_FIELD_NAMES) — otherwise this would over-eagerly rename
    # legitimate field-to-field copies. Cheap gate: file must mention at
    # least one of the temp names.
    alias_terminal_for: dict[str, str] = {}  # temp_field -> terminal_field
    if any(t in text.lower() for t in ("parceluuidfromstring", "uuidfromstring")):
        for am in ALIAS_PROPAGATION_RE.finditer(text):
            terminal = am.group(1)
            source = am.group(2)
            if _is_rejected_field_name(source) and not _is_rejected_field_name(terminal):
                alias_terminal_for.setdefault(source, terminal)

    # Pre-pass: GATT-sink LHS recovery. When the developer's semantic name
    # is on the LHS of `<field> = service.getCharacteristic(UUID.fromString(...))`,
    # the inline UUID expression carries no name and `UUID_ASSIGNMENT_RE`
    # would either miss the assignment (LHS isn't the UUID's owner) or
    # capture `service` / minified noise. The LHS field name is the right
    # answer. Cheap gate: file must mention getCharacteristic/getService.
    sink_lhs_uuid_to_name: dict[str, str] = {}
    sink_lhs_uuid_to_kind: dict[str, str] = {}
    if "getCharacteristic" in text or "getService" in text:
        for sm in GATT_SINK_LHS_RE.finditer(text):
            lhs = sm.group(1)
            kind = sm.group(2)
            sk_uuid = normalize_uuid(sm.group(3))
            # Hygiene: don't promote rejected temps / generic role words
            # — `service`, `characteristic`, etc. are stripped by
            # `uuid_name_from_field` to `None`, so use that as the filter.
            cleaned = uuid_name_from_field(lhs)
            if not cleaned:
                continue
            sink_lhs_uuid_to_name.setdefault(sk_uuid, lhs)
            sink_lhs_uuid_to_kind.setdefault(
                sk_uuid,
                "GATT Service" if kind == "getService" else "GATT Characteristic",
            )

    # Pre-pass: BLE catalog-map / label-map parsing. Gated on file showing
    # actual Bluetooth context (BleNamesResolver / BluetoothGatt* /
    # mServices / mCharacteristics / attributes.put). Without the gate,
    # generated object registries that happen to use `.put("uuid", "label")`
    # for non-BLE purposes would leak labels into UUID_name.
    catalog_label_for: dict[str, str] = {}  # uuid -> human label
    catalog_kind_for: dict[str, str] = {}   # uuid -> Service/Characteristic
    if BLE_CATALOG_FILE_GATE_RE.search(text):
        # First, build a local-constant map for `IDENT = "uuid";` so
        # `map.put(IDENT, "Label")` rows can be resolved.
        local_str_const: dict[str, str] = {}
        for mm in UUID_STRING_ASSIGNMENT_RE.finditer(text):
            local_str_const.setdefault(mm.group(1), normalize_uuid(mm.group(2)))
        for mm in UUID_RAW_STRING_ASSIGNMENT_RE.finditer(text):
            local_str_const.setdefault(mm.group(1), normalize_uuid(mm.group(2)))
        for cm in BLE_CATALOG_MAP_PUT_RE.finditer(text):
            map_name = cm.group(1) or ""
            uuid_str = cm.group(2)
            ident = cm.group(3)
            label = cm.group(4).strip()
            if not label:
                continue
            if uuid_str:
                c_uuid = normalize_uuid(uuid_str)
            elif ident and ident in local_str_const:
                c_uuid = local_str_const[ident]
            else:
                continue
            catalog_label_for.setdefault(c_uuid, label)
            # Classification hint from the map name: mServices implies
            # Service, mCharacteristics implies Characteristic. Anything
            # else (attributes.put, generic put) leaves it unset so the
            # rest of the pipeline decides.
            mn = map_name.lower()
            if "service" in mn:
                catalog_kind_for.setdefault(c_uuid, "GATT Service")
            elif "characteristic" in mn:
                catalog_kind_for.setdefault(c_uuid, "GATT Characteristic")

    # Pre-pass: SQL INSERT catalog rows. Apps that ship the GATT schema as a
    # SQLite catalog (e.g. Belwith pdqsmart) define UUID → Name → role inside
    # `INSERT INTO Characteristics (...) VALUES (...)` strings. Yields a
    # uuid → (name, classification) map that overrides downstream heuristics.
    uuid_to_sql_catalog: dict[str, tuple[str, str]] = {}
    for sm in UUID_SQL_INSERT_RE.finditer(text):
        for u, n, c in parse_sql_insert(sm.group(1), sm.group(2), sm.group(3)):
            uuid_to_sql_catalog.setdefault(u, (n, c))

    lines = text.splitlines()
    skidata_region_occurrences = _skidata_region_uuid_occurrences(
        text, java_package
    )
    skidata_region_uuid_spans = {
        (start, end) for _, start, end in skidata_region_occurrences
    }
    skidata_region_uuid_values = set(external_skidata_region_uuid_values or ())
    skidata_region_uuid_values.update(uuid for uuid, _, _ in skidata_region_occurrences)
    skidata_scan_filter_spans = _skidata_scan_filter_occurrence_spans(
        text, java_package, skidata_region_uuid_values
    )
    skidata_non_gatt_spans = skidata_region_uuid_spans | skidata_scan_filter_spans
    line_start_offsets: list[int] = []
    if skidata_non_gatt_spans:
        source_offset = 0
        for source_line in text.splitlines(keepends=True):
            line_start_offsets.append(source_offset)
            source_offset += len(source_line)
    nested_type_roles = _nested_uuid_type_roles(text)

    # Pass 1: collect candidates.
    # Map: uuid -> dict(field_name, candidate_classification, snippet, line_idx)
    candidates: dict[str, dict] = {}
    # Also map field_name -> uuid for the usage-trace pass.
    field_to_uuid: dict[str, str] = {}
    # Array-of-UUIDs declarations attach the array variable name to every
    # UUID in the array. Keyed by uuid → array_name (the inverse of
    # field_to_uuid) because one array name applies to N UUIDs.
    array_uuid_to_name: dict[str, str] = {}
    # Strong same-branch labels such as BLE_UUID_IC_RC_FEATURE that appear
    # immediately after a literal in a debug log.
    nearby_log_label_for: dict[str, str] = {}

    for idx, line in enumerate(lines):
        # Capture the (LHS-identifier, UUID) pairs on this line. This is the
        # "read the assignment" step — much more informative than the bare
        # UUID literal alone.
        for am in UUID_ASSIGNMENT_RE.finditer(line):
            f_name = am.group(1)
            f_uuid = normalize_uuid(am.group(2))
            field_to_uuid[f_name] = f_uuid
        # Also capture `private static final String FOO_UUID = "uuid-literal";`
        # declarations — the literal is a string field, not a UUID instance,
        # but the field name still tells us the role.
        for sm in UUID_STRING_ASSIGNMENT_RE.finditer(line):
            f_name = sm.group(1)
            f_uuid = normalize_uuid(sm.group(2))
            field_to_uuid.setdefault(f_name, f_uuid)
        for im in UUID_INSTANCE_STRING_ASSIGNMENT_RE.finditer(line):
            field_to_uuid[im.group(1)] = normalize_uuid(im.group(2))
        # Untyped raw-string UUID assignment inside a static block:
        #   HEART_RATE_MEASUREMENT = "00002a37-…";
        # The class-level declaration `public static String HEART_RATE_MEASUREMENT;`
        # gives no UUID; the static block does. Gated on constant-style LHS
        # (uppercase first char) to avoid matching ordinary string vars.
        for rm in UUID_RAW_STRING_ASSIGNMENT_RE.finditer(line):
            f_name = rm.group(1)
            f_uuid = normalize_uuid(rm.group(2))
            field_to_uuid.setdefault(f_name, f_uuid)
        # Array-of-UUIDs declarations: every UUID in the body picks up the
        # array-variable name as its (shared) field-name hint. Stored
        # separately because the field_to_uuid map is keyed by field name
        # (1:1), but here a single array name applies to N UUIDs.
        for am in UUID_ARRAY_ASSIGNMENT_RE.finditer(line):
            arr_name = am.group(1)
            for um in UUID128_LITERAL_RE.finditer(am.group(2)):
                inner_uuid = normalize_uuid("-".join(um.groups()))
                array_uuid_to_name.setdefault(inner_uuid, arr_name)
        # ScanFilter.Builder().setServiceUuid(...) — capture the enclosing
        # field name (list of scan filters) as the UUID's best label.
        for sf in SCAN_FILTER_BUILDER_RE.finditer(line):
            list_name = sf.group(1)
            sf_uuid = normalize_uuid(sf.group(2))
            array_uuid_to_name.setdefault(sf_uuid, list_name)

        uuid_line_context = None
        uuid_line_classification = None
        for m in UUID128_LITERAL_RE.finditer(line):
            # The schema cannot represent descriptors. Suppress only this
            # literal occurrence when it is directly passed to getDescriptor;
            # another service or characteristic use of the same value stays.
            preceding = lines[max(0, idx - 4):idx]
            if ("getDescriptor" in line or any("getDescriptor" in prev for prev in preceding)) and re.search(
                r"\bgetDescriptor\s*\(\s*(?:java\.util\.)?UUID\s*\.\s*fromString\s*\(\s*['\"]$",
                "\n".join(preceding + [line[:m.start()]]),
            ):
                continue
            # This app's DeviceServices class is a mixed display-name lookup,
            # including SDP IDs, units, and many third-party UUIDs. A map row
            # does not show that this app uses the UUID as a GATT attribute.
            # Skip only that row occurrence; a separate use remains eligible.
            if (is_pc_mouse_device_services
                    and re.search(r"\b(?:services|map)\s*\.\s*put\s*\(\s*\"", line)):
                continue
            # These SBIS profile model annotations link documentation pages;
            # a GUID embedded in a documentation URL is not GATT use.
            if (java_package in {
                    "ru.tensor.sbis.profile_service.controller.employee_profile",
                    "ru.tensor.sbis.profile_service.models.person",
                } and "@Deprecated" in line
                    and "https://online.sbis.ru/opendoc.html?guid=" in line):
                continue
            if skidata_non_gatt_spans:
                literal_span = (
                    line_start_offsets[idx] + m.start(),
                    line_start_offsets[idx] + m.end(),
                )
                if literal_span in skidata_non_gatt_spans:
                    continue
            uuid = normalize_uuid("-".join(m.groups()))
            if _pushd_demo_author_occurrence(java_package, text, line, m.start()):
                continue
            if _equiem_edition_id_occurrence(java_package, text, line, uuid):
                continue
            if _seashels_sendbird_hostname_occurrence(java_package, text, line, uuid):
                continue
            if uuid in DROP_OUTRIGHT_UUIDS:
                continue
            if uuid_line_context is None:
                lo = max(0, idx - 8)
                hi = min(len(lines), idx + 8)
                window = "\n".join(lines[lo:hi])
                log_label = _nearby_ble_log_label(lines, idx)
                uuid_line_context = (window, log_label, bool(NON_GATT_HINT_RE.search(window)))
            window, log_label, has_non_gatt_hint = uuid_line_context
            if log_label:
                nearby_log_label_for.setdefault(uuid, log_label)
            if has_non_gatt_hint and not log_label:
                continue
            assigned_fields = _assigned_fields_for_uuid_on_line(line, uuid)
            # Include named aliases only for exact package/class-scoped
            # non-GATT hints. This catches ANTLR's UUID temp -> parser-field
            # assignments while also allowing an explicit GATT sink on the
            # semantic alias to override the exclusion.
            semantic_hint_fields = _non_gatt_scoped_fields_for_uuid(
                uuid, java_package, text
            )
            fields_for_scope = set(assigned_fields) | semantic_hint_fields
            has_non_gatt_field_name = any(
                _is_non_gatt_field_hint(field, java_package, text)
                for field in fields_for_scope
            )
            has_gatt_sink = any(
                _field_has_gatt_sink(field, text) for field in fields_for_scope
            )
            if has_non_gatt_field_name and not has_gatt_sink and not log_label:
                continue
            if (not has_gatt_sink
                    and _sony_non_gatt_uuid_context(uuid, java_package, text)):
                continue

            # Step 0: SQL catalog row (e.g. INSERT INTO Characteristics).
            # This is the strongest possible signal — the developer literally
            # tabulated UUID → Name → role inside SQLite seed data.
            sql_hit = uuid_to_sql_catalog.get(uuid)
            method_name = uuid_to_method_name.get(uuid)
            cls = None
            cls_source: str | None = None
            if sql_hit and sql_hit[1] in ("GATT Service", "GATT Characteristic"):
                cls = sql_hit[1]
                cls_source = f"sql-catalog:{sql_hit[0]}"
            if cls is None:
                # Step 1: method-return pattern — `public X getY() { return "uuid"; }`
                cls = classify_via_field_name(method_name)
                if cls is not None:
                    cls_source = f"method-name:{method_name}"
            if cls is None:
                # Step 1.5: the LHS field name from the same-line assignment.
                # `field_to_uuid` has already been populated for this line by
                # the assignment pass above. Looking up the current UUID's
                # field name lets `classify_via_field_name` apply its
                # service/char substring rule to camelCase names that
                # SERVICE_HINT_RE / CHARACTERISTIC_HINT_RE don't match —
                # e.g. Tobit's `serviceUuidDevice` / `writeCharacteristicDevice`
                # never trip `_SERVICE\b` or `BluetoothGatt*`, but `classify_via_field_name`
                # sees the lowercase "service" / "characteristic" substring and
                # returns the right role. Was a silent gap pre-2026-05-16.
                lhs_field = next((f for f, u in field_to_uuid.items() if u == uuid), None)
                cls = classify_via_field_name(lhs_field)
                if cls is not None:
                    cls_source = f"field-name:{lhs_field}"
            if cls is None:
                # Step 2: anchor/window heuristics (the existing classifier).
                if uuid_line_classification is None:
                    uuid_line_classification = classify(window, anchor_line=line)
                cls = uuid_line_classification
                if cls != "Unknown":
                    cls_source = "naming-convention"
            if cls is None or cls == "Unknown":
                if not file_is_ble:
                    continue
                if has_chr_class and not has_svc_class:
                    cls = "GATT Characteristic"
                elif has_svc_class and not has_chr_class:
                    cls = "GATT Service"
                elif has_chr_class:
                    cls = "GATT Characteristic"
                else:
                    cls = "GATT Service"
                cls_source = cls_source or "file-level-default"

            nested_evidence = nested_type_roles.get(uuid)
            if (
                nested_evidence
                and classification_source_strength(nested_evidence[1])
                > classification_source_strength(cls_source)
            ):
                cls, cls_source = nested_evidence

            entry = candidates.setdefault(uuid, {
                "classification": cls,
                "field_name": None,
                "snippets": [],
                "parent_candidates": [],
                "declaring_packages": set(),
                "classification_source": cls_source or "naming-convention",
            })
            merge_role_evidence(entry, cls, cls_source)
            entry["snippets"].append(line.strip())
            if java_package:
                entry["declaring_packages"].add(java_package)
            # SQL-catalog name beats everything else — it's an explicit
            # developer-curated label, not a heuristic.
            if sql_hit and sql_hit[0] and entry["field_name"] is None:
                entry["field_name"] = sql_hit[0]
            # Use the method name as the field_name (only if we don't have
            # one already — UUID_ASSIGNMENT_RE takes priority).
            if method_name and entry["field_name"] is None:
                entry["field_name"] = method_name

    # Constructor-label recovery. This must run after the assignment scan
    # because it resolves UUID temp variables (`uuidFromString21`, etc.)
    # through field_to_uuid. Single-UUID rows can use the label directly
    # (Bird / Lovens). Multi-UUID rows are only accepted when the matching
    # constructor body exposes each arg's semantic target field (PAX);
    # otherwise the one shared label would be ambiguous.
    constructor_labels_by_uuid: dict[str, set[str]] = {}
    constructor_field_maps = _constructor_field_maps(text)
    for line in lines:
        for ctor_name, args in _iter_constructor_calls_on_line(line):
            if not args:
                continue
            label = _quoted_constructor_label(args[0])
            if not label:
                continue
            uuid_args: list[tuple[int, str]] = []
            for arg_idx, arg in enumerate(args):
                ident = arg.strip()
                if (
                    re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", ident)
                    and ident in field_to_uuid
                    and _is_rejected_field_name(ident)
                ):
                    uuid_args.append((arg_idx, field_to_uuid[ident]))
            if not uuid_args:
                continue
            if len(uuid_args) == 1:
                constructor_labels_by_uuid.setdefault(uuid_args[0][1], set()).add(label)
                continue
            field_map = constructor_field_maps.get((ctor_name, len(args)), {})
            if not all(arg_idx in field_map for arg_idx, _uuid in uuid_args):
                continue
            by_uuid: dict[str, list[str]] = {}
            for arg_idx, target_uuid in uuid_args:
                by_uuid.setdefault(target_uuid, []).append(field_map[arg_idx])
            for target_uuid, field_names in by_uuid.items():
                suffix = (
                    _shared_field_suffix(field_names)
                    if len(field_names) > 1
                    else field_names[0]
                )
                if suffix:
                    constructor_labels_by_uuid.setdefault(target_uuid, set()).add(f"{label}_{suffix}")
    # A UUID can be intentionally re-used by multiple constructor rows
    # with different labels (Bird's 0x2C00 is both BD_BIRD_SERVICE and
    # BIRD_FLEX_SERVICE). Do not guess between them on first pass.
    constructor_label_for = {
        uuid: next(iter(labels))
        for uuid, labels in constructor_labels_by_uuid.items()
        if len(labels) == 1
    }

    # Lowered-enum row recovery. JADX frequently fails to reconstruct the
    # `enum` modifier but still leaves rows shaped like:
    #   WIFI_CONTROL = new TwinService("WIFI_CONTROL", 1, "uuid");
    #   DISCOVER_CMD = new a("DISCOVER_CMD", 0, uuidFromString);
    # The assignment LHS is authoritative whenever the constructor's first
    # argument repeats the same developer-written label and exactly one UUID
    # argument is present.
    lowered_enum_row_for: dict[str, str] = {}
    for line in lines:
        for lhs, _ctor_name, args in _iter_assigned_constructor_calls_on_line(line):
            if not args or _quoted_constructor_label(args[0]) != lhs:
                continue
            uuid_args: list[str] = []
            for arg in args:
                raw = UUID128_LITERAL_RE.search(arg)
                if raw:
                    uuid_args.append(normalize_uuid("-".join(raw.groups())))
                    continue
                ident = arg.strip()
                if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", ident) and ident in field_to_uuid:
                    uuid_args.append(field_to_uuid[ident])
            if len(uuid_args) == 1:
                lowered_enum_row_for.setdefault(uuid_args[0], lhs)

    # Constructor-parameter role recovery. This handles call sites where
    # the UUID literals are temps but the callee's signature still carries
    # the original semantic names, e.g. SharkNinja's:
    #   return new BluetoothServiceConfiguration(uuid1, uuid2, uuid3, uuid4, ...);
    # whose constructor declares
    #   (... UUID notifyCharacteristicUUID, UUID notifyDescriptorUUID, ...)
    constructor_param_for: dict[str, str] = {}
    constructor_param_roles_by_field: dict[str, set[tuple[str, str, str]]] = {}
    constructor_pair_roles_by_field: dict[str, set[tuple[str, int, str]]] = {}
    constructor_assignment_for: dict[str, str] = {}
    typed_uuid_pair_roles = (
        external_typed_uuid_pair_roles
        if external_typed_uuid_pair_roles is not None
        else _typed_uuid_pair_constructor_roles(text)
    )
    external_params = external_constructor_param_maps or {}
    external_index = external_constructor_param_index
    if external_index is None:
        external_index = _index_constructor_param_maps(external_params)
    local_params: dict[tuple[str, int], list[str | None]] | None = None
    local_index: dict[str, list[tuple[int, list[str | None]]]] | None = None
    paren_cache: list[dict[int, int] | None] = [None]
    for line in lines:
        paren_cache[0] = None
        for ctor_name, args in _iter_constructor_calls_on_line(line, paren_cache):
            pair_slots = typed_uuid_pair_roles.get((ctor_name, len(args)), {})
            for arg_idx, pair_role in pair_slots.items():
                if arg_idx >= len(args):
                    continue
                ident_match = re.fullmatch(
                    r"(?:this\.)?([A-Za-z_$][A-Za-z0-9_$]*)", args[arg_idx].strip()
                )
                if ident_match:
                    constructor_pair_roles_by_field.setdefault(
                        ident_match.group(1), set()
                    ).add((pair_role, arg_idx + 1, ctor_name))
            if local_params is None:
                local_params = _constructor_param_maps(text)
                local_index = _index_constructor_param_maps(local_params)
            assert local_index is not None
            params = _best_constructor_params(ctor_name, len(args), local_params, external_params, local_index, external_index)
            if not params:
                continue
            for arg_idx, arg in enumerate(args):
                if arg_idx >= len(params):
                    continue
                ident = arg.strip()
                if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", ident):
                    continue
                param_name = params[arg_idx]
                role = _gatt_characteristic_entity_param_role(ctor_name, param_name)
                if role:
                    constructor_param_roles_by_field.setdefault(ident, set()).add(
                        (role, ctor_name, param_name)
                    )
                if ident not in field_to_uuid:
                    continue
                # Preserve the existing field-name recovery behavior for
                # decompiler-generated temps; ordinary semantic field names
                # need the role evidence above but no name replacement.
                if not _is_rejected_field_name(ident):
                    continue
                if (
                    not param_name
                    or _is_rejected_field_name(param_name)
                    or _is_generic_constructor_param_name(param_name)
                ):
                    continue
                uuid = field_to_uuid[ident]
                constructor_param_for.setdefault(uuid, param_name)
        for lhs, ctor_name, args in _iter_assigned_constructor_calls_on_line(line, paren_cache):
            if local_params is None:
                local_params = _constructor_param_maps(text)
                local_index = _index_constructor_param_maps(local_params)
            assert local_index is not None
            lhs_kind = classify_via_field_name(lhs)
            params = _best_constructor_params(ctor_name, len(args), local_params, external_params, local_index, external_index)
            if not lhs_kind or not params:
                continue
            has_service_role = any((p or "").lower().startswith("service") for p in params)
            if lhs_kind == "GATT Characteristic" and not has_service_role:
                continue
            generic_uuid_candidates: list[str] = []
            for arg_idx, arg in enumerate(args):
                if arg_idx >= len(params):
                    continue
                ident = arg.strip()
                if not (
                    re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", ident)
                    and ident in field_to_uuid
                    and _is_rejected_field_name(ident)
                ):
                    continue
                param_name = params[arg_idx]
                # For wrappers like BleCharacteristic(serviceId, id), the
                # target field (`writeCharacteristic`) is more informative
                # than the callee's generic second parameter (`id`).
                if _is_generic_constructor_param_name(param_name):
                    if lhs_kind == "GATT Characteristic" and not (param_name or "").lower().startswith("service"):
                        generic_uuid_candidates.append(field_to_uuid[ident])
                    elif lhs_kind == "GATT Service":
                        generic_uuid_candidates.append(field_to_uuid[ident])
            if len(set(generic_uuid_candidates)) == 1:
                constructor_assignment_for.setdefault(generic_uuid_candidates[0], lhs)

    # Alias propagation: replace temp-name UUID entries with their terminal
    # field. Kotlin `let { … }` lowering produces `parcelUuidFromString =
    # ParcelUuid.fromString("…"); serviceUUID = parcelUuidFromString;` —
    # the assignment pass grabbed `parcelUuidFromString` (a temp) as the
    # field name. The terminal `serviceUUID = parcelUuidFromString;` line
    # is captured in `alias_terminal_for`. Walk field_to_uuid, and for any
    # entry whose field name maps through alias_terminal_for, register the
    # terminal name pointing at the same UUID. We *don't* delete the temp
    # entry — leaving it lets the usage-trace pass still work — but we add
    # the terminal so the better name is available for selection.
    for temp_name, terminal in list(alias_terminal_for.items()):
        if temp_name in field_to_uuid:
            target_uuid = field_to_uuid[temp_name]
            field_to_uuid.setdefault(terminal, target_uuid)

    # Resolve constructor argument fields only after Kotlin's UUID-temp aliases
    # have been propagated to semantic fields such as WRITE_UUID.
    constructor_param_roles: dict[str, set[tuple[str, str, str]]] = {}
    for field, evidence in constructor_param_roles_by_field.items():
        uuid = field_to_uuid.get(field)
        if uuid:
            constructor_param_roles.setdefault(uuid, set()).update(evidence)

    constructor_pair_roles: dict[str, set[tuple[str, int, str, str]]] = {}
    for field, evidence in constructor_pair_roles_by_field.items():
        uuid = field_to_uuid.get(field)
        if uuid:
            for role, arg_index, ctor_name in evidence:
                constructor_pair_roles.setdefault(uuid, set()).add(
                    (role, arg_index, ctor_name, field)
                )

    # Backfill field_name (the LHS identifier) onto each entry. A UUID might
    # be assigned to multiple fields in the same file; keep the first one
    # we saw (most likely the canonical declaration).
    # Iterate aliases ahead of temps so the terminal field wins when both
    # exist — i.e. `serviceUUID` is registered before the entry under
    # `parcelUuidFromString` would have been processed.
    for field, uuid in field_to_uuid.items():
        if uuid not in candidates:
            continue
        cur = candidates[uuid]["field_name"]
        if cur is None:
            candidates[uuid]["field_name"] = field
        else:
            # Same-file upgrade: if a later assignment yields a name with
            # a higher semantic score than the one we already attached
            # (e.g. terminal `serviceUUID` after temp `parcelUuidFromString`),
            # take the better one.
            if name_semantic_score(field) > name_semantic_score(cur):
                candidates[uuid]["field_name"] = field
    # Backfill enum-constant identifiers (e.g. KONTAKT_DFU_SERVICE) onto any
    # UUID that's still nameless after the assignment pass. Enum constants
    # carry the same authority as plain assignments — they ARE the developer's
    # declaration — so we register them in field_to_uuid as well, so the
    # usage-trace pass below can spot `EnumName.getUuid()` lookups.
    for uuid, e_name in enum_uuid_to_name.items():
        if uuid in candidates and candidates[uuid]["field_name"] is None:
            candidates[uuid]["field_name"] = e_name
        field_to_uuid.setdefault(e_name, uuid)
    # Backfill lowered-enum row names (Ricoh TwinService/TwinCharacteristic,
    # JADX-failed enum reconstructions, etc.).
    for uuid, row_name in lowered_enum_row_for.items():
        if uuid in candidates:
            cur = candidates[uuid]["field_name"]
            if cur is None or name_semantic_score(row_name) > name_semantic_score(cur):
                candidates[uuid]["field_name"] = row_name
        field_to_uuid.setdefault(row_name, uuid)
    # Backfill nested-subclass names (Climax-style FlashLight/History/etc.).
    # These are *higher* priority than generic field-name backfill because
    # the subclass name was explicitly written by the developer to label the
    # UUID's role — we override existing names if the subclass name has a
    # higher semantic score. We also register in field_to_uuid so the
    # cross-file usage trace can find these.
    for uuid, sub_name in subclass_uuid_to_name.items():
        if uuid in candidates:
            cur = candidates[uuid]["field_name"]
            if cur is None or name_semantic_score(sub_name) > name_semantic_score(cur):
                candidates[uuid]["field_name"] = sub_name
        field_to_uuid.setdefault(sub_name, uuid)
    # Anonymous singleton/object rows (SleepIQ-style Auth/BulkTransfer/etc.).
    for uuid, obj_name in anon_object_uuid_to_name.items():
        if uuid in candidates:
            cur = candidates[uuid]["field_name"]
            if cur is None or name_semantic_score(obj_name) > name_semantic_score(cur):
                candidates[uuid]["field_name"] = obj_name
        field_to_uuid.setdefault(obj_name, uuid)
    # Backfill GATT-sink LHS field names (`this.characteristicAppComm =
    # service.getCharacteristic(UUID.fromString("57420002-..."))`). These
    # come from outside the UUID's own declaration site, but they're a
    # developer-written semantic label. Score-gate against the current
    # best name so we don't downgrade a stronger identifier from elsewhere
    # in the file. Also use the kind hint to classify when no other signal
    # exists.
    for uuid, sink_name in sink_lhs_uuid_to_name.items():
        if uuid in candidates:
            cur = candidates[uuid]["field_name"]
            if cur is None or name_semantic_score(sink_name) > name_semantic_score(cur):
                candidates[uuid]["field_name"] = sink_name
            kind = sink_lhs_uuid_to_kind.get(uuid)
            if kind and candidates[uuid].get("classification") in (None, "Unknown"):
                candidates[uuid]["classification"] = kind
                candidates[uuid]["classification_source"] = f"sink-lhs:{sink_name}"
        field_to_uuid.setdefault(sink_name, uuid)
    # Constructor labels recover semantic names that moved away from the
    # UUID assignment during Kotlin/JADX lowering. Score-gate so a direct
    # developer field name still wins if one exists.
    for uuid, ctor_name in constructor_label_for.items():
        if uuid in candidates:
            cur = candidates[uuid]["field_name"]
            if cur is None or name_semantic_score(ctor_name) > name_semantic_score(cur):
                candidates[uuid]["field_name"] = ctor_name
        field_to_uuid.setdefault(ctor_name, uuid)
    # Cross-file constructor parameter names are developer-authored labels
    # that survive even when the call-site UUID variables are all decomp temps.
    for uuid, param_name in constructor_param_for.items():
        if uuid in candidates:
            cur = candidates[uuid]["field_name"]
            if cur is None or name_semantic_score(param_name) > name_semantic_score(cur):
                candidates[uuid]["field_name"] = param_name
        field_to_uuid.setdefault(param_name, uuid)
    # Assigned wrapper objects can preserve the semantic name on the LHS even
    # when the callee exposes only generic parameter names (`id`, `uuid`).
    for uuid, lhs_name in constructor_assignment_for.items():
        if uuid in candidates:
            cur = candidates[uuid]["field_name"]
            if cur is None or name_semantic_score(lhs_name) > name_semantic_score(cur):
                candidates[uuid]["field_name"] = lhs_name
        field_to_uuid.setdefault(lhs_name, uuid)
    # Strong nearby `BLE_UUID_*` log labels are narrower than prose logs and
    # often the only human-readable name left in heavily obfuscated files.
    for uuid, log_label in nearby_log_label_for.items():
        if uuid in candidates:
            cur = candidates[uuid]["field_name"]
            if cur is None or name_semantic_score(log_label) > name_semantic_score(cur):
                candidates[uuid]["field_name"] = log_label
    # Backfill array-array UUIDs that didn't get a singleton name above.
    for uuid, arr_name in array_uuid_to_name.items():
        if uuid in candidates and candidates[uuid]["field_name"] is None:
            candidates[uuid]["field_name"] = arr_name
    # BLE catalog labels (mServices.put / mCharacteristics.put / attributes.put).
    # The human label is the strongest possible UUID_name signal — it was
    # hand-curated by the developer specifically to describe the UUID. Set
    # unconditionally (overrides every heuristic-derived name) once the
    # BLE-context gate has vetted the file. Same logic for classification:
    # the map name (`mServices` vs `mCharacteristics`) is authoritative,
    # overriding whatever the line-level classifier guessed from imports.
    for uuid, label in catalog_label_for.items():
        if uuid in candidates:
            candidates[uuid]["field_name"] = label
            kind = catalog_kind_for.get(uuid)
            if kind:
                candidates[uuid]["classification"] = kind
                candidates[uuid]["classification_source"] = "catalog-map"
    # SQL-catalog names override any prior backfill: developer-curated > heuristic.
    for uuid, (cat_name, _cls) in uuid_to_sql_catalog.items():
        if uuid in candidates and cat_name:
            candidates[uuid]["field_name"] = cat_name

    # Kotlin/JADX can move the literal into a UUID temporary and only reveal
    # its semantic field name in a later alias assignment. Reapply the field
    # name classifier after that backfill, but only over weak local guesses.
    # `GattCharacteristicsKt` is also a narrowly typed profile container: its
    # neutral UUID fields (for example GeneralPurposeSwitchInputs and
    # SystemStatusState) are characteristics, while explicit `...Service`
    # names above keep their service role.
    for uuid, entry in candidates.items():
        source = entry.get("classification_source", "")
        if source not in {"file-level-default", "naming-convention"}:
            continue
        role_from_name = classify_via_field_name(entry.get("field_name"))
        if role_from_name:
            entry["classification"] = role_from_name
            entry["classification_source"] = f"field-name:{entry['field_name']}"
        elif has_gatt_characteristics_container:
            entry["classification"] = "GATT Characteristic"
            entry["classification_source"] = "characteristics-container:GattCharacteristics"

    # Pass 2: usage trace. For each known field name, look for definitive
    # `getService(name)` / `getCharacteristic(name)` calls anywhere in the
    # file. Authoritative — override whatever the heuristic guessed.
    local_usage_roles: dict[str, set[str]] = {}
    for field, uuid in field_to_uuid.items():
        if uuid not in candidates:
            continue
        roles = _field_usage_roles(field, text)
        local_usage_roles.setdefault(uuid, set()).update(roles)
    for uuid, roles in local_usage_roles.items():
        if len(roles) > 1:
            candidates[uuid]["classification_source"] = "ambiguous-usage"
        elif roles:
            role = next(iter(roles))
            candidates[uuid]["classification"] = role
            if role == "GATT Characteristic":
                candidates[uuid]["classification_source"] = "usage:getCharacteristic"
            else:
                candidates[uuid]["classification_source"] = "usage:getService"

    # Typed UUID-pair wrapper roles are source-backed by constructor bodies
    # assigning UUID-typed args directly to semantic service/characteristic
    # fields. Apply after local GATT usage so direct Android API evidence wins.
    for uuid, role_evidence in constructor_pair_roles.items():
        if uuid not in candidates:
            continue
        for role, arg_index, ctor_name, field_name in sorted(role_evidence):
            merge_role_evidence(
                candidates[uuid], role,
                f"constructor-pair:{ctor_name}#arg{arg_index}->{field_name}",
            )

    # Constructor parameter roles are source-backed by the GATT entity's
    # typed signature and the UUID argument position. Apply them after local
    # GATT usage so direct Android API evidence remains stronger.
    for uuid, role_evidence in constructor_param_roles.items():
        if uuid not in candidates:
            continue
        for role, ctor_name, param_name in sorted(role_evidence):
            merge_role_evidence(
                candidates[uuid], role,
                f"constructor-param:{ctor_name}.{param_name}",
            )

    # Gardena's sealed API objects lower their pair into constructor-local
    # UUID temps followed by super(...); do not resolve temps across objects.
    for service, characteristic in gardena_super_pairs:
        for uuid, role in ((service, "GATT Service"), (characteristic, "GATT Characteristic")):
            if uuid in candidates:
                merge_role_evidence(candidates[uuid], role, "constructor-pair:GardenaApi.super")

    # Final pass: source-verified object flow only. Co-location and matching
    # names do not prove that a particular characteristic belongs to a
    # particular service.
    direct_parent_pairs = _direct_service_characteristic_pairs(
        text, field_to_uuid, candidates
    )
    for service, characteristic in gardena_super_pairs:
        if characteristic in candidates and service in candidates:
            direct_parent_pairs.setdefault(characteristic, []).append(service)
    for uuid, entry in candidates.items():
        entry["parent_candidates"] = (
            direct_parent_pairs.get(uuid, [])
            if entry["classification"] == "GATT Characteristic"
            else []
        )

    return candidates


def _indexed_uuid_array_roles(file_texts: dict[str, str]) -> dict[str, set[str]]:
    """Recover UUID roles from profile arrays matched by array index.

    Some obfuscated BLE SDKs keep {service, characteristic, characteristic}
    UUID arrays in a constants class, then compare index 0 with a discovered
    BluetoothGattService UUID and indices 1/2 with discovered characteristic
    UUIDs in another class. This follows only explicit indexed comparisons;
    it does not assume the array's convention by itself.
    """
    symbol_to_uuid: dict[str, str] = {}
    simple_arrays: dict[str, list[str]] = {}
    array_aliases: dict[str, str] = {}
    matrix_members: dict[str, list[str]] = {}
    root_matrix_fields: dict[str, str] = {}
    group_to_matrix_field: dict[str, str] = {}
    observed_roles: dict[str, set[str]] = {}

    ident = r"[A-Za-z_$][A-Za-z0-9_$]*"
    # UUID[][] consumers and definitions are the only sources needed for
    # indexed-profile dataflow. Restrict body parsing to this source subset.
    array_sources = [
        text for text in file_texts.values()
        if re.search(r"\bUUID\s*\[\s*\]", text)
    ]

    def matching_pair(text: str, open_index: int, opening: str, closing: str) -> int | None:
        depth = 0
        quote: str | None = None
        escaped = False
        for index in range(open_index, len(text)):
            ch = text[index]
            if quote is not None:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                continue
            if ch in {"\"", "'"}:
                quote = ch
            elif ch == opening:
                depth += 1
            elif ch == closing:
                depth -= 1
                if depth == 0:
                    return index
        return None

    method_start_re = re.compile(
        rf"(?m)^[ \t]*(?:public|protected|private)\s+"
        rf"(?:(?:static|final|synchronized|abstract|native|default)\s+)*"
        rf"[\w.$<>?,\[\]]+\s+({ident})\s*\("
    )

    def iter_methods(text: str):
        declarations: dict[str, set[int]] = {}
        methods = []
        for declaration in method_start_re.finditer(text):
            name = declaration.group(1)
            open_index = text.find("(", declaration.start(1) + len(name))
            close_index = matching_pair(text, open_index, "(", ")")
            if close_index is None:
                continue
            after = close_index + 1
            while after < len(text) and text[after].isspace():
                after += 1
            if text.startswith("throws", after):
                body_open = text.find("{", after)
                semicolon = text.find(";", after)
                if body_open < 0 or (semicolon >= 0 and semicolon < body_open):
                    continue
            else:
                body_open = after if after < len(text) and text[after] == "{" else -1
            if body_open < 0:
                continue
            body_close = matching_pair(text, body_open, "{", "}")
            if body_close is None:
                continue
            params = _split_top_level_java_args(text[open_index + 1:close_index])
            declarations.setdefault(name, set()).add(open_index)
            methods.append((name, params, text[body_open + 1:body_close]))
        return methods, declarations

    def local_uuid_roles(body: str) -> dict[str, str]:
        typed: dict[str, str] = {}
        for java_type, role in (
            ("BluetoothGattService", "GATT Service"),
            ("BluetoothGattCharacteristic", "GATT Characteristic"),
        ):
            for receiver in re.findall(rf"\b{java_type}\s+({ident})\b", body):
                typed[receiver] = role
        out: dict[str, str] = {}
        for receiver, role in typed.items():
            for uuid_var in re.findall(
                rf"\bUUID\s+({ident})\s*=\s*{re.escape(receiver)}\s*\.\s*getUuid\s*\(\s*\)\s*;",
                body,
                re.IGNORECASE,
            ):
                out[uuid_var] = role
        return out

    def indexed_roles(body: str, array_name: str, uuid_roles: dict[str, str]) -> dict[int, set[str]]:
        out: dict[int, set[str]] = {}
        for match in re.finditer(
            rf"\b{re.escape(array_name)}\s*\[\s*(\d+)\s*\]\s*\.\s*equals\s*\(\s*({ident})\s*\)",
            body,
            re.IGNORECASE,
        ):
            role = uuid_roles.get(match.group(2))
            if role:
                out.setdefault(int(match.group(1)), set()).add(role)
        return out

    for text in array_sources:
        for assignment_re in (
            UUID_ASSIGNMENT_RE,
            UUID_STRING_ASSIGNMENT_RE,
            UUID_RAW_STRING_ASSIGNMENT_RE,
            UUID_INSTANCE_STRING_ASSIGNMENT_RE,
        ):
            for match in assignment_re.finditer(text):
                symbol_to_uuid[match.group(1)] = normalize_uuid(match.group(2))

        # UUID[] x = {a, b} and x = new UUID[]{a, b} declarations.
        for match in re.finditer(
            rf"(?:UUID\s*\[\s*\]\s+)?({ident})\s*=\s*"
            rf"(?:new\s+UUID\s*\[\s*\]\s*)?\{{([^{{}}]*)\}}\s*;",
            text,
        ):
            vals = [v.strip() for v in match.group(2).split(",") if v.strip()]
            if vals and all(re.fullmatch(ident, v) for v in vals):
                simple_arrays[match.group(1)] = vals

        # Field/local UUID[][] x = new UUID[][]{profileA, profileB}.
        for match in re.finditer(
            rf"(?:UUID\s*\[\s*\]\s*\[\s*\]\s+)?({ident})\s*=\s*"
            rf"new\s+UUID\s*\[\s*\]\s*\[\s*\]\s*\{{([^{{}}]*)\}}\s*;",
            text,
        ):
            vals = [v.strip() for v in match.group(2).split(",") if v.strip()]
            if vals and all(re.fullmatch(ident, v) for v in vals):
                matrix_members[match.group(1)] = vals

        # Static initialized matrices and local aliases to a matrix field.
        for match in re.finditer(
            rf"\bUUID\s*\[\s*\]\s*\[\s*\]\s+({ident})\s*=\s*([A-Za-z_$][\w$.]*)\s*;",
            text,
        ):
            root_matrix_fields[match.group(1)] = match.group(2).split(".")[-1]
        for match in re.finditer(
            rf"\bUUID\s*\[\s*\]\s+({ident})\s*=\s*({ident})\s*\[\s*[^]\s]+\s*\]\s*;",
            text,
        ):
            root_name = match.group(2)
            matrix_field = root_matrix_fields.get(root_name)
            if matrix_field:
                group_to_matrix_field[match.group(1)] = matrix_field

        # If an array field was assigned a local initializer array, preserve
        # that relationship (for example, f2817e = uuidArr).
        for match in re.finditer(rf"\b({ident})\s*=\s*({ident})\s*;", text):
            lhs, rhs = match.groups()
            if lhs != rhs:
                array_aliases.setdefault(lhs, rhs)

        methods, declarations = iter_methods(text)
        role_maps: dict[tuple[str, int], dict[int, dict[int, set[str]]]] = {}
        for method_name, params, body in methods:
            uuid_roles = local_uuid_roles(body)
            for group, matrix_field in group_to_matrix_field.items():
                for index, roles in indexed_roles(body, group, uuid_roles).items():
                    observed_roles.setdefault(f"{matrix_field}:{index}", set()).update(roles)
            param_roles: dict[int, dict[int, set[str]]] = {}
            for param_index, param in enumerate(params):
                param_name = _java_param_name(param)
                if not param_name or not re.search(r"UUID\s*\[\s*\]", param):
                    continue
                roles = indexed_roles(body, param_name, uuid_roles)
                if roles:
                    param_roles[param_index] = roles
            if param_roles:
                role_maps[(method_name, len(params))] = param_roles

        for method_name, params, _body in methods:
            role_map = role_maps.get((method_name, len(params)))
            if not role_map:
                continue
            call_re = re.compile(
                rf"(?<![A-Za-z0-9_$])(?:[A-Za-z_$][\w$]*\s*\.\s*)*"
                rf"{re.escape(method_name)}\s*\("
            )
            for call in call_re.finditer(text):
                open_index = text.find("(", call.start())
                if open_index in declarations.get(method_name, set()):
                    continue
                close_index = matching_pair(text, open_index, "(", ")")
                if close_index is None:
                    continue
                args = _split_top_level_java_args(text[open_index + 1:close_index])
                if len(args) != len(params):
                    continue
                for param_index, slots in role_map.items():
                    actual = re.sub(r"^(?:this\s*\.\s*)+", "", args[param_index].strip())
                    matrix_field = group_to_matrix_field.get(actual)
                    if not matrix_field:
                        continue
                    for index, roles in slots.items():
                        observed_roles.setdefault(f"{matrix_field}:{index}", set()).update(roles)

    # Resolve symbolic aliases once, then map array positions to UUIDs.
    def resolve_symbol(name: str) -> str | None:
        seen: set[str] = set()
        while name in symbol_to_uuid or name in array_aliases:
            if name in seen:
                return None
            seen.add(name)
            if name in symbol_to_uuid:
                return symbol_to_uuid[name]
            name = array_aliases[name]
        return None

    def resolve_array(name: str, seen: set[str] | None = None) -> list[str] | None:
        seen = set() if seen is None else seen
        if name in seen:
            return None
        seen.add(name)
        vals = simple_arrays.get(name)
        if vals is None and name in array_aliases:
            return resolve_array(array_aliases[name], seen)
        if vals is None:
            return None
        out: list[str] = []
        for val in vals:
            uuid = resolve_symbol(val)
            if uuid is None:
                return None
            out.append(uuid)
        return out

    roles_by_uuid: dict[str, set[str]] = {}
    filter_sources = [text for text in file_texts.values() if "setServiceUuid" in text]
    for text in filter_sources:
        for match in SCAN_FILTER_BUILDER_RE.finditer(text):
            roles_by_uuid.setdefault(normalize_uuid(match.group(2)), set()).add("GATT Service")
    for matrix_slot, roles in observed_roles.items():
        matrix_field, index_text = matrix_slot.rsplit(":", 1)
        matrix = matrix_members.get(matrix_field)
        if not matrix:
            continue
        index = int(index_text)
        for array_name in matrix:
            values = resolve_array(array_name)
            if values is None or index >= len(values):
                continue
            roles_by_uuid.setdefault(values[index], set()).update(roles)
    return roles_by_uuid


def _kryo_ooler_feature_characteristics(file_texts: dict[str, str]) -> set[str]:
    """Recover characteristic literals from the source-verified Kryo feature map.

    The map stores (service, characteristic) in Kotlin Pairs. Only apply
    this narrow rule when the same APK contains the corresponding GATT
    resolver, whose first and second Pair components feed the two lookups.
    Parent assignments remain a separate, host-specific review decision.
    """
    manager = next((text for path, text in file_texts.items()
                    if path.replace('\\', '/').endswith('/com/kryoinc/devices/ooler/OolerManager.java')), None)
    if manager is None:
        return set()
    compact = re.sub(r"\s+", "", manager)
    if not all(token in compact for token in (
        "newd().c().entrySet()",
        "gatt.getService((UUID)((Pair)entry.getValue()).c())",
        "service.getCharacteristic((UUID)((Pair)entry.getValue()).d())",
    )):
        return set()
    profile = next((text for path, text in file_texts.items()
                    if path.replace('\\', '/').endswith('/com/kryoinc/devices/ooler/d.java')), None)
    if profile is None or _java_package_of(profile) != "com.kryoinc.devices.ooler" or "BluetoothFeatures" not in profile:
        return set()
    literal = r"([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})"
    pair = re.compile(r"\bnew\s+Pair\s*\(\s*this\.[A-Za-z_$][\w$]*\s*,\s*UUID\.fromString\s*\(\s*\"" + literal + r"\"\s*\)\s*\)")
    return {normalize_uuid(match.group(1)) for match in pair.finditer(profile)}


def _spot_model_characteristics(file_texts: dict[str, str]) -> set[str]:
    """Resolve the source-verified Illuminati SpotModel characteristic map."""
    def named(suffix: str) -> str | None:
        return next((text for path, text in file_texts.items() if path.replace('\\', '/').endswith(suffix)), None)
    model = named('/com/pvimaging/spotdemo/spot/gatt/model/SpotModel.java')
    device = named('/com/pvimaging/spotdemo/spot/gatt/BtSpotDevice.java')
    if not model or not device:
        return set()
    compact_model = re.sub(r"\s+", "", model)
    compact_device = re.sub(r"\s+", "", device)
    if not all(token in compact_model for token in (
        'CharacterMapput(UUIDservice,UUIDuuid,', 'SERVICE_REVERSE_MAPPING.put(uuid,service)',
    )) or not all(token in compact_device for token in (
        'SpotModel.getServiceUuid(uuid)', 'connectedGatt.getService(serviceUuid)',
        'service.getCharacteristic(uuid)',
    )):
        return set()
    literal = r'([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})'
    symbols: dict[str, set[str]] = {}
    for path, text in file_texts.items():
        normalized = path.replace('\\', '/')
        if '/com/pvimaging/spotdemo/spot/gatt/model/' not in normalized or not normalized.endswith('.java'):
            continue
        owner = normalized.rsplit('/', 1)[-1][:-5]
        temps = {m.group(1): normalize_uuid(m.group(2)) for m in re.finditer(
            r'\bUUID\s+([A-Za-z_$][\w$]*)\s*=\s*UUID\.fromString\(\s*"' + literal + r'"\s*\)', text)}
        for field, value in re.findall(
            r'\b([A-Z][A-Z0-9_]*)\s*=\s*UUID\.fromString\(\s*"' + literal + r'"\s*\)', text
        ):
            symbols.setdefault(owner + '.' + field, set()).add(normalize_uuid(value))
        for field, temp in re.findall(r'\b([A-Z][A-Z0-9_]*)\s*=\s*([A-Za-z_$][\w$]*)\s*;', text):
            if temp in temps:
                symbols.setdefault(owner + '.' + field, set()).add(temps[temp])
        for temp, value in temps.items():
            if re.fullmatch(r'[A-Z][A-Z0-9_]*', temp):
                symbols.setdefault(owner + '.' + temp, set()).add(value)
    for local, owner, field in re.findall(
        r'\bUUID\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\.([A-Z][A-Z0-9_]*)\s*;', model
    ):
        values = symbols.get(owner + '.' + field, set())
        symbols.setdefault(local, set()).update(values)
    found: set[str] = set()
    for service, characteristic in re.findall(
        r'\bput(?:\$default)?\s*\(\s*(?:this\s*,\s*)?([A-Za-z_$][\w$.]*)\s*,\s*([A-Za-z_$][\w$.]*)\s*,', model
    ):
        services, chars = symbols.get(service, set()), symbols.get(characteristic, set())
        if len(services) == len(chars) == 1 and services != chars:
            found.update(chars)
    return found


def _sunradon_typed_characteristics(file_texts: dict[str, str]) -> set[str]:
    """Resolve SunRADON UUID getters checked against typed GATT characteristics."""
    def named(suffix: str) -> str | None:
        return next((text for path, text in file_texts.items() if path.replace('\\', '/').endswith(suffix)), None)
    utility = named('/com/app/utility/bluetooth/BluetoothUtil.java')
    device = named('/com/app/service/DeviceService.java')
    if not utility or not device or '626b8801-39ce-491b-a871-5b9a209eedc8' not in utility.lower():
        return set()
    literal = r'([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})'
    fields = dict(re.findall(
        r'\bUUID\s+(CHARACTERISTIC_[A-Z0-9_]+)\s*=\s*UUID\.fromString\(\s*"' + literal + r'"\s*\)', utility
    ))
    variables = set(re.findall(r'\bBluetoothGattCharacteristic\s+([A-Za-z_$][\w$]*)\b', device))
    result = set()
    for field, uuid in fields.items():
        getter = 'get' + field
        if not re.search(r'\bUUID\s+' + re.escape(getter) + r'\s*\(\s*\)\s*\{\s*return\s+' + re.escape(field) + r'\s*;', utility):
            continue
        for variable in variables:
            if re.search(r'\b' + re.escape(variable) + r'\.getUuid\(\)\s*,\s*BluetoothUtil\.INSTANCE\.' + re.escape(getter) + r'\s*\(', device):
                result.add(normalize_uuid(uuid))
                break
    return result


def _riddell_set_pu_characteristics(file_texts: dict[str, str]) -> set[str]:
    """Resolve exact UUID fields passed to Riddell's typed config writer."""
    def named(suffix: str) -> str | None:
        return next((text for path, text in file_texts.items() if path.replace("\\", "/").endswith(suffix)), None)
    common = named("/com/riddell/alertmonitor/view/utils/CommonUUID.java")
    caller = named("/com/riddell/alertmonitor/view/activities/BaseBLEActivity.java")
    service = named("/com/riddell/alertmonitor/livestreaming/LiveStreamingService.java")
    if not common or not caller or not service:
        return set()
    compact = re.sub(r"\s+", "", service)
    if not all(token in compact for token in (
        "setPUBLEValues(UUIDuuid,", "getService(UUID.fromString(CommonUUID.CONFIG_SERVICE_UUID))",
        "service.getCharacteristic(uuid)",
    )):
        return set()
    literal = r'([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})'
    fields = dict(re.findall(r'\bString\s+([A-Za-z_$][\w$]*)\s*=\s*"' + literal + r'"', common))
    passed = re.findall(r'\bsetPUBLEValues\s*\(\s*UUID\.fromString\s*\(\s*CommonUUID\.([A-Za-z_$][\w$]*)\s*\)', caller)
    return {normalize_uuid(fields[name]) for name in passed if name in fields}


def scan_jadx_output(jadx_out_dir: str) -> dict[str, dict]:
    """Aggregate UUIDs from all .java files in jadx_out_dir, then run a
    cross-file usage trace to fix classifications when a UUID is *declared*
    in one file but *used* (getService/getCharacteristic) in another.

    Parent candidates retain their per-file provenance: a candidate is
    included only when the Service and Characteristic were both observed in
    the same Java file. The APK-wide pass may correct a UUID's role, but it
    must not manufacture parent relationships between unrelated files.
    """
    all_uuids: dict[str, dict] = {}
    # Keep each field's declaring source file. A bare field token such as `o`
    # is not a global identifier: cross-file matching must bind a use to this
    # class (or an explicit import), not to any same-spelled class/member.
    cross_file_fields: list[tuple[str, str, str]] = []
    src_dir = os.path.join(jadx_out_dir, "sources")
    if not os.path.isdir(src_dir):
        return all_uuids
    # Read once up front. Besides avoiding a second disk pass later, this lets
    # call sites in one file use constructor parameter names declared in a
    # different file (SharkNinja's provider -> BluetoothServiceConfiguration).
    java_paths: list[str] = list(iter_java_files(src_dir))
    file_texts: dict[str, str] = {}
    cross_file_constructor_param_maps: dict[tuple[str, int], list[str | None]] = {}
    cross_file_typed_uuid_pair_roles: dict[tuple[str, int], dict[int, str]] = {}
    constructor_definition_counts: dict[tuple[str, int], int] = {}
    for jpath in java_paths:
        try:
            with open(jpath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
        file_texts[jpath] = text
        for key, value in _constructor_param_maps(text).items():
            cross_file_constructor_param_maps.setdefault(key, value)
        for key, count in _constructor_definition_counts(text).items():
            constructor_definition_counts[key] = constructor_definition_counts.get(key, 0) + count
        for key, roles in _typed_uuid_pair_constructor_roles(text).items():
            cross_file_typed_uuid_pair_roles.setdefault(key, roles)
    skidata_region_uuid_values = {
        uuid
        for source in file_texts.values()
        for uuid, _, _ in _skidata_region_uuid_occurrences(
            source, _java_package_of(source)
        )
    }
    cross_file_typed_uuid_pair_roles = {
        key: roles for key, roles in cross_file_typed_uuid_pair_roles.items()
        if constructor_definition_counts.get(key) == 1
    }
    cross_file_constructor_param_index = _index_constructor_param_maps(
        cross_file_constructor_param_maps
    )

    # Pass A: per-file scan + accumulate cross-file field map.
    for jpath in java_paths:
        scanned = scan_one_file(
            jpath,
            cross_file_constructor_param_maps,
            cross_file_constructor_param_index,
            cross_file_typed_uuid_pair_roles,
            skidata_region_uuid_values,
        )
        for uuid, entry in scanned.items():
            field_name = entry.get("field_name")
            if field_name and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", field_name):
                cross_file_fields.append((jpath, field_name, uuid))
            if uuid not in all_uuids:
                all_uuids[uuid] = entry
                continue
            existing = all_uuids[uuid]
            merge_role_evidence(
                existing,
                entry["classification"],
                entry.get("classification_source"),
            )
            existing["snippets"].extend(entry["snippets"][:2])
            existing["parent_candidates"].extend(entry["parent_candidates"])
            existing.setdefault("declaring_packages", set()).update(entry.get("declaring_packages", set()))
            # Cross-file field_name upgrade: if this file has a better-quality
            # name than what we've accumulated, take it. Same scoring used at
            # merge_records, so per-file and cross-APK upgrades are consistent.
            # Ambiguous-name preservation: when both names are meaningful and
            # neither is a substring of the other (Climax KPT32 `SetDisarmCode`
            # vs BL3 `ReadStepCounter` for the same UUID), join them with ` / `
            # so the CLUES record reflects both device-family meanings.
            new_name = entry.get("field_name")
            cur_name = existing.get("field_name")
            if new_name:
                new_score = name_semantic_score(new_name)
                cur_score = name_semantic_score(cur_name)
                existing_aliases = {a.strip() for a in (cur_name or "").split(" / ") if a.strip()}
                if new_score > cur_score and new_name not in existing_aliases:
                    existing["field_name"] = new_name
                elif (
                    cur_score >= 25
                    and new_score >= 25
                    and new_name not in existing_aliases
                    and (cur_name not in new_name)
                    and (new_name not in cur_name)
                    and len(existing_aliases) < 4
                ):
                    existing["field_name"] = cur_name + " / " + new_name

    # Pass B: cross-file usage trace. Decompiled BLE code often splits the
    # UUID constants into a dedicated tiny class (e.g. `final class d { static
    # final UUID a = UUID.fromString("..."); ... }`) and consumes them
    # elsewhere via dotted access (`getService(d.a)`, `getCharacteristic(d.b)`).
    # The per-file pass classifies these as "GATT Service" by file-level
    # default (the declaring file has no BluetoothGatt* imports). Cross-file
    # usage trace fixes that.
    #
    # We only need to consult files we haven't already classified as
    # Characteristic via local evidence. The compiled regex per field is
    # small; the dominant cost is the file reads, so we cache them.
    gatt_context_re = re.compile(
        r"\b(?:BluetoothGattService|BluetoothGattCharacteristic)\b|"
        r"\b(?:getService|getCharacteristic|hasService|hasCharacteristic|"
        r"addService|addCharacteristic|writeCharacteristic|readCharacteristic|"
        r"setCharacteristicNotification|setCharacteristicIndication)\s*\(",
        re.IGNORECASE,
    )
    usage_paths = [
        (jpath, text) for jpath, text in file_texts.items()
        if gatt_context_re.search(text)
    ]

    # Resolve only legal cross-file references to the declaring class. In
    # particular, never search for a bare obfuscated token (`o`) across every
    # file: `ABTest.getService(o.f50121a)` is an analytics Context lookup, not
    # a use of an unrelated RealSil UUID field also named `o`.
    phase1_package_by_path: dict[str, str] = {}
    phase1_imports_by_path: dict[str, set[str]] = {}
    phase1_gatt_vars_by_path: dict[str, dict[str, set[str]]] = {}
    phase1_gatt_type_re = re.compile(
        r"\b(?:(android\.bluetooth)\.)?"
        r"(BluetoothGatt|BluetoothGattServer|BluetoothGattService|BluetoothGattCharacteristic)\s+"
        r"([A-Za-z_$][A-Za-z0-9_$]*)\b"
    )
    phase1_android_bt_wildcard_paths: set[str] = set()
    for jpath, text in file_texts.items():
        package_match = re.search(r"(?m)^\s*package\s+([\w$.]+)\s*;", text)
        phase1_package_by_path[jpath] = package_match.group(1) if package_match else ""
        phase1_imports_by_path[jpath] = set()
        for match in re.finditer(r"(?m)^\s*import\s+(static\s+)?([\w.$*]+)\s*;", text):
            imported = match.group(2)
            if match.group(1):
                continue
            if imported == "android.bluetooth.*":
                phase1_android_bt_wildcard_paths.add(jpath)
            elif not imported.endswith(".*"):
                phase1_imports_by_path[jpath].add(imported)
        typed_vars: dict[str, set[str]] = {}
        for match in phase1_gatt_type_re.finditer(text):
            type_name = match.group(2)
            type_is_android = (
                match.group(1) == "android.bluetooth"
                or f"android.bluetooth.{type_name}" in phase1_imports_by_path[jpath]
                or jpath in phase1_android_bt_wildcard_paths
            )
            if type_is_android:
                typed_vars.setdefault(match.group(3), set()).add(type_name)
        phase1_gatt_vars_by_path[jpath] = typed_vars

    phase1_field_ref_cache: dict[tuple[str, str, str], re.Pattern] = {}

    def phase1_owner_field_ref(owner_path: str, field: str, use_path: str) -> re.Pattern:
        key = (owner_path, field, use_path)
        if key in phase1_field_ref_cache:
            return phase1_field_ref_cache[key]
        owner_text = file_texts.get(owner_path, "")
        owner_package = phase1_package_by_path.get(owner_path, "")
        use_package = phase1_package_by_path.get(use_path, "")
        owner_class = os.path.splitext(os.path.basename(owner_path))[0]
        qname = f"{owner_package}.{owner_class}" if owner_package else owner_class
        patterns = [
            rf"(?<![A-Za-z0-9_$]){re.escape(qname)}\s*\.\s*{re.escape(field)}(?![A-Za-z0-9_$])"
        ]
        if use_package == owner_package or qname in phase1_imports_by_path.get(use_path, set()):
            patterns.append(
                rf"(?<![A-Za-z0-9_$]){re.escape(owner_class)}\s*\.\s*{re.escape(field)}(?![A-Za-z0-9_$])"
            )
        ref = re.compile("(?:" + "|".join(patterns) + ")")
        phase1_field_ref_cache[key] = ref
        return ref

    def phase1_gatt_receiver(use_path: str, receiver: str, expected: set[str]) -> bool:
        receiver_name = receiver.rsplit(".", 1)[-1]
        typed_vars = phase1_gatt_vars_by_path.get(use_path, {})
        if typed_vars.get(receiver_name, set()) & expected:
            return True
        # Some JADX output uses local wrapper types (or Object in generated
        # test fixtures) while retaining descriptive receiver names such as
        # `gatt` and `bluetoothGattService`. Accept those names as weak GATT
        # context, but never treat a class-style call like ABTest.getService
        # as a Bluetooth API sink.
        lower_name = receiver_name.lower()
        if "gatt" not in lower_name or receiver_name[:1].isupper():
            return False
        if expected == {"BluetoothGattService"}:
            return "service" in lower_name
        if expected == {"BluetoothGattCharacteristic"}:
            return "characteristic" in lower_name
        return "service" not in lower_name and "characteristic" not in lower_name

    def phase1_uuid_expression_uses_ref(expression: str, ref: re.Pattern) -> bool:
        """Match a field directly or through Java's String-to-UUID wrapper."""
        expression = expression.strip()
        if ref.fullmatch(expression):
            return True
        wrapper = re.fullmatch(
            r"(?:(?:java\.util\.)?UUID)\s*\.\s*fromString\s*\((.*)\)",
            expression,
            re.DOTALL,
        )
        return bool(wrapper and ref.fullmatch(wrapper.group(1).strip()))

    def phase1_typed_call(use_path: str, line: str, method: str, ref: re.Pattern, expected: set[str]) -> bool:
        ident = r"[A-Za-z_$][A-Za-z0-9_$]*"
        call_re = re.compile(r"\b" + re.escape(method) + r"\s*\(")
        paren_pairs = _matching_paren_indices_on_line(line)
        close_to_open = {closing: opening for opening, closing in paren_pairs.items()}
        for match in call_re.finditer(line):
            # Require a member invocation and parse its first Java argument so
            # UUID.fromString(Owner.FIELD) is recognized without matching an
            # arbitrary occurrence of FIELD elsewhere on the line.
            dot_idx = match.start() - 1
            while dot_idx >= 0 and line[dot_idx].isspace():
                dot_idx -= 1
            if dot_idx < 0 or line[dot_idx] != ".":
                continue
            prefix = line[:dot_idx].rstrip()
            receiver_match = re.search(
                rf"(?P<receiver>(?:{ident}\s*\.\s*)*{ident})\s*$", prefix
            )
            receiver_is_typed = bool(
                receiver_match
                and phase1_gatt_receiver(use_path, receiver_match.group("receiver"), expected)
            )
            # BluetoothGatt.getService(UUID) has the Android-declared return
            # type BluetoothGattService. Support the source-backed chain
            # `typedGatt.getService(...).getCharacteristic(...)` by checking
            # the receiver of that exact getService call.
            if (
                not receiver_is_typed
                and method == "getCharacteristic"
                and expected == {"BluetoothGattService"}
                and prefix.endswith(")")
            ):
                opening = close_to_open.get(len(prefix) - 1)
                if opening is not None:
                    before_open = line[:opening]
                    service_call = re.search(
                        rf"(?P<receiver>(?:{ident}\s*\.\s*)*{ident})\s*\.\s*getService\s*$",
                        before_open,
                    )
                    receiver_is_typed = bool(
                        service_call
                        and phase1_gatt_receiver(
                            use_path,
                            service_call.group("receiver"),
                            {"BluetoothGatt", "BluetoothGattServer"},
                        )
                    )
            if not receiver_is_typed:
                continue
            open_idx = match.end() - 1
            close_idx = _matching_paren_for_constructor(line, open_idx, [paren_pairs])
            if close_idx is None:
                continue
            args = _split_top_level_java_args(line[open_idx + 1:close_idx])
            if args and phase1_uuid_expression_uses_ref(args[0], ref):
                return True
        return False

    def phase1_typed_compare(use_path: str, line: str, ref: re.Pattern, expected_type: str) -> bool:
        compare_re = re.compile(
            r"(?P<receiver>(?:[A-Za-z_$][A-Za-z0-9_$]*\.)*[A-Za-z_$][A-Za-z0-9_$]*)"
            + r"\s*\.\s*getUuid\s*\(\s*\)"
            + r"(?:\s*\.\s*toString\s*\(\s*\))?"
            + r"\s*\.\s*(?:equals|equalsIgnoreCase|compareTo|compareToIgnoreCase)\s*\(\s*"
            + ref.pattern + r"\s*\)",
            re.IGNORECASE,
        )
        return any(
            phase1_gatt_receiver(use_path, match.group("receiver"), {expected_type})
            for match in compare_re.finditer(line)
        )

    phase1_method_body_cache: dict[str, list[str]] = {}

    def phase1_method_bodies(source: str) -> list[str]:
        """Return Java method bodies so local UUID aliases cannot leak across methods."""
        ident = r"[A-Za-z_$][A-Za-z0-9_$]*"
        declaration_re = re.compile(
            rf"(?m)^[ \t]*(?:public|protected|private)\s+"
            rf"(?:(?:static|final|synchronized|abstract|native|default)\s+)*"
            rf"[\w.$<>?,\[\]]+\s+({ident})\s*\("
        )
        brace_closes = dict(_java_brace_spans(source))

        def matching_paren(open_index: int) -> int | None:
            depth = 0
            quote: str | None = None
            escaped = False
            i = open_index
            while i < len(source):
                ch = source[i]
                nxt = source[i + 1] if i + 1 < len(source) else ""
                if quote:
                    if escaped:
                        escaped = False
                    elif ch == "\\":
                        escaped = True
                    elif ch == quote:
                        quote = None
                elif ch in {"\"", "'"}:
                    quote = ch
                elif ch == "/" and nxt == "/":
                    newline = source.find("\n", i + 2)
                    if newline < 0:
                        return None
                    i = newline
                elif ch == "/" and nxt == "*":
                    close = source.find("*/", i + 2)
                    if close < 0:
                        return None
                    i = close + 1
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        return i
                i += 1
            return None

        bodies: list[str] = []
        for declaration in declaration_re.finditer(source):
            open_index = source.find("(", declaration.start(1) + len(declaration.group(1)))
            close_index = matching_paren(open_index)
            if close_index is None:
                continue
            after = close_index + 1
            while after < len(source) and source[after].isspace():
                after += 1
            if source.startswith("throws", after):
                body_open = source.find("{", after)
                semicolon = source.find(";", after)
                if body_open < 0 or (semicolon >= 0 and semicolon < body_open):
                    continue
            else:
                body_open = after if after < len(source) and source[after] == "{" else -1
            body_close = brace_closes.get(body_open)
            if body_open >= 0 and body_close is not None:
                bodies.append(source[body_open + 1:body_close])
        return bodies

    def phase1_local_uuid_alias_roles(
        use_path: str, source: str, owner_field_ref: re.Pattern
    ) -> tuple[set[str], dict[str, set[str]]]:
        """Follow a class UUID field through local aliases into typed GATT sinks.

        In addition to lookup/comparison APIs, a UUID passed as argument 1 to
        the Android GATT entity constructors has a role fixed by that
        constructor's type. This is accepted only for an imported or fully
        qualified android.bluetooth class and a UUID local alias traced back
        to the exact declaring class field.
        """
        ident = r"[A-Za-z_$][A-Za-z0-9_$]*"
        roles: set[str] = set()
        constructor_roles: dict[str, set[str]] = {}
        gatt_constructor_roles = {
            "BluetoothGattService": "GATT Service",
            "BluetoothGattCharacteristic": "GATT Characteristic",
        }
        explicit_android_imports = set(re.findall(
            r"(?m)^\s*import\s+android\.bluetooth\.(BluetoothGattService|BluetoothGattCharacteristic)\s*;",
            source,
        ))
        declared_java_types = set(re.findall(
            r"\b(?:class|interface|enum|record)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b",
            source,
        ))
        assignment_re = re.compile(
            rf"(?<![A-Za-z0-9_$])(?:(?:java\.util\.)?UUID\s+)?"
            rf"(?P<lhs>{ident})\s*=\s*(?P<rhs>[^;{{}}]+);"
        )
        method_bodies = phase1_method_body_cache.get(use_path)
        if method_bodies is None:
            method_bodies = phase1_method_bodies(source)
            phase1_method_body_cache[use_path] = method_bodies
        for body in method_bodies:
            if not owner_field_ref.search(body):
                continue
            uuid_vars = set(re.findall(rf"\b(?:java\.util\.)?UUID\s+({ident})\b", body))
            aliases: set[str] = set()
            for line in body.splitlines():
                for assignment in assignment_re.finditer(line):
                    lhs = assignment.group("lhs")
                    if lhs not in uuid_vars:
                        continue
                    rhs = assignment.group("rhs")
                    rhs_alias = any(
                        re.search(rf"(?<![A-Za-z0-9_$]){re.escape(alias)}(?![A-Za-z0-9_$])", rhs)
                        for alias in aliases
                    )
                    if owner_field_ref.search(rhs) or rhs_alias:
                        aliases.add(lhs)
                    else:
                        aliases.discard(lhs)
                if not aliases:
                    continue
                refs = [owner_field_ref.pattern]
                refs.extend(
                    rf"(?<![A-Za-z0-9_$]){re.escape(alias)}(?![A-Za-z0-9_$])"
                    for alias in sorted(aliases)
                )
                alias_ref = re.compile("(?:" + "|".join(refs) + ")")
                if phase1_typed_call(
                    use_path, line, "getService", alias_ref,
                    {"BluetoothGatt", "BluetoothGattServer"},
                ):
                    roles.add("GATT Service")
                if phase1_typed_call(
                    use_path, line, "getCharacteristic", alias_ref,
                    {"BluetoothGattService"},
                ):
                    roles.add("GATT Characteristic")
                if phase1_typed_compare(use_path, line, alias_ref, "BluetoothGattService"):
                    roles.add("GATT Service")
                if phase1_typed_compare(use_path, line, alias_ref, "BluetoothGattCharacteristic"):
                    roles.add("GATT Characteristic")
                for constructor_match in NEW_CONSTRUCTOR_START_RE.finditer(line):
                    constructor_type = constructor_match.group(1)
                    ctor_name = constructor_type.split(".")[-1]
                    role = gatt_constructor_roles.get(ctor_name)
                    if not role:
                        continue
                    fully_qualified = constructor_type == f"android.bluetooth.{ctor_name}"
                    simple_import = (
                        constructor_type == ctor_name
                        and ctor_name in explicit_android_imports
                        and ctor_name not in declared_java_types
                    )
                    # Resolve each call independently. A qualified constructor
                    # elsewhere in this source cannot bless a same-named local
                    # class, and wildcard imports are intentionally fail-closed.
                    if not (fully_qualified or simple_import):
                        continue
                    open_index = line.find("(", constructor_match.start())
                    close_index = _matching_paren_for_constructor(line, open_index, None)
                    if close_index is None:
                        continue
                    args = _split_top_level_java_args(line[open_index + 1:close_index])
                    if args and phase1_uuid_expression_uses_ref(args[0], alias_ref):
                        roles.add(role)
                        constructor_roles.setdefault(role, set()).add(ctor_name)
        # A static UUID field can be used directly in a typed Android GATT
        # entity constructor without first passing through a local UUID alias.
        # Resolve only constructors bound to the Android class (the same
        # explicit-import / fully-qualified rule as above), and require the
        # exact field in argument zero.
        for line in source.splitlines():
            if not owner_field_ref.search(line):
                continue
            for constructor_match in NEW_CONSTRUCTOR_START_RE.finditer(line):
                constructor_type = constructor_match.group(1)
                ctor_name = constructor_type.split(".")[-1]
                role = gatt_constructor_roles.get(ctor_name)
                if not role:
                    continue
                fully_qualified = constructor_type == f"android.bluetooth.{ctor_name}"
                simple_import = (
                    constructor_type == ctor_name
                    and ctor_name in explicit_android_imports
                    and ctor_name not in declared_java_types
                )
                if not (fully_qualified or simple_import):
                    continue
                open_index = line.find("(", constructor_match.start())
                close_index = _matching_paren_for_constructor(line, open_index, None)
                if close_index is None:
                    continue
                args = _split_top_level_java_args(line[open_index + 1:close_index])
                if args and phase1_uuid_expression_uses_ref(args[0], owner_field_ref):
                    roles.add(role)
                    constructor_roles.setdefault(role, set()).add(ctor_name)
        return roles, constructor_roles

    # Index source methods whose UUID argument roles are proven by typed
    # Android GATT constructors. This adds one fail-closed wrapper hop for
    # SDKs that accept (service UUID, characteristic UUID, callback), then
    # build the profile internally. Match the receiver's declared class,
    # package/import, method name, arity, and compatible argument types; never
    # bind an arbitrary same-named obfuscated method across the APK.
    helper_models_by_fqn: dict[str, list[tuple[str, dict]]] = {}
    helper_source_paths_by_fqn: dict[str, set[str]] = {}
    for helper_path, helper_text in file_texts.items():
        if "BluetoothGattService" not in helper_text or "BluetoothGattCharacteristic" not in helper_text:
            continue
        helper_package = phase1_package_by_path.get(helper_path, "")
        helper_class = os.path.splitext(os.path.basename(helper_path))[0]
        if not re.search(
            rf"\b(?:class|interface|enum|record)\s+{re.escape(helper_class)}\b",
            helper_text,
        ):
            continue
        helper_fqn = f"{helper_package}.{helper_class}" if helper_package else helper_class
        for model in _typed_gatt_method_models(helper_text):
            helper_models_by_fqn.setdefault(helper_fqn, []).append((helper_path, model))
            helper_source_paths_by_fqn.setdefault(helper_fqn, set()).add(helper_path)

    cross_method_roles_by_uuid: dict[str, set[str]] = {}
    cross_method_source_by_uuid: dict[str, set[str]] = {}
    cross_method_parents_by_char: dict[str, set[str]] = {}

    def caller_variable_types(body: str, params: list[str]) -> dict[str, str]:
        result: dict[str, str] = {}
        for param in params:
            name = _java_param_name(param)
            typ = _java_param_type(param)
            if name and typ:
                result[name] = typ
        for match in re.finditer(
            r"(?<![A-Za-z0-9_$])(?P<type>[A-Za-z_$][A-Za-z0-9_$.]*)\s+"
            r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*(?==|;|,)",
            body,
        ):
            result.setdefault(match.group("name"), match.group("type").rsplit(".", 1)[-1])
        return result

    def resolve_helper_fqn(simple_type: str, caller_path: str) -> str | None:
        if "." in simple_type:
            return simple_type if simple_type in helper_models_by_fqn else None
        caller_package = phase1_package_by_path.get(caller_path, "")
        imports = phase1_imports_by_path.get(caller_path, set())
        imported = [name for name in imports if name.rsplit(".", 1)[-1] == simple_type]
        if len(imported) == 1 and imported[0] in helper_models_by_fqn:
            return imported[0]
        if imported:
            return None
        candidate = f"{caller_package}.{simple_type}" if caller_package else simple_type
        if candidate in helper_models_by_fqn:
            return candidate
        return None

    def call_argument_type(expression: str, variable_types: dict[str, str]) -> str | None:
        expression = expression.strip()
        if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", expression):
            return variable_types.get(expression)
        created = re.match(r"new\s+([A-Za-z_$][A-Za-z0-9_$.]*)\s*\(", expression)
        if created:
            return created.group(1).rsplit(".", 1)[-1]
        if re.fullmatch(r"\"(?:[^\"\\]|\\.)*\"", expression):
            return "String"
        if re.fullmatch(r"(?:-?\d+)(?:[lL])?", expression):
            return "long" if expression.lower().endswith("l") else "int"
        if expression in {"true", "false"}:
            return "boolean"
        return None

    def helper_candidate_compatible(model: dict, argument_types: list[str | None]) -> bool:
        for expected, actual in zip(model.get("param_types", []), argument_types):
            if not expected or not actual:
                continue
            if expected != actual and expected not in {"Object", "?"}:
                return False
        return True

    def callsite_uuid_values(
        body: str,
        caller_params: list[str],
        caller_path: str,
        call_offsets: list[int],
        owner_refs: list[tuple[str, re.Pattern]] | None = None,
    ) -> tuple[dict[int, dict[str, set[str]]], list[tuple[str, re.Pattern]]]:
        """Resolve UUID local aliases as each helper call is reached in source order."""
        variable_types = caller_variable_types(body, caller_params)
        uuid_vars = {
            name for name, typ in variable_types.items()
            if typ == "UUID"
        }
        refs = owner_refs
        if refs is None:
            refs = []
            body_identifiers = set(re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", body))
            for owner_path, field, uuid in cross_file_fields:
                if field not in body_identifiers:
                    continue
                ref = phase1_owner_field_ref(owner_path, field, caller_path)
                if ref.search(body):
                    refs.append((uuid, ref))
        if not refs:
            return {}, refs
        aliases: dict[str, set[str]] = {name: set() for name in uuid_vars}
        assignment_re = re.compile(
            r"(?:(?:java\.util\.)?UUID\s+)?"
            r"(?P<lhs>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?P<rhs>[^;{}]+);"
        )

        def resolve_expr(expression: str) -> set[str]:
            found = {uuid for uuid, ref in refs if ref.search(expression)}
            for name, values in aliases.items():
                if values and re.search(rf"(?<![A-Za-z0-9_$]){re.escape(name)}(?![A-Za-z0-9_$])", expression):
                    found.update(values)
            return found

        # An assignment's value takes effect at its semicolon, after calls that
        # may appear in its right-hand side. Calls snapshot aliases at call start.
        events: list[tuple[int, str, object]] = [
            (assignment.end(), "assignment", assignment)
            for assignment in assignment_re.finditer(body)
            if assignment.group("lhs") in uuid_vars
        ]
        events.extend((offset, "call", offset) for offset in call_offsets)
        events.sort(key=lambda event: (event[0], 0 if event[1] == "call" else 1))
        snapshots: dict[int, dict[str, set[str]]] = {}
        cursor = 0
        depth = 0
        for offset, kind, payload in events:
            between = body[cursor:offset]
            depth = max(0, depth + between.count("{") - between.count("}"))
            if kind == "call":
                snapshots[offset] = {name: set(values) for name, values in aliases.items()}
                cursor = offset
                continue
            assignment = payload
            lhs = assignment.group("lhs")
            values = resolve_expr(assignment.group("rhs"))
            # Branch assignments contribute alternatives; straight-line
            # assignments replace the value reaching later call sites.
            nested = depth > 0
            if nested:
                aliases.setdefault(lhs, set()).update(values)
            else:
                aliases[lhs] = values
            cursor = offset
        return snapshots, refs

    helper_fqns_by_package: dict[str, set[str]] = {}
    for fqn in helper_models_by_fqn:
        package = fqn.rsplit(".", 1)[0] if "." in fqn else ""
        helper_fqns_by_package.setdefault(package, set()).add(fqn)
    for caller_path, caller_text in file_texts.items():
        if not helper_models_by_fqn:
            break
        caller_package = phase1_package_by_path.get(caller_path, "")
        imports = phase1_imports_by_path.get(caller_path, set())
        eligible_helper_fqns = helper_fqns_by_package.get(caller_package, set()) | (
            imports & helper_models_by_fqn.keys()
        )
        if not eligible_helper_fqns:
            continue
        eligible_helper_names = sorted({
            fqn.rsplit(".", 1)[-1] for fqn in eligible_helper_fqns
        })
        helper_type_re = re.compile(
            r"\b(?:" + "|".join(re.escape(name) for name in eligible_helper_names)
            + r")\s+[A-Za-z_$][A-Za-z0-9_$]*\b"
        )
        if not helper_type_re.search(caller_text):
            continue
        for caller_method_name, caller_params, caller_body in _iter_java_method_defs(caller_text):
            variable_types = caller_variable_types(caller_body, caller_params)
            if not variable_types:
                continue
            if not any(resolve_helper_fqn(typ, caller_path) for typ in variable_types.values()):
                continue
            calls = list(re.finditer(
                r"(?P<receiver>[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*"
                r"(?P<method>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
                caller_body,
            ))
            helper_call_offsets = []
            for possible_call in calls:
                receiver_type = variable_types.get(possible_call.group("receiver"))
                if not receiver_type:
                    continue
                receiver_fqn = resolve_helper_fqn(receiver_type, caller_path)
                if receiver_fqn and len(helper_source_paths_by_fqn.get(receiver_fqn, set())) == 1:
                    helper_call_offsets.append(possible_call.start())
            aliases_by_call, refs = callsite_uuid_values(
                caller_body, caller_params, caller_path, helper_call_offsets
            )
            if not refs:
                continue
            for call in calls:
                receiver = call.group("receiver")
                helper_type = variable_types.get(receiver)
                if not helper_type:
                    continue
                helper_fqn = resolve_helper_fqn(helper_type, caller_path)
                if not helper_fqn or len(helper_source_paths_by_fqn.get(helper_fqn, set())) != 1:
                    continue
                open_idx = caller_body.find("(", call.start("method") + len(call.group("method")))
                close_idx = _find_matching_java_paren(caller_body, open_idx)
                if close_idx is None:
                    continue
                args = _split_top_level_java_args(caller_body[open_idx + 1:close_idx])
                candidates = [
                    model for _path, model in helper_models_by_fqn.get(helper_fqn, [])
                    if model["name"] == call.group("method")
                    and len(model.get("param_types", [])) == len(args)
                ]
                if not candidates:
                    continue
                actual_types = [call_argument_type(arg, variable_types) for arg in args]
                compatible = [
                    model for model in candidates
                    if helper_candidate_compatible(model, actual_types)
                ]
                if not compatible:
                    continue
                evidence_shapes = {
                    (
                        tuple((slot, tuple(sorted(roles))) for slot, roles in sorted(model.get("roles", {}).items())),
                        tuple(sorted(model.get("parent_pairs", set()))),
                    )
                    for model in compatible
                }
                if len(evidence_shapes) != 1:
                    continue
                model = compatible[0]
                aliases = aliases_by_call.get(call.start(), {})

                def resolve_arg_uuids(expression: str) -> set[str]:
                    values = {uuid for uuid, ref in refs if ref.search(expression)}
                    for local, local_values in aliases.items():
                        if local_values and re.search(
                            rf"(?<![A-Za-z0-9_$]){re.escape(local)}(?![A-Za-z0-9_$])",
                            expression,
                        ):
                            values.update(local_values)
                    return values

                values_by_slot = {
                    idx: resolve_arg_uuids(arg)
                    for idx, arg in enumerate(args)
                }
                helper_label = f"{helper_fqn}.{call.group('method')}"
                for slot, roles in model.get("roles", {}).items():
                    if slot >= len(args):
                        continue
                    for uuid in values_by_slot.get(slot, set()):
                        if uuid not in all_uuids:
                            continue
                        cross_method_roles_by_uuid.setdefault(uuid, set()).update(roles)
                        cross_method_source_by_uuid.setdefault(uuid, set()).add(
                            f"cross-file usage:helper-method:{helper_label}#arg{slot + 1}"
                        )
                for service_slot, characteristic_slot in model.get("parent_pairs", set()):
                    service_values = values_by_slot.get(service_slot, set())
                    characteristic_values = values_by_slot.get(characteristic_slot, set())
                    if len(service_values) != 1 or len(characteristic_values) != 1:
                        continue
                    for characteristic_uuid in characteristic_values:
                        for service_uuid in service_values:
                            if service_uuid in all_uuids and characteristic_uuid in all_uuids:
                                cross_method_parents_by_char.setdefault(
                                    characteristic_uuid, set()
                                ).add(service_uuid)

    cross_roles_by_uuid: dict[str, set[str]] = {}
    cross_field_by_uuid: dict[str, str] = {}
    cross_constructor_roles_by_uuid: dict[str, dict[str, set[str]]] = {}
    for owner_path, field, uuid in cross_file_fields:
        if uuid not in all_uuids:
            continue
        source_roles = cross_roles_by_uuid.setdefault(uuid, set())
        cross_field_by_uuid.setdefault(uuid, field)
        for use_path, text in usage_paths:
            if use_path == owner_path:
                continue  # scan_one_file already handled local field use
            ref = phase1_owner_field_ref(owner_path, field, use_path)
            if not ref.search(text):
                continue
            for line in text.splitlines():
                if not ref.search(line):
                    continue
                if phase1_typed_call(use_path, line, "getService", ref, {"BluetoothGatt", "BluetoothGattServer"}):
                    source_roles.add("GATT Service")
                if phase1_typed_call(use_path, line, "getCharacteristic", ref, {"BluetoothGattService"}):
                    source_roles.add("GATT Characteristic")
                if phase1_typed_compare(use_path, line, ref, "BluetoothGattService"):
                    source_roles.add("GATT Service")
                if phase1_typed_compare(use_path, line, ref, "BluetoothGattCharacteristic"):
                    source_roles.add("GATT Characteristic")
            local_roles, local_constructor_roles = phase1_local_uuid_alias_roles(
                use_path, text, ref
            )
            source_roles.update(local_roles)
            for role, ctor_names in local_constructor_roles.items():
                cross_constructor_roles_by_uuid.setdefault(uuid, {}).setdefault(
                    role, set()
                ).update(ctor_names)
    for uuid, source_roles in cross_roles_by_uuid.items():
        existing = all_uuids[uuid]
        prior_source = existing.get("classification_source", "")
        if prior_source.startswith("ambiguous-") and prior_source != "ambiguous-role-conflict":
            continue
        if prior_source.startswith(("usage:", "cross-file usage:")):
            prior_role = existing.get("classification")
            if prior_role in {"GATT Service", "GATT Characteristic"}:
                source_roles.add(prior_role)
        if len(source_roles) > 1:
            existing["classification_source"] = "ambiguous-usage"
        elif source_roles:
            role = next(iter(source_roles))
            existing["classification"] = role
            field = cross_field_by_uuid[uuid]
            constructor_names = sorted(
                cross_constructor_roles_by_uuid.get(uuid, {}).get(role, set())
            )
            if constructor_names:
                existing["classification_source"] = (
                    f"cross-file constructor:new {constructor_names[0]}({field})"
                )
            elif role == "GATT Characteristic":
                existing["classification_source"] = f"cross-file usage:getCharacteristic({field})"
            else:
                existing["classification_source"] = f"cross-file usage:getService({field})"

    # A uniquely bound typed helper method can carry role evidence across one
    # UUID-argument boundary. Its Android constructor sinks are direct usage
    # evidence, so merge it at direct-usage strength. Parentage is retained
    # only for a helper invocation whose body adds the characteristic to the
    # service built from its paired argument.
    for uuid, roles in cross_method_roles_by_uuid.items():
        existing = all_uuids.get(uuid)
        if not existing:
            continue
        sources = sorted(cross_method_source_by_uuid.get(uuid, set()))
        source = sources[0] if sources else "cross-file usage:helper-method"
        if len(roles) > 1:
            existing["classification_source"] = "ambiguous-usage:helper-method-role-conflict"
            continue
        merge_role_evidence(existing, next(iter(roles)), source)

    for characteristic_uuid, parent_uuids in cross_method_parents_by_char.items():
        characteristic = all_uuids.get(characteristic_uuid)
        if not characteristic or characteristic.get("classification") != "GATT Characteristic":
            continue
        if characteristic.get("classification_source", "").startswith("ambiguous-"):
            continue
        for parent_uuid in sorted(parent_uuids):
            parent = all_uuids.get(parent_uuid)
            if parent and parent.get("classification") == "GATT Service":
                candidates = characteristic.setdefault("parent_candidates", [])
                if parent_uuid not in candidates:
                    candidates.append(parent_uuid)

    # Apply source-proven role evidence from indexed profile arrays.
    # Conflicting service/characteristic roles are intentionally left alone;
    # one UUID can serve as a scan-filter service in one path and a
    # characteristic in another supported profile.
    indexed_roles_by_uuid = _indexed_uuid_array_roles(file_texts)
    for uuid, roles in indexed_roles_by_uuid.items():
        if uuid not in all_uuids:
            continue
        if len(roles) != 1:
            all_uuids[uuid]["classification_source"] = "ambiguous-indexed-array-usage"
            continue
        role = next(iter(roles))
        prior_source = all_uuids[uuid].get("classification_source", "")
        prior_role = all_uuids[uuid].get("classification")
        if (prior_source.startswith("ambiguous-") and prior_source != "ambiguous-role-conflict") or (
            prior_source.startswith(("usage:", "cross-file usage:")) and prior_role != role
        ):
            all_uuids[uuid]["classification_source"] = "ambiguous-indexed-array-usage"
            continue
        all_uuids[uuid]["classification"] = role
        all_uuids[uuid]["classification_source"] = "indexed-array-usage"

    # Vise bundles a large GATT attribute-name table in
    # `com.vise.baseble.model.resolver.GattAttributeResolver`. Some entries in
    # that table are real SDK UUIDs (including Estimote's), but table presence
    # alone does not show that the host APK uses them. Suppress only Estimote
    # literals whose sole source occurrence is a declaration/map row in this
    # exact resolver and which have no direct GATT sink anywhere in the APK.
    # A use from another source file, including a direct use of the field in
    # getService/getCharacteristic, keeps the candidate. This check belongs
    # after Pass B so cross-file GATT use has already had precedence.
    vise_estimote_fields_by_uuid: dict[str, set[str]] = {}
    vise_resolver_texts: dict[str, str] = {}
    for jpath, text in file_texts.items():
        if _java_package_of(text) != "com.vise.baseble.model.resolver":
            continue
        if not re.search(r"\bclass\s+GattAttributeResolver\b", text):
            continue
        vise_resolver_texts[jpath] = text
        for line in text.splitlines():
            for raw in UUID128_LITERAL_RE.finditer(line):
                uuid = normalize_uuid("-".join(raw.groups()))
                for field in _assigned_fields_for_uuid_on_line(line, uuid):
                    if field.startswith("ESTIMOTE_"):
                        vise_estimote_fields_by_uuid.setdefault(uuid, set()).add(field)

    if vise_estimote_fields_by_uuid and vise_resolver_texts:
        gatt_sink_names = (
            "getService|hasService|addService|getCharacteristic|hasCharacteristic|"
            "addCharacteristic|writeCharacteristic|readCharacteristic|"
            "setCharacteristicNotification|setCharacteristicIndication"
        )
        for uuid, fields in vise_estimote_fields_by_uuid.items():
            if uuid not in all_uuids:
                continue
            # Require table-only references inside the resolver: declaration
            # and map.put rows are expected; any other field use is evidence
            # that this is more than a display lookup table.
            resolver_is_table_only = True
            for resolver_text in vise_resolver_texts.values():
                for field in fields:
                    field_re = re.compile(rf"\b{re.escape(field)}\b")
                    for line in resolver_text.splitlines():
                        if not field_re.search(line):
                            continue
                        declaration = field in _assigned_fields_for_uuid_on_line(line, uuid)
                        map_row = bool(re.search(
                            rf"\.\s*put\s*\(\s*{re.escape(field)}\s*,", line
                        ))
                        if not (declaration or map_row):
                            resolver_is_table_only = False
                            break
                    if not resolver_is_table_only:
                        break
                if not resolver_is_table_only:
                    break
            if not resolver_is_table_only:
                continue

            # Any occurrence of the UUID outside the resolver means the
            # evidence is not table-only, even if the occurrence is not a
            # recognized Android GATT sink.
            other_source_literal = any(
                jpath not in vise_resolver_texts
                and re.search(re.escape(uuid), text, re.IGNORECASE)
                for jpath, text in file_texts.items()
            )
            if other_source_literal:
                continue

            # Check both field aliases assigned this UUID and direct literal
            # arguments. The latter covers getService(UUID.fromString(...)).
            aliases_by_uuid: set[str] = set(fields)
            for text in file_texts.values():
                for line in text.splitlines():
                    aliases_by_uuid.update(_assigned_fields_for_uuid_on_line(line, uuid))
            direct_characteristic_field = None
            direct_service_field = None
            for field in sorted(aliases_by_uuid):
                usage_re = make_field_usage_re(field)
                if direct_characteristic_field is None and any(
                    usage_re["characteristic"].search(text) for text in file_texts.values()
                ):
                    direct_characteristic_field = field
                if direct_service_field is None and any(
                    usage_re["service"].search(text) for text in file_texts.values()
                ):
                    direct_service_field = field
            direct_field_use = (
                direct_characteristic_field is not None
                or direct_service_field is not None
            )
            direct_literal_use_re = re.compile(
                rf"\b(?:{gatt_sink_names})\s*\([^;{{}}]{{0,512}}"
                rf"{re.escape(uuid)}",
                re.IGNORECASE,
            )
            direct_literal_use = any(
                direct_literal_use_re.search(text) for text in file_texts.values()
            )
            if direct_characteristic_field is not None:
                all_uuids[uuid]["classification"] = "GATT Characteristic"
                all_uuids[uuid]["classification_source"] = (
                    f"cross-file usage:getCharacteristic({direct_characteristic_field})"
                )
            elif direct_service_field is not None:
                all_uuids[uuid]["classification"] = "GATT Service"
                all_uuids[uuid]["classification_source"] = (
                    f"cross-file usage:getService({direct_service_field})"
                )
            elif not direct_literal_use:
                all_uuids.pop(uuid, None)
                for entry in all_uuids.values():
                    entry["parent_candidates"] = [
                        parent for parent in entry.get("parent_candidates", [])
                        if parent != uuid
                    ]

    # BuildConfig.java commonly carries hotel/property identifiers as UUID-
    # shaped strings. A field-name classifier can mistake a *_HOTEL_ID for a
    # GATT characteristic. Suppress only when an explicit hotel/location ID
    # assignment in BuildConfig is the sole evidence for that UUID. Any source
    # occurrence outside BuildConfig, recognized GATT role evidence, or direct
    # GATT sink keeps the candidate; this is source-scoped and never blacklists
    # the UUID value globally.
    buildconfig_hotel_fields_by_uuid = _buildconfig_hotel_id_fields(file_texts)
    buildconfig_paths = {
        path for path, text in file_texts.items()
        if os.path.basename(path) == "BuildConfig.java"
        and re.search(r"\bclass\s+BuildConfig\b", text)
    }
    gatt_sink_names = (
        "getService|hasService|addService|getCharacteristic|hasCharacteristic|"
        "addCharacteristic|writeCharacteristic|readCharacteristic|"
        "setCharacteristicNotification|setCharacteristicIndication"
    )
    for uuid, hotel_fields in buildconfig_hotel_fields_by_uuid.items():
        if uuid not in all_uuids:
            continue
        if any(
            path not in buildconfig_paths
            and re.search(re.escape(uuid), text, re.IGNORECASE)
            for path, text in file_texts.items()
        ):
            continue

        aliases = set(hotel_fields)
        for path in buildconfig_paths:
            text = file_texts[path]
            for line in text.splitlines():
                aliases.update(_assigned_fields_for_uuid_on_line(line, uuid))

        # A separate GATT-named alias in the same generated class is enough
        # to make this UUID ambiguous, even when a hotel ID also shares it.
        semantic_ble_alias = re.compile(
            r"(?:^|_)(?:BLE|GATT|UUID|SERVICE|CHAR|CHARACTERISTIC|DESC|"
            r"NOTIFY|NOTIFICATION|READ|WRITE|ADVERT)(?:_|$)",
            re.IGNORECASE,
        )
        if any(semantic_ble_alias.search(field) for field in aliases - hotel_fields):
            continue

        gatt_field_use = any(
            _field_usage_roles(field, text)
            for field in aliases
            for text in file_texts.values()
        )
        direct_literal_use_re = re.compile(
            rf"\b(?:{gatt_sink_names})\s*\([^;{{}}]{{0,512}}"
            rf"{re.escape(uuid)}",
            re.IGNORECASE,
        )
        direct_literal_use = any(
            direct_literal_use_re.search(text) for text in file_texts.values()
        )
        if gatt_field_use or direct_literal_use or indexed_roles_by_uuid.get(uuid):
            continue

        all_uuids.pop(uuid, None)
        for entry in all_uuids.values():
            entry["parent_candidates"] = [
                parent for parent in entry.get("parent_candidates", [])
                if parent != uuid
            ]

    # Mobilytics OwnerIdentifier values identify analytics feature owners,
    # including fields whose names happen to contain SERVICE or PLATFORM.
    # Keep any independent typed GATT use recovered across the whole APK.
    for uuid in _mobilytics_owner_uuid_sources(file_texts):
        # Direct literals may retain a weaker merged classification than a
        # field reference. Preserve the same bounded GATT sink evidence used
        # by the other source-scoped metadata filters above.
        direct_owner_role = None
        for sink, role in (("getCharacteristic", "GATT Characteristic"),
                           ("getService", "GATT Service")):
            pattern = re.compile(
                rf"\b{sink}\s*\([^;{{}}]{{0,512}}{re.escape(uuid)}", re.I
            )
            if any(pattern.search(text) for text in file_texts.values()):
                direct_owner_role = role
                break
        entry = all_uuids.get(uuid)
        if entry is not None and direct_owner_role:
            entry["classification"] = direct_owner_role
            entry["classification_source"] = "cross-file usage:Mobilytics independent GATT literal"
            continue
        if entry is None or classification_source_strength(
            entry.get("classification_source", "")
        ) >= 75:
            continue
        all_uuids.pop(uuid, None)
        for other in all_uuids.values():
            other["parent_candidates"] = [
                parent for parent in other.get("parent_candidates", [])
                if parent != uuid
            ]

    # Suppress SmartBear recording dictionaries only after APK-wide typed
    # GATT recovery. Removing them in scan_one_file would hide a legitimate
    # use of a catalog field from an independent GATT consumer in another
    # source file. Strong role evidence, or any literal outside this exact
    # SDK package, keeps the UUID; metadata parent guesses are then cleared.
    smartbear_metadata = _smartbear_ui_metadata_uuid_sources(file_texts)
    for uuid in smartbear_metadata:
        entry = all_uuids.get(uuid)
        if entry is None:
            continue
        source = entry.get("classification_source", "")
        if classification_source_strength(source) >= 75:
            continue
        if any(
            _java_package_of(text) != "com.smartbear.testing"
            and re.search(re.escape(uuid), text, re.IGNORECASE)
            for text in file_texts.values()
        ):
            continue
        all_uuids.pop(uuid, None)
        for other in all_uuids.values():
            other["parent_candidates"] = [
                parent for parent in other.get("parent_candidates", [])
                if parent != uuid
            ]

    # The Kryo feature map's Pair second component is passed to the typed
    # GATT characteristic lookup. It outranks file-level and name guesses.
    for uuid in _kryo_ooler_feature_characteristics(file_texts):
        if uuid in all_uuids:
            merge_role_evidence(all_uuids[uuid], "GATT Characteristic", "usage:kryo-feature-pair")
    for uuid in _spot_model_characteristics(file_texts):
        if uuid in all_uuids:
            merge_role_evidence(all_uuids[uuid], "GATT Characteristic", "usage:spot-character-map")
    for uuid in _sunradon_typed_characteristics(file_texts):
        if uuid in all_uuids:
            merge_role_evidence(all_uuids[uuid], "GATT Characteristic", "usage:sunradon-typed-getter")

    for uuid in _riddell_set_pu_characteristics(file_texts):
        if uuid in all_uuids:
            merge_role_evidence(all_uuids[uuid], "GATT Characteristic", "usage:riddell-config-writer")

    # Pass D: normalize the candidates collected by scan_one_file. These
    # candidates are local evidence (both UUIDs occurred in the same Java
    # file); replacing them with every Service in the APK loses that
    # provenance and assigns unrelated Services as parents. A cross-file
    # role correction can make a UUID a Characteristic, but it is not enough
    # evidence to infer a parent when its own file had none.
    for entry in all_uuids.values():
        entry["parent_candidates"] = list(dict.fromkeys(entry.get("parent_candidates", [])))

    return all_uuids


def filter_vendor_specific(
    found: dict[str, dict],
    member_uuids: dict[str, str] | None = None,
    curated_uuids: set[str] | None = None,
) -> tuple[dict[str, dict], set[str]]:
    """Filter `found` down to UUIDs that should be emitted into CLUES output,
    and separately return the set of UUID16s that *were* in member_uuids.yaml
    (used to infer the app's company).

    Dropped:
      - UUIDs in SIG-standard UUID16 ranges (services 0x1800-0x18FF, etc.)
      - UUIDs in `member_uuids.yaml` — those are already in the public
        Bluetooth SIG list, no need to re-record them. We still surface them
        as `member_hits` so the per-APK company-inference step can use them.
      - UUIDs already present in the curated CLUES_data_human_verified.json. Those entries
        are human-verified and authoritative; re-emitting auto-extracted
        versions would risk a curator accepting a regression on merge.

    Kept:
      - Vendor UUID16s outside the SIG-standard ranges AND not in
        member_uuids AND not in curated CLUES
      - All vendor UUID128s not in curated CLUES
    """
    member_uuids = member_uuids or {}
    curated_uuids = curated_uuids or set()
    out: dict[str, dict] = {}
    member_hits: set[str] = set()
    for uuid, entry in found.items():
        # Phase-6 cache: hard-drop confirmed-non-BLE UUID-shaped tokens
        # (Google Business Messages agent IDs, Gannett topic IDs, etc.)
        # whether they appear as full UUID128 or as a SIG-collapsed short.
        if uuid.lower() in KNOWN_NON_BLE_UUIDS:
            continue
        # Curated CLUES check is first because it applies to both UUID16
        # and UUID128 forms (collapsed and full). We check the full uuid
        # first, then the would-be-emitted short form if SIG-base wrapped.
        if uuid in curated_uuids:
            continue
        m = SIG_BASE_RE.match(uuid)
        if m:
            short = m.group(1).lower()
            if is_standard_sig_uuid16(short):
                continue
            if short in KNOWN_NON_BLE_UUIDS:
                continue
            if short in member_uuids:
                # Already published in member_uuids.yaml — don't duplicate
                # into CLUES output, but record the hit for company inference.
                member_hits.add(short)
                continue
            if short in curated_uuids:
                continue
            entry["_emit_as"] = short
            out[short] = entry
        else:
            entry["_emit_as"] = uuid
            out[uuid] = entry
    return out, member_hits


# ---------------------------------------------------------------------------
# CLUES record building / merging
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Phase-6 caches: lessons learned from prior Phase-5 runs.
# ---------------------------------------------------------------------------
# `KNOWN_NON_BLE_UUIDS` — UUID-shaped tokens that Phase 5 has confirmed are
# NOT Bluetooth UUIDs (Google Business Messages agent IDs, Gannett topic IDs,
# Salesforce session IDs, etc.). These were caught by the Phase-1 regex
# because they share UUID128 shape, but they live inside URLs / topic-ID
# comparisons / non-BLE contexts. Filtering them at Phase 1 prevents the
# false-positive record from being recreated on every re-scan of the same APK.
# Stored lowercased, canonical form (with dashes for UUID128, bare hex for
# UUID16). Add new entries via Phase 6.
KNOWN_NON_BLE_UUIDS: set[str] = {
    # Populated by Phase 6 as Phase 5 confirms false-positives.
    # Phase-5 false-positive review: this token is NOT a BLE UUID. It is the
    # agent_id query parameter in a Google Business Messages widget URL
    # (`https://businessmessages.google.com/widget/agent/226cc854-...`)
    # hard-coded in `com.simplisafe.mobile.utils.Vars.IN_APP_CHAT_URL`.
    "226cc854-a3fb-438e-bdbe-bc39f7045804",
    "48c9ea12-fdd0-46f5-9c2e-6e120abcaf20",
    # ------------------------------------------------------------
    # Phase-6 (folders 0014..0017, 2026-05): full Gannett news-content
    # topic-GUID family. Same shape as the single 48c9ea12 entry above —
    # Gannett uses UUID128-shaped strings as topic IDs across their
    # com.gannett.android.news.features.base.utils + sibling packages.
    # Field names captured by Phase 1 include `opinion_system_tag`,
    # `FACEBOOK_ID`, `liveStoryTagProd`, `BIG_STORY_TAG_GUID`,
    # `AR_TAG_GUID`, `INVESTIGATION`, etc. None of these are Bluetooth.
    "198ac15e-c735-49d0-93ec-509b8b4778a0",  # opinion_system_tag
    "1d6d74e9-bec3-4c25-95e2-9625b3f6ec38",  # opinion_collection_system_tag
    "1da72bcb-13f1-4543-8720-7404c0d52d2d",  # liveStoryTagStage
    "2819d279-dcf3-4c49-8157-f17469b3eaa6",  # FRONT_GLOSSY_TAG_PHONE
    "2afbc71f-0c16-45b9-a6be-df11c0ba569e",  # BIG_STORY_TAG_GUID_STAGING
    "34434e1c-06c2-48ae-9086-01b4b9c941c3",  # ANALYSIS
    "469e6fcb-0816-432a-b844-4d3236aba34d",  # modularStoryTagProd
    "5b804337-22c8-46b8-8c83-09dd1adea8b0",  # FACEBOOK_ID
    "5b84e8dc-2a50-4c5c-9293-bf6a6fc9fe8c",  # liveStoryTagProd
    "5fda21d6-808f-4ace-bf2e-c5157e6cfd2c",  # EXCLUSIVE
    "73bd44ae-5c8a-4a76-aa89-15915b891dde",  # FRONT_GLOSSY_TAG_TABLET
    "87be7ece-c48e-4e85-9246-1976bb43f796",  # HOME_FRONT_GLOSSY_TAG_TABLET
    "8a38660e-6d04-45bd-ae91-7be7aaf535b2",  # AR_TAG_GUID
    "93ff038a-fd04-477b-9f8e-28b654b0d8a0",  # editorial_system_tag
    "a641e2a4-d635-4fb1-a261-2fb076ead22e",  # modularStoryTagStage
    "c431e6b7-7cfc-49a0-a26b-48f5d3c64f10",  # INVESTIGATION
    "d9abe0f9-8cd4-4654-bafc-cb85570e0c55",  # THE_SHORT_LIST_STAGING
    "ddd49cd2-64dc-4de1-b056-8f414b94ae3d",  # HOME_FRONT_GLOSSY_TAG_PHONE
    "dfefe7a0-3ed3-4aa8-bbde-64b39f56803a",  # BIG_STORY_TAG_GUID
    "e227eb03-6038-4ace-b8f2-ccab87b38302",  # AR_TAG_GUID_STAGING
    "fa96f701-795a-4d73-974a-67a1a933dec0",  # THE_SHORT_LIST
    # ------------------------------------------------------------
    # Phase-6 chunk 02 (folders 0393..0459, 2026-05): Phase-5
    # confirmed these UUID-shaped strings are not BLE.
    "29d9ed98-a469-4536-ade2-f981bc1d605e",
    "9188040d-6c67-4c5b-b112-36a304b66dad",
    # ------------------------------------------------------------
    # Phase-6 chunk 03 (folders 0460..0526, 2026-05): RFC 4122
    # namespace UUIDs for UUIDv3/v5 deterministic generation.
    # Appear in apps that derive content-addressed IDs, never
    # on the BLE air interface. Constant per the IETF RFC.
    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",  # NAMESPACE_DNS
    "6ba7b811-9dad-11d1-80b4-00c04fd430c8",  # NAMESPACE_URL
    "6ba7b812-9dad-11d1-80b4-00c04fd430c8",  # NAMESPACE_OID
    "6ba7b814-9dad-11d1-80b4-00c04fd430c8",  # NAMESPACE_X500
    # ------------------------------------------------------------
    # Phase-6 (AndroZoo BLUETOOTH_SCAN batch 1, 2026-09): AOSP
    # android.media.audiofx effect-type UUIDs. Verified by reading
    # io/agora/base/internal/voiceengine/WebRtcAudioEffects.java in
    # ac.cloud.com -- they are AudioEffect type UUIDs passed to
    # AcousticEchoCanceler / NoiseSuppressor / AutomaticGainControl,
    # never to any BluetoothGatt API. They previously clustered with
    # real BLE UUIDs only because they share the 0002a5d5c51b suffix.
    "aa8130e0-66fc-11e0-bad0-0002a5d5c51b",  # AOSP_AUTOMATIC_GAIN_CONTROL
    "bb392ec0-8d4d-11e0-a896-0002a5d5c51b",  # AOSP_ACOUSTIC_ECHO_CANCELER
    "c06c8400-8e06-11e0-9cb6-0002a5d5c51b",  # AOSP_NOISE_SUPPRESSOR
}

# `KNOWN_SDK_JAVA_PACKAGES` — Java-package-prefix → company-name mapping for
# third-party BLE SDKs whose Java packages are stable and unique enough to
# identify by import path alone. When Phase 1 finds a UUID declared in a Java
# package matching one of these prefixes, it skips the "Third-party SDK code
# (Phase-4 identification needed)" placeholder and uses the cached company
# directly — exactly as if the UUID itself was in `KNOWN_SDK_UUIDS`.
# Match is on dot boundaries: a key `com.foo.sdk` matches both
# `com.foo.sdk` exactly and any subpackage like `com.foo.sdk.internal.ble`.
# Add new entries via Phase 6 after Phase 4/5 identifies an SDK.
KNOWN_SDK_JAVA_PACKAGES: dict[str, str] = {
    # Populated by Phase 6 as Phase 4/5 identifies SDK Java-package prefixes.
    # Each entry is gated by a token-overlap check (Java-package tokens must
    # share ≥1 element with the company-name tokens) so a merge-induced
    # cross-pollination like `com.ihealth.* -> WeCo Batteries` can't slip in.
    # ------------------------------------------------------------
    # Phase-5 attributions, folders 0008+0009 (2026-05):
    "com.bluecats.sdk":         "BlueCats (Bluetooth beacon SDK — com.bluecats.sdk)",
    "com.elatec.mobilebadge":   "Elatec GmbH (Germany) — Mobile Badge SDK (com.elatec.mobilebadge)",
    "com.ido.ble":              "iDO Smart Wearable BLE SDK (com.ido.ble — Chinese smartwatch/fitness-band common SDK)",
    "com.iseo.io":              "Iseo Serrature S.p.A. (Italian smart-lock vendor) — CSR-based mobile credentials SDK",
    "com.meross.ble":           "Meross Technology (com.meross.ble — wifi/bluetooth smart-home SDK; OEM-shipped in Refoss-brand devices)",
    "com.tesa.tesalocklibrary": "TESA Assa Abloy (Spain) — TESA Lock BLE SDK (com.tesa.tesalocklibrary)",
    "de.kisi.android":          "Kisi (German cloud-based access-control company)",
    # ------------------------------------------------------------
    # Phase-6 attributions, folders 0010..0013 (2026-05):
    "com.minew.device":         "Minew Technology (Chinese BLE beacon / IoT module manufacturer)",
    # ------------------------------------------------------------
    # Phase-6 attributions, folders 0014..0017 (2026-05):
    "com.android.chileaf":              "Chileaf (Chinese fitness/cardio device vendor; com.android.chileaf.fitness Android SDK)",
    "com.networkr.external":            "Networkr (event-networking platform; com.networkr.external.click2connect.ConnectSDK)",
    "com.polar.androidcommunications":  "Polar Electro (heart-rate / fitness sensor BLE protocol; com.polar.androidcommunications SDK)",
    # ------------------------------------------------------------
    # Phase-6 attributions, folders 0026..0030 (2026-05):
    "com.kontakt.sdk":                  "Kontakt.io (Polish BLE beacon vendor; com.kontakt.sdk.android Android SDK)",
    "com.yongse.android":               "Yongse Technology (Chinese BLE module vendor; com.yongse.android.ble Android SDK — heater / general-power / w31x product lines)",
    # ------------------------------------------------------------
    # Phase-6 attributions, folders 0031..0035 (2026-05):
    "com.sifli.siflidfu":               "Sifli Technology (Chinese BLE chip vendor; com.sifli.siflidfu Android SDK)",
    # ------------------------------------------------------------
    # Phase-6 attributions, folders 0036..0040 (2026-05):
    "com.agamatrix.ambtsdk":            "AgaMatrix (US glucose-meter manufacturer; com.agamatrix.ambtsdk Android SDK; OEM-shipped in Sensyne DBm-Health)",
    "com.validic.mobile.ble":           "Validic (US digital-health connectivity SDK; com.validic.mobile.ble — bridges medical-device BLE to clinical apps)",
    "com.unikey.sdk":                   "UniKey Technologies (US smart-lock SDK; com.unikey.sdk Android library, used by DMP Joule and other locks)",
    "com.hprt":                         "HPRT (Hangzhou Polymer Printing Industries — Chinese label/photo printer vendor; com.hprt.cp4lib Android SDK)",
    "pl.netizens.myspiroosdk":          "MySpiroo (Polish spirometer vendor — pl.netizens.myspiroosdk Android SDK; integrated by Healthup Doctor app)",
    "com.nix.nixsensor_lib":            "Nix Sensor Ltd. (Canadian color-measurement device vendor; com.nix.nixsensor_lib Android SDK)",
    # ------------------------------------------------------------
    # Phase-6 attributions (AndroZoo BLUETOOTH_SCAN batch 1, 2026-09):
    "com.sumup.reader.core":    "SumUp (card-reader SDK - com.sumup.reader.core.pinplus.transport; Air / Solo / PIN+ readers)",
    "com.squareup.cardreader":  "Square (Square Reader BLE GATT SDK - com.squareup.cardreader.ble.R12Gatt)",
    "com.ttlock.bl.sdk":        "Sciener (TTLock smart-lock SDK - com.ttlock.bl.sdk; UUID 73631912-... is ASCII 'scienerisfirst')",
    "com.kogenta.kettle":       "Kogenta (Kettle beacon-proximity SDK - com.kogenta.kettle; developer.kogenta.com)",
    "com.epson.epsonio":        "Epson (Epson IO BLE SDK - com.epson.epsonio.ble; Kagaribi chip series)",
    # AE00 is shared with Jieli, so attribute Suprema only when source belongs
    # to its SDK package instead of using a global UUID16 cache hit.
    "com.supremainc.android.libsupremaac": "Suprema Inc. (Korean biometric / access-control vendor; com.supremainc.android.libsupremaac SDK)",
    "com.skidata.mobileflow_plugin": "Skidata GmbH (MobileFlow ski-pass / access-control SDK)",
}


def java_package_known_sdk(declaring_pkg: str) -> str | None:
    """If `declaring_pkg` (or any dot-prefixed ancestor) is in
    KNOWN_SDK_JAVA_PACKAGES, return the cached company. Otherwise None.
    """
    if not declaring_pkg:
        return None
    for prefix in KNOWN_SDK_JAVA_PACKAGES:
        if declaring_pkg == prefix or declaring_pkg.startswith(prefix + "."):
            return KNOWN_SDK_JAVA_PACKAGES[prefix]
    return None


def _detect_third_party_sdk_package(
    declaring_packages: set[str],
    host_pkg: str,
) -> str | None:
    """If a UUID was declared inside a Java package whose top-level vendor
    tokens don't overlap with the host APK's package_id, return the most
    distinctive declaring-package string. That's a strong single-APK
    signal the UUID belongs to a third-party SDK, not the host app's own
    code. Phase-4 cluster detection requires ≥3 unrelated host apps; this
    catches the case where we only see the SDK in one host so far.

    Examples:
      host_pkg = "sesame.smartspaces.d2i.co"
      declaring = {"com.ondo.ocssmartlibrary.utils"}
       → returns "com.ondo.ocssmartlibrary.utils"
         (tokens 'ondo'/'ocssmartlibrary' don't appear in the host)

      host_pkg = "com.abbott.lingo.wellness"
      declaring = {"com.abbott.lingo.wellness.bsm"}
       → returns None (tokens overlap on 'abbott'/'lingo')
    """
    if not declaring_packages:
        return None
    host_tokens = {
        t.lower() for t in re.split(r"\W+", host_pkg)
        if t and t.lower() not in _TLDLIKE_COMPONENTS and len(t) >= 3
    }
    best: str | None = None
    best_len = -1
    for dpkg in declaring_packages:
        d_tokens = {
            t.lower() for t in dpkg.split(".")
            if t and t.lower() not in _TLDLIKE_COMPONENTS and len(t) >= 3
        }
        if d_tokens & host_tokens:
            continue  # this declaring package looks like host's own code
        # Distinct-from-host candidate — prefer the longest one (more specific).
        if len(dpkg) > best_len:
            best = dpkg
            best_len = len(dpkg)
    return best


SDK_AUTHORITATIVE_ROLE_SOURCES = (
    "usage:",
    "cross-file usage:",
    "cross-file constructor:",
    "ambiguous-",
    "indexed-array-usage",
    "catalog-map",
    "sink-lhs:",
    "sql-catalog:",
    "nested-type:",
)


def _classification_with_sdk_cache(uuid: str, classification: str, source: str) -> str:
    """Apply the curated SDK role only when source evidence is not stronger."""
    sdk_hit = KNOWN_SDK_UUIDS.get(uuid.lower())
    if not sdk_hit or source.startswith(SDK_AUTHORITATIVE_ROLE_SOURCES):
        return classification
    sdk_name = (sdk_hit.get("name") or "").upper()
    if "SERVICE" in sdk_name or "_SVC" in sdk_name:
        return "GATT Service"
    if "CHAR" in sdk_name or "DESCRIPTOR" in sdk_name:
        return "GATT Characteristic"
    return classification


def _resolved_uuid_roles(found: dict[str, dict]) -> dict[str, str]:
    """Build role lookups for validating parent candidates after SDK resolution."""
    roles: dict[str, str] = {}
    for uuid, entry in found.items():
        normalized = normalize_uuid(uuid)
        role = _classification_with_sdk_cache(
            normalized,
            entry.get("classification", "Unknown"),
            entry.get("classification_source", ""),
        )
        roles[normalized] = role
        sig_match = SIG_BASE_RE.match(normalized)
        if sig_match:
            roles[sig_match.group(1).lower()] = role
    return roles


def build_record(
    uuid: str,
    entry: dict,
    apk_meta: dict,
    package_path: str,
    submitter: str,
    inferred_company: str,
    resolved_roles: dict[str, str] | None = None,
) -> dict:
    classification = entry["classification"]
    pkg = apk_meta["package_id"]
    field_name = entry.get("field_name")
    cls_source = entry.get("classification_source", "naming-convention")
    uuid_name = uuid_name_from_field(field_name) or "Unknown"
    declaring_packages = entry.get("declaring_packages", set())
    third_party_sdk_pkg = _detect_third_party_sdk_package(declaring_packages, pkg)

    # If this UUID is in the curated KNOWN_SDK_UUIDS table (Phase 4 cache of
    # third-party-SDK UUIDs), use those values directly — they beat any
    # per-package inference. The host app's package_id is recorded in
    # android_info_array regardless, so provenance isn't lost.
    sdk_hit = KNOWN_SDK_UUIDS.get(uuid.lower())
    if sdk_hit:
        company_for_record = sdk_hit["company"]
        uuid_name_for_record = sdk_hit.get("name") or uuid_name
        # SDK hits override classification too. The SDK table is authoritative
        # about each UUID's role; per-file heuristics often misclassify when
        # the declaring file imports both BluetoothGattService AND
        # BluetoothGattCharacteristic (e.g. FlicManager declares both Service
        # `g` and Characteristic `h, i` in the same file → file-level default
        # picks the wrong one for `g`). When the SDK-canonical name contains
        # SERVICE/SVC we mark it as a Service; CHAR/DESCRIPTOR → Characteristic.
        classification = _classification_with_sdk_cache(uuid, classification, cls_source)
    elif third_party_sdk_pkg:
        cached_sdk_company = java_package_known_sdk(third_party_sdk_pkg)
        if cached_sdk_company:
            company_for_record = cached_sdk_company
        else:
            company_for_record = (
                f"Third-party SDK code (declared in Java package "
                f"`{third_party_sdk_pkg}` — distinct from host {pkg}; "
                f"Phase-4 identification needed)"
            )
        uuid_name_for_record = uuid_name
    else:
        company_for_record = inferred_company
        uuid_name_for_record = uuid_name

    # Discovery and role are not the UUID's function. Source review can
    # replace this once a functional purpose is supported by evidence.
    purpose = "The purpose is unknown."

    rec: dict = {
        "UUID": uuid,
        "company": company_for_record,
        "UUID_name": uuid_name_for_record,
        "UUID_purpose": purpose,
        "UUID_usage_array": [classification],
        "evidence_array": [
            {
                "description": (
                    f"Found in decompiled DEX of {pkg} "
                    f"v{apk_meta['version_name']} (versionCode "
                    f"{apk_meta['version_code']})"
                    + (f", in Java field `{field_name}`" if field_name else "")
                    + (f", declared in Java package `{third_party_sdk_pkg}` (third-party SDK)"
                       if third_party_sdk_pkg else "")
                    + f". Classification source: {cls_source}."
                ),
                "submitter": submitter,
            }
        ],
        "android_info_array": [
            {
                "package_id": pkg,
                "version_code": apk_meta["version_code"],
                "version_name": apk_meta["version_name"],
                "package_path": compact_package_path(package_path),
                "description": (
                    f"Detected by apk-clues-extract scan; usage '{classification}'"
                    + (f"; Java field `{field_name}`" if field_name else "")
                    + "."
                ),
            }
        ],
    }
    if classification == "GATT Characteristic" and entry.get("parent_candidates"):
        # A co-located Service is useful local evidence only when it is the
        # sole candidate. Choosing the lexicographically smallest among several
        # candidates is arbitrary and has produced false parent links when an
        # APK contains multiple GATT profiles. Keep the schema's optional
        # parent_UUID absent when the local evidence is ambiguous.
        def parent_class(p: str) -> tuple[int, str]:
            m = SIG_BASE_RE.match(p)
            if m:
                short = m.group(1).lower()
                if is_standard_sig_uuid16(short):
                    return (2, p)  # SIG-standard: not emitted by this extractor
                return (1, short)  # vendor UUID16
            return (0, p)  # vendor UUID128

        parents = list(dict.fromkeys(entry["parent_candidates"]))
        if resolved_roles is not None:
            parents = [
                parent for parent in parents
                if resolved_roles.get(normalize_uuid(parent)) == "GATT Service"
            ]
        if len(parents) == 1:
            parent = parents[0]
            parent_kind, parent_value = parent_class(parent)
            if parent_kind != 2:
                rec["parent_UUID"] = parent_value
    return rec


# ---------------------------------------------------------------------------
# Evidence-array deduplication
# ---------------------------------------------------------------------------
#
# A single record can collect many evidence entries: one per APK encounter
# from Phase 1, one URL evidence per (package_id, version_name) from Phase 3,
# Phase-5 attribution notes, etc. Without deduplication a record routinely
# accumulates redundant entries because:
#
#   * A UUID found in multiple Java files within the same APK creates a
#     `Found in decompiled DEX of <pkg> v<ver>` entry per file — those convey
#     the same fact ("seen in this APK build") and only differ in metadata
#     like the classification source or the Java field name. The
#     android_info_array already carries the (pkg, version_code) deduped
#     view of the same fact, so multiple evidence entries are pure noise.
#   * Re-running a phase that appends an evidence entry (Phase 3 URL, Phase 5
#     note) on a record that already had it would otherwise stack identical
#     entries every run.
#
# `dedupe_evidence_array` collapses all of the above into a single entry per
# logical fact: one per URL, one per (pkg, version_name, version_code), one
# per (description, submitter) for anything else. When two entries collide it
# keeps the more informative survivor (prefers the entry that captured a
# Java field name and an authoritative classification source).
_FOUND_IN_DEX_RE = re.compile(
    r'^Found in decompiled DEX of (\S+) v(\S+) \(versionCode (\d+)\)'
)


def _evidence_priority(e: dict) -> tuple:
    """Higher tuple = more informative. Used to pick the survivor when two
    evidence entries collide on the same dedup key."""
    desc = e.get("description") or ""
    has_field = "in Java field " in desc
    has_third_party = "third-party SDK" in desc
    # Authoritative > heuristic > file-level fallback.
    if "Classification source: usage:" in desc:
        cls_rank = 3
    elif "Classification source: naming-convention" in desc:
        cls_rank = 2
    elif "Classification source: anchor-line" in desc:
        cls_rank = 2
    elif "Classification source: window" in desc:
        cls_rank = 2
    elif "Classification source: file-level-default" in desc:
        cls_rank = 1
    else:
        cls_rank = 0
    return (has_third_party, has_field, cls_rank, len(desc))


def dedupe_evidence_array(evidence: list) -> list:
    """Return a new evidence_array with duplicate entries collapsed.

    Two entries are duplicates iff any of these match:
      * Both carry the same `URL` (case-insensitive after strip).
      * Both descriptions begin with
        "Found in decompiled DEX of <pkg> v<ver> (versionCode <code>)"
        with identical (pkg, version_name, version_code).
      * Both have identical (description, submitter) (and neither has a URL).

    When two entries collide, the higher-priority survivor wins (prefers
    Java-field-named, authoritative-classification, third-party-SDK-annotated
    entries). Order is preserved: the survivor occupies the position of the
    first occurrence.
    """
    if not evidence:
        return list(evidence) if evidence is not None else []
    out: list = []
    seen: dict = {}  # dedup_key -> index in `out`
    for e in evidence:
        if not isinstance(e, dict):
            out.append(e)
            continue
        desc = (e.get("description") or "").strip()
        url = (e.get("URL") or "").strip().lower()
        sub = (e.get("submitter") or "").strip()
        if url:
            key = ("URL", url)
        else:
            m = _FOUND_IN_DEX_RE.match(desc)
            if m:
                key = ("DEC", m.group(1).lower(), m.group(2), m.group(3))
            else:
                key = ("OTHER", desc, sub)
        if key in seen:
            idx = seen[key]
            if _evidence_priority(e) > _evidence_priority(out[idx]):
                out[idx] = e
        else:
            seen[key] = len(out)
            out.append(e)
    return out


def _usage_role_signal(rec: dict, role: str) -> int:
    """Score how strongly a record supports one GATT role over the other."""
    role_l = role.lower()
    other_l = "service" if role == "Characteristic" else "characteristic"
    score = 0

    name = rec.get("UUID_name") or ""
    name_cls = classify_via_field_name(name)
    if name_cls == f"GATT {role}":
        score += 90
    elif name_cls == f"GATT {other_l.title()}":
        score -= 90

    if role == "Characteristic" and rec.get("parent_UUID"):
        score += 80

    purpose = (rec.get("UUID_purpose") or "").lower()
    if f"gatt {role_l}" in purpose or role_l in purpose:
        score += 15
    if f"gatt {other_l}" in purpose:
        score -= 15

    for ev in rec.get("evidence_array", []):
        desc = (ev.get("description") or "").lower()
        if role == "Characteristic":
            if "usage:getcharacteristic" in desc or "writecharacteristic" in desc or "setcharacteristicnotification" in desc:
                score += 180
            if "bluetoothgattcharacteristic" in desc or "gatt characteristic" in desc:
                score += 25
            if "usage:getservice" in desc:
                score -= 180
        else:
            if "usage:getservice" in desc:
                score += 180
            if "bluetoothgattservice" in desc or "gatt service" in desc:
                score += 25
            if "usage:getcharacteristic" in desc or "writecharacteristic" in desc or "setcharacteristicnotification" in desc:
                score -= 180
    return score


GATT_ROLE_TEXT_RE = re.compile(r"\bGATT (Service|Characteristic)\b")
ANDROID_INFO_USAGE_RE = re.compile(r"usage 'GATT (Service|Characteristic)'")


def _single_usage_role(rec: dict) -> str | None:
    usage = rec.get("UUID_usage_array") or []
    if len(usage) == 1 and usage[0] in {"GATT Service", "GATT Characteristic"}:
        return usage[0]
    return None


def _parent_uuid_key(uuid: str) -> str:
    normalized = normalize_uuid(str(uuid))
    sig_match = SIG_BASE_RE.match(normalized)
    return sig_match.group(1).lower() if sig_match else normalized


def _validated_new_parent_records(
    existing: list[dict], new_records: list[dict]
) -> list[dict]:
    """Drop invalid parent proposals from this batch without rewriting old rows."""
    target_roles: dict[str, set[str]] = {}
    for record in [*existing, *new_records]:
        uuid = record.get("UUID")
        if not uuid:
            continue
        roles = target_roles.setdefault(_parent_uuid_key(uuid), set())
        roles.update(
            role for role in (record.get("UUID_usage_array") or [])
            if role in {"GATT Service", "GATT Characteristic"}
        )

    validated: list[dict] = []
    for record in new_records:
        copy = dict(record)
        parent = copy.get("parent_UUID")
        if parent:
            target_roles_for_parent = target_roles.get(_parent_uuid_key(parent))
            if target_roles_for_parent is not None and target_roles_for_parent != {"GATT Service"}:
                copy.pop("parent_UUID", None)
        if _single_usage_role(copy) != "GATT Characteristic":
            copy.pop("parent_UUID", None)
        validated.append(copy)
    return validated


def _uuid_name_compatible_with_usage(name: str | None, usage: str | None) -> bool:
    if not name or not usage:
        return True
    implied = classify_via_field_name(name)
    return implied is None or implied == usage


def _sync_record_role_text(rec: dict) -> None:
    """Keep generated role text aligned after usage reconciliation.

    Evidence descriptions are left alone because they document what a specific
    scan observed. The synthesized record purpose and android_info summary
    should describe the final deconflicted role.
    """
    role = _single_usage_role(rec)
    if not role:
        return
    purpose = rec.get("UUID_purpose")
    if isinstance(purpose, str) and GATT_ROLE_TEXT_RE.search(purpose):
        rec["UUID_purpose"] = GATT_ROLE_TEXT_RE.sub(role, purpose)
    name = rec.get("UUID_name")
    if isinstance(name, str) and not _is_unknown_name(name):
        aliases = [a.strip() for a in name.split(" / ") if a.strip()]
        compatible = [a for a in aliases if _uuid_name_compatible_with_usage(a, role)]
        if len(compatible) != len(aliases):
            rec["UUID_name"] = " / ".join(compatible) if compatible else "Unknown"
    for info in rec.get("android_info_array", []):
        desc = info.get("description")
        if isinstance(desc, str) and ANDROID_INFO_USAGE_RE.search(desc):
            info["description"] = ANDROID_INFO_USAGE_RE.sub(f"usage '{role}'", desc)
    if role == "GATT Service":
        rec.pop("parent_UUID", None)


def _direct_gatt_roles_in_record(rec: dict) -> set[str]:
    """Return only role claims with explicit source-backed sink evidence.

    Names, parents, prose purposes, and file-level defaults are deliberately
    excluded: they can help choose one role but cannot justify retaining both.
    """
    roles: set[str] = set()
    evidence = rec.get("evidence_array") or []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        desc = item.get("description") or ""
        if re.search(
            r"Classification source:\s*(?:cross-file )?usage:getService\b|"
            r"Classification source:\s*cross-file constructor:new BluetoothGattService\b",
            desc,
            re.IGNORECASE,
        ):
            roles.add("GATT Service")
        if re.search(
            r"Classification source:\s*(?:cross-file )?usage:(?:getCharacteristic|writeCharacteristic|readCharacteristic|setCharacteristicNotification|setCharacteristicIndication)\b|"
            r"Classification source:\s*cross-file constructor:new BluetoothGattCharacteristic\b",
            desc,
            re.IGNORECASE,
        ):
            roles.add("GATT Characteristic")

        # Source-reviewed correction notes sometimes cite exact API calls
        # instead of using the extractor's Classification source label. Count
        # them only when the note explicitly binds both calls to the same UUID.
        if (
            re.match(r"\s*Source[- ]review(?:ed)?\b", desc, re.IGNORECASE)
            and re.search(r"\bsame (?:UUID|literal|target)\b", desc, re.IGNORECASE)
        ):
            if re.search(r"\bgetService\b", desc, re.IGNORECASE):
                roles.add("GATT Service")
            if re.search(
                r"\b(?:getCharacteristic|writeCharacteristic|readCharacteristic|setCharacteristicNotification|setCharacteristicIndication)\b",
                desc,
                re.IGNORECASE,
            ):
                roles.add("GATT Characteristic")
    return roles


def reconcile_uuid_usage(cur: dict, rec: dict) -> list[str]:
    """Reconcile conflicting roles without discarding proven dual use.

    Phase-1 has weak service fallbacks for constant-only files. Keep the
    existing single-role scoring for weak conflicts, but retain both roles
    when source-backed evidence independently proves each GATT sink.
    """
    cur_usage = cur.get("UUID_usage_array", [])
    rec_usage = rec.get("UUID_usage_array", [])
    combined = list(dict.fromkeys(cur_usage + rec_usage))
    if len(combined) <= 1:
        return combined
    if set(combined) != {"GATT Service", "GATT Characteristic"}:
        return combined

    direct_roles = _direct_gatt_roles_in_record(cur) | _direct_gatt_roles_in_record(rec)
    if direct_roles == {"GATT Service", "GATT Characteristic"}:
        return ["GATT Service", "GATT Characteristic"]

    char_score = _usage_role_signal(cur, "Characteristic") + _usage_role_signal(rec, "Characteristic")
    svc_score = _usage_role_signal(cur, "Service") + _usage_role_signal(rec, "Service")
    if char_score > svc_score:
        return ["GATT Characteristic"]
    if svc_score > char_score:
        return ["GATT Service"]

    # Tie-breaker: keep the established role rather than inventing ambiguity.
    if cur_usage == ["GATT Characteristic"] or rec_usage == ["GATT Characteristic"]:
        return ["GATT Characteristic"]
    return cur_usage[:1] or rec_usage[:1] or combined[:1]


def merge_records(existing: list[dict], new_records: list[dict]) -> list[dict]:
    """De-dupe by UUID. When two records have the same UUID, merge their
    android_info_array and reconcile UUID_usage_array. Existing curated fields
    (company / UUID_name / UUID_purpose) are kept unless they are still the
    auto-generated placeholders — in which case a *better* value from the
    new record (specifically: a non-"Unknown" company or UUID_name) takes
    over. This lets a second APK that has more identifying info upgrade an
    earlier record that only saw a poorly-named instance."""
    by_uuid: dict[str, dict] = {}
    new_records = _validated_new_parent_records(existing, new_records)
    for rec in existing:
        u = rec.get("UUID", "").lower()
        if u:
            by_uuid[u] = rec

    for rec in new_records:
        u = rec["UUID"].lower()
        if u not in by_uuid:
            by_uuid[u] = rec
            continue
        cur = by_uuid[u]
        # Upgrade company when the existing value is the placeholder.
        if cur.get("company", "Unknown") == "Unknown" and rec.get("company", "Unknown") != "Unknown":
            cur["company"] = rec["company"]
        # A UUID listed in KNOWN_SDK_UUIDS gets its company directly from the
        # SDK table — that statement is about the *UUID's owner* (the SDK
        # vendor), not about the host app. If we are now seeing this UUID
        # paired with its SDK-canonical company, it ALWAYS beats whatever
        # the existing record had (which was likely the host package's
        # publisher from Phase 2 enrichment — a different category of fact).
        if u in KNOWN_SDK_UUIDS:
            sdk_company = KNOWN_SDK_UUIDS[u].get("company")
            if sdk_company and rec.get("company") == sdk_company:
                cur["company"] = sdk_company
        # Upgrade UUID_name to the more semantic alternative. This handles
        # the case where one APK has the UUID under field name `LED_COLOR_UUID`
        # and another APK (with the obfuscator turned on) has it as `f15558a`
        # — we want `LED COLOR` (or `LED_COLOR_UUID`) to win.
        #
        # Ambiguous-name handling: some shared UUIDs are reused across
        # related device families with *different* but equally-valid names.
        # The user-cited Climax model: the same UUID is `ClearStepCounter`
        # in BL3Characteristic and `SetDisarmCode` in a BL4 panel, etc.
        # When both names are individually meaningful (score ≥ 25) and
        # neither is a strict prefix/substring of the other, preserve both
        # as aliases joined by ` / ` instead of forcing a canonical pick.
        cur_name = cur.get("UUID_name", "Unknown")
        new_name = rec.get("UUID_name", "Unknown")
        if new_name and new_name != "Unknown":
            cur_score = name_semantic_score(cur_name)
            new_score = name_semantic_score(new_name)
            # Tokenize current aliases to test "already present".
            existing_aliases = {a.strip() for a in cur_name.split(" / ")} if cur_name and cur_name != "Unknown" else set()
            if new_score > cur_score and new_name not in existing_aliases:
                cur["UUID_name"] = new_name
            elif (
                cur_score >= 25
                and new_score >= 25
                and new_name not in existing_aliases
                and cur_name not in new_name
                and new_name not in cur_name
                and len(existing_aliases) < 4  # cap at 4 aliases so the field stays readable
            ):
                cur["UUID_name"] = cur_name + " / " + new_name
        # Merge android_info_array (dedupe by package_id+version_code).
        seen = {(e.get("package_id"), e.get("version_code")) for e in cur.get("android_info_array", [])}
        for entry in rec.get("android_info_array", []):
            key = (entry.get("package_id"), entry.get("version_code"))
            if key not in seen:
                cur.setdefault("android_info_array", []).append(entry)
                seen.add(key)
        # Reconcile UUID_usage_array. Weak mixed-role observations collapse to
        # one role; explicit source-backed use at both GATT sinks is preserved.
        cur["UUID_usage_array"] = reconcile_uuid_usage(cur, rec)
        _sync_record_role_text(cur)
        # Append a fresh evidence entry from each new APK encounter, then
        # collapse duplicates so re-finding the UUID in a sibling Java file
        # of the same APK (different classification source / field) doesn't
        # leave two near-identical entries behind. dedupe_evidence_array is
        # order-preserving, so curator-edited entries stay first.
        cur.setdefault("evidence_array", []).extend(rec.get("evidence_array", []))
        cur["evidence_array"] = dedupe_evidence_array(cur["evidence_array"])
        # Pick up parent_UUID if we now have one and didn't before.
        if "parent_UUID" not in cur and "parent_UUID" in rec:
            cur["parent_UUID"] = rec["parent_UUID"]
    return list(by_uuid.values())


def _is_unknown_name(name: str | None) -> bool:
    return name in (None, "", "Unknown")


def count_unknown_uuid_names(records: list[dict]) -> int:
    return sum(1 for r in records if _is_unknown_name(r.get("UUID_name")))


def semantic_upgrade_report(
    before_by_uuid: dict[str, dict],
    after_records: list[dict],
) -> dict[str, list[dict]]:
    """Summarize semantic improvements made to existing records.

    `--session-output` intentionally reports only brand-new UUID records.
    In `--search-unknown` mode, however, the whole point is usually to
    improve *existing* records: `UUID_name: "Unknown"` becomes a real
    developer label, `company: "Unknown"` becomes a vendor/SDK owner, or an
    already-named UUID gains a better alias. This helper captures those
    upgrades so reprocessing stale Unknowns has an auditable artifact.
    """
    name_upgrades: list[dict] = []
    company_upgrades: list[dict] = []
    for rec in after_records:
        uuid = (rec.get("UUID") or "").lower()
        before = before_by_uuid.get(uuid)
        if not before:
            continue
        old_name = before.get("UUID_name")
        new_name = rec.get("UUID_name")
        if old_name != new_name and _is_unknown_name(old_name) and not _is_unknown_name(new_name):
            name_upgrades.append({
                "UUID": rec.get("UUID"),
                "old_UUID_name": old_name or "Unknown",
                "new_UUID_name": new_name,
                "company": rec.get("company"),
            })
        old_company = before.get("company")
        new_company = rec.get("company")
        if old_company != new_company and (old_company in (None, "", "Unknown")) and new_company not in (None, "", "Unknown"):
            company_upgrades.append({
                "UUID": rec.get("UUID"),
                "UUID_name": rec.get("UUID_name"),
                "old_company": old_company or "Unknown",
                "new_company": new_company,
            })
    name_upgrades.sort(key=lambda r: (str(r.get("UUID", "")).lower(), str(r.get("new_UUID_name", ""))))
    company_upgrades.sort(key=lambda r: (str(r.get("UUID", "")).lower(), str(r.get("new_company", ""))))
    return {
        "UUID_name_upgrades": name_upgrades,
        "company_upgrades": company_upgrades,
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def process_one_apk(
    apk_path: str,
    aapt: str,
    jadx: str,
    submitter: str,
    jadx_timeout_sec: int,
    keep_tmp: bool,
    member_uuids: dict[str, str] | None = None,
    curated_uuids: set[str] | None = None,
    predecompiled: tuple[str, ...] | None = (),
) -> tuple[str, list[dict]]:
    """Returns (status_string, list_of_records).
    status_string is for logging — one of:
        'ok:<n>'             — n UUIDs extracted
        'no_bt_perms'
        'aapt_failed'
        'jadx_failed'
        'jadx_timeout'
        'exception:<msg>'
    """
    fname = os.path.basename(apk_path)
    is_xapk = apk_path.lower().endswith(".xapk")

    tmp_root = tempfile.mkdtemp(prefix="apk_clues_")
    try:
        # For XAPKs, jadx 1.5+ understands the format directly, but using the
        # base APK is faster and more predictable. Extract the base APK first.
        scan_target = apk_path
        if is_xapk:
            base_apk = extract_base_apk_from_xapk(apk_path, tmp_root)
            if base_apk:
                scan_target = base_apk
            # else: fall through and hope jadx handles the .xapk natively

        meta = get_apk_metadata(aapt, scan_target)
        if meta is None:
            return "aapt_failed", []
        if not meta["has_bt_perm"]:
            return "no_bt_perms", []

        jadx_out, reused = jadx_output_dir(
            jadx, apk_path, scan_target, tmp_root, jadx_timeout_sec,
            predecompiled=predecompiled,
        )
        kept: dict[str, dict] = {}
        member_hits: dict = {}
        resolved_roles: dict[str, str] | None = None
        if jadx_out is not None:
            found = scan_jadx_output(jadx_out)
            resolved_roles = _resolved_uuid_roles(found)
            kept, member_hits = filter_vendor_specific(found, member_uuids, curated_uuids)

        # Infer the company for this APK. Prefer a Bluetooth SIG official
        # member name (via member_uuids.yaml hits) over the package-id
        # heuristic. This is the "always prefer SIG official member names
        # where possible" rule.
        inferred = None
        if member_uuids:
            inferred = company_from_member_uuids(
                meta["package_id"], member_hits, member_uuids
            )
        if inferred is None:
            inferred = company_from_package(meta["package_id"])

        records = []
        for emit_uuid, entry in kept.items():
            records.append(
                build_record(
                    emit_uuid, entry, meta, apk_path, submitter, inferred,
                    resolved_roles=resolved_roles,
                )
            )
        managed_meta = dict(meta, inferred_company=inferred)
        managed_status, managed_records = managed_clues.scan_managed_apk(
            scan_target, managed_meta, submitter, curated_uuids or set(), tmp_root
        )
        for rec in managed_records:
            value = rec["UUID"].lower()
            sig_match = SIG_BASE_RE.match(value)
            if value in DROP_OUTRIGHT_UUIDS or value in KNOWN_NON_BLE_UUIDS:
                continue
            if sig_match and is_standard_sig_uuid16(sig_match.group(1)):
                continue
            records = merge_records(records, [rec])

        # A managed-code failure must not become an `ok:0` checkpoint. That
        # would make a Xamarin/MAUI APK appear fully scanned on later runs.
        if managed_status.startswith(("error:", "unavailable:")):
            return f"managed_incomplete:{managed_status} dex={len(kept)}", records
        if jadx_out is None:
            return f"jadx_failed_or_timeout managed={managed_status}", records
        return (f"ok:{len(records)} company={inferred!r} managed={managed_status}"
                + (" (predecompiled)" if reused else "")), records
    except Exception as e:
        return f"exception:{type(e).__name__}:{e}", []
    finally:
        if not keep_tmp:
            shutil.rmtree(tmp_root, ignore_errors=True)


def _is_successful_apk_status(status: str) -> bool:
    """Return whether a per-APK status means the scan completed as intended.

    APKs without Bluetooth permissions are an expected skip. Every other
    status must be an `ok:<count>` result; failures stay non-ok in the
    checkpoint so the normal resume filter retries them on the next run.
    """
    return status == "no_bt_perms" or status.startswith("ok:")


def _field_ref_re(field: str) -> re.Pattern:
    """Match a decompiled Java field reference, with or without class prefix."""
    field = field.strip()
    if "." in field:
        return re.compile(r"(?<![A-Za-z0-9_$])" + re.escape(field) + r"(?![A-Za-z0-9_$])")
    return re.compile(
        r"(?<![A-Za-z0-9_$])(?:[A-Za-z_$][A-Za-z0-9_$]*\.)?"
        + re.escape(field)
        + r"(?![A-Za-z0-9_$])"
    )


def _field_last_segment(field: str) -> str:
    return field.rsplit(".", 1)[-1]


# Phase-5 role-signal gate: only count GATT role evidence (getService /
# write / read / notify / characteristic-changed / UI-log strings) from files
# that actually do BLE. Without this, a UUID-shaped string that ALSO appears
# in a Parcelable's writeToParcel, an AutoValue data class, or an Android
# media class (PlaybackStateCompat) picks up a spurious "write path" signal —
# the root cause of the deep pass's false positives (ARUBA_CONSOLE_SERVICE
# from AbtConfigParcelable.java, GRABTAXI_PROXY_* from AutoValue_*.java,
# NAVUS_IBEACON_* from AboutActivity.java / AdwHomeBadger.java).
PHASE5_BLE_FILE_RE = re.compile(
    # Direct android.bluetooth references...
    r"BluetoothGatt|android\.bluetooth|\bScanFilter\b|\bParcelUuid\b|BluetoothLeScanner|"
    # ...plus GATT operation method names, so BLE-library wrappers (RxAndroidBle,
    # Nordic, GARDENA's WriteCharacteristic.java) that don't contain the literal
    # `BluetoothGatt` token still qualify. These tokens are GATT-specific and do
    # NOT appear in the false-positive files (writeToParcel / AutoValue / media /
    # launcher), so adding them recovers real BLE code without re-admitting noise.
    r"writeCharacteristic|readCharacteristic|setCharacteristicNotification|"
    r"onCharacteristicChanged|onCharacteristicRead|onCharacteristicWrite|GattCallback",
    re.IGNORECASE,
)


def _phase5_deep_re_jadx(
    jadx_out_dir: str,
    target_uuids: set[str],
    package_id: str | None,
) -> dict[str, dict]:
    """Recover names/roles for Unknown UUIDs from deeper local code behavior.

    Phase 1 deliberately stays cheap: literal site, nearby lines, and simple
    cross-file field use. This pass is more interpretive. It traces UUID
    constants through GATT callback aliases and uses observed sinks to recover
    the GATT role. A UUID name is emitted only when a meaningful field name
    survives in the code; app package IDs and behavior labels are not UUID-name
    evidence, since the UUID may come from a bundled third-party SDK. The
    `package_id` argument remains for call-site compatibility but is not used
    to generate names.
    """
    src_dir = os.path.join(jadx_out_dir, "sources")
    if not os.path.isdir(src_dir) or not target_uuids:
        return {}

    java_paths = list(iter_java_files(src_dir))
    file_texts: dict[str, str] = {}
    for jpath in java_paths:
        try:
            with open(jpath, "r", encoding="utf-8", errors="replace") as f:
                file_texts[jpath] = f.read()
        except OSError:
            continue

    # Keep the source file with each obfuscated field. A one-letter name like
    # `d` or `u` is not globally unique: matching it in every BLE file can
    # transfer another class's GATT behavior onto this UUID. Cross-file flows
    # are still followed when they qualify the declaring class (`Owner.field`).
    uuid_to_fields: dict[str, set[tuple[str, str]]] = {u: set() for u in target_uuids}
    field_to_uuid: dict[tuple[str, str], str] = {}
    write_helper_methods: set[tuple[str, str]] = set()

    package_by_path: dict[str, str] = {}
    imports_by_path: dict[str, set[str]] = {}
    static_imports_by_path: dict[str, set[tuple[str, str]]] = {}
    android_bluetooth_wildcard_paths: set[str] = set()
    gatt_receiver_types_by_path: dict[str, dict[str, set[str]]] = {}
    gatt_type_decl_re = re.compile(
        r"\b(?:(android\.bluetooth)\.)?"
        r"(BluetoothGatt|BluetoothGattService|BluetoothGattCharacteristic)\s+"
        r"([A-Za-z_$][A-Za-z0-9_$]*)\b"
    )
    for jpath, text in file_texts.items():
        package_match = re.search(r"(?m)^\s*package\s+([\w$.]+)\s*;", text)
        package_by_path[jpath] = package_match.group(1) if package_match else ""
        imports_by_path[jpath] = set()
        static_imports_by_path[jpath] = set()
        for match in re.finditer(r"(?m)^\s*import\s+(static\s+)?([\w.$*]+)\s*;", text):
            imported = match.group(2)
            if match.group(1):
                owner, dot, member = imported.rpartition(".")
                if dot:
                    static_imports_by_path[jpath].add((owner, member))
            elif imported == "android.bluetooth.*":
                android_bluetooth_wildcard_paths.add(jpath)
            elif not imported.endswith(".*"):
                imports_by_path[jpath].add(imported)
        typed_vars: dict[str, set[str]] = {}
        for match in gatt_type_decl_re.finditer(text):
            type_name = match.group(2)
            android_type_is_bound = (
                match.group(1) == "android.bluetooth"
                or f"android.bluetooth.{type_name}" in imports_by_path[jpath]
                or jpath in android_bluetooth_wildcard_paths
            )
            if android_type_is_bound:
                typed_vars.setdefault(match.group(3), set()).add(type_name)
        gatt_receiver_types_by_path[jpath] = typed_vars

    field_ref_cache: dict[tuple[str, str, str], re.Pattern] = {}

    def field_ref_for_source(owner_path: str, field: str, use_path: str) -> re.Pattern:
        if os.path.abspath(owner_path) == os.path.abspath(use_path):
            return _field_ref_re(field)
        cache_key = (owner_path, field, use_path)
        cached = field_ref_cache.get(cache_key)
        if cached is not None:
            return cached

        owner_class = os.path.splitext(os.path.basename(owner_path))[0]
        owner_package = package_by_path.get(owner_path, "")
        use_package = package_by_path.get(use_path, "")
        owner_classes = {owner_class, owner_class.replace("$", ".")}
        owner_qnames = {f"{owner_package}.{name}" if owner_package else name
                        for name in owner_classes}
        use_imports = imports_by_path.get(use_path, set())
        patterns: list[str] = []
        for qname in owner_qnames:
            patterns.append(_field_ref_re(f"{qname}.{field}").pattern)
        # In another package, accept a simple class qualifier only when that
        # exact owner class is explicitly imported. A package wildcard is not
        # enough: an unrelated local/imported class with the same simple name
        # must never bind a UUID field by accident.
        class_is_in_scope = (
            use_package == owner_package
            or bool(owner_qnames & use_imports)
        )
        if class_is_in_scope:
            for name in owner_classes:
                patterns.append(_field_ref_re(f"{name}.{field}").pattern)
        if any((qname, field) in static_imports_by_path.get(use_path, set())
               for qname in owner_qnames):
            patterns.append(_field_ref_re(field).pattern)
        # An out-of-scope owner has no legal field reference in this file.
        # Never compile an empty alternation: `(?:)` matches every source line.
        result = re.compile("(?:" + "|".join(dict.fromkeys(patterns)) + ")") if patterns else re.compile(r"(?!)")
        field_ref_cache[cache_key] = result
        return result

    def is_typed_gatt_call(
        use_path: str, line: str, method: str, field_ref: re.Pattern, expected_type: str
    ) -> bool:
        """Only trust a GATT sink when its receiver has a declared Android GATT type."""
        call_re = re.compile(
            r"(?P<receiver>(?:[A-Za-z_$][A-Za-z0-9_$]*\.)*[A-Za-z_$][A-Za-z0-9_$]*)"
            + r"\s*\.\s*" + re.escape(method) + r"\s*\(\s*"
            + field_ref.pattern + r"\s*\)"
        )
        typed_vars = gatt_receiver_types_by_path.get(use_path, {})
        for match in call_re.finditer(line):
            receiver = match.group("receiver").rsplit(".", 1)[-1]
            if expected_type in typed_vars.get(receiver, set()):
                return True
        return False

    # Capture typed UUID/String constants and looser string field assignments
    # like `private final String avion_char_out_uuid = "..."`.
    loose_string_re = re.compile(
        r'(?:public\s+|private\s+|protected\s+|static\s+|final\s+)*'
        r'(?:String\s+)?(?:this\.)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*'
        r'"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"',
    )
    for jpath, text in file_texts.items():
        class_name = os.path.splitext(os.path.basename(jpath))[0]
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            hm = re.search(
                r"\b(?:public\s+|private\s+|protected\s+|static\s+)*"
                r"(?:void|boolean)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\("
                r"[^)]*BluetoothGattCharacteristic",
                line,
            )
            if not hm:
                continue
            body_preview = "\n".join(lines[idx: min(len(lines), idx + 40)])
            if "writeCharacteristic" in body_preview:
                write_helper_methods.add((jpath, hm.group(1)))
        for regex in (UUID_ASSIGNMENT_RE, UUID_STRING_ASSIGNMENT_RE, loose_string_re):
            for m in regex.finditer(text):
                field = m.group(1)
                uuid = normalize_uuid(m.group(2))
                if uuid not in target_uuids:
                    continue
                field_ref = (jpath, field)
                field_to_uuid[field_ref] = uuid
                uuid_to_fields[uuid].add(field_ref)

    # Pass A: direct role evidence for UUID fields, and alias recovery. The
    # alias model catches patterns like:
    #   if (ch.getUuid().compareTo(UUID_FIELD) == 0) STATIC_CHAR_FIELD = ch;
    alias_to_uuid: dict[tuple[str, str], str] = {}
    role_signals: dict[str, set[str]] = {u: set() for u in target_uuids}
    evidence: dict[str, list[str]] = {u: [] for u in target_uuids}

    assignment_after_compare_re = re.compile(
        r"((?:[A-Za-z_$][A-Za-z0-9_$]*\.)?[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
        r"[A-Za-z_$][A-Za-z0-9_$]*\s*;"
    )
    for jpath, text in file_texts.items():
        if not PHASE5_BLE_FILE_RE.search(text):
            continue  # only trust GATT role evidence from BLE-relevant files
        lines = text.splitlines()
        for uuid, fields in uuid_to_fields.items():
            for owner_path, field in list(fields):
                ref = field_ref_for_source(owner_path, field, jpath)
                for idx, line in enumerate(lines):
                    if not ref.search(line):
                        continue
                    if is_typed_gatt_call(jpath, line, "getService", ref, "BluetoothGatt"):
                        role_signals[uuid].add("service")
                        evidence[uuid].append(f"{os.path.basename(jpath)}:{idx + 1} BluetoothGatt.getService({field})")
                    is_service_compare = bool(re.search(
                        r"(?:BluetoothGattService|[A-Za-z_$][A-Za-z0-9_$]*service[A-Za-z0-9_$]*)"
                        r"\.getUuid\(\)\.(?:compareTo|equals)\(\s*" + ref.pattern,
                        line,
                        re.IGNORECASE,
                    ))
                    if is_service_compare:
                        role_signals[uuid].add("service")
                        evidence[uuid].append(f"{os.path.basename(jpath)}:{idx + 1} service.getUuid() UUID match ({field})")
                    is_characteristic_compare = bool(re.search(
                        r"(?:BluetoothGattCharacteristic|[A-Za-z_$][A-Za-z0-9_$]*characteristic[A-Za-z0-9_$]*)"
                        r"\.getUuid\(\)\.(?:compareTo|equals)\(\s*" + ref.pattern,
                        line,
                        re.IGNORECASE,
                    ))
                    if is_characteristic_compare:
                        role_signals[uuid].add("characteristic")
                        evidence[uuid].append(f"{os.path.basename(jpath)}:{idx + 1} characteristic.getUuid() UUID match ({field})")
                    if re.search(r"getCharacteristic\s*\(\s*" + ref.pattern + r"\s*\)", line):
                        role_signals[uuid].add("characteristic")
                        evidence[uuid].append(f"{os.path.basename(jpath)}:{idx + 1} getCharacteristic({field})")

                    # Recover characteristic aliases assigned shortly after a
                    # UUID comparison in service discovery.
                    if "compareTo" in line and "getUuid()" in line and not is_service_compare:
                        after_lines: list[str] = []
                        for follow in lines[idx: min(len(lines), idx + 8)]:
                            if after_lines and "compareTo" in follow and "getUuid()" in follow:
                                break
                            if after_lines and re.search(r"}\s*else\s+if\b", follow):
                                break
                            after_lines.append(follow)
                        after = "\n".join(after_lines)
                        am = assignment_after_compare_re.search(after)
                        if am:
                            alias = am.group(1)
                            alias_leaf = _field_last_segment(alias)
                            if alias_leaf == field or _is_rejected_field_name(alias_leaf):
                                continue
                            alias_to_uuid[(jpath, alias)] = uuid
                            uuid_to_fields[uuid].add((jpath, alias))
                            if alias_leaf != alias:
                                alias_to_uuid[(jpath, alias_leaf)] = uuid
                                uuid_to_fields[uuid].add((jpath, alias_leaf))
                            role_signals[uuid].add("characteristic")
                            evidence[uuid].append(
                                f"{os.path.basename(jpath)}:{idx + 1} characteristic alias {alias} assigned after UUID compare"
                            )

    # Pass B: inspect behavior of recovered aliases and original fields.
    for jpath, text in file_texts.items():
        if not PHASE5_BLE_FILE_RE.search(text):
            continue  # only trust GATT role evidence from BLE-relevant files
        lines = text.splitlines()
        for (owner_path, field), uuid in {**field_to_uuid, **alias_to_uuid}.items():
            if uuid not in target_uuids:
                continue
            ref = field_ref_for_source(owner_path, field, jpath)
            for idx, line in enumerate(lines):
                if not ref.search(line):
                    continue
                lo = max(0, idx - 10)
                hi = min(len(lines), idx + 11)
                window = "\n".join(lines[lo:hi])
                low_window = window.lower()
                low_line = line.lower()
                # `ENABLE_NOTIFICATION_VALUE` can be several lines away from
                # the UUID comparison and belong to a different characteristic
                # nested in the same service-discovery block. Only bind a
                # notification signal to a field/alias actually passed to the
                # Android notification API on this line.
                if "setcharacteristicnotification" in low_line:
                    role_signals[uuid].update({"characteristic", "notify"})
                    evidence[uuid].append(f"{os.path.basename(jpath)}:{idx + 1} notification subscription")
                if "oncharacteristicchanged" in low_window:
                    role_signals[uuid].update({"characteristic", "changed", "notify", "output"})
                    evidence[uuid].append(f"{os.path.basename(jpath)}:{idx + 1} changed value broadcast/handler")
                helper_write = False
                for helper_owner, helper in write_helper_methods:
                    helper_ref = field_ref_for_source(helper_owner, helper, jpath).pattern
                    if re.search(
                        helper_ref + r"\s*\([^;\n]{0,240}" + ref.pattern,
                        line,
                    ):
                        helper_write = True
                        break
                # A method merely named `write` is not BLE evidence. Trust the
                # Android sink itself or a helper whose owner was resolved by
                # package/import-aware field_ref_for_source().
                if (
                    "writecharacteristic" in low_line
                    or helper_write
                ):
                    role_signals[uuid].update({"characteristic", "write"})
                    if re.search(r"\benabl(?:e|ing|ed)\b", low_window) and "console" in low_window:
                        role_signals[uuid].update({"enable", "console"})
                    evidence[uuid].append(f"{os.path.basename(jpath)}:{idx + 1} write path")
                if "readcharacteristic" in low_line:
                    role_signals[uuid].update({"characteristic", "read"})
                    evidence[uuid].append(f"{os.path.basename(jpath)}:{idx + 1} read path")
                if any(tok in low_window for tok in ("buttonsend", "edittextcmd", "user console", "console command")):
                    role_signals[uuid].update({"input", "send", "command", "console"})
                if "line_separator" in low_window and re.search(r"\bstring\s*\+", low_window):
                    role_signals[uuid].update({"input", "send", "command", "console"})
                if "extras_console_text" in low_window or "textviewbluconsoleoutput" in low_window:
                    role_signals[uuid].update({"console", "output"})

    # Pass C: preserve recovered field names and grounded roles. Behavior can
    # establish a GATT role, but it cannot establish ownership or a semantic
    # UUID name. In particular, never prefix a generic behavior label with the
    # host APK package ID: the UUID may belong to a shared SDK.
    out: dict[str, dict] = {}
    for uuid in sorted(target_uuids):
        signals = role_signals.get(uuid, set())
        fields = uuid_to_fields.get(uuid, set())
        semantic_fields: list[tuple[str, str | None]] = []
        for _owner_path, f in fields:
            leaf = _field_last_segment(f)
            cleaned = uuid_name_from_field(leaf)
            if cleaned and name_semantic_score(cleaned) >= 25:
                # Keep the original field spelling for this deep pass. The goal
                # is auditability back to decompiled code; if the APK says
                # `avion_char_out_uuid`, preserving that exact identifier is
                # more useful than stripping the suffix to `avion_char_out`.
                semantic_fields.append((leaf, classify_via_field_name(cleaned)))
        behavior_usage = None
        if "service" in signals:
            behavior_usage = "GATT Service"
        elif signals:
            behavior_usage = "GATT Characteristic"
        if behavior_usage:
            usage = behavior_usage
        else:
            field_roles = {role for _leaf, role in semantic_fields if role}
            usage = field_roles.pop() if len(field_roles) == 1 else None
        direct_semantic_fields = [
            leaf for leaf, role in semantic_fields
            if role is None or usage is None or role == usage
        ]
        if not signals and not direct_semantic_fields:
            continue
        name = None
        if direct_semantic_fields:
            name = sorted(
                direct_semantic_fields,
                key=lambda n: (-(name_semantic_score(uuid_name_from_field(n)) or 0), n),
            )[0]
        if name == "Unknown":
            name = None
        note_bits = sorted(set(evidence.get(uuid, [])))[:8]
        if not name and not usage:
            continue
        if name:
            note = f"Deep Phase-5 RE preserved meaningful UUID field name `{name}`"
        else:
            note = "Deep Phase-5 RE recovered GATT role from local UUID-field dataflow"
        note += (": " + "; ".join(note_bits)) if note_bits else "."
        entry = {
            "note": note,
            "cache_in_sdk_table": False,
        }
        if name:
            entry["UUID_name"] = name
        if usage:
            entry["UUID_usage_array"] = [usage]
        out[uuid] = entry
    return out


def phase5_deep_re_apk(
    apk_path: str,
    target_uuids: set[str],
    aapt: str,
    jadx: str,
    jadx_timeout_sec: int,
    keep_tmp: bool,
    predecompiled: tuple[str, ...] | None = (),
) -> tuple[str, dict[str, dict]]:
    """Run the deep Phase-5 recovery pass for one APK."""
    fname = os.path.basename(apk_path)
    is_xapk = apk_path.lower().endswith(".xapk")
    tmp_root = tempfile.mkdtemp(prefix="apk_clues_phase5_")
    try:
        scan_target = apk_path
        if is_xapk:
            base_apk = extract_base_apk_from_xapk(apk_path, tmp_root)
            if base_apk:
                scan_target = base_apk
        meta = get_apk_metadata(aapt, scan_target)
        if meta is None:
            return "aapt_failed", {}
        if not meta["has_bt_perm"]:
            return "no_bt_perms", {}
        jadx_out, reused = jadx_output_dir(
            jadx, apk_path, scan_target, tmp_root, jadx_timeout_sec,
            show_bad_code=True, predecompiled=predecompiled,
        )
        if jadx_out is None:
            return "jadx_failed_or_timeout", {}
        mapping = _phase5_deep_re_jadx(jadx_out, target_uuids, meta.get("package_id"))
        return (f"ok:{len(mapping)} deep-name candidates from {fname}"
                + (" (predecompiled)" if reused else "")), mapping
    except Exception as e:
        return f"exception:{type(e).__name__}:{e}", {}
    finally:
        if not keep_tmp:
            shutil.rmtree(tmp_root, ignore_errors=True)


def apply_phase5_deep_mapping(
    records: list[dict],
    mapping: dict[str, dict],
    submitter: str,
) -> int:
    """Apply deep Phase-5 findings in-place. Returns number of records changed."""
    changed = 0
    for rec in records:
        uuid = (rec.get("UUID") or "").lower()
        if uuid not in mapping:
            continue
        entry = mapping[uuid]
        did = False
        new_name = entry.get("UUID_name")
        usage = entry.get("UUID_usage_array")
        usage_role = usage[0] if isinstance(usage, list) and len(usage) == 1 else None
        if new_name and not _uuid_name_compatible_with_usage(new_name, usage_role):
            new_name = None
        if new_name and _is_unknown_name(rec.get("UUID_name")):
            rec["UUID_name"] = new_name
            did = True
        if usage:
            old_usage = rec.get("UUID_usage_array", [])
            # A deep observation from one APK must not erase an existing role,
            # including a different role observed in another APK. Conflicting
            # roles need source review before changing the record.
            if not old_usage:
                rec["UUID_usage_array"] = usage
                _sync_record_role_text(rec)
                did = True
        note = entry.get("note")
        if note:
            rec.setdefault("evidence_array", []).append({
                "description": f"Deep Phase-5 UUID-name resolution: {note}",
                "submitter": submitter,
            })
            rec["evidence_array"] = dedupe_evidence_array(rec["evidence_array"])
            did = True
        if did:
            changed += 1
    return changed


def derive_unknown_uuid_targets(
    records: list[dict],
    path_filters: list[str] | None = None,
) -> tuple[dict[str, set[str]], int, int]:
    """Return APK path -> Unknown UUIDs from the current output file."""
    unknown_record_count = 0
    by_path: dict[str, set[str]] = {}
    prefixes = [os.path.abspath(p) for p in (path_filters or [])]
    for rec in records:
        if not _is_unknown_name(rec.get("UUID_name")):
            continue
        uuid = (rec.get("UUID") or "").lower()
        if not UUID128_LITERAL_RE.fullmatch(uuid):
            continue
        unknown_record_count += 1
        for info in rec.get("android_info_array", []):
            pp = info.get("package_path")
            if not pp:
                continue
            resolved = resolve_package_path(pp)
            app = os.path.abspath(resolved)
            if prefixes and not any(app == pre or app.startswith(pre.rstrip(os.sep) + os.sep) for pre in prefixes):
                continue
            by_path.setdefault(resolved, set()).add(uuid)
    missing = 0
    on_disk: dict[str, set[str]] = {}
    for pp, uuids in by_path.items():
        if os.path.isfile(pp):
            on_disk[pp] = uuids
        else:
            missing += 1
    return on_disk, unknown_record_count, missing


def iter_input_paths(root: str) -> Iterable[str]:
    if os.path.isfile(root):
        yield root
        return
    for dp, dn, fns in os.walk(root):
        if predecompiled_cache is not None and predecompiled_cache.ROOT_MARKER in fns:
            dn[:] = []  # a predecompile_apks.py tree: no APKs, millions of .java files
            continue
        for fn in fns:
            lo = fn.lower()
            if lo.endswith(".apk") or lo.endswith(".xapk"):
                yield os.path.join(dp, fn)


def load_existing(output_path: str) -> list[dict]:
    return load_clues(output_path)


UNIDENTIFIED_SHARED_SDK_MARKER = "Unidentified shared SDK"


def degrade_shared_sdk_companies(records: list[dict]) -> int:
    """Walk records and, for any UUID that meets the "shared-SDK signal"
    (≥3 host packages with non-overlapping inferred-company tokens AND not
    already in KNOWN_SDK_UUIDS), set its `company` to a clearly-uncertain
    marker. This is the critical-correctness fix for the case where a
    shared third-party SDK leaks BLE constants into many unrelated host
    apps — without this, the first host app processed gets credit for the
    SDK's UUIDs.

    The Phase-4 agent loop (list_shared_sdk_clusters.py + the SDK-id
    helper) later upgrades these records to the real SDK vendor.

    Returns the number of records mutated.
    """
    degraded = 0
    for rec in records:
        uuid = rec.get("UUID", "").lower()
        if uuid in KNOWN_SDK_UUIDS:
            continue
        infos = rec.get("android_info_array", [])
        if len(infos) < 3:
            continue
        # Per-app vendor tokens (same heuristic as company_from_package's
        # fallback) — if those tokens are all different across host apps,
        # the UUID is shared-SDK by signal.
        tokens: set[str] = set()
        for a in infos:
            pid = a.get("package_id", "")
            for part in pid.split("."):
                if not part or part.lower() in _TLDLIKE_COMPONENTS:
                    continue
                if part.isdigit() or len(part) < 3:
                    continue
                tokens.add(part.lower())
                break
        if len(tokens) < 3:
            continue  # not enough distinct vendor tokens to call it shared
        # Already degraded — leave alone.
        if rec.get("company", "").startswith(UNIDENTIFIED_SHARED_SDK_MARKER):
            continue
        # Preserve curated values: only degrade auto-inferred companies.
        existing = rec.get("company", "")
        if existing and "(inferred from package id)" not in existing and existing != "Unknown":
            continue
        rec["company"] = (
            f"{UNIDENTIFIED_SHARED_SDK_MARKER} "
            f"(observed in {len(infos)} unrelated host apps with non-overlapping "
            f"vendor tokens — Phase-4 identification needed)"
        )
        # Attribution uncertainty is already recorded in company; do not
        # append provenance to the functional UUID purpose.
        degraded += 1
    return degraded


def save_output(output_path: str, records: list[dict]) -> None:
    # Apply the shared-SDK degradation just before writing so the on-disk
    # JSON is always honest about what we don't yet know.
    n_degraded = degrade_shared_sdk_companies(records)
    if n_degraded:
        print(
            f"[*] degraded {n_degraded} records' company to "
            f"'{UNIDENTIFIED_SHARED_SDK_MARKER} (...)' "
            f"because the UUID is shared across multiple host packages "
            f"with non-overlapping vendor tokens; run Phase-4 to identify.",
            file=sys.stderr,
        )
    # Safety net: dedupe every record's evidence_array on the way out, so any
    # path that mutated records without going through merge_records (e.g. a
    # caller-supplied list of pre-existing records, helper-script edits) is
    # still cleaned up before the file is written.
    n_collapsed = 0
    for rec in records:
        ev = rec.get("evidence_array")
        if not ev:
            continue
        deduped = dedupe_evidence_array(ev)
        if len(deduped) != len(ev):
            n_collapsed += len(ev) - len(deduped)
            rec["evidence_array"] = deduped
    if n_collapsed:
        print(
            f"[*] collapsed {n_collapsed} duplicate evidence_array entries "
            f"before writing.",
            file=sys.stderr,
        )
    # Sort for stable diff: by UUID length (UUID16 first), then by UUID itself.
    records.sort(key=lambda r: (len(r.get("UUID", "")), r.get("UUID", "")))
    # `save_clues` writes a single combined file when the serialized output
    # is under ~100 MB and switches to 16 hex-bucketed shards above that.
    save_clues(records, output_path)


def self_test() -> int:
    """Run a couple of sanity checks on the regex and classifier."""
    import tempfile as _tempfile  # used by several blocks below
    failures: list[str] = []

    # Regex picks up a 128-bit UUID embedded in code.
    sample = '''UUID.fromString("0000fe40-cc7a-482a-984a-7f2ed5b3e58f");
        BluetoothGattService svc = new BluetoothGattService(svcId, ...);
    '''
    matches = UUID128_LITERAL_RE.findall(sample)
    if len(matches) != 1:
        failures.append(f"regex: expected 1 match, got {len(matches)}")

    # Classifier picks Service.
    res = classify(sample)
    if res != "GATT Service":
        failures.append(f"classifier: expected Service, got {res}")

    # Classifier picks Characteristic when only that hint is present.
    res = classify("BluetoothGattCharacteristic c = new BluetoothGattCharacteristic(u, 0, 0);")
    if res != "GATT Characteristic":
        failures.append(f"classifier: expected Characteristic, got {res}")

    # Field-name conventions: `LIBRE3_DATA_SERVICE` should classify as Service.
    res = classify('public static final UUID LIBRE3_DATA_SERVICE = UUID.fromString("...");')
    if res != "GATT Service":
        failures.append(f"classifier(_SERVICE): expected Service, got {res}")

    # Field-name conventions: `LIBRE3_CHAR_BLE_LOGIN` should classify as Characteristic.
    res = classify('public static final UUID LIBRE3_CHAR_BLE_LOGIN = UUID.fromString("...");')
    if res != "GATT Characteristic":
        failures.append(f"classifier(_CHAR_): expected Characteristic, got {res}")

    # New Relic's UUID-shaped BUILD_ID is app telemetry metadata, not a GATT
    # characteristic. Test the exact source scope and ensure a direct GATT
    # sink for the same field still takes precedence.
    newrelic_build_id = "6810a607-ac68-44d4-951c-842ca3a1b7c1"
    newrelic_config_file = (
        "package com.newrelic.agent.android;\n"
        "public class NewRelicConfig {\n"
        f'  static final String BUILD_ID = "{newrelic_build_id}";\n'
        "  static String getBuildId() { return BUILD_ID; }\n"
        "}\n"
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(newrelic_config_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        if newrelic_build_id in found:
            failures.append("New Relic NewRelicConfig.BUILD_ID should be filtered as non-GATT")
    finally:
        os.unlink(tmppath)

    newrelic_config_with_gatt_use = (
        "package com.newrelic.agent.android;\n"
        "import android.bluetooth.BluetoothGattService;\n"
        "public class NewRelicConfig {\n"
        f'  static final String BUILD_ID = "{newrelic_build_id}";\n'
        "  BluetoothGattCharacteristic lookup(BluetoothGattService svc) {\n"
        "    return svc.getCharacteristic(BUILD_ID);\n"
        "  }\n"
        "}\n"
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(newrelic_config_with_gatt_use)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        entry = found.get(newrelic_build_id, {})
        if entry.get("classification") != "GATT Characteristic":
            failures.append("New Relic scoped BUILD_ID hint must yield to direct getCharacteristic use")
    finally:
        os.unlink(tmppath)

    # Real Mobilytics analytics constants include SERVICE-like field names.
    # Check the exact annotation source shape and APK-wide endpoint overrides.
    owner_uuid = "00c6e132-abc1-46dc-b459-2a1128b15e8d"
    owner_fixture = (
        "package com.amazon.alexa.mobilytics;\n"
        "import java.lang.annotation.Retention;\n"
        "import java.lang.annotation.RetentionPolicy;\n"
        "@Retention(RetentionPolicy.SOURCE)\n"
        "public @interface OwnerIdentifier {\n"
        f' public static final String LOCATION_SERVICE_ALL = "{owner_uuid}";\n'
        "}\n"
    )
    owner_consumer = (
        "package example;\nimport android.bluetooth.BluetoothGattService;\n"
        "import com.amazon.alexa.mobilytics.OwnerIdentifier;\n"
        "import java.util.UUID;\nclass Consumer {\n"
        " Object use(BluetoothGattService service) { return service.getCharacteristic("
        "UUID.fromString(OwnerIdentifier.LOCATION_SERVICE_ALL)); }\n}\n"
    )
    owner_cases = [
        ({"OwnerIdentifier.java": owner_fixture}, set(), "Mobilytics owner analytics suppression"),
        ({"OwnerIdentifier.java": owner_fixture,
          "Consumer.java": owner_consumer}, {owner_uuid}, "Mobilytics typed GATT field override"),
        ({"OwnerIdentifier.java": owner_fixture,
          "Consumer.java": owner_consumer.replace(
              "OwnerIdentifier.LOCATION_SERVICE_ALL", f'"{owner_uuid}"'
          )}, {owner_uuid}, "Mobilytics direct GATT literal override"),
        ({"OwnerIdentifier.java": owner_fixture.replace(
              "package com.amazon.alexa.mobilytics;", "package example;"
          )}, {owner_uuid}, "Mobilytics exact package scope"),
        ({"OwnerIdentifier.java": owner_fixture.replace(
              "@interface OwnerIdentifier", "class OwnerIdentifier"
          )}, {owner_uuid}, "Mobilytics exact annotation scope"),
    ]
    for source_files, expected_uuids, case_name in owner_cases:
        with _tempfile.TemporaryDirectory() as td:
            source_dir = os.path.join(td, "sources")
            os.makedirs(source_dir)
            for filename, body in source_files.items():
                with open(os.path.join(source_dir, filename), "w") as fixture:
                    fixture.write(body)
            found = scan_jadx_output(td)
            if set(found) != expected_uuids:
                failures.append(f"{case_name}: expected {sorted(expected_uuids)}, got {sorted(found)}")
            if "GATT" in case_name and found.get(owner_uuid, {}).get("classification") != "GATT Characteristic":
                failures.append(f"{case_name}: typed GATT override must retain characteristic role")

    # SmartBear's UI metadata dictionaries previously became GATT profiles.
    # Run the APK-wide path so independent typed cross-file GATT uses get
    # their normal authoritative role before the scoped metadata filter.
    smartbear_ids = (
        "33fc031b-cffd-428b-85f5-ef5f289ddf14",
        "58440155-e6a1-4bbe-a73e-0118e03c2154",
        "f30d8ee9-a91b-4cfa-8628-1f94fd0dd375",
    )
    smartbear_dictionary = (
        "package com.smartbear.testing;\n"
        "import java.util.UUID;\n"
        "public class bs {\n"
        + "\n".join(
            f' public static final UUID {field} = UUID.fromString("{uuid}");'
            for field, uuid in zip(("a", "b", "c"), smartbear_ids)
        ) + "\n}\n"
    )
    smartbear_hooks = (
        "package com.smartbear.testing;\n"
        "import android.view.MotionEvent;\nimport android.view.View;\n"
        "class nw implements NotificationCallback {\n"
        + "\n".join(
            f' private static final String {field} = "{uuid}";'
            for field, uuid in zip(("f", "g", "h"), smartbear_ids)
        )
        + "\n boolean check(String name, View view, MotionEvent event) {\n"
        " return name.equalsIgnoreCase(f) || g.equalsIgnoreCase(name) || name.equalsIgnoreCase(h);\n"
        " }\n}\n"
    )
    smartbear_factory = (
        "package com.smartbear.testing;\n"
        "import java.util.UUID;\nclass fh implements fo {\n"
        " static {\n"
        + "\n".join(
            f' map.put(UUID.fromString("{uuid}"), {kind}.class);'
            for uuid, kind in zip(smartbear_ids, ("fm", "fl", "fi"))
        )
        + "\n }\n Object create(Class type) throws Exception {\n"
        " return type.getConstructor(fo.class).newInstance(this);\n }\n}\n"
    )
    smartbear_cases = [
        ({"bs.java": smartbear_dictionary}, set(), "SmartBear UI adapter catalog"),
        ({"mu.java": smartbear_dictionary.replace("class bs", "class mu")}, set(), "SmartBear event-property catalog"),
        ({"ry.java": smartbear_dictionary.replace("class bs", "class ry")}, set(), "SmartBear Xamarin catalog"),
        ({"mx.java": smartbear_dictionary.replace("class bs", "class mx")}, set(), "SmartBear event-type catalog"),
        ({"nw.java": smartbear_hooks}, set(), "SmartBear notification hooks"),
        ({"fh.java": smartbear_factory}, set(), "SmartBear expression factory"),
        ({"bs.java": smartbear_dictionary.replace("com.smartbear.testing", "example.other")},
         set(smartbear_ids), "SmartBear package boundary"),
        ({"Other.java": smartbear_dictionary.replace("class bs", "class Other")},
         set(smartbear_ids), "SmartBear exact class boundary"),
        ({"bs.java": smartbear_dictionary.replace("\n}\n", "\n Object lookup(BluetoothGattService service) { return service.getCharacteristic(a); }\n}\n")
          .replace("import java.util.UUID;", "import java.util.UUID;\nimport android.bluetooth.BluetoothGattService;")},
         {smartbear_ids[0]}, "SmartBear same-file GATT override"),
        ({"bs.java": smartbear_dictionary,
          "ActualGatt.java": "package example.consumer;\nimport com.smartbear.testing.bs;\n"
             "import android.bluetooth.BluetoothGattService;\nclass ActualGatt {\n"
             " Object lookup(BluetoothGattService service) { return service.getCharacteristic(bs.a); }\n}\n"},
         {smartbear_ids[0]}, "SmartBear cross-file GATT override"),
        ({"bs.java": smartbear_dictionary,
          "ActualGatt.java": "package example.consumer;\nimport java.util.UUID;\n"
             "import android.bluetooth.BluetoothGattService;\nclass ActualGatt {\n"
             f' Object lookup(BluetoothGattService service) {{ return service.getCharacteristic(UUID.fromString("{smartbear_ids[0]}")); }}\n}}\n'},
         {smartbear_ids[0]}, "SmartBear independent literal retention"),
    ]
    for source_files, expected_uuids, case_name in smartbear_cases:
        with _tempfile.TemporaryDirectory() as td:
            source_dir = os.path.join(td, "sources")
            os.makedirs(source_dir)
            for filename, body in source_files.items():
                with open(os.path.join(source_dir, filename), "w") as fixture:
                    fixture.write(body)
            found = scan_jadx_output(td)
            if set(found) != expected_uuids:
                failures.append(f"{case_name}: expected {sorted(expected_uuids)}, got {sorted(found)}")
            if "GATT override" in case_name:
                if found.get(smartbear_ids[0], {}).get("classification") != "GATT Characteristic":
                    failures.append(f"{case_name}: direct GATT role must remain authoritative")

    # Sony's five-UUID Classic contracts satisfy the constants fallback.
    # Validate source scope, UUID-return methods, reversed aliases, and a
    # direct GATT override rather than globally excluding those UUID values.
    sony_contract_ids = (
        "91819d50-5d72-4478-a001-29eb2c763568",
        "b9b213ce-eeab-49e4-8fd9-aa478ed1b26b",
        "6bb2d18e-47aa-d98f-e449-abeece13b2b9",
        "764cbf0d-bbcb-438f-a8bb-6b92759d6053",
        "53609d75-926b-bba8-8f43-cbbb0dbf4c76",
    )
    sony_contract = (
        "package com.sony.songpal.tandemfamily;\n"
        "public class SppConnectionContract$Tandem {\n"
        " SppConnectionContract$DevASpec devA;\n"
        " SppConnectionContract$DevBSpec devB;\n"
        + "\n".join(
            f' UUID value{i}() {{ return UUID.fromString("{uuid}"); }}'
            for i, uuid in enumerate(sony_contract_ids)
        ) + "\n}\n"
    )
    sony_unknown = "5b830000-6bc7-4802-8e9a-723ceca4bd8f"
    sony_service_sentinel = (
        "package com.sony.songpal.ble.client;\n"
        "import android.bluetooth.BluetoothGattService;\n"
        "enum ServiceUuid {\n"
        f' UNKNOWN_SERVICE(UUID.fromString("{sony_unknown}"));\n'
        " static ServiceUuid lookup(UUID uuid) { return UNKNOWN_SERVICE; }\n"
        "}\n"
    )
    sony_characteristic_sentinel = (
        "package com.sony.songpal.ble.client;\n"
        "import android.bluetooth.BluetoothGattCharacteristic;\n"
        "class CharacteristicUuid {\n"
        " static {\n"
        ' CharacteristicUuid sentinel = new CharacteristicUuid("UNKNOWN", 76, '
        f'UUID.fromString("{sony_unknown}"), Unknown.class, "Unknown", ServiceUuid.e());\n'
        " G0 = sentinel;\n"
        " }\n"
        " static CharacteristicUuid lookup(UUID uuid) { return G0; }\n"
        "}\n"
    )
    sony_cases = [
        (sony_contract, set(), "Sony Classic contract"),
        (sony_contract.replace("$Tandem", "$Fiestable"), set(), "Sony Fiestable contract"),
        (sony_contract.replace("com.sony.songpal.tandemfamily", "example.unrelated"),
         set(sony_contract_ids), "Sony exclusion package boundary"),
        (sony_service_sentinel, set(), "Sony service lookup sentinel"),
        (sony_characteristic_sentinel, set(), "Sony characteristic lookup sentinel"),
        (sony_service_sentinel.replace("return UNKNOWN_SERVICE;", "return null;"),
         {sony_unknown}, "Sony named UNKNOWN without fallback"),
        (sony_characteristic_sentinel.replace("ServiceUuid.e()", "ServiceUuid.f(realService)"),
         {sony_unknown}, "Sony UNKNOWN with real parent"),
        (sony_contract.replace("public class", "import android.bluetooth.BluetoothGattService;\npublic class")
         .replace(" SppConnectionContract$DevASpec devA;",
                  f' UUID actualGatt = UUID.fromString("{sony_contract_ids[0]}");\n'
                  ' Object read(BluetoothGattService service) { return service.getCharacteristic(actualGatt); }\n'
                  ' SppConnectionContract$DevASpec devA;'),
         {sony_contract_ids[0]}, "Sony Classic hint yields to GATT sink"),
    ]
    for sony_source, expected_uuids, case_name in sony_cases:
        with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
            tf.write(sony_source)
            tmppath = tf.name
        try:
            found = scan_one_file(tmppath)
            if set(found) != expected_uuids:
                failures.append(f"{case_name}: expected {sorted(expected_uuids)}, got {sorted(found)}")
            if case_name.endswith("GATT sink") and found.get(sony_contract_ids[0], {}).get("classification") != "GATT Characteristic":
                failures.append("Sony Classic override must preserve characteristic role")
        finally:
            os.unlink(tmppath)

    # Cordova BluetoothSerial's two UUIDs identify classic RFCOMM listening
    # sockets. Three UUID.fromString literals (including the standard SPP UUID)
    # trigger the constants-file BLE fallback, so verify the exact source
    # fields are excluded while a direct GATT sink remains authoritative.
    rfcomm_secure_uuid = "7a9c3b55-78d0-44a7-a94e-a93e3fe118ce"
    rfcomm_insecure_uuid = "23f18142-b389-4772-93bd-52bdbb2c03e9"
    rfcomm_file = (
        "package com.megster.cordova;\n"
        "import android.bluetooth.BluetoothAdapter;\n"
        "import java.util.UUID;\n"
        "public class BluetoothSerialService {\n"
        f'  private static final UUID MY_UUID_SECURE = UUID.fromString("{rfcomm_secure_uuid}");\n'
        f'  private static final UUID MY_UUID_INSECURE = UUID.fromString("{rfcomm_insecure_uuid}");\n'
        '  private static final UUID UUID_SPP = UUID.fromString("00001101-0000-1000-8000-00805f9b34fb");\n'
        "  void listen(BluetoothAdapter adapter) throws Exception {\n"
        "    adapter.listenUsingRfcommWithServiceRecord(\"secure\", MY_UUID_SECURE);\n"
        "    adapter.listenUsingInsecureRfcommWithServiceRecord(\"insecure\", MY_UUID_INSECURE);\n"
        "  }\n"
        "}\n"
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(rfcomm_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        for rfcomm_uuid in (rfcomm_secure_uuid, rfcomm_insecure_uuid):
            if rfcomm_uuid in found:
                failures.append(f"Cordova RFCOMM UUID {rfcomm_uuid} should be filtered as non-GATT")
    finally:
        os.unlink(tmppath)

    rfcomm_file_with_gatt_use = rfcomm_file.replace(
        "  void listen(BluetoothAdapter adapter) throws Exception {\n",
        "  BluetoothGattCharacteristic lookup(BluetoothGattService svc) {\n"
        "    return svc.getCharacteristic(MY_UUID_SECURE);\n"
        "  }\n"
        "  void listen(BluetoothAdapter adapter) throws Exception {\n",
    ).replace(
        "import android.bluetooth.BluetoothAdapter;\n",
        "import android.bluetooth.BluetoothAdapter;\n"
        "import android.bluetooth.BluetoothGattService;\n"
        "import android.bluetooth.BluetoothGattCharacteristic;\n",
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(rfcomm_file_with_gatt_use)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        entry = found.get(rfcomm_secure_uuid, {})
        if entry.get("classification") != "GATT Characteristic":
            failures.append("Cordova RFCOMM UUID hint must yield to direct getCharacteristic use")
    finally:
        os.unlink(tmppath)

    # The exclusion must not become global: the same uppercase field name in
    # another package remains eligible for ordinary UUID/GATT heuristics.
    unrelated_build_id_file = (
        "package example.unrelated.sdk;\n"
        "public class NewRelicConfig {\n"
        f'  static final String BUILD_ID = "{newrelic_build_id}";\n'
        "}\n"
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(unrelated_build_id_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        if newrelic_build_id not in found:
            failures.append("New Relic BUILD_ID hint must remain limited to the New Relic SDK package")
    finally:
        os.unlink(tmppath)

    # UUID_ASSIGNMENT_RE picks up the LHS identifier.
    am = UUID_ASSIGNMENT_RE.search(
        'public static final UUID LIBRE3_DATA_SERVICE = UUID.fromString("089810cc-ef89-11e9-81b4-2a2ae2dbcce4");'
    )
    if not am or am.group(1) != "LIBRE3_DATA_SERVICE":
        failures.append(f"UUID_ASSIGNMENT_RE: expected LIBRE3_DATA_SERVICE, got {am.group(1) if am else None}")

    # UUID_ASSIGNMENT_RE also accepts ParcelUuid.fromString — Tobit's
    # zimoscooterlibrary.ScooterUtil declares its UUIDs this way.
    am = UUID_ASSIGNMENT_RE.search(
        'ParcelUuid serviceUuidDevice = ParcelUuid.fromString("69401001-b5a3-f393-e0a9-e50e24dcca99");'
    )
    if not am or am.group(1) != "serviceUuidDevice":
        failures.append(f"UUID_ASSIGNMENT_RE(ParcelUuid): expected serviceUuidDevice, got {am.group(1) if am else None}")
    am = UUID_ASSIGNMENT_RE.search(
        'ParcelUuid writeCharacteristicDevice = ParcelUuid.fromString("69401002-b5a3-f393-e0a9-e50e24dcca99");'
    )
    if not am or am.group(1) != "writeCharacteristicDevice":
        failures.append(f"UUID_ASSIGNMENT_RE(ParcelUuid char): expected writeCharacteristicDevice, got {am.group(1) if am else None}")

    # ENUM_CONSTANT_UUID_RE — Kontakt's KontaktDeviceService / Characteristic
    # enums. The UUID can be in any constructor position; we capture (name, uuid)
    # regardless. The first four lines mirror the real decompiled Kontakt SDK
    # and use raw quoted UUID strings; the final line keeps coverage for the
    # wrapped UUID.fromString(...) style used by some other SDKs.
    kontakt_lines = [
        ('KONTAKT_DFU_SERVICE("1b314d70-6c97-43fc-b5dd-3d0e125e15fb", "Kontakt DFU (KDFU) Service"),',
         "KONTAKT_DFU_SERVICE", "1b314d70-6c97-43fc-b5dd-3d0e125e15fb"),
        ('KDFU_COMMAND("KDFU Command Characteristic", "1b314d71-6c97-43fc-b5dd-3d0e125e15fb"),',
         "KDFU_COMMAND", "1b314d71-6c97-43fc-b5dd-3d0e125e15fb"),
        ('KDFU_RESPONSE("KDFU Response Characteristic", "1b314d72-6c97-43fc-b5dd-3d0e125e15fb"),',
         "KDFU_RESPONSE", "1b314d72-6c97-43fc-b5dd-3d0e125e15fb"),
        ('DIAGNOSTIC_SERVICE("469dca90-0c88-019f-1a4b-595f74caa04f", "Diagnostic Service"),',
         "DIAGNOSTIC_SERVICE", "469dca90-0c88-019f-1a4b-595f74caa04f"),
        ('WRAPPED_SERVICE("Wrapped", UUID.fromString("abcde001-1234-5678-9abc-def012345678")),',
         "WRAPPED_SERVICE", "abcde001-1234-5678-9abc-def012345678"),
    ]
    for snippet, want_name, want_uuid in kontakt_lines:
        em = ENUM_CONSTANT_UUID_RE.search(snippet)
        if not em or em.group(1) != want_name or em.group(2) != want_uuid:
            got = (em.group(1), em.group(2)) if em else None
            failures.append(f"ENUM_CONSTANT_UUID_RE(Kontakt): expected ({want_name!r}, {want_uuid!r}), got {got!r}")

    # End-to-end: a Kontakt-style enum file should yield the developer's
    # enum-constant identifier as the UUID_name and classify the
    # DIAGNOSTIC_SERVICE-style names as Service.
    kontakt_file = (
        'package com.kontakt.sdk.android.ble.spec;\n'
        'import android.bluetooth.BluetoothGattService;\n'
        'public enum KontaktDeviceService {\n'
        '  KONTAKT_DFU_SERVICE("1b314d70-6c97-43fc-b5dd-3d0e125e15fb", "Kontakt DFU (KDFU) Service"),\n'
        '  DIAGNOSTIC_SERVICE("469dca90-0c88-019f-1a4b-595f74caa04f", "Diagnostic Service");\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(kontakt_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        if found.get("1b314d70-6c97-43fc-b5dd-3d0e125e15fb", {}).get("field_name") != "KONTAKT_DFU_SERVICE":
            failures.append("enum scan(Kontakt): KONTAKT_DFU_SERVICE not captured as field_name")
        if found.get("469dca90-0c88-019f-1a4b-595f74caa04f", {}).get("field_name") != "DIAGNOSTIC_SERVICE":
            failures.append("enum scan(Kontakt): DIAGNOSTIC_SERVICE not captured as field_name")
    finally:
        os.unlink(tmppath)

    # Constructor-label recovery — Bird-style enum lowering. The UUID temp
    # is rejected noise; the quoted constructor arg is the semantic name.
    bird_ctor_file = (
        'package co.bird.android.model;\n'
        'import android.bluetooth.BluetoothGattCharacteristic;\n'
        'import java.util.UUID;\n'
        'public final class GattUuid {\n'
        '  static {\n'
        '    UUID uuidFromString21 = UUID.fromString("abcde00d-1234-5678-9abc-def012345678");\n'
        '    LOCK = new GattUuid("LOCK", 20, uuidFromString21);\n'
        '  }\n'
        '  private GattUuid(String str, int i, UUID uuid) { this.uuid = uuid; }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(bird_ctor_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        n = found.get("abcde00d-1234-5678-9abc-def012345678", {}).get("field_name")
        if n != "LOCK":
            failures.append(f"constructor-label(Bird LOCK): expected LOCK, got {n!r}")
    finally:
        os.unlink(tmppath)

    bird_ambiguous_ctor_file = (
        'package co.bird.android.model;\n'
        'import android.bluetooth.BluetoothGattCharacteristic;\n'
        'import java.util.UUID;\n'
        'class GattUuid {\n'
        '  static {\n'
        '    UUID uuidFromString = UUID.fromString("abcde013-1234-5678-9abc-def012345678");\n'
        '    UUID uuidFromString2 = UUID.fromString("abcde013-1234-5678-9abc-def012345678");\n'
        '    A = new GattUuid("BD_BIRD_SERVICE", 0, uuidFromString);\n'
        '    B = new GattUuid("BIRD_FLEX_SERVICE", 1, uuidFromString2);\n'
        '  }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(bird_ambiguous_ctor_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        n = found.get("abcde013-1234-5678-9abc-def012345678", {}).get("field_name")
        if n in {"BD_BIRD_SERVICE", "BIRD_FLEX_SERVICE"}:
            failures.append("constructor-label ambiguity: distinct labels for one UUID should not pick a side")
    finally:
        os.unlink(tmppath)

    # Constructor-label recovery — Lovens-style data rows. The same pass
    # must tolerate nested calls later in the constructor arg list.
    lovens_ctor_file = (
        'package com.conneqtech.ctble.b.b;\n'
        'import android.bluetooth.BluetoothGattCharacteristic;\n'
        'import java.util.UUID;\n'
        'class c0 {\n'
        '  static {\n'
        '    UUID uuidFromString = UUID.fromString("abcde00e-1234-5678-9abc-def012345678");\n'
        '    x = list(new b("bikeOnOff", uuidFromString, wrap(new a(range, metadata))));\n'
        '  }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(lovens_ctor_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        n = found.get("abcde00e-1234-5678-9abc-def012345678", {}).get("field_name")
        if n != "bikeOnOff":
            failures.append(f"constructor-label(Lovens bikeOnOff): got {n!r}")
    finally:
        os.unlink(tmppath)

    # Constructor-label recovery — PAX-style multi-UUID rows. Distinct UUID
    # args pick up the direct destination field name; duplicate args sharing
    # one UUID collapse to their common semantic suffix.
    pax_ctor_file = (
        'package com.pax.peace.g.p;\n'
        'import android.bluetooth.BluetoothGattCharacteristic;\n'
        'import java.util.UUID;\n'
        'public final class f {\n'
        '  static {\n'
        '    UUID uuidFromString = UUID.fromString("abcde00f-1234-5678-9abc-def012345678");\n'
        '    UUID uuidFromString2 = UUID.fromString("abcde010-1234-5678-9abc-def012345678");\n'
        '    f a = new f("PAX_SERVICE_NOTIFICATION", 0, svc, uuidFromString, uuidFromString2);\n'
        '    UUID uuidFromString3 = UUID.fromString("abcde011-1234-5678-9abc-def012345678");\n'
        '    f b = new f("INTERNAL_SERVICE_NOTIFICATION", 1, svc, uuidFromString3, uuidFromString3);\n'
        '  }\n'
        '  private f(String str, int i, Object svc, UUID uuid, UUID uuid2) {\n'
        '    this.dataReadyCharacteristicUUID = uuid;\n'
        '    this.readCharacteristicUUID = uuid2;\n'
        '  }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(pax_ctor_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        n1 = found.get("abcde00f-1234-5678-9abc-def012345678", {}).get("field_name")
        n2 = found.get("abcde010-1234-5678-9abc-def012345678", {}).get("field_name")
        n3 = found.get("abcde011-1234-5678-9abc-def012345678", {}).get("field_name")
        if n1 != "PAX_SERVICE_NOTIFICATION_dataReadyCharacteristicUUID":
            failures.append(f"constructor-label(PAX dataReady): got {n1!r}")
        if n2 != "PAX_SERVICE_NOTIFICATION_readCharacteristicUUID":
            failures.append(f"constructor-label(PAX read): got {n2!r}")
        if n3 != "INTERNAL_SERVICE_NOTIFICATION_characteristicUUID":
            failures.append(f"constructor-label(PAX duplicate UUID collapse): got {n3!r}")
    finally:
        os.unlink(tmppath)

    # Nearby strong BLE log labels — Canon remote-control branch pattern.
    canon_log_file = (
        'package com.canon.eos;\n'
        'import android.bluetooth.BluetoothGattCharacteristic;\n'
        'class b {\n'
        '  void handle(BluetoothGattCharacteristic c) {\n'
        '    if ("abcde012-1234-5678-9abc-def012345678".equals(c.getUuid().toString())) {\n'
        '      log("EOSBLERemoteControlService -BLE_UUID_IC_RC_FEATURE");\n'
        '    }\n'
        '  }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(canon_log_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        n = found.get("abcde012-1234-5678-9abc-def012345678", {}).get("field_name")
        if n != "BLE_UUID_IC_RC_FEATURE":
            failures.append(f"nearby BLE log label(Canon): got {n!r}")
    finally:
        os.unlink(tmppath)

    # Alias propagation — Intesis BLEManager pattern. The temp
    # `parcelUuidFromString` is in REJECT_FIELD_NAMES; the terminal
    # `serviceUUID` should win. Verbatim from
    # `com.intesis.intesishome.api.wifiConfig.ble.BLEManager`.
    intesis_file = (
        'package com.intesis.intesishome.api.wifiConfig.ble;\n'
        'import android.bluetooth.BluetoothGattService;\n'
        'import android.os.ParcelUuid;\n'
        'public final class BLEManager {\n'
        '    private static final ParcelUuid serviceUUID;\n'
        '    static {\n'
        '        ParcelUuid parcelUuidFromString = ParcelUuid.fromString("0000baf0-0000-1000-8000-00805f9b07d1");\n'
        '        serviceUUID = parcelUuidFromString;\n'
        '    }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(intesis_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        fname = found.get("0000baf0-0000-1000-8000-00805f9b07d1", {}).get("field_name")
        if fname != "serviceUUID":
            failures.append(f"alias propagation(Intesis): expected serviceUUID, got {fname!r}")
    finally:
        os.unlink(tmppath)

    # REJECT_FIELD_NAMES — temp variable names must not survive into UUID_name.
    if uuid_name_from_field("parcelUuidFromString") is not None:
        failures.append("REJECT_FIELD_NAMES: parcelUuidFromString should be rejected")
    if uuid_name_from_field("uuidFromString") is not None:
        failures.append("REJECT_FIELD_NAMES: uuidFromString should be rejected")
    if uuid_name_from_field("hashCode") is not None:
        failures.append("REJECT_FIELD_NAMES: hashCode should be rejected")
    # Numbered temps — Kotlin compiler emits parcelUuidFromString2/3/… when
    # multiple let{} blocks lower in the same scope. They must also be
    # rejected; without this rule they leaked through the original
    # exact-match REJECT list and ended up in CLUES UUID_name fields
    # (observed: edfec62e-…-2a32 in Climax / 6e400003-…-e80060 in Tobit).
    if uuid_name_from_field("parcelUuidFromString2") is not None:
        failures.append("REJECT_FIELD_NAMES: parcelUuidFromString2 should be rejected")
    if uuid_name_from_field("parcelUuidFromString10") is not None:
        failures.append("REJECT_FIELD_NAMES: parcelUuidFromString10 should be rejected")
    if uuid_name_from_field("uuidFromString3") is not None:
        failures.append("REJECT_FIELD_NAMES: uuidFromString3 should be rejected")
    # Bare GATT role words and numbered variants — these are common LHS
    # field names in decompiled `this.characteristic = getCharacteristic(...)`
    # sinks and must not be promoted to UUID_name. Observed leakage when
    # the GATT-sink LHS recovery was first added (`characteristic`,
    # `characteristic2`, … `characteristic13`, plain `service`, etc.).
    for n in ["service", "characteristic", "char", "desc", "descriptor", "gatt"]:
        if uuid_name_from_field(n) is not None:
            failures.append(f"REJECT bare role word {n!r} should be rejected")
    if uuid_name_from_field("characteristic2") is not None:
        failures.append("REJECT: numbered role word characteristic2 should be rejected")
    if uuid_name_from_field("service10") is not None:
        failures.append("REJECT: numbered role word service10 should be rejected")
    # Legit names containing role words must still pass.
    if uuid_name_from_field("characteristicAppComm") is None:
        failures.append("over-reject: characteristicAppComm should pass (real camelCase identifier)")
    if uuid_name_from_field("serviceUUID") is None:
        failures.append("over-reject: serviceUUID should pass")
    # Negative: legit names that share a prefix substring must NOT be
    # falsely rejected (e.g. a hypothetical user-named `parcelUuidFromStringFOO`).
    if uuid_name_from_field("parcelUuidFromStringFOO") is None:
        failures.append("REJECT_FIELD_NAMES over-reject: parcelUuidFromStringFOO should pass")
    # Legit names must NOT be rejected. `serviceUUID` keeps its suffix
    # because stripping leaves the bare role word "service".
    if uuid_name_from_field("serviceUUID") != "serviceUUID":
        failures.append(f"uuid_name_from_field(serviceUUID): got {uuid_name_from_field('serviceUUID')!r}")

    # Nested-subclass extractor — Climax BL3Characteristic pattern.
    # Verbatim from `com.climax.fourSecure.services.bluetooth.uuid.BL3Characteristic`.
    climax_file = (
        'package com.climax.fourSecure.services.bluetooth.uuid;\n'
        'import android.bluetooth.BluetoothGattCharacteristic;\n'
        'public abstract class BL3Characteristic extends CommonCharacteristic {\n'
        '    public static final class FlashLight extends BL3Characteristic {\n'
        '        public static final FlashLight INSTANCE = new FlashLight();\n'
        '        private FlashLight() {\n'
        '            super("08dea137-9666-45c6-9f20-131620ed63dc", "BLE 紅燈閃爍五次", null);\n'
        '        }\n'
        '    }\n'
        '    public static final class History extends BL3Characteristic {\n'
        '        public static final History INSTANCE = new History();\n'
        '        private History() {\n'
        '            super("db40d49e-9f4f-4b6b-9fcd-f241b236039d", "讀取歷史資料", null);\n'
        '        }\n'
        '    }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(climax_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        n1 = found.get("08dea137-9666-45c6-9f20-131620ed63dc", {}).get("field_name")
        n2 = found.get("db40d49e-9f4f-4b6b-9fcd-f241b236039d", {}).get("field_name")
        if n1 != "FlashLight":
            failures.append(f"nested-subclass(FlashLight): expected FlashLight, got {n1!r}")
        if n2 != "History":
            failures.append(f"nested-subclass(History): expected History, got {n2!r}")
    finally:
        os.unlink(tmppath)

    # Nested-subclass temp-super extractor — Earl/LifeEar Granite16 pattern.
    # JADX moved the UUID literal into `uuidFromString`, then passed that temp
    # to `super(...)`; the nested class name is still the right semantic label.
    granite_file = (
        'package com.earl.core.model.aids.granite16;\n'
        'import android.bluetooth.BluetoothGattCharacteristic;\n'
        'import java.util.UUID;\n'
        'public abstract class Granite16Characteristic {\n'
        '  public static final class BinaryTransferData extends Granite16Characteristic {\n'
        '    private BinaryTransferData() {\n'
        '      UUID uuidFromString = UUID.fromString("a1dd3001-6520-4c40-93aa-e40346ff9f41");\n'
        '      super(uuidFromString, null);\n'
        '    }\n'
        '  }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(granite_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        n = found.get("a1dd3001-6520-4c40-93aa-e40346ff9f41", {}).get("field_name")
        if n != "BinaryTransferData":
            failures.append(f"nested-subclass temp-super(BinaryTransferData): got {n!r}")
    finally:
        os.unlink(tmppath)

    # Lowered-enum row recovery — Ricoh TwinService pattern. Jadx failed to
    # restore the `enum` modifier, but the row still repeats the semantic
    # identifier as both the LHS and constructor arg #0.
    ricoh_lowered_enum = (
        'package com.ricoh360.mobile.bluetooth;\n'
        'import android.bluetooth.le.ScanFilter;\n'
        'class TwinService {\n'
        '  public static final TwinService WIFI_CONTROL = '
        'new TwinService("WIFI_CONTROL", 1, "0000b81d-0000-1000-8000-00805f9b34fb");\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(ricoh_lowered_enum)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        n = found.get("0000b81d-0000-1000-8000-00805f9b34fb", {}).get("field_name")
        if n != "WIFI_CONTROL":
            failures.append(f"lowered-enum row(WIFI_CONTROL): got {n!r}")
    finally:
        os.unlink(tmppath)

    # Anonymous singleton-object recovery — SleepIQ / FuzionBle GattProfile.
    sleepiq_object = (
        'package com.fuzionble.implementation;\n'
        'import android.bluetooth.BluetoothGattCharacteristic;\n'
        'import java.util.UUID;\n'
        'public abstract class e0 {\n'
        '  public static final e0 BulkTransfer = new e0() {\n'
        '    { UUID.fromString("0ec9a5a3-8ac3-4582-92f3-1666421f323d"); }\n'
        '  };\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(sleepiq_object)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        n = found.get("0ec9a5a3-8ac3-4582-92f3-1666421f323d", {}).get("field_name")
        if n != "BulkTransfer":
            failures.append(f"anonymous-object(BulkTransfer): got {n!r}")
    finally:
        os.unlink(tmppath)

    # Untyped raw-string assignment — Fanlight SampleGattAttributes pattern.
    # `public static String Test_Cooker;` declared at class level, then
    # assigned inside a static { } block on a later line.
    fanlight_file = (
        'package kr.co.fanlight.peb.BLE;\n'
        'import android.bluetooth.BluetoothGattCharacteristic;\n'
        'public class SampleGattAttributes {\n'
        '    public static String Test_Cooker;\n'
        '    static {\n'
        '        Test_Cooker = "00010203-0405-0607-0809-0a0b0c0d2b19";\n'
        '    }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(fanlight_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        n = found.get("00010203-0405-0607-0809-0a0b0c0d2b19", {}).get("field_name")
        if n != "Test_Cooker":
            failures.append(f"raw-string assignment(Test_Cooker): expected Test_Cooker, got {n!r}")
    finally:
        os.unlink(tmppath)

    # Transformed fromString literal — Tobit zimoscooterlibrary pattern.
    # `UUID.fromString("…".toUpperCase())` / `.toLowerCase(Locale.US)`.
    # Before this change, UUID_ASSIGNMENT_RE required the literal to be
    # the direct argument to fromString, so these were silently missed.
    tobit_transformed = (
        'package com.Tobit.labs.zimoscooterlibrary;\n'
        'import android.bluetooth.BluetoothGattCharacteristic;\n'
        'import android.os.ParcelUuid;\n'
        'import java.util.Locale;\n'
        'class PwUtil {\n'
        '  public static ParcelUuid serviceUuidPw = ParcelUuid.fromString("abcde004-1234-5678-9abc-def012345678".toUpperCase());\n'
        '  public static UUID notifyCharacteristicDevice_password = UUID.fromString("abcde005-1234-5678-9abc-def012345678".toLowerCase(Locale.US));\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(tobit_transformed)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        n1 = found.get("abcde004-1234-5678-9abc-def012345678", {}).get("field_name")
        n2 = found.get("abcde005-1234-5678-9abc-def012345678", {}).get("field_name")
        if n1 != "serviceUuidPw":
            failures.append(f"transformed fromString(toUpperCase): got {n1!r}")
        if n2 != "notifyCharacteristicDevice_password":
            failures.append(f"transformed fromString(toLowerCase Locale): got {n2!r}")
    finally:
        os.unlink(tmppath)

    # GATT-sink LHS recovery. The developer's name is on the LHS of an
    # assignment whose RHS is a getCharacteristic(UUID.fromString(...))
    # lookup. From the user-cited Tobit example.
    sink_file = (
        'package com.example.app;\n'
        'import android.bluetooth.BluetoothGattCharacteristic;\n'
        'import android.bluetooth.BluetoothGattService;\n'
        'class Conn {\n'
        '  BluetoothGattCharacteristic characteristicAppComm;\n'
        '  void init(BluetoothGattService service) {\n'
        '    this.characteristicAppComm =\n'
        '        service.getCharacteristic(UUID.fromString("abcde006-1234-5678-9abc-def012345678"));\n'
        '    this.characteristicImuComm =\n'
        '        service.getCharacteristic(UUID.fromString("abcde007-1234-5678-9abc-def012345678"));\n'
        '  }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(sink_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        n1 = found.get("abcde006-1234-5678-9abc-def012345678", {}).get("field_name")
        n2 = found.get("abcde007-1234-5678-9abc-def012345678", {}).get("field_name")
        if n1 != "characteristicAppComm":
            failures.append(f"sink-LHS(characteristicAppComm): got {n1!r}")
        if n2 != "characteristicImuComm":
            failures.append(f"sink-LHS(characteristicImuComm): got {n2!r}")
        # Classification should be Characteristic since the sink was getCharacteristic.
        cls1 = found.get("abcde006-1234-5678-9abc-def012345678", {}).get("classification")
        if cls1 != "GATT Characteristic":
            failures.append(f"sink-LHS classification: got {cls1!r}")
    finally:
        os.unlink(tmppath)

    # GATT-sink LHS hygiene: must NOT promote rejected temp names or bare
    # role words. `service` / `parcelUuidFromString` on the LHS should
    # fall through (uuid_name_from_field returns None for these).
    sink_reject = (
        'package x;\n'
        'import android.bluetooth.BluetoothGattCharacteristic;\n'
        'class X {\n'
        '  void f(BluetoothGattService service) {\n'
        '    parcelUuidFromString = service.getCharacteristic(UUID.fromString("abcde008-1234-5678-9abc-def012345678"));\n'
        '  }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(sink_reject)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        n = found.get("abcde008-1234-5678-9abc-def012345678", {}).get("field_name")
        if n == "parcelUuidFromString":
            failures.append("sink-LHS hygiene: rejected temp `parcelUuidFromString` was promoted to UUID_name")
    finally:
        os.unlink(tmppath)

    # BLE catalog-map (BleNamesResolver-style). Two forms: directly-quoted
    # UUID key, and locally-propagated identifier key. Both should emit
    # the human label as UUID_name.
    catalog_file = (
        'package com.example.ble;\n'
        'import android.bluetooth.BluetoothGattService;\n'
        'class BleNamesResolver {\n'
        '  static final String SERVICE_ONBOARDING_UUID = "abcde009-1234-5678-9abc-def012345678";\n'
        '  static java.util.HashMap<String,String> mServices = new java.util.HashMap<>();\n'
        '  static java.util.HashMap<String,String> mCharacteristics = new java.util.HashMap<>();\n'
        '  static {\n'
        '    mServices.put("abcde00a-1234-5678-9abc-def012345678", "Valeo Generic Service");\n'
        '    mServices.put(SERVICE_ONBOARDING_UUID, "SERVICE_ONBOARDING");\n'
        '    mCharacteristics.put("abcde00b-1234-5678-9abc-def012345678", "Scale User Info");\n'
        '  }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(catalog_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        n_direct = found.get("abcde00a-1234-5678-9abc-def012345678", {}).get("field_name")
        n_indirect = found.get("abcde009-1234-5678-9abc-def012345678", {}).get("field_name")
        n_char = found.get("abcde00b-1234-5678-9abc-def012345678", {}).get("field_name")
        if n_direct != "Valeo Generic Service":
            failures.append(f"catalog-map(direct UUID key): got {n_direct!r}")
        if n_indirect != "SERVICE_ONBOARDING":
            failures.append(f"catalog-map(local ident key): got {n_indirect!r}")
        if n_char != "Scale User Info":
            failures.append(f"catalog-map(mCharacteristics): got {n_char!r}")
        # mServices.put implies Service classification.
        cls_svc = found.get("abcde00a-1234-5678-9abc-def012345678", {}).get("classification")
        cls_char = found.get("abcde00b-1234-5678-9abc-def012345678", {}).get("classification")
        if cls_svc != "GATT Service":
            failures.append(f"catalog-map(mServices) classification: got {cls_svc!r}")
        if cls_char != "GATT Characteristic":
            failures.append(f"catalog-map(mCharacteristics) classification: got {cls_char!r}")
    finally:
        os.unlink(tmppath)

    # Safety rail: a non-BLE object registry must NOT fire the catalog
    # parser. File contains `.put("uuid", "Label")` but has no Bluetooth
    # context — the BLE_CATALOG_FILE_GATE_RE should keep the UUID Unknown
    # (or at least keep the spurious label out).
    non_ble_registry = (
        'package com.analytics.sdk;\n'
        'class EventRegistry {\n'
        '  java.util.HashMap<String,String> events = new java.util.HashMap<>();\n'
        '  EventRegistry() {\n'
        '    events.put("abcde00c-1234-5678-9abc-def012345678", "Login Event");\n'
        '  }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(non_ble_registry)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        # The file has no BluetoothGatt* / BleNamesResolver / mServices /
        # mCharacteristics imports, so file_is_ble will be False and the
        # UUID literal should be filtered out entirely — but if some
        # future change makes the UUID survive scanning, the catalog
        # parser must NOT label it "Login Event".
        n = found.get("abcde00c-1234-5678-9abc-def012345678", {}).get("field_name")
        if n == "Login Event":
            failures.append("catalog-map gate: non-BLE registry leaked label into UUID_name")
    finally:
        os.unlink(tmppath)

    # Kotlin @Metadata d2 parser — recover property names from the
    # decompiled-Kotlin annotation. Verbatim from `t3/a.java` (tree 01
    # of the /tmp/apk_unknown100 set): obfuscated getters a()/b() get
    # mapped back to CHARACTERISTIC_UUID/DESCRIPTOR_UUID via the d2
    # string table.
    kotlin_file = (
        'package t3;\n'
        'import kotlin.Metadata;\n'
        'public class a {\n'
        '    @Metadata(bv = {}, d1 = {"\\u0000\\u0010"},\n'
        '        d2 = {"Lt3/a$c;", "", "", "a", "()Ljava/lang/String;",\n'
        '              "CHARACTERISTIC_UUID", "b", "DESCRIPTOR_UUID",\n'
        '              "<init>", "()V", "infrastructure_release"},\n'
        '        k = 1, mv = {1, 7, 1})\n'
        '    public static final class c {\n'
        '        private c() {}\n'
        '        public final String a() { return "abcde001-1234-5678-9abc-def012345678"; }\n'
        '        public final String b() { return "abcde002-1234-5678-9abc-def012345678"; }\n'
        '    }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(kotlin_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        a_name = found.get("abcde001-1234-5678-9abc-def012345678", {}).get("field_name")
        b_name = found.get("abcde002-1234-5678-9abc-def012345678", {}).get("field_name")
        if a_name != "CHARACTERISTIC_UUID":
            failures.append(f"Kotlin @Metadata d2(a): expected CHARACTERISTIC_UUID, got {a_name!r}")
        if b_name != "DESCRIPTOR_UUID":
            failures.append(f"Kotlin @Metadata d2(b): expected DESCRIPTOR_UUID, got {b_name!r}")
    finally:
        os.unlink(tmppath)

    # Unit-test the d2 parser itself with the verbatim string layout from
    # the tree-01 example.
    mp = parse_kotlin_metadata_property_map(
        '@Metadata(d2 = {"Lt3/a$c;", "", "", "a", "()Ljava/lang/String;", '
        '"CHARACTERISTIC_UUID", "b", "DESCRIPTOR_UUID", '
        '"<init>", "()V", "infrastructure_release"})'
    )
    if mp.get("a") != "CHARACTERISTIC_UUID":
        failures.append(f"d2 parser(a): got {mp.get('a')!r}")
    if mp.get("b") != "DESCRIPTOR_UUID":
        failures.append(f"d2 parser(b): got {mp.get('b')!r}")
    # Negative: the parser must not emit class signatures or init markers
    # as property names.
    bad = [v for v in mp.values() if v.startswith("L") or v == "<init>"]
    if bad:
        failures.append(f"d2 parser emitted noise: {bad!r}")

    # Ambiguous-name handling — `merge_records` should preserve two
    # meaningful names as `A / B` when neither is a strict upgrade.
    rec_a = {
        "UUID": "abcde001-1234-5678-9abc-def012345678",
        "UUID_name": "ClearStepCounter",
        "UUID_purpose": "x", "UUID_usage_array": ["GATT Characteristic"],
        "company": "x", "evidence_array": [],
        "android_info_array": [{"package_id": "com.climax.bl3", "version_code": 1, "version_name": "1"}],
    }
    rec_b = dict(rec_a)
    rec_b["UUID_name"] = "SetDisarmCode"
    rec_b["android_info_array"] = [{"package_id": "com.climax.bl4", "version_code": 1, "version_name": "1"}]
    merged = merge_records([rec_a], [rec_b])
    merged_name = merged[0]["UUID_name"]
    if "/" not in merged_name or "ClearStepCounter" not in merged_name or "SetDisarmCode" not in merged_name:
        failures.append(f"merge aliases: expected ClearStepCounter / SetDisarmCode, got {merged_name!r}")

    # End-to-end: a Tobit-style ParcelUuid file. Without the
    # ParcelUuid.fromString broadening + SERVICE_HINT_RE pruning, the
    # `writeCharacteristicDevice` UUID would (a) lose its field name and
    # (b) be misclassified as GATT Service because of the bare-ParcelUuid
    # service-hint match. Both are regressions worth pinning.
    tobit_file = (
        'package com.Tobit.labs.zimoscooterlibrary;\n'
        'import android.os.ParcelUuid;\n'
        'import android.bluetooth.BluetoothGattCharacteristic;\n'
        'public class ScooterUtil {\n'
        '  public static ParcelUuid serviceUuidDevice = ParcelUuid.fromString("69401001-b5a3-f393-e0a9-e50e24dcca99");\n'
        '  public static ParcelUuid writeCharacteristicDevice = ParcelUuid.fromString("69401002-b5a3-f393-e0a9-e50e24dcca99");\n'
        '  public static ParcelUuid readCharacteristicDevice = ParcelUuid.fromString("69401003-b5a3-f393-e0a9-e50e24dcca99");\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(tobit_file)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        for u, want_name, want_cls in [
            ("69401001-b5a3-f393-e0a9-e50e24dcca99", "serviceUuidDevice",    "GATT Service"),
            ("69401002-b5a3-f393-e0a9-e50e24dcca99", "writeCharacteristicDevice", "GATT Characteristic"),
            ("69401003-b5a3-f393-e0a9-e50e24dcca99", "readCharacteristicDevice",  "GATT Characteristic"),
        ]:
            got_name = found.get(u, {}).get("field_name")
            if got_name != want_name:
                failures.append(f"Tobit ParcelUuid: expected field_name={want_name!r}, got {got_name!r}")
            got_cls = found.get(u, {}).get("classification")
            if got_cls != want_cls:
                failures.append(f"Tobit ParcelUuid: expected classification={want_cls!r} for {want_name}, got {got_cls!r}")
    finally:
        os.unlink(tmppath)

    # Cross-file constructor-parameter role recovery — SharkNinja-style
    # provider returns a config object using only uuidFromString temps, while
    # the callee constructor keeps the original semantic parameter names.
    with _tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "sources", "com", "sharkninja", "shark", "v2", "infrastructure", "bluetooth")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "BluetoothServiceConfiguration.java"), "w", encoding="utf-8") as f:
            f.write(
                'package com.sharkninja.shark.v2.infrastructure.bluetooth;\n'
                'import java.util.UUID;\n'
                'class BluetoothServiceConfiguration {\n'
                '  public BluetoothServiceConfiguration(UUID deviceServiceUUID, UUID writeCommandCharacteristicUUID, '
                'UUID notifyCharacteristicUUID, UUID notifyDescriptorUUID, int i, long j, boolean z, int mask, Object marker) {}\n'
                '}\n'
            )
        with open(os.path.join(src, "SharkBluetoothConfigurationProvider.java"), "w", encoding="utf-8") as f:
            f.write(
                'package com.sharkninja.shark.v2.infrastructure.bluetooth;\n'
                'import android.bluetooth.BluetoothGattCharacteristic;\n'
                'import java.util.UUID;\n'
                'class SharkBluetoothConfigurationProvider {\n'
                '  BluetoothServiceConfiguration getConfiguration() {\n'
                '    UUID uuidFromString = UUID.fromString("0000fcbb-0000-1000-8000-00805f9b34fb");\n'
                '    UUID uuidFromString2 = UUID.fromString("0000b002-0000-1000-8000-00805f9b34fb");\n'
                '    UUID uuidFromString3 = UUID.fromString("0000b004-0000-1000-8000-00805f9b34fb");\n'
                '    UUID uuidFromString4 = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");\n'
                '    return new BluetoothServiceConfiguration(uuidFromString, uuidFromString2, uuidFromString3, uuidFromString4, 0, 0L, false, 80, null);\n'
                '  }\n'
                '}\n'
            )
        found = scan_jadx_output(td)
        n = found.get("0000b004-0000-1000-8000-00805f9b34fb", {}).get("field_name")
        if n != "notifyCharacteristicUUID":
            failures.append(f"cross-file ctor-param(notifyCharacteristicUUID): got {n!r}")

    # Assigned-constructor LHS recovery — CampChef's wrapper type keeps only
    # generic callee params (`serviceId`, `id`), while the semantic label lives
    # on the target field (`writeCharacteristic`).
    with _tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "sources", "com", "campchef", "sdk")
        lib = os.path.join(td, "sources", "com", "lightningkite", "rx", "android", "ble")
        os.makedirs(src, exist_ok=True)
        os.makedirs(lib, exist_ok=True)
        with open(os.path.join(lib, "BleCharacteristic.java"), "w", encoding="utf-8") as f:
            f.write(
                'package com.lightningkite.rx.android.ble;\n'
                'import java.util.UUID;\n'
                'public class BleCharacteristic {\n'
                '  public BleCharacteristic(UUID serviceId, UUID id) {}\n'
                '}\n'
            )
        with open(os.path.join(src, "OldRemoteGrillKt.java"), "w", encoding="utf-8") as f:
            f.write(
                'package com.campchef.sdk;\n'
                'import android.bluetooth.BluetoothGattCharacteristic;\n'
                'import com.lightningkite.rx.android.ble.BleCharacteristic;\n'
                'import java.util.UUID;\n'
                'class OldRemoteGrillKt {\n'
                '  static {\n'
                '    UUID uuidFromString = UUID.fromString("91bad492-b950-4226-aa2b-4ede9fa42f59");\n'
                '    UUID uuidFromString2 = UUID.fromString("b88e398b-afa6-4af3-a6ad-abc645b219da");\n'
                '    writeCharacteristic = new BleCharacteristic(uuidFromString, uuidFromString2);\n'
                '  }\n'
                '}\n'
            )
        found = scan_jadx_output(td)
        n = found.get("b88e398b-afa6-4af3-a6ad-abc645b219da", {}).get("field_name")
        if n != "writeCharacteristic":
            failures.append(f"assigned ctor LHS(writeCharacteristic): got {n!r}")

    # uuid_name_from_field preserves the developer's identifier verbatim,
    # only stripping a trailing _UUID / Uuid and Java m/s prefixes.
    if uuid_name_from_field("LED_COLOR_UUID") != "LED_COLOR":
        failures.append(f"uuid_name_from_field(LED_COLOR_UUID): got {uuid_name_from_field('LED_COLOR_UUID')!r}")
    if uuid_name_from_field("LIBRE3_DATA_SERVICE") != "LIBRE3_DATA_SERVICE":
        failures.append(f"uuid_name_from_field(LIBRE3_DATA_SERVICE): got {uuid_name_from_field('LIBRE3_DATA_SERVICE')!r}")
    # mServiceUuid → ServiceUuid (m-prefix strip + suffix kept because
    # stripping leaves the bare role word "Service").
    if uuid_name_from_field("mServiceUuid") != "ServiceUuid":
        failures.append(f"uuid_name_from_field(mServiceUuid): got {uuid_name_from_field('mServiceUuid')!r}")
    if uuid_name_from_field("f7217p") is not None:
        failures.append(f"uuid_name_from_field(f7217p) should reject minified, got {uuid_name_from_field('f7217p')!r}")
    if uuid_name_from_field("I") is not None:
        failures.append(f"uuid_name_from_field(I) should reject single-letter, got {uuid_name_from_field('I')!r}")

    # company_from_package
    if company_from_package("com.abbott.lingo.wellness") != "Abbott":
        failures.append(f"company_from_package(com.abbott.lingo.wellness): got {company_from_package('com.abbott.lingo.wellness')!r}")
    if company_from_package("com.dexcom.stelo") != "Dexcom":
        failures.append("company_from_package(com.dexcom.stelo)")
    # company_from_package fallback: an unrecognized vendor token should yield
    # `Xxx (inferred from package id)`. Use a clearly-unknown package; don't
    # use anything under `branded.com.*` (the cache now maps that prefix to
    # the Virtuagym white-label fitness platform).
    fallback = company_from_package("com.someunknownvendor1234.app")
    if "Someunknownvendor1234" not in fallback:
        failures.append(f"company_from_package fallback: got {fallback!r}")

    # Usage-trace pattern.
    # NOTE: don't use repeating-digit UUIDs like 11111111-... — they're in
    # DROP_OUTRIGHT_UUIDS (the "developer placeholder" filter) and would be
    # silently rejected before classification, masking real failures here.
    svc_uuid = "12345abc-1111-2222-3333-444455556666"
    chr_uuid = "fedcba98-1111-2222-3333-444455556666"
    file_body = (
        'package x;\nimport android.bluetooth.BluetoothGatt;\nimport android.bluetooth.BluetoothGattService;\n'
        'class Foo {\n'
        f'  static final UUID SVC = UUID.fromString("{svc_uuid}");\n'
        f'  static final UUID CHR = UUID.fromString("{chr_uuid}");\n'
        '  void run(BluetoothGatt g) {\n'
        '    BluetoothGattService s = g.getService(SVC);\n'
        '    s.getCharacteristic(CHR);\n'
        '  }\n'
        '}\n'
    )
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(file_body)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        if found.get(svc_uuid, {}).get("classification") != "GATT Service":
            failures.append("usage-trace: SVC should be Service")
        if found.get(chr_uuid, {}).get("classification") != "GATT Characteristic":
            failures.append("usage-trace: CHR should be Characteristic")
        if found.get(svc_uuid, {}).get("field_name") != "SVC":
            failures.append("field_name capture: SVC")
    finally:
        os.unlink(tmppath)

    # company_from_member_uuids picks the most specific name when multiple
    # SIG member entries are tied to the same vendor token.
    mem = {
        "fde3": "Abbott Diabetes Care",
        "fe73": "Abbott (formerly St. Jude Medical, Inc.)",
    }
    # For an Abbott Diabetes app, only fde3 should be a hit.
    res = company_from_member_uuids("com.abbott.lingo.wellness", {"fde3"}, mem)
    if res != "Abbott Diabetes Care":
        failures.append(f"company_from_member_uuids: got {res!r}")
    # No hits → returns None (caller falls back to package heuristic).
    res = company_from_member_uuids("com.abbott.lingo.wellness", set(), mem)
    if res is not None:
        failures.append(f"company_from_member_uuids (empty): got {res!r}")

    # name_semantic_score ranks human-meaningful names over jadx aliases.
    s_meaningful = name_semantic_score("LED_COLOR_UUID")
    s_alias = name_semantic_score("f15558a")
    s_letter = name_semantic_score("I")
    s_unk = name_semantic_score("Unknown")
    if not (s_meaningful > s_alias > s_unk):
        failures.append(f"name_semantic_score: meaningful({s_meaningful}) > alias({s_alias}) > unknown({s_unk}) violated")
    if not (s_letter < 10):
        failures.append(f"name_semantic_score: single-letter should be tiny, got {s_letter}")

    # company_from_member_uuids: overlap gate. Lingo's package id overlaps
    # with `Abbott Diabetes Care` on `abbott` → keep that name.
    overlap_mem = {
        "fde3": "Abbott Diabetes Care",
        "fc00": "Taobao",  # arbitrary unrelated SIG member
    }
    res = company_from_member_uuids("com.abbott.lingo.wellness", {"fde3", "fc00"}, overlap_mem)
    if res != "Abbott Diabetes Care":
        failures.append(f"overlap gate: expected Abbott Diabetes Care, got {res!r}")
    # Unrelated fitness app — only Taobao is hit, no overlap → return None.
    res = company_from_member_uuids("digifit.android.virtuagym.pro.forgefit24", {"fc00"}, overlap_mem)
    if res is not None:
        failures.append(f"overlap gate: shared-library Taobao UUID should NOT attribute, got {res!r}")

    # filter_vendor_specific drops UUID16s already in member_uuids and
    # surfaces them as member_hits for the company-inference step.
    cands = {
        "0000fde3-0000-1000-8000-00805f9b34fb": {"classification": "GATT Service", "field_name": None, "snippets": [], "parent_candidates": []},
        "0000abcd-0000-1000-8000-00805f9b34fb": {"classification": "GATT Service", "field_name": None, "snippets": [], "parent_candidates": []},
        "deadbeef-0000-1000-8000-00805f9b34fb": {"classification": "GATT Service", "field_name": None, "snippets": [], "parent_candidates": []},
    }
    kept, hits = filter_vendor_specific(cands, mem)
    if "abcd" not in kept:
        failures.append("filter: abcd should be kept (vendor UUID16, not in member_uuids)")
    if "fde3" in kept:
        failures.append("filter: fde3 should be DROPPED (in member_uuids)")
    if "fde3" not in hits:
        failures.append("filter: fde3 should appear in member_hits")
    if "deadbeef-0000-1000-8000-00805f9b34fb" not in kept:
        failures.append("filter: deadbeef-prefix UUID128 should be kept")

    # SIG-standard UUID16 dropped.
    assert is_standard_sig_uuid16("1800"), "0x1800 (GAP) must be dropped"
    assert is_standard_sig_uuid16("2a00"), "0x2a00 (Device Name) must be dropped"
    assert is_standard_sig_uuid16("0000"), "0x0000 (junk) must be dropped"
    assert is_standard_sig_uuid16("0001"), "0x0001 (SDP protocol) must be dropped"
    assert is_standard_sig_uuid16("1101"), "0x1101 (SDP service class) must be dropped"
    assert is_standard_sig_uuid16("1105"), "0x1105 (OBEX Object Push) must be dropped"
    assert is_standard_sig_uuid16("12ff"), "0x12ff (boundary) must be dropped"
    assert not is_standard_sig_uuid16("fd44"), "0xfd44 (Apple member UUID) must be kept"
    assert not is_standard_sig_uuid16("fcca"), "0xfcca (member UUID range) must be kept"
    assert not is_standard_sig_uuid16("8a20"), "0x8a20 (random vendor) must be kept"
    assert not is_standard_sig_uuid16("e001"), "0xe001 (private range) must be kept"

    # SIG base regex.
    m = SIG_BASE_RE.match("00001800-0000-1000-8000-00805f9b34fb")
    if not m or m.group(1).lower() != "1800":
        failures.append("SIG_BASE_RE didn't match standard SIG form")

    # Merge must not make a UUID both a service and a characteristic when a
    # later weak fallback disagrees with a semantic characteristic name.
    rec_char = {
        "UUID": "11111111-2222-3333-4444-555555555555",
        "company": "x",
        "UUID_name": "WRITE_CHARACTERISTIC",
        "UUID_purpose": "GATT Characteristic under service.",
        "UUID_usage_array": ["GATT Characteristic"],
        "evidence_array": [{
            "description": "Found in decompiled DEX of x v1 (versionCode 1). Classification source: usage:getCharacteristic.",
            "submitter": "self-test",
        }],
    }
    rec_weak_svc = {
        "UUID": "11111111-2222-3333-4444-555555555555",
        "company": "x",
        "UUID_name": "WRITE_CHARACTERISTIC",
        "UUID_purpose": "Custom GATT Service observed in Android app x.",
        "UUID_usage_array": ["GATT Service"],
        "evidence_array": [{
            "description": "Found in decompiled DEX of y v1 (versionCode 1). Classification source: file-level-default.",
            "submitter": "self-test",
        }],
    }
    merged_usage = merge_records([rec_char], [rec_weak_svc])[0].get("UUID_usage_array")
    if merged_usage != ["GATT Characteristic"]:
        failures.append(f"merge usage conflict should keep Characteristic, got {merged_usage!r}")

    # Authoritative API usage should beat a stale role word embedded in an
    # existing UUID_name, and generated purpose/android_info text should be
    # synchronized to the final role.
    rec_stale_char = {
        "UUID": "22222222-3333-4444-5555-666666666666",
        "company": "x",
        "UUID_name": "MEDTRONIC_CONSOLE_OUTPUT_NOTIFY_CHARACTERISTIC",
        "UUID_purpose": "Custom GATT Characteristic observed in Android app x.",
        "UUID_usage_array": ["GATT Characteristic"],
        "evidence_array": [{
            "description": "Found in decompiled DEX of x v1 (versionCode 1).",
            "submitter": "self-test",
        }],
        "android_info_array": [{
            "package_id": "x",
            "version_code": 1,
            "version_name": "1",
            "description": "Detected by apk-clues-extract scan; usage 'GATT Characteristic'.",
        }],
    }
    rec_getservice = copy.deepcopy(rec_stale_char)
    rec_getservice["UUID_purpose"] = "Custom GATT Service observed in Android app x."
    rec_getservice["UUID_usage_array"] = ["GATT Service"]
    rec_getservice["UUID_name"] = "Unknown"
    rec_getservice["evidence_array"] = [{
        "description": "Found in decompiled DEX of x v1 (versionCode 1), in Java field `c`. Classification source: cross-file usage:getService(c).",
        "submitter": "self-test",
    }]
    rec_getservice["android_info_array"] = [{
        "package_id": "y",
        "version_code": 1,
        "version_name": "1",
        "description": "Detected by apk-clues-extract scan; usage 'GATT Service'.",
    }]
    merged_role_rec = merge_records([rec_stale_char], [rec_getservice])[0]
    if merged_role_rec.get("UUID_usage_array") != ["GATT Service"]:
        failures.append(f"merge authoritative getService should win, got {merged_role_rec.get('UUID_usage_array')!r}")
    if "GATT Characteristic" in merged_role_rec.get("UUID_purpose", ""):
        failures.append("merge role sync: purpose still says GATT Characteristic")
    if merged_role_rec.get("UUID_name") != "Unknown":
        failures.append(f"merge role sync: incompatible name should be demoted, got {merged_role_rec.get('UUID_name')!r}")
    if any("usage 'GATT Characteristic'" in a.get("description", "") for a in merged_role_rec.get("android_info_array", [])):
        failures.append("merge role sync: android_info usage text still says GATT Characteristic")

    # Deep Phase-5 should not promote a semantic field name whose role word
    # contradicts observed GATT service usage.
    with _tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "sources", "com", "medtronic", "diabetes")
        os.makedirs(src, exist_ok=True)
        phase5_uuid = "33333333-4444-5555-6666-777777777777"
        with open(os.path.join(src, "Console.java"), "w", encoding="utf-8") as f:
            f.write(
                "package com.medtronic.diabetes;\n"
                "import android.bluetooth.BluetoothGatt;\n"
                "import java.util.UUID;\n"
                "class Console {\n"
                f"  static final UUID MEDTRONIC_CONSOLE_OUTPUT_NOTIFY_CHARACTERISTIC = UUID.fromString(\"{phase5_uuid}\");\n"
                "  void run(BluetoothGatt g) { g.getService(MEDTRONIC_CONSOLE_OUTPUT_NOTIFY_CHARACTERISTIC); }\n"
                "}\n"
            )
        mapping = _phase5_deep_re_jadx(td, {phase5_uuid}, "com.medtronic.diabetes.fota.us")
        got = mapping.get(phase5_uuid, {})
        if got.get("UUID_usage_array") != ["GATT Service"]:
            failures.append(f"deep Phase-5 role conflict: expected service usage, got {got.get('UUID_usage_array')!r}")
        if got.get("UUID_name") == "MEDTRONIC_CONSOLE_OUTPUT_NOTIFY_CHARACTERISTIC":
            failures.append("deep Phase-5 role conflict: promoted incompatible characteristic name onto service")

    # Technogym's BleHeartRateService compares the target UUID on a
    # BluetoothGattService with equals(), then enables notifications on a
    # nested BluetoothGattCharacteristic a few lines later. The nearby
    # ENABLE_NOTIFICATION_VALUE must not turn the service UUID into a
    # characteristic; both equals() receiver roles should remain recoverable.
    with _tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "sources", "com", "technogym", "sdk", "btleheartrate")
        os.makedirs(src, exist_ok=True)
        heart_rate_service_uuid = "6a4e2500-667b-11e3-949a-0800200c9a66"
        heart_rate_characteristic_uuid = "6a4e2501-667b-11e3-949a-0800200c9a66"
        with open(os.path.join(src, "BleHeartRateService.java"), "w", encoding="utf-8") as f:
            f.write(
                "package com.technogym.sdk.btleheartrate;\n"
                "import android.bluetooth.BluetoothGatt;\n"
                "import android.bluetooth.BluetoothGattService;\n"
                "import android.bluetooth.BluetoothGattCharacteristic;\n"
                "import android.bluetooth.BluetoothGattDescriptor;\n"
                "import java.util.UUID;\n"
                "class BleHeartRateService {\n"
                f'  static final UUID f25592z = UUID.fromString("{heart_rate_service_uuid}");\n'
                f'  static final UUID B = UUID.fromString("{heart_rate_characteristic_uuid}");\n'
                "  void onServicesDiscovered(BluetoothGatt g) {\n"
                "    for (BluetoothGattService bluetoothGattService : g.getServices()) {\n"
                "      if (bluetoothGattService.getUuid().equals(f25592z)) {\n"
                "        for (BluetoothGattCharacteristic bluetoothGattCharacteristic : bluetoothGattService.getCharacteristics()) {\n"
                "          if (bluetoothGattCharacteristic.getUuid().equals(B)) {\n"
                "            g.setCharacteristicNotification(bluetoothGattCharacteristic, true);\n"
                "            BluetoothGattDescriptor descriptor = bluetoothGattCharacteristic.getDescriptor(B);\n"
                "            descriptor.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);\n"
                "          }\n"
                "        }\n"
                "      }\n"
                "    }\n"
                "  }\n"
                "}\n"
            )
        mapping = _phase5_deep_re_jadx(
            td,
            {heart_rate_service_uuid, heart_rate_characteristic_uuid},
            "com.optilifewichita.fitness",
        )
        service_entry = mapping.get(heart_rate_service_uuid, {})
        characteristic_entry = mapping.get(heart_rate_characteristic_uuid, {})
        if service_entry.get("UUID_usage_array") != ["GATT Service"]:
            failures.append(
                "deep Phase-5 service equals: expected GATT Service for f25592z, "
                f"got {service_entry.get('UUID_usage_array')!r}"
            )
        if "notification subscription" in service_entry.get("note", ""):
            failures.append(
                "deep Phase-5 service equals: nested notification signal leaked onto service UUID"
            )
        if characteristic_entry.get("UUID_usage_array") != ["GATT Characteristic"]:
            failures.append(
                "deep Phase-5 characteristic equals: expected characteristic role for B, "
                f"got {characteristic_entry.get('UUID_usage_array')!r}"
            )

    # Behavior can establish a role, but a host package ID must not be used
    # to invent a semantic name for a UUID coming from a shared SDK.
    with _tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "sources", "com", "shared", "heartrate")
        os.makedirs(src, exist_ok=True)
        shared_sdk_uuid = "12345678-abcd-4321-9876-1234567890ab"
        with open(os.path.join(src, "Measurement.java"), "w", encoding="utf-8") as f:
            f.write(
                "package com.shared.heartrate;\n"
                "import android.bluetooth.BluetoothGatt;\n"
                "import android.bluetooth.BluetoothGattCharacteristic;\n"
                "import java.util.UUID;\n"
                "class Measurement {\n"
                f'  static final UUID a = UUID.fromString("{shared_sdk_uuid}");\n'
                "  BluetoothGattCharacteristic b;\n"
                "  void discovered(BluetoothGattCharacteristic c) {\n"
                "    if (c.getUuid().compareTo(a) == 0) { b = c; }\n"
                "  }\n"
                "  void changed(BluetoothGatt g, BluetoothGattCharacteristic c) {\n"
                "    g.setCharacteristicNotification(b, true);\n"
                "    onCharacteristicChanged(g, b);\n"
                "  }\n"
                "  void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic c) {}\n"
                "}\n"
            )
        mapping = _phase5_deep_re_jadx(
            td, {shared_sdk_uuid}, "com.optilifeeastwichita.technogym"
        )
        got = mapping.get(shared_sdk_uuid, {})
        if got.get("UUID_usage_array") != ["GATT Characteristic"]:
            failures.append(
                f"deep Phase-5 shared SDK: expected grounded characteristic role, got {got.get('UUID_usage_array')!r}"
            )
        if got.get("UUID_name"):
            failures.append(
                f"deep Phase-5 shared SDK: behavior-only name should be omitted, got {got.get('UUID_name')!r}"
            )
        existing = {
            "UUID": shared_sdk_uuid,
            "UUID_name": "Heart Rate Measurement",
            "UUID_usage_array": ["GATT Characteristic"],
            "evidence_array": [],
        }
        apply_phase5_deep_mapping([existing], mapping, "self-test")
        if existing.get("UUID_name") != "Heart Rate Measurement":
            failures.append("deep Phase-5 shared SDK: overwrote an existing semantic name")

    # A real semantic declaration name remains recoverable and keeps its
    # field spelling while behavior supplies the characteristic role.
    with _tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "sources", "com", "vendor", "ble")
        os.makedirs(src, exist_ok=True)
        semantic_uuid = "12345678-abcd-4321-9876-1234567890ac"
        with open(os.path.join(src, "HeartRate.java"), "w", encoding="utf-8") as f:
            f.write(
                "package com.vendor.ble;\n"
                "import android.bluetooth.BluetoothGatt;\n"
                "import java.util.UUID;\n"
                "class HeartRate {\n"
                f'  static final UUID HEART_RATE_MEASUREMENT_CHARACTERISTIC_UUID = UUID.fromString("{semantic_uuid}");\n'
                "  void read(BluetoothGatt g) { g.getCharacteristic(HEART_RATE_MEASUREMENT_CHARACTERISTIC_UUID); }\n"
                "}\n"
            )
        mapping = _phase5_deep_re_jadx(
            td, {semantic_uuid}, "com.unrelated.hostapp"
        )
        got = mapping.get(semantic_uuid, {})
        if got.get("UUID_name") != "HEART_RATE_MEASUREMENT_CHARACTERISTIC_UUID":
            failures.append(
                f"deep Phase-5 semantic name: expected original field, got {got.get('UUID_name')!r}"
            )
        if got.get("UUID_usage_array") != ["GATT Characteristic"]:
            failures.append(
                f"deep Phase-5 semantic name: expected characteristic role, got {got.get('UUID_usage_array')!r}"
            )

    # File-level fallback: UUID block far from any BluetoothGatt* identifier
    # in a file that nevertheless imports BluetoothGattService etc.
    body = "package x;\nimport android.bluetooth.BluetoothGattService;\n"
    body += "class Foo {\n  BluetoothGattService svc;\n"
    body += "\n" * 50  # force the UUID block far from the import
    body += '  public static final UUID U1 = UUID.fromString("0000abcd-0000-1000-8000-00805f9b34fb");\n'
    body += '  public static final UUID U2 = UUID.fromString("12345678-1234-1234-1234-123456789abc");\n}\n'
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(body)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        if "0000abcd-0000-1000-8000-00805f9b34fb" not in found:
            failures.append("file-level fallback: missed SIG-base wrapped UUID16 (abcd)")
        if "12345678-1234-1234-1234-123456789abc" not in found:
            failures.append("file-level fallback: missed vendor UUID128")
    finally:
        os.unlink(tmppath)

    # Fallback: a file with no android.bluetooth imports but ≥3
    # UUID.fromString literals (the e2/d.java case in com.harman.akgn20lt).
    # NOTE: don't use aaaaaaaa-..., bbbbbbbb-..., cccccccc-... — those are in
    # DROP_OUTRIGHT_UUIDS (developer-placeholder filter) and would all be
    # dropped, hiding any real regression in the ≥3 fallback path.
    u_a = "abcde001-1111-2222-3333-444455556677"
    u_b = "abcde002-1111-2222-3333-444455556677"
    u_c = "abcde003-1111-2222-3333-444455556677"
    body3 = "package e2;\nimport java.util.UUID;\nclass d {\n"
    body3 += f'  static final UUID A = UUID.fromString("{u_a}");\n'
    body3 += f'  static final UUID B = UUID.fromString("{u_b}");\n'
    body3 += f'  static final UUID C = UUID.fromString("{u_c}");\n'
    body3 += "}\n"
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(body3)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        if u_a not in found:
            failures.append("≥3 UUID.fromString fallback: missed first UUID")
        if len(found) != 3:
            failures.append(f"≥3 UUID.fromString fallback: expected 3, got {len(found)}")
    finally:
        os.unlink(tmppath)

    # Negative: a file without ANY BLE imports should NOT pick up a stray UUID.
    body2 = "package x;\nclass Bar {\n"
    body2 += '  String licenseKey = "12345678-1234-1234-1234-123456789abc";\n}\n'
    with _tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as tf:
        tf.write(body2)
        tmppath = tf.name
    try:
        found = scan_one_file(tmppath)
        if "12345678-1234-1234-1234-123456789abc" in found:
            failures.append("non-BLE file: leaked a non-BLE UUID through")
    finally:
        os.unlink(tmppath)

    # --session-output delta logic — emulate what `main` does.
    pre_existing = [{"UUID": "aaaa", "company": "X", "UUID_name": "X",
                     "UUID_purpose": "x", "UUID_usage_array": ["GATT Service"],
                     "evidence_array": [{"submitter": "x"}],
                     "android_info_array": [{"package_id": "x", "version_code": 1, "version_name": "1"}]}]
    accum_after = pre_existing + [
        {"UUID": "bbbb", "company": "Y", "UUID_name": "Y",
         "UUID_purpose": "y", "UUID_usage_array": ["GATT Service"],
         "evidence_array": [{"submitter": "y"}],
         "android_info_array": [{"package_id": "y", "version_code": 1, "version_name": "1"}]},
    ]
    pre_uuids = {"aaaa"}
    session_delta = [r for r in accum_after if r["UUID"].lower() not in pre_uuids]
    if len(session_delta) != 1 or session_delta[0]["UUID"] != "bbbb":
        failures.append(f"session-output delta: expected only 'bbbb', got {[r['UUID'] for r in session_delta]}")

    # _detect_third_party_sdk_package
    res = _detect_third_party_sdk_package(
        {"com.ondo.ocssmartlibrary.utils"}, "sesame.smartspaces.d2i.co")
    if res != "com.ondo.ocssmartlibrary.utils":
        failures.append(f"_detect_third_party_sdk_package(ondo vs sesame): got {res!r}")
    res = _detect_third_party_sdk_package(
        {"com.abbott.lingo.wellness.bsm"}, "com.abbott.lingo.wellness")
    if res is not None:
        failures.append(f"_detect_third_party_sdk_package(abbott vs abbott): got {res!r}")
    res = _detect_third_party_sdk_package(set(), "anything")
    if res is not None:
        failures.append("_detect_third_party_sdk_package(empty): should be None")

    # CLUES_data_human_verified.json skip-list: filter_vendor_specific drops UUIDs in curated.
    cands = {
        "0000abcd-0000-1000-8000-00805f9b34fb": {"classification": "GATT Service", "field_name": None, "snippets": [], "parent_candidates": []},
        "deadbeef-aaaa-aaaa-aaaa-aaaaaaaaaaaa": {"classification": "GATT Service", "field_name": None, "snippets": [], "parent_candidates": []},
        "11111111-1111-1111-1111-111111111111": {"classification": "GATT Service", "field_name": None, "snippets": [], "parent_candidates": []},
    }
    curated = {"abcd", "11111111-1111-1111-1111-111111111111"}
    kept, _ = filter_vendor_specific(cands, member_uuids={}, curated_uuids=curated)
    if "abcd" in kept:
        failures.append("curated skip: abcd should be dropped (in curated as UUID16)")
    if "11111111-1111-1111-1111-111111111111" in kept:
        failures.append("curated skip: 1111... UUID128 should be dropped (in curated)")
    if "deadbeef-aaaa-aaaa-aaaa-aaaaaaaaaaaa" not in kept:
        failures.append("curated skip: deadbeef should be kept (not in curated)")

    # dedupe_evidence_array: the user-reported Sterilor pattern (two
    # `Found in decompiled DEX of <pkg> v<ver>` entries that differ only in
    # `Classification source:`) collapses to one — the more-informative
    # survivor wins.
    sterilor_ev = [
        {
            "description": "Found in decompiled DEX of com.sterilor.app v1.12.19 (versionCode 1094). Classification source: naming-convention.",
            "submitter": DEFAULT_SUBMITTER,
        },
        {
            "URL": "https://apkpure.net/app/com.sterilor.app/download/1.12.19",
            "description": "APK at this package + version is downloadable from apkpure.net; URL verified (status=ok, direct_download=False).",
            "submitter": DEFAULT_SUBMITTER,
        },
        {
            "description": "Found in decompiled DEX of com.sterilor.app v1.12.19 (versionCode 1094). Classification source: file-level-default.",
            "submitter": DEFAULT_SUBMITTER,
        },
    ]
    deduped = dedupe_evidence_array(sterilor_ev)
    if len(deduped) != 2:
        failures.append(f"dedupe(Sterilor): expected 2 entries, got {len(deduped)}")
    elif "naming-convention" not in deduped[0].get("description", ""):
        failures.append("dedupe(Sterilor): naming-convention (higher priority) should have won")

    # dedupe_evidence_array: exact duplicates collapse, order preserved.
    same = {"description": "Foo", "submitter": "X"}
    out2 = dedupe_evidence_array([same, {"URL": "https://a/b", "description": "u", "submitter": "X"}, same])
    if len(out2) != 2:
        failures.append(f"dedupe(exact-dup): expected 2 entries, got {len(out2)}")

    # dedupe_evidence_array: URL match collapses regardless of differing description.
    url_ev = [
        {"URL": "https://EX.com/x", "description": "first wording", "submitter": "A"},
        {"URL": "https://ex.com/x", "description": "second wording (longer, so might win priority)", "submitter": "A"},
    ]
    out3 = dedupe_evidence_array(url_ev)
    if len(out3) != 1:
        failures.append(f"dedupe(URL): case-insensitive URL match should collapse to 1, got {len(out3)}")

    # dedupe_evidence_array: distinct Phase-5 notes are preserved (different "OTHER" keys).
    phase5_ev = [
        {"description": "Phase-5 UUID-name resolution: foo characteristic", "submitter": DEFAULT_SUBMITTER},
        {"description": "Phase-5 UUID-name resolution: bar characteristic", "submitter": DEFAULT_SUBMITTER},
    ]
    out4 = dedupe_evidence_array(phase5_ev)
    if len(out4) != 2:
        failures.append(f"dedupe(Phase-5 distinct): should preserve 2 entries, got {len(out4)}")

    # dedupe_evidence_array: priority survivor — third-party-SDK entry beats plain.
    sdk_ev = [
        {
            "description": "Found in decompiled DEX of com.host.app v1 (versionCode 1). Classification source: naming-convention.",
            "submitter": "X",
        },
        {
            "description": "Found in decompiled DEX of com.host.app v1 (versionCode 1), in Java field `MY_FIELD`, declared in Java package `com.sdk.lib` (third-party SDK). Classification source: usage:getService.",
            "submitter": "X",
        },
    ]
    out5 = dedupe_evidence_array(sdk_ev)
    if len(out5) != 1:
        failures.append(f"dedupe(priority): expected 1 entry, got {len(out5)}")
    elif "third-party SDK" not in out5[0]["description"]:
        failures.append("dedupe(priority): the third-party-SDK / usage entry should have won")

    # semantic_upgrade_report: --search-unknown style reruns may add zero new
    # UUIDs while still turning existing Unknown names into real labels. Make
    # sure that signal is preserved separately from --session-output.
    before = {
        "abcde001-1234-5678-9abc-def012345678": {
            "UUID": "abcde001-1234-5678-9abc-def012345678",
            "company": "Unknown",
            "UUID_name": "Unknown",
        }
    }
    after = [{
        "UUID": "abcde001-1234-5678-9abc-def012345678",
        "company": "Example Vendor",
        "UUID_name": "EXAMPLE_NOTIFY_CHARACTERISTIC",
    }]
    upgrades = semantic_upgrade_report(before, after)
    if len(upgrades["UUID_name_upgrades"]) != 1:
        failures.append("semantic-upgrade-report: missed Unknown -> named UUID_name recovery")
    if len(upgrades["company_upgrades"]) != 1:
        failures.append("semantic-upgrade-report: missed Unknown -> named company recovery")

    # Predecompiled jadx output: found through the "<ancestor>_jadx" layout and
    # through an explicit root, refused for a changed APK or the other jadx
    # flag set, and its tree is pruned from APK discovery.
    if predecompiled_cache is not None:
        with _tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "apks")
            apk = os.path.join(base, "00", "x.apk")
            os.makedirs(os.path.dirname(apk))
            with open(apk, "wb") as f:
                f.write(b"PK\x03\x04 not really an apk")
            root = predecompiled_cache.root_for_base(base)
            entry = predecompiled_cache.entry_path(root, base, apk)
            os.makedirs(os.path.join(entry, "sources"))
            with open(os.path.join(root, predecompiled_cache.ROOT_MARKER), "w") as f:
                f.write("{}")
            with open(os.path.join(entry, predecompiled_cache.META_NAME), "w") as f:
                json.dump({"schema": predecompiled_cache.SCHEMA_VERSION, "status": "partial",
                           "show_bad_code": False, "apk_name": "x.apk",
                           "apk_size": os.path.getsize(apk),
                           "apk_fingerprint": predecompiled_cache.apk_fingerprint(apk)}, f)
            if predecompiled_cache.find_predecompiled(apk) != entry:
                failures.append("predecompiled: entry under <ancestor>_jadx not found")
            if predecompiled_cache.find_predecompiled(apk, show_bad_code=True) is not None:
                failures.append("predecompiled: default entry served a --show-bad-code lookup")
            open(os.path.join(root, "00", "decoy.apk"), "wb").close()
            if list(iter_input_paths(td)) != [apk]:
                failures.append("predecompiled: APK discovery descended into a _jadx tree")
            moved = os.path.join(td, "elsewhere")
            shutil.move(root, moved)
            if predecompiled_cache.find_predecompiled(apk) is not None:
                failures.append("predecompiled: entry found after its root moved away")
            if predecompiled_cache.find_predecompiled(apk, extra_roots=[moved]) != os.path.join(
                    moved, "00", "x.apk.jadx"):
                failures.append("predecompiled: explicit root not searched by path suffix")
            with open(apk, "ab") as f:
                f.write(b"changed")
            if predecompiled_cache.find_predecompiled(apk, extra_roots=[moved]) is not None:
                failures.append("predecompiled: stale entry used for a changed APK")

        # The same through an archive entry: found, unpacked whole into the
        # caller's scratch directory (also via the CLI the agents use), a
        # directory entry at the same location goes first, and a damaged
        # archive is refused rather than half unpacked.
        import contextlib as _contextlib
        import io as _io
        with _tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "apks")
            apk = os.path.join(base, "00", "x.apk")
            os.makedirs(os.path.dirname(apk))
            with open(apk, "wb") as f:
                f.write(b"PK\x03\x04 not really an apk")
            root = predecompiled_cache.root_for_base(base)
            out = os.path.join(td, "out")
            os.makedirs(os.path.join(out, "sources", "com", "x"))
            with open(os.path.join(out, "sources", "com", "x", "A.java"), "w") as f:
                f.write("class A {}\n")
            # Incompressible bulk after A.java, so a cut-off archive still
            # yields a partial sources/ before the reader hits the damage.
            with open(os.path.join(out, "sources", "com", "x", "Z.bin"), "wb") as f:
                f.write(os.urandom(256 * 1024))
            with open(os.path.join(out, predecompiled_cache.META_NAME), "w") as f:
                json.dump({"schema": predecompiled_cache.SCHEMA_VERSION, "status": "ok",
                           "show_bad_code": False, "apk_name": "x.apk",
                           "apk_size": os.path.getsize(apk),
                           "apk_fingerprint": predecompiled_cache.apk_fingerprint(apk)}, f)
            loc = predecompiled_cache.entry_path(root, base, apk)
            arc = predecompiled_cache.entry_forms(loc)[1]
            os.makedirs(os.path.dirname(arc))
            predecompiled_cache.write_archive(out, arc, preset=0)
            if predecompiled_cache.find_predecompiled(apk) != arc:
                failures.append("predecompiled: archive entry not found")
            if predecompiled_cache.find_predecompiled(apk, show_bad_code=True) is not None:
                failures.append("predecompiled: archive entry served a --show-bad-code lookup")
            t1 = os.path.join(td, "t1")
            try:
                jout, reused = jadx_output_dir("/nonexistent/jadx", apk, apk, t1, 5)
            except OSError:     # fell through to running jadx
                jout, reused = None, False
            if not (reused and jout and jout.startswith(t1 + os.sep) and os.path.isfile(
                    os.path.join(jout, "sources", "com", "x", "A.java"))):
                failures.append("predecompiled: archive entry not unpacked into tmp_root")
            dest = os.path.join(td, "agentcache", "x")
            with _contextlib.redirect_stdout(_io.StringIO()) as so:
                rc = predecompiled_cache.main(["--extract-to", dest, apk])
            if rc != 0 or so.getvalue().strip() != dest or not os.path.isdir(
                    os.path.join(dest, "sources")):
                failures.append("predecompiled: CLI --extract-to did not unpack the archive")
            shutil.copytree(out, loc)
            if predecompiled_cache.find_predecompiled(apk) != loc:
                failures.append("predecompiled: archive preferred over a directory entry")
            shutil.rmtree(loc)
            with open(arc, "rb") as f:
                data = f.read()
            with open(arc, "wb") as f:
                f.write(data[:len(data) * 3 // 4])
            bad = os.path.join(td, "t2", "jadx_predecompiled")
            if predecompiled_cache.materialize(arc, bad) is not None or os.path.exists(
                    os.path.join(bad, "sources")):
                failures.append("predecompiled: truncated archive was unpacked")

    try:
        managed_clues.self_test()
    except Exception as exc:
        failures.append(f"managed-code helper: {exc}")

    if failures:
        for f in failures:
            print("FAIL:", f, file=sys.stderr)
        return 1
    print("self-test OK")
    return 0


# ---------------------------------------------------------------------------
# Checkpoint (for resumable + parallel runs)
# ---------------------------------------------------------------------------

def _checkpoint_path(output_path: str) -> str:
    """Sidecar file next to the output JSON. Maps APK SHA-1 → {status, ts}."""
    return output_path + ".processed.json"


def _apk_sha1(apk_path: str) -> str:
    """Cheap content hash so we can tell when an APK at the same path has
    changed (a publisher re-released the same version with different bits).
    SHA-1 over the first 4 MiB is plenty — APKs differ in their header.
    Full-file hashing would dominate a fast scan."""
    import hashlib
    h = hashlib.sha1()
    try:
        with open(apk_path, "rb") as f:
            h.update(f.read(4 * 1024 * 1024))
    except OSError:
        return ""
    h.update(str(os.path.getsize(apk_path)).encode())
    return h.hexdigest()


def _load_checkpoint(path: str) -> dict[str, dict]:
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_checkpoint(path: str, ckpt: dict[str, dict]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(ckpt, f, indent=2)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Deep Phase-5 RE checkpointing
#
# The deep Phase-5 pass decompiles one APK at a time with `jadx
# --show-bad-code` -- minutes of work each, and a corpus-wide run is hours
# long. The plain serial loop accumulated every recovered name in RAM and
# wrote it out only at the very end, so any interruption (OOM, reboot,
# Ctrl-C) threw the whole run away. `_run_phase5_deep_loop` instead records
# each finished APK's result to a JSON-Lines sidecar
# (`<output>.phase5_deep.jsonl`) and fsyncs it, so a re-run of the same
# command resumes from the next APK instead of from scratch. On clean
# completion the caller drops the sidecar (`_remove_phase5_deep_state`) so a
# later re-run re-derives the Unknown set fresh; `--no-resume` discards it
# up front. The sidecar is keyed by APK content SHA-1, not path.
# ---------------------------------------------------------------------------

def _phase5_deep_state_path(output_path: str) -> str:
    """Per-APK deep-Phase-5 resume sidecar, next to --output."""
    return output_path + ".phase5_deep.jsonl"


def _load_phase5_deep_state(path: str) -> list[dict]:
    """Replay the deep-Phase-5 sidecar (one JSON object per line). A torn
    final line from a crash mid-append is tolerated and skipped."""
    out: list[dict] = []
    if not os.path.isfile(path):
        return out
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # interrupted append -- ignore the partial line
    except OSError:
        pass
    return out


def _append_phase5_deep_state(path: str, entry: dict) -> None:
    """Append one finished APK's result as a JSON line and fsync it, so an
    interrupted run loses at most the APK currently in flight."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


def _remove_phase5_deep_state(output_path: str) -> None:
    """Drop the resume sidecar after a clean deep-Phase-5 completion."""
    try:
        os.remove(_phase5_deep_state_path(output_path))
    except OSError:
        pass


def _run_phase5_deep_loop(
    to_process: list[str],
    unknown_uuid_targets_by_path: dict[str, set[str]],
    aapt: str,
    jadx: str,
    args,
    predecompiled: tuple[str, ...] | None = (),
) -> tuple[dict[str, dict], int]:
    """Decompile each target APK and run the deep Phase-5 RE pass, checkpointing
    every finished APK to a crash-safe sidecar. Returns the merged UUID->info
    mapping (successful sidecar entries + this run's fresh results) and the
    number of failed or incomplete APKs. Failed entries remain retryable."""
    state_path = _phase5_deep_state_path(args.output)
    deep_mapping: dict[str, dict] = {}
    # Key the sidecar by APK content hash so a moved/renamed APK still resumes.
    targets = [(apk, _apk_sha1(apk)) for apk in to_process]
    run_shas = {sha for _, sha in targets if sha}
    done_shas: set[str] = set()
    failed_apks = 0
    if args.no_resume:
        if os.path.isfile(state_path):
            os.remove(state_path)
    else:
        for entry in _load_phase5_deep_state(state_path):
            sha = entry.get("sha", "")
            status = entry.get("status", "")
            if sha and sha in run_shas and _is_successful_apk_status(status):
                done_shas.add(sha)
                deep_mapping.update(entry.get("mapping", {}))
        if done_shas:
            print(
                f"[*] deep Phase-5 resume: {len(done_shas)}/{len(targets)} target "
                f"APK(s) already done in {state_path}; "
                f"{len(deep_mapping)} mapping entr(ies) restored",
                file=sys.stderr,
            )
    pending = [(apk, sha) for apk, sha in targets if sha not in done_shas]
    for i, (apk, sha) in enumerate(pending, 1):
        target_uuids = unknown_uuid_targets_by_path.get(apk, set())
        if not target_uuids:
            continue
        print(
            f"[deep Phase-5 {i}/{len(pending)}] {apk} "
            f"({len(target_uuids)} Unknown UUID target(s))",
            file=sys.stderr,
        )
        status, mapping = phase5_deep_re_apk(
            apk, target_uuids, aapt, jadx, args.jadx_timeout_sec, args.keep_tmp,
            predecompiled=predecompiled,
        )
        print(f"    -> {status}", file=sys.stderr)
        if not _is_successful_apk_status(status):
            failed_apks += 1
        deep_mapping.update(mapping)
        # Durably checkpoint this APK before the next one starts.
        if sha:
            _append_phase5_deep_state(
                state_path,
                {"sha": sha, "path": apk, "status": status, "mapping": mapping},
            )
    return deep_mapping, failed_apks


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Extract vendor-specific GATT UUIDs from APKs/XAPKs into CLUES JSON."
    )
    p.add_argument("path", nargs="*", help="One or more APK files, XAPK files, or directories to recurse. Each directory is walked; each file is processed directly. Use as many positional args as you like; duplicates (same APK reached via multiple paths) are skipped via the checkpoint.")
    p.add_argument("--output", default=DEFAULT_OUTPUT, help=f"Output JSON path (default: {DEFAULT_OUTPUT})")
    p.add_argument("--submitter", default=DEFAULT_SUBMITTER, help="Submitter string written into every emitted record")
    p.add_argument("--jadx-timeout-sec", type=int, default=DEFAULT_JADX_TIMEOUT_SEC, help="Per-APK jadx wall-clock timeout (seconds)")
    p.add_argument("--keep-tmp", action="store_true", help="Don't delete the per-APK jadx output tmpdir (debug only)")
    p.add_argument("--predecompiled-dir", action="append", default=[],
                   help="Extra root of predecompile_apks.py output to search (repeatable; also "
                        "$APK_CLUES_PREDECOMPILED_DIRS). Not needed for the default layout: an "
                        "APK's entry in the '<ancestor dir>_jadx/' tree predecompile_apks.py "
                        "writes is found automatically.")
    p.add_argument("--no-predecompiled", action="store_true",
                   help="Ignore predecompiled jadx output and run jadx for every APK.")
    p.add_argument("--member-uuids-yaml", default=DEFAULT_SIG_ASSIGNED_NUMBERS,
                   help=f"Path to Bluetooth SIG member_uuids.yaml. Used both to drop already-published UUID16s and to infer the per-APK company name. Default: {DEFAULT_SIG_ASSIGNED_NUMBERS}")
    p.add_argument("--curated-clues", default=DEFAULT_CURATED_CLUES,
                   help=f"Path to the canonical hand-curated CLUES_data_human_verified.json (renamed from CLUES_data.json when data moved under CLUES_Schema/data/). UUIDs already present there are human-verified and the highest-trust source in the project; this skill skips them on output rather than risk a curated entry being regressed on merge. Pass an empty string to disable the skip-list. Default: {DEFAULT_CURATED_CLUES}")
    p.add_argument("--session-output", default=None,
                   help="Optional second output file. After the run, this file is "
                        "written with ONLY records whose UUID didn't exist in --output "
                        "before this session started — useful for diffing what a "
                        "specific run contributed without having to compute it by hand. "
                        "If --output was empty/missing at start, --session-output is "
                        "identical to --output.")
    p.add_argument("--semantic-upgrades-output", default=None,
                   help="Optional JSON report of semantic upgrades made to records that "
                        "already existed in --output at the start of this run. Especially "
                        "useful with --search-unknown, where the run may add zero brand-new "
                        "UUIDs but still recover many UUID_name/company values.")
    p.add_argument("--progress-interval", type=int, default=100,
                   help="Emit a checkpoint progress line every N processed APKs, including "
                        "the current count of UUID_name=='Unknown' records. Default: 100. "
                        "Use 0 to disable.")
    p.add_argument("--parallel", type=int, default=1,
                   help="Number of worker processes for the per-APK pipeline. 1 = serial (default). "
                        "On an 8-core machine, --parallel 4 typically cuts wall time by ~3x. "
                        "Each worker spawns its own jadx subprocess, so the practical ceiling is "
                        "min(cpu_count() // 2, len(targets)).")
    p.add_argument("--no-resume", action="store_true",
                   help="Ignore the checkpoint sidecar (.processed.json next to --output) and "
                        "re-process every APK from scratch. Default is to skip APKs already in "
                        "the checkpoint with status='ok' (and matching SHA-1).")
    p.add_argument("--search-unknown", action="store_true",
                   help="Re-analyze APKs that contributed records with UUID_name=='Unknown' "
                        "(or empty/missing) to --output. The target APK set is derived from the "
                        "android_info_array.package_path fields of those records, the checkpoint "
                        "is bypassed for those specific APKs (so they get re-processed even though "
                        "they already have status='ok'), and the rest of the checkpoint is left "
                        "intact. Useful because Phase-1's classifier improves over time — a re-run "
                        "with new heuristics can resolve UUIDs that were Unknown on the first scan. "
                        "After the normal re-extraction, this also runs the deep Phase-5 RE pass "
                        "on the same Unknown UUIDs: JADX --show-bad-code, UUID-field dataflow, "
                        "GATT service/characteristic aliases, write/read/notify usage, and nearby "
                        "UI/log strings. "
                        "Positional path args, if given, act as a filter: only Unknown-record APKs "
                        "whose absolute path matches one of those paths exactly OR lives under one "
                        "of them are processed. Paths that no longer exist on disk are skipped with "
                        "a warning. This flag makes the positional path args optional.")
    p.add_argument("--phase5-deep-re", action="store_true",
                   help="Run ONLY the deep Phase-5 RE pass against UUID_name=='Unknown' records "
                        "already present in --output. This derives target APKs from "
                        "android_info_array.package_path, optionally filtered by positional paths, "
                        "decompiles with JADX --show-bad-code, traces obfuscated UUID constants "
                        "through GATT aliases and read/write/notify behavior, applies confident "
                        "Unknown->name upgrades in place, and exits without doing normal Phase-1 "
                        "extraction.")
    p.add_argument("--phase5-deep-re-output", default=None,
                   help="Optional JSON mapping report produced by the deep Phase-5 RE pass. "
                        "Keys are UUIDs; values include recovered UUID_name, usage, and note.")
    p.add_argument("--self-test", action="store_true", help="Run internal sanity checks and exit")
    args = p.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.path and not args.search_unknown and not args.phase5_deep_re:
        p.error("at least one path is required (unless --self-test, --search-unknown, or --phase5-deep-re)")

    if (args.search_unknown or args.phase5_deep_re) and args.session_output and not args.semantic_upgrades_output:
        root, ext = os.path.splitext(args.session_output)
        args.semantic_upgrades_output = root + "_semantic_upgrades" + (ext or ".json")

    for one in args.path:
        if not os.path.exists(one):
            p.error(f"path does not exist: {one}")

    aapt = find_aapt()
    jadx = find_jadx()
    predecompiled = None if args.no_predecompiled else tuple(args.predecompiled_dir)
    if predecompiled is not None and predecompiled_cache is None:
        print("[!] predecompiled_cache.py is not next to extract_clues.py; "
              "running jadx for every APK", file=sys.stderr)
        predecompiled = None
    member_uuids = load_member_uuids(args.member_uuids_yaml)
    curated_uuids = load_curated_clues_uuids(args.curated_clues) if args.curated_clues else set()

    existing = load_existing(args.output)
    existing_uuids = {r.get("UUID", "").lower() for r in existing}
    # Snapshot of UUIDs present BEFORE this session — used by --session-output
    # to write only the records this run contributed.
    pre_session_uuids = set(existing_uuids)
    # Snapshot of semantic fields BEFORE this session — used by
    # --semantic-upgrades-output and by the final stderr summary. This is the
    # audit trail that --search-unknown needs: zero UUIDs may be new while many
    # UUID_name values improve from "Unknown" to a real developer label.
    pre_session_by_uuid = {
        (r.get("UUID") or "").lower(): copy.deepcopy(r)
        for r in existing
        if r.get("UUID")
    }
    ckpt_path = _checkpoint_path(args.output)
    ckpt = {} if args.no_resume else _load_checkpoint(ckpt_path)
    print(
        f"[*] aapt={aapt}\n[*] jadx={jadx}\n[*] output={args.output} "
        f"(starting with {len(existing)} records, {len(existing_uuids)} unique UUIDs)\n"
        f"[*] member_uuids.yaml: {len(member_uuids)} entries loaded from "
        f"{args.member_uuids_yaml}\n"
        f"[*] curated CLUES_data_human_verified.json: {len(curated_uuids)} UUIDs loaded "
        f"from {args.curated_clues or '(disabled)'} — these will be SKIPPED on output\n"
        f"[*] checkpoint={ckpt_path} ({len(ckpt)} APKs already recorded)\n"
        f"[*] submitter={args.submitter!r}, credited on every evidence entry this run "
        f"writes (pass --submitter if that is not the model doing this run)",
        file=sys.stderr,
    )
    if predecompiled is None:
        print("[*] predecompiled jadx output: not used", file=sys.stderr)
    else:
        extra = predecompiled_cache.configured_roots(predecompiled)
        print("[*] predecompiled jadx output: reused when valid ('<ancestor>_jadx/' entries"
              + (f" + {extra}" if extra else "") + ")", file=sys.stderr)

    targets: list[str] = []
    seen: set[str] = set()
    unknown_uuid_targets_by_path: dict[str, set[str]] = {}
    if args.search_unknown or args.phase5_deep_re:
        # Derive targets from records in --output whose UUID_name is Unknown/empty.
        # The package_path field on each android_info_array entry was written at
        # extraction time and points to the on-disk APK that yielded the UUID.
        before_filter_targets, unknown_record_count, missing = derive_unknown_uuid_targets(existing)
        unknown_paths = set(before_filter_targets)
        print(
            f"[*] Unknown target derivation: {unknown_record_count} UUID128 record(s) with "
            f"UUID_name=='Unknown'/empty -> {len(unknown_paths)} unique source APK path(s)",
            file=sys.stderr,
        )
        if args.path:
            before = len(unknown_paths)
            unknown_uuid_targets_by_path, _unknown_record_count2, missing = derive_unknown_uuid_targets(existing, args.path)
            unknown_paths = set(unknown_uuid_targets_by_path)
            print(
                f"[*] Unknown target derivation: positional path filter -> "
                f"{len(unknown_paths)} of {before} kept",
                file=sys.stderr,
            )
        else:
            unknown_uuid_targets_by_path = before_filter_targets
        on_disk = sorted(unknown_uuid_targets_by_path)
        if missing:
            print(
                f"[*] Unknown target derivation: {missing} path(s) no longer on disk; skipped",
                file=sys.stderr,
            )
        for apk in on_disk:
            abs_apk = os.path.abspath(apk)
            if abs_apk in seen:
                continue
            seen.add(abs_apk)
            targets.append(apk)
    else:
        for one in args.path:
            for apk in iter_input_paths(one):
                abs_apk = os.path.abspath(apk)
                if abs_apk in seen:
                    continue
                seen.add(abs_apk)
                targets.append(apk)
    # Resumability: skip APKs the checkpoint says we've already done.
    # In --search-unknown mode the checkpoint is ignored for the derived
    # target set (re-processing them is the whole point) but is still
    # consulted-and-preserved for any other entries — non-target APKs in
    # the sidecar are not touched.
    to_process: list[str] = []
    skipped = 0
    for apk in targets:
        sha = _apk_sha1(apk)
        prior = ckpt.get(sha) if sha else None
        if (
            not args.search_unknown
            and not args.phase5_deep_re
            and prior
            and prior.get("status", "").startswith("ok")
            and prior.get("path") == apk
        ):
            skipped += 1
            continue
        to_process.append(apk)
    print(
        f"[*] {len(targets)} input APK/XAPK file(s); "
        f"{skipped} already in checkpoint, {len(to_process)} to process; "
        f"parallel={args.parallel}",
        file=sys.stderr,
    )

    accum = existing
    if args.phase5_deep_re:
        deep_mapping, deep_failed_apks = _run_phase5_deep_loop(
            to_process, unknown_uuid_targets_by_path, aapt, jadx, args,
            predecompiled=predecompiled,
        )
        changed = apply_phase5_deep_mapping(accum, deep_mapping, args.submitter)
        if changed:
            save_output(args.output, accum)
            print(
                f"[*] deep Phase-5 applied {changed} record update(s) to {args.output}",
                file=sys.stderr,
            )
        else:
            print("[*] deep Phase-5 found no confident updates", file=sys.stderr)
        # Drop the resume sidecar only after every APK completed successfully.
        # Failed statuses stay retryable on the next invocation.
        if not deep_failed_apks:
            _remove_phase5_deep_state(args.output)
        if args.phase5_deep_re_output:
            tmp = args.phase5_deep_re_output + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(deep_mapping, f, indent=4, ensure_ascii=False)
                f.write("\n")
            os.replace(tmp, args.phase5_deep_re_output)
            print(
                f"[*] wrote deep Phase-5 mapping report to {args.phase5_deep_re_output}",
                file=sys.stderr,
            )
        upgrade_report = semantic_upgrade_report(pre_session_by_uuid, accum)
        if args.semantic_upgrades_output:
            tmp = args.semantic_upgrades_output + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(upgrade_report, f, indent=4, ensure_ascii=False)
                f.write("\n")
            os.replace(tmp, args.semantic_upgrades_output)
        print(
            f"[*] semantic upgrades this run: "
            f"{len(upgrade_report['UUID_name_upgrades'])} UUID_name, "
            f"{len(upgrade_report['company_upgrades'])} company",
            file=sys.stderr,
        )
        if deep_failed_apks:
            print(
                f"[!] {deep_failed_apks} deep Phase-5 APK(s) failed or were incomplete; "
                f"their resume entries remain retryable. Fix the reported cause and rerun.",
                file=sys.stderr,
            )
        return 1 if deep_failed_apks else 0

    incomplete_managed = 0
    failed_apks = 0
    phase5_failed_apks = 0
    if args.parallel <= 1:
        # Serial loop — simpler, what we've always had.
        for i, apk in enumerate(to_process, 1):
            print(f"[{i}/{len(to_process)}] {apk}", file=sys.stderr)
            status, records = process_one_apk(
                apk, aapt, jadx, args.submitter, args.jadx_timeout_sec,
                args.keep_tmp, member_uuids=member_uuids,
                curated_uuids=curated_uuids, predecompiled=predecompiled,
            )
            print(f"    -> {status}", file=sys.stderr)
            if not _is_successful_apk_status(status):
                failed_apks += 1
            if status.startswith("managed_incomplete:"):
                incomplete_managed += 1
            sha = _apk_sha1(apk)
            if sha:
                ckpt[sha] = {"status": status, "path": apk}
                _save_checkpoint(ckpt_path, ckpt)
            if records:
                accum = merge_records(accum, records)
                save_output(args.output, accum)
                print(
                    f"    -> wrote {len(accum)} total records to {args.output}",
                    file=sys.stderr,
                )
            if args.progress_interval > 0 and (
                i % args.progress_interval == 0 or i == len(to_process)
            ):
                print(
                    f"[*] progress checkpoint: {i}/{len(to_process)} APKs processed; "
                    f"UUID_name=='Unknown' remaining: {count_unknown_uuid_names(accum)}",
                    file=sys.stderr,
                )
    else:
        # Parallel pool — workers run process_one_apk; main thread merges
        # + serializes output writes (the only shared resource).
        import concurrent.futures
        n_workers = max(1, args.parallel)
        with concurrent.futures.ProcessPoolExecutor(max_workers=n_workers) as ex:
            futures = {
                ex.submit(
                    process_one_apk,
                    apk, aapt, jadx, args.submitter, args.jadx_timeout_sec,
                    args.keep_tmp, member_uuids, curated_uuids, predecompiled,
                ): apk
                for apk in to_process
            }
            done = 0
            for fut in concurrent.futures.as_completed(futures):
                apk = futures[fut]
                done += 1
                try:
                    status, records = fut.result()
                except Exception as e:
                    status, records = f"exception:{type(e).__name__}:{e}", []
                print(f"[{done}/{len(to_process)}] {apk}", file=sys.stderr)
                print(f"    -> {status}", file=sys.stderr)
                if not _is_successful_apk_status(status):
                    failed_apks += 1
                if status.startswith("managed_incomplete:"):
                    incomplete_managed += 1
                sha = _apk_sha1(apk)
                if sha:
                    ckpt[sha] = {"status": status, "path": apk}
                    _save_checkpoint(ckpt_path, ckpt)
                if records:
                    accum = merge_records(accum, records)
                    save_output(args.output, accum)
                    print(
                        f"    -> wrote {len(accum)} total records to {args.output}",
                        file=sys.stderr,
                    )
                if args.progress_interval > 0 and (
                    done % args.progress_interval == 0 or done == len(to_process)
                ):
                    print(
                        f"[*] progress checkpoint: {done}/{len(to_process)} APKs processed; "
                        f"UUID_name=='Unknown' remaining: {count_unknown_uuid_names(accum)}",
                        file=sys.stderr,
                    )

    if args.search_unknown:
        print(
            f"[*] --search-unknown: running deep Phase-5 RE over "
            f"{len(to_process)} reprocessed APK(s)",
            file=sys.stderr,
        )
        deep_mapping, phase5_failed_apks = _run_phase5_deep_loop(
            to_process, unknown_uuid_targets_by_path, aapt, jadx, args,
            predecompiled=predecompiled,
        )
        changed = apply_phase5_deep_mapping(accum, deep_mapping, args.submitter)
        if changed:
            save_output(args.output, accum)
            print(
                f"[*] --search-unknown deep Phase-5 applied "
                f"{changed} record update(s)",
                file=sys.stderr,
            )
        else:
            print("[*] --search-unknown deep Phase-5 found no confident updates", file=sys.stderr)
        if not phase5_failed_apks:
            _remove_phase5_deep_state(args.output)
        if args.phase5_deep_re_output:
            tmp = args.phase5_deep_re_output + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(deep_mapping, f, indent=4, ensure_ascii=False)
                f.write("\n")
            os.replace(tmp, args.phase5_deep_re_output)
            print(
                f"[*] wrote deep Phase-5 mapping report to {args.phase5_deep_re_output}",
                file=sys.stderr,
            )

    print(
        f"[*] DONE. Final record count: {len(accum)} (in {args.output})",
        file=sys.stderr,
    )
    upgrade_report = semantic_upgrade_report(pre_session_by_uuid, accum)
    print(
        f"[*] semantic upgrades this run: "
        f"{len(upgrade_report['UUID_name_upgrades'])} UUID_name, "
        f"{len(upgrade_report['company_upgrades'])} company",
        file=sys.stderr,
    )
    if args.semantic_upgrades_output:
        tmp = args.semantic_upgrades_output + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(upgrade_report, f, indent=4, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp, args.semantic_upgrades_output)
        print(
            f"[*] wrote semantic-upgrades report to {args.semantic_upgrades_output}",
            file=sys.stderr,
        )

    # Write the session-output delta if requested. Includes only records
    # whose UUID was NOT in --output at the start of the run — i.e. UUIDs
    # this session first observed. Records the run touched-but-didn't-create
    # (existing UUIDs that gained new android_info_array entries) are NOT
    # included; their full state is already in --output and they pre-date
    # this session.
    if args.session_output:
        session_records = [
            r for r in accum
            if r.get("UUID", "").lower() not in pre_session_uuids
        ]
        # Sort the same way as save_output so the file is diff-friendly.
        session_records.sort(key=lambda r: (len(r.get("UUID", "")), r.get("UUID", "")))
        tmp = args.session_output + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(session_records, f, indent=4, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp, args.session_output)
        print(
            f"[*] wrote {len(session_records)} session-new records to "
            f"{args.session_output} (UUIDs not present in --output before this run)",
            file=sys.stderr,
        )
    if incomplete_managed:
        print(
            f"[!] {incomplete_managed} APK(s) contained managed code that was not fully scanned; "
            f"their checkpoint statuses are retryable. Fix the reported managed-scan cause and rerun.",
            file=sys.stderr,
        )
    if failed_apks:
        print(
            f"[!] {failed_apks} APK(s) failed or were incomplete; their non-ok checkpoint "
            f"statuses are retryable. See the per-APK status above and rerun after fixing the cause.",
            file=sys.stderr,
        )
    if phase5_failed_apks:
        print(
            f"[!] {phase5_failed_apks} deep Phase-5 APK(s) failed or were incomplete; "
            f"their resume entries remain retryable. Fix the reported cause and rerun.",
            file=sys.stderr,
        )
    return 1 if failed_apks or phase5_failed_apks else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
