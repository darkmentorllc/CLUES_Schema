import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


class Shard01NonGattHintTests(unittest.TestCase):
    def scan(self, source: str) -> dict[str, dict]:
        with tempfile.TemporaryDirectory(prefix="clues-shard01-fp-") as tmp:
            path = Path(tmp) / "Synthetic.java"
            path.write_text(source, encoding="utf-8")
            return extractor.scan_one_file(str(path))

    def test_onesignal_app_and_misspelled_channel_ids_are_filtered(self):
        app_id = "89785e84-3330-4e07-b216-be05b666c212"
        channel_id = "7641ca74-3235-40d5-9394-bee29349b247"
        source = f'''package com.apporioinfolabs.multiserviceoperator.developer;
final class NotificationPoster {{
    private String ONE_SIGNAL_CHNNEL_ID = "{channel_id}";
    private String ONE_SIGNAL_APP_ID = "{app_id}";
}}
'''
        found = self.scan(source)
        self.assertNotIn(app_id, found)
        self.assertNotIn(channel_id, found)
        self.assertNotIn(app_id, extractor.KNOWN_NON_BLE_UUIDS)
        self.assertNotIn(channel_id, extractor.KNOWN_NON_BLE_UUIDS)

    def test_onesignal_compact_spelling_remains_filtered(self):
        app_id = "ae30e7f9-04dc-40bb-8e43-a06d05f75b45"
        source = f'''package com.example.settings;
final class PushSettings {{
    private static final String KLIPSCH_ONESIGNAL_APP_ID = "{app_id}";
}}
'''
        self.assertNotIn(app_id, self.scan(source))

    def test_scoped_shard01_client_ids_are_filtered(self):
        cases = [
            (
                "com.microsoft.identity.common.adal.internal",
                "Broker",
                "WEBCP_CLIENT_ID",
                "74bcdadc-2fdc-4bb3-8459-76d06952a0e9",
            ),
            (
                "com.ce.android.brand.havajava",
                "HavaJavaProperties",
                "CLIENT_ID",
                "8364a024-4051-46e3-8428-86d6d28bcec6",
            ),
            (
                "zendesk.android.internal.frontendevents",
                "FrontendEventsRepository",
                "CLIENT_ID",
                "383f2407-53f9-475b-87bd-6d2f1ce12105",
            ),
            (
                "zendesk.analyticskit.android.model",
                "AnalyticsSettings",
                "CLIENT_ID",
                "383f2407-53f9-475b-87bd-6d2f1ce12105",
            ),
            (
                "com.zebra.sdk.comm.internal",
                "BluetoothUuids",
                "STATUS_CHANNEL_ID",
                "aeb33570-0b7b-11e3-8ffd-0800200c9a66",
            ),
        ]
        for package, class_name, field, value in cases:
            with self.subTest(package=package, field=field):
                source = f'''package {package};
final class {class_name} {{
    private static final String {field} = "{value}";
}}
'''
                self.assertNotIn(value, self.scan(source))
                self.assertNotIn(value, extractor.KNOWN_NON_BLE_UUIDS)

    def test_zendesk_repeated_analytics_client_id_literal_is_scoped_to_declaring_class(self):
        client_id = "383f2407-53f9-475b-87bd-6d2f1ce12105"
        source = f'''package zendesk.android.internal.frontendevents;
final class FrontendEventsRepository {{
    private static final String CLIENT_ID = "{client_id}";
    void sendEvent() {{ api.sendPageViewEvent("{client_id}"); }}
}}
'''
        self.assertNotIn(client_id, self.scan(source))
        self.assertNotIn(client_id, extractor.KNOWN_NON_BLE_UUIDS)

    def test_same_client_id_value_is_not_globally_dropped(self):
        client_id = "383f2407-53f9-475b-87bd-6d2f1ce12105"
        source = f'''package com.example.other;
final class OtherConfig {{
    private static final String CLIENT_ID = "{client_id}";
}}
'''
        self.assertIn(client_id, self.scan(source))
        self.assertNotIn(client_id, extractor.KNOWN_NON_BLE_UUIDS)

    def test_antlr_atn_serialization_constants_filtered_via_semantic_aliases(self):
        values = {
            "33761b2d-78bb-4a43-8b0b-4f5bee8aacf3": "BASE_SERIALIZED_UUID",
            "1da0c57d-6c06-438a-9b27-10bcb3ce0f61": "ADDED_PRECEDENCE_TRANSITIONS",
            "aadb8d7e-aeef-4415-ad2b-8204d6cf042e": "ADDED_LEXER_ACTIONS",
        }
        source = '''package org.antlr.v4.runtime.atn;
import java.util.UUID;
final class ATNDeserializer {
    private static final UUID BASE_SERIALIZED_UUID;
    private static final UUID ADDED_PRECEDENCE_TRANSITIONS;
    private static final UUID ADDED_LEXER_ACTIONS;
    private static final UUID SERIALIZED_UUID;
    static {
        UUID uuidFromString = UUID.fromString("33761B2D-78BB-4A43-8B0B-4F5BEE8AACF3");
        BASE_SERIALIZED_UUID = uuidFromString;
        UUID uuidFromString2 = UUID.fromString("1DA0C57D-6C06-438A-9B27-10BCB3CE0F61");
        ADDED_PRECEDENCE_TRANSITIONS = uuidFromString2;
        UUID uuidFromString3 = UUID.fromString("AADB8D7E-AEEF-4415-AD2B-8204D6CF042E");
        ADDED_LEXER_ACTIONS = uuidFromString3;
        SERIALIZED_UUID = uuidFromString3;
    }
}
'''
        found = self.scan(source)
        for value in values:
            with self.subTest(uuid=value):
                self.assertNotIn(value, found)
                self.assertNotIn(value, extractor.KNOWN_NON_BLE_UUIDS)

    def test_onesignal_uuid_survives_explicit_gatt_service_use(self):
        app_id = "89785e84-3330-4e07-b216-be05b666c212"
        source = f'''package com.example.ble;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
final class BleConfig {{
    private static final String ONE_SIGNAL_APP_ID = "{app_id}";
    BluetoothGattService find(BluetoothGatt gatt) {{
        return gatt.getService(UUID.fromString(ONE_SIGNAL_APP_ID));
    }}
}}
'''
        found = self.scan(source)
        self.assertIn(app_id, found)
        self.assertEqual(found[app_id]["classification"], "GATT Service")

    def test_havajava_client_id_survives_explicit_gatt_service_use(self):
        client_id = "8364a024-4051-46e3-8428-86d6d28bcec6"
        source = f'''package com.ce.android.brand.havajava;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
final class HavaJavaProperties {{
    private static final String CLIENT_ID = "{client_id}";
    BluetoothGattService find(BluetoothGatt gatt) {{
        return gatt.getService(UUID.fromString(CLIENT_ID));
    }}
}}
'''
        found = self.scan(source)
        self.assertIn(client_id, found)
        self.assertEqual(found[client_id]["classification"], "GATT Service")

    def test_antlr_uuid_alias_survives_explicit_gatt_service_use(self):
        service_uuid = "1da0c57d-6c06-438a-9b27-10bcb3ce0f61"
        source = f'''package org.antlr.v4.runtime.atn;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
final class ATNDeserializer {{
    private static final UUID ADDED_PRECEDENCE_TRANSITIONS;
    static {{
        UUID uuidFromString = UUID.fromString("33761B2D-78BB-4A43-8B0B-4F5BEE8AACF3");
        BASE_SERIALIZED_UUID = uuidFromString;
        UUID uuidFromString2 = UUID.fromString("{service_uuid}");
        ADDED_PRECEDENCE_TRANSITIONS = uuidFromString2;
        UUID uuidFromString3 = UUID.fromString("AADB8D7E-AEEF-4415-AD2B-8204D6CF042E");
        ADDED_LEXER_ACTIONS = uuidFromString3;
    }}
    BluetoothGattService find(BluetoothGatt gatt) {{
        return gatt.getService(ADDED_PRECEDENCE_TRANSITIONS);
    }}
}}
'''
        found = self.scan(source)
        self.assertIn(service_uuid, found)
        self.assertEqual(found[service_uuid]["classification"], "GATT Service")


if __name__ == "__main__":
    unittest.main()
