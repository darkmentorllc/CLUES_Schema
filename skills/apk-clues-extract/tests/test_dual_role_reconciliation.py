import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


class DualRoleReconciliationTests(unittest.TestCase):
    @staticmethod
    def record(uuid: str, role: str, source: str, package_id: str) -> dict:
        name = "SERVICE_UUID" if role == "GATT Service" else "DATA_CHARACTERISTIC"
        return {
            "UUID": uuid,
            "company": "Fixture",
            "UUID_name": name,
            "UUID_purpose": f"Custom profile UUID observed in {package_id}.",
            "UUID_usage_array": [role],
            "evidence_array": [{
                "description": (
                    f"Found in decompiled DEX of {package_id} v1 (versionCode 1), "
                    f"in Java field `{name}`. Classification source: {source}."
                ),
                "submitter": "test",
            }],
            "android_info_array": [{
                "package_id": package_id,
                "version_code": 1,
                "version_name": "1",
                "package_path": f"{package_id}.apk",
                "description": f"Detected; usage '{role}'.",
            }],
        }

    def test_cross_app_direct_service_and_characteristic_roles_are_preserved(self):
        uuid = "ffe5"
        service = self.record(uuid, "GATT Service", "cross-file usage:getService(m)", "app.service")
        characteristic = self.record(
            uuid, "GATT Characteristic",
            "cross-file usage:getCharacteristic(UUID_IBT_BLE_INTERNAL_MODEL)",
            "app.characteristic",
        )
        merged = extractor.merge_records([service], [characteristic])[0]
        self.assertEqual(merged["UUID_usage_array"], ["GATT Service", "GATT Characteristic"])
        self.assertEqual(
            extractor._direct_gatt_roles_in_record(merged),
            {"GATT Service", "GATT Characteristic"},
        )

    def test_source_review_citations_for_same_literal_preserve_both_roles(self):
        uuid = "c9b88775-394a-49cc-a0e9-17d75c91a6a6"
        rec = self.record(uuid, "GATT Characteristic", "usage:getCharacteristic", "te.HoursOfService")
        rec["UUID_usage_array"] = ["GATT Characteristic", "GATT Service"]
        rec["evidence_array"].append({
            "description": (
                "Source review for fixture: The same literal is assigned to "
                "SERVICE_UUID and ECM_UUID; BluetoothGatt.getService(SERVICE_UUID) "
                "and service.getCharacteristic(ECM_UUID) use that same target."
            ),
            "submitter": "reviewer",
        })
        self.assertEqual(
            extractor.reconcile_uuid_usage(rec, rec),
            ["GATT Service", "GATT Characteristic"],
        )

    def test_weak_default_conflict_still_collapses_to_one_role(self):
        uuid = "12345678-1234-5678-1234-567812345678"
        service = self.record(uuid, "GATT Service", "file-level-default", "app.one")
        characteristic = self.record(uuid, "GATT Characteristic", "file-level-default", "app.two")
        result = extractor.reconcile_uuid_usage(service, characteristic)
        self.assertEqual(len(result), 1)
        self.assertIn(result[0], {"GATT Service", "GATT Characteristic"})

    def test_one_direct_role_does_not_preserve_opposing_weak_default(self):
        uuid = "abcdef12-1234-5678-9abc-def012345678"
        service = self.record(uuid, "GATT Service", "file-level-default", "app.one")
        characteristic = self.record(
            uuid, "GATT Characteristic", "usage:getCharacteristic", "app.two"
        )
        result = extractor.reconcile_uuid_usage(service, characteristic)
        self.assertEqual(result, ["GATT Characteristic"])

    def test_one_direct_service_does_not_promote_weak_characteristic_default(self):
        uuid = "abcdef13-1234-5678-9abc-def012345678"
        service = self.record(uuid, "GATT Service", "usage:getService", "app.one")
        characteristic = self.record(uuid, "GATT Characteristic", "file-level-default", "app.two")
        result = extractor.reconcile_uuid_usage(service, characteristic)
        self.assertEqual(result, ["GATT Service"])


if __name__ == "__main__":
    unittest.main()
