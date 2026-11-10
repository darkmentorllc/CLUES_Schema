"""Unknown functions stay distinct from discovery and SDK attribution."""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import apply_sdk_identification as sdk
import extract_clues as ext
import managed_clues as managed

META = {"package_id": "com.example.test", "version_name": "1", "version_code": 1}
UNKNOWN = "The purpose is unknown."


def test_java_and_managed_extraction_keep_role_separate_from_purpose():
    entry = {"classification": "GATT Characteristic", "field_name": "DATA_CHAR_UUID", "declaring_packages": set()}
    record = ext.build_record("f0001234-1111-2222-3333-444455556666", entry, META, "example.apk", "test", "Example")
    assert record["UUID_purpose"] == UNKNOWN
    assert record["UUID_usage_array"] == ["GATT Characteristic"]
    assert record["evidence_array"] and record["android_info_array"]
    managed_record = managed._record("f0001234-1111-2222-3333-444455556666", "DATA_UUID", "GATT Characteristic", "MyAssembly", "Source.cs", META, "example.apk", "test", "direct use")
    assert managed_record["UUID_purpose"] == UNKNOWN
    assert managed_record["UUID_usage_array"] == ["GATT Characteristic"]
    assert managed_record["evidence_array"] and managed_record["android_info_array"]


def test_attribution_changes_never_pollute_functional_purpose(tmp_path):
    records = [{"UUID": "f0001234-1111-2222-3333-444455556666", "company": "Unknown", "UUID_name": "Unknown", "UUID_purpose": "Transfers temperature measurements.", "android_info_array": [{"package_id": "com.alpha.app"}, {"package_id": "com.bravo.app"}, {"package_id": "com.charlie.app"}], "evidence_array": []}]
    assert ext.degrade_shared_sdk_companies(records) == 1
    assert records[0]["UUID_purpose"] == "Transfers temperature measurements."
    data = tmp_path / "data.json"
    mapping = tmp_path / "mapping.json"
    data.write_text(json.dumps(records))
    mapping.write_text(json.dumps({"cluster": {"company": "Vendor", "note": "Vendor SDK", "uuids": [records[0]["UUID"]]}}))
    assert sdk.main([str(data), str(mapping)]) == 0
    assert sdk.main([str(data), str(mapping)]) == 0
    updated = json.loads(data.read_text())[0]
    assert updated["UUID_purpose"] == records[0]["UUID_purpose"]
    assert [ev["description"] for ev in updated["evidence_array"]].count("SDK identification: Vendor SDK.") == 1


def test_purpose_resolution_rejects_role_only_before_writing(tmp_path):
    import apply_uuid_name_resolution as resolution
    data = tmp_path / "data.json"
    mapping = tmp_path / "mapping.json"
    before = json.dumps([{"UUID": "1234", "UUID_name": "Unknown", "UUID_purpose": UNKNOWN}])
    data.write_text(before)
    for bad in ("GATT Characteristic identified in Android app code.",
                "Possible GATT Characteristic; the role remains an extractor inference.",
                "GATT Characteristic and GATT Service identified in Android app code."):
        mapping.write_text(json.dumps({"1234": {"UUID_name": "Device", "UUID_purpose": bad}}))
        assert resolution.main([str(data), str(mapping)]) == 2
        assert data.read_text() == before
    mapping.write_text(json.dumps({"1234": {"UUID_name": "Device", "UUID_purpose": "Reports the sensor temperature."}}))
    assert resolution.main([str(data), str(mapping)]) == 0
    assert json.loads(data.read_text())[0]["UUID_purpose"] == "Reports the sensor temperature."
