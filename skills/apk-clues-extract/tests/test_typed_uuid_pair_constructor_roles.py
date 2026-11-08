"""Regression tests for source-typed service/characteristic UUID pair wrappers."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_clues as extractor  # noqa: E402


SERVICE = "f2010001-1234-5678-9abc-def012345678"
WRITE = "f2010002-1234-5678-9abc-def012345678"
NOTIFY = "f2010003-1234-5678-9abc-def012345678"


class TypedUuidPairConstructorRoleTests(unittest.TestCase):
    @staticmethod
    def write_source(root: Path, relative: str, text: str) -> None:
        path = root / "sources" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    @staticmethod
    def pair_wrapper(class_name: str = "ThingUUID") -> str:
        return f'''package sdk.connect;
import java.util.UUID;
public class ConnectOptions {{
    public static class {class_name} {{
        public UUID character;
        public UUID service;
        public {class_name}(UUID uuid, UUID uuid2) {{
            this.service = uuid;
            this.character = uuid2;
        }}
        public {class_name}(UUID uuid, UUID uuid2, boolean force) {{
            this.service = uuid;
            this.character = uuid2;
        }}
    }}
}}
'''

    @staticmethod
    def protocol_source(extra: str = "") -> str:
        return f'''package sdk.protocol;
import java.util.UUID;
class Protocol {{
    UUID SERVER_UUID = UUID.fromString("{SERVICE}");
    UUID WRITE_UUID = UUID.fromString("{WRITE}");
    UUID NOTIFY_UUID = UUID.fromString("{NOTIFY}");
    void connect() {{
        Object write = new ConnectOptions.ThingUUID(this.SERVER_UUID, this.WRITE_UUID);
        Object notify = new ConnectOptions.ThingUUID(this.SERVER_UUID, this.NOTIFY_UUID);
        {extra}
    }}
}}
'''

    def test_cross_file_typed_pair_positions_classify_service_write_and_notify(self):
        with tempfile.TemporaryDirectory(prefix="typed-uuid-pair-") as tmp:
            root = Path(tmp)
            self.write_source(root, "sdk/connect/ConnectOptions.java", self.pair_wrapper())
            self.write_source(root, "sdk/protocol/Protocol.java", self.protocol_source())
            found = extractor.scan_jadx_output(str(root))

        self.assertEqual(found[SERVICE]["classification"], "GATT Service")
        self.assertEqual(found[WRITE]["classification"], "GATT Characteristic")
        self.assertEqual(found[NOTIFY]["classification"], "GATT Characteristic")
        self.assertTrue(found[WRITE]["classification_source"].startswith("constructor-pair:"))
        self.assertTrue(found[NOTIFY]["classification_source"].startswith("constructor-pair:"))

    def test_direct_gatt_usage_remains_stronger_than_pair_position(self):
        protocol = self.protocol_source(
            "BluetoothGatt gatt = null; gatt.getService(WRITE_UUID);"
        ).replace("import java.util.UUID;", "import java.util.UUID;\nimport android.bluetooth.BluetoothGatt;")
        with tempfile.TemporaryDirectory(prefix="typed-uuid-pair-direct-") as tmp:
            root = Path(tmp)
            self.write_source(root, "sdk/connect/ConnectOptions.java", self.pair_wrapper())
            self.write_source(root, "sdk/protocol/Protocol.java", protocol)
            found = extractor.scan_jadx_output(str(root))
        self.assertEqual(found[WRITE]["classification"], "GATT Service")
        self.assertTrue(found[WRITE]["classification_source"].startswith(
            ("usage:getService", "cross-file usage:getService")
        ))

    def test_untyped_pair_constructor_is_not_inferred(self):
        source = self.pair_wrapper().replace(
            "ThingUUID(UUID uuid, UUID uuid2)",
            "ThingUUID(Object uuid, Object uuid2)",
        ).replace(
            "this.service = uuid;\n            this.character = uuid2;",
            "if (uuid instanceof UUID) this.service = (UUID) uuid;\n            if (uuid2 instanceof UUID) this.character = (UUID) uuid2;",
            1,
        )
        roles = extractor._typed_uuid_pair_constructor_roles(source)
        self.assertNotIn(("ThingUUID", 2), roles)

    def test_same_name_constructor_collision_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="typed-uuid-pair-collision-") as tmp:
            root = Path(tmp)
            first = self.pair_wrapper("Pair")
            second = self.pair_wrapper("Pair").replace("package sdk.connect;", "package other.connect;")
            self.write_source(root, "sdk/connect/ConnectOptions.java", first)
            self.write_source(root, "other/connect/ConnectOptions.java", second)
            self.write_source(root, "sdk/protocol/Protocol.java", self.protocol_source().replace("ThingUUID", "Pair"))
            found = extractor.scan_jadx_output(str(root))
        self.assertNotIn("constructor-pair:", found[WRITE]["classification_source"])
        self.assertNotIn("constructor-pair:", found[NOTIFY]["classification_source"])


if __name__ == "__main__":
    unittest.main()
