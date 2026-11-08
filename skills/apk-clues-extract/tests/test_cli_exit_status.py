import contextlib
import importlib
import io
import json
from concurrent.futures import Future
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
extractor = importlib.import_module("extract_clues")


class RaisingExecutor:
    """Process-pool stand-in that surfaces a worker exception immediately."""

    def __init__(self, max_workers):
        self.max_workers = max_workers

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def submit(self, *args, **kwargs):
        future = Future()
        future.set_exception(RuntimeError("worker crashed"))
        return future


class CliExitStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="extract-cli-status-")
        self.root = Path(self.tmp.name)
        self.apk = self.root / "sample.apk"
        self.apk.write_bytes(b"synthetic APK bytes for checkpoint hashing")
        self.output = self.root / "clues.json"

    def tearDown(self):
        self.tmp.cleanup()

    def invoke_main(self, status=None, *, parallel=1, process_exception=False):
        argv = [
            str(self.apk), "--output", str(self.output), "--parallel", str(parallel),
            "--member-uuids-yaml", "", "--curated-clues", "",
            "--progress-interval", "0",
        ]
        process_patch = patch.object(
            extractor, "process_one_apk",
            return_value=(status, []),
        )
        if process_exception:
            future_patch = patch("concurrent.futures.ProcessPoolExecutor", RaisingExecutor)
        else:
            future_patch = contextlib.nullcontext()
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(extractor, "find_aapt", return_value="/fake/aapt"))
            stack.enter_context(patch.object(extractor, "find_jadx", return_value="/fake/jadx"))
            stack.enter_context(patch.object(extractor, "load_member_uuids", return_value={}))
            stack.enter_context(patch.object(extractor, "load_curated_clues_uuids", return_value=set()))
            process_mock = stack.enter_context(process_patch)
            stack.enter_context(future_patch)
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            result = extractor.main(argv)
        return result, process_mock

    def checkpoint_status(self):
        checkpoint = self.output.with_suffix(self.output.suffix + ".processed.json")
        data = json.loads(checkpoint.read_text())
        return data[extractor._apk_sha1(str(self.apk))]["status"]

    def test_expected_statuses_exit_successfully(self):
        for status in ("no_bt_perms", "ok:0 company=None managed=absent"):
            with self.subTest(status=status):
                result, _ = self.invoke_main(status)
                self.assertEqual(result, 0)

    def test_per_apk_failures_exit_nonzero(self):
        failures = (
            "aapt_failed",
            "jadx_failed_or_timeout managed=absent",
            "managed_incomplete:error:ilspycmd missing dex=0",
            "exception:RuntimeError:scan failed",
        )
        for status in failures:
            with self.subTest(status=status):
                result, _ = self.invoke_main(status)
                self.assertEqual(result, 1)
                self.assertEqual(self.checkpoint_status(), status)

    def test_unhandled_parallel_worker_exception_exits_nonzero(self):
        result, _ = self.invoke_main(parallel=2, process_exception=True)
        self.assertEqual(result, 1)
        self.assertTrue(self.checkpoint_status().startswith("exception:RuntimeError:worker crashed"))

    def test_deep_phase5_failure_exits_nonzero_and_remains_retryable(self):
        state_path = Path(str(self.output) + ".phase5_deep.jsonl")
        record = {
            "UUID": "12345678-1234-5678-1234-567812345678",
            "UUID_name": "Unknown",
            "android_info_array": [{"package_path": str(self.apk)}],
        }
        argv = ["--output", str(self.output), "--phase5-deep-re"]

        def run_phase5(status):
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(extractor, "find_aapt", return_value="/fake/aapt"))
                stack.enter_context(patch.object(extractor, "find_jadx", return_value="/fake/jadx"))
                stack.enter_context(patch.object(extractor, "load_member_uuids", return_value={}))
                stack.enter_context(patch.object(extractor, "load_curated_clues_uuids", return_value=set()))
                stack.enter_context(patch.object(extractor, "load_existing", return_value=[record]))
                phase5_mock = stack.enter_context(patch.object(
                    extractor, "phase5_deep_re_apk", return_value=(status, {}),
                ))
                stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                result = extractor.main(argv)
            return result, phase5_mock

        result, phase5_mock = run_phase5("jadx_failed_or_timeout")
        self.assertEqual(result, 1)
        phase5_mock.assert_called_once()
        first_entry = json.loads(state_path.read_text().splitlines()[0])
        self.assertEqual(first_entry["status"], "jadx_failed_or_timeout")

        result, phase5_mock = run_phase5("ok:0 deep-name candidates")
        self.assertEqual(result, 0)
        phase5_mock.assert_called_once()
        self.assertFalse(state_path.exists())

    def test_failed_checkpoint_retries_and_success_checkpoint_skips(self):
        result, process_mock = self.invoke_main("aapt_failed")
        self.assertEqual(result, 1)
        process_mock.assert_called_once()

        result, process_mock = self.invoke_main("ok:0 company=None managed=absent")
        self.assertEqual(result, 0)
        process_mock.assert_called_once()

        result, process_mock = self.invoke_main("should not be reached")
        self.assertEqual(result, 0)
        process_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
