import importlib
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
fixed = importlib.import_module("extract_clues")


FAKE_JADX = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import signal
import sys
import time

scenario = sys.argv[-1]
out = Path(sys.argv[sys.argv.index("-d") + 1])
if scenario != "clean-no-sources":
    sources = out / "sources"
    sources.mkdir(parents=True, exist_ok=True)
    (sources / "Partial.java").write_text("class Partial {}\\n")

if scenario == "partial":
    print("ERROR - finished with errors, count: 1")
    raise SystemExit(3)
if scenario == "oom":
    print("Terminating due to java.lang.OutOfMemoryError: Java heap space")
    raise SystemExit(3)
if scenario == "oom-after-marker":
    print("ERROR - finished with errors, count: 1")
    print("Terminating due to java.lang.OutOfMemoryError: Java heap space")
    raise SystemExit(3)
if scenario == "error-no-marker":
    print("ERROR - decompilation failed")
    raise SystemExit(3)
if scenario == "aborted":
    raise SystemExit(143)
if scenario == "killed":
    os.kill(os.getpid(), signal.SIGKILL)
if scenario == "timeout":
    time.sleep(5)
'''


class RunJadxStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="run-jadx-test-")
        root = Path(self.tmp.name)
        self.jadx = root / "fake-jadx"
        self.jadx.write_text(FAKE_JADX)
        self.jadx.chmod(0o755)
        self.root = root

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, module, scenario, timeout=2):
        out_dir = self.root / f"{module.__name__}-{scenario}"
        out_dir.mkdir()
        return module.run_jadx(str(self.jadx), scenario, str(out_dir), timeout)

    def test_clean_exit_succeeds(self):
        self.assertTrue(self.call(fixed, "clean"))

    def test_jadx_3_with_completion_marker_preserves_partial_output(self):
        self.assertTrue(self.call(fixed, "partial"))

    def test_oom_is_rejected_even_with_sources_and_completion_marker(self):
        self.assertFalse(self.call(fixed, "oom"))
        self.assertFalse(self.call(fixed, "oom-after-marker"))

    def test_nonzero_without_completed_partial_marker_is_rejected(self):
        self.assertFalse(self.call(fixed, "error-no-marker"))

    def test_aborted_exit_is_rejected_even_with_sources(self):
        self.assertFalse(self.call(fixed, "aborted"))

    def test_signal_killed_exit_is_rejected_even_with_sources(self):
        self.assertFalse(self.call(fixed, "killed"))

    def test_timeout_is_rejected_even_with_sources(self):
        self.assertFalse(self.call(fixed, "timeout", timeout=0.15))

    def test_zero_exit_without_sources_is_rejected(self):
        self.assertFalse(self.call(fixed, "clean-no-sources"))



if __name__ == "__main__":
    unittest.main(verbosity=2)
