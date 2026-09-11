"""Exercise the governed-door inventory in an isolated Git working tree."""

import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("check-governed-doors.sh")


class GovernedDoorsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts/check-governed-doors.sh")
        # Materialize the declared inventory, so each negative fixture changes
        # just one property of an otherwise accepted tree. No product files or
        # index entries in the developer's checkout are touched.
        for name in ("PINNED", "DISPATCH_PINNED"):
            table = re.search(rf'^{name}="\\\n(.*?)"', SCRIPT.read_text(), re.M | re.S)
            self.assertIsNotNone(table)
            for entry in table.group(1).splitlines():
                filename, method, count = entry.split("|")
                path = self.root / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a") as output:
                    output.write(f"store.{method}();\n" * int(count))
        self.git("init", "-q")
        self.git("add", ".")
        self.assertEqual(self.check().returncode, 0)

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)

    def check(self):
        return subprocess.run(
            ["bash", "scripts/check-governed-doors.sh"],
            cwd=self.root, capture_output=True, text=True,
        )

    def test_new_untracked_calls_are_rejected_before_staging(self):
        path = self.root / "crates/new-host/src/lib.rs"
        path.parent.mkdir(parents=True)
        for method in ("admit_host_action", "run_selective_verb_generic"):
            with self.subTest(method=method):
                path.write_text(f"store.{method}();\n")
                result = self.check()
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"> crates/new-host/src/lib.rs|{method}|1", result.stderr)

    def test_removed_pinned_call_is_rejected(self):
        path = self.root / "crates/whipplescript-store/src/native_stores.rs"
        path.write_text("")
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("< crates/whipplescript-store/src/native_stores.rs|admit_host_action|1", result.stderr)

    def test_ignored_build_output_is_excluded(self):
        (self.root / ".gitignore").write_text("/crates/generated/\n")
        path = self.root / "crates/generated/output.rs"
        path.parent.mkdir()
        path.write_text("store.admit_host_action();\nrun_selective_verb_generic();\n")
        self.assertEqual(self.check().returncode, 0)


if __name__ == "__main__":
    unittest.main()
