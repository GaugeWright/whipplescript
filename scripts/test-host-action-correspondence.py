"""Break each property scripts/check-host-action-correspondence.py guards, one at a time.

Each case copies the real models, table and every source file the table names
into a scratch root, proves the copy passes, changes exactly one thing and
expects the named failure. Nothing in the checkout is touched.
"""

import importlib.util
import pathlib
import shutil
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "host_action_correspondence", ROOT / "scripts/check-host-action-correspondence.py"
)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class CorrespondenceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = pathlib.Path(directory.name)
        paths = {CHECK.TABLE}
        for model in CHECK.MODELS:
            paths.add(f"models/maude/{model}")
            paths.add(f"models/maude/tests/{model}")
        for line in (ROOT / CHECK.TABLE).read_text().splitlines():
            if line.startswith("#") or line.startswith("model\t") or not line.strip():
                continue
            cells = line.split("\t")
            for item in (cells[4] + "," + cells[5]).split(","):
                if "#" in item:
                    paths.add(item.split("#", 1)[0])
        for path in paths:
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
        self.assertEqual(CHECK.check(self.root), [])

    def edit(self, path, old, new, count=1):
        file = self.root / path
        text = file.read_text()
        self.assertIn(old, text)
        file.write_text(text.replace(old, new, count))

    def assertFails(self, fragment):
        problems = CHECK.check(self.root)
        self.assertTrue(any(fragment in p for p in problems), problems)

    def test_a_new_rule_without_a_row_fails(self):
        self.edit(
            "models/maude/host-actions.maude",
            "  rl [remote-apply]",
            "  rl [unmapped-step] : invoke(K) => none .\n  rl [remote-apply]",
        )
        self.assertFails("[unmapped-step]: no row")

    def test_a_row_for_a_removed_rule_fails(self):
        self.edit(
            "models/maude/host-action-recovery.maude",
            "rl [refuse-compensation]",
            "rl [refuse-compensation-renamed]",
        )
        self.assertFails("[refuse-compensation]: the row names a rule the model no longer has")

    def test_a_control_no_search_exercises_fails(self):
        self.edit(
            "models/maude/tests/host-action-recovery.maude",
            "in WHIPPLESCRIPT-HOST-ACTION-FILE-CEILING-MISSING :",
            "in WHIPPLESCRIPT-HOST-ACTION-FILE-CEILING :",
        )
        self.assertFails("WHIPPLESCRIPT-HOST-ACTION-FILE-CEILING-MISSING is exercised by no search")

    def test_a_vanished_implementation_fails(self):
        self.edit(
            "crates/whipplescript-kernel/src/save_reconciliation.rs",
            "fn require_committed_target(",
            "fn require_committed_target_renamed(",
        )
        self.assertFails("no longer defines fn require_committed_target")

    def test_a_vanished_regression_fails(self):
        self.edit(
            "crates/whipplescript-store/src/effect_recovery.rs",
            "fn late_evidence_is_retained_and_contradiction_stops_recovery(",
            "fn late_evidence_renamed(",
        )
        self.assertFails("regression late_evidence_is_retained_and_contradiction_stops_recovery is no longer")

    def test_an_ignored_or_helper_regression_fails(self):
        self.edit(
            "crates/whipplescript-store/src/host_actions.rs",
            "    #[test]\n    fn host_action_native_rolls_back_at_each_admission_boundary(",
            "    #[test]\n    #[ignore]\n    fn host_action_native_rolls_back_at_each_admission_boundary(",
        )
        self.assertFails("host_action_native_rolls_back_at_each_admission_boundary in")

    def test_a_forbids_row_in_a_base_module_fails(self):
        self.edit(CHECK.TABLE, "\tadmit\trealizes\t", "\tadmit\tforbids\t")
        self.assertFails("role forbids disagrees with its module")

    def test_a_row_without_a_regression_fails(self):
        table = self.root / CHECK.TABLE
        lines = table.read_text().splitlines()
        for index, line in enumerate(lines):
            if "\tbypass-auth\t" in line:
                cells = line.split("\t")
                cells[5] = "-"
                lines[index] = "\t".join(cells)
        table.write_text("\n".join(lines) + "\n")
        self.assertFails("[bypass-auth]: names no regression")


if __name__ == "__main__":
    unittest.main()
