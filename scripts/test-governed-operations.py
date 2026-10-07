"""Negative controls for the governed-operation inventory (HA-4)."""

import importlib.util
import pathlib
import subprocess
import tempfile
import textwrap
import unittest

SCRIPT = pathlib.Path(__file__).with_name("check-governed-operations.py")
spec = importlib.util.spec_from_file_location("check_governed_operations", SCRIPT)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)

HANDLERS = "crates/whipplescript-kernel/src/effect_handlers.rs"
TABLE = f"""\
external-effect|fresh|{HANDLERS}|run_notify_effect_generic|start_dispatch_observed|1
tool|legacy|{HANDLERS}|run_capability_effect_generic|start_run|1"""
SOURCE = textwrap.dedent(
    """\
    pub fn run_notify_effect_generic(kernel: &mut K) {
        let braces = r#"} } {"#;
        let brace = '}';
        // kernel.start_run( is only a comment
        kernel.start_dispatch_observed(run, effect)?;
    }

    pub fn run_capability_effect_generic(kernel: &mut K) {
        kernel.start_run(RunStart { instance_id })?;
    }

    #[cfg(test)]
    mod tests {
        fn fixture() { kernel.start_run(run); }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[path = "effect_handlers/fixture.rs"]
    pub mod fixture;
    """
)


class GovernedOperationsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.write(HANDLERS, SOURCE)
        # A test-only #[path] module and everything it declares are fixtures.
        self.write(
            "crates/whipplescript-kernel/src/effect_handlers/fixture.rs",
            "fn direct() { kernel.start_run(run); }\n#[path = \"deeper.rs\"]\nmod deeper;\n",
        )
        self.write(
            "crates/whipplescript-kernel/src/effect_handlers/deeper.rs",
            "fn deeper() { kernel.start_dispatch(run); }\n",
        )
        # Store implementations define the primitives; they are not callers.
        self.write(
            "crates/whipplescript-store/src/lib.rs",
            "fn start_dispatch(&mut self) { self.start_run(run) }\n",
        )
        self.write("crates/whipplescript-cli/tests/journey.rs", "fn t() { kernel.start_run(run); }\n")
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        self.assertEqual(self.check(), [])

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def check(self, table=TABLE):
        return inventory.check(self.root, table)

    def test_the_repository_inventory_is_current(self):
        self.assertEqual(inventory.check(), [])

    def test_a_migrated_handler_cannot_slide_back_to_start_run(self):
        self.write(HANDLERS, SOURCE.replace(
            "kernel.start_dispatch_observed(run, effect)?;", "kernel.start_run(run)?;"))
        problems = self.check()
        self.assertIn(
            f"> {HANDLERS}|run_notify_effect_generic|start_run|1: an unclassified run-starting "
            "function; add it to the inventory with its family", problems)
        self.assertTrue(any(p.startswith(f"< {HANDLERS}|run_notify_effect_generic") for p in problems))
        # Reclassifying the row to match does not launder it either.
        relabelled = TABLE.replace(
            "external-effect|fresh|" + HANDLERS + "|run_notify_effect_generic|start_dispatch_observed",
            "external-effect|legacy|" + HANDLERS + "|run_notify_effect_generic|start_run")
        self.assertTrue(any("migrated family `external-effect`" in p for p in self.check(relabelled)))

    def test_a_second_run_start_in_a_migrated_handler_is_refused(self):
        self.write(HANDLERS, SOURCE.replace(
            "kernel.start_dispatch_observed(run, effect)?;",
            "kernel.start_dispatch_observed(run, effect)?;\n    kernel.start_run(retry)?;"))
        self.assertTrue(any("run_notify_effect_generic|start_run|1" in p for p in self.check()))

    def test_a_new_run_starting_function_is_unclassified(self):
        self.write("crates/new-host/src/lib.rs", "pub fn deliver(k: &mut K) { k.start_run(run); }\n")
        self.assertIn(
            "> crates/new-host/src/lib.rs|deliver|start_run|1: an unclassified run-starting "
            "function; add it to the inventory with its family", self.check())

    def test_a_removed_run_start_is_reported(self):
        self.write(HANDLERS, SOURCE.replace("kernel.start_run(RunStart { instance_id })?;", ""))
        self.assertIn(
            f"< {HANDLERS}|run_capability_effect_generic|start_run|1: the tree no longer has this run start",
            self.check())

    def test_not_test_cfg_is_production(self):
        self.write("crates/new-host/src/lib.rs",
                   "#[cfg(not(test))]\nfn live(k: &mut K) { k.start_run(run); }\n")
        self.assertTrue(any("crates/new-host/src/lib.rs|live|start_run|1" in p for p in self.check()))

    def test_a_test_mod_file_is_not_production(self):
        self.write("crates/new-host/src/lib.rs", "#[cfg(test)]\nmod tests;\n")
        self.write("crates/new-host/src/tests.rs", "fn t(k: &mut K) { k.start_run(run); }\n")
        self.assertEqual(self.check(), [])

    def test_unknown_family_and_wrong_status_are_refused(self):
        self.assertTrue(any("unknown family" in p for p in self.check(TABLE.replace("tool|", "gadget|"))))
        self.assertTrue(any("is legacy dispatch, not fresh" in p
                            for p in self.check(TABLE.replace("tool|legacy", "tool|fresh"))))


if __name__ == "__main__":
    unittest.main()
