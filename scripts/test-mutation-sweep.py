"""Cheap scanner/mutator contracts; Rust compilation plants stay in the deep sweep."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import mutation_sweep as sweep


class TypedRefusalTests(unittest.TestCase):
    def test_discovers_only_constructions(self):
        for name in ("Busy", "NotReleased", "ReservationMismatch", "StreamMissing"):
            with self.subTest(name=name):
                self.assertTrue(sweep.variant_is_refusal(f"return Ok(Outcome::{name});"))
                self.assertFalse(sweep.variant_is_refusal(f"Outcome::{name} => false,"))
                self.assertFalse(sweep.variant_is_refusal(f"let Outcome::{name} = value;"))
                self.assertFalse(sweep.variant_is_refusal(f"assert_eq!(value, Outcome::{name});"))
        self.assertTrue(sweep.variant_is_refusal(
            "return Ok(Outcome::Busy { holder_reservation_id });"))
        self.assertFalse(sweep.variant_is_refusal("Outcome::Busy { holder_reservation_id } => {}"))
        self.assertFalse(sweep.variant_is_refusal("Outcome::AlreadyAcknowledged"))

    def test_multiline_patterns_are_not_sites(self):
        for tail in ("=> false,", "| Outcome::NotReleased => false,", "= value;"):
            self.assertEqual(sweep.find_sites(["Outcome::StreamMissing", tail]), [])

    def test_native_only_test_module_is_skipped_without_swallowing_production(self):
        source = ['#[cfg(all(test, feature = "native"))]', 'mod tests {',
                  '    return Ok(Outcome::StreamMissing);', '}',
                  'return Ok(Outcome::NotReleased);']
        self.assertEqual([site.line for site in sweep.find_sites(source)], [5])
        # any(test, ...) and not(test) can carry production; do not hide them.
        for attr in ('#[cfg(any(test, feature = "native"))]', '#[cfg(not(test))]'):
            self.assertEqual(len(sweep.find_sites([attr, 'return Ok(Outcome::NotReleased);'])), 1)

    def test_every_unreachable_plant_is_discovered_and_mutable(self):
        source = sweep.PLANT.splitlines()
        sites = sweep.find_sites(source)
        self.assertEqual(len(sites), 17)
        self.assertEqual(len(sites), sweep.PLANT_COUNT)
        for site in sites:
            with self.subTest(site=site):
                mutation = sweep.apply_mutation(source, site)
                self.assertIsNotNone(mutation)
                self.assertNotEqual(source, mutation)

    def test_a_declared_success_expression_replaces_the_whole_returned_value(self):
        # The shape the bare `MUTATION-SUCCESS` form cannot reach: a unit
        # refusal WRAPPED in another enum, where the first `Ident::Ident` on the
        # line is the wrapper and carries a payload. Substituting a path inside
        # the expression would leave the wrapper's argument list behind, so this
        # form replaces the returned expression entire.
        source = ['let Some(route) = route else {',
                  '    // MUTATION-SUCCESS-EXPR: Outcome::Served { fact: String::new() }',
                  '    return Outcome::Refused(Refusal::UnknownPath);', '};']
        [site] = sweep.find_sites(source)
        mutated = sweep.apply_mutation(source, site)
        self.assertEqual(
            mutated,
            [*source[:2], '    return Outcome::Served { fact: String::new() };', '};'],
        )

    def test_a_declared_success_expression_is_taken_only_from_the_line_above(self):
        # The expression is arbitrary by design, which is exactly why it may
        # never be inferred: it is read from a comment a human wrote directly
        # above the refusal, and nowhere else.
        source = ['// MUTATION-SUCCESS-EXPR: Outcome::Served { fact: String::new() }',
                  'let x = 1;',
                  'return Outcome::Refused(Refusal::UnknownPath);']
        [site] = sweep.find_sites(source)
        # No mutation rather than a distant one: the site reports UNMEASURED,
        # which is the honest answer. Reaching further up the file for a success
        # expression would let a comment written about one refusal silently
        # govern another.
        self.assertIsNone(sweep.apply_mutation(source, site))

    def test_false_success_preserves_a_let_else_return(self):
        source = ['let Some(stream) = stream else {',
                  '    // MUTATION-SUCCESS: Outcome::Acknowledged',
                  '    return Ok(Outcome::StreamMissing);', '};']
        [site] = sweep.find_sites(source)
        mutated = sweep.apply_mutation(source, site)
        self.assertEqual(mutated, [*source[:2], '    return Ok(Outcome::Acknowledged);', '};'])

    def test_false_success_preserves_an_expression_arm(self):
        source = ['if matches {', '    Outcome::AlreadyActive', '} else {',
                  '    // MUTATION-SUCCESS: Outcome::AlreadyActive',
                  '    Outcome::ReservationMismatch', '}']
        [site] = sweep.find_sites(source)
        mutated = sweep.apply_mutation(source, site)
        self.assertEqual(mutated[4], '    Outcome::AlreadyActive')
        self.assertEqual(mutated[:4], source[:4])

    def test_success_annotation_never_injects_a_payload_or_another_type(self):
        for replacement in ('Other::Acknowledged', 'Outcome::StreamMissing',
                            'Outcome::Admitted(stream)', 'panic!()'):
            source = [f'// MUTATION-SUCCESS: {replacement}',
                      'return Ok(Outcome::StreamMissing);']
            [site] = sweep.find_sites(source)
            self.assertIsNone(sweep.apply_mutation(source, site))

    def test_busy_mutation_keeps_the_if_let_binding(self):
        source = ['if let Some(holder_reservation_id) = holder {',
                  '    return Ok(Outcome::Busy { holder_reservation_id });', '}',
                  'Ok(Outcome::Admitted)']
        [site] = sweep.find_sites(source)
        mutated = sweep.apply_mutation(source, site)
        self.assertEqual(mutated[0], source[0])
        self.assertEqual(mutated[1].strip(), 'if false {')
        self.assertIn(source[1], mutated)

    def test_ambiguous_unit_is_a_refusal_only_when_declared(self):
        source = ['// MUTATION-SUCCESS: Outcome::AlreadyArchived',
                  'return Ok(Outcome::BoundaryReserved)']
        self.assertEqual(sweep.find_sites(source[1:]), [])
        [site] = sweep.find_sites(source)
        self.assertEqual(sweep.apply_mutation(source, site)[1],
                         'return Ok(Outcome::AlreadyArchived)')


class CalibrationTests(unittest.TestCase):
    def test_all_seventeen_edits_combine_without_line_offset_interference(self):
        source = ["// original source boundary"] + sweep.PLANT.split("\n")
        sites = sweep.find_sites(source)
        combined = sweep.batch_unreachable_mutations(source, sites, 1)
        # Reverse-position individual application is an independent oracle for
        # the simultaneous edits, including mutations that insert/delete lines.
        sequential = source
        for site in reversed(sites):
            sequential = sweep.apply_mutation(sequential, site)
            self.assertIsNotNone(sequential)
        self.assertEqual(combined, sequential)
        self.assertEqual(combined[0], source[0])
        self.assertEqual(len(sites), 17)

    def test_absent_or_noop_mutation_cannot_calibrate(self):
        source = ["real", "plant"]
        for result in (None, source):
            with self.subTest(result=result), mock.patch.object(sweep, "apply_mutation", return_value=result):
                with self.assertRaisesRegex(ValueError, "no calibration mutation"):
                    sweep.batch_unreachable_mutations(source, [sweep.Site(2, "plant")], 1)

    def test_calibration_cannot_modify_real_source_or_overlap_another_mutation(self):
        source = ["real", "first", "second"]
        with mock.patch.object(sweep, "apply_mutation", return_value=["changed", "first", "second"]):
            with self.assertRaisesRegex(ValueError, "real source"):
                sweep.batch_unreachable_mutations(source, [sweep.Site(2, "plant")], 1)
        with mock.patch.object(sweep, "apply_mutation", return_value=["real", "changed", "second"]):
            with self.assertRaisesRegex(ValueError, "overlap"):
                sweep.batch_unreachable_mutations(source, [sweep.Site(2, "first"), sweep.Site(3, "second")], 1)

    def test_calibration_still_uses_the_actual_target_and_filter_once(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.rs"
            backup = Path(directory) / "original.rs"
            source = "// original, deliberately without a final newline"
            backup.write_text(source)
            observed = []
            def trial(filter_expr):
                observed.append((filter_expr, target.read_text()))
                return sweep.PASSED
            with mock.patch.object(sweep, "run_suite", side_effect=trial), contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(sweep.self_test(str(target), "-p actual-package", str(backup)))
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0][0], "-p actual-package")
            self.assertTrue(observed[0][1].startswith(source + "\n"))
            expected = sweep.batch_unreachable_mutations(
                source.split("\n") + sweep.PLANT.split("\n"),
                sweep.find_sites(source.split("\n") + sweep.PLANT.split("\n")),
                1,
            )
            self.assertEqual(observed[0][1], "\n".join(expected))
            self.assertEqual(backup.read_text(), source)

    def test_bad_discovery_build_failure_or_caught_calibration_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.rs"
            backup = Path(directory) / "original.rs"
            backup.write_text("// original\n")
            with mock.patch.object(sweep, "find_sites", return_value=[]), mock.patch.object(sweep, "run_suite") as trial, contextlib.redirect_stderr(io.StringIO()):
                self.assertFalse(sweep.self_test(str(target), "filter", str(backup)))
                trial.assert_not_called()
            for outcome in (sweep.BUILD_FAILED, sweep.CAUGHT):
                with self.subTest(outcome=outcome), mock.patch.object(sweep, "run_suite", return_value=outcome), contextlib.redirect_stderr(io.StringIO()):
                    self.assertFalse(sweep.self_test(str(target), "filter", str(backup)))

    def test_failed_calibration_restores_the_original_source(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.rs"
            original = "// original bytes\n"
            target.write_text(original)
            args = ["mutation_sweep.py", "--target", str(target), "--filter", "named-test"]
            with mock.patch("sys.argv", args), mock.patch.object(sweep, "run_suite", return_value=sweep.BUILD_FAILED), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(sweep.main(), 1)
            self.assertEqual(target.read_text(), original)
            self.assertFalse(Path(str(target) + ".sweepbak").exists())

    def test_real_refusals_are_still_mutated_one_at_a_time(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.rs"
            backup = Path(directory) / "original.rs"
            original = 'errors.push("first");\nerrors.push("second");'
            backup.write_text(original)
            observed = []
            def trial(_filter):
                observed.append(target.read_text())
                return sweep.PASSED
            with mock.patch.object(sweep, "run_suite", side_effect=trial), contextlib.redirect_stdout(io.StringIO()):
                survivors, unmeasured = sweep.sweep(str(target), "filter", sweep.find_sites(original.split("\n")), str(backup))
            self.assertEqual(len(survivors), 2)
            self.assertEqual(unmeasured, [])
            self.assertEqual(len(observed), 2)
            self.assertTrue(all(value.count("errors.push") == 1 for value in observed))
            self.assertNotEqual(observed[0], observed[1])


if __name__ == '__main__':
    unittest.main()
