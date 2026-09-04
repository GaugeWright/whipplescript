"""Cheap scanner/mutator contracts; Rust compilation plants stay in the deep sweep."""
import unittest

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
        self.assertEqual(len(sites), 16)
        self.assertEqual(len(sites), sweep.PLANT_COUNT)
        for site in sites:
            with self.subTest(site=site):
                mutation = sweep.apply_mutation(source, site)
                self.assertIsNotNone(mutation)
                self.assertNotEqual(source, mutation)

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


if __name__ == '__main__':
    unittest.main()
