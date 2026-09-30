//! Host-neutral holdout partition for regularized improve campaigns. The
//! campaign id is minted before proposer access; a host supplies its pinned
//! scenario roster and cumulative retirement state.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

/// A sealed scenario retires after this many promotion-gate exposures.
pub const WEAR_OUT_AT: i64 = 3;
/// Default sealed fraction and floor, settled by the improve holdout policy.
pub const SEALED_FRACTION: f64 = 0.2;
pub const SEALED_FLOOR: usize = 2;
/// Below four eligible scenarios, sealing two would leave too little open
/// material. The campaign instead runs with an `unheld-out` tag.
pub const MIN_SCENARIOS_FOR_SEALING: usize = 4;

/// Partition an eligible, pinned scenario roster for one campaign. Retired
/// scenarios are absent from both outputs. The ranking preserves the CLI's
/// durable `sha256("{campaign_id}|{scenario_name}")` vector and is independent
/// of input order. Names must be unique in the host's admitted roster.
pub fn seal_scenarios<'a, T>(
    campaign_id: &str,
    scenarios: &'a [T],
    name: impl Fn(&T) -> &str,
    retired: impl Fn(&T) -> bool,
) -> (Vec<&'a T>, Vec<&'a T>, bool) {
    let eligible: Vec<&T> = scenarios
        .iter()
        .filter(|scenario| !retired(scenario))
        .collect();
    if eligible.len() < MIN_SCENARIOS_FOR_SEALING {
        return (eligible, Vec::new(), false);
    }
    let sealed_count = ((eligible.len() as f64 * SEALED_FRACTION).ceil() as usize)
        .max(SEALED_FLOOR)
        .min(eligible.len().saturating_sub(2));
    let mut ranked: Vec<(&T, String)> = eligible
        .iter()
        .map(|scenario| {
            let material = format!("{campaign_id}|{}", name(scenario));
            let digest = Sha256::digest(material.as_bytes());
            let rank = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            (*scenario, rank)
        })
        .collect();
    ranked.sort_by(|a, b| a.1.cmp(&b.1));
    let sealed: Vec<&T> = ranked
        .iter()
        .take(sealed_count)
        .map(|(scenario, _)| *scenario)
        .collect();
    let sealed_names: BTreeSet<&str> = sealed.iter().map(|scenario| name(scenario)).collect();
    let open: Vec<&T> = eligible
        .into_iter()
        .filter(|scenario| !sealed_names.contains(name(scenario)))
        .collect();
    (open, sealed, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct Scenario {
        name: String,
        retired: bool,
    }

    fn partition(scenarios: &[Scenario]) -> (Vec<&Scenario>, Vec<&Scenario>, bool) {
        seal_scenarios(
            "C-1",
            scenarios,
            |scenario| scenario.name.as_str(),
            |scenario| scenario.retired,
        )
    }

    #[test]
    fn small_rosters_are_honestly_unheld_out() {
        let scenarios = (0..3)
            .map(|index| Scenario {
                name: format!("s{index}"),
                retired: false,
            })
            .collect::<Vec<_>>();
        let (open, sealed, engaged) = partition(&scenarios);
        assert!(!engaged);
        assert_eq!(open.len(), 3);
        assert!(sealed.is_empty());
    }

    #[test]
    fn fraction_floor_retirement_and_ranking_are_stable() {
        let mut scenarios = (0..10)
            .map(|index| Scenario {
                name: format!("s{index}"),
                retired: false,
            })
            .collect::<Vec<_>>();
        let (open, sealed, engaged) = partition(&scenarios);
        assert!(engaged);
        assert_eq!(open.len(), 8);
        assert_eq!(sealed.len(), 2);
        let names = sealed
            .iter()
            .map(|scenario| scenario.name.clone())
            .collect::<Vec<_>>();
        assert_eq!(names, ["s7", "s1"]);
        scenarios.reverse();
        let (_, reordered, _) = partition(&scenarios);
        assert_eq!(
            reordered
                .iter()
                .map(|scenario| scenario.name.clone())
                .collect::<Vec<_>>(),
            names
        );
        for scenario in &mut scenarios {
            scenario.retired = scenario.name == names[0];
        }
        let (open, sealed, engaged) = partition(&scenarios);
        assert!(engaged);
        assert_eq!(open.len(), 7);
        assert_eq!(sealed.len(), 2);
        assert!(!open
            .iter()
            .chain(sealed.iter())
            .any(|scenario| scenario.name == names[0]));
    }
}
