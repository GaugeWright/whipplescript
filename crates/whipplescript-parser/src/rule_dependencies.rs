//! Canonical activation edges from compiler-derived read/write footprints.
//! A footprint is not complete rule metadata, pacing evidence or admission.
use crate::{fact_flow, IrRuleDependency};

pub struct Footprint<'a> {
    pub name: &'a str,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
}

/// Both lowerers supply every rule's actual activation footprint. This pure
/// join does not validate completeness or reinterpret query-validity edges.
pub fn build(rules: &[Footprint<'_>]) -> Vec<IrRuleDependency> {
    let reads: Vec<Vec<String>> = rules
        .iter()
        .map(|rule| {
            rule.reads
                .iter()
                .map(|read| fact_flow::normalize_read(read))
                .collect()
        })
        .collect();
    let mut dependencies = Vec::new();
    for producer in rules {
        for fact in &producer.writes {
            for (consumer, reads) in rules.iter().zip(&reads) {
                if reads.contains(fact) {
                    dependencies.push(IrRuleDependency {
                        producer: producer.name.into(),
                        consumer: consumer.name.into(),
                        fact: fact.clone(),
                    });
                }
            }
        }
    }
    dependencies.sort_by(|left, right| {
        (&left.producer, &left.consumer, &left.fact).cmp(&(
            &right.producer,
            &right.consumer,
            &right.fact,
        ))
    });
    dependencies
}
