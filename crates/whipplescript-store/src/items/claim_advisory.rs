//! Historical concurrent acquisitions, never current lease arbitration.
use super::IssueEvent;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ConcurrentClaimAdvisory {
    pub issue_id: String,
    pub content_id: String,
    pub event_ids: [String; 2],
    pub actors: [String; 2],
}

/// `content_id` is the permanent issue identity, never a clone-local alias.
/// Report pairs only when both complete ancestor sets prove neither acquisition
/// precedes the other. Missing parents cannot establish concurrency. Release,
/// expiry and current ownership are deliberately not inferred from this history.
pub fn concurrent_claim_advisories(
    content_id: &str,
    events: &[IssueEvent],
) -> Vec<ConcurrentClaimAdvisory> {
    let index: BTreeMap<&str, &IssueEvent> = events
        .iter()
        .filter(|e| !e.event_id.is_empty())
        .map(|e| (e.event_id.as_str(), e))
        .collect();
    let mut claims = Vec::new();
    for (&id, event) in &index {
        if event.kind != "claim.acquired" {
            continue;
        }
        let Some(actor) = event
            .payload
            .get("actor")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let mut ancestors = BTreeSet::new();
        let mut pending: Vec<&str> = event.parents.iter().map(String::as_str).collect();
        let mut complete = true;
        while let Some(parent) = pending.pop() {
            if !ancestors.insert(parent) {
                continue;
            }
            let Some(ancestor) = index.get(parent) else {
                complete = false;
                break;
            };
            pending.extend(ancestor.parents.iter().map(String::as_str));
        }
        if complete && !ancestors.contains(id) {
            claims.push((id, actor, ancestors));
        }
    }
    let mut result = Vec::new();
    for (i, (left, actor, ancestors)) in claims.iter().enumerate() {
        for (right, other, parents) in &claims[i + 1..] {
            if !ancestors.contains(right) && !parents.contains(left) {
                result.push(ConcurrentClaimAdvisory {
                    issue_id: content_id.into(),
                    content_id: content_id.into(),
                    event_ids: [(*left).into(), (*right).into()],
                    actors: [(*actor).into(), (*other).into()],
                });
            }
        }
    }
    result
}
