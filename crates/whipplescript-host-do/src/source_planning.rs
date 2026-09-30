//! Full-workspace read access must be authenticated by the embedding. Only
//! subject coordinates are request data; deployment inputs establish trust.
use crate::do_store::{DoSql, DoSqliteStore};
use serde::Deserialize;

const PROTOCOL: &str = "whipplescript.source-admission/v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    candidate_witness_digest: String,
    attempt_id: String,
}

/// A query-only embedding over the existing DO journal and VCS. Nothing in
/// the body can choose the ledger, install a method, assert coverage or
/// supply a success certificate. Partial Home capture remains a blocker.
pub fn execute_installed_hosted_source_plan<Sql: DoSql + Clone>(
    sql: &Sql,
    trust: &str,
    command: &str,
    deployment: &str,
) -> Result<String, String> {
    if command.len() > 65_536 {
        return Err("source admission query exceeds 64 KiB".into());
    }
    let request: Request = serde_json::from_str(command).map_err(|error| error.to_string())?;
    if request.protocol != PROTOCOL {
        return Err("unsupported source admission query protocol".into());
    }
    // Match the native query's reproducible selection coordinate. It is no
    // clock or freshness proof and grants no expiry-dependent exception.
    let time_basis = format!(
        "hosted-source-admission/{}",
        request.candidate_witness_digest
    );
    let vcs = crate::do_branches::observe_vcs(sql);
    let ledger = DoSqliteStore::new(sql.clone());
    crate::norm_commands::with_query_host(sql, trust, deployment, &time_basis, |host| {
        let plan = whipplescript_kernel::source_admission::plan(
            &vcs,
            &ledger,
            host,
            &request.candidate_witness_digest,
            &request.attempt_id,
        )?;
        serde_json::to_string(&plan.to_json()).map_err(|error| error.to_string())
    })
}
