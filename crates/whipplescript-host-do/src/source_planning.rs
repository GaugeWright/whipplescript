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
    execute_installed_hosted_source_plan_with_capture(
        sql,
        trust,
        command,
        deployment,
        whipplescript_kernel::source_admission::SourceAdmissionCapture::default(),
    )
}

/// The embedding independently installs owning review and Home readers.
/// Neither is request data; this seam does not create a hosted review store,
/// establish Home coverage or activate an admission route.
pub fn execute_installed_hosted_source_plan_with_capture<Sql: DoSql + Clone>(
    sql: &Sql,
    trust: &str,
    command: &str,
    deployment: &str,
    capture: whipplescript_kernel::source_admission::SourceAdmissionCapture<'_>,
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
        let plan = whipplescript_kernel::source_admission::plan_with_capture(
            &vcs,
            &ledger,
            host,
            &request.candidate_witness_digest,
            &request.attempt_id,
            capture,
        )?;
        serde_json::to_string(&plan.to_json()).map_err(|error| error.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::do_store::test_support::RusqliteDoSql;

    #[test]
    fn oversized_source_query_refuses_before_opening_any_authority_store() {
        let sql = RusqliteDoSql::in_memory();
        let command = format!(
            "{}{}",
            " ".repeat(65_537),
            serde_json::json!({
                "protocol": PROTOCOL,
                "candidate_witness_digest": "retained-candidate",
                "attempt_id": "attempt"
            })
        );
        assert!(serde_json::from_str::<Request>(&command).is_ok());
        assert_eq!(
            execute_installed_hosted_source_plan(&sql, "{}", &command, "{}").unwrap_err(),
            "source admission query exceeds 64 KiB"
        );
        assert!(sql
            .query("SELECT name FROM sqlite_master", &[])
            .unwrap()
            .is_empty());
    }
}
