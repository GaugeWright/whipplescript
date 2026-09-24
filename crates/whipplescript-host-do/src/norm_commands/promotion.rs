//! The hosted promote door (norm-plane §5): `whip stream promote` for a
//! workspace object, gated on the deployment's own planning inputs.
//!
//! The mainline gate evaluates exactly what `/host/norm/impacts` would plan:
//! the object's ledger under deployment trust, its runtime journal, its cuts,
//! and the deployment's planning roles, protected runtime and verified image.
//! None of them comes from the request, which names only the stream, a stable
//! promotion identity, and the requester's reservation tokens.
use super::impact::Deployment;
use super::HostedNormTrust;
use crate::do_store::{DoSql, DoSqliteStore};
use serde::Deserialize;
use whipplescript_kernel::effect_handlers::{
    run_reserved_boundary_promotion_generic, BoundaryRunOutcome, PromoteDoorRequest,
    SingleWriterSerialization,
};
use whipplescript_kernel::norm_admission::{AdmissionDoor, AdmissionHost, NormMainlineAdmission};
use whipplescript_kernel::norm_execution_policy::ProtectedPythonPolicy;
use whipplescript_kernel::norm_planning::PlanningConfiguration;
use whipplescript_kernel::norm_runner::PythonRuntime;
use whipplescript_store::branches::MAINLINE_BRANCH_ID;

const PROTOCOL: &str = "whipplescript.norm.promotion/v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    command: Promotion,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Promotion {
    stream: String,
    /// The caller's stable identity for this promotion: its reservation,
    /// proposed cut and time coordinate derive from it, so a retry after a
    /// lost response replays the same promotion rather than minting another.
    promotion: String,
    #[serde(default)]
    tokens: Vec<String>,
}

/// Promote a stream onto the object's mainline through its gate. A refusal is
/// the structured answer `whip stream promote` prints; an error is a request
/// or installation this door could not evaluate at all.
pub fn execute_installed_hosted_norm_promotion<Sql: DoSql + Clone>(
    sql: &Sql,
    trust: &str,
    command: &str,
    deployment: &str,
) -> Result<String, String> {
    let deployment = Deployment::parse(deployment)?;
    let installed = deployment.installed()?;
    let request: Request = serde_json::from_str(command).map_err(|e| e.to_string())?;
    if request.protocol != PROTOCOL {
        return Err("unsupported norm promotion protocol".into());
    }
    let planning = PlanningConfiguration::parse(&deployment.planning)?;
    let policy = ProtectedPythonPolicy::new(&deployment.runtime, &deployment.time_basis)?;
    let trust: HostedNormTrust = serde_json::from_str(trust).map_err(|e| e.to_string())?;
    let verify =
        |selected: &PythonRuntime| installed.validate_for(&deployment.deployed_image, selected);
    let Promotion {
        stream,
        promotion,
        tokens,
    } = request.command;
    trust.with_verifier(|verifier| {
        let ledger = DoSqliteStore::new(sql.clone());
        let runtime = DoSqliteStore::new(sql.clone());
        let mut gate = NormMainlineAdmission::new(
            &ledger,
            Ok(AdmissionHost {
                verifier,
                configuration: &planning,
                runtime: &runtime,
                policy: &policy,
                verify_runtime: &verify,
            }),
            AdmissionDoor::Promote,
            MAINLINE_BRANCH_ID,
        )
        .with_tokens(tokens);
        let mut streams =
            crate::do_workstreams::DoWorkstreams::new(sql.clone()).map_err(|e| format!("{e:?}"))?;
        let mut vcs = crate::do_branches::compose_vcs(sql).map_err(|e| format!("{e:?}"))?;
        let seed = crate::do_store::stable_hash_hex(&format!("promotion|{promotion}"));
        let result = run_reserved_boundary_promotion_generic(
            &mut streams,
            &mut vcs,
            &PromoteDoorRequest {
                stream_id: &stream,
                reservation_id: &format!("promotion-{seed}"),
                proposed_main: &format!("cut-{seed}-promote"),
                at: &format!("promotion:{promotion}"),
                receipt_scope: "durable-object-workspace",
            },
            &mut SingleWriterSerialization,
            &mut gate,
        );
        let result = match result? {
            BoundaryRunOutcome::Promoted { receipt, .. } => {
                serde_json::json!({"promoted": stream, "into": MAINLINE_BRANCH_ID, "receipt": receipt})
            }
            BoundaryRunOutcome::GateRefused(refusal) => serde_json::json!({
                "refused": stream,
                "door": "promote",
                "target": MAINLINE_BRANCH_ID,
                "reason": refusal.reason,
                "detail": refusal.detail,
            }),
            BoundaryRunOutcome::Conflicted { conflicts } => serde_json::json!({
                "conflicted": stream,
                "paths": conflicts.iter().map(|conflict| conflict.path.clone()).collect::<Vec<_>>(),
            }),
            BoundaryRunOutcome::Refused(reason) => {
                serde_json::json!({"refused": stream, "reason": reason})
            }
        };
        serde_json::to_string(&serde_json::json!({"protocol": PROTOCOL, "result": result}))
            .map_err(|e| e.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deployment whose runtime, image binding and deployed image agree.
    fn deployment() -> serde_json::Value {
        let runtime = serde_json::json!({
            "engine": {
                "kind": "cpython3147_wasi",
                "artifact_path": "/opt/reactor.wasm",
                "artifact_sha256": "a".repeat(64),
            },
            "executable": "/usr/local/bin/whip",
            "python_version": "3.14.7",
            "environment": "epoch",
        });
        let image = format!("sha256:{}", "c".repeat(64));
        serde_json::json!({
            "planning": serde_json::json!({"capability": "observer", "roles": []}).to_string(),
            "runtime": runtime.to_string(),
            "deployed_image": image,
            "image_binding": serde_json::json!({
                "protocol": "whipplescript.exec.runtime-image/v1",
                "image_id": image,
                "runtime": runtime,
            })
            .to_string(),
            "time_basis": "hosted-fixture",
        })
    }

    /// The door refuses what it cannot evaluate before it reads anything: an
    /// oversized deployment, and a request in another protocol.
    #[test]
    fn the_hosted_promotion_door_refuses_what_it_cannot_evaluate() {
        let sql = crate::do_store::test_support::RusqliteDoSql::with_store_schema();
        let trust = serde_json::json!({"bindings": [], "creation_grants": []}).to_string();
        let request = |protocol: &str| {
            serde_json::json!({
                "protocol": protocol,
                "command": {"stream": "work", "promotion": "p-1"},
            })
            .to_string()
        };
        let mut oversized = deployment().to_string();
        oversized.push_str(&" ".repeat(131_073 - oversized.len()));
        assert_eq!(
            execute_installed_hosted_norm_promotion(&sql, &trust, &request(PROTOCOL), &oversized),
            Err("hosted impact deployment exceeds 128 KiB".into())
        );
        assert_eq!(
            execute_installed_hosted_norm_promotion(
                &sql,
                &trust,
                &request("whipplescript.norm.impact/v1"),
                &deployment().to_string(),
            ),
            Err("unsupported norm promotion protocol".into())
        );
    }
}
