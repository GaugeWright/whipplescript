//! Building the report from what the orchestrator returned.

use sha2::{Digest, Sha256};
use whipplescript_core::norm_buck2_report::{CaseExecution, CaseStatus, ExecutionKind};

use crate::proto::buck::data::command_execution_kind::Command;
use crate::proto::buck::test::execution_status::Status;
use crate::proto::buck::test::{execution_stream, ExecutionResult2};

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn stream_bytes(stream: &Option<crate::proto::buck::test::ExecutionStream>) -> Vec<u8> {
    match stream.as_ref().and_then(|stream| stream.item.as_ref()) {
        Some(execution_stream::Item::Inline(bytes)) => bytes.clone(),
        None => Vec::new(),
    }
}

fn millis(duration: &Option<prost_types::Duration>) -> u64 {
    duration
        .as_ref()
        .map(|d| {
            let seconds = u64::try_from(d.seconds).unwrap_or(0);
            let nanos = u64::try_from(d.nanos).unwrap_or(0);
            seconds
                .saturating_mul(1000)
                .saturating_add(nanos / 1_000_000)
        })
        .unwrap_or(0)
}

/// The verdict a `whip` adapter case prints: `whip-test: case <name> <pass|fail>`.
pub fn whip_verdict(stdout: &[u8], case: &str) -> Option<CaseStatus> {
    let text = String::from_utf8_lossy(stdout);
    let mut verdict = None;
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("whip-test:") || words.next() != Some("case") {
            continue;
        }
        if words.next() != Some(case) {
            continue;
        }
        verdict = match words.next() {
            Some("pass") => Some(CaseStatus::Pass),
            Some("fail") => Some(CaseStatus::Fail),
            _ => None,
        };
    }
    verdict
}

/// The case names a `whip` adapter listing prints, one per line.
pub fn whip_listing(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

pub struct Observed {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub start_time_ms: u64,
    pub duration_ms: u64,
    pub execution_kind: ExecutionKind,
    pub max_memory_used_bytes: Option<u64>,
}

pub fn observe(result: &ExecutionResult2) -> Observed {
    let (exit_code, timed_out) = match result.status.as_ref().and_then(|s| s.status.as_ref()) {
        Some(Status::Finished(code)) => (Some(*code), false),
        Some(Status::TimedOut(_)) => (None, true),
        None => (None, false),
    };
    let execution_kind = match result
        .execution_details
        .as_ref()
        .and_then(|details| details.execution_kind.as_ref())
        .and_then(|kind| kind.command.as_ref())
    {
        Some(Command::LocalCommand(_)) => ExecutionKind::Local,
        Some(Command::RemoteCommand(_)) => ExecutionKind::Remote,
        Some(Command::OmittedLocalCommand(_)) => ExecutionKind::OmittedLocal,
        Some(Command::WorkerInitCommand(_)) => ExecutionKind::WorkerInit,
        Some(Command::WorkerCommand(_)) => ExecutionKind::Worker,
        None => ExecutionKind::Unknown,
    };
    Observed {
        exit_code,
        timed_out,
        stdout: stream_bytes(&result.stdout),
        stderr: stream_bytes(&result.stderr),
        start_time_ms: millis(&result.start_time),
        duration_ms: millis(&result.execution_time),
        execution_kind,
        max_memory_used_bytes: result.max_memory_used_bytes,
    }
}

impl Observed {
    /// The case's execution record. A verdict line decides the status when
    /// the adapter read one; otherwise the exit code does, and the record
    /// says which.
    pub fn case(&self, case: &str, verdict: Option<CaseStatus>) -> CaseExecution {
        let status = match (verdict, self.timed_out, self.exit_code) {
            (_, true, _) => CaseStatus::Timeout,
            (Some(verdict), false, _) => verdict,
            (None, false, Some(0)) => CaseStatus::Unknown,
            (None, false, Some(_)) => CaseStatus::Fail,
            (None, false, None) => CaseStatus::Unknown,
        };
        CaseExecution {
            case: case.to_owned(),
            status,
            exit_code: self.exit_code,
            verdict_line: verdict.is_some(),
            start_time_ms: self.start_time_ms,
            duration_ms: self.duration_ms,
            execution_kind: self.execution_kind,
            stdout_sha256: sha256_hex(&self.stdout),
            stderr_sha256: sha256_hex(&self.stderr),
            max_memory_used_bytes: self.max_memory_used_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(exit_code: Option<i32>, timed_out: bool) -> Observed {
        Observed {
            exit_code,
            timed_out,
            stdout: Vec::new(),
            stderr: Vec::new(),
            start_time_ms: 1,
            duration_ms: 2,
            execution_kind: ExecutionKind::Local,
            max_memory_used_bytes: None,
        }
    }

    #[test]
    fn a_verdict_line_decides_and_the_exit_code_only_stands_in() {
        let out = b"noise\nwhip-test: case a pass\nwhip-test: case b fail\n";
        assert_eq!(whip_verdict(out, "a"), Some(CaseStatus::Pass));
        assert_eq!(whip_verdict(out, "b"), Some(CaseStatus::Fail));
        assert_eq!(whip_verdict(out, "c"), None);
        // A swallowed failure: the verdict says fail while the process exited 0.
        let swallowed = observed(Some(0), false).case("b", Some(CaseStatus::Fail));
        assert_eq!(swallowed.status, CaseStatus::Fail);
        assert!(swallowed.verdict_line);
        assert_eq!(swallowed.exit_code, Some(0));
        // No verdict and exit 0 is unknown, never pass.
        let silent = observed(Some(0), false).case("c", None);
        assert_eq!(silent.status, CaseStatus::Unknown);
        assert!(!silent.verdict_line);
        assert_eq!(
            observed(Some(3), false).case("c", None).status,
            CaseStatus::Fail
        );
        assert_eq!(
            observed(None, true)
                .case("c", Some(CaseStatus::Pass))
                .status,
            CaseStatus::Timeout
        );
        assert_eq!(whip_listing(b" one \n\ntwo\n"), vec!["one", "two"]);
    }
}
