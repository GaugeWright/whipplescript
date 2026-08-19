//! Agent harness adapter contract and command-backed harnesses.

use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use serde_json::json;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentTurnRequest {
    pub instance_id: String,
    pub effect_id: String,
    pub run_id: String,
    pub agent: String,
    pub profile: Option<String>,
    pub input_json: String,
    pub skill_names: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderRunStatus {
    Completed,
    Failed,
    TimedOut,
    /// A deliberate cancellation. Distinct from `Failed` so the effect settles
    /// `cancelled` (auto-fail-exempt; observed by `after x cancelled`) — the
    /// brokered/DO path used to collapse this into `Failed`, firing `fails`
    /// arms and losing the cancel semantics.
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderArtifact {
    pub kind: String,
    pub path: String,
    pub content_hash: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderFailure {
    pub provider: String,
    pub adapter: String,
    pub phase: String,
    pub error_kind: String,
    pub message: String,
    pub recoverable: bool,
    pub retry_after: Option<String>,
    pub workspace_id: Option<String>,
    pub provider_session_id: Option<String>,
    pub provider_thread_id: Option<String>,
    pub missing_config_keys: Vec<String>,
    pub raw_json: Option<String>,
}

impl ProviderFailure {
    pub fn new(
        phase: impl Into<String>,
        error_kind: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            provider: String::new(),
            adapter: String::new(),
            phase: phase.into(),
            error_kind: error_kind.into(),
            message: message.into(),
            recoverable: false,
            retry_after: None,
            workspace_id: None,
            provider_session_id: None,
            provider_thread_id: None,
            missing_config_keys: Vec::new(),
            raw_json: None,
        }
    }

    pub fn provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = provider.into();
        self
    }

    pub fn adapter(mut self, adapter: impl Into<String>) -> Self {
        self.adapter = adapter.into();
        self
    }

    pub fn recoverable(mut self, recoverable: bool) -> Self {
        self.recoverable = recoverable;
        self
    }

    pub fn missing_config_keys(mut self, keys: Vec<String>) -> Self {
        self.missing_config_keys = keys;
        self
    }

    pub fn raw_json(mut self, raw_json: impl Into<String>) -> Self {
        self.raw_json = Some(raw_json.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRunResult {
    pub status: ProviderRunStatus,
    pub summary: String,
    pub stdout: String,
    pub stderr: String,
    pub transcript: String,
    pub exit_code: Option<i64>,
    pub usage_json: String,
    pub artifacts: Vec<ProviderArtifact>,
    pub failure: Option<ProviderFailure>,
}

pub trait AgentHarness {
    fn before_launch(&self, _request: &AgentTurnRequest) {}

    fn run(&self, request: AgentTurnRequest) -> ProviderRunResult;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandLaunchPlan {
    pub provider: String,
    pub adapter: String,
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: BTreeMap<String, String>,
    pub required_env: Vec<String>,
    pub required_commands: Vec<String>,
    pub timeout: Option<Duration>,
    pub require_stdout_json: bool,
}

impl CommandLaunchPlan {
    pub fn new(provider: impl Into<String>, executable: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            adapter: "command".to_owned(),
            executable: executable.into(),
            args: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            required_env: Vec::new(),
            required_commands: Vec::new(),
            timeout: None,
            require_stdout_json: false,
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn adapter(mut self, adapter: impl Into<String>) -> Self {
        self.adapter = adapter.into();
        self
    }

    pub fn require_env(mut self, key: impl Into<String>) -> Self {
        self.required_env.push(key.into());
        self
    }

    pub fn require_command(mut self, command: impl Into<String>) -> Self {
        self.required_commands.push(command.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn require_stdout_json(mut self) -> Self {
        self.require_stdout_json = true;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandAgentHarness {
    plan: CommandLaunchPlan,
}

impl CommandAgentHarness {
    pub fn new(plan: CommandLaunchPlan) -> Self {
        Self { plan }
    }

    fn request_payload(&self, request: &AgentTurnRequest) -> String {
        json!({
            "provider": self.plan.provider,
            "instance_id": request.instance_id,
            "effect_id": request.effect_id,
            "run_id": request.run_id,
            "agent": request.agent,
            "profile": request.profile,
            "input": serde_json::from_str::<serde_json::Value>(&request.input_json)
                .unwrap_or_else(|_| serde_json::Value::String(request.input_json.clone())),
            "skills": request.skill_names,
        })
        .to_string()
    }
}

impl AgentHarness for CommandAgentHarness {
    fn run(&self, request: AgentTurnRequest) -> ProviderRunResult {
        let payload = self.request_payload(&request);
        if let Some(result) = self.preflight_failure(&request, &payload) {
            return result;
        }

        let mut command = Command::new(&self.plan.executable);
        command.args(&self.plan.args);
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        if let Some(cwd) = &self.plan.cwd {
            command.current_dir(cwd);
        }
        for (key, value) in &self.plan.env {
            command.env(key, value);
        }
        configure_child_process(&mut command);

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                return command_failure_result(CommandFailure {
                    plan: &self.plan,
                    request: &request,
                    payload: &payload,
                    phase: "provider.launch.failed",
                    error_kind: "spawn_error",
                    summary: format!("failed to launch {}: {error}", self.plan.provider),
                    exit_code: None,
                    stdout: "",
                    stderr: &error.to_string(),
                    recoverable: true,
                    missing_config_keys: Vec::new(),
                });
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            if let Err(error) = stdin.write_all(payload.as_bytes()) {
                return command_failure_result(CommandFailure {
                    plan: &self.plan,
                    request: &request,
                    payload: &payload,
                    phase: "provider.stdin.failed",
                    error_kind: "stdin_write_error",
                    summary: format!("failed to write request to {}: {error}", self.plan.provider),
                    exit_code: None,
                    stdout: "",
                    stderr: &error.to_string(),
                    recoverable: true,
                    missing_config_keys: Vec::new(),
                });
            }
        }

        let output = match wait_with_optional_timeout(child, self.plan.timeout) {
            Ok(WaitOutcome::Completed(output)) => output,
            Ok(WaitOutcome::TimedOut(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                let artifacts = command_output_artifacts(&self.plan, &request, &stdout, &stderr);
                return ProviderRunResult {
                    status: ProviderRunStatus::TimedOut,
                    summary: format!(
                        "{} timed out after {}ms",
                        self.plan.provider,
                        self.plan
                            .timeout
                            .map(|timeout| timeout.as_millis())
                            .unwrap_or(0)
                    ),
                    transcript: command_transcript(
                        &self.plan, &request, &payload, &stdout, &stderr,
                    ),
                    stdout,
                    stderr,
                    exit_code: output.status.code().map(i64::from),
                    usage_json: "{}".to_owned(),
                    artifacts,
                    failure: Some(
                        base_failure(
                            &self.plan,
                            "provider.timeout",
                            "timeout",
                            format!(
                                "{} timed out after {}ms",
                                self.plan.provider,
                                self.plan
                                    .timeout
                                    .map(|timeout| timeout.as_millis())
                                    .unwrap_or(0)
                            ),
                        )
                        .recoverable(true),
                    ),
                };
            }
            Err(error) => {
                return command_failure_result(CommandFailure {
                    plan: &self.plan,
                    request: &request,
                    payload: &payload,
                    phase: "provider.stream.failed",
                    error_kind: "wait_error",
                    summary: format!("failed to wait for {}: {error}", self.plan.provider),
                    exit_code: None,
                    stdout: "",
                    stderr: &error.to_string(),
                    recoverable: true,
                    missing_config_keys: Vec::new(),
                });
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let exit_code = output.status.code().map(i64::from);
        if output.status.success()
            && self.plan.require_stdout_json
            && serde_json::from_str::<serde_json::Value>(&stdout).is_err()
        {
            let summary = format!("{} returned invalid JSON stdout", self.plan.provider);
            return command_failure_result(CommandFailure {
                plan: &self.plan,
                request: &request,
                payload: &payload,
                phase: "provider.result.invalid",
                error_kind: "invalid_stdout_json",
                summary,
                exit_code,
                stdout: &stdout,
                stderr: &stderr,
                recoverable: false,
                missing_config_keys: Vec::new(),
            });
        }
        let status = if output.status.success() {
            ProviderRunStatus::Completed
        } else {
            ProviderRunStatus::Failed
        };
        let summary = if output.status.success() {
            format!("{} completed", self.plan.provider)
        } else {
            format!(
                "{} failed with exit code {:?}",
                self.plan.provider, exit_code
            )
        };
        let transcript = command_transcript(&self.plan, &request, &payload, &stdout, &stderr);
        let artifacts = command_output_artifacts(&self.plan, &request, &stdout, &stderr);
        let failure = (!output.status.success()).then(|| {
            let failure_message = command_failure_message(&summary, &stderr);
            base_failure(
                &self.plan,
                "provider.exit.failed",
                "nonzero_exit",
                failure_message,
            )
            .recoverable(true)
        });

        ProviderRunResult {
            status,
            summary,
            stdout,
            stderr,
            transcript,
            exit_code,
            usage_json: "{}".to_owned(),
            artifacts,
            failure,
        }
    }
}

impl CommandAgentHarness {
    fn preflight_failure(
        &self,
        request: &AgentTurnRequest,
        payload: &str,
    ) -> Option<ProviderRunResult> {
        let missing_env = self
            .plan
            .required_env
            .iter()
            .filter(|key| {
                !self.plan.env.contains_key(key.as_str())
                    && std::env::var_os(key.as_str()).is_none()
            })
            .cloned()
            .collect::<Vec<_>>();
        if !missing_env.is_empty() {
            let summary = format!(
                "{} missing required provider config: {}",
                self.plan.provider,
                missing_env.join(", ")
            );
            return Some(command_failure_result(
                CommandFailure {
                    plan: &self.plan,
                    request,
                    payload,
                    phase: "provider.config.missing",
                    error_kind: "missing_provider_config",
                    summary,
                    exit_code: None,
                    stdout: "",
                    stderr: "",
                    recoverable: true,
                    missing_config_keys: Vec::new(),
                }
                .missing_config_keys(missing_env),
            ));
        }

        for command in &self.plan.required_commands {
            if !command_exists(command) {
                let summary = format!(
                    "{} adapter command not found on PATH: {}",
                    self.plan.provider, command
                );
                return Some(command_failure_result(CommandFailure {
                    plan: &self.plan,
                    request,
                    payload,
                    phase: "adapter.resolve.failed",
                    error_kind: "adapter_command_not_found",
                    summary,
                    exit_code: None,
                    stdout: "",
                    stderr: "",
                    recoverable: true,
                    missing_config_keys: Vec::new(),
                }));
            }
        }

        if let Some(cwd) = &self.plan.cwd {
            if !cwd.is_dir() {
                let summary = format!(
                    "{} workspace cwd is not available: {}",
                    self.plan.provider,
                    cwd.display()
                );
                return Some(command_failure_result(CommandFailure {
                    plan: &self.plan,
                    request,
                    payload,
                    phase: "workspace.prepare.failed",
                    error_kind: "workspace_cwd_missing",
                    summary,
                    exit_code: None,
                    stdout: "",
                    stderr: "",
                    recoverable: true,
                    missing_config_keys: Vec::new(),
                }));
            }
        }

        None
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexAgentHarness {
    inner: CommandAgentHarness,
}

impl CodexAgentHarness {
    pub fn new(plan: CommandLaunchPlan) -> Self {
        Self {
            inner: CommandAgentHarness::new(plan),
        }
    }
}

impl AgentHarness for CodexAgentHarness {
    fn run(&self, request: AgentTurnRequest) -> ProviderRunResult {
        self.inner.run(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudeCodeAgentHarness {
    inner: CommandAgentHarness,
}

impl ClaudeCodeAgentHarness {
    pub fn new(plan: CommandLaunchPlan) -> Self {
        Self {
            inner: CommandAgentHarness::new(plan),
        }
    }
}

impl AgentHarness for ClaudeCodeAgentHarness {
    fn run(&self, request: AgentTurnRequest) -> ProviderRunResult {
        self.inner.run(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MockAgentHarness {
    result: ProviderRunResult,
}

impl MockAgentHarness {
    pub fn completed(summary: impl Into<String>) -> Self {
        Self {
            result: ProviderRunResult {
                status: ProviderRunStatus::Completed,
                summary: summary.into(),
                stdout: "mock stdout\n".to_owned(),
                stderr: String::new(),
                transcript: "mock transcript\n".to_owned(),
                exit_code: Some(0),
                usage_json: r#"{"input_tokens":1,"output_tokens":1}"#.to_owned(),
                artifacts: vec![ProviderArtifact {
                    kind: "transcript".to_owned(),
                    path: "artifacts/mock-transcript.txt".to_owned(),
                    content_hash: Some("mock-transcript-hash".to_owned()),
                    mime_type: Some("text/plain".to_owned()),
                }],
                failure: None,
            },
        }
    }

    pub fn failed(summary: impl Into<String>) -> Self {
        let summary = summary.into();
        Self {
            result: ProviderRunResult {
                status: ProviderRunStatus::Failed,
                summary: summary.clone(),
                stdout: String::new(),
                stderr: "mock failure\n".to_owned(),
                transcript: "mock failed transcript\n".to_owned(),
                exit_code: Some(1),
                usage_json: r#"{"input_tokens":1,"output_tokens":0}"#.to_owned(),
                artifacts: Vec::new(),
                failure: Some(
                    ProviderFailure::new("provider.fixture.failed", "fixture_failure", summary)
                        .provider("mock")
                        .adapter("mock"),
                ),
            },
        }
    }
}

impl AgentHarness for MockAgentHarness {
    fn run(&self, request: AgentTurnRequest) -> ProviderRunResult {
        let mut result = self.result.clone();
        result.transcript.push_str(&format!(
            "agent={} effect={} run={} skills={}\n",
            request.agent,
            request.effect_id,
            request.run_id,
            request.skill_names.join(",")
        ));
        result
    }
}

struct CommandFailure<'a> {
    plan: &'a CommandLaunchPlan,
    request: &'a AgentTurnRequest,
    payload: &'a str,
    phase: &'a str,
    error_kind: &'a str,
    summary: String,
    exit_code: Option<i64>,
    stdout: &'a str,
    stderr: &'a str,
    recoverable: bool,
    missing_config_keys: Vec<String>,
}

impl<'a> CommandFailure<'a> {
    fn missing_config_keys(mut self, missing_config_keys: Vec<String>) -> Self {
        self.missing_config_keys = missing_config_keys;
        self
    }
}

fn command_failure_result(failure: CommandFailure<'_>) -> ProviderRunResult {
    let transcript = command_transcript(
        failure.plan,
        failure.request,
        failure.payload,
        failure.stdout,
        failure.stderr,
    );
    ProviderRunResult {
        status: ProviderRunStatus::Failed,
        summary: failure.summary.clone(),
        stdout: failure.stdout.to_owned(),
        stderr: failure.stderr.to_owned(),
        transcript,
        exit_code: failure.exit_code,
        usage_json: "{}".to_owned(),
        artifacts: command_output_artifacts(
            failure.plan,
            failure.request,
            failure.stdout,
            failure.stderr,
        ),
        failure: Some(
            base_failure(
                failure.plan,
                failure.phase,
                failure.error_kind,
                command_failure_message(&failure.summary, failure.stderr),
            )
            .recoverable(failure.recoverable)
            .missing_config_keys(failure.missing_config_keys),
        ),
    }
}

fn command_failure_message(summary: &str, stderr: &str) -> String {
    let stderr = stderr.trim();
    if stderr.is_empty() || summary.contains(stderr) {
        summary.to_owned()
    } else {
        format!("{summary}: stderr {}", redacted_text_reference(stderr))
    }
}

fn base_failure(
    plan: &CommandLaunchPlan,
    phase: impl Into<String>,
    error_kind: impl Into<String>,
    message: impl Into<String>,
) -> ProviderFailure {
    ProviderFailure::new(phase, error_kind, message)
        .provider(plan.provider.clone())
        .adapter(plan.adapter.clone())
}

enum WaitOutcome {
    Completed(std::process::Output),
    TimedOut(std::process::Output),
}

fn wait_with_optional_timeout(
    mut child: std::process::Child,
    timeout: Option<Duration>,
) -> std::io::Result<WaitOutcome> {
    let Some(timeout) = timeout else {
        return child.wait_with_output().map(WaitOutcome::Completed);
    };
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output().map(WaitOutcome::Completed);
        }
        if Instant::now() >= deadline {
            terminate_process_tree(&mut child);
            return child.wait_with_output().map(WaitOutcome::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn command_exists(command: &str) -> bool {
    let path = PathBuf::from(command);
    if path.components().count() > 1 {
        return command_is_executable(&path);
    }

    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join(command))
                .any(|candidate| command_is_executable(&candidate))
        })
        .unwrap_or(false)
}

fn command_is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        path.metadata()
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg_attr(not(unix), allow(unused_variables))]
fn configure_child_process(command: &mut Command) {
    strip_control_plane_secrets(command);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        command.process_group(0);
    }
}

/// whip's own control-plane secrets that a spawned provider process (the
/// command harness or a stdio sidecar) must never inherit. These authorize
/// the whole control plane / governance signing and are irrelevant to a
/// provider child — leaking them into a process that runs an untrusted
/// model's tool loop (or a PATH-hijacked binary) is a least-privilege
/// violation. Provider API credentials (ANTHROPIC/OPENAI keys) are NOT
/// stripped: a provider child may legitimately need them, and a malicious
/// child would receive them over the protocol regardless. Extend this list
/// when new control-plane secrets are introduced.
pub(crate) const CONTROL_PLANE_SECRET_ENV: &[&str] = &[
    "WHIP_CONTROL_TOKEN",
    "WHIP_EXECUTOR_TOKEN",
    "WHIPPLESCRIPT_GOV_ADMIN",
];

/// Remove whip's control-plane secrets from a child command's inherited
/// environment. Applied to every provider subprocess spawn.
pub fn strip_control_plane_secrets(command: &mut Command) {
    strip_env_vars(command, CONTROL_PLANE_SECRET_ENV);
}

/// Provider API-credential env vars, grouped by family. A provider sidecar
/// only needs its OWN family's credentials, so — least privilege — each spawn
/// strips the OTHER families' keys: the Claude sidecar has no business seeing
/// an OpenAI key, nor the codex app-server an Anthropic key. (The child's own
/// family is left inherited; it may read it directly.) Both are unconditional
/// pub: the external whipplescript-provider-codex / -claude crates strip the
/// other family's key when spawning their sidecar (DR-0024 split).
pub const ANTHROPIC_CREDENTIAL_ENV: &[&str] = &["ANTHROPIC_API_KEY"];
pub const OPENAI_CREDENTIAL_ENV: &[&str] = &["OPENAI_API_KEY"];
pub const XAI_CREDENTIAL_ENV: &[&str] = &["XAI_API_KEY"];

/// Remove the named env vars from a child command's inherited environment.
pub fn strip_env_vars(command: &mut Command, names: &[&str]) {
    for name in names {
        command.env_remove(name);
    }
}

fn terminate_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        send_signal_to_process_group(child.id(), "TERM");
    }
    let _ = child.kill();
    #[cfg(unix)]
    {
        send_signal_to_process_group(child.id(), "KILL");
    }
}

/// Argument vector for signalling a whole process group through `kill(1)`.
///
/// The obvious spelling — `kill -TERM -1234` — is not merely wrong, it is
/// catastrophic. procps-ng's `kill` consumes the leading-dash `-1234` as an
/// *option* rather than as a pid operand, is left with no operands at all,
/// and falls back to signalling pid 0: the CALLER'S OWN PROCESS GROUP. Under
/// `cargo test` on CI that group contains the Actions runner agent, so a
/// provider timeout SIGKILLed the runner mid-suite — no failing test, no
/// panic, just a job that died with exit 143 wherever the timeout tests
/// happened to land.
///
/// `-s <SIGNAL>` keeps the signal out of operand position and `--` ends
/// option parsing, so the negative pgid is read as the process group it names.
/// Both spellings are honoured by procps-ng and by BSD `kill(1)`.
#[cfg(unix)]
fn process_group_signal_args(process_group_id: u32, signal: &str) -> [String; 4] {
    [
        "-s".to_owned(),
        signal.to_owned(),
        "--".to_owned(),
        format!("-{process_group_id}"),
    ]
}

#[cfg(unix)]
fn send_signal_to_process_group(process_group_id: u32, signal: &str) {
    let _ = Command::new("kill")
        .args(process_group_signal_args(process_group_id, signal))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn command_output_artifacts(
    plan: &CommandLaunchPlan,
    request: &AgentTurnRequest,
    stdout: &str,
    stderr: &str,
) -> Vec<ProviderArtifact> {
    let mut artifacts = vec![command_ref_artifact(plan, request, "transcript_ref")];
    if !stdout.is_empty() {
        artifacts.push(command_ref_artifact(plan, request, "stdout_ref"));
    }
    if !stderr.is_empty() {
        artifacts.push(command_ref_artifact(plan, request, "stderr_ref"));
    }
    artifacts
}

fn command_ref_artifact(
    plan: &CommandLaunchPlan,
    request: &AgentTurnRequest,
    kind: &str,
) -> ProviderArtifact {
    ProviderArtifact {
        kind: kind.to_owned(),
        path: format!(
            "provider://{}/runs/{}/{}",
            sanitize_artifact_ref_segment(&plan.provider),
            sanitize_artifact_ref_segment(&request.run_id),
            kind
        ),
        content_hash: None,
        mime_type: Some("text/plain".to_owned()),
    }
}

fn sanitize_artifact_ref_segment(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn command_transcript(
    plan: &CommandLaunchPlan,
    request: &AgentTurnRequest,
    payload: &str,
    stdout: &str,
    stderr: &str,
) -> String {
    format!(
        "provider={}\ncommand={} {}\ninstance={}\neffect={}\nrun={}\nrequest={}\nstdout={}\nstderr={}\n",
        plan.provider,
        plan.executable,
        plan.args.join(" "),
        request.instance_id,
        request.effect_id,
        request.run_id,
        redacted_text_reference(payload),
        redacted_text_reference(stdout),
        redacted_text_reference(stderr),
    )
}

fn redacted_text_reference(text: &str) -> String {
    format!(
        "<redacted bytes={} chars={}>",
        text.len(),
        text.chars().count()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_control_plane_secrets_removes_whip_secrets_but_keeps_others() {
        // A control-plane secret and an unrelated WHIP_-prefixed var both live
        // in this process's environment.
        std::env::set_var("WHIPPLESCRIPT_GOV_ADMIN", "1");
        std::env::set_var("WHIP_KEEP_PROBE_ENVVAR", "retained");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("echo GOV=${WHIPPLESCRIPT_GOV_ADMIN:-absent} KEEP=${WHIP_KEEP_PROBE_ENVVAR:-absent}")
            .stdout(Stdio::piped());
        strip_control_plane_secrets(&mut command);
        let output = command.output().expect("child runs");
        let stdout = String::from_utf8_lossy(&output.stdout);
        // The secret is not inherited; an unrelated var (prefix match would be
        // wrong — the count vars WHIPPLESCRIPT_*_MAX_TOKEN must survive) is.
        assert!(
            stdout.contains("GOV=absent"),
            "gov-admin secret must be stripped: {stdout}"
        );
        assert!(
            stdout.contains("KEEP=retained"),
            "unrelated env must still be inherited: {stdout}"
        );
        std::env::remove_var("WHIPPLESCRIPT_GOV_ADMIN");
        std::env::remove_var("WHIP_KEEP_PROBE_ENVVAR");
    }

    #[test]
    fn strip_env_vars_removes_only_named_keys() {
        // Per-provider scoping: a spawn strips the OTHER family's key while
        // leaving unrelated env intact. Uses test-unique names (race-safe).
        std::env::set_var("WHIP_PROBE_FOREIGN_KEY", "foreign");
        std::env::set_var("WHIP_PROBE_OWN_KEY", "own");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("echo FOREIGN=${WHIP_PROBE_FOREIGN_KEY:-absent} OWN=${WHIP_PROBE_OWN_KEY:-absent}")
            .stdout(Stdio::piped());
        strip_env_vars(&mut command, &["WHIP_PROBE_FOREIGN_KEY"]);
        let output = command.output().expect("child runs");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("FOREIGN=absent"),
            "the named key must be stripped: {stdout}"
        );
        assert!(
            stdout.contains("OWN=own"),
            "an unnamed key must be retained: {stdout}"
        );
        std::env::remove_var("WHIP_PROBE_FOREIGN_KEY");
        std::env::remove_var("WHIP_PROBE_OWN_KEY");
    }

    #[test]
    #[cfg(unix)]
    fn process_group_signal_never_lands_on_the_caller_s_own_group() {
        // A group signal has to name its target in operand position. Written
        // as `kill -TERM -1234`, procps-ng eats `-1234` as an option, finds no
        // operands, and signals pid 0 — the caller's own process group. That
        // is how a provider timeout used to SIGKILL the CI runner agent out
        // from under `cargo test`, so the argv shape is pinned here rather
        // than left to a comment. Asserting the effect instead would mean a
        // regression takes the whole test binary down with it.
        assert_eq!(
            process_group_signal_args(1234, "TERM"),
            ["-s", "TERM", "--", "-1234"],
            "the signal must stay out of operand position and `--` must end \
             option parsing, or `kill` signals this process group"
        );
    }

    #[test]
    fn command_harness_sends_request_to_stdin_and_captures_output() {
        let harness = CommandAgentHarness::new(
            CommandLaunchPlan::new("fixture", "sh")
                .arg("-c")
                .arg("cat; echo err >&2"),
        );

        let result = harness.run(AgentTurnRequest {
            instance_id: "instance-a".to_owned(),
            effect_id: "tell".to_owned(),
            run_id: "run-tell".to_owned(),
            agent: "worker".to_owned(),
            profile: Some("repo-writer".to_owned()),
            input_json: r#"{"prompt":"go"}"#.to_owned(),
            skill_names: vec!["repo-user".to_owned()],
        });

        assert_eq!(result.status, ProviderRunStatus::Completed);
        assert_eq!(result.exit_code, Some(0));
        assert!(result.stdout.contains("\"effect_id\":\"tell\""));
        assert!(result.stderr.contains("err"));
        assert!(result.transcript.contains("provider=fixture"));
        assert!(result.transcript.contains("request=<redacted"));
        assert!(result.transcript.contains("stdout=<redacted"));
        assert!(result.transcript.contains("stderr=<redacted"));
        assert!(!result.transcript.contains("\"effect_id\":\"tell\""));
        assert!(!result.transcript.contains("err\n"));
        assert_eq!(
            result
                .artifacts
                .iter()
                .map(|artifact| artifact.kind.as_str())
                .collect::<Vec<_>>(),
            vec!["transcript_ref", "stdout_ref", "stderr_ref"]
        );
        assert_eq!(
            result.artifacts[0].path,
            "provider://fixture/runs/run-tell/transcript_ref"
        );
        assert!(result.failure.is_none());
    }

    #[test]
    fn command_harness_captures_launch_failure_as_structured_failure() {
        let harness = CommandAgentHarness::new(CommandLaunchPlan::new(
            "fixture",
            "definitely-not-a-command",
        ));

        let result = harness.run(AgentTurnRequest {
            instance_id: "instance-a".to_owned(),
            effect_id: "tell".to_owned(),
            run_id: "run-tell".to_owned(),
            agent: "worker".to_owned(),
            profile: Some("repo-writer".to_owned()),
            input_json: r#"{"prompt":"go"}"#.to_owned(),
            skill_names: Vec::new(),
        });

        let failure = result.failure.expect("failure is structured");
        assert_eq!(result.status, ProviderRunStatus::Failed);
        assert_eq!(failure.phase, "provider.launch.failed");
        assert_eq!(failure.error_kind, "spawn_error");
        assert!(failure.recoverable);
        assert!(result.transcript.contains("definitely-not-a-command"));
    }

    #[test]
    fn command_harness_captures_nonzero_exit_as_structured_failure() {
        let harness = CommandAgentHarness::new(
            CommandLaunchPlan::new("fixture", "sh")
                .arg("-c")
                .arg("cat >/dev/null; echo nope >&2; exit 42"),
        );

        let result = harness.run(AgentTurnRequest {
            instance_id: "instance-a".to_owned(),
            effect_id: "tell".to_owned(),
            run_id: "run-tell".to_owned(),
            agent: "worker".to_owned(),
            profile: Some("repo-writer".to_owned()),
            input_json: r#"{"prompt":"go"}"#.to_owned(),
            skill_names: Vec::new(),
        });

        let failure = result.failure.expect("failure is structured");
        assert_eq!(result.status, ProviderRunStatus::Failed);
        assert_eq!(result.exit_code, Some(42));
        assert_eq!(failure.phase, "provider.exit.failed");
        assert_eq!(failure.error_kind, "nonzero_exit");
        assert!(result.stderr.contains("nope"));
    }

    #[test]
    fn command_harness_classifies_missing_provider_config_before_launch() {
        let harness = CommandAgentHarness::new(
            CommandLaunchPlan::new("fixture", "sh")
                .require_env("WHIPPLESCRIPT_TEST_PROVIDER_CONFIG_DOES_NOT_EXIST"),
        );

        let result = harness.run(test_request());

        let failure = result.failure.expect("failure is structured");
        assert_eq!(result.status, ProviderRunStatus::Failed);
        assert_eq!(failure.provider, "fixture");
        assert_eq!(failure.adapter, "command");
        assert_eq!(failure.phase, "provider.config.missing");
        assert_eq!(failure.error_kind, "missing_provider_config");
        assert_eq!(
            failure.missing_config_keys,
            vec!["WHIPPLESCRIPT_TEST_PROVIDER_CONFIG_DOES_NOT_EXIST"]
        );
        assert!(failure.recoverable);
        assert_eq!(result.stdout, "");
    }

    #[test]
    fn command_harness_required_env_accepts_plan_env() {
        let key = "WHIPPLESCRIPT_TEST_PROVIDER_CONFIG_FROM_PLAN";
        let harness = CommandAgentHarness::new(
            CommandLaunchPlan::new("fixture", "sh")
                .arg("-c")
                .arg(format!("cat >/dev/null; test \"${key}\" = injected"))
                .env(key, "injected")
                .require_env(key),
        );

        let result = harness.run(test_request());

        assert_eq!(result.status, ProviderRunStatus::Completed);
        assert_eq!(result.exit_code, Some(0));
        assert!(result.failure.is_none());
    }

    #[test]
    fn command_harness_classifies_adapter_resolution_before_launch() {
        let harness = CommandAgentHarness::new(
            CommandLaunchPlan::new("fixture", "sh")
                .adapter("codex-app-server")
                .require_command("definitely-not-a-provider-adapter-command"),
        );

        let result = harness.run(test_request());

        let failure = result.failure.expect("failure is structured");
        assert_eq!(result.status, ProviderRunStatus::Failed);
        assert_eq!(failure.adapter, "codex-app-server");
        assert_eq!(failure.phase, "adapter.resolve.failed");
        assert_eq!(failure.error_kind, "adapter_command_not_found");
    }

    #[test]
    #[cfg(unix)]
    fn command_harness_classifies_non_executable_required_command_before_launch() {
        use std::os::unix::fs::PermissionsExt;

        let command_path = unique_temp_path("non-executable-adapter");
        std::fs::write(&command_path, "#!/bin/sh\nexit 0\n").expect("test command file writes");
        let mut permissions = std::fs::metadata(&command_path)
            .expect("test command metadata reads")
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&command_path, permissions)
            .expect("test command permissions update");

        let harness = CommandAgentHarness::new(
            CommandLaunchPlan::new("fixture", "sh")
                .adapter("codex-app-server")
                .require_command(command_path.to_string_lossy().into_owned()),
        );

        let result = harness.run(test_request());
        let _ = std::fs::remove_file(&command_path);

        let failure = result.failure.expect("failure is structured");
        assert_eq!(result.status, ProviderRunStatus::Failed);
        assert_eq!(failure.adapter, "codex-app-server");
        assert_eq!(failure.phase, "adapter.resolve.failed");
        assert_eq!(failure.error_kind, "adapter_command_not_found");
    }

    #[test]
    fn command_harness_classifies_workspace_prepare_before_launch() {
        let harness = CommandAgentHarness::new(
            CommandLaunchPlan::new("fixture", "sh")
                .cwd("/definitely/not/a/whipplescript/workspace"),
        );

        let result = harness.run(test_request());

        let failure = result.failure.expect("failure is structured");
        assert_eq!(result.status, ProviderRunStatus::Failed);
        assert_eq!(failure.phase, "workspace.prepare.failed");
        assert_eq!(failure.error_kind, "workspace_cwd_missing");
    }

    #[test]
    fn command_harness_classifies_timeout() {
        let harness = CommandAgentHarness::new(
            CommandLaunchPlan::new("fixture", "sh")
                .arg("-c")
                .arg("sleep 1")
                .timeout(Duration::from_millis(25)),
        );

        let result = harness.run(test_request());

        let failure = result.failure.expect("failure is structured");
        assert_eq!(result.status, ProviderRunStatus::TimedOut);
        assert_eq!(failure.phase, "provider.timeout");
        assert_eq!(failure.error_kind, "timeout");
        assert!(failure.recoverable);
    }

    #[test]
    #[cfg(unix)]
    fn command_harness_timeout_terminates_descendant_processes() {
        let pid_file = unique_temp_path("timeout-child-pid");
        let harness = CommandAgentHarness::new(
            CommandLaunchPlan::new("fixture", "sh")
                .arg("-c")
                .arg("sleep 5 & echo $! > \"$WHIPPLESCRIPT_CHILD_PID_FILE\"; cat >/dev/null; wait")
                .env(
                    "WHIPPLESCRIPT_CHILD_PID_FILE",
                    pid_file.display().to_string(),
                )
                .timeout(Duration::from_millis(250)),
        );

        let result = harness.run(test_request());

        let pid = std::fs::read_to_string(&pid_file)
            .expect("child pid file exists")
            .trim()
            .parse::<u32>()
            .expect("child pid parses");
        let gone = wait_until_process_gone(pid, Duration::from_millis(1_000));
        if !gone {
            let _ = Command::new("kill")
                .arg("-KILL")
                .arg(pid.to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = std::fs::remove_file(&pid_file);

        let failure = result.failure.expect("failure is structured");
        assert_eq!(result.status, ProviderRunStatus::TimedOut);
        assert_eq!(failure.phase, "provider.timeout");
        assert!(
            gone,
            "timed-out command left descendant process {pid} alive"
        );
    }

    #[test]
    fn command_harness_classifies_result_validation_failure() {
        let harness = CommandAgentHarness::new(
            CommandLaunchPlan::new("fixture", "sh")
                .arg("-c")
                .arg("cat >/dev/null; printf not-json")
                .require_stdout_json(),
        );

        let result = harness.run(test_request());

        let failure = result.failure.expect("failure is structured");
        assert_eq!(result.status, ProviderRunStatus::Failed);
        assert!(matches!(result.exit_code, Some(0) | None));
        assert_eq!(failure.phase, "provider.result.invalid");
        assert_eq!(failure.error_kind, "invalid_stdout_json");
        assert!(!failure.recoverable);
    }

    #[test]
    fn real_provider_adapters_delegate_to_command_plan() {
        let request = AgentTurnRequest {
            instance_id: "instance-a".to_owned(),
            effect_id: "tell".to_owned(),
            run_id: "run-tell".to_owned(),
            agent: "worker".to_owned(),
            profile: Some("repo-writer".to_owned()),
            input_json: "{}".to_owned(),
            skill_names: Vec::new(),
        };

        let codex = CodexAgentHarness::new(
            CommandLaunchPlan::new("codex", "sh")
                .arg("-c")
                .arg("cat >/dev/null"),
        );
        let claude = ClaudeCodeAgentHarness::new(
            CommandLaunchPlan::new("claude-code", "sh")
                .arg("-c")
                .arg("cat >/dev/null"),
        );

        assert_eq!(
            codex.run(request.clone()).status,
            ProviderRunStatus::Completed
        );
        assert_eq!(claude.run(request).status, ProviderRunStatus::Completed);
    }

    fn test_request() -> AgentTurnRequest {
        AgentTurnRequest {
            instance_id: "instance-a".to_owned(),
            effect_id: "tell".to_owned(),
            run_id: "run-tell".to_owned(),
            agent: "worker".to_owned(),
            profile: Some("repo-writer".to_owned()),
            input_json: r#"{"prompt":"go"}"#.to_owned(),
            skill_names: Vec::new(),
        }
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "whipplescript-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

    #[cfg(unix)]
    fn wait_until_process_gone(pid: u32, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !process_exists(pid) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        !process_exists(pid)
    }

    #[cfg(unix)]
    fn process_exists(pid: u32) -> bool {
        Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
}
