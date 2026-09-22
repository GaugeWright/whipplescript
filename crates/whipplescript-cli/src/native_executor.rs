//! Native Docker lifecycle adapter. Creating or discovering an inert container
//! does not grant controller admission; removal is not an invocation proof.
use serde::{Deserialize, Serialize};
use whipplescript_store::{
    exec_lifetime::{Fence, FenceReason},
    exec_native_owner::{Allocation, Container, Owner},
    RuntimeStore, SqliteStore, StoreError, StoreResult,
};

mod managed;
mod norm_admission;
mod norm_driver;
mod norm_host;
pub use norm_admission::NativeNormAdmission;
pub use norm_driver::{native_norm_runs, NativeNormProgress, NativeNormRecovery};
pub use norm_host::NativeNormHost;
mod runtime_image;
pub use managed::ManagedReconciliation;
pub use runtime_image::{
    HostedRuntimeContextRequest, NativeRuntimeImage, PreparedRuntimeContext, RuntimeImageRequest,
    RuntimeImageVerificationRequest, MAX_NORM_RUNTIME_PROFILE_BYTES, NORM_RUNTIME_PROBE_PROTOCOL,
};

pub const OWNER_LABEL: &str = "whipplescript.executor.owner";
pub const TRACK_LABEL: &str = "whipplescript.executor.tracking";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    pub id: String,
    pub image: String,
    pub name: String,
    pub owner: String,
    pub tracking: String,
}

/// Trusted host interface. Engine implementations supply physical observations,
/// never workflow-provided booleans. The ordinary implementation uses Docker.
pub trait Engine {
    fn daemon_id(&mut self) -> StoreResult<String>;
    fn create_inert(&mut self, owner: &Owner) -> StoreResult<String>;
    fn inspect(&mut self, id_or_owner: &str) -> StoreResult<Option<Inspection>>;
    fn remove(&mut self, container_id: &str) -> StoreResult<()>;
}

#[derive(Debug)]
pub enum Prepared {
    /// Allocation survived, but no creation response/container is observable.
    /// A late original create can still arrive; never issue a second create.
    AwaitingCreation,
    Bound(Container),
    /// The original binding is retained; its absence cannot mint a replacement.
    Absent(Container),
}

pub struct NativeExecutor<E> {
    engine: E,
}
impl<E: Engine> NativeExecutor<E> {
    pub fn new(engine: E) -> Self {
        Self { engine }
    }
    fn same_daemon(&mut self, owner: &Owner) -> StoreResult<()> {
        if self.engine.daemon_id()? != owner.daemon_id {
            return Err(StoreError::Conflict("native Docker daemon changed".into()));
        }
        Ok(())
    }
    fn verify(owner: &Owner, held: &Inspection) -> StoreResult<()> {
        if held.image != owner.image_id
            || held.name != format!("/{}", owner.owner_id)
            || held.owner != owner.owner_id
            || held.tracking != owner.tracking_event_id
        {
            return Err(StoreError::Conflict(
                "Docker container does not match retained owner".into(),
            ));
        }
        Ok(())
    }
    pub fn prepare(
        &mut self,
        store: &mut SqliteStore,
        instance: &str,
        run: &str,
        image: &str,
    ) -> StoreResult<Prepared> {
        let daemon = self.engine.daemon_id()?;
        let receipt = store.allocate_native_executor(Allocation {
            instance_id: instance,
            run_id: run,
            daemon_id: &daemon,
            image_id: image,
        })?;
        let owner = receipt.owner;
        if let Some(bound) = store.native_executor_container(instance, run)? {
            self.same_daemon(&owner)?;
            let actual = self.engine.inspect(&bound.container_id)?;
            self.same_daemon(&owner)?;
            return match actual {
                None => Ok(Prepared::Absent(bound)),
                Some(actual) => {
                    Self::verify(&owner, &actual)?;
                    if actual.id != bound.container_id {
                        return Err(StoreError::Conflict(
                            "Docker substituted a bound container".into(),
                        ));
                    }
                    Ok(Prepared::Bound(bound))
                }
            };
        }
        self.same_daemon(&owner)?;
        // A failed/timed-out create may have succeeded at the daemon. Leave the
        // allocation intact; cold recovery discovers it by the immutable owner.
        let created_id = if receipt.created {
            Some(self.engine.create_inert(&owner)?)
        } else {
            None
        };
        self.same_daemon(&owner)?;
        let selector = created_id.as_deref().unwrap_or(&owner.owner_id);
        let Some(actual) = self.engine.inspect(selector)? else {
            return Ok(Prepared::AwaitingCreation);
        };
        self.same_daemon(&owner)?;
        Self::verify(&owner, &actual)?;
        if created_id.as_ref().is_some_and(|id| id != &actual.id) {
            return Err(StoreError::Conflict(
                "Docker changed its creation identity".into(),
            ));
        }
        // Late binding is valid cleanup custody even if a fence raced create.
        store.bind_native_executor_container(instance, run, &actual.id)?;
        Ok(Prepared::Bound(
            store
                .native_executor_container(instance, run)?
                .ok_or_else(|| {
                    StoreError::Conflict("native container binding disappeared".into())
                })?,
        ))
    }

    /// Remove the bound immutable ID through its original external owner.
    /// The controller must still close/drain its gate before deriving proof.
    pub fn remove_bound(
        &mut self,
        store: &mut SqliteStore,
        instance: &str,
        run: &str,
        reason: FenceReason,
    ) -> StoreResult<Container> {
        store.ensure_exec_fence(Fence {
            instance_id: instance,
            run_id: run,
            reason,
        })?;
        let bound = store
            .native_executor_container(instance, run)?
            .ok_or_else(|| {
                StoreError::Conflict("native container has no retained binding".into())
            })?;
        self.same_daemon(&bound.owner)?;
        if let Some(actual) = self.engine.inspect(&bound.container_id)? {
            Self::verify(&bound.owner, &actual)?;
            if actual.id != bound.container_id {
                return Err(StoreError::Conflict(
                    "Docker substituted a removal target".into(),
                ));
            }
            self.same_daemon(&bound.owner)?;
            self.engine.remove(&bound.container_id)?;
        }
        self.same_daemon(&bound.owner)?;
        if self.engine.inspect(&bound.container_id)?.is_some() {
            return Err(StoreError::Conflict(
                "Docker removal has not completed".into(),
            ));
        }
        self.same_daemon(&bound.owner)?;
        Ok(bound)
    }
}

/// A fixed Docker endpoint, independent of later ambient context selection.
/// Authentication remains Docker's host configuration; no credential is journaled.
pub struct Docker {
    endpoint: String,
    program: std::path::PathBuf,
    timeout: std::time::Duration,
}
impl Docker {
    pub fn new(endpoint: &str) -> StoreResult<Self> {
        if endpoint.is_empty() || endpoint.chars().any(char::is_control) {
            return Err(StoreError::Conflict(
                "native Docker endpoint is missing or invalid".into(),
            ));
        }
        Ok(Self {
            endpoint: endpoint.into(),
            program: "docker".into(),
            timeout: std::time::Duration::from_secs(30),
        })
    }
    fn command(&self, args: &[&str], token: Option<&str>) -> StoreResult<String> {
        self.command_io(args, token, None, 65_536, self.timeout)
    }
    fn command_io(
        &self,
        args: &[&str],
        token: Option<&str>,
        input: Option<Vec<u8>>,
        output_limit: u64,
        timeout: std::time::Duration,
    ) -> StoreResult<String> {
        use std::{
            io::{Read, Write},
            process::{Command, Stdio},
            sync::mpsc,
            time::{Duration, Instant},
        };
        let mut command = Command::new(&self.program);
        command
            .args(["--host", &self.endpoint])
            .args(args)
            .env_remove("DOCKER_CONTEXT")
            .env_remove("DOCKER_HOST")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(token) = token {
            command.env("WHIP_EXECUTOR_TOKEN", token);
        }
        let mut child = command.spawn()?;
        let input_done = if let Some(input) = input {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| StoreError::Conflict("Docker stdin is unavailable".into()))?;
            let (send, receive) = mpsc::channel();
            std::thread::spawn(move || {
                let result = stdin.write_all(&input);
                drop(stdin);
                let _ = send.send(result);
            });
            Some(receive)
        } else {
            None
        };
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| StoreError::Conflict("Docker stdout is unavailable".into()))?;
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout
                .take(output_limit + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = send.send(result);
        });
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(StoreError::Conflict(
                    "Docker operation timed out; reconcile retained ownership".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        if !status.success() {
            return Err(StoreError::Conflict(
                "Docker operation failed; reconcile retained ownership".into(),
            ));
        }
        let bytes = receive
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| StoreError::Conflict("Docker output did not close".into()))??;
        if bytes.len() as u64 > output_limit {
            return Err(StoreError::Conflict(
                "Docker output exceeded its bound".into(),
            ));
        }
        if let Some(done) = input_done {
            done.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| StoreError::Conflict("Docker input did not close".into()))??;
        }
        String::from_utf8(bytes)
            .map(|s| s.trim().to_owned())
            .map_err(|_| StoreError::Conflict("Docker output is not UTF-8".into()))
    }

    /// Address authority independently of workflow allocation history. The
    /// expected daemon is a retained host binding, never inferred from a missing
    /// volume on whichever daemon happens to answer the endpoint today.
    pub fn controller(
        &mut self,
        expected_daemon: &str,
        helper_image: &str,
        identity: &crate::native_controller::Identity,
        command: crate::native_controller::Command,
    ) -> StoreResult<crate::native_controller::Reply> {
        use crate::{native_controller, native_controller_helper};
        identity
            .envelope
            .dispatch(&identity.selected)
            .map_err(StoreError::Conflict)?;
        if !helper_image.strip_prefix("sha256:").is_some_and(digest) {
            return Err(StoreError::Conflict(
                "native controller helper requires an immutable image".into(),
            ));
        }
        if expected_daemon.is_empty() || self.daemon_id()? != expected_daemon {
            return Err(StoreError::Conflict(
                "native controller daemon differs from its retained binding".into(),
            ));
        }
        let volume = identity.controller_id();
        let owner_label = format!("whipplescript.executor.controller={volume}");
        let protocol_label = format!(
            "whipplescript.executor.controller.protocol={}",
            native_controller::PROTOCOL
        );
        let created = self.command(
            &[
                "volume",
                "create",
                "--label",
                &owner_label,
                "--label",
                &protocol_label,
                &volume,
            ],
            None,
        )?;
        if created != volume {
            return Err(StoreError::Conflict(
                "Docker substituted the controller volume".into(),
            ));
        }
        let labels: serde_json::Value = serde_json::from_str(&self.command(
            &["volume", "inspect", "--format", "{{json .Labels}}", &volume],
            None,
        )?)?;
        if labels["whipplescript.executor.controller"] != volume
            || labels["whipplescript.executor.controller.protocol"] != native_controller::PROTOCOL
        {
            return Err(StoreError::Conflict(
                "Docker controller volume ownership differs".into(),
            ));
        }
        if self.daemon_id()? != expected_daemon {
            return Err(StoreError::Conflict(
                "native controller daemon changed before dispatch".into(),
            ));
        }
        let claim = matches!(command, native_controller::Command::Claim { .. });
        let request = native_controller_helper::Request::Control {
            identity: identity.clone(),
            command: command.clone(),
        };
        let reply = self.helper_exchange(
            expected_daemon,
            helper_image,
            identity,
            &request,
            "none",
            None,
        )?;
        let mut acknowledged = reply.state.clone();
        acknowledged.apply(command)?;
        if acknowledged != reply.state || (reply.create && !claim) {
            return Err(StoreError::Conflict(
                "native controller response differs from retained authority".into(),
            ));
        }
        Ok(reply)
    }
    fn helper_exchange(
        &mut self,
        expected_daemon: &str,
        helper_image: &str,
        identity: &crate::native_controller::Identity,
        request: &crate::native_controller_helper::Request,
        network: &str,
        token: Option<&str>,
    ) -> StoreResult<crate::native_controller::Reply> {
        use crate::{native_controller, native_controller_helper};
        if self.daemon_id()? != expected_daemon {
            return Err(StoreError::Conflict(
                "native helper daemon changed before exchange".into(),
            ));
        }
        let input = serde_json::to_vec(request)?;
        if input.len() as u64 > native_controller_helper::MAX_CONTROL_BYTES {
            return Err(StoreError::Conflict(
                "native controller request exceeds its bound".into(),
            ));
        }
        let mount = format!(
            "type=volume,src={},dst=/authority",
            identity.controller_id()
        );
        let mut args = vec![
            "run",
            "--rm",
            "-i",
            "--pull=never",
            "--network",
            network,
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--mount",
            &mount,
            "--entrypoint",
            "whip",
        ];
        if token.is_some() {
            args.extend(["--env", "WHIP_EXECUTOR_TOKEN"]);
        }
        args.extend([
            helper_image,
            "executor",
            "controller",
            "--database",
            "/authority/controller.sqlite",
        ]);
        let output = self.command_io(
            &args,
            token,
            Some(input),
            native_controller_helper::MAX_CONTROL_RESPONSE_BYTES,
            std::time::Duration::from_secs(360),
        )?;
        if self.daemon_id()? != expected_daemon {
            return Err(StoreError::Conflict(
                "native controller daemon changed during dispatch".into(),
            ));
        }
        let reply: native_controller::Reply = serde_json::from_str(&output)?;
        reply.state.validate(identity)?;
        if reply.decision.is_some()
            || reply.response != reply.state.reply(false)?.response
            || reply
                .state
                .owner
                .as_ref()
                .is_some_and(|owner| owner.daemon_id != expected_daemon)
        {
            return Err(StoreError::Conflict(
                "native helper response differs from retained authority".into(),
            ));
        }
        Ok(reply)
    }
    fn create_inert_profile(
        &mut self,
        owner: &Owner,
        profile: Option<&str>,
    ) -> StoreResult<String> {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut bytes = [0u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| StoreError::Conflict("cannot generate executor authentication".into()))?;
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let pinned = profile.map(|value| format!("WHIP_EXECUTOR_DISPATCH_SHA256={value}"));
        let owner_label = format!("{OWNER_LABEL}={}", owner.owner_id);
        let tracking_label = format!("{TRACK_LABEL}={}", owner.tracking_event_id);
        let mut args = vec![
            "container",
            "create",
            "--pull=never",
            "--name",
            &owner.owner_id,
            "--label",
            &owner_label,
            "--label",
            &tracking_label,
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--env",
            "WHIP_EXECUTOR_TOKEN",
        ];
        if let Some(pinned) = &pinned {
            args.extend(["--env", pinned]);
        }
        args.push(&owner.image_id);
        self.command(&args, Some(&token))
    }
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Engine for Docker {
    fn daemon_id(&mut self) -> StoreResult<String> {
        self.command(&["info", "--format", "{{.ID}}"], None)
    }
    fn create_inert(&mut self, owner: &Owner) -> StoreResult<String> {
        self.create_inert_profile(owner, None)
    }
    fn inspect(&mut self, selector: &str) -> StoreResult<Option<Inspection>> {
        let filter = if digest(selector) {
            format!("id={selector}")
        } else if selector.strip_prefix("whip-exec-").is_some_and(digest) {
            format!("name=^/{selector}$")
        } else {
            return Err(StoreError::Conflict(
                "Docker lookup requires an immutable executor identity".into(),
            ));
        };
        let ids = self.command(
            &[
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                &filter,
                "--format",
                "{{.ID}}",
            ],
            None,
        )?;
        if ids.is_empty() {
            return Ok(None);
        }
        if !digest(&ids) {
            return Err(StoreError::Conflict(
                "Docker owner lookup is ambiguous".into(),
            ));
        }
        let format = r#"{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},"owner":{{json (index .Config.Labels "whipplescript.executor.owner")}},"tracking":{{json (index .Config.Labels "whipplescript.executor.tracking")}}}"#;
        Ok(Some(serde_json::from_str(&self.command(
            &["container", "inspect", "--format", format, &ids],
            None,
        )?)?))
    }
    fn remove(&mut self, container_id: &str) -> StoreResult<()> {
        if !digest(container_id) {
            return Err(StoreError::Conflict(
                "Docker removal requires an immutable container ID".into(),
            ));
        }
        self.command(
            &["container", "rm", "--force", "--volumes", container_id],
            None,
        )?;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn native_docker_controller_refuses_changed_external_authority() {
        use crate::native_controller::{Authority, Command, Identity};
        use std::os::unix::fs::PermissionsExt;
        use whipplescript_kernel::exec_invocation::{Envelope, Invocation};
        let dir = std::env::temp_dir().join(format!(
            "docker-controller-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let selected = Invocation {
            instance_id: "controller-fixture".into(),
            effect_id: "exec".into(),
            attempt_admission_event_id: None,
        };
        let identity = Identity {
            envelope: Envelope::new(
                selected.clone(),
                serde_json::json!({"protocol":"whip-executor/1","effect_id":"exec"}),
            )
            .unwrap(),
            selected,
        };
        let reply = Authority::open(&dir.join("state.sqlite"))
            .unwrap()
            .apply(&identity, Command::Read)
            .unwrap();
        let baseline = serde_json::to_value(reply).unwrap();
        let path = dir.join("docker");
        std::fs::write(
            &path,
            r#"#!/bin/sh
here=${0%/*}
mode=$(cat "$here/mode")
case "$3 $4" in
  'info --format')
    count=$(cat "$here/count" 2>/dev/null || printf 0)
    count=$((count + 1))
    printf '%s' "$count" > "$here/count"
    if [ "$mode" = "daemon-$count" ]; then printf foreign; else printf daemon; fi ;;
  'volume create')
    if [ "$mode" = volume-name ]; then printf foreign; else cat "$here/volume"; fi ;;
  'volume inspect') cat "$here/labels" ;;
  'run --rm') cat > "$here/request"; cat "$here/reply" ;;
  *) exit 7 ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(dir.join("volume"), identity.controller_id()).unwrap();
        for mode in [
            "exact",
            "volume-name",
            "volume-label",
            "volume-protocol",
            "mutable-image",
            "daemon-1",
            "daemon-2",
            "daemon-3",
            "daemon-4",
            "reply-identity",
            "reply-action",
            "reply-grant",
            "reply-decision",
            "reply-daemon",
            "unacknowledged-claim",
            "oversized-input",
        ] {
            let _ = std::fs::remove_file(dir.join("count"));
            let _ = std::fs::remove_file(dir.join("request"));
            std::fs::write(dir.join("mode"), mode).unwrap();
            let mut labels = serde_json::json!({"whipplescript.executor.controller":identity.controller_id(),"whipplescript.executor.controller.protocol":crate::native_controller::PROTOCOL});
            if mode == "volume-label" {
                labels["whipplescript.executor.controller"] = serde_json::json!("foreign");
            }
            if mode == "volume-protocol" {
                labels["whipplescript.executor.controller.protocol"] =
                    serde_json::json!("foreign-protocol");
            }
            std::fs::write(dir.join("labels"), labels.to_string()).unwrap();
            let mut reply = baseline.clone();
            match mode {
                "reply-identity" => {
                    reply["state"]["identity"]["selected"]["instance_id"] =
                        serde_json::json!("foreign")
                }
                "reply-action" => {
                    reply["response"]["action"] =
                        serde_json::json!({"action":"execute","incarnation":"forged"})
                }
                "reply-grant" => reply["create"] = serde_json::json!(true),
                "reply-decision" => reply["decision"] = serde_json::json!({"action":"execute"}),
                "reply-daemon" => {
                    reply["state"]["owner"] = serde_json::json!({"protocol":whipplescript_store::exec_native_owner::PROTOCOL,"instance_id":identity.selected.instance_id,"effect_id":"exec","run_id":identity.selected.run_id(),"tracking_event_id":"track","daemon_id":"foreign","image_id":format!("sha256:{}","a".repeat(64)),"owner_id":"owner"})
                }
                _ => {}
            }
            std::fs::write(dir.join("reply"), reply.to_string()).unwrap();
            let mut docker = Docker::new("unix:///fixture").unwrap();
            docker.program = path.clone();
            let requested = if matches!(mode, "unacknowledged-claim" | "oversized-input") {
                Command::Claim {
                    owner: Owner {
                        protocol: whipplescript_store::exec_native_owner::PROTOCOL.into(),
                        instance_id: identity.selected.instance_id.clone(),
                        effect_id: "exec".into(),
                        run_id: identity.selected.run_id(),
                        tracking_event_id: if mode == "oversized-input" {
                            "t".repeat(16 * 1024 * 1024)
                        } else {
                            "track".into()
                        },
                        daemon_id: "daemon".into(),
                        image_id: format!("sha256:{}", "a".repeat(64)),
                        owner_id: "owner".into(),
                    },
                }
            } else {
                Command::Read
            };
            let image = if mode == "mutable-image" {
                "mutable-image:latest".to_owned()
            } else {
                format!("sha256:{}", "a".repeat(64))
            };
            let result = docker.controller("daemon", &image, &identity, requested);
            assert_eq!(result.is_ok(), mode == "exact", "{mode}");
            if mode == "exact" {
                let request: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(dir.join("request")).unwrap()).unwrap();
                assert_eq!(request["op"], "control");
                assert_eq!(
                    request["identity"],
                    serde_json::to_value(&identity).unwrap()
                );
            }
            if mode.starts_with("volume-")
                || mode == "mutable-image"
                || mode == "oversized-input"
                || mode == "daemon-1"
                || mode == "daemon-2"
            {
                assert!(!dir.join("request").exists(), "{mode} dispatched a helper");
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn native_docker_command_bounds_and_identity_syntax() {
        use std::{
            os::unix::fs::PermissionsExt,
            time::{Duration, Instant},
        };
        assert!(Docker::new("").is_err());
        assert!(Docker::new("unix://invalid\n").is_err());
        let mut docker = Docker::new("unix:///fixture").unwrap();
        assert!(docker.inspect("mutable-name").is_err());
        assert!(docker.remove("mutable-name").is_err());
        let dir = std::env::temp_dir().join(format!(
            "docker-command-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("docker");
        docker.program = path.clone();
        // Two kinds of case, and only one of them is about time.
        //
        // A case that asserts what the output parses to is not asserting that
        // the parse was quick, so its deadline must be far enough away that
        // only a genuinely stuck child reaches it. It used to be two seconds,
        // which is a statement about the host's scheduler rather than about
        // this code: on a loaded machine a child that runs `printf` and exits
        // was not reaped inside it, and the bar failed with `Docker operation
        // timed out` — a message about retained ownership, for a test that had
        // never gone near a daemon. Measured on the founder's machine under a
        // concurrent build and six forking loops, that was two failures in six
        // runs, each landing on the ceiling exactly.
        //
        // A case that asserts the operation is BOUNDED does need a short
        // deadline, because the deadline is the input. What it must not need is
        // a tight ceiling: the property is that the call returns without
        // waiting for the child, so the child sleeps far longer than the
        // ceiling and scheduling noise has nowhere to push the verdict. The two
        // backgrounded cases leave that sleep orphaned, which is why it is ten
        // seconds and not a minute.
        const UNBOUNDED: Duration = Duration::from_secs(60);
        const BOUND_DEADLINE: Duration = Duration::from_millis(30);
        const BOUND_CEILING: Duration = Duration::from_secs(5);

        // Which leaves the cases that are neither: they are expected to fail,
        // and not for want of time. `is_err()` cannot tell their own refusal
        // from the deadline catching a hang, so with UNBOUNDED sixty seconds
        // away it would read that hang as a pass -- quietly, and a minute
        // later. Assert instead that the deadline fired exactly when it was
        // the input and never otherwise, which is a question about the error
        // rather than about the clock.
        let bound_fired = |result: &StoreResult<String>| {
            matches!(
                result,
                Err(StoreError::Conflict(message))
                    if message.contains("timed out") || message.contains("did not close")
            )
        };

        for (case, script) in [
            ("exact", "printf '  daemon-id\\n'"),
            ("failure", "exit 7"),
            ("timeout", "sleep 10"),
            ("inherited-pipe", "sleep 10 & exit 0"),
            ("delayed-output", "(sleep 0.2; printf daemon-id) & exit 0"),
            ("oversized", "head -c 65537 /dev/zero"),
            ("invalid-utf8", "printf '\\377'"),
        ] {
            std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let bounded = matches!(case, "timeout" | "inherited-pipe");
            docker.timeout = if bounded { BOUND_DEADLINE } else { UNBOUNDED };
            let started = Instant::now();
            let result = docker.daemon_id();
            if matches!(case, "exact" | "delayed-output") {
                assert_eq!(result.unwrap(), "daemon-id");
            } else {
                assert!(result.is_err(), "{case}");
                assert_eq!(bound_fired(&result), bounded, "{case}");
            }
            if bounded {
                assert!(
                    started.elapsed() < BOUND_CEILING,
                    "{case} did not bound the client operation"
                );
            }
        }
        for (case, script) in [
            ("duplex", "head -c 1048576 /dev/zero; cat"),
            ("unread-input", "sleep 10"),
            ("closed-input", "exec 0<&-; sleep 0.02; printf '{}'"),
            (
                "inherited-input",
                "exec 3<&0; sleep 10 <&3 >/dev/null & exit 0",
            ),
            (
                "delayed-input",
                "exec 3<&0; (sleep 0.2; cat <&3 >/dev/null) >/dev/null & printf '{}'",
            ),
        ] {
            std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
            let started = Instant::now();
            let bounded = matches!(case, "unread-input" | "inherited-input");
            let result = docker.command_io(
                &[],
                None,
                Some(vec![b'x'; 1048576]),
                3 * 1048576,
                if bounded { BOUND_DEADLINE } else { UNBOUNDED },
            );
            if case == "duplex" {
                let output = result.unwrap();
                assert_eq!(output.len(), 2 * 1048576);
                assert!(output.as_bytes()[..1048576].iter().all(|b| *b == 0));
                assert!(output.as_bytes()[1048576..].iter().all(|b| *b == b'x'));
            } else if case == "delayed-input" {
                assert_eq!(result.unwrap(), "{}");
            } else {
                assert!(result.is_err(), "{case}");
                assert_eq!(bound_fired(&result), bounded, "{case}");
                if bounded {
                    assert!(
                        started.elapsed() < BOUND_CEILING,
                        "{case} did not bound stdin"
                    );
                }
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
