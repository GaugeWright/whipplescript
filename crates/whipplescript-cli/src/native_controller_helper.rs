//! Trusted native controller helper. Its Docker mount and PID namespace must
//! remain separate from executed scripts; only the executor network is shared.
use crate::native_controller::{Authority, Command, Identity, Reply};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::Path,
    time::Duration,
};
use whipplescript_kernel::exec_incarnation;
use whipplescript_store::{StoreError, StoreResult};

pub(crate) const MAX_CONTROL_BYTES: u64 = 16 * 1024 * 1024;
// Two 512-KiB streams can each expand sixfold when JSON escapes controls.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
// Retained state includes the response in the controller and provider receipt,
// plus the returned action and dispatch material. Bound the complete envelope.
pub(crate) const MAX_CONTROL_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Control {
        identity: Identity,
        command: Command,
    },
    Deliver {
        identity: Identity,
        owner: String,
        container_id: String,
    },
}

/// Only the trusted adapter supplies this process transport. The response still
/// passes through the shared incarnation codec before durable completion.
pub trait Transport {
    fn exchange(&mut self, path: &str, body: Option<&str>) -> StoreResult<String>;
}

pub fn process(
    authority: &mut Authority,
    request: Request,
    transport: &mut impl Transport,
) -> StoreResult<Reply> {
    match request {
        Request::Control { identity, command } => authority.apply(&identity, command),
        Request::Deliver {
            identity,
            owner,
            container_id,
        } => {
            let retained = authority.apply(&identity, Command::Read)?;
            if retained.state.owner.as_ref().map(|o| o.owner_id.as_str()) != Some(&owner)
                || retained.state.container_id.as_deref() != Some(&container_id)
            {
                return Err(StoreError::Conflict(
                    "native helper delivery differs from physical binding".into(),
                ));
            }
            // A cold status/replay must not contact or start a replacement.
            if retained.response["action"]["action"] != "absent" {
                return Ok(retained);
            }
            let handshake = transport.exchange("/exec/incarnation", None)?;
            let incarnation =
                exec_incarnation::read_handshake(&handshake).map_err(StoreError::Conflict)?;
            let dispatch = identity
                .envelope
                .dispatch(&identity.selected)
                .map_err(StoreError::Conflict)?;
            let delivery = exec_incarnation::delivery(&incarnation, dispatch.clone())
                .map_err(StoreError::Conflict)?;
            let mut reply = authority.execute(
                &identity,
                &owner,
                &container_id,
                &incarnation,
                dispatch,
                || {
                    let response = transport.exchange("/exec/bound", Some(&delivery))?;
                    exec_incarnation::read_completion(&response, &incarnation)
                        .map_err(StoreError::Conflict)
                },
            )?;
            reply.decision = None;
            Ok(reply)
        }
    }
}

struct Loopback;
impl Transport for Loopback {
    fn exchange(&mut self, path: &str, body: Option<&str>) -> StoreResult<String> {
        let token = std::env::var("WHIP_EXECUTOR_TOKEN").map_err(|_| {
            StoreError::Conflict("native helper requires executor credential".into())
        })?;
        if token.is_empty() {
            return Err(StoreError::Conflict(
                "native helper requires executor credential".into(),
            ));
        }
        let agent = ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .redirects(0)
            .timeout_connect(Duration::from_secs(3))
            .timeout(Duration::from_secs(310))
            .build();
        let url = format!("http://127.0.0.1:8080{path}");
        let request = agent
            .request(if body.is_some() { "POST" } else { "GET" }, &url)
            .set("X-Whip-Executor-Token", &token);
        let response = match body {
            Some(body) => request.send_string(body),
            None => request.call(),
        }
        .map_err(|_| {
            StoreError::Conflict(
                "native executor transport failed; reconcile retained admission".into(),
            )
        })?;
        if response.status() != 200 {
            return Err(StoreError::Conflict(
                "native executor transport returned a non-success response".into(),
            ));
        }
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(StoreError::Conflict(
                "native executor response exceeds its bound".into(),
            ));
        }
        String::from_utf8(bytes)
            .map_err(|_| StoreError::Conflict("native executor response is not UTF-8".into()))
    }
}

/// One bounded stdin/stdout exchange. No listener, proxy, Docker socket or
/// workflow-supplied endpoint is exposed inside the helper.
pub fn serve(path: &Path, input: impl Read, mut output: impl Write) -> StoreResult<()> {
    let mut bytes = Vec::new();
    input.take(MAX_CONTROL_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONTROL_BYTES {
        return Err(StoreError::Conflict(
            "native controller request exceeds its bound".into(),
        ));
    }
    let request: Request = serde_json::from_slice(&bytes)?;
    let reply = process(&mut Authority::open(path)?, request, &mut Loopback)?;
    let bytes = serde_json::to_vec(&reply)?;
    if bytes.len() as u64 > MAX_CONTROL_RESPONSE_BYTES {
        return Err(StoreError::Conflict(
            "native controller response exceeds its bound".into(),
        ));
    }
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(())
}
