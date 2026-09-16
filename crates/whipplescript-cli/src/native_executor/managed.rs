//! Composition over the external authority. Callers retain workflow intent
//! before entering this trusted adapter; workflow snapshots do not own its tip.
use super::*;
use crate::{
    native_controller::{Command, Identity, Reply},
    native_controller_helper::Request,
};
use serde_json::Value;

mod reconcile;
pub use reconcile::ManagedReconciliation;

fn dispatch_digest(identity: &Identity) -> StoreResult<String> {
    Ok(whipplescript_kernel::exec_http::sha256_hex(
        identity
            .envelope
            .dispatch(&identity.selected)
            .map_err(StoreError::Conflict)?
            .to_string()
            .as_bytes(),
    ))
}
impl Docker {
    /// A restored workflow's candidate must never replace an existing external
    /// owner. Only a fresh retained claim authorizes inert physical creation.
    pub fn prepare_managed(
        &mut self,
        daemon: &str,
        helper_image: &str,
        identity: &Identity,
        candidate: &Owner,
    ) -> StoreResult<Reply> {
        let mut retained = self.controller(daemon, helper_image, identity, Command::Read)?;
        let mut created = None;
        if retained.state.owner.is_none() {
            if retained.response["action"]["action"] != "absent" {
                return Ok(retained);
            }
            if candidate.daemon_id != daemon
                || !candidate
                    .image_id
                    .strip_prefix("sha256:")
                    .is_some_and(digest)
                || !candidate
                    .owner_id
                    .strip_prefix("whip-exec-")
                    .is_some_and(digest)
            {
                return Err(StoreError::Conflict(
                    "managed executor candidate has no immutable owner binding".into(),
                ));
            }
            retained = self.controller(
                daemon,
                helper_image,
                identity,
                Command::Claim {
                    owner: candidate.clone(),
                },
            )?;
            if std::mem::take(&mut retained.create) {
                if self.daemon_id()? != daemon {
                    return Err(StoreError::Conflict(
                        "managed executor daemon changed before creation".into(),
                    ));
                }
                // A lost response leaves the claim retained. Discovery may bind
                // that original create later, including after a racing fence.
                created =
                    Some(self.create_inert_profile(candidate, Some(&dispatch_digest(identity)?))?);
            }
        }
        let Some(owner) = retained.state.owner.clone() else {
            return Ok(retained);
        };
        if retained.state.container_id.is_some() {
            return Ok(retained);
        }
        if self.daemon_id()? != daemon {
            return Err(StoreError::Conflict(
                "managed executor daemon changed before discovery".into(),
            ));
        }
        let Some(actual) = self.inspect(created.as_deref().unwrap_or(&owner.owner_id))? else {
            return Ok(retained);
        };
        if self.daemon_id()? != daemon {
            return Err(StoreError::Conflict(
                "managed executor daemon changed during discovery".into(),
            ));
        }
        NativeExecutor::<Docker>::verify(&owner, &actual)?;
        if created.as_ref().is_some_and(|id| id != &actual.id) {
            return Err(StoreError::Conflict(
                "managed executor creation identity changed".into(),
            ));
        }
        self.controller(
            daemon,
            helper_image,
            identity,
            Command::Bind {
                owner,
                container_id: actual.id,
            },
        )
    }

    fn managed_profile(
        &mut self,
        identity: &Identity,
        owner: &Owner,
        container: &str,
    ) -> StoreResult<String> {
        if self.daemon_id()? != owner.daemon_id {
            return Err(StoreError::Conflict(
                "managed executor daemon changed".into(),
            ));
        }
        let actual = self.inspect(container)?.ok_or_else(|| {
            StoreError::Conflict(
                "managed executor is absent; reconcile its original authority".into(),
            )
        })?;
        NativeExecutor::<Docker>::verify(owner, &actual)?;
        if actual.id != container {
            return Err(StoreError::Conflict(
                "managed executor substituted a bound target".into(),
            ));
        }
        let format = r#"{"id":{{json .Id}},"env":{{json .Config.Env}},"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},"network":{{json .HostConfig.NetworkMode}},"networks":{{json .NetworkSettings.Networks}},"pid":{{json .HostConfig.PidMode}},"privileged":{{json .HostConfig.Privileged}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"mounts":{{json .Mounts}},"add":{{json .HostConfig.CapAdd}},"drop":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"status":{{json .State.Status}}}"#;
        let profile: Value = serde_json::from_str(&self.command(
            &["container", "inspect", "--format", format, container],
            None,
        )?)?;
        let token = validate_profile(&profile, container, &dispatch_digest(identity)?)?;
        if self.daemon_id()? != owner.daemon_id {
            return Err(StoreError::Conflict(
                "managed executor daemon changed during inspection".into(),
            ));
        }
        Ok(token)
    }

    pub fn deliver_managed(
        &mut self,
        daemon: &str,
        helper_image: &str,
        identity: &Identity,
    ) -> StoreResult<Reply> {
        let retained = self.controller(daemon, helper_image, identity, Command::Read)?;
        if retained.response["action"]["action"] != "absent" {
            return Ok(retained);
        }
        let owner = retained.state.owner.ok_or_else(|| {
            StoreError::Conflict("managed execution has no retained owner".into())
        })?;
        let container = retained
            .state
            .container_id
            .ok_or_else(|| StoreError::Conflict("managed creation is not yet bound".into()))?;
        self.managed_profile(identity, &owner, &container)?;
        let started = self.command(&["container", "start", &container], None)?;
        if started != container {
            return Err(StoreError::Conflict(
                "managed executor startup identity changed".into(),
            ));
        }
        // A competing helper or fence may have committed during startup.
        let retained = self.controller(daemon, helper_image, identity, Command::Read)?;
        if retained.response["action"]["action"] != "absent" {
            return Ok(retained);
        }
        let token = self.managed_profile(identity, &owner, &container)?;
        let reply = self.helper_exchange(
            daemon,
            helper_image,
            identity,
            &Request::Deliver {
                identity: identity.clone(),
                owner: owner.owner_id.clone(),
                container_id: container.clone(),
            },
            &format!("container:{container}"),
            Some(&token),
        )?;
        if reply.create
            || reply.state.owner.as_ref() != Some(&owner)
            || reply.state.container_id.as_ref() != Some(&container)
        {
            return Err(StoreError::Conflict(
                "managed delivery changed its physical authority".into(),
            ));
        }
        Ok(reply)
    }

    /// The caller retains its workflow fence before this external operation.
    /// Finish waits for helper completion custody after immutable destruction.
    pub fn fence_managed(
        &mut self,
        daemon: &str,
        helper_image: &str,
        identity: &Identity,
        fence_id: &str,
    ) -> StoreResult<Reply> {
        let mut retained = self.controller(
            daemon,
            helper_image,
            identity,
            Command::Fence {
                fence_id: fence_id.into(),
            },
        )?;
        let Some(owner) = retained.state.owner.clone() else {
            return Ok(retained);
        };
        if retained.state.container_id.is_none() {
            if self.daemon_id()? != daemon {
                return Err(StoreError::Conflict("managed fence daemon changed".into()));
            }
            if let Some(actual) = self.inspect(&owner.owner_id)? {
                NativeExecutor::<Docker>::verify(&owner, &actual)?;
                retained = self.controller(
                    daemon,
                    helper_image,
                    identity,
                    Command::Bind {
                        owner: owner.clone(),
                        container_id: actual.id,
                    },
                )?;
            }
        }
        let Some(container) = retained.state.container_id.clone() else {
            return Ok(retained);
        };
        if self.daemon_id()? != daemon {
            return Err(StoreError::Conflict(
                "managed removal daemon changed".into(),
            ));
        }
        if let Some(actual) = self.inspect(&container)? {
            NativeExecutor::<Docker>::verify(&owner, &actual)?;
            if actual.id != container {
                return Err(StoreError::Conflict(
                    "managed removal target changed".into(),
                ));
            }
            if self.daemon_id()? != daemon {
                return Err(StoreError::Conflict(
                    "managed daemon changed before removal".into(),
                ));
            }
            self.remove(&container)?;
        }
        if self.daemon_id()? != daemon
            || self.inspect(&container)?.is_some()
            || self.daemon_id()? != daemon
        {
            return Err(StoreError::Conflict(
                "managed physical removal has not been established".into(),
            ));
        }
        if let Some(barrier) = &retained.state.barrier {
            if barrier["closing"] == true {
                let barrier_id = barrier["barrier_id"].as_str().ok_or_else(|| {
                    StoreError::Conflict("managed barrier identity is missing".into())
                })?;
                return self.controller(
                    daemon,
                    helper_image,
                    identity,
                    Command::Finish {
                        container_id: container,
                        barrier_id: barrier_id.into(),
                    },
                );
            }
        }
        Ok(retained)
    }
}

fn validate_profile(
    profile: &Value,
    container: &str,
    expected_digest: &str,
) -> StoreResult<String> {
    let networks = profile["networks"].as_object().is_some_and(|n| {
        (n.len() == 1 && n.contains_key("none")) || (n.is_empty() && profile["status"] == "created")
    });
    let mounts = profile["mounts"].as_array().is_some_and(|m| {
        m.iter()
            .all(|m| m["Type"] == "tmpfs" && m["Destination"] == "/tmp")
    });
    if profile["id"] != container
        || profile["network"] != "none"
        || !networks
        || profile["pid"] != ""
        || profile["privileged"] != false
        || profile["readonly"] != true
        || !mounts
        || !(profile["add"].is_null() || profile["add"] == serde_json::json!([]))
        || profile["drop"] != serde_json::json!(["ALL"])
        || profile["security"] != serde_json::json!(["no-new-privileges"])
        || profile["entrypoint"]
            != serde_json::json!(["whip", "executor", "--bind", "0.0.0.0:8080"])
        || !(profile["cmd"].is_null() || profile["cmd"] == serde_json::json!([]))
    {
        return Err(StoreError::Conflict(
            "managed Docker execution profile changed".into(),
        ));
    }
    let env = profile["env"]
        .as_array()
        .ok_or_else(|| StoreError::Conflict("managed executor environment is missing".into()))?;
    let values = |name: &str| {
        env.iter()
            .filter_map(Value::as_str)
            .filter_map(|v| v.strip_prefix(name))
            .collect::<Vec<_>>()
    };
    let pins = values("WHIP_EXECUTOR_DISPATCH_SHA256=");
    let tokens = values("WHIP_EXECUTOR_TOKEN=");
    if pins != vec![expected_digest] || tokens.len() != 1 || !digest(tokens[0]) {
        return Err(StoreError::Conflict(
            "managed executor dispatch or credential binding changed".into(),
        ));
    }
    Ok(tokens[0].to_owned())
}

#[cfg(test)]
mod tests;
