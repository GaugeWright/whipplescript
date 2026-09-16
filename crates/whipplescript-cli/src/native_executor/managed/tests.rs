use super::*;
use serde_json::json;

fn profile() -> Value {
    json!({
        "id": "container", "network": "none", "networks": {"none": {}},
        "pid": "", "privileged": false, "readonly": true, "mounts": [],
        "add": null, "drop": ["ALL"], "security": ["no-new-privileges"],
        "entrypoint": ["whip", "executor", "--bind", "0.0.0.0:8080"],
        "cmd": null, "status": "running",
        "env": [
            format!("WHIP_EXECUTOR_DISPATCH_SHA256={}", "a".repeat(64)),
            format!("WHIP_EXECUTOR_TOKEN={}", "b".repeat(64))
        ]
    })
}

#[test]
fn managed_profile_accepts_only_isolated_pinned_execution() {
    let pin = "a".repeat(64);
    let mut valid = profile();
    assert_eq!(
        validate_profile(&valid, "container", &pin).unwrap(),
        "b".repeat(64)
    );
    valid["networks"] = json!({});
    valid["status"] = json!("created");
    valid["mounts"] = json!([{"Type": "tmpfs", "Destination": "/tmp"}]);
    valid["add"] = json!([]);
    valid["cmd"] = json!([]);
    assert!(validate_profile(&valid, "container", &pin).is_ok());
    let cases = [
        ("id", json!("replacement")),
        ("network", json!("host")),
        ("networks", json!({"none": {}, "bridge": {}})),
        ("networks", json!({})),
        ("networks", Value::Null),
        ("pid", json!("host")),
        ("privileged", json!(true)),
        ("readonly", json!(false)),
        (
            "mounts",
            json!([{"Type": "volume", "Destination": "/authority"}]),
        ),
        ("mounts", json!([{"Type": "tmpfs", "Destination": "/proc"}])),
        ("mounts", Value::Null),
        ("add", json!(["SYS_ADMIN"])),
        ("drop", json!([])),
        ("security", json!([])),
        ("entrypoint", json!(["sh"])),
        ("cmd", json!(["--other-mode"])),
        ("env", Value::Null),
        ("env", json!([])),
        (
            "env",
            json!([format!("WHIP_EXECUTOR_TOKEN={}", "b".repeat(64))]),
        ),
        (
            "env",
            json!([
                format!("WHIP_EXECUTOR_DISPATCH_SHA256={pin}"),
                "WHIP_EXECUTOR_TOKEN=invalid"
            ]),
        ),
        (
            "env",
            json!([
                format!("WHIP_EXECUTOR_DISPATCH_SHA256={}", "c".repeat(64)),
                format!("WHIP_EXECUTOR_TOKEN={}", "b".repeat(64))
            ]),
        ),
        (
            "env",
            json!([
                format!("WHIP_EXECUTOR_DISPATCH_SHA256={pin}"),
                format!("WHIP_EXECUTOR_DISPATCH_SHA256={pin}"),
                format!("WHIP_EXECUTOR_TOKEN={}", "b".repeat(64))
            ]),
        ),
        (
            "env",
            json!([
                format!("WHIP_EXECUTOR_DISPATCH_SHA256={pin}"),
                format!("WHIP_EXECUTOR_TOKEN={}", "b".repeat(64)),
                format!("WHIP_EXECUTOR_TOKEN={}", "b".repeat(64))
            ]),
        ),
    ];
    for (key, value) in cases {
        let mut changed = profile();
        changed[key] = value;
        assert!(
            validate_profile(&changed, "container", &pin).is_err(),
            "accepted changed {key}"
        );
    }
}

#[cfg(unix)]
#[test]
fn managed_creation_never_returns_or_replays_a_consumed_grant() {
    use crate::native_controller::Authority;
    use std::os::unix::fs::PermissionsExt;
    use whipplescript_kernel::exec_invocation::{Envelope, Invocation};
    let dir = std::env::temp_dir().join(format!(
        "managed-create-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let selected = Invocation {
        instance_id: "managed-fixture".into(),
        effect_id: "exec".into(),
        attempt_admission_event_id: None,
    };
    let identity = Identity {
        envelope: Envelope::new(
            selected.clone(),
            json!({"protocol":"whip-executor/1","effect_id":"exec"}),
        )
        .unwrap(),
        selected,
    };
    let owner = Owner {
        protocol: whipplescript_store::exec_native_owner::PROTOCOL.into(),
        instance_id: identity.selected.instance_id.clone(),
        effect_id: "exec".into(),
        run_id: identity.selected.run_id(),
        tracking_event_id: "track".into(),
        daemon_id: "daemon".into(),
        image_id: format!("sha256:{}", "a".repeat(64)),
        owner_id: format!("whip-exec-{}", "b".repeat(64)),
    };
    let mut authority = Authority::open(&dir.join("state.sqlite")).unwrap();
    for (name, command) in [
        ("read", Command::Read),
        (
            "claim",
            Command::Claim {
                owner: owner.clone(),
            },
        ),
        ("retained", Command::Read),
    ] {
        let reply = authority.apply(&identity, command).unwrap();
        std::fs::write(dir.join(name), serde_json::to_vec(&reply).unwrap()).unwrap();
    }
    std::fs::write(dir.join("volume"), identity.controller_id()).unwrap();
    std::fs::write(
        dir.join("labels"),
        json!({
            "whipplescript.executor.controller": identity.controller_id(),
            "whipplescript.executor.controller.protocol": crate::native_controller::PROTOCOL,
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(dir.join("cid"), "c".repeat(64)).unwrap();
    let path = dir.join("docker");
    std::fs::write(
        &path,
        r#"#!/bin/sh
here=${0%/*}
case "$3 $4" in
  'info --format') printf daemon ;;
  'volume create') cat "$here/volume" ;;
  'volume inspect') cat "$here/labels" ;;
  'run --rm')
    cat > "$here/request"
    count=$(cat "$here/count" 2>/dev/null || printf 0)
    count=$((count + 1))
    printf '%s' "$count" > "$here/count"
    case "$count" in
      1) cat "$here/read" ;;
      2) cat "$here/claim" ;;
      *) cat "$here/retained" ;;
    esac ;;
  'container create')
    printf 'create\n' >> "$here/creates"
    if [ "$(cat "$here/mode")" = lost ]; then exit 9; fi
    cat "$here/cid" ;;
  'container ls') : ;;
  *) exit 7 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    for mode in ["invisible", "lost"] {
        let _ = std::fs::remove_file(dir.join("count"));
        let _ = std::fs::remove_file(dir.join("creates"));
        std::fs::write(dir.join("mode"), mode).unwrap();
        let mut docker = Docker::new("unix:///fixture").unwrap();
        docker.program = path.clone();
        let first = docker.prepare_managed("daemon", &owner.image_id, &identity, &owner);
        if mode == "lost" {
            assert!(first.is_err());
        } else {
            let first = first.unwrap();
            assert!(
                !first.create,
                "composed adapter returned its consumed grant"
            );
            assert!(first.state.container_id.is_none());
        }
        let mut replacement = owner.clone();
        replacement.tracking_event_id = "restored-track".into();
        replacement.owner_id = format!("whip-exec-{}", "d".repeat(64));
        let retry = docker
            .prepare_managed("daemon", &owner.image_id, &identity, &replacement)
            .unwrap();
        assert!(!retry.create);
        assert_eq!(retry.state.owner.as_ref(), Some(&owner));
        assert_eq!(
            std::fs::read_to_string(dir.join("creates")).unwrap(),
            "create\n"
        );
    }
    drop(authority);
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
mod races;

#[cfg(unix)]
mod physical;
