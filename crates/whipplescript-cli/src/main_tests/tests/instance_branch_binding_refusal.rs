//! `bind_instance_to_branch` translates a `BindOutcome` into what the operator
//! is told, and that translation is the CLI's own. `branches.rs` proves the
//! store returns `GatedRef` for the mainline and `AlreadyBound` for a second
//! branch; nothing proved this layer still refuses on either. Remove one of
//! those arms and the match falls through to the success path, which appends a
//! `branch.bound` event and reports the instance bound — so each test here
//! measures the refusal by the binding that must NOT exist afterwards.

use super::*;

struct BindFixture {
    root: PathBuf,
    previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl BindFixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "whip-instance-bind-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).expect("mkdir");
        let previous: Vec<(&'static str, Option<std::ffi::OsString>)> = [
            "WHIPPLESCRIPT_BRANCH_STORE",
            "WHIPPLESCRIPT_VCS_CONTENT_STORE",
        ]
        .into_iter()
        .map(|key| (key, std::env::var_os(key)))
        .collect();
        std::env::set_var("WHIPPLESCRIPT_BRANCH_STORE", root.join("branches.sqlite"));
        std::env::set_var(
            "WHIPPLESCRIPT_VCS_CONTENT_STORE",
            root.join("content.sqlite"),
        );

        let mut vcs = open_vcs().expect("vcs");
        vcs.init("t0").expect("init");
        vcs.create_branch("work-a", None, "main", "t1")
            .expect("work branch");
        vcs.create_branch("work-b", None, "main", "t2")
            .expect("second work branch");
        drop(vcs);

        Self { root, previous }
    }

    fn store_path(&self) -> PathBuf {
        self.root.join("store.sqlite")
    }

    fn bound_to(&self, instance_id: &str) -> Option<String> {
        let vcs = open_vcs().expect("vcs");
        vcs.instance_branch(instance_id).expect("instance branch")
    }
}

impl Drop for BindFixture {
    fn drop(&mut self) {
        for (key, value) in std::mem::take(&mut self.previous) {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        std::fs::remove_dir_all(&self.root).ok();
    }
}

#[test]
fn binding_an_instance_to_the_mainline_is_refused() {
    let _guard = crate::env_lock();
    let fixture = BindFixture::new("gated");

    // A work branch binds, so the refusal below is about the ref and not about
    // the fixture being unable to bind anything at all.
    bind_instance_to_branch(&fixture.store_path(), "ins_gated", "work-a").expect("work branch");
    assert_eq!(fixture.bound_to("ins_gated").as_deref(), Some("work-a"));

    let refusal = bind_instance_to_branch(&fixture.store_path(), "ins_main", "main")
        .expect_err("the mainline is a gated ref");
    assert!(
        refusal.contains("is gated") && refusal.contains("work branch"),
        "unexpected refusal: {refusal}"
    );
    assert_eq!(
        fixture.bound_to("ins_main"),
        None,
        "a refused bind must leave the instance bound to nothing"
    );
}

#[test]
fn rebinding_an_instance_to_a_second_branch_is_refused() {
    let _guard = crate::env_lock();
    let fixture = BindFixture::new("rebound");

    bind_instance_to_branch(&fixture.store_path(), "ins_1", "work-a").expect("first bind");
    // Same branch again is the idempotent retry, not a rebind.
    bind_instance_to_branch(&fixture.store_path(), "ins_1", "work-a").expect("idempotent retry");

    let refusal = bind_instance_to_branch(&fixture.store_path(), "ins_1", "work-b")
        .expect_err("an instance is born on one branch");
    assert!(
        refusal.contains("already bound to branch") && refusal.contains("work-a"),
        "the refusal must name the branch it is already on: {refusal}"
    );
    assert_eq!(
        fixture.bound_to("ins_1").as_deref(),
        Some("work-a"),
        "a refused rebind must not move the instance"
    );
}

/// `norm_pass_absorbs` is the worker's answer to "does this failure end the
/// pass?", and every arm of it is load-bearing in a direction no container is
/// needed to state. Absorb too little and a host with scripts hard-off reports
/// a broken worker; absorb too much and an error the worker cannot interpret
/// drops the remaining effects silently.
#[test]
fn a_norm_pass_absorbs_only_what_a_later_pass_can_retry() {
    use whipplescript_store::StoreError;

    // "Not now": the effect is left for a later pass.
    assert!(norm_pass_absorbs(&StoreError::Conflict("refused".into())));
    assert!(norm_pass_absorbs(&StoreError::CapacityBlocked {
        effect_id: "e".into(),
        reason: "full".into(),
    }));
    for reason in [
        "security.script_disabled: exec is hard-off here",
        "capacity exhausted for this worker",
    ] {
        assert!(
            norm_pass_absorbs(&StoreError::PolicyBlocked {
                effect_id: "e".into(),
                reason: reason.into(),
            }),
            "a pass must finish on a host that blocks for `{reason}`"
        );
    }

    // Everything else ends the pass. A policy block the worker does not
    // recognise is NOT "not now" -- absorbing it would skip the effect every
    // pass, forever, and report the worker idle.
    assert!(!norm_pass_absorbs(&StoreError::PolicyBlocked {
        effect_id: "e".into(),
        reason: "operator revoked this capability".into(),
    }));
    // A FAULT is the store saying something it cannot explain. Absorbing one
    // would let a pass walk past corruption and report itself healthy -- the
    // exact shape `StoreError::fault` exists to keep out of `Conflict`.
    assert!(!norm_pass_absorbs(&StoreError::fault(
        "runtime store",
        "missing immediately after the write that should have created it",
    )));
}
