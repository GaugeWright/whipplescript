//! `whip branch create --from` / `whip branch fork --from` with the value
//! missing used to fall back to the mainline: the branch was cut from
//! somewhere the operator never named, silently. Each verb now refuses in its
//! own words, and each refusal is measured here by the branch that must NOT
//! exist afterwards — remove either guard and its test sees the branch the
//! fallback would have created.

use super::*;

struct BranchStoreFixture {
    root: PathBuf,
    previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl BranchStoreFixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "whip-branch-from-{label}-{}-{}",
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
        vcs.create_branch("named-parent", None, "main", "t1")
            .expect("parent branch");
        drop(vcs);

        Self { root, previous }
    }

    fn branch_args(&self, args: &[&str]) -> CliOptions {
        CliOptions {
            command: Some("branch".to_owned()),
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            store_path: self.root.join("store.sqlite"),
            json: false,
            input_json: None,
        }
    }

    fn parent_of(&self, branch_id: &str) -> Option<String> {
        let vcs = open_vcs().expect("vcs");
        vcs.get_branch(branch_id)
            .expect("branch lookup")
            .and_then(|row| row.parent_branch_id)
    }

    fn exists(&self, branch_id: &str) -> bool {
        let vcs = open_vcs().expect("vcs");
        vcs.get_branch(branch_id).expect("branch lookup").is_some()
    }
}

impl Drop for BranchStoreFixture {
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
fn branch_create_refuses_a_from_without_a_parent() {
    let _guard = crate::env_lock();
    let fixture = BranchStoreFixture::new("create");

    // The flag works when it is given its value: the branch is cut from the
    // branch the operator named, not the mainline.
    let code = branch_command(&fixture.branch_args(&["create", "kid", "--from", "named-parent"]));
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    assert_eq!(fixture.parent_of("kid").as_deref(), Some("named-parent"));

    // With the value missing the whole invocation is refused. Were the guard
    // removed, `--from` would fall back to the mainline and `orphan` would be
    // created from `main` — which is exactly what this asserts cannot happen.
    let code = branch_command(&fixture.branch_args(&["create", "orphan", "--from"]));
    assert_eq!(code, std::process::ExitCode::from(2));
    assert!(
        !fixture.exists("orphan"),
        "a value-less `--from` must refuse, never cut from the mainline"
    );
}

#[test]
fn branch_fork_refuses_a_from_without_a_source() {
    let _guard = crate::env_lock();
    let fixture = BranchStoreFixture::new("fork");

    let code = branch_command(&fixture.branch_args(&["fork", "kid", "--from", "named-parent"]));
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    assert_eq!(fixture.parent_of("kid").as_deref(), Some("named-parent"));

    let code = branch_command(&fixture.branch_args(&["fork", "orphan", "--from"]));
    assert_eq!(code, std::process::ExitCode::from(2));
    assert!(
        !fixture.exists("orphan"),
        "a value-less `--from` must refuse, never fork off the mainline"
    );
}
