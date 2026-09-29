//! Exact native Git candidate pins for the reviewed-contribution record.
//! This invokes a local bare repository; it serves no Git network endpoint.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::source_review::{ReviewError, ReviewResult};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitPin {
    pub contribution_id: String,
    pub upload_id: String,
    pub source_ref: String,
    pub commit_oid: String,
    pub tree_oid: String,
    pub pin_ref: String,
}

pub struct GitCandidatePins {
    git_dir: PathBuf,
}

impl GitCandidatePins {
    pub fn open(git_dir: impl AsRef<Path>) -> ReviewResult<Self> {
        let git_dir = git_dir.as_ref().to_path_buf();
        if git(&git_dir, &["rev-parse", "--is-bare-repository"])? != "true" {
            return Err(ReviewError::Invalid(
                "candidate source must be a bare Git repository".into(),
            ));
        }
        Ok(Self { git_dir })
    }

    /// The ref is created only when absent. Retrying the same upload is
    /// idempotent while the source branch retains that commit; reusing its
    /// identity for different content is refused.
    /// A later source branch tail does not change the selected commit.
    pub fn pin(
        &self,
        contribution_id: &str,
        upload_id: &str,
        source_ref: &str,
        commit_oid: &str,
    ) -> ReviewResult<GitPin> {
        let pin_ref = format!("refs/reviews/{contribution_id}/{upload_id}");
        git(&self.git_dir, &["check-ref-format", &pin_ref])?;
        git(&self.git_dir, &["check-ref-format", source_ref])?;
        if !source_ref.starts_with("refs/heads/") {
            return Err(ReviewError::Invalid(
                "candidate source must be a branch ref".into(),
            ));
        }
        let resolved = git(
            &self.git_dir,
            &["rev-parse", "--verify", &format!("{commit_oid}^{{commit}}")],
        )?;
        if resolved != commit_oid {
            return Err(ReviewError::Invalid(
                "candidate needs a full commit object id".into(),
            ));
        }
        let source_head_oid = git(&self.git_dir, &["rev-parse", "--verify", source_ref])?;
        if git_status(
            &self.git_dir,
            &["merge-base", "--is-ancestor", commit_oid, &source_head_oid],
        )? != 0
        {
            return Err(ReviewError::Invalid(
                "candidate is outside its declared source ref".into(),
            ));
        }
        let tree_oid = git(
            &self.git_dir,
            &["rev-parse", &format!("{commit_oid}^{{tree}}")],
        )?;
        let zero = "0".repeat(commit_oid.len());
        if let Err(create_error) = git(&self.git_dir, &["update-ref", &pin_ref, commit_oid, &zero])
        {
            let existing = git(
                &self.git_dir,
                &["rev-parse", "--verify", "--quiet", &pin_ref],
            )
            .map_err(|_| create_error)?;
            if existing != commit_oid {
                return Err(ReviewError::Conflict(
                    "upload id already pins another commit".into(),
                ));
            }
        }
        let pin = GitPin {
            contribution_id: contribution_id.into(),
            upload_id: upload_id.into(),
            source_ref: source_ref.into(),
            commit_oid: commit_oid.into(),
            tree_oid,
            pin_ref,
        };
        self.verify(&pin)?;
        Ok(pin)
    }

    pub fn verify(&self, pin: &GitPin) -> ReviewResult<()> {
        let actual = git(
            &self.git_dir,
            &["rev-parse", "--verify", "--quiet", &pin.pin_ref],
        )
        .ok();
        if actual.as_deref() != Some(pin.commit_oid.as_str()) {
            return Err(ReviewError::Corrupt(
                "candidate pin is missing or moved".into(),
            ));
        }
        let actual_tree = git(
            &self.git_dir,
            &["rev-parse", &format!("{}^{{tree}}", pin.commit_oid)],
        )?;
        if actual_tree != pin.tree_oid {
            return Err(ReviewError::Corrupt(
                "candidate tree disagrees with its commit".into(),
            ));
        }
        Ok(())
    }

    /// Recover a pin after the review store recorded an upload but before it
    /// published the revision. This does not consult the moving source branch.
    pub fn recover(
        &self,
        contribution_id: &str,
        upload_id: &str,
        source_ref: &str,
        commit_oid: &str,
    ) -> ReviewResult<Option<GitPin>> {
        let pin_ref = format!("refs/reviews/{contribution_id}/{upload_id}");
        git(&self.git_dir, &["check-ref-format", &pin_ref])?;
        match git_status(
            &self.git_dir,
            &["show-ref", "--verify", "--quiet", &pin_ref],
        )? {
            0 => {}
            1 => return Ok(None),
            status => return Err(ReviewError::Git(format!("Git show-ref exited {status}"))),
        }
        let actual = git(&self.git_dir, &["rev-parse", "--verify", &pin_ref])?;
        if actual != commit_oid {
            return Err(ReviewError::Conflict(
                "pending upload pin names another commit".into(),
            ));
        }
        let tree_oid = git(
            &self.git_dir,
            &["rev-parse", &format!("{commit_oid}^{{tree}}")],
        )?;
        Ok(Some(GitPin {
            contribution_id: contribution_id.into(),
            upload_id: upload_id.into(),
            source_ref: source_ref.into(),
            commit_oid: commit_oid.into(),
            tree_oid,
            pin_ref,
        }))
    }
}

fn git(git_dir: &Path, args: &[&str]) -> ReviewResult<String> {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(ReviewError::Git(
            String::from_utf8_lossy(&output.stderr).trim().into(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().into())
}

fn git_status(git_dir: &Path, args: &[&str]) -> ReviewResult<i32> {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(args)
        .output()?;
    exit_code(output.status)
}

fn exit_code(status: std::process::ExitStatus) -> ReviewResult<i32> {
    status
        .code()
        .ok_or_else(|| ReviewError::Git("Git command was interrupted".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        bare: PathBuf,
        work: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let number = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "whipplescript-review-git-{}-{number}",
                std::process::id()
            ));
            let bare = root.join("source.git");
            let work = root.join("work");
            std::fs::create_dir_all(&work).expect("create fixture");
            run(
                None,
                &["init", "--bare", "-q", bare.to_str().expect("bare path")],
            );
            run(Some(&work), &["init", "-q"]);
            run(
                Some(&work),
                &["config", "user.email", "author@example.test"],
            );
            run(Some(&work), &["config", "user.name", "Author"]);
            run(Some(&work), &["checkout", "-qb", "work"]);
            Self { root, bare, work }
        }

        fn commit(&self, content: &str) -> String {
            std::fs::write(self.work.join("story.txt"), content).expect("write story");
            run(Some(&self.work), &["add", "story.txt"]);
            run(Some(&self.work), &["commit", "-qm", "candidate"]);
            run(
                Some(&self.work),
                &[
                    "push",
                    "-q",
                    self.bare.to_str().expect("bare path"),
                    "HEAD:refs/heads/work",
                ],
            );
            run(Some(&self.work), &["rev-parse", "HEAD"])
        }

        fn pins(&self) -> GitCandidatePins {
            GitCandidatePins::open(&self.bare).expect("open pins")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).expect("remove fixture");
        }
    }

    fn run(work: Option<&Path>, args: &[&str]) -> String {
        let mut command = Command::new("git");
        if let Some(work) = work {
            command.arg("-C").arg(work);
        }
        let output = command.args(args).output().expect("run Git");
        assert!(
            output.status.success(),
            "git {:?}: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().into()
    }

    #[test]
    fn pin_keeps_an_exact_commit_while_the_source_branch_advances() {
        let fixture = Fixture::new();
        let first = fixture.commit("one\n");
        let pins = fixture.pins();
        let pin = pins
            .pin("C1", "upload-one", "refs/heads/work", &first)
            .expect("pin first");
        assert_eq!(pin.commit_oid, first);
        let tail = fixture.commit("one\ntwo\n");
        assert_ne!(tail, first);
        pins.verify(&pin).expect("old pin survives tail");
        assert_eq!(
            pins.pin("C1", "upload-one", "refs/heads/work", &first)
                .expect("idempotent retry"),
            pin
        );
    }

    #[test]
    fn invalid_source_and_reused_pin_are_refused() {
        let fixture = Fixture::new();
        let first = fixture.commit("one\n");
        let pins = fixture.pins();
        assert!(matches!(
            pins.pin("C1", "bad", "refs/tags/v1", &first),
            Err(ReviewError::Invalid(_))
        ));
        assert!(matches!(
            pins.pin("C1", "short", "refs/heads/work", &first[..12]),
            Err(ReviewError::Invalid(_))
        ));
        pins.pin("C1", "upload-one", "refs/heads/work", &first)
            .expect("first pin");
        let second = fixture.commit("two\n");
        assert!(matches!(
            pins.pin("C1", "upload-one", "refs/heads/work", &second),
            Err(ReviewError::Conflict(_))
        ));
        run(Some(&fixture.work), &["checkout", "--orphan", "unrelated"]);
        std::fs::write(fixture.work.join("story.txt"), "unrelated\n").expect("write");
        run(Some(&fixture.work), &["add", "story.txt"]);
        run(Some(&fixture.work), &["commit", "-qm", "unrelated"]);
        let outside = run(Some(&fixture.work), &["rev-parse", "HEAD"]);
        run(
            Some(&fixture.work),
            &[
                "push",
                "-q",
                fixture.bare.to_str().expect("bare path"),
                "HEAD:refs/heads/unrelated",
            ],
        );
        assert!(matches!(
            pins.pin("C1", "outside", "refs/heads/work", &outside),
            Err(ReviewError::Invalid(message))
                if message == "candidate is outside its declared source ref"
        ));
    }

    #[test]
    fn moved_pin_and_non_bare_repository_are_refused() {
        let fixture = Fixture::new();
        assert!(matches!(
            GitCandidatePins::open(fixture.work.join(".git")),
            Err(ReviewError::Invalid(_))
        ));
        let first = fixture.commit("one\n");
        let pins = fixture.pins();
        let pin = pins
            .pin("C1", "upload-one", "refs/heads/work", &first)
            .expect("pin");
        let second = fixture.commit("two\n");
        git(
            &fixture.bare,
            &["update-ref", &pin.pin_ref, &second, &first],
        )
        .expect("simulate authority violation");
        assert!(matches!(pins.verify(&pin), Err(ReviewError::Corrupt(_))));
    }

    #[test]
    fn failed_git_command_is_reported() {
        let fixture = Fixture::new();
        assert!(matches!(
            git(&fixture.bare, &["check-ref-format", "bad ref"]),
            Err(ReviewError::Git(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_git_command_is_reported() {
        use std::os::unix::process::ExitStatusExt;
        assert!(matches!(
            exit_code(std::process::ExitStatus::from_raw(9)),
            Err(ReviewError::Git(message)) if message == "Git command was interrupted"
        ));
    }

    #[test]
    fn recovery_distinguishes_missing_conflicting_and_broken_pins() {
        let fixture = Fixture::new();
        let first = fixture.commit("one\n");
        let pins = fixture.pins();
        assert!(pins
            .recover("C1", "upload-one", "refs/heads/work", &first)
            .expect("missing pin")
            .is_none());
        pins.pin("C1", "upload-one", "refs/heads/work", &first)
            .expect("pin");
        let second = fixture.commit("two\n");
        assert!(matches!(
            pins.recover("C1", "upload-one", "refs/heads/work", &second),
            Err(ReviewError::Conflict(message)) if message == "pending upload pin names another commit"
        ));
        std::fs::rename(&fixture.bare, fixture.root.join("moved.git"))
            .expect("simulate missing Git repository");
        assert!(matches!(
            pins.recover("C1", "upload-one", "refs/heads/work", &first),
            Err(ReviewError::Git(message)) if message.starts_with("Git show-ref exited")
        ));
    }
}
