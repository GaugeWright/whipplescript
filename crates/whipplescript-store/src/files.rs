//! File-store seam (DR-0033 Phase 4).
//!
//! File effects (`file.read` / `file.write` / `file.import` / `file.export`)
//! route their raw byte I/O through this trait so a second physical tier can back
//! files without the language changing: the durable-object host inlines small
//! files in DO SQLite (transactional with fact-derivation) and spills large ones
//! to a platform object store (Phase 7), while the native CLI backs files with
//! `std::fs` under a workspace root. Path resolution and the `file store` policy
//! boundary stay in the effect handler; only the byte I/O crosses this seam.
//!
//! The trait is intentionally minimal — exactly the operations the file effects
//! perform today. The content-hash-handle / tiering model of DR-0033 Decision 4
//! is layered on later (Phase 7) behind the same seam.

use std::io;
use std::path::{Path, PathBuf};

/// Exact content identity within a host-verified compartment. This descriptor
/// carries no bytes and grants no access to a store merely by naming a hash.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileContentReference {
    pub content_hash: String,
    pub label_ref: String,
}

impl FileContentReference {
    /// Validate descriptor syntax only. Current compartment access remains a
    /// host obligation; diagnostics must never echo untrusted descriptor data.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.content_hash.len() != 32
            || !self
                .content_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("file content reference requires a canonical content-store hash");
        }
        if self.label_ref.trim().is_empty() {
            return Err("file content reference requires a nonblank label");
        }
        Ok(())
    }
}

/// The exact result accepted by a reference-based write. Structured operation
/// evidence is retained separately under its own label, as for text writes.
#[derive(Debug)]
pub struct FileReferenceWriteAccepted {
    pub reference: FileContentReference,
    pub byte_len: usize,
    pub evidence: Option<FileWriteEvidence>,
}

/// Durable dispatch coordinates supplied by the governed handler after its
/// run-start commit. These locate evidence; possession is not authorization.
#[derive(Clone, Copy, Debug)]
pub struct FileWriteContext<'a> {
    pub instance_id: &'a str,
    pub effect_id: &'a str,
    pub run_id: &'a str,
    pub started_event_id: &'a str,
}

/// A structured operation result awaiting content-addressed retention by the
/// handler. Bodies stay behind the resulting labeled reference in run/fact
/// metadata; this payload is never copied into an action command.
#[derive(Clone, Debug)]
pub struct FileWriteEvidence {
    pub schema_ref: String,
    pub label_ref: String,
    pub content: String,
}

#[derive(Debug)]
pub struct FileWriteAccepted {
    pub content: String,
    pub evidence: Option<FileWriteEvidence>,
}

#[derive(Debug)]
pub struct FileWriteFailure {
    pub error: io::Error,
    pub evidence: Option<FileWriteEvidence>,
}

impl From<io::Error> for FileWriteFailure {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            evidence: None,
        }
    }
}

/// The byte-I/O operations a file effect performs, abstracted over the physical
/// backing. Object-safe so a durable-object backend can be used as `&dyn`.
pub trait FileStore {
    /// Pure declaration of a scoped versioned-save realization. Wrappers must
    /// forward it unchanged. It describes the actual binding used by their I/O;
    /// neither the descriptor nor this query grants authority to access it.
    fn scoped_save_binding(
        &self,
    ) -> Option<(
        &crate::vcs_file_save::VersionedSaveBinding,
        &crate::vcs::resolution_scope::ResolutionMemoryScope,
    )> {
        None
    }

    /// Resolve an admitted immutable input without passing its body through an
    /// effect value. Unsupported stores must not fall back to an inline read.
    fn read_content_reference(&self, _path: &Path) -> io::Result<FileContentReference> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file store does not support content-reference reads",
        ))
    }

    /// Apply an exact host-bound reference using the ordinary governed write
    /// coordinates. Possession of this descriptor is not permission to resolve
    /// it, and an unsupported store cannot substitute an ambient CAS lookup.
    fn write_content_reference(
        &self,
        _path: &Path,
        _reference: &FileContentReference,
        _context: FileWriteContext<'_>,
    ) -> Result<FileReferenceWriteAccepted, FileWriteFailure> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file store does not support content-reference writes",
        )
        .into())
    }

    /// Read the whole file at `path` as UTF-8 text.
    fn read_to_string(&self, path: &Path) -> io::Result<String>;

    /// Whether a file exists at `path` (the write-mode precondition check).
    fn exists(&self, path: &Path) -> bool;

    /// Ensure the directory at `path` (and its parents) exists.
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;

    /// Write `bytes` to `path`, replacing any existing contents.
    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;

    /// Write text and return the exact text accepted by this operation. A
    /// merge-aware backend overrides this so runtime evidence captures the
    /// merged result, rather than incorrectly hashing the submitted draft.
    /// The replacement default matches the existing byte-write contract.
    /// Returning text supplies content evidence, not proof of external
    /// disposition or permission to retry an uncertain operation.
    fn write_text(&self, path: &Path, content: &str) -> io::Result<String> {
        self.write(path, content.as_bytes())?;
        Ok(content.to_owned())
    }

    /// A versioned binding can return its accepted cut or structured conflict
    /// and bind that result to the exact dispatch. Legacy byte stores retain
    /// their existing semantics and make no operation-receipt claim.
    fn write_text_with_context(
        &self,
        path: &Path,
        content: &str,
        _context: FileWriteContext<'_>,
    ) -> Result<FileWriteAccepted, FileWriteFailure> {
        self.write_text(path, content)
            .map(|content| FileWriteAccepted {
                content,
                evidence: None,
            })
            .map_err(Into::into)
    }

    /// Append `bytes` to `path`, creating it if absent.
    fn append(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;

    /// Remove the file at `path`. Restorable-context restore (RC-5) uses this to
    /// drop mediated files created after a cut so the file plane equals exactly
    /// the cut manifest. Removing an absent path is a no-op (idempotent).
    fn remove(&self, path: &Path) -> io::Result<()>;

    /// Optional host-level path check after the language-level lexical policy.
    /// Native filesystems need this to reject symlink escapes; virtual stores
    /// can use the default because no host symlinks are traversed.
    fn path_policy_error(
        &self,
        _root: &Path,
        _relative_path: &Path,
        _store_name: &str,
        _operation: &str,
    ) -> Option<String> {
        None
    }
}

/// Native backing: files live on the local filesystem (the workspace root is
/// applied by the caller before the path reaches this store).
pub struct NativeFileStore;

impl FileStore for NativeFileStore {
    fn path_policy_error(
        &self,
        root: &Path,
        relative_path: &Path,
        store_name: &str,
        _operation: &str,
    ) -> Option<String> {
        let root_path = if root.as_os_str().is_empty() {
            Path::new(".")
        } else {
            root
        };
        let canonical_root = match root_path.canonicalize() {
            Ok(path) => path,
            Err(_) => return None,
        };
        let full = root_path.join(relative_path);
        let anchor = if full.exists() {
            Some(full)
        } else {
            full.parent()
                .map(Path::to_path_buf)
                .and_then(nearest_existing_ancestor)
        };
        let anchor = anchor?;
        match anchor.canonicalize() {
            Ok(canonical_anchor) if canonical_anchor.starts_with(&canonical_root) => None,
            Ok(_) => Some(format!(
                "path `{}` escapes the `{store_name}` store root",
                relative_path.display()
            )),
            Err(_) => None,
        }
    }

    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        std::fs::write(path, bytes)
    }

    fn append(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?
            .write_all(bytes)
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            // Idempotent: an already-absent file is not an error.
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn nearest_existing_ancestor(mut path: PathBuf) -> Option<PathBuf> {
    loop {
        if path.exists() {
            return Some(path);
        }
        if !path.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unimplemented_content_references_refuse_without_text_fallback() {
        let files: &dyn FileStore = &NativeFileStore;
        let reference = FileContentReference {
            content_hash: crate::stable_hash_hex("protected"),
            label_ref: "private".into(),
        };
        let path = Path::new("/not-an-admitted-reference");
        let read = files.read_content_reference(path).unwrap_err();
        assert_eq!(read.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            read.to_string(),
            "file store does not support content-reference reads"
        );
        let write = files
            .write_content_reference(
                path,
                &reference,
                FileWriteContext {
                    instance_id: "instance",
                    effect_id: "effect",
                    run_id: "attempt",
                    started_event_id: "start",
                },
            )
            .unwrap_err()
            .error;
        assert_eq!(write.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            write.to_string(),
            "file store does not support content-reference writes"
        );
        let mut value = serde_json::to_value(&reference).expect("serialize");
        value["body"] = serde_json::json!("protected");
        assert!(serde_json::from_value::<FileContentReference>(value).is_err());
    }

    #[test]
    fn content_reference_requires_canonical_hash_and_nonblank_label() {
        let reference = FileContentReference {
            content_hash: crate::stable_hash_hex("protected"),
            label_ref: "input-private".into(),
        };
        assert_eq!(reference.validate(), Ok(()));
        for hash in [
            "".to_owned(),
            "a".repeat(31),
            "a".repeat(33),
            "G".repeat(32),
            "A".repeat(32),
            "é".repeat(16),
        ] {
            assert_eq!(
                FileContentReference {
                    content_hash: hash,
                    ..reference.clone()
                }
                .validate(),
                Err("file content reference requires a canonical content-store hash")
            );
        }
        for label in ["", " ", "\t\n", "\u{2003}"] {
            assert_eq!(
                FileContentReference {
                    label_ref: label.into(),
                    ..reference.clone()
                }
                .validate(),
                Err("file content reference requires a nonblank label")
            );
        }
    }

    /// Drive the native store through `&dyn FileStore`: proves object-safety (a
    /// boxed durable-object backend is legal) and that write / read / append /
    /// exists round-trip as the file effects expect.
    #[test]
    fn native_file_store_round_trips_through_the_trait() {
        let dir = std::env::temp_dir().join(format!(
            "whipplescript-filestore-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        let path = dir.join("nested/note.txt");
        let files: &dyn FileStore = &NativeFileStore;

        assert!(!files.exists(&path));
        files
            .create_dir_all(path.parent().expect("parent"))
            .expect("mkdir");
        files.write(&path, b"hello").expect("write");
        assert!(files.exists(&path));
        assert_eq!(files.read_to_string(&path).expect("read"), "hello");
        files.append(&path, b" world").expect("append");
        assert_eq!(files.read_to_string(&path).expect("read"), "hello world");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn native_file_store_refuses_symlink_escape() {
        let dir = std::env::temp_dir().join(format!(
            "whipplescript-filestore-link-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        let root = dir.join("root");
        let outside = dir.join("outside");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("secret.txt"), b"secret").expect("secret");
        std::os::unix::fs::symlink(&outside, root.join("link")).expect("symlink");

        let files = NativeFileStore;
        let reason = files
            .path_policy_error(&root, Path::new("link/secret.txt"), "workspace", "read")
            .expect("symlink escapes root");
        assert!(reason.contains("escapes"), "{reason}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
