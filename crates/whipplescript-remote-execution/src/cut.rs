//! The versioned encoding between a workspace cut and remote-execution
//! objects (DR-0124 §14.3): `whipplescript.build.input-root/v1`.
//!
//! A cut's manifest maps paths to the workspace content store's ids, which
//! are truncated hashes of the bytes; a remote-execution input root is a
//! Merkle tree of `Directory` messages over full SHA-256 digests. Neither is
//! the other, so the encoding is explicit: every file's bytes are read from
//! the cut, digested as the protocol digests them, and stored under the
//! encoding view's uses with the labels of the file's path; the directories
//! are built bottom-up in the protocol's canonical order and stored the same
//! way. The root digest is recorded as provenance beside the cut it encodes.

use std::collections::BTreeMap;

use prost::Message;

use crate::digest::Digest;
use crate::proto::re;
use crate::store::{Labels, Store, View};

pub const INPUT_ROOT_ENCODING_V1: &str = "whipplescript.build.input-root/v1";

/// What a cut encoded to.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EncodedCut {
    pub encoding: String,
    pub cut: String,
    pub input_root: Digest,
    pub files: usize,
    pub directories: usize,
}

#[derive(Default)]
struct Node {
    files: BTreeMap<String, (Digest, bool)>,
    children: BTreeMap<String, Node>,
}

impl Node {
    fn insert(&mut self, path: &str, digest: Digest, executable: bool) -> Result<(), String> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
        {
            return Err(format!("a cut path is not a tree path: {path}"));
        }
        // A split yields at least one part, and no part is empty here.
        let (name, directories) = parts.split_last().expect("a path has a last part");
        let mut node = self;
        for part in directories {
            node = node.children.entry((*part).to_owned()).or_default();
        }
        node.files.insert((*name).to_owned(), (digest, executable));
        Ok(())
    }
}

/// Encode a cut's manifest into an input root under `view`, reading each
/// path's bytes with `read` and labeling each file's use with `labels_of`.
pub fn encode_cut(
    store: &Store,
    view: &View,
    cut: &str,
    manifest: &BTreeMap<String, String>,
    mut read: impl FnMut(&str) -> Result<Vec<u8>, String>,
    labels_of: impl Fn(&str) -> Labels,
) -> Result<EncodedCut, String> {
    let mut root = Node::default();
    let mut files = 0;
    for path in manifest.keys() {
        let bytes = read(path)?;
        let executable = path.ends_with(".sh");
        let digest = store.put(view, &bytes, &labels_of(path));
        root.insert(path, digest, executable)?;
        files += 1;
    }
    let mut directories = 0;
    let input_root = store_directory(store, view, &root, &labels_of, "", &mut directories);
    Ok(EncodedCut {
        encoding: INPUT_ROOT_ENCODING_V1.into(),
        cut: cut.to_owned(),
        input_root,
        files,
        directories,
    })
}

fn store_directory(
    store: &Store,
    view: &View,
    node: &Node,
    labels_of: &impl Fn(&str) -> Labels,
    prefix: &str,
    count: &mut usize,
) -> Digest {
    let mut labels = Labels::new();
    let directory = re::Directory {
        files: node
            .files
            .iter()
            .map(|(name, (digest, executable))| {
                labels.extend(labels_of(&join(prefix, name)));
                re::FileNode {
                    name: name.clone(),
                    digest: Some(digest.to_proto()),
                    is_executable: *executable,
                    node_properties: None,
                }
            })
            .collect(),
        directories: node
            .children
            .iter()
            .map(|(name, child)| {
                let child_prefix = join(prefix, name);
                let digest = store_directory(store, view, child, labels_of, &child_prefix, count);
                labels.extend(labels_of(&child_prefix));
                re::DirectoryNode {
                    name: name.clone(),
                    digest: Some(digest.to_proto()),
                }
            })
            .collect(),
        symlinks: Vec::new(),
        node_properties: None,
    };
    *count += 1;
    // A directory's listing is a disclosure of its members' names: its use
    // carries the join of their labels.
    store.put(view, &directory.encode_to_vec(), &labels)
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    }
}

/// Decode an input root under a view back into path → digest, walking only
/// what the view can read; a directory the view cannot read ends the walk
/// with a refusal rather than an emptier tree.
pub fn decode_input_root(
    store: &Store,
    view: &View,
    root: &Digest,
) -> Result<BTreeMap<String, (Digest, bool)>, String> {
    let mut out = BTreeMap::new();
    walk(store, view, root, "", &mut out)?;
    Ok(out)
}

fn walk(
    store: &Store,
    view: &View,
    digest: &Digest,
    prefix: &str,
    out: &mut BTreeMap<String, (Digest, bool)>,
) -> Result<(), String> {
    let bytes = store
        .get(view, digest)
        .ok_or_else(|| format!("directory {digest} is missing under this view"))?;
    let directory = re::Directory::decode(bytes.as_slice())
        .map_err(|error| format!("directory {digest} does not decode: {error}"))?;
    for file in &directory.files {
        let file_digest = file
            .digest
            .as_ref()
            .ok_or_else(|| format!("file {} has no digest", file.name))?;
        out.insert(
            join(prefix, &file.name),
            (Digest::from_proto(file_digest)?, file.is_executable),
        );
    }
    for child in &directory.directories {
        let child_digest = child
            .digest
            .as_ref()
            .ok_or_else(|| format!("directory {} has no digest", child.name))?;
        walk(
            store,
            view,
            &Digest::from_proto(child_digest)?,
            &join(prefix, &child.name),
            out,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{HandleId, Principal};

    fn manifest() -> BTreeMap<String, String> {
        [
            ("FIXTURE", "f0"),
            ("tests/passing.sh", "p0"),
            ("secret-gate/FIXTURE", "f1"),
            ("secret-gate/protected/flag", "s0"),
        ]
        .into_iter()
        .map(|(p, h)| (p.to_owned(), h.to_owned()))
        .collect()
    }

    fn view(store: &Store, name: &str, labels: &[&str]) -> View {
        store
            .admit(
                HandleId(format!("h-{name}")),
                Principal {
                    name: name.into(),
                    labels: labels.iter().map(|l| l.to_string()).collect(),
                },
            )
            .unwrap()
    }

    fn labels_of(path: &str) -> Labels {
        if path.starts_with("secret-gate/protected/") {
            ["protected".to_owned()].into_iter().collect()
        } else {
            Labels::new()
        }
    }

    #[test]
    fn a_cut_encodes_to_a_merkle_input_root_and_decodes_only_under_a_view_that_holds_it() {
        let store = Store::new();
        let owner = view(&store, "owner", &["protected"]);
        let encoded = encode_cut(
            &store,
            &owner,
            "cut-1",
            &manifest(),
            |path| Ok(format!("body of {path}").into_bytes()),
            labels_of,
        )
        .unwrap();
        assert_eq!(encoded.encoding, INPUT_ROOT_ENCODING_V1);
        assert_eq!(encoded.cut, "cut-1");
        assert_eq!(encoded.files, 4);
        assert_eq!(encoded.directories, 4);
        // The same cut encodes to the same root: the encoding is canonical.
        let again = encode_cut(
            &store,
            &owner,
            "cut-1",
            &manifest(),
            |path| Ok(format!("body of {path}").into_bytes()),
            labels_of,
        )
        .unwrap();
        assert_eq!(again.input_root, encoded.input_root);
        let decoded = decode_input_root(&store, &owner, &encoded.input_root).unwrap();
        assert_eq!(decoded.len(), 4);
        assert_eq!(
            decoded["tests/passing.sh"],
            (Digest::of(b"body of tests/passing.sh"), true)
        );
        assert!(!decoded["FIXTURE"].1);
        // dev holds no protected label: the tree is missing under their view
        // at the first directory whose listing they may not read.
        let dev = view(&store, "dev", &[]);
        assert_eq!(
            decode_input_root(&store, &dev, &encoded.input_root).unwrap_err(),
            format!(
                "directory {} is missing under this view",
                encoded.input_root
            )
        );
        let mut bad = manifest();
        bad.insert("../escape".into(), "x".into());
        assert_eq!(
            encode_cut(&store, &owner, "cut-2", &bad, |_| Ok(Vec::new()), labels_of).unwrap_err(),
            "a cut path is not a tree path: ../escape"
        );
    }
}
