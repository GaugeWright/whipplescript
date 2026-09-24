//! The endpoint: the store, the action cache and the compute plane's runner
//! behind the four services, with the one operation they share — executing
//! an action under a view.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use prost::Message;

use crate::cache::{ActionCache, Classification, Entry, CLASSIFICATION_TYPE_URL};
use crate::cut::decode_input_root;
use crate::db::Db;
use crate::digest::Digest;
use crate::proto::re;
use crate::runner::{ActionRunner, Output, PreparedAction};
use crate::store::{HandleId, Labels, Principal, Store, View};

/// The platform property a client may set to classify its actions' results
/// beyond what their inputs carry (the wrapper passes the package ceiling
/// of §14.2 this way): a comma-separated list of labels.
pub const LABELS_PROPERTY: &str = "whipplescript.labels";

/// The metadata key a direct client names its handle under.
pub const HANDLE_HEADER: &str = "x-whipplescript-handle";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
const INLINE_LIMIT: usize = 64 * 1024;

/// Why an execution did not happen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecuteRefusal {
    /// Inputs the view cannot read: reported as missing under it, never as
    /// absent from the store.
    Missing(Vec<Digest>),
    /// The action is malformed.
    Invalid(String),
    /// The result is classified beyond the caller's view.
    Classified(Labels),
    /// The runner failed.
    Failed(String),
}

/// An execution's answer.
#[derive(Clone, Debug)]
pub struct Executed {
    pub result: re::ActionResult,
    pub cached: bool,
}

pub struct Endpoint {
    pub store: Store,
    pub cache: ActionCache,
    runner: Arc<dyn ActionRunner>,
    /// The handle header-less connections act under: the daemon this
    /// endpoint was started for, or none.
    daemon: Option<HandleId>,
    operations: Mutex<HashMap<String, Executed>>,
}

impl Endpoint {
    /// An endpoint whose store and cache live as long as the process.
    pub fn new(runner: Arc<dyn ActionRunner>) -> Self {
        Self::over(runner, Db::in_memory())
    }

    /// An endpoint whose store and cache are the database at `state`, so what
    /// it stored and executed outlives it: the next process over the same
    /// file serves the same principals the same answers.
    pub fn open(runner: Arc<dyn ActionRunner>, state: &std::path::Path) -> Result<Self, String> {
        Ok(Self::over(runner, Db::open(state)?))
    }

    /// An endpoint whose uses and cache are the database at `state` and whose
    /// bytes are the workspace's content store at `content` (§14.3): one copy
    /// of every blob, under the workspace's erasure.
    pub fn open_sharing(
        runner: Arc<dyn ActionRunner>,
        state: &std::path::Path,
        content: &std::path::Path,
    ) -> Result<Self, String> {
        let db = Db::open(state)?;
        let shared =
            whipplescript_store::content::ContentStore::open(content).map_err(|error| {
                format!(
                    "cannot open the workspace's content store {}: {error:?}",
                    content.display()
                )
            })?;
        Ok(Self::with_store(
            runner,
            Store::sharing(db.clone(), shared)?,
            db,
        ))
    }

    fn over(runner: Arc<dyn ActionRunner>, db: Db) -> Self {
        Self::with_store(runner, Store::over(db.clone()), db)
    }

    fn with_store(runner: Arc<dyn ActionRunner>, store: Store, db: Db) -> Self {
        Self {
            store,
            cache: ActionCache::over(db),
            runner,
            daemon: None,
            operations: Mutex::new(HashMap::new()),
        }
    }

    /// Mint a handle for a principal: a random token only its holder knows.
    pub fn admit(&self, principal: Principal) -> Result<(HandleId, View), String> {
        let token: String = {
            use rand::RngCore;
            let mut bytes = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut bytes);
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        };
        let handle = HandleId(token);
        let view = self.store.admit(handle.clone(), principal)?;
        Ok((handle, view))
    }

    /// Make one admitted handle the identity of every connection that names
    /// none: the daemon the endpoint serves.
    pub fn serve_daemon_as(&mut self, handle: HandleId) -> Result<(), String> {
        if self.store.view(&handle).is_none() {
            return Err(format!("no admitted handle {}", handle.0));
        }
        self.daemon = Some(handle);
        Ok(())
    }

    /// The view a request acts under: the handle it names, else the daemon's.
    pub fn view_for(&self, named: Option<&str>) -> Option<View> {
        let handle = match named {
            Some(token) => HandleId(token.to_owned()),
            None => self.daemon.clone()?,
        };
        self.store.view(&handle)
    }

    pub fn executor_name(&self) -> &str {
        self.runner.name()
    }

    fn read_message<M: Message + Default>(
        &self,
        view: &View,
        digest: &Digest,
        missing: &mut Vec<Digest>,
    ) -> Option<M> {
        let bytes = match self.store.get(view, digest) {
            Some(bytes) => bytes,
            None => {
                missing.push(digest.clone());
                return None;
            }
        };
        M::decode(bytes.as_slice()).ok()
    }

    /// Execute an action under a view, or serve its cached result.
    pub async fn execute(
        &self,
        view: &View,
        action_digest: &Digest,
        skip_cache_lookup: bool,
    ) -> Result<Executed, ExecuteRefusal> {
        if !skip_cache_lookup {
            if let Some(entry) = self.cached(view, action_digest) {
                return Ok(Executed {
                    result: entry.result,
                    cached: true,
                });
            }
        }
        let mut missing = Vec::new();
        let action: Option<re::Action> = self.read_message(view, action_digest, &mut missing);
        let Some(action) = action else {
            if missing.is_empty() {
                return Err(ExecuteRefusal::Invalid(format!(
                    "action {action_digest} does not decode"
                )));
            }
            return Err(ExecuteRefusal::Missing(missing));
        };
        let command_digest = action
            .command_digest
            .as_ref()
            .ok_or_else(|| ExecuteRefusal::Invalid("the action names no command".into()))
            .and_then(|d| Digest::from_proto(d).map_err(ExecuteRefusal::Invalid))?;
        let root_digest = action
            .input_root_digest
            .as_ref()
            .ok_or_else(|| ExecuteRefusal::Invalid("the action names no input root".into()))
            .and_then(|d| Digest::from_proto(d).map_err(ExecuteRefusal::Invalid))?;
        let command: Option<re::Command> = self.read_message(view, &command_digest, &mut missing);
        let files = match decode_input_root(&self.store, view, &root_digest) {
            Ok(files) => files,
            Err(_) => {
                missing.push(root_digest.clone());
                BTreeMap::new()
            }
        };
        let mut inputs = BTreeMap::new();
        let mut input_digests = vec![
            action_digest.clone(),
            command_digest.clone(),
            root_digest.clone(),
        ];
        for (path, (digest, executable)) in &files {
            match self.store.get(view, digest) {
                Some(bytes) => {
                    inputs.insert(path.clone(), (bytes, *executable));
                }
                None => missing.push(digest.clone()),
            }
            input_digests.push(digest.clone());
        }
        if !missing.is_empty() {
            return Err(ExecuteRefusal::Missing(missing));
        }
        let Some(command) = command else {
            return Err(ExecuteRefusal::Invalid(format!(
                "command {command_digest} does not decode"
            )));
        };
        // Rule 5 and §14.2: the result is classified by everything that shaped
        // it — every input's use under this view, and what the platform says.
        let mut labels = Labels::new();
        for digest in &input_digests {
            if let Some(found) = self.store.use_of(view, digest) {
                labels.extend(found);
            }
        }
        // A client at API 2.0 puts the platform and the outputs on the
        // command; the daemon we serve puts them on the action. Both are read.
        #[allow(deprecated)]
        let platform: Vec<(String, String)> = command
            .platform
            .as_ref()
            .or(action.platform.as_ref())
            .map(|p| {
                p.properties
                    .iter()
                    .map(|p| (p.name.clone(), p.value.clone()))
                    .collect()
            })
            .unwrap_or_default();
        for (name, value) in &platform {
            if name == LABELS_PROPERTY {
                labels.extend(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(str::to_owned),
                );
            }
        }
        if !view.principal.holds(&labels) {
            return Err(ExecuteRefusal::Classified(labels));
        }
        let mut output_paths: Vec<String> = command.output_paths.clone();
        #[allow(deprecated)]
        {
            output_paths.extend(command.output_files.iter().cloned());
            output_paths.extend(command.output_directories.iter().cloned());
        }
        output_paths.sort();
        output_paths.dedup();
        let timeout = action
            .timeout
            .as_ref()
            .and_then(|d| Duration::try_from(*d).ok())
            .filter(|d| !d.is_zero())
            .unwrap_or(DEFAULT_TIMEOUT);
        let prepared = PreparedAction {
            arguments: command.arguments.clone(),
            environment: command
                .environment_variables
                .iter()
                .map(|e| (e.name.clone(), e.value.clone()))
                .collect(),
            working_directory: command.working_directory.clone(),
            inputs,
            output_paths: output_paths.clone(),
            timeout: Some(timeout),
        };
        let outcome = self
            .runner
            .run(prepared)
            .await
            .map_err(ExecuteRefusal::Failed)?;
        let classification = Classification {
            labels: labels.clone(),
            inputs: input_digests,
            platform,
        };
        let mut result = re::ActionResult {
            exit_code: if outcome.timed_out {
                -1
            } else {
                outcome.exit_code
            },
            ..Default::default()
        };
        for (path, output) in &outcome.outputs {
            match output {
                Output::File { bytes, executable } => {
                    let digest = self
                        .store
                        .put(view, bytes, &labels)
                        .map_err(ExecuteRefusal::Failed)?;
                    result.output_files.push(re::OutputFile {
                        path: path.clone(),
                        digest: Some(digest.to_proto()),
                        is_executable: *executable,
                        contents: Vec::new(),
                        node_properties: None,
                    });
                }
                Output::Directory { files } => {
                    let (tree_digest, root_digest) = self
                        .store_tree(view, files, &labels)
                        .map_err(ExecuteRefusal::Failed)?;
                    result.output_directories.push(re::OutputDirectory {
                        path: path.clone(),
                        tree_digest: Some(tree_digest.to_proto()),
                        is_topologically_sorted: false,
                        root_directory_digest: Some(root_digest.to_proto()),
                    });
                }
            }
        }
        let stdout = self
            .store
            .put(view, &outcome.stdout, &labels)
            .map_err(ExecuteRefusal::Failed)?;
        let stderr = self
            .store
            .put(view, &outcome.stderr, &labels)
            .map_err(ExecuteRefusal::Failed)?;
        result.stdout_digest = Some(stdout.to_proto());
        result.stderr_digest = Some(stderr.to_proto());
        if outcome.stdout.len() <= INLINE_LIMIT {
            result.stdout_raw = outcome.stdout.clone();
        }
        if outcome.stderr.len() <= INLINE_LIMIT {
            result.stderr_raw = outcome.stderr.clone();
        }
        result.execution_metadata = Some(re::ExecutedActionMetadata {
            worker: self.runner.name().to_owned(),
            auxiliary_metadata: vec![prost_types::Any {
                type_url: CLASSIFICATION_TYPE_URL.into(),
                value: serde_json::to_vec(&classification).unwrap_or_default(),
            }],
            ..Default::default()
        });
        if !action.do_not_cache && !outcome.timed_out && outcome.exit_code == 0 {
            self.cache
                .record_executed(
                    action_digest,
                    self.runner.name(),
                    result.clone(),
                    classification,
                )
                .map_err(ExecuteRefusal::Failed)?;
        }
        Ok(Executed {
            result,
            cached: false,
        })
    }

    /// The cached result a view may be served: one the cache gives it whose
    /// outputs, logs and output trees it can still read. A result whose
    /// bytes are gone — erased by the workspace, or never uploaded by the
    /// client that claimed it — is not served, since a hit the caller cannot
    /// download is a failure it would learn of later and worse.
    pub fn cached(&self, view: &View, action: &Digest) -> Option<Entry> {
        let entry = self.cache.lookup(view, action)?;
        let result = &entry.result;
        let mut referenced = Vec::new();
        let mut push = |digest: Option<&re::Digest>| -> Option<()> {
            if let Some(digest) = digest {
                referenced.push(Digest::from_proto(digest).ok()?);
            }
            Some(())
        };
        for file in &result.output_files {
            push(file.digest.as_ref())?;
        }
        push(result.stdout_digest.as_ref())?;
        push(result.stderr_digest.as_ref())?;
        let mut trees = Vec::new();
        for directory in &result.output_directories {
            push(directory.tree_digest.as_ref())?;
            let tree = Digest::from_proto(directory.tree_digest.as_ref()?).ok()?;
            trees.push(tree);
        }
        for tree in &trees {
            let tree = re::Tree::decode(self.store.get(view, tree)?.as_slice()).ok()?;
            for directory in tree.root.iter().chain(tree.children.iter()) {
                for file in &directory.files {
                    push(file.digest.as_ref())?;
                }
            }
        }
        self.store
            .missing(view, referenced.iter())
            .is_empty()
            .then_some(entry)
    }

    /// Store an output directory as a `Tree` under the view, returning the
    /// tree's digest and its root directory's.
    fn store_tree(
        &self,
        view: &View,
        files: &BTreeMap<String, (Vec<u8>, bool)>,
        labels: &Labels,
    ) -> Result<(Digest, Digest), String> {
        #[derive(Default)]
        struct Node {
            files: Vec<re::FileNode>,
            children: BTreeMap<String, Node>,
        }
        let mut root = Node::default();
        for (path, (bytes, executable)) in files {
            let digest = self.store.put(view, bytes, labels)?;
            let mut parts: Vec<&str> = path.split('/').collect();
            let name = parts.pop().unwrap_or_default().to_owned();
            let mut node = &mut root;
            for part in parts {
                node = node.children.entry(part.to_owned()).or_default();
            }
            node.files.push(re::FileNode {
                name,
                digest: Some(digest.to_proto()),
                is_executable: *executable,
                node_properties: None,
            });
        }
        fn build(node: &Node, children: &mut Vec<re::Directory>) -> re::Directory {
            let mut files = node.files.clone();
            files.sort_by(|a, b| a.name.cmp(&b.name));
            let directories = node
                .children
                .iter()
                .map(|(name, child)| {
                    let directory = build(child, children);
                    let digest = Digest::of(&directory.encode_to_vec());
                    children.push(directory);
                    re::DirectoryNode {
                        name: name.clone(),
                        digest: Some(digest.to_proto()),
                    }
                })
                .collect();
            re::Directory {
                files,
                directories,
                symlinks: Vec::new(),
                node_properties: None,
            }
        }
        let mut children = Vec::new();
        let root_directory = build(&root, &mut children);
        let root_digest = self
            .store
            .put(view, &root_directory.encode_to_vec(), labels)?;
        for child in &children {
            self.store.put(view, &child.encode_to_vec(), labels)?;
        }
        let tree = re::Tree {
            root: Some(root_directory),
            children,
        };
        let tree_digest = self.store.put(view, &tree.encode_to_vec(), labels)?;
        Ok((tree_digest, root_digest))
    }

    /// Remember a completed execution under an operation name, for
    /// `WaitExecution`.
    pub fn remember_operation(&self, executed: &Executed) -> String {
        let name = {
            use rand::RngCore;
            let mut bytes = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut bytes);
            format!(
                "operations/{}",
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            )
        };
        self.operations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(name.clone(), executed.clone());
        name
    }

    pub fn operation(&self, name: &str) -> Option<Executed> {
        self.operations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(name)
            .cloned()
    }

    /// The endpoint's evidence for an action: what its own executor ran.
    pub fn evidence(&self, action: &Digest) -> Option<Entry> {
        self.cache.evidence(action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::LocalRunner;

    fn endpoint() -> (tempfile::TempDir, Endpoint) {
        let scratch = tempfile::tempdir().expect("scratch");
        let endpoint = Endpoint::new(Arc::new(LocalRunner::new(scratch.path())));
        (scratch, endpoint)
    }

    #[test]
    fn the_daemon_identity_must_be_an_admitted_handle() {
        let (_scratch, mut endpoint) = endpoint();
        assert_eq!(
            endpoint
                .serve_daemon_as(HandleId("nobody".into()))
                .unwrap_err(),
            "no admitted handle nobody"
        );
        assert_eq!(endpoint.view_for(None), None);
        let (handle, view) = endpoint
            .admit(Principal {
                name: "owner".into(),
                labels: Labels::new(),
            })
            .expect("admitted");
        endpoint
            .serve_daemon_as(handle.clone())
            .expect("the daemon's");
        assert_eq!(endpoint.view_for(None), Some(view.clone()));
        assert_eq!(endpoint.view_for(Some(&handle.0)), Some(view));
        assert_eq!(endpoint.view_for(Some("nobody")), None);
    }

    #[tokio::test]
    async fn a_malformed_action_is_refused_by_what_is_wrong_with_it() {
        let (_scratch, endpoint) = endpoint();
        let (_, view) = endpoint
            .admit(Principal {
                name: "dev".into(),
                labels: Labels::new(),
            })
            .expect("admitted");
        let garbage = endpoint
            .store
            .put(&view, b"\xff\xfe not a message", &Labels::new())
            .unwrap();
        assert_eq!(
            endpoint.execute(&view, &garbage, true).await.unwrap_err(),
            ExecuteRefusal::Invalid(format!("action {garbage} does not decode"))
        );
        let unknown = Digest::of(b"never uploaded");
        assert_eq!(
            endpoint.execute(&view, &unknown, true).await.unwrap_err(),
            ExecuteRefusal::Missing(vec![unknown])
        );
        let empty_root = endpoint
            .store
            .put(
                &view,
                &re::Directory::default().encode_to_vec(),
                &Labels::new(),
            )
            .unwrap();
        let no_command = endpoint
            .store
            .put(
                &view,
                &re::Action {
                    input_root_digest: Some(empty_root.to_proto()),
                    ..Default::default()
                }
                .encode_to_vec(),
                &Labels::new(),
            )
            .unwrap();
        assert_eq!(
            endpoint
                .execute(&view, &no_command, true)
                .await
                .unwrap_err(),
            ExecuteRefusal::Invalid("the action names no command".into())
        );
        let bad_command = endpoint
            .store
            .put(&view, b"\xff\xfe not a command", &Labels::new())
            .unwrap();
        let action = endpoint
            .store
            .put(
                &view,
                &re::Action {
                    command_digest: Some(bad_command.to_proto()),
                    input_root_digest: Some(empty_root.to_proto()),
                    ..Default::default()
                }
                .encode_to_vec(),
                &Labels::new(),
            )
            .unwrap();
        assert_eq!(
            endpoint.execute(&view, &action, true).await.unwrap_err(),
            ExecuteRefusal::Invalid(format!("command {bad_command} does not decode"))
        );
        // A well-formed action over an input the view cannot read is missing
        // that input under the view, before anything runs.
        let command = endpoint
            .store
            .put(
                &view,
                &re::Command {
                    arguments: vec!["true".into()],
                    ..Default::default()
                }
                .encode_to_vec(),
                &Labels::new(),
            )
            .unwrap();
        let unseen = Digest::of(b"a file nobody uploaded");
        let root = endpoint
            .store
            .put(
                &view,
                &re::Directory {
                    files: vec![re::FileNode {
                        name: "in.txt".into(),
                        digest: Some(unseen.to_proto()),
                        is_executable: false,
                        node_properties: None,
                    }],
                    ..Default::default()
                }
                .encode_to_vec(),
                &Labels::new(),
            )
            .unwrap();
        let action = endpoint
            .store
            .put(
                &view,
                &re::Action {
                    command_digest: Some(command.to_proto()),
                    input_root_digest: Some(root.to_proto()),
                    ..Default::default()
                }
                .encode_to_vec(),
                &Labels::new(),
            )
            .unwrap();
        assert_eq!(
            endpoint.execute(&view, &action, true).await.unwrap_err(),
            ExecuteRefusal::Missing(vec![unseen])
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_executed_result_is_served_by_the_next_process_over_the_same_state() {
        let scratch = tempfile::tempdir().expect("scratch");
        let state = scratch.path().join("endpoint.sqlite");
        let open = || {
            Endpoint::open(
                Arc::new(LocalRunner::new(scratch.path().join("actions"))),
                &state,
            )
            .expect("the state opens")
        };
        let owner = || Principal {
            name: "owner".into(),
            labels: Labels::new(),
        };
        let (action, output) = {
            let endpoint = open();
            let (_, view) = endpoint.admit(owner()).expect("admitted");
            let put = |bytes: Vec<u8>| endpoint.store.put(&view, &bytes, &Labels::new()).unwrap();
            let command = put(re::Command {
                arguments: vec!["sh".into(), "-c".into(), "echo kept > out.txt".into()],
                output_paths: vec!["out.txt".into()],
                ..Default::default()
            }
            .encode_to_vec());
            let root = put(re::Directory::default().encode_to_vec());
            let action = put(re::Action {
                command_digest: Some(command.to_proto()),
                input_root_digest: Some(root.to_proto()),
                ..Default::default()
            }
            .encode_to_vec());
            let executed = endpoint.execute(&view, &action, false).await.expect("ran");
            assert!(!executed.cached);
            let output = Digest::from_proto(
                executed.result.output_files[0]
                    .digest
                    .as_ref()
                    .expect("an output digest"),
            )
            .expect("a digest");
            (action, output)
        };
        let endpoint = open();
        let (_, view) = endpoint.admit(owner()).expect("admitted again");
        let served = endpoint
            .execute(&view, &action, false)
            .await
            .expect("served");
        assert!(served.cached);
        assert_eq!(served.result.exit_code, 0);
        assert!(endpoint.evidence(&action).is_some());
        assert_eq!(
            endpoint.store.get(&view, &output).as_deref(),
            Some(&b"kept\n"[..])
        );
        assert_eq!(endpoint.cache.counts(), (1, 0));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_result_whose_output_the_workspace_erased_is_not_served_and_cannot_be_remade() {
        use whipplescript_store::content::{ContentBlobs, ContentStore};
        let scratch = tempfile::tempdir().expect("scratch");
        let state = scratch.path().join("endpoint.sqlite");
        let content = scratch.path().join("vcs-content.sqlite");
        let endpoint = Endpoint::open_sharing(
            Arc::new(LocalRunner::new(scratch.path().join("actions"))),
            &state,
            &content,
        )
        .expect("the state and the content store open");
        let (_, view) = endpoint
            .admit(Principal {
                name: "owner".into(),
                labels: Labels::new(),
            })
            .expect("admitted");
        let put = |bytes: Vec<u8>| endpoint.store.put(&view, &bytes, &Labels::new()).unwrap();
        let command = put(re::Command {
            arguments: vec!["sh".into(), "-c".into(), "echo derived > out.txt".into()],
            output_paths: vec!["out.txt".into()],
            ..Default::default()
        }
        .encode_to_vec());
        let root = put(re::Directory::default().encode_to_vec());
        let action = put(re::Action {
            command_digest: Some(command.to_proto()),
            input_root_digest: Some(root.to_proto()),
            ..Default::default()
        }
        .encode_to_vec());
        let executed = endpoint.execute(&view, &action, false).await.expect("ran");
        let output = Digest::from_proto(
            executed.result.output_files[0]
                .digest
                .as_ref()
                .expect("an output digest"),
        )
        .expect("a digest");
        // The output is the workspace's bytes, under the workspace's id.
        let workspace = ContentStore::open(&content).expect("a second connection");
        assert_eq!(
            workspace.get(&output.hash[..32]).unwrap().as_deref(),
            Some(&b"derived\n"[..])
        );
        assert!(endpoint.cached(&view, &action).is_some());
        workspace.erase(&output.hash[..32], "t1").expect("erased");
        assert_eq!(endpoint.cached(&view, &action), None);
        assert!(
            endpoint.evidence(&action).is_some(),
            "the record of the run stays"
        );
        assert_eq!(
            endpoint.execute(&view, &action, false).await.unwrap_err(),
            ExecuteRefusal::Failed(format!(
                "cannot write blob {output} to the workspace's content store: derived content identity was erased"
            ))
        );
        let not_a_store = scratch.path().join("notes.txt");
        std::fs::write(&not_a_store, vec![b'x'; 4096]).expect("the fixture's own step");
        assert!(Endpoint::open_sharing(
            Arc::new(LocalRunner::new(scratch.path().join("actions"))),
            &scratch.path().join("other.sqlite"),
            &not_a_store,
        )
        .err()
        .expect("refused")
        .starts_with(&format!(
            "cannot open the workspace's content store {}: ",
            not_a_store.display()
        )));
    }
}
