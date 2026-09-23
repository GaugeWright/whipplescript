//! BE-05 of the admission fixtures, over the wire: the five rules at the
//! store boundary (DR-0124 §14.3) as a real gRPC client meets them. A client
//! submits an action-cache result whose digest matches an approved action; a
//! principal issues a missing-blobs query naming blobs outside their view; a
//! cached output is served for an action not rerun.

use std::collections::BTreeMap;
use std::sync::Arc;

use prost::Message;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::{Code, Request};
use whipplescript_remote_execution::cache::{Classification, Origin, CLASSIFICATION_TYPE_URL};
use whipplescript_remote_execution::cut::{encode_cut, INPUT_ROOT_ENCODING_V1};
use whipplescript_remote_execution::digest::Digest;
use whipplescript_remote_execution::endpoint::{Endpoint, HANDLE_HEADER, LABELS_PROPERTY};
use whipplescript_remote_execution::proto::google::bytestream::byte_stream_client::ByteStreamClient;
use whipplescript_remote_execution::proto::google::bytestream::{ReadRequest, WriteRequest};
use whipplescript_remote_execution::proto::google::longrunning::operation;
use whipplescript_remote_execution::proto::re;
use whipplescript_remote_execution::runner::LocalRunner;
use whipplescript_remote_execution::store::{HandleId, Labels, Principal};

fn labels(list: &[&str]) -> Labels {
    list.iter().map(|l| l.to_string()).collect()
}

struct Client {
    handle: Option<String>,
    channel: Channel,
}

impl Client {
    fn request<T>(&self, message: T) -> Request<T> {
        let mut request = Request::new(message);
        if let Some(handle) = &self.handle {
            request.metadata_mut().insert(
                HANDLE_HEADER,
                MetadataValue::try_from(handle.as_str()).expect("a header value"),
            );
        }
        request
    }
    fn cas(
        &self,
    ) -> re::content_addressable_storage_client::ContentAddressableStorageClient<Channel> {
        re::content_addressable_storage_client::ContentAddressableStorageClient::new(
            self.channel.clone(),
        )
    }
    fn ac(&self) -> re::action_cache_client::ActionCacheClient<Channel> {
        re::action_cache_client::ActionCacheClient::new(self.channel.clone())
    }
    fn exec(&self) -> re::execution_client::ExecutionClient<Channel> {
        re::execution_client::ExecutionClient::new(self.channel.clone())
    }
    fn bytes(&self) -> ByteStreamClient<Channel> {
        ByteStreamClient::new(self.channel.clone())
    }

    async fn upload(&self, bytes: &[u8]) -> Digest {
        let digest = Digest::of(bytes);
        let response = self
            .cas()
            .batch_update_blobs(self.request(re::BatchUpdateBlobsRequest {
                instance_name: "main".into(),
                requests: vec![re::batch_update_blobs_request::Request {
                    digest: Some(digest.to_proto()),
                    data: bytes.to_vec(),
                    compressor: 0,
                }],
                digest_function: 0,
            }))
            .await
            .expect("the upload answers")
            .into_inner();
        assert_eq!(
            response.responses[0].status.as_ref().map(|s| s.code),
            Some(0)
        );
        digest
    }

    async fn missing(&self, digests: &[&Digest]) -> Vec<Digest> {
        self.cas()
            .find_missing_blobs(self.request(re::FindMissingBlobsRequest {
                instance_name: "main".into(),
                blob_digests: digests.iter().map(|d| d.to_proto()).collect(),
                digest_function: 0,
            }))
            .await
            .expect("the query answers")
            .into_inner()
            .missing_blob_digests
            .iter()
            .map(|d| Digest::from_proto(d).expect("the fixture's own step"))
            .collect()
    }

    async fn read(&self, digest: &Digest) -> Result<Vec<u8>, i32> {
        let response = self
            .cas()
            .batch_read_blobs(self.request(re::BatchReadBlobsRequest {
                instance_name: "main".into(),
                digests: vec![digest.to_proto()],
                acceptable_compressors: vec![],
                digest_function: 0,
            }))
            .await
            .expect("the read answers")
            .into_inner();
        let item = &response.responses[0];
        let code = item.status.as_ref().map(|s| s.code).unwrap_or(-1);
        (code == 0).then(|| item.data.clone()).ok_or(code)
    }

    async fn execute(
        &self,
        action: &Digest,
        skip_cache: bool,
    ) -> Result<re::ExecuteResponse, tonic::Status> {
        let mut stream = self
            .exec()
            .execute(self.request(re::ExecuteRequest {
                instance_name: "main".into(),
                skip_cache_lookup: skip_cache,
                action_digest: Some(action.to_proto()),
                ..Default::default()
            }))
            .await?
            .into_inner();
        let operation = stream.message().await?.expect("one operation");
        assert!(operation.done);
        match operation.result {
            Some(operation::Result::Response(any)) => {
                Ok(re::ExecuteResponse::decode(any.value.as_slice()).expect("an execute response"))
            }
            other => panic!("not a response: {other:?}"),
        }
    }

    async fn cached(&self, action: &Digest) -> Result<re::ActionResult, Code> {
        self.ac()
            .get_action_result(self.request(re::GetActionResultRequest {
                instance_name: "main".into(),
                action_digest: Some(action.to_proto()),
                ..Default::default()
            }))
            .await
            .map(|r| r.into_inner())
            .map_err(|status| status.code())
    }
}

/// An action that copies `in.txt` to `out.txt`, over an input root of one
/// file, optionally classified by the platform.
async fn action_for(
    client: &Client,
    content: &[u8],
    platform_labels: Option<&str>,
) -> (Digest, Digest) {
    let file = client.upload(content).await;
    let directory = re::Directory {
        files: vec![re::FileNode {
            name: "in.txt".into(),
            digest: Some(file.to_proto()),
            is_executable: false,
            node_properties: None,
        }],
        ..Default::default()
    };
    let root = client.upload(&directory.encode_to_vec()).await;
    let platform = platform_labels.map(|value| re::Platform {
        properties: vec![re::platform::Property {
            name: LABELS_PROPERTY.into(),
            value: value.into(),
        }],
    });
    let command = re::Command {
        arguments: vec![
            "sh".into(),
            "-c".into(),
            "tr a-z A-Z < in.txt > out.txt; echo copied".into(),
        ],
        output_paths: vec!["out.txt".into()],
        ..Default::default()
    };
    let command_digest = client.upload(&command.encode_to_vec()).await;
    let action = re::Action {
        command_digest: Some(command_digest.to_proto()),
        input_root_digest: Some(root.to_proto()),
        platform,
        ..Default::default()
    };
    (client.upload(&action.encode_to_vec()).await, file)
}

#[tokio::test]
async fn the_five_rules_hold_at_the_wire() {
    let scratch = tempfile::tempdir().expect("scratch");
    let endpoint = Endpoint::new(Arc::new(LocalRunner::new(scratch.path())));
    let (owner_handle, owner_view) = endpoint
        .admit(Principal {
            name: "owner".into(),
            labels: labels(&["protected"]),
        })
        .expect("the fixture's own step");
    let (dev_handle, _) = endpoint
        .admit(Principal {
            name: "dev".into(),
            labels: labels(&[]),
        })
        .expect("the fixture's own step");
    // A cut encoded under owner: its protected file is a blob owner has a
    // labeled use of, and dev has no use of at all.
    let manifest: BTreeMap<String, String> =
        [("secret-gate/protected/flag", "s0"), ("FIXTURE", "f0")]
            .into_iter()
            .map(|(p, h)| (p.to_owned(), h.to_owned()))
            .collect();
    let encoded = encode_cut(
        &endpoint.store,
        &owner_view,
        "cut-1",
        &manifest,
        |path| Ok(format!("body of {path}").into_bytes()),
        |path| {
            if path.starts_with("secret-gate/protected/") {
                labels(&["protected"])
            } else {
                labels(&[])
            }
        },
    )
    .expect("the fixture's own step");
    assert_eq!(encoded.encoding, INPUT_ROOT_ENCODING_V1);
    let protected = Digest::of(b"body of secret-gate/protected/flag");
    let endpoint = Arc::new(endpoint);
    let (listener, address) = whipplescript_remote_execution::server::bind("127.0.0.1:0")
        .await
        .expect("the fixture's own step");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(whipplescript_remote_execution::server::serve(
        endpoint.clone(),
        listener,
        async move {
            let _ = stopped.await;
        },
    ));
    let channel = Channel::from_shared(format!("http://{address}"))
        .expect("the fixture's own step")
        .connect()
        .await
        .expect("the fixture's own step");
    let owner = Client {
        handle: Some(owner_handle.0.clone()),
        channel: channel.clone(),
    };
    let dev = Client {
        handle: Some(dev_handle.0.clone()),
        channel: channel.clone(),
    };
    let nobody = Client {
        handle: None,
        channel: channel.clone(),
    };
    let stranger = Client {
        handle: Some("not-a-handle".into()),
        channel: channel.clone(),
    };

    // No handle, no view: the connection is not a principal.
    for client in [&nobody, &stranger] {
        let status = client
            .cas()
            .find_missing_blobs(client.request(re::FindMissingBlobsRequest::default()))
            .await
            .expect_err("refused");
        assert_eq!(status.code(), Code::Unauthenticated);
        assert_eq!(status.message(), "no admitted handle names this caller");
    }
    let capabilities = owner
        .cas()
        .find_missing_blobs(owner.request(re::FindMissingBlobsRequest::default()))
        .await
        .expect("owner is admitted");
    assert!(capabilities.into_inner().missing_blob_digests.is_empty());

    // Rule 1: dev knows the protected digest and reads nothing by it.
    assert_eq!(dev.read(&protected).await, Err(Code::NotFound as i32));
    assert_eq!(
        owner
            .read(&protected)
            .await
            .expect("the fixture's own step"),
        b"body of secret-gate/protected/flag"
    );
    let refused = dev
        .bytes()
        .read(dev.request(ReadRequest {
            resource_name: format!("main/blobs/{}/{}", protected.hash, protected.size_bytes),
            read_offset: 0,
            read_limit: 0,
        }))
        .await
        .expect_err("a stream read is refused too");
    assert_eq!(refused.code(), Code::NotFound);

    // Rule 4 (BE-05): dev's missing-blobs query naming a blob outside their
    // view reports it missing, and the duplicate upload is accepted.
    assert_eq!(dev.missing(&[&protected]).await, vec![protected.clone()]);
    assert!(owner.missing(&[&protected]).await.is_empty());
    assert!(endpoint.store.stored(&protected));
    let again = dev.upload(b"body of secret-gate/protected/flag").await;
    assert_eq!(again, protected);
    assert!(dev.missing(&[&protected]).await.is_empty());
    assert_eq!(
        dev.read(&protected).await.expect("the fixture's own step"),
        b"body of secret-gate/protected/flag"
    );
    // Rule 3: dev's use is unlabeled, owner's still carries the label.
    assert_eq!(
        endpoint.store.use_of(&owner_view, &protected),
        Some(labels(&["protected"]))
    );
    let dev_view = endpoint
        .store
        .view(&HandleId(dev_handle.0.clone()))
        .expect("the fixture's own step");
    assert_eq!(
        endpoint.store.use_of(&dev_view, &protected),
        Some(labels(&[]))
    );

    // A byte-stream upload round-trips and is admitted like a batch one.
    let large = vec![7u8; 3 * 1024 * 1024 + 17];
    let large_digest = Digest::of(&large);
    let resource = format!(
        "main/uploads/u1/blobs/{}/{}",
        large_digest.hash, large_digest.size_bytes
    );
    let chunks: Vec<WriteRequest> = large
        .chunks(1024 * 1024)
        .enumerate()
        .map(|(index, chunk)| WriteRequest {
            resource_name: if index == 0 {
                resource.clone()
            } else {
                String::new()
            },
            write_offset: (index * 1024 * 1024) as i64,
            finish_write: (index + 1) * 1024 * 1024 >= large.len(),
            data: chunk.to_vec(),
        })
        .collect();
    let committed = dev
        .bytes()
        .write(dev.request(tokio_stream::iter(chunks)))
        .await
        .expect("the write answers")
        .into_inner()
        .committed_size;
    assert_eq!(committed, large_digest.size_bytes);
    let mut read = dev
        .bytes()
        .read(dev.request(ReadRequest {
            resource_name: format!(
                "main/blobs/{}/{}",
                large_digest.hash, large_digest.size_bytes
            ),
            read_offset: 0,
            read_limit: 0,
        }))
        .await
        .expect("the read answers")
        .into_inner();
    let mut got = Vec::new();
    while let Some(part) = read.message().await.expect("the fixture's own step") {
        got.extend(part.data);
    }
    assert_eq!(got, large);

    // Execution: dev's own action over dev's own upload runs, its output is
    // dev's to read, and the result binds its classification (rule 5).
    let (action, _) = action_for(&dev, b"alpha", None).await;
    let response = dev
        .execute(&action, false)
        .await
        .expect("the fixture's own step");
    assert!(!response.cached_result);
    let result = response.result.expect("the fixture's own step");
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout_raw, b"copied\n");
    let out = Digest::from_proto(
        result.output_files[0]
            .digest
            .as_ref()
            .expect("the fixture's own step"),
    )
    .expect("the fixture's own step");
    assert_eq!(out, Digest::of(b"ALPHA"));
    assert_eq!(
        dev.read(&out).await.expect("the fixture's own step"),
        b"ALPHA"
    );
    let metadata = result
        .execution_metadata
        .as_ref()
        .expect("the fixture's own step");
    assert_eq!(metadata.worker, "whip-remote-execution/local");
    let classification: Classification =
        serde_json::from_slice(&metadata.auxiliary_metadata[0].value)
            .expect("the fixture's own step");
    assert_eq!(
        metadata.auxiliary_metadata[0].type_url,
        CLASSIFICATION_TYPE_URL
    );
    assert!(classification.labels.is_empty());
    assert!(classification.inputs.contains(&Digest::of(b"alpha")));
    // Rule 5 (BE-05): served again for an action not rerun, with the same
    // classification and analysis dependencies.
    let served_again = dev
        .execute(&action, false)
        .await
        .expect("the fixture's own step");
    assert!(served_again.cached_result);
    let cached = dev.cached(&action).await.expect("the fixture's own step");
    assert_eq!(cached.output_files, result.output_files);
    let again: Classification = serde_json::from_slice(
        &cached
            .execution_metadata
            .expect("the fixture's own step")
            .auxiliary_metadata[0]
            .value,
    )
    .expect("the fixture's own step");
    assert_eq!(again, classification);
    let evidence = endpoint
        .evidence(&action)
        .expect("the executor's run is evidence");
    assert_eq!(
        evidence.origin,
        Origin::Executed {
            executor: "whip-remote-execution/local".into()
        }
    );

    // A platform-classified action: refused to dev beyond their view, run for
    // owner, and its cached result is owner's alone.
    let (gated, _) = action_for(&dev, b"beta", Some("protected")).await;
    let refused = dev
        .execute(&gated, false)
        .await
        .expect_err("classified beyond dev");
    assert_eq!(refused.code(), Code::PermissionDenied);
    assert_eq!(
        refused.message(),
        "the action's result is classified protected beyond this view"
    );
    // owner has no use of dev's inputs: under owner's view they are missing.
    let missing = owner
        .execute(&gated, false)
        .await
        .expect_err("owner cannot see dev's inputs");
    assert_eq!(missing.code(), Code::FailedPrecondition);
    assert!(missing
        .message()
        .starts_with("missing under this view: blobs/"));
    let (owners, _) = action_for(&owner, b"beta", Some("protected")).await;
    assert_eq!(
        owners, gated,
        "the same action has the same digest whoever uploaded it"
    );
    let run = owner
        .execute(&gated, false)
        .await
        .expect("the fixture's own step");
    assert!(!run.cached_result);
    assert_eq!(dev.cached(&gated).await, Err(Code::NotFound));
    let not_found = dev
        .ac()
        .get_action_result(dev.request(re::GetActionResultRequest {
            instance_name: "main".into(),
            action_digest: Some(gated.to_proto()),
            ..Default::default()
        }))
        .await
        .expect_err("not dev's to read");
    assert_eq!(
        not_found.message(),
        format!("no result for action {gated} under this view")
    );
    assert!(owner.cached(&gated).await.is_ok());
    // The gated output is new bytes under owner's labeled use: dev reads
    // nothing by its digest, while dev's own upload of the input stays theirs.
    let gated_out = Digest::of(b"BETA");
    assert_eq!(
        owner
            .read(&gated_out)
            .await
            .expect("the fixture's own step"),
        b"BETA"
    );
    assert_eq!(dev.read(&gated_out).await, Err(Code::NotFound as i32));
    assert_eq!(
        dev.read(&Digest::of(b"beta"))
            .await
            .expect("the fixture's own step"),
        b"beta"
    );

    // Rule 2 (BE-05): a client-submitted result whose digest matches an
    // approved action produces no evidence.
    let claimed = re::ActionResult {
        exit_code: 0,
        ..Default::default()
    };
    let refused = dev
        .ac()
        .update_action_result(dev.request(re::UpdateActionResultRequest {
            instance_name: "main".into(),
            action_digest: Some(action.to_proto()),
            action_result: Some(claimed.clone()),
            ..Default::default()
        }))
        .await
        .expect_err("an executed result is not replaced by a claim");
    assert_eq!(refused.code(), Code::FailedPrecondition);
    let forged = Digest::of(b"an action nobody ran");
    dev.ac()
        .update_action_result(dev.request(re::UpdateActionResultRequest {
            instance_name: "main".into(),
            action_digest: Some(forged.to_proto()),
            action_result: Some(claimed.clone()),
            ..Default::default()
        }))
        .await
        .expect("a claim is accepted into the claimant's view");
    assert_eq!(
        dev.cached(&forged)
            .await
            .expect("the fixture's own step")
            .exit_code,
        0
    );
    assert_eq!(owner.cached(&forged).await, Err(Code::NotFound));
    assert_eq!(endpoint.evidence(&forged), None);
    let executed: Vec<String> = endpoint
        .cache
        .executed_actions()
        .into_iter()
        .map(|(digest, _)| digest.hash)
        .collect();
    assert!(executed.contains(&action.hash) && executed.contains(&gated.hash));
    assert!(!executed.contains(&forged.hash));

    // What the protocol offers and this endpoint does not, said by name.
    let split = dev
        .cas()
        .split_blob(dev.request(re::SplitBlobRequest::default()))
        .await
        .expect_err("not offered");
    assert_eq!(
        (split.code(), split.message()),
        (Code::Unimplemented, "blob splitting is not offered")
    );
    let splice = dev
        .cas()
        .splice_blob(dev.request(re::SpliceBlobRequest::default()))
        .await
        .expect_err("not offered");
    assert_eq!(
        (splice.code(), splice.message()),
        (Code::Unimplemented, "blob splicing is not offered")
    );
    for (resource, message) in [
        (
            format!(
                "main/compressed-blobs/zstd/{}/{}",
                large_digest.hash, large_digest.size_bytes
            ),
            "compressed blobs are not offered".to_owned(),
        ),
        (
            "main/nothing".to_owned(),
            "not a blob resource: main/nothing".to_owned(),
        ),
        (
            "main/blobs/onlyhash".to_owned(),
            "not a blob resource: main/blobs/onlyhash".to_owned(),
        ),
    ] {
        let refused = dev
            .bytes()
            .read(dev.request(ReadRequest {
                resource_name: resource,
                read_offset: 0,
                read_limit: 0,
            }))
            .await
            .expect_err("not a readable resource");
        assert_eq!(
            (refused.code(), refused.message().to_owned()),
            (Code::InvalidArgument, message)
        );
    }
    // A stream write is checked as it arrives: named first, contiguous,
    // finished, and the bytes it promised.
    let small = Digest::of(b"small");
    let named = format!("main/uploads/u2/blobs/{}/{}", small.hash, small.size_bytes);
    let write = |requests: Vec<WriteRequest>| {
        let dev = &dev;
        async move {
            dev.bytes()
                .write(dev.request(tokio_stream::iter(requests)))
                .await
                .map(|r| r.into_inner().committed_size)
                .map_err(|status| status.message().to_owned())
        }
    };
    assert_eq!(
        write(vec![WriteRequest {
            resource_name: String::new(),
            write_offset: 0,
            finish_write: true,
            data: b"small".to_vec()
        }])
        .await,
        Err("the first write names no resource".into())
    );
    assert_eq!(
        write(vec![WriteRequest {
            resource_name: named.clone(),
            write_offset: 5,
            finish_write: true,
            data: b"small".to_vec()
        }])
        .await,
        Err("write offset 5 where 0 bytes were committed".into())
    );
    assert_eq!(
        write(vec![WriteRequest {
            resource_name: named.clone(),
            write_offset: 0,
            finish_write: false,
            data: b"sma".to_vec()
        }])
        .await,
        Err("the write did not finish".into())
    );
    assert_eq!(
        write(vec![WriteRequest {
            resource_name: named.clone(),
            write_offset: 0,
            finish_write: true,
            data: b"other".to_vec()
        }])
        .await,
        Err("the data does not match its digest".into())
    );
    assert_eq!(
        write(vec![WriteRequest {
            resource_name: named,
            write_offset: 0,
            finish_write: true,
            data: b"small".to_vec()
        }])
        .await,
        Ok(5)
    );
    let _ = stop.send(());
    server
        .await
        .expect("the fixture's own step")
        .expect("the fixture's own step");
}
