//! The four services of the Remote Execution API, and the ByteStream the
//! protocol carries large blobs over, each answered under the view the
//! request names (DR-0124 §14.3, §14.4).

use std::pin::Pin;
use std::sync::Arc;

use futures::Stream;
use prost::Message;
use tonic::{Request, Response, Status, Streaming};

use crate::cache::Classification;
use crate::digest::Digest;
use crate::endpoint::{Endpoint, ExecuteRefusal, Executed, HANDLE_HEADER};
use crate::proto::google::bytestream::{
    byte_stream_server::ByteStream, QueryWriteStatusRequest, QueryWriteStatusResponse, ReadRequest,
    ReadResponse, WriteRequest, WriteResponse,
};
use crate::proto::google::longrunning::{operation, Operation};
use crate::proto::re;
use crate::store::{Labels, View};

const READ_CHUNK: usize = 1024 * 1024;
const MAX_BATCH_TOTAL_SIZE_BYTES: i64 = 4 * 1024 * 1024;

#[derive(Clone)]
pub struct Services {
    pub endpoint: Arc<Endpoint>,
}

impl Services {
    /// The view a request acts under, or the protocol's refusal to act at
    /// all: a connection that names no handle and serves no daemon is not a
    /// principal, and an unknown handle sees nothing.
    fn view<T>(&self, request: &Request<T>) -> Result<View, Status> {
        let named = request
            .metadata()
            .get(HANDLE_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        self.endpoint
            .view_for(named.as_deref())
            .ok_or_else(|| Status::unauthenticated("no admitted handle names this caller"))
    }
}

fn digest_of(digest: Option<&re::Digest>, what: &str) -> Result<Digest, Status> {
    let digest = digest.ok_or_else(|| Status::invalid_argument(format!("no {what} digest")))?;
    Digest::from_proto(digest).map_err(Status::invalid_argument)
}

fn any_of<M: Message>(type_name: &str, message: &M) -> prost_types::Any {
    prost_types::Any {
        type_url: format!("type.googleapis.com/{type_name}"),
        value: message.encode_to_vec(),
    }
}

fn operation_of(name: String, action: &Digest, executed: &Executed) -> Operation {
    let response = re::ExecuteResponse {
        result: Some(executed.result.clone()),
        cached_result: executed.cached,
        ..Default::default()
    };
    Operation {
        name,
        metadata: Some(any_of(
            "build.bazel.remote.execution.v2.ExecuteOperationMetadata",
            &re::ExecuteOperationMetadata {
                stage: re::execution_stage::Value::Completed as i32,
                action_digest: Some(action.to_proto()),
                digest_function: re::digest_function::Value::Sha256 as i32,
                ..Default::default()
            },
        )),
        done: true,
        result: Some(operation::Result::Response(any_of(
            "build.bazel.remote.execution.v2.ExecuteResponse",
            &response,
        ))),
    }
}

fn refusal_status(refusal: ExecuteRefusal) -> Status {
    match refusal {
        ExecuteRefusal::Missing(digests) => Status::failed_precondition(format!(
            "missing under this view: {}",
            digests
                .iter()
                .map(|d| format!("blobs/{d}"))
                .collect::<Vec<_>>()
                .join(" ")
        )),
        ExecuteRefusal::Invalid(message) => Status::invalid_argument(message),
        ExecuteRefusal::Classified(labels) => Status::permission_denied(format!(
            "the action's result is classified {} beyond this view",
            labels.into_iter().collect::<Vec<_>>().join(",")
        )),
        ExecuteRefusal::Failed(message) => Status::internal(message),
    }
}

type OperationStream = Pin<Box<dyn Stream<Item = Result<Operation, Status>> + Send>>;

#[tonic::async_trait]
impl re::execution_server::Execution for Services {
    type ExecuteStream = OperationStream;
    type WaitExecutionStream = OperationStream;

    async fn execute(
        &self,
        request: Request<re::ExecuteRequest>,
    ) -> Result<Response<Self::ExecuteStream>, Status> {
        let view = self.view(&request)?;
        let request = request.into_inner();
        let action = digest_of(request.action_digest.as_ref(), "action")?;
        let executed = self
            .endpoint
            .execute(&view, &action, request.skip_cache_lookup)
            .await
            .map_err(refusal_status)?;
        let name = self.endpoint.remember_operation(&executed);
        let operation = operation_of(name, &action, &executed);
        Ok(Response::new(Box::pin(futures::stream::once(async move {
            Ok(operation)
        }))))
    }

    async fn wait_execution(
        &self,
        request: Request<re::WaitExecutionRequest>,
    ) -> Result<Response<Self::WaitExecutionStream>, Status> {
        self.view(&request)?;
        let name = request.into_inner().name;
        let executed = self
            .endpoint
            .operation(&name)
            .ok_or_else(|| Status::not_found(format!("no operation {name}")))?;
        let action = executed
            .result
            .execution_metadata
            .as_ref()
            .map(|_| Digest::empty())
            .unwrap_or_else(Digest::empty);
        let operation = operation_of(name, &action, &executed);
        Ok(Response::new(Box::pin(futures::stream::once(async move {
            Ok(operation)
        }))))
    }
}

#[tonic::async_trait]
impl re::action_cache_server::ActionCache for Services {
    async fn get_action_result(
        &self,
        request: Request<re::GetActionResultRequest>,
    ) -> Result<Response<re::ActionResult>, Status> {
        let view = self.view(&request)?;
        let action = digest_of(request.get_ref().action_digest.as_ref(), "action")?;
        match self.endpoint.cache.lookup(&view, &action) {
            Some(entry) => Ok(Response::new(entry.result)),
            None => Err(Status::not_found(format!(
                "no result for action {action} under this view"
            ))),
        }
    }

    /// A client's result is accepted into its own view and is never
    /// evidence (rule 2).
    async fn update_action_result(
        &self,
        request: Request<re::UpdateActionResultRequest>,
    ) -> Result<Response<re::ActionResult>, Status> {
        let view = self.view(&request)?;
        let request = request.into_inner();
        let action = digest_of(request.action_digest.as_ref(), "action")?;
        let result = request
            .action_result
            .ok_or_else(|| Status::invalid_argument("no action result"))?;
        let classification = Classification {
            labels: Labels::new(),
            inputs: vec![action.clone()],
            platform: Vec::new(),
        };
        self.endpoint
            .cache
            .record_submitted(&view, &action, result.clone(), classification)
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(result))
    }
}

type TreeStream = Pin<Box<dyn Stream<Item = Result<re::GetTreeResponse, Status>> + Send>>;

#[tonic::async_trait]
impl re::content_addressable_storage_server::ContentAddressableStorage for Services {
    /// Missing under the view: what it has no readable use of, whether or
    /// not the bytes are stored (rule 4).
    async fn find_missing_blobs(
        &self,
        request: Request<re::FindMissingBlobsRequest>,
    ) -> Result<Response<re::FindMissingBlobsResponse>, Status> {
        let view = self.view(&request)?;
        let digests = request
            .get_ref()
            .blob_digests
            .iter()
            .map(|d| Digest::from_proto(d).map_err(Status::invalid_argument))
            .collect::<Result<Vec<_>, _>>()?;
        let missing = self.endpoint.store.missing(&view, digests.iter());
        Ok(Response::new(re::FindMissingBlobsResponse {
            missing_blob_digests: missing.iter().map(Digest::to_proto).collect(),
        }))
    }

    async fn batch_update_blobs(
        &self,
        request: Request<re::BatchUpdateBlobsRequest>,
    ) -> Result<Response<re::BatchUpdateBlobsResponse>, Status> {
        let view = self.view(&request)?;
        let mut responses = Vec::new();
        for item in &request.get_ref().requests {
            let status =
                match Digest::from_proto(item.digest.as_ref().unwrap_or(&re::Digest::default())) {
                    Ok(claimed) => {
                        if item.compressor != re::compressor::Value::Identity as i32 {
                            rpc_status(
                                tonic::Code::InvalidArgument,
                                "compressed uploads are not accepted",
                            )
                        } else if Digest::of(&item.data) != claimed {
                            rpc_status(
                                tonic::Code::InvalidArgument,
                                "the data does not match its digest",
                            )
                        } else {
                            self.endpoint.store.put(&view, &item.data, &Labels::new());
                            rpc_status(tonic::Code::Ok, "")
                        }
                    }
                    Err(error) => rpc_status(tonic::Code::InvalidArgument, &error),
                };
            responses.push(re::batch_update_blobs_response::Response {
                digest: item.digest.clone(),
                status: Some(status),
            });
        }
        Ok(Response::new(re::BatchUpdateBlobsResponse { responses }))
    }

    async fn batch_read_blobs(
        &self,
        request: Request<re::BatchReadBlobsRequest>,
    ) -> Result<Response<re::BatchReadBlobsResponse>, Status> {
        let view = self.view(&request)?;
        let mut responses = Vec::new();
        for wanted in &request.get_ref().digests {
            let (data, status) = match Digest::from_proto(wanted) {
                Ok(digest) => match self.endpoint.store.get(&view, &digest) {
                    Some(data) => (data, rpc_status(tonic::Code::Ok, "")),
                    None => (
                        Vec::new(),
                        rpc_status(tonic::Code::NotFound, "missing under this view"),
                    ),
                },
                Err(error) => (Vec::new(), rpc_status(tonic::Code::InvalidArgument, &error)),
            };
            responses.push(re::batch_read_blobs_response::Response {
                digest: Some(wanted.clone()),
                data,
                compressor: re::compressor::Value::Identity as i32,
                status: Some(status),
            });
        }
        Ok(Response::new(re::BatchReadBlobsResponse { responses }))
    }

    type GetTreeStream = TreeStream;

    async fn get_tree(
        &self,
        request: Request<re::GetTreeRequest>,
    ) -> Result<Response<Self::GetTreeStream>, Status> {
        let view = self.view(&request)?;
        let root = digest_of(request.get_ref().root_digest.as_ref(), "root")?;
        let mut directories = Vec::new();
        let mut pending = vec![root];
        while let Some(digest) = pending.pop() {
            let bytes = self.endpoint.store.get(&view, &digest).ok_or_else(|| {
                Status::not_found(format!("directory {digest} is missing under this view"))
            })?;
            let directory = re::Directory::decode(bytes.as_slice()).map_err(|error| {
                Status::invalid_argument(format!("directory {digest} does not decode: {error}"))
            })?;
            for child in &directory.directories {
                pending.push(digest_of(child.digest.as_ref(), "directory")?);
            }
            directories.push(directory);
        }
        let response = re::GetTreeResponse {
            directories,
            next_page_token: String::new(),
        };
        Ok(Response::new(Box::pin(futures::stream::once(async move {
            Ok(response)
        }))))
    }

    async fn split_blob(
        &self,
        _: Request<re::SplitBlobRequest>,
    ) -> Result<Response<re::SplitBlobResponse>, Status> {
        Err(Status::unimplemented("blob splitting is not offered"))
    }

    async fn splice_blob(
        &self,
        _: Request<re::SpliceBlobRequest>,
    ) -> Result<Response<re::SpliceBlobResponse>, Status> {
        Err(Status::unimplemented("blob splicing is not offered"))
    }
}

fn rpc_status(code: tonic::Code, message: &str) -> crate::proto::google::rpc::Status {
    crate::proto::google::rpc::Status {
        code: code as i32,
        message: message.to_owned(),
        details: Vec::new(),
    }
}

#[tonic::async_trait]
impl re::capabilities_server::Capabilities for Services {
    async fn get_capabilities(
        &self,
        request: Request<re::GetCapabilitiesRequest>,
    ) -> Result<Response<re::ServerCapabilities>, Status> {
        self.view(&request)?;
        let sha256 = re::digest_function::Value::Sha256 as i32;
        Ok(Response::new(re::ServerCapabilities {
            cache_capabilities: Some(re::CacheCapabilities {
                digest_functions: vec![sha256],
                action_cache_update_capabilities: Some(re::ActionCacheUpdateCapabilities {
                    update_enabled: true,
                }),
                cache_priority_capabilities: None,
                max_batch_total_size_bytes: MAX_BATCH_TOTAL_SIZE_BYTES,
                symlink_absolute_path_strategy:
                    re::symlink_absolute_path_strategy::Value::Disallowed as i32,
                supported_compressors: vec![],
                supported_batch_update_compressors: vec![],
                max_cas_blob_size_bytes: 0,
                blob_split_support: false,
                blob_splice_support: false,
            }),
            execution_capabilities: Some(re::ExecutionCapabilities {
                digest_function: sha256,
                exec_enabled: true,
                execution_priority_capabilities: None,
                supported_node_properties: vec![],
                digest_functions: vec![sha256],
            }),
            deprecated_api_version: None,
            low_api_version: Some(crate::proto::build::bazel::semver::SemVer {
                major: 2,
                minor: 0,
                patch: 0,
                prerelease: String::new(),
            }),
            high_api_version: Some(crate::proto::build::bazel::semver::SemVer {
                major: 2,
                minor: 3,
                patch: 0,
                prerelease: String::new(),
            }),
        }))
    }
}

/// `{instance}/blobs/{hash}/{size}` for reads, and
/// `{instance}/uploads/{uuid}/blobs/{hash}/{size}` for writes.
fn resource_digest(resource: &str) -> Result<Digest, Status> {
    let parts: Vec<&str> = resource.split('/').collect();
    if parts.contains(&"compressed-blobs") {
        return Err(Status::invalid_argument("compressed blobs are not offered"));
    }
    let at = parts
        .iter()
        .rposition(|part| *part == "blobs")
        .ok_or_else(|| Status::invalid_argument(format!("not a blob resource: {resource}")))?;
    match (parts.get(at + 1), parts.get(at + 2)) {
        (Some(hash), Some(size)) => {
            Digest::from_resource(hash, size).map_err(Status::invalid_argument)
        }
        _ => Err(Status::invalid_argument(format!(
            "not a blob resource: {resource}"
        ))),
    }
}

type ReadStream = Pin<Box<dyn Stream<Item = Result<ReadResponse, Status>> + Send>>;

#[tonic::async_trait]
impl ByteStream for Services {
    type ReadStream = ReadStream;

    async fn read(
        &self,
        request: Request<ReadRequest>,
    ) -> Result<Response<Self::ReadStream>, Status> {
        let view = self.view(&request)?;
        let request = request.into_inner();
        let digest = resource_digest(&request.resource_name)?;
        let bytes = self.endpoint.store.get(&view, &digest).ok_or_else(|| {
            Status::not_found(format!("blob {digest} is missing under this view"))
        })?;
        let offset = usize::try_from(request.read_offset.max(0))
            .unwrap_or(0)
            .min(bytes.len());
        let limit = usize::try_from(request.read_limit).ok().filter(|l| *l > 0);
        let end = limit
            .map(|l| (offset + l).min(bytes.len()))
            .unwrap_or(bytes.len());
        let chunks: Vec<Result<ReadResponse, Status>> = if offset >= end {
            vec![Ok(ReadResponse { data: Vec::new() })]
        } else {
            bytes[offset..end]
                .chunks(READ_CHUNK)
                .map(|chunk| {
                    Ok(ReadResponse {
                        data: chunk.to_vec(),
                    })
                })
                .collect()
        };
        Ok(Response::new(Box::pin(futures::stream::iter(chunks))))
    }

    async fn write(
        &self,
        request: Request<Streaming<WriteRequest>>,
    ) -> Result<Response<WriteResponse>, Status> {
        let view = self.view(&request)?;
        let mut stream = request.into_inner();
        let mut resource = None;
        let mut data = Vec::new();
        let mut finished = false;
        while let Some(message) = stream.message().await? {
            if resource.is_none() {
                if message.resource_name.is_empty() {
                    return Err(Status::invalid_argument(
                        "the first write names no resource",
                    ));
                }
                resource = Some(message.resource_name.clone());
            }
            let expected = i64::try_from(data.len()).unwrap_or(i64::MAX);
            if message.write_offset != expected {
                return Err(Status::invalid_argument(format!(
                    "write offset {} where {expected} bytes were committed",
                    message.write_offset
                )));
            }
            data.extend_from_slice(&message.data);
            if message.finish_write {
                finished = true;
                break;
            }
        }
        let resource = resource.ok_or_else(|| Status::invalid_argument("an empty write"))?;
        if !finished {
            return Err(Status::invalid_argument("the write did not finish"));
        }
        let claimed = resource_digest(&resource)?;
        if Digest::of(&data) != claimed {
            return Err(Status::invalid_argument(
                "the data does not match its digest",
            ));
        }
        self.endpoint.store.put(&view, &data, &Labels::new());
        Ok(Response::new(WriteResponse {
            committed_size: claimed.size_bytes,
        }))
    }

    async fn query_write_status(
        &self,
        request: Request<QueryWriteStatusRequest>,
    ) -> Result<Response<QueryWriteStatusResponse>, Status> {
        let view = self.view(&request)?;
        let digest = resource_digest(&request.get_ref().resource_name)?;
        let complete = self.endpoint.store.get(&view, &digest).is_some();
        Ok(Response::new(QueryWriteStatusResponse {
            committed_size: if complete { digest.size_bytes } else { 0 },
            complete,
        }))
    }
}
