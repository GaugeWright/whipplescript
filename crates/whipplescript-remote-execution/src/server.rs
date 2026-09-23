//! Serving the endpoint: every service on one listener, ended by a signal.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

use crate::endpoint::Endpoint;
use crate::proto::google::bytestream::byte_stream_server::ByteStreamServer;
use crate::proto::re;
use crate::services::Services;

/// Bind the listener; the address is what the daemon is pointed at.
pub async fn bind(address: &str) -> Result<(TcpListener, SocketAddr), String> {
    let listener = TcpListener::bind(address)
        .await
        .map_err(|error| format!("cannot listen on {address}: {error}"))?;
    let bound = listener
        .local_addr()
        .map_err(|error| format!("cannot read the bound address: {error}"))?;
    Ok((listener, bound))
}

/// Serve until `shutdown` resolves.
pub async fn serve(
    endpoint: Arc<Endpoint>,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), String> {
    let services = Services { endpoint };
    tonic::transport::Server::builder()
        .add_service(re::execution_server::ExecutionServer::new(services.clone()))
        .add_service(re::action_cache_server::ActionCacheServer::new(
            services.clone(),
        ))
        .add_service(
            re::content_addressable_storage_server::ContentAddressableStorageServer::new(
                services.clone(),
            ),
        )
        .add_service(re::capabilities_server::CapabilitiesServer::new(
            services.clone(),
        ))
        .add_service(ByteStreamServer::new(services))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await
        .map_err(|error| format!("the endpoint stopped: {error}"))
}
