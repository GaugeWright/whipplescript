//! The two connections Buck2 opened: a gRPC server on one, a client on the
//! other, each over the single TCP stream the daemon accepted.

use futures::{stream, StreamExt};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use crate::proto::buck::test::test_executor_server::{TestExecutor, TestExecutorServer};

/// A client channel over a connection that already exists. It cannot
/// reconnect: the daemon accepted exactly one connection for it.
pub async fn client_channel(addr: &str, name: &str) -> Result<Channel, String> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|error| format!("cannot connect to Buck2's {name} at {addr}: {error}"))?;
    let mut io = Some(TokioIo::new(stream));
    Endpoint::try_from(format!("http://{name}.invalid"))
        .map_err(|error| error.to_string())?
        .connect_with_connector(service_fn(move |_: Uri| {
            let io = io
                .take()
                .ok_or_else(|| "the connection to Buck2 was already used".to_owned());
            std::future::ready(io)
        }))
        .await
        .map_err(|error| format!("cannot open the {name} channel: {error}"))
}

/// Serve one gRPC connection until `shutdown` resolves.
pub async fn serve_executor<E: TestExecutor>(
    addr: &str,
    executor: E,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), String> {
    let stream = TcpStream::connect(addr).await.map_err(|error| {
        format!("cannot connect to Buck2's executor listener at {addr}: {error}")
    })?;
    // One connection, then no more: the pending tail keeps the server from
    // ending when the incoming stream is exhausted.
    let incoming =
        stream::once(std::future::ready(Ok::<_, std::io::Error>(stream))).chain(stream::pending());
    tonic::transport::Server::builder()
        .add_service(
            TestExecutorServer::new(executor)
                .max_decoding_message_size(usize::MAX)
                .max_encoding_message_size(usize::MAX),
        )
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await
        .map_err(|error| format!("the executor service failed: {error}"))
}
