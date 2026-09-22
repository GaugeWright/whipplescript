//! The `TestExecutor` service Buck2 calls: it collects each target's external
//! runner spec and signals when there are no more.

use std::sync::Mutex;

use tokio::sync::oneshot;
use tonic::{Request, Response, Status};

use crate::proto::buck::test::test_executor_server::TestExecutor;
use crate::proto::buck::test::{
    Empty, ExternalRunnerSpec, ExternalRunnerSpecRequest, UnstableHeapDumpRequest,
    UnstableHeapDumpResponse,
};

pub struct SpecCollector {
    specs: Mutex<Vec<ExternalRunnerSpec>>,
    done: Mutex<Option<oneshot::Sender<Vec<ExternalRunnerSpec>>>>,
}

impl SpecCollector {
    pub fn new() -> (Self, oneshot::Receiver<Vec<ExternalRunnerSpec>>) {
        let (send, receive) = oneshot::channel();
        (
            Self {
                specs: Mutex::new(Vec::new()),
                done: Mutex::new(Some(send)),
            },
            receive,
        )
    }
}

#[tonic::async_trait]
impl TestExecutor for SpecCollector {
    async fn external_runner_spec(
        &self,
        request: Request<ExternalRunnerSpecRequest>,
    ) -> Result<Response<Empty>, Status> {
        let spec = request
            .into_inner()
            .test_spec
            .ok_or_else(|| Status::invalid_argument("missing test_spec"))?;
        self.specs
            .lock()
            .map_err(|_| Status::internal("spec list poisoned"))?
            .push(spec);
        Ok(Response::new(Empty {}))
    }

    async fn end_of_test_requests(&self, _: Request<Empty>) -> Result<Response<Empty>, Status> {
        let specs = std::mem::take(
            &mut *self
                .specs
                .lock()
                .map_err(|_| Status::internal("spec list poisoned"))?,
        );
        let sender = self
            .done
            .lock()
            .map_err(|_| Status::internal("completion poisoned"))?
            .take();
        match sender {
            Some(sender) => {
                // The run side may already have gone away; that is its report.
                let _ = sender.send(specs);
                Ok(Response::new(Empty {}))
            }
            None => Err(Status::failed_precondition(
                "Buck2 reported the end of test requests twice",
            )),
        }
    }

    async fn unstable_heap_dump(
        &self,
        _: Request<UnstableHeapDumpRequest>,
    ) -> Result<Response<UnstableHeapDumpResponse>, Status> {
        Err(Status::unimplemented(
            "this executor does not dump its heap",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn specs_are_collected_once_and_the_rest_is_refused_by_name() {
        let (collector, done) = SpecCollector::new();
        let missing = collector
            .external_runner_spec(Request::new(ExternalRunnerSpecRequest { test_spec: None }))
            .await
            .expect_err("a request without a spec is refused");
        assert_eq!(missing.code(), tonic::Code::InvalidArgument);
        collector
            .external_runner_spec(Request::new(ExternalRunnerSpecRequest {
                test_spec: Some(ExternalRunnerSpec {
                    test_type: "whip".into(),
                    ..Default::default()
                }),
            }))
            .await
            .expect("a spec is collected");
        collector
            .end_of_test_requests(Request::new(Empty {}))
            .await
            .expect("the end is reported once");
        let specs = done.await.expect("the collected specs are handed over");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].test_type, "whip");
        let twice = collector
            .end_of_test_requests(Request::new(Empty {}))
            .await
            .expect_err("a second end is refused");
        assert_eq!(twice.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            twice.message(),
            "Buck2 reported the end of test requests twice"
        );
        let dump = collector
            .unstable_heap_dump(Request::new(UnstableHeapDumpRequest {
                destination_path: "/nowhere".into(),
            }))
            .await
            .expect_err("no heap dump");
        assert_eq!(dump.code(), tonic::Code::Unimplemented);
        assert_eq!(dump.message(), "this executor does not dump its heap");
    }
}
