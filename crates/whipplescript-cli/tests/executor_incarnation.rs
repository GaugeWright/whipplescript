//! Actual process replacement at the same endpoint must reject old bindings.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use whipplescript_kernel::exec_incarnation;

struct Executor(Child);

/// A file for the executor's two streams, and what it wrote, for a failure
/// message.
///
/// The fixture used to send both streams to `Stdio::null()`, so an executor
/// that panicked, could not take its address, or rejected its token failed
/// this test as "executor exited during startup" or "executor startup timed
/// out" — which say that it did not come up, and never which of those it
/// was. An unnamed temporary keeps the output out of a passing run and out
/// of the way of tests running beside this one.
fn executor_log() -> File {
    tempfile::tempfile().expect("a file for the executor's output")
}

fn said(log: &mut File) -> String {
    let mut text = String::new();
    let _ = log.seek(SeekFrom::Start(0));
    match log.read_to_string(&mut text) {
        Ok(_) if !text.trim().is_empty() => format!("; it said: {}", text.trim()),
        Ok(_) => "; it wrote nothing before stopping".to_string(),
        Err(error) => format!("; its output could not be read: {error}"),
    }
}

impl Drop for Executor {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(address: SocketAddr) -> (Executor, String) {
    let mut log = executor_log();
    let mut process = Executor(
        Command::new(env!("CARGO_BIN_EXE_whip"))
            .args(["executor", "--bind", &address.to_string()])
            .env("WHIP_EXECUTOR_TOKEN", "incarnation-fixture")
            .stdout(Stdio::from(log.try_clone().expect("share the log")))
            .stderr(Stdio::from(log.try_clone().expect("share the log")))
            .spawn()
            .expect("start executor process"),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = ureq::get(&format!("http://{address}/exec/incarnation"))
            .set("authorization", "Bearer incarnation-fixture")
            .timeout(Duration::from_millis(200))
            .call();
        if let Ok(response) = response {
            let identity =
                exec_incarnation::read_handshake(&response.into_string().expect("handshake body"))
                    .expect("authenticated handshake");
            return (process, identity);
        }
        if let Some(status) = process.0.try_wait().expect("process status") {
            panic!(
                "executor exited during startup with {status}{}",
                said(&mut log)
            );
        }
        assert!(
            Instant::now() < deadline,
            "executor startup timed out after 10s{}",
            said(&mut log)
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn executor_incarnation_changes_on_real_process_replacement() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve endpoint");
    let address = listener.local_addr().expect("endpoint address");
    drop(listener);
    let (first, original) = start(address);
    let unauthenticated = ureq::get(&format!("http://{address}/exec/incarnation"))
        .call()
        .expect_err("handshake requires configured authentication");
    assert!(matches!(unauthenticated, ureq::Error::Status(401, _)));
    drop(first);
    let (_second, replacement) = start(address);
    assert_ne!(original, replacement);
    // This invalid inner dispatch would return a bound 400 if it reached the
    // handler. A stale binding must instead fail at the outer 409 boundary.
    let stale = exec_incarnation::delivery(&original, serde_json::json!({"protocol":"wrong"}))
        .expect("stale request");
    let refused = ureq::post(&format!("http://{address}/exec/bound"))
        .set("authorization", "Bearer incarnation-fixture")
        .send_string(&stale)
        .expect_err("replacement refuses old incarnation");
    assert!(matches!(refused, ureq::Error::Status(409, _)));
    let current = exec_incarnation::delivery(&replacement, serde_json::json!({"protocol":"wrong"}))
        .expect("current request");
    let unauthenticated = ureq::post(&format!("http://{address}/exec/bound"))
        .send_string(&current)
        .expect_err("bound route requires authentication");
    assert!(matches!(unauthenticated, ureq::Error::Status(401, _)));
    let response = ureq::post(&format!("http://{address}/exec/bound"))
        .set("authorization", "Bearer incarnation-fixture")
        .send_string(&current)
        .expect("bound handler refusal")
        .into_string()
        .expect("bound response");
    assert_eq!(
        exec_incarnation::read_completion(&response, &replacement)
            .expect("current binding")
            .0,
        400
    );
    assert!(exec_incarnation::read_completion(&response, &original).is_err());
}
