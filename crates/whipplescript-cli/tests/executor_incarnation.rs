//! Actual process replacement at the same endpoint must reject old bindings.
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use whipplescript_kernel::exec_incarnation;

struct Executor(Child);
impl Drop for Executor {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(address: SocketAddr) -> (Executor, String) {
    let mut process = Executor(
        Command::new(env!("CARGO_BIN_EXE_whip"))
            .args(["executor", "--bind", &address.to_string()])
            .env("WHIP_EXECUTOR_TOKEN", "incarnation-fixture")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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
        assert!(
            process.0.try_wait().expect("process status").is_none(),
            "executor exited during startup"
        );
        assert!(Instant::now() < deadline, "executor startup timed out");
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
