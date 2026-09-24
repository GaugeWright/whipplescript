use std::io::{BufRead, BufReader, Read, Write};
use std::sync::{Arc, Mutex};

use super::*;
use crate::runner::ActionRunner;

type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;
type Respond = Arc<dyn Fn(&str, &[u8]) -> Vec<u8> + Send + Sync>;

/// Serve one HTTP/1.1 request on a connection, recording its path and its
/// authorization header.
fn serve_one(stream: impl Read + Write, respond: &Respond, log: &Seen) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
    let (mut length, mut authorization) = (0, None);
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap_or(0) == 0 {
            return;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_owned());
            }
        }
    }
    let mut body = vec![0; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    log.lock()
        .expect("the log")
        .push((path.clone(), authorization));
    let mut stream = reader.into_inner();
    let _ = stream.write_all(&respond(&path, &body));
    let _ = stream.flush();
}

/// A server on its own thread; `tls` wraps each connection when given.
fn serve_with(
    tls: Option<Arc<rustls::ServerConfig>>,
    respond: impl Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static,
) -> (String, Seen) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let url = match tls {
        Some(_) => format!("https://localhost:{port}"),
        None => format!("http://127.0.0.1:{port}"),
    };
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let respond: Respond = Arc::new(respond);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let (respond, log, tls) = (respond.clone(), log.clone(), tls.clone());
            std::thread::spawn(move || match tls {
                Some(config) => {
                    let Ok(connection) = rustls::ServerConnection::new(config) else {
                        return;
                    };
                    serve_one(rustls::StreamOwned::new(connection, stream), &respond, &log);
                }
                None => serve_one(stream, &respond, &log),
            });
        }
    });
    (url, seen)
}

fn serve(respond: impl Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static) -> (String, Seen) {
    serve_with(None, respond)
}

fn http(status: u16, value: &Value) -> Vec<u8> {
    raw(status, "application/json", value.to_string().as_bytes())
}

fn raw(status: u16, kind: &str, body: &[u8]) -> Vec<u8> {
    let mut answer = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: {kind}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    answer.extend_from_slice(body);
    answer
}

/// The real sidecar handler behind a server.
fn sidecar(root: &std::path::Path) -> impl Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static {
    let sidecar = ActionSidecar::new(root);
    move |path, body| match sidecar.handle(path, body).expect("an action route") {
        (status, Answer::Json(value)) => http(status, &value),
        (status, Answer::Bytes(bytes)) => raw(status, "application/octet-stream", &bytes),
    }
}

fn shout(input: &[u8]) -> PreparedAction {
    action(
        &[("in.txt", input)],
        "tr a-z A-Z < in.txt > out.txt",
        &["out.txt"],
    )
}

fn paths(seen: &Seen) -> Vec<String> {
    seen.lock()
        .expect("the log")
        .iter()
        .map(|(path, _)| path.clone())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_runner_sends_only_what_the_sidecar_lacks_and_reads_back_the_outputs() {
    let root = tempfile::tempdir().expect("scratch");
    let (url, seen) = serve(sidecar(root.path()));
    let runner = SidecarRunner::new(&url, Some("secret".into())).unwrap();
    assert_eq!(runner.name(), SIDECAR_EXECUTOR);
    for _ in 0..2 {
        let outcome = runner
            .run(shout(b"loud"))
            .await
            .expect("ran at the sidecar");
        assert!(
            matches!(&outcome.outputs["out.txt"], Output::File { bytes, .. } if bytes == b"LOUD")
        );
    }
    // The second run found the input held and sent no blob.
    assert_eq!(
        paths(&seen),
        [
            "/action/missing",
            "/action/blobs",
            "/action",
            "/action/missing",
            "/action"
        ]
    );
    assert!(seen
        .lock()
        .unwrap()
        .iter()
        .all(|(_, auth)| auth.as_deref() == Some("Bearer secret")));
}

#[test]
fn an_input_larger_than_a_chunk_is_uploaded_and_an_output_larger_than_an_answer_is_fetched() {
    let root = tempfile::tempdir().expect("scratch");
    let (url, seen) = serve(sidecar(root.path()));
    let runner = SidecarRunner::new(&url, None).unwrap();
    let input = vec![b'q'; CHUNK_BYTES + 1024];
    let outcome = runner
        .run_blocking(&action(
            &[("in.bin", &input)],
            "wc -c < in.bin > count; cat in.bin in.bin > twice",
            &["count", "twice"],
        ))
        .expect("ran at the sidecar");
    assert!(
        matches!(&outcome.outputs["count"], Output::File { bytes, .. }
        if String::from_utf8_lossy(bytes).trim() == input.len().to_string())
    );
    assert!(
        matches!(&outcome.outputs["twice"], Output::File { bytes, .. } if bytes.len() == 2 * input.len())
    );
    let paths = paths(&seen);
    assert_eq!(
        paths.iter().filter(|p| *p == "/action/upload").count(),
        2,
        "{paths:?}"
    );
    // Twice the input is three chunks: fetched, never inline.
    assert_eq!(
        paths.iter().filter(|p| *p == "/action/fetch").count(),
        3,
        "{paths:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sidecar_that_loses_an_input_is_sent_it_once_more_and_then_refused() {
    let root = tempfile::tempdir().expect("scratch");
    let real = sidecar(root.path());
    let losses = Arc::new(Mutex::new(1));
    let remaining = losses.clone();
    let blob_dir = root.path().join("blobs");
    let (url, _) = serve(move |path, body| {
        if path == "/action" && *remaining.lock().unwrap() > 0 {
            *remaining.lock().unwrap() -= 1;
            let _ = std::fs::remove_dir_all(&blob_dir);
        }
        real(path, body)
    });
    let runner = SidecarRunner::new(&url, None).unwrap();
    runner
        .run(shout(b"once"))
        .await
        .expect("recovered by one resend");
    *losses.lock().unwrap() = 2;
    assert_eq!(
        runner.run(shout(b"twice")).await.unwrap_err(),
        format!("the sidecar at {url} refused /action (409): inputs are missing from the sidecar")
    );
}

#[test]
fn what_the_runner_cannot_use_it_refuses_by_name() {
    assert_eq!(
        SidecarRunner::new("ftp://pool.example:8080", None).err(),
        Some("the sidecar runner speaks HTTP or HTTPS; ftp://pool.example:8080 is neither".into())
    );
    let run = |url: &str, action: &PreparedAction| {
        SidecarRunner::new(url, None)
            .unwrap()
            .run_blocking(action)
            .unwrap_err()
    };
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    assert!(run(&closed, &shout(b"x")).starts_with(&format!(
        "the sidecar at {closed} did not answer /action/missing: "
    )));
    let (url, _) = serve(|_, _| b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\nnot json".to_vec());
    assert!(run(&url, &shout(b"x")).starts_with(&format!(
        "the sidecar at {url} answered /action/missing with no JSON: "
    )));
    let (url, _) = serve(|_, _| http(401, &json!({"error": "unauthorized"})));
    assert_eq!(
        run(&url, &shout(b"x")),
        format!("the sidecar at {url} refused /action/missing (401): unauthorized")
    );
    let stranger = Digest::of(b"not an input").to_string();
    let (url, _) = serve(move |_, _| {
        http(
            200,
            &json!({"protocol": ACTION_PROTOCOL, "missing": [stranger.clone()]}),
        )
    });
    assert_eq!(
        run(&url, &shout(b"x")),
        format!(
            "the sidecar at {url} asked for {}, which this action does not name",
            Digest::of(b"not an input")
        )
    );
    let wants = |digest: Digest| {
        move |path: &str, _: &[u8]| {
            if path == "/action/missing" {
                http(
                    200,
                    &json!({"protocol": ACTION_PROTOCOL, "missing": [digest.to_string()]}),
                )
            } else {
                http(507, &json!({"error": "full"}))
            }
        }
    };
    let (url, _) = serve(wants(Digest::of(b"x")));
    assert_eq!(
        run(&url, &shout(b"x")),
        format!("the sidecar at {url} refused /action/blobs (507): full")
    );
    let large = vec![b'l'; CHUNK_BYTES + 1];
    let (url, _) = serve(wants(Digest::of(&large)));
    assert_eq!(
        run(&url, &shout(&large)),
        format!("the sidecar at {url} refused /action/upload (507): full")
    );
}

#[test]
fn an_output_the_sidecar_lost_or_cut_short_is_refused_by_name() {
    let root = tempfile::tempdir().expect("scratch");
    let real = sidecar(root.path());
    // A sidecar that answers the run naming a large output, then has lost it
    // — or hands back nothing of it.
    let serving = |lose: bool| {
        let real = sidecar(root.path());
        move |path: &str, body: &[u8]| {
            if path == "/action/fetch" {
                return if lose {
                    http(404, &json!({"error": "the sidecar does not hold it"}))
                } else {
                    raw(200, "application/octet-stream", b"")
                };
            }
            real(path, body)
        }
    };
    let big = action(&[], "head -c 2000000 /dev/zero > big", &["big"]);
    let (url, _) = serve(serving(true));
    assert_eq!(
        SidecarRunner::new(&url, None)
            .unwrap()
            .run_blocking(&big)
            .unwrap_err(),
        format!("the sidecar at {url} refused /action/fetch (404): the sidecar does not hold it")
    );
    let (url, _) = serve(serving(false));
    let produced = Digest::of(&vec![0u8; 2_000_000]);
    assert_eq!(
        SidecarRunner::new(&url, None)
            .unwrap()
            .run_blocking(&big)
            .unwrap_err(),
        format!("the sidecar at {url} ended {produced} after 0 bytes")
    );
    drop(real);
}

/// A CA, and a server certificate for `localhost` it signed.
fn authority() -> (String, Arc<rustls::ServerConfig>) {
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("a ca key");
    let ca = ca_params.self_signed(&ca_key).expect("a ca");
    let leaf_key = rcgen::KeyPair::generate().expect("a server key");
    let leaf = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .expect("server params")
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("a server certificate");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
    )
    .expect("a server config");
    (ca.pem(), Arc::new(config))
}

#[test]
fn over_https_the_runner_trusts_the_pools_authority_and_nothing_else() {
    let root = tempfile::tempdir().expect("scratch");
    let (ca_pem, config) = authority();
    let (url, seen) = serve_with(Some(config), sidecar(root.path()));
    let dir = tempfile::tempdir().expect("scratch");
    let ca = dir.path().join("pool-ca.pem");
    std::fs::write(&ca, &ca_pem).expect("the fixture's own step");
    let outcome = SidecarRunner::trusting(&url, Some("secret".into()), &ca)
        .unwrap()
        .run_blocking(&shout(b"private"))
        .expect("ran over https");
    assert!(
        matches!(&outcome.outputs["out.txt"], Output::File { bytes, .. } if bytes == b"PRIVATE")
    );
    assert!(seen
        .lock()
        .unwrap()
        .iter()
        .all(|(_, auth)| auth.as_deref() == Some("Bearer secret")));
    // Without the pool's authority, the platform's roots do not vouch for it.
    let refused = SidecarRunner::new(&url, None)
        .unwrap()
        .run_blocking(&shout(b"private"))
        .unwrap_err();
    assert!(
        refused.starts_with(&format!(
            "the sidecar at {url} did not answer /action/missing: "
        )),
        "{refused}"
    );
    // A bundle it cannot use is refused before anything is sent.
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "").expect("the fixture's own step");
    assert_eq!(
        SidecarRunner::trusting(&url, None, &empty).err(),
        Some(format!(
            "{} is not a usable PEM certificate bundle: it holds no certificate",
            empty.display()
        ))
    );
    let absent = dir.path().join("absent.pem");
    assert!(SidecarRunner::trusting(&url, None, &absent)
        .err()
        .expect("refused")
        .starts_with(&format!(
            "{} is not a usable PEM certificate bundle: ",
            absent.display()
        )));
    let garbage = dir.path().join("garbage.pem");
    std::fs::write(
        &garbage,
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
    )
    .expect("the fixture's own step");
    assert!(SidecarRunner::trusting(&url, None, &garbage)
        .err()
        .expect("refused")
        .starts_with(&format!(
            "{} is not a usable PEM certificate bundle: ",
            garbage.display()
        )));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_endpoint_records_what_the_sidecar_ran_as_the_sidecars() {
    use crate::endpoint::Endpoint;
    use crate::proto::re;
    use crate::store::{Labels, Principal};
    use prost::Message;
    let root = tempfile::tempdir().expect("scratch");
    let (url, seen) = serve(sidecar(root.path()));
    let endpoint = Endpoint::new(Arc::new(SidecarRunner::new(&url, None).unwrap()));
    let (_, view) = endpoint
        .admit(Principal {
            name: "owner".into(),
            labels: Labels::new(),
        })
        .expect("admitted");
    let put = |bytes: Vec<u8>| endpoint.store.put(&view, &bytes, &Labels::new()).unwrap();
    let file = put(b"remote".to_vec());
    let command = put(re::Command {
        arguments: vec![
            "sh".into(),
            "-c".into(),
            "tr a-z A-Z < in.txt > out.txt".into(),
        ],
        output_paths: vec!["out.txt".into()],
        ..Default::default()
    }
    .encode_to_vec());
    let root_directory = put(re::Directory {
        files: vec![re::FileNode {
            name: "in.txt".into(),
            digest: Some(file.to_proto()),
            is_executable: false,
            node_properties: None,
        }],
        ..Default::default()
    }
    .encode_to_vec());
    let action = put(re::Action {
        command_digest: Some(command.to_proto()),
        input_root_digest: Some(root_directory.to_proto()),
        ..Default::default()
    }
    .encode_to_vec());
    let executed = endpoint.execute(&view, &action, false).await.expect("ran");
    assert_eq!(
        executed.result.execution_metadata.as_ref().unwrap().worker,
        SIDECAR_EXECUTOR
    );
    let output =
        Digest::from_proto(executed.result.output_files[0].digest.as_ref().unwrap()).unwrap();
    assert_eq!(
        endpoint.store.get(&view, &output).as_deref(),
        Some(&b"REMOTE"[..])
    );
    assert_eq!(
        endpoint.evidence(&action).map(|entry| entry.origin),
        Some(crate::cache::Origin::Executed {
            executor: SIDECAR_EXECUTOR.into()
        })
    );
    assert!(paths(&seen).iter().any(|path| path == "/action"));
    assert!(
        endpoint
            .execute(&view, &action, false)
            .await
            .expect("served")
            .cached
    );
}
