use super::*;

fn action(inputs: &[(&str, &[u8])], script: &str, outputs: &[&str]) -> PreparedAction {
    PreparedAction {
        arguments: vec!["sh".into(), "-c".into(), script.into()],
        environment: vec![("LANG".into(), "C".into())],
        working_directory: String::new(),
        inputs: inputs
            .iter()
            .map(|(path, bytes)| ((*path).to_owned(), (bytes.to_vec(), false)))
            .collect(),
        output_paths: outputs.iter().map(|o| (*o).to_owned()).collect(),
        timeout: Some(Duration::from_secs(30)),
    }
}

fn body(value: Value) -> Vec<u8> {
    value.to_string().into_bytes()
}

fn json_of(answer: Answer) -> Value {
    match answer {
        Answer::Json(value) => value,
        Answer::Bytes(bytes) => panic!("expected JSON, got {} bytes", bytes.len()),
    }
}

fn ask(sidecar: &ActionSidecar, path: &str, request: Value) -> (u16, Value) {
    let (status, answer) = sidecar.handle(path, &body(request)).expect("a route");
    (status, json_of(answer))
}

fn error(sidecar: &ActionSidecar, path: &str, request: Value) -> (u16, String) {
    let (status, value) = ask(sidecar, path, request);
    (
        status,
        value["error"].as_str().unwrap_or_default().to_owned(),
    )
}

fn batch(digest: &Digest, bytes: &[u8]) -> Value {
    json!({"protocol": ACTION_PROTOCOL, "blobs": {digest.to_string(): encode(bytes)}})
}

fn chunk(digest: &Digest, offset: u64, bytes: &[u8]) -> Value {
    json!({"protocol": ACTION_PROTOCOL, "digest": digest.to_string(), "offset": offset, "bytes": encode(bytes)})
}

/// What a sidecar would fetch for a runner, straight through the handler.
fn fetch_from(sidecar: &ActionSidecar) -> impl FnMut(&Digest) -> Result<Vec<u8>, String> + '_ {
    move |digest| match sidecar.handle(
        "/action/fetch",
        &body(json!({"protocol": ACTION_PROTOCOL, "digest": digest.to_string()})),
    ) {
        Some((200, Answer::Bytes(bytes))) => Ok(bytes),
        other => Err(format!("{other:?}")),
    }
}

#[test]
fn the_sidecar_runs_what_it_holds_and_names_what_it_lacks() {
    let root = tempfile::tempdir().expect("scratch");
    let sidecar = ActionSidecar::new(root.path());
    let prepared = action(
        &[("in.txt", b"shout")],
        "tr a-z A-Z < in.txt > out.txt; mkdir -p d; echo x > d/x; echo ran",
        &["out.txt", "d"],
    );
    let input = Digest::of(b"shout");
    assert_eq!(sidecar.handle("/exec", b"{}"), None);
    let (status, answer) = ask(
        &sidecar,
        "/action/missing",
        json!({"protocol": ACTION_PROTOCOL, "digests": [input.to_string(), Digest::empty().to_string()]}),
    );
    assert_eq!(
        (status, answer["missing"].clone()),
        (200, json!([input.to_string()]))
    );
    // Asked to run before it holds the input, it names what is missing.
    let (status, answer) = ask(&sidecar, "/action", encode_action(&prepared));
    assert_eq!(
        (status, answer["missing"].clone()),
        (409, json!([input.to_string()]))
    );
    assert_eq!(
        error(&sidecar, "/action/blobs", batch(&input, b"other")),
        (
            400,
            format!("the bytes sent as {input} are not those bytes")
        )
    );
    assert_eq!(
        ask(&sidecar, "/action/blobs", batch(&input, b"shout")).0,
        200
    );
    let (status, answer) = ask(&sidecar, "/action", encode_action(&prepared));
    assert_eq!(status, 200, "{answer}");
    let outcome = decode_outcome(&answer, fetch_from(&sidecar)).unwrap();
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(outcome.stdout, b"ran\n");
    assert!(matches!(&outcome.outputs["out.txt"], Output::File { bytes, .. } if bytes == b"SHOUT"));
    assert!(matches!(&outcome.outputs["d"], Output::Directory { files } if files["x"].0 == b"x\n"));
    // What the wire refuses, it refuses by name.
    for (path, request, expected) in [
        (
            "/action",
            json!({"protocol": "other/v1"}),
            "expected protocol whipplescript.build.action/v2, not other/v1",
        ),
        (
            "/action/blobs",
            json!({"protocol": ACTION_PROTOCOL}),
            "a blob batch names no blobs",
        ),
        (
            "/action/missing",
            json!({"protocol": ACTION_PROTOCOL, "digests": ["nohash"]}),
            "not a digest: nohash",
        ),
        (
            "/action/upload",
            json!({"protocol": ACTION_PROTOCOL, "digest": input.to_string()}),
            "an upload names no offset",
        ),
    ] {
        assert_eq!(error(&sidecar, path, request), (400, expected.to_owned()));
    }
    assert!(error(&sidecar, "/action", Value::String("x".into()))
        .1
        .starts_with("expected protocol"));
    assert!(sidecar
        .handle("/action", b"not json")
        .map(|(_, a)| json_of(a))
        .unwrap()["error"]
        .as_str()
        .unwrap()
        .starts_with("invalid JSON body: "));
    assert_eq!(
        error(
            &sidecar,
            "/action",
            json!({"protocol": ACTION_PROTOCOL, "arguments": []})
        ),
        (422, "an action names no command".to_owned())
    );
}

#[test]
fn a_large_blob_arrives_in_chunks_and_a_large_output_is_fetched_by_digest() {
    let root = tempfile::tempdir().expect("scratch");
    let sidecar = ActionSidecar::new(root.path());
    let big = vec![b'z'; 3000];
    let digest = Digest::of(&big);
    assert_eq!(
        ask(&sidecar, "/action/upload", chunk(&digest, 0, &big[..1000])).1["committed"],
        1000
    );
    // A chunk at the wrong offset is told where the upload stands.
    let (status, answer) = ask(&sidecar, "/action/upload", chunk(&digest, 0, &big[..1000]));
    assert_eq!((status, answer["committed"].clone()), (409, json!(1000)));
    assert_eq!(
        answer["error"],
        format!("the upload of {digest} is at 1000, not 0")
    );
    let (_, answer) = ask(
        &sidecar,
        "/action/upload",
        chunk(&digest, 1000, &big[1000..]),
    );
    assert_eq!(answer["complete"], true);
    assert_eq!(
        ask(
            &sidecar,
            "/action/missing",
            json!({"protocol": ACTION_PROTOCOL, "digests": [digest.to_string()]})
        )
        .1["missing"],
        json!([])
    );
    // Once held, a further upload of it is already complete.
    assert_eq!(
        ask(&sidecar, "/action/upload", chunk(&digest, 0, b"")).1["complete"],
        true
    );
    // An upload that outgrows its digest, or ends as other bytes, is dropped.
    let other = Digest::of(b"abcd");
    assert_eq!(
        error(&sidecar, "/action/upload", chunk(&other, 0, b"abcde")),
        (
            400,
            format!("the upload of {other} is longer than its digest says")
        )
    );
    assert_eq!(
        error(&sidecar, "/action/upload", chunk(&other, 0, b"wxyz")),
        (
            400,
            format!("the bytes sent as {other} are not those bytes")
        )
    );
    assert_eq!(
        ask(&sidecar, "/action/upload", chunk(&other, 0, b"ab")).1["committed"],
        2,
        "a dropped upload starts again from nothing"
    );
    // An output larger than the answer carries inline is named by digest,
    // left in the cache, and fetched in chunks.
    let prepared = action(
        &[("in.bin", &big)],
        "cat in.bin in.bin in.bin in.bin in.bin in.bin in.bin in.bin in.bin in.bin > ten; \
         i=0; while [ $i -lt 40 ]; do cat ten; i=$((i+1)); done > big.out",
        &["big.out"],
    );
    let (status, answer) = ask(&sidecar, "/action", encode_action(&prepared));
    assert_eq!(status, 200, "{answer}");
    let named = &answer["outputs"]["big.out"]["file"];
    assert!(named.get("bytes").is_none(), "{named}");
    let produced = parse_digest(named["digest"].as_str().unwrap()).unwrap();
    assert_eq!(produced.size_bytes, 3000 * 400);
    assert!(produced.size_bytes as usize > INLINE_BYTES);
    let (status, answer_bytes) = sidecar
        .handle(
            "/action/fetch",
            &body(json!({"protocol": ACTION_PROTOCOL, "digest": produced.to_string(), "offset": 10, "limit": 5})),
        )
        .unwrap();
    assert_eq!(
        (status, answer_bytes),
        (200, Answer::Bytes(b"zzzzz".to_vec()))
    );
    let outcome = decode_outcome(&answer, fetch_from(&sidecar)).unwrap();
    assert!(
        matches!(&outcome.outputs["big.out"], Output::File { bytes, .. } if bytes.len() == 1_200_000)
    );
    let unknown = Digest::of(b"never kept");
    assert_eq!(
        error(
            &sidecar,
            "/action/fetch",
            json!({"protocol": ACTION_PROTOCOL, "digest": unknown.to_string()})
        ),
        (404, format!("the sidecar does not hold {unknown}"))
    );
    // A fetch that hands back other bytes than the digest names is refused.
    let mut lying = |_: &Digest| Ok(b"not it".to_vec());
    assert_eq!(
        decode_outcome(&answer, &mut lying).unwrap_err(),
        format!("the sidecar sent other bytes for big.out than {produced}")
    );
}

#[test]
fn the_cache_evicts_the_least_recently_used_past_its_capacity() {
    let root = tempfile::tempdir().expect("scratch");
    let sidecar = ActionSidecar::with_capacity(root.path(), 100);
    let blob = |fill: u8| vec![fill; 40];
    let (a, b, c) = (blob(b'a'), blob(b'b'), blob(b'c'));
    let pause = || std::thread::sleep(Duration::from_millis(30));
    assert_eq!(
        ask(&sidecar, "/action/blobs", batch(&Digest::of(&a), &a)).0,
        200
    );
    pause();
    assert_eq!(
        ask(&sidecar, "/action/blobs", batch(&Digest::of(&b), &b)).0,
        200
    );
    pause();
    // Asking after a marks it used, so b is now the oldest.
    ask(
        &sidecar,
        "/action/missing",
        json!({"protocol": ACTION_PROTOCOL, "digests": [Digest::of(&a).to_string()]}),
    );
    pause();
    assert_eq!(
        ask(&sidecar, "/action/blobs", batch(&Digest::of(&c), &c)).0,
        200
    );
    let (_, answer) = ask(
        &sidecar,
        "/action/missing",
        json!({"protocol": ACTION_PROTOCOL, "digests": [Digest::of(&a).to_string(), Digest::of(&b).to_string(), Digest::of(&c).to_string()]}),
    );
    assert_eq!(answer["missing"], json!([Digest::of(&b).to_string()]));
}

#[test]
fn a_cache_it_cannot_write_or_read_refuses_by_name() {
    let input = Digest::of(b"shout");
    let root = tempfile::tempdir().expect("scratch");
    std::fs::write(
        root.path().join("blobs"),
        b"a file where the directory goes",
    )
    .expect("the fixture's own step");
    let (status, message) = error(
        &ActionSidecar::new(root.path()),
        "/action/blobs",
        batch(&input, b"shout"),
    );
    assert_eq!(status, 500);
    assert!(message.starts_with(&format!(
        "cannot create {}: ",
        root.path().join("blobs").display()
    )));
    let blocked = tempfile::tempdir().expect("scratch");
    std::fs::create_dir_all(blocked.path().join("blobs").join(&input.hash).join("x"))
        .expect("the fixture's own step");
    let (status, message) = error(
        &ActionSidecar::new(blocked.path()),
        "/action/blobs",
        batch(&input, b"shout"),
    );
    assert_eq!(status, 500);
    assert!(message.starts_with(&format!("cannot keep blob {input}: ")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // An upload whose partial file cannot be appended to.
        let stuck = tempfile::tempdir().expect("scratch");
        let partial = stuck.path().join("partial").join(&input.hash);
        std::fs::create_dir_all(partial.parent().unwrap()).expect("the fixture's own step");
        std::fs::write(&partial, b"").expect("the fixture's own step");
        std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o444))
            .expect("the fixture's own step");
        let (status, message) = error(
            &ActionSidecar::new(stuck.path()),
            "/action/upload",
            chunk(&input, 0, b"sh"),
        );
        assert_eq!(status, 500);
        assert!(message.starts_with(&format!("cannot keep blob {input}: ")));
        let sealed = tempfile::tempdir().expect("scratch");
        let sidecar = ActionSidecar::new(sealed.path());
        assert_eq!(
            ask(&sidecar, "/action/blobs", batch(&input, b"shout")).0,
            200
        );
        let path = sealed.path().join("blobs").join(&input.hash);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
            .expect("the fixture's own step");
        let (status, message) = error(
            &sidecar,
            "/action/fetch",
            json!({"protocol": ACTION_PROTOCOL, "digest": input.to_string()}),
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("the fixture's own step");
        assert_eq!(status, 500);
        assert!(message.starts_with(&format!("cannot read blob {input}: ")));
    }
}

#[test]
fn an_answer_the_runner_cannot_read_is_refused_by_name() {
    let never = |_: &Digest| -> Result<Vec<u8>, String> { Err("no fetch".into()) };
    assert_eq!(
        decode_outcome(&json!({"protocol": ACTION_PROTOCOL}), never).unwrap_err(),
        "the sidecar's answer names no exit code"
    );
    assert_eq!(
        decode_outcome(
            &json!({"protocol": ACTION_PROTOCOL, "exit_code": 0, "outputs": {"o": {}}}),
            never
        )
        .unwrap_err(),
        "output o is neither a file nor a directory"
    );
    assert_eq!(
        decode_outcome(
            &json!({"protocol": ACTION_PROTOCOL, "exit_code": 0, "stdout": {"digest": Digest::empty().to_string(), "bytes": "!!"}}),
            never
        )
        .unwrap_err(),
        "stdout is not base64: Invalid symbol 33, offset 0."
    );
}

#[test]
fn capacity_and_root_come_from_the_executors_environment_or_their_defaults() {
    // Read, never written: the executor's environment is the operator's.
    let capacity = default_sidecar_capacity();
    match std::env::var("WHIP_EXECUTOR_ACTIONS_BYTES") {
        Ok(value) if value.trim().parse::<u64>().is_ok_and(|v| v > 0) => {
            assert_eq!(capacity, value.trim().parse::<u64>().unwrap());
        }
        _ => assert_eq!(capacity, DEFAULT_CAPACITY_BYTES),
    }
    assert!(!default_sidecar_root().as_os_str().is_empty());
}

#[cfg(feature = "endpoint")]
mod client;
