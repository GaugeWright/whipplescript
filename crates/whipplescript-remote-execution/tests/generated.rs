//! The checked-in protocol code is what the vendored proto files generate.
//! A drift between them is a build that speaks one protocol and a source
//! tree that says another. Set `WHIPPLESCRIPT_REGENERATE_PROTO=1` to write
//! the generated code into `src/proto` instead of comparing.

#![cfg(feature = "endpoint")]

use std::path::Path;

const GENERATED: &[&str] = &[
    "build.bazel.remote.execution.v2.rs",
    "build.bazel.semver.rs",
    "google.api.rs",
    "google.bytestream.rs",
    "google.longrunning.rs",
    "google.rpc.rs",
];

#[test]
fn the_checked_in_protocol_code_is_current() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let proto_dir = crate_dir.join("proto");
    let out = tempfile::tempdir().expect("a temporary directory");
    let fds = protox::Compiler::new([proto_dir.as_path()])
        .expect("the proto directory")
        .include_imports(true)
        .open_files([
            "build/bazel/remote/execution/v2/remote_execution.proto",
            "google/bytestream/bytestream.proto",
        ])
        .expect("the vendored protocol compiles")
        .file_descriptor_set();
    let mut config = prost_build::Config::new();
    config.out_dir(out.path());
    tonic_prost_build::configure()
        .out_dir(out.path())
        .build_client(true)
        .build_server(true)
        .emit_rerun_if_changed(false)
        .compile_fds_with_config(fds, config)
        .expect("the vendored protocol generates");
    let regenerate = std::env::var_os("WHIPPLESCRIPT_REGENERATE_PROTO").is_some();
    for name in GENERATED {
        let generated = std::fs::read_to_string(out.path().join(name)).expect(name);
        let target = crate_dir.join("src").join("proto").join(name);
        if regenerate {
            std::fs::write(&target, &generated).expect("write the generated code");
            continue;
        }
        let checked_in = std::fs::read_to_string(&target).expect(name);
        assert!(
            generated == checked_in,
            "{name} differs from what proto/ generates; regenerate it (see src/proto.rs)"
        );
    }
}
