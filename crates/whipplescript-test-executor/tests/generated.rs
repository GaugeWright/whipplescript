//! The checked-in protocol code is what the vendored proto files generate.
//! A drift between them is a build that speaks one protocol and a source
//! tree that says another.

use std::path::Path;

#[test]
fn the_checked_in_protocol_code_is_current() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let proto_dir = crate_dir.join("proto");
    let out = tempfile::tempdir().expect("a temporary directory");
    let fds = protox::Compiler::new([proto_dir.as_path()])
        .expect("the proto directory")
        .include_imports(true)
        .open_files(["test.proto", "data.proto", "host_sharing.proto"])
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
    for name in ["buck.test.rs", "buck.data.rs", "buck.host_sharing.rs"] {
        let generated = std::fs::read_to_string(out.path().join(name)).expect(name);
        let checked_in =
            std::fs::read_to_string(crate_dir.join("src").join("proto").join(name)).expect(name);
        assert!(
            generated == checked_in,
            "{name} differs from what proto/ generates; regenerate it (see src/proto.rs)"
        );
    }
}
