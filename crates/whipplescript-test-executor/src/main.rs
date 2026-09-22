//! `whip-test-executor`: the Buck2 test executor of DR-0124 §14.5.
//!
//! Buck2 is configured to call this binary (`test.v2_test_executor`) and
//! launches it with two connections: one on which this process serves the
//! `TestExecutor` service and receives each test target's external runner
//! spec, and one on which it is a client of Buck2's `TestOrchestrator`,
//! asking Buck2 to execute commands and reporting what it found. Every case
//! runs as its own action through the orchestrator, so Buck2's executors,
//! cache and materialization apply per case and Buck2's own event log carries
//! each result. The executor decides no adequacy: it writes the versioned
//! report of `whipplescript_core::norm_buck2_report`, and the norm plane's
//! adapter judges it.
//!
//! This executor speaks the TCP launch (`--executor-addr`, `--orchestrator-addr`),
//! which Buck2 uses when its daemon runs with `BUCK2_TEST_TPX_USE_TCP=1`; the
//! wrapper starts the daemon that way. The file-descriptor launch is refused
//! by name, because taking ownership of an inherited descriptor is unsafe
//! code and this workspace forbids it.

mod args;
mod executor;
mod proto;
mod report;
mod run;
mod transport;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args = match args::Args::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("whip-test-executor: {error}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("whip-test-executor: cannot start a runtime: {error}");
            return ExitCode::from(2);
        }
    };
    match runtime.block_on(run::serve(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("whip-test-executor: {error}");
            ExitCode::from(2)
        }
    }
}
