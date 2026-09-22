//! The launch arguments Buck2 passes and the executor's own, after `--`.

use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Args {
    pub executor_addr: String,
    pub orchestrator_addr: String,
    /// Where the report is written; absent, the report goes to stdout, which
    /// Buck2 keeps in its own log.
    pub report: Option<String>,
    /// The workspace cut the wrapper names for the report.
    pub cut: Option<String>,
    pub timeout: Duration,
    /// Buck2's trace id for this invocation, the key into its event log.
    pub trace_id: Option<String>,
    /// The `--config-entry` values Buck2 passed, kept as provenance.
    pub config_entries: Vec<String>,
}

impl Args {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut executor_addr = None;
        let mut orchestrator_addr = None;
        let mut report = None;
        let mut cut = None;
        let mut timeout = Duration::from_secs(600);
        let mut trace_id = None;
        let mut config_entries = Vec::new();
        let mut args = args.into_iter();
        let mut own = false;
        while let Some(arg) = args.next() {
            if !own {
                match arg.as_str() {
                    "--" => own = true,
                    "--executor-addr" => executor_addr = Some(required(&mut args, &arg)?),
                    "--orchestrator-addr" => orchestrator_addr = Some(required(&mut args, &arg)?),
                    "--executor-fd" | "--orchestrator-fd" => {
                        return Err(format!(
                            "{arg}: this executor speaks Buck2's TCP launch; start the daemon with BUCK2_TEST_TPX_USE_TCP=1, as the wrapper does"
                        ));
                    }
                    // Buck2's own launch arguments, kept as provenance.
                    "--buck-trace-id" => trace_id = Some(required(&mut args, &arg)?),
                    "--config-entry" => config_entries.push(required(&mut args, &arg)?),
                    other => return Err(format!("unknown launch argument {other}")),
                }
            } else {
                match arg.as_str() {
                    // Buck2 leads the runner arguments with a placeholder
                    // positional and `--buck-test-info <path>`; neither is
                    // this executor's.
                    "--buck-test-info" | "--experiment" | "--tags" => {
                        required(&mut args, &arg)?;
                    }
                    positional if !positional.starts_with("--") => {}
                    "--report" => report = Some(required(&mut args, &arg)?),
                    "--cut" => cut = Some(required(&mut args, &arg)?),
                    "--timeout" => {
                        let seconds: u64 = required(&mut args, &arg)?
                            .parse()
                            .map_err(|_| "--timeout needs a whole number of seconds".to_owned())?;
                        timeout = Duration::from_secs(seconds);
                    }
                    other => return Err(format!("unknown executor argument {other}")),
                }
            }
        }
        Ok(Self {
            executor_addr: executor_addr.ok_or("Buck2 did not pass --executor-addr")?,
            orchestrator_addr: orchestrator_addr.ok_or("Buck2 did not pass --orchestrator-addr")?,
            report,
            cut,
            timeout,
            trace_id,
            config_entries,
        })
    }
}

fn required(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(list: &[&str]) -> Result<Args, String> {
        Args::parse(list.iter().map(|s| s.to_string()))
    }

    #[test]
    fn the_tcp_launch_and_the_executors_own_arguments_parse() {
        let args = parse(&[
            "--buck-trace-id",
            "trace-1",
            "--config-entry",
            "host=linux",
            "--executor-addr",
            "127.0.0.1:1",
            "--orchestrator-addr",
            "127.0.0.1:2",
            "--",
            "ignored",
            "--buck-test-info",
            "ignored",
            "--report",
            "/tmp/r.json",
            "--cut",
            "cut-a0",
            "--timeout",
            "30",
        ])
        .unwrap();
        assert_eq!(args.executor_addr, "127.0.0.1:1");
        assert_eq!(args.orchestrator_addr, "127.0.0.1:2");
        assert_eq!(args.report.as_deref(), Some("/tmp/r.json"));
        assert_eq!(args.cut.as_deref(), Some("cut-a0"));
        assert_eq!(args.timeout, Duration::from_secs(30));
        assert_eq!(args.trace_id.as_deref(), Some("trace-1"));
        assert_eq!(args.config_entries, vec!["host=linux"]);
    }

    #[test]
    fn the_descriptor_launch_is_refused_by_name() {
        let error = parse(&["--executor-fd", "5", "--orchestrator-fd", "6", "--"]).unwrap_err();
        assert!(error.contains("BUCK2_TEST_TPX_USE_TCP"), "{error}");
        assert!(parse(&["--"]).unwrap_err().contains("--executor-addr"));
        assert!(parse(&["--executor-addr", "a", "--"])
            .unwrap_err()
            .contains("--orchestrator-addr"));
        assert!(parse(&["--mystery", "x", "--"])
            .unwrap_err()
            .contains("unknown launch argument --mystery"));
        assert!(parse(&["--executor-addr"])
            .unwrap_err()
            .contains("needs a value"));
        assert!(parse(&[
            "--executor-addr",
            "a",
            "--orchestrator-addr",
            "b",
            "--",
            "--timeout",
            "soon"
        ])
        .unwrap_err()
        .contains("whole number"));
        assert_eq!(
            parse(&[
                "--executor-addr",
                "a",
                "--orchestrator-addr",
                "b",
                "--",
                "--bogus"
            ])
            .unwrap_err(),
            "unknown executor argument --bogus"
        );
    }
}
