# Buck2 test-executor fixture

A prelude-free Buck2 project the WhippleScript test executor (DR-0124 §14.5)
is qualified against. Its build file is `FIXTURE`, so the company's Buck2 workspace, whose packages are `BUCK` files, never evaluates it. Its one rule, `whip_test` in `rules.bzl`, returns an
`ExternalRunnerTestInfo` of type `whip`: the script lists its cases under
`WHIP_TEST_LIST`, runs the case named by `WHIP_TEST_CASE`, and reports each
verdict as a `whip-test: case <name> <pass|fail>` line. Three targets cover
the executor's three obligations from the admission fixtures' BE-02: a suite
that passes, a suite whose wrapper swallows a failure and exits 0, and a
suite that runs and reports nothing.

The executor crate's integration test runs
`buck2 test //... -- --report <path>` here with
`-c test.v2_test_executor=<the built executor>` and reads the report.

`//:remote` (`platforms.bzl`) is a remote-only execution platform, registered
only when a build selects it with `-c build.execution_platforms=root//:remote`
or a `.buckconfig.local` says so, and `//secret-gate:shout` is a real
`actions.run` over this package's build file: under that platform every
action goes to the wrapper's remote-execution endpoint (DR-0124 §14.4), which
the endpoint crate's `buck2` test drives with a real daemon (BE-05).

`secret-gate/` is a second package, the qualification experiment of DR-0124
§14.2 (BE-03, BE-04): its build file globs `protected/` and generates
`//secret-gate:gate` with `whip_file`, an action with no file input whose
content says whether the listing was observed. The Home daemon's wrapper
labels `secret-gate/protected/` `protected` in its fixture, so a principal
without that label receives a projection without the directory, builds the
other branch there, and is refused the cut's result by name — while
`//:passing` in the root package, whose listing stops at the sub-package,
stays public.
