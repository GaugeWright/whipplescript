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
