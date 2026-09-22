# The one rule the fixture needs: a shell test whose ExternalRunnerTestInfo
# names the executor's `whip` adapter protocol (DR-0124 §14.5). The script
# lists its cases when WHIP_TEST_LIST is set, runs one case named by
# WHIP_TEST_CASE, and reports each case's verdict on stdout as
# `whip-test: case <name> <pass|fail>`; the executor reads the verdict line,
# never only the exit status.

def _whip_test_impl(ctx):
    script = ctx.attrs.script
    return [
        DefaultInfo(default_output = script),
        ExternalRunnerTestInfo(
            type = "whip",
            command = ["sh", script],
            env = ctx.attrs.env,
            labels = ctx.attrs.labels,
        ),
    ]

whip_test = rule(
    impl = _whip_test_impl,
    attrs = {
        "script": attrs.source(),
        "env": attrs.dict(key = attrs.string(), value = attrs.string(), default = {}),
        "labels": attrs.list(attrs.string(), default = []),
    },
)
