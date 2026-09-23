# The execution platform that sends every action to the wrapper's
# remote-execution endpoint (DR-0124 §14.4): remote only, so an action that
# ran at all ran there, with the endpoint's action cache consulted first and
# the platform naming the labels the endpoint classifies results under.
# The fixture's tests run with no platform registered, so nothing here is in
# their way; the endpoint's fixture selects it with
# `-c build.execution_platforms=root//:remote`.

def _remote_platform_impl(ctx):
    return [
        DefaultInfo(),
        ExecutionPlatformRegistrationInfo(
            platforms = [
                ExecutionPlatformInfo(
                    label = ctx.label.raw_target(),
                    configuration = ConfigurationInfo(constraints = {}, values = {}),
                    executor_config = CommandExecutorConfig(
                        local_enabled = False,
                        remote_enabled = True,
                        remote_cache_enabled = True,
                        allow_cache_uploads = False,
                        remote_execution_use_case = "buck2-default",
                        remote_execution_properties = ctx.attrs.properties,
                    ),
                ),
            ],
        ),
    ]

remote_platform = rule(
    impl = _remote_platform_impl,
    attrs = {
        "properties": attrs.dict(key = attrs.string(), value = attrs.string(), default = {}),
    },
)
