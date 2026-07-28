# Native Provider Config Examples

These files are release-package examples for native Codex and Claude
bindings. They are safe to publish because credential fields are references,
not secret values.

Validate from a checkout or release artifact with:

```sh
whip --json doctor --provider-config examples/provider-configs/native/native.example.json
scripts/check-native-provider-configs.sh
```

For strict release validation, point `WHIPPLESCRIPT_PROVIDER_CONFIGS` at this
file or at an environment-specific copy. The legacy
`WHIPPLESCRIPT_NATIVE_PROVIDER_CONFIGS` variable is still accepted.

```sh
WHIPPLESCRIPT_PROVIDER_CONFIGS=examples/provider-configs/native/native.example.json \
WHIPPLESCRIPT_NATIVE_PROVIDER_CONFIG_STRICT=1 \
scripts/check-native-provider-configs.sh
```

Before using these bindings for real provider turns, replace placeholder
credential refs, workspace policy, model names, profile ids, and health checks
with environment-specific values.

## Prices (`prices` block)

The optional top-level `prices` array is the spend price table: USD per
million tokens, per (provider, model), input and output rated separately.
Pricing is config-only by design — whip ships no built-in rates (a stale
built-in would misprice spend silently), and usage with no matching entry
records honestly as `unpriced` with cost 0, so the improve spend cap
cannot bind on it. Pricing happens at record time: spend events store the
computed cost and history is never repriced.

The rates in this example are maintained as plausible published list
prices at the time the example was last touched — **verify against your
provider's current price sheet before relying on the cap**, and add one
entry per (provider, model) pair your programs actually use. Provider
names: `anthropic`, `openai`, `openai-generic` for native coerce turns
(judges, proposers); agent-turn runs price under the provider string the
run records.
