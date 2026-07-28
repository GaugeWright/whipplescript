# Examples

CI checks each selected example in [`examples/`](https://github.com/jamesjscully/whipplescript/tree/main/examples/).
Each example also has a stable `.ir` snapshot. The purpose of this catalog is
not a large quantity of examples. Each example is present because it shows a
different capability of the language or a useful pattern of coordination.

An example with the `@service` tag becomes idle or recurs. It does not complete.
This behavior is deliberate. Each example below checks with no credentials. By
default, an agent turn uses the built-in **`owned`** brokered harness. In this
harness, whip runs the tool-use loop itself. A fixture model client that needs
no credentials drives the `run` command and CI. Two examples show the
**optional** delegating providers instead. These examples are
`multi-agent-bounded-concurrency` (Codex and Claude) and `incident-router`.
The `incident-router` example routes across `codex` and `claude` `AgentRef`
values at check time. The `scripts/check-docs-examples.sh` script verifies the
commands in this catalog.

## Start Here

| Example | Check command | Why it exists |
| --- | --- | --- |
| [`minimal-noop.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/minimal-noop.whip) | `whip check examples/minimal-noop.whip` | The smallest complete workflow. It uses `started`, `record`, `complete`, and an output contract. |
| [`triage-chain.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/triage-chain.whip) | `whip check examples/triage-chain.whip` | A sequential `then` chain: an agent step, a coerced approval, a `case` branch, and a terminal output or failure. |

## Core Language Patterns

| Example | Check command | Why it exists |
| --- | --- | --- |
| [`coerce-branch.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/coerce-branch.whip) | `whip check examples/coerce-branch.whip` | A named typed model decision with a success fact. A failure files an issue into a review tracker. A person then works the issue with the `whip issue` command. |
| [`terminal-output-union.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/terminal-output-union.whip) | `whip check examples/terminal-output-union.whip` | An exhaustive `case` over the terminal union of an effect: completed, failed, timed out, and cancelled. |
| [`incident-router.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/incident-router.whip) | `whip check examples/incident-router.whip` | Full guards and dynamic routing: arrays, maps, optionals, `exists`, `in`, assertions, and `AgentRef`. This example also shows the **optional providers**. It routes `AgentRef` values across `codex` and `claude` at check time. Codex and Claude are the delegating providers that you can use. |
| [`scheduled-escalation.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/scheduled-escalation.whip) | `whip check examples/scheduled-escalation.whip` | Time as effects: `timeout`, `timer until`, `cancel`, and the handling of a terminal union. |
| [`exec-json-ingest.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/exec-json-ingest.whip) | `whip check examples/exec-json-ingest.whip` | Local commands with a gate and typed JSON output: `exec -> Type` and `exec -> each Type`. |
| [`event-bridge.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/event-bridge.whip) | `whip check examples/event-bridge.whip` | Ingress of an external signal with the `whip signal` command, and injection of a directed signal. The `emit signal ... to <instance>` statement relays an acknowledgement into a live peer instance. That instance reacts through a typed `when` clause. If the target is absent, the effect fails with `target instance <id> not found`. |
| [`reusable-review-pattern.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/reusable-review-pattern.whip) | `whip check examples/reusable-review-pattern.whip` | Reuse at compile time with `pattern` and `apply`. There is no hidden subroutine at run time. |
| [`messaging-demo.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/messaging-demo.whip) | `whip check examples/messaging-demo.whip` | The `std.messaging` package: a `channel`, an inbound `when message from <channel>` clause that binds the generic `Message`, and an outbound `send via <channel>` statement. To inject inbound data, use the `whip message` command. |
| [`file-store-demo.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/file-store-demo.whip) | `whip check examples/file-store-demo.whip` | The `std.files` package: a `file store` policy boundary with `allow read` globs and `allow write` globs. The example does a durable `write text ... mode upsert` statement and then a `read text ... as f` statement. It completes with `f.content`. |
| [`owned-harness-demo.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/owned-harness-demo.whip) | `whip check examples/owned-harness-demo.whip` | The built-in **`owned`** brokered harness (DR-0024). Whip runs the tool-use loop of the agent itself. The `when <agent> completed turn` clause settles to the same `agent.turn.<status>` fact as a delegating provider. Run this example with `--provider owned`. |

## Coordination Recipes

| Example | Check command | Why it exists |
| --- | --- | --- |
| [`queue-worker-with-review.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/queue-worker-with-review.whip) | `whip check examples/queue-worker-with-review.whip` | The canonical work loop: claim a queue item, run an agent, do a typed review, and then finish, release, or escalate. |
| [`multi-agent-bounded-concurrency.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/multi-agent-bounded-concurrency.whip) | `whip check examples/multi-agent-bounded-concurrency.whip` | Two agents that have different capacities, and a handoff to a reviewer. This example also shows the **optional providers**. It binds Codex and Claude. |
| [`circuit-breaker.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/circuit-breaker.whip) | `whip check examples/circuit-breaker.whip` | A resilience pattern as facts, a counter with a limit, and an explicit policy for failure. |
| [`ralph.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/ralph.whip) | `whip check examples/ralph.whip` | A small recurrent service. The completion of the agent supplies the next turn. Capacity limits the loop. |

## Showcase Workflows

| Example | Check command | Why it exists |
| --- | --- | --- |
| [`openclaw-lite.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/openclaw-lite.whip) | `whip check examples/openclaw-lite.whip` | A composition of scheduled operations: a heartbeat, a `memory.query` recall before the planning turn, a file operation into a queue, a `memory.write` save, and a review by a person. The example imports the embedded `std.memory` package. It needs no lock. |
| [`autoresearch-lite.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/autoresearch-lite.whip) | `whip check examples/autoresearch-lite.whip` | A research loop with an objective: an experiment with a budget, typed ingestion of a metric, and a decision to keep or to stop. |
| [`gastown-lite.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/gastown-lite.whip) | `whip check examples/gastown-lite.whip` | Coordination of coding agents: a file operation into a queue, a lease on the workspace, work by an agent, a typed review, and a record in a ledger. |

## Runtime Operations

| Example | Check command | Why it exists |
| --- | --- | --- |
| [`revision-ticket-v1.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/revision-ticket-v1.whip) / [`revision-ticket-v2.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/revision-ticket-v2.whip) | `whip check examples/revision-ticket-v1.whip` / `whip check examples/revision-ticket-v2.whip` | A pair of source files for the `whip revise` command. The pair shows compatible changes to a workflow that runs now. |
| [`revision-parent-child.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/revision-parent-child.whip) | `whip check examples/revision-parent-child.whip --root ParentRevisionExample` | Invocation of a child workflow from a parent workflow, and an explicit map of the success payload and the failure payload. |
| [`revision-validation-approval.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/revision-validation-approval.whip) | `whip check examples/revision-validation-approval.whip --root RevisionValidation` | A revision proposal that is safe for an operator. The child workflow drafts a candidate. A person reviews the candidate. The activation stays external to the source. |
| [`revision-running-cancel.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/revision-running-cancel.whip) | `whip check examples/revision-running-cancel.whip` | The behavior of a revision when provider work is already in operation. |
| [`revision-repair-planner.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/revision-repair-planner.whip) | `whip check examples/revision-repair-planner.whip` | A repair proposal that an agent drafts. The proposal returns a dry-run command. The proposal does not activate itself. |

## Test Fixtures

These files stay in `examples/` because the runtime tests and the report tests
use them. These files are not part of the learning path:

| Fixture | Purpose |
| --- | --- |
| [`provider-language-e2e.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/provider-language-e2e.whip) | A fixture for the acceptance tests and the report tests. It covers routing across more than one provider, assertions with tags, and redaction of coerce evidence. |
| [`provider-language-e2e.accept.json`](https://github.com/jamesjscully/whipplescript/blob/main/examples/provider-language-e2e.accept.json) | The expectations for the `whip accept` command. A machine checks these expectations. |
| Package capability fixture | This fixture uses the lowering of `capability.call` with a package lock. It also uses the validation of the output at the boundary of the runtime. |
| [`queue-gated-smoke.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/queue-gated-smoke.whip) | A small smoke test for a queue dependency. To copy a pattern, use `queue-worker-with-review.whip` instead. |

## How to Run the Examples

```sh
whip check examples/triage-chain.whip

whip --store .whipplescript/examples.sqlite \
  run examples/triage-chain.whip \
  --provider fixture --until idle --json
```

These variations are useful:

```sh
# stream progress as NDJSON (openclaw-lite imports the embedded `std.memory` package — no lock needed)
whip --store .whipplescript/examples.sqlite \
  run examples/openclaw-lite.whip \
  --provider fixture --until idle --stream ndjson

# run an acceptance fixture end to end
whip --store .whipplescript/accept.sqlite --json \
  accept examples/provider-language-e2e.accept.json

# inspect the desugared rules for a then chain or pattern expansion
whip check examples/reusable-review-pattern.whip
```

## Reading Order

1. `minimal-noop.whip`
2. `triage-chain.whip`
3. `queue-worker-with-review.whip`
4. `incident-router.whip`
5. `scheduled-escalation.whip`
6. `openclaw-lite.whip`
7. `autoresearch-lite.whip` or `gastown-lite.whip`
