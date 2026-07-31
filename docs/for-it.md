# For IT and data owners

## Summary

Your staff want to use AI agents on company work. You agree with the goal. You
cannot approve it, because you have no way to limit what an agent does with
company data. A prompt is not a control.

WhippleScript makes the limit a property of the language. You declare your data
sources and their audiences one time, in a signed policy file. The compiler then
refuses to build any workflow that violates the policy. The refusal occurs
before the workflow runs, not during an incident.

Three properties follow:

- **The control is external to the workflow.** You write the policy. Your staff
  and their agents write the workflows. A workflow cannot widen its own
  authority.
- **The control is a compile error.** A denied workflow does not deploy. There
  is no run-time monitor to tune and no alert to triage.
- **The control produces a document.** The `whip check` command prints a
  guarantee report for each workflow. The report names each data source, each
  audience, and each approved crossing.

## Questionnaire

| Your question | The answer | The evidence |
| --- | --- | --- |
| Can an agent send confidential data to a party that must not see it? | No. The compiler denies a value to each audience outside its set of readers. | The `models/maude/infoflow-*.maude` suite and `models/lean/Whipple/ReaderSets.lean`. |
| Can content from an untrusted source, such as a public inbox, steer a privileged action? | No. The compiler denies untrusted data influence over a sink with more trust. The only crossing is an `endorsed` coercion that a person authorized. | `models/lean/Whipple/NMIF.lean`. |
| Can an attacker make the system release his own data? | No. The compiler denies data that an attacker controls the ability to steer its own release. | `models/lean/Whipple/NMIF.lean`. |
| If we remove a field, is the field truly gone? | Yes. A `redact … keep` statement physically removes the field at run time. | `models/lean/Whipple/Redaction.lean`. |
| Can a workflow read data above the clearance of the person who started it? | No. The compiler denies an agent each read above the clearance of its user. | The `models/maude/infoflow-*.maude` suite. |
| Can a workflow run forever? | The compiler does not prove general termination, and we do not claim that it does. It checks that each workflow has a path to its declared completion or failure, it rejects the known unbounded forms, and it requires a workflow that runs continuously by design to say so with an explicit `@service` tag. A long-running workflow is then a declaration that you can audit, not an accident. | The static liveness checks. Refer to [Guarantees](guarantees.md#termination). |
| Our staff want agents that start other agents. Can that recursion run away? | No. The invoke tree of the agent tools must be acyclic and locally convergent, so a turn never blocks for an unlimited time. Non-termination is a privilege of the root only. | `models/maude/subworkflow-convergence.maude`. |
| Can a workflow spend without a limit? | No. A campaign that reaches its spend cap parks with its state intact. You resume it later with a new allowance. A cap never silently truncates the work. | Refer to [Guarantees](guarantees.md#termination). |
| Does a retry do a paid action two times? | No. Each effect derives a stable idempotency key from its firing identity. A retry, a crash recovery, and a replay each deduplicate against that key. | `models/maude/effect-key.maude` and `models/maude/prefix-replay.maude`. |
| Can a workflow reach the shell, the file system, or the network? | Not by default. Each of the three is default-deny. An operator allow-list opens each one. The virtual shell has no reach to the operating system and no reach to the network. | `models/maude/script-hard-off.maude`. Refer to [Providers & packages](providers.md). |
| Can a workflow give itself more authority than we granted? | No. Authority enters explicitly and only becomes more narrow. Nothing becomes larger downstream. | `models/maude/workflow-authority-attenuation.maude` and `models/maude/turn-access-grant.maude`. |
| Can we audit what occurred? | Yes. The event log is append-only. Each event carries causation and correlation identifiers. The `whip trace --check` command replays a run against the conformance model. | `models/tla/ControlPlaneLifecycle.tla`. |
| Can we approve one exception? | Yes. A crossing is a `declassified` coercion or an `endorsed` coercion, under a grant, with a source mark. The guarantee report lists each one. | Refer to [Govern a workflow](tutorials/governance.md). |
| Where does the data stay? | In a store that you select. The store is a local SQLite file, or a Cloudflare Durable Object in your own account. | Refer to [Runtime & operations](runtime-operations.md). |
| Who can read the credentials? | Only the owner of the configuration file. A workflow refers to a credential by name. A workflow never contains a key. | Refer to [Providers & packages](providers.md). |

Each model in the evidence column is executable. The
`scripts/check-formal-models.sh` script runs all of them in CI. A guarantee on
this site is not prose.

## How to evaluate this

1. Read [Guarantees](guarantees.md). The page states each promise and names the
   model that carries it.
2. Do the governance tutorial. It takes approximately 20 minutes. You see the
   compiler reject an unsafe workflow, you correct the workflow, and you
   authorize one deliberate crossing. Refer to
   [Govern a workflow](tutorials/governance.md).
3. Write your policy file for one real data source. The
   [`examples/infoflow/`](https://github.com/GaugeWright/whipplescript/tree/main/examples/infoflow)
   directory has a policy for a CRM, a public inbox, and a reply channel.
4. Give your staff [GaugeDesk](https://gaugewright.com/gaugedesk/) with that
   policy applied. They install nothing.

## What is not ready

Use this section in your risk assessment.

- WhippleScript is pre-1.0. The syntax, the CLI flags, and the JSON field names
  can change between releases.
- Live delivery through Slack and email is not available. The messaging
  providers today are a local mailbox, a desktop notification, and standard I/O.
- The adapters for the Codex and Claude providers, and the direct calls to the
  OpenAI and Anthropic model APIs, need credentials and are gated. The default
  path is a deterministic fixture that needs no credentials.
- Network access is limited to an HTTP GET from an allow-list of hosts. The
  policy blocks each private address and each loopback address.
- The prebuilt release binaries are new. An install from source is the reliable
  alternative.

The full list is in [current state](current-state.md).

## Recommended first deployment

Select one workflow with a real approval gate and no external egress. Run it
against the fixture provider first, then against one real provider, with
supervision. Read the guarantee report before each promotion. Then add the
egress channel under a declared grant.
