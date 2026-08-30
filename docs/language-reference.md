# Language reference

This is the complete reference for `.whip` source. For a guided introduction,
start with the [tutorials](tutorials/index.md). For authoring guidance, refer to
the [manual](manual.md).

## Program structure

A program is a root file and its `include` closure. A file contains
declarations. The declarations are a maximum of one workflow header, or any
quantity of workflows in braces; classes; enums; agents; coerce functions;
tables; rules; assertions; patterns; events; coordination resources; harnesses;
and imports.

<!-- check: skip — sketch; the includes it names are not in the tree -->
```whip
include "shared/review.whip"
include "review.coerce"

use std.memory

workflow Example

input request WorkRequest
output result WorkResult
failure error WorkFailure

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule start
  when WorkRequest as request
  when worker is available
=> {
  tell worker as turn """markdown
  Do the work:
  {{ request.title }}
  """

  after turn succeeds as completed {
    complete result {
      id request.id
      summary completed.summary
    }
  }
}
```

A file with one workflow uses the header form above. When one file holds more
than one workflow, put each workflow in braces. Then select the root with the
`--root` flag:

```whip
workflow Parent {
  input task Task
  ...
}

workflow Child {
  output result ChildResult
  ...
}
```

The two forms support the full language. The support includes contracts and
terminal actions. A library workflow in the same bundle is available to the
`invoke` statement by its name. A workflow with the `@private` tag is the
exception. The system still validates a private workflow, and you can select a
private workflow with `--root`. But an adjacent workflow cannot invoke a
private workflow.

You can write the contracts as a compact signature on the workflow line. The
alternative is separate `input`, `output`, and `failure` lines:

<!-- check: skip — excerpt; `Ticket` is declared elsewhere on the page -->
```whip
workflow Triage(ticket: Ticket) -> Resolution ! TriageFailed
```

This line is exactly equivalent to these lines:

<!-- check: skip — excerpt; `Ticket` is declared elsewhere on the page -->
```whip
workflow Triage
  input ticket Ticket
  output result Resolution
  failure error TriageFailed
```

The compact form takes one or more inputs in the `name: Type` form. The form
takes an output type after `->`, which binds as `result`. The form takes an
optional failure type after `!`, which binds as `error`. The two forms are
legal. The `whip fmt` command changes the compact signature into the keyword
lines.

The contract of a terminal payload is a class or a scalar type. The scalar
types are `int`, `float`, `string`, and `bool`. Complete a class contract with a
block of fields. Complete a scalar contract with a value alone:

<!-- check: skip — excerpt; `Ticket` is declared elsewhere on the page -->
```whip
workflow Score(ticket: Ticket) -> float

rule score
  when Ticket as ticket
=> {
  complete result 0.9
}
```

Do not mix the shapes. A block against a scalar contract is a compile error. A
value alone against a class contract is also a compile error.

Each program must declare a minimum of one `workflow`. A file that declares
only shared types or patterns is a library. Use an `include` statement to bring
the library into a workflow. Do not compile the library alone. A compilation of
the library alone reports ``program declares no `workflow` ``.

The compilation validates **each** workflow in the bundle. The compilation does
not validate only the workflow that you select with `--root`. Thus one pass
finds an error in each workflow.

The scope is lexical. A top-level declaration is external to each
`workflow { ... }` block. Thus the full bundle shares a top-level declaration.
A declaration in a workflow block is private to that workflow. A reference to a
private name of a different workflow is an error. To share the declaration,
move the declaration to the top level.

For a workflow declaration, the `@private` tag is a membrane for invocation.
The tag is not lexical scope. The tag hides the workflow from an `invoke`
statement in an adjacent workflow. The tag keeps root selection available for
an internal run.

## Lexical Structure

WhippleScript is line-oriented. WhippleScript is not sensitive to indentation.
A newline separates a declaration, a clause, and a statement in a block. Braces
group a body. Whitespace separates tokens and has no other meaning.

An identifier starts with a letter or with `_`. An identifier continues with
letters, digits, `_`, or `.`. The `.` character is legal where a dotted name of
an event or a fact is applicable. By convention, the name of a type and the
name of a declaration are `UpperCamelCase`. By convention, a binding, an agent,
a queue, a resource, and a field are `lower_snake_case`.

A line comment starts with `#` or with `//` outside a string. A line comment
continues to the end of the line. In the body of a rule, a comment must occupy
its own line. A comment after a statement is legal only at the top level. The
two markers operate. A `#` character in a prompt with triple quotation marks is
content and not a comment. A string literal uses double quotation marks. A
prompt with more than one line uses triple quotation marks. You can annotate
the opening marks with a content type:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
"""markdown
Prompt body
"""
```

The annotation is metadata. The annotation does not validate the body of the
prompt. Put the body of the prompt on the line after the opening marks. Put the
binding of an effect on the line of the effect, before the opening marks:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
tell worker as turn """markdown
Do the work.
"""
```

A reserved word cannot be the name of an `as` binding. The rejected set has the
words for operations and control. The set includes `record`, `done`, `tell`,
`coerce`, `decide`, `exec`, `call`, `invoke`, `signal`, `source`, `emit`,
`complete`, `fail`, `after`, `case`, `when`, `on`, `timer`, `cancel`,
`acquire`, `release`, `append`, and `consume`.

## Syntax Shape

The reference grammar below is deliberately compact. The remainder of this page
gives a concrete example of each construct.

```text
program       ::= include* use* item*
item          ::= workflow | contract | harness | agent | class | enum | event
                | table | tracker | lease | ledger | counter | coerce | rule
                | pattern | apply | action | assert
workflow      ::= tag* "workflow" Ident block?   # header form if block omitted
contract      ::= ("input" | "output" | "failure") Ident Type
class         ::= "class" TypeName "{" field* "}"
enum          ::= "enum" TypeName "{" variant* "}"
event         ::= "event" dotted_name "{" field* "}"
agent         ::= "agent" Ident ("using" Ident)? "{" agent_field* "}"
harness       ::= "harness" Ident ":" Ident
table         ::= "table" Ident "as" TypeName "[" row* "]"
tracker       ::= "tracker" Ident "{" "provider" Ident "}"
lease         ::= "lease" Ident "{" "shared"? "key" TypeName "slots" int "ttl" duration "}"
ledger        ::= "ledger" Ident "{" "shared"? "entry" TypeName "partition" "by" Ident "retain" duration "}"
counter       ::= "counter" Ident "{" "shared"? "key" TypeName "cap" int "reset" period ("timezone" string)? "}"
coerce        ::= "coerce" Ident "(" params? ")" "->" Type (block | string)
rule          ::= "rule" Ident when* "=>" block
pattern       ::= "pattern" Ident ("<" TypeName ("," TypeName)* ">")? block
apply         ::= "apply" Ident type_args? "as" Ident block
action        ::= "action" Ident "(" params? ")" block
assert        ::= "assert" expr
when          ::= "when" readiness
block         ::= "{" statement* "}"
```

The parser is deliberately strict about a source form that is similar to valid
WhippleScript but that would lower ambiguously. For example, the parser rejects
a block of Gherkin `Given`, `When`, or `Then` free text. The parser gives a
specific diagnostic. The parser does not treat the block as a comment or as an
unknown declaration.

## Declarations

### `workflow`

The workflow is the boundary of the runtime. A start operation on a workflow
makes a durable instance. The instance has its own event log, facts, effects,
runs, and lifecycle state.

A contract declares the data that an instance accepts and the data that an
instance supplies:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
input phase PhaseReviewRequest
output result PhaseReviewResult
failure error ReviewPhaseFailure
```

Sometimes no other part of the program uses the payload class of a contract. In
that condition, the contract can declare the class in position. The forms are
`output result { message string }` and `failure error { reason string }`. This
form synthesizes a hygienic anonymous class. The names are `output.result` and
`failure.error`. A user class cannot collide with such a dotted name.

The binding name keys the input payload. For `input phase PhaseReviewRequest`,
start the workflow with `--input '{"phase": {"id": "phase-1", ...}}'`. The
runtime then seeds a `PhaseReviewRequest` fact. The `complete` statement and the
`fail` statement below are the only methods that a rule uses to supply the
declared outputs. A cancel operation is an action of an operator. A cancel
operation has no syntax in the source.

The `@private` tag on a workflow prevents an invocation from an adjacent
workflow:

<!-- check: skip — excerpt; `AuditRequest` is declared elsewhere on the page -->
```whip
@private
workflow InternalAuditHarness {
  input request AuditRequest
  output result AuditReport
}
```

A private workflow is still a valid root for an internal run. A public wrapper
must expose its own workflow contract or a shared pattern body. A public
wrapper must not invoke the private workflow as an adjacent workflow.

### `class` and `enum`

These are the typed shapes for a fact and for a payload:

<!-- check: fragment -->
```whip
enum ReviewStatus {
  Accept
  Revise
  Blocked
}

class WorkReview {
  status ReviewStatus
  reason string
  confidence float
}
```

The type of a field is in the subset that a coercion can use. The types are the
scalars (`string`, `int`, `float`, `bool`), an array (`string[]`), a class, an
enum, an optional, a string literal, a literal union
(`status "open" | "done"`), and an agent domain
(`AgentRef<codex | claude>`). A field with a literal type is the idiomatic
method to model a small state machine. A `when` clause binds a field to one
value of such a union; see [Conditional fields](#conditional-fields).

### `agent`

An agent is a target that an agent turn can address:

<!-- check: fragment -->
```whip
agent reviewer {
  profile "repo-reader"
  capacity 1
}

agent coder delegated to claude {
  profile "repo-writer"
  capacity 2
  capabilities ["agent.tell"]
  settings project
}
```

Each field of an agent is optional. A bare `agent name` declaration with no
block is complete. The `capacity` value defaults to `1`. The `profile` value
defaults to `no-repo`, which is the builtin profile with the least authority.
Thus an absent field can never grant more than a declared field. A plain
declaration is **managed** by default. In this condition, the harness of
WhippleScript runs the turn and assembles the context of the turn.

An `agent name delegated to <provider>` declaration names an external runtime.
The runtimes are `codex`, `claude`, `native-fixture`, and `command`. Such a
runtime assembles its own context (DR-0034). The legacy `provider <kind>` field
and the `using <harness>` binding stay supported. These forms classify onto the
same managed and delegated axis.

The `profile` field is necessary. The field names the profile for the
authority. The `capacity` field limits the concurrent turns and supports the
`is available` readiness pattern. The `capabilities` field limits the
operations that you can ask the agent to do. The `skills` field attaches
bundles of context to the turns of the agent.

The `requires [<feature.class>, …]` field declares portable requirements for
features from the taxonomy in DR-0015. An example is `requires [turn.cancel]`.
A class outside the taxonomy is a compile error. At check time, the checker
validates each required class against the published report of features of the
selected provider. If the report cannot state truthfully that the provider
supports the class as `native` or `emulated`, the check fails. Refer to
`spec/std-agent.md`.

The `settings` field applies to a delegated harness (DR-0034). The field
selects the sources of ambient configuration that the delegate can read when it
assembles its context. The values are `project`, `user`, and `none`. If you do
not set the field, the provider uses its own default. Ambient configuration
steers the behavior only. The envelope of the profile and the capabilities is
the only grant of authority. Thus a delegate that reads its own project
configuration can never get a tool that the program did not authorize.

The controls for the context divide by the class of the harness. The
`compaction` control applies only to a managed harness, because a delegated
harness compacts its own context. The `settings` control applies only to a
delegated harness, because WhippleScript already assembles the context of a
managed agent. A declaration of either control on the incorrect class is a
compile error. Such a declaration is never a silent no-operation.

### `table`

A table holds static seed rows. The rows are typed against a class. The runtime
records the rows when the instance starts:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
table language_tasks as LanguageTask [
  {
    provider codex
    language "French"
    status "queued"
  }
  {
    provider claude
    language "Hindi"
    status "queued"
  }
]
```

Use a table for deterministic source data. Each item that depends on the output
of a provider, on the wall clock, or on an external system belongs in an effect
and in a recorded fact. A fact that a table seeds reports
`provenance_class: "table"`. Such a fact carries the source spans of its row in
the JSON output.

### `coerce`

A coercion is a typed model decision that a coercion backend supports. A call
to a coercion in a rule makes a durable `schema.coerce` effect:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
coerce assessIncident(title string, impact string, mitigation string) -> IncidentAssessment {
  prompt """markdown
  Assess the incident response.

  Incident: {{ title }}
  Impact: {{ impact }}
  Proposed mitigation: {{ mitigation }}

  {{ ctx.output_format }}
  """
}
```

A `coerce` statement is an effect. A `coerce` statement is not a call to a
function. The typed output is available only in an `after ... succeeds` branch.

A coercion with a prompt only can omit the block and the keyword. The string
after the return type is then the prompt:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
coerce assessIncident(title string) -> IncidentAssessment """markdown
Assess the incident: {{ title }}

{{ ctx.output_format }}
"""
```

The body of the block form is a validated list of clauses. The body is not free
text. The clauses are `prompt` and `provider <name>`. A `prompt` clause has one
line or more than one line, and it takes an optional annotation for the content
type. A `provider <name>` clause overrides the provider for this effect. This
clause is the highest level of the selection of a provider for a coercion. Each
other clause is a check error with the message `unknown coerce field`. Thus a
spelling error such as `promt` cannot silently make a coercion with no prompt.

For a decision that occurs one time and that does not need a named
declaration, use the inline `decide` form in the body of a rule. Refer to
[Inline `decide`](#inline-decide). For free-text model output with no schema,
use the [`prompt` effect](#the-prompt-effect).

### `pattern` and `apply`

These constructs give reuse at compile time. The `apply` statement expands a
pattern into usual declarations before the type check:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
pattern AgentReview<Input, Output> {
  input Input as item

  rule dispatch
    when Input as item
    when reviewer is available
  => {
    tell reviewer as turn "Review {{ item.title }}."

    after turn succeeds as reviewed {
      done item -> record Output {
        turn reviewed
        status "reviewed"
      }
    }
  }
}

apply AgentReview<PhaseReviewRequest, PhaseReviewResult> as ReviewPlanPhase {
  reviewer codex
}
```

A pattern has no identity at run time. When the work that you reuse needs its
own lifecycle, use a `workflow` declaration and an `invoke` statement.

### `action`

An action gives reuse at compile time for a *chain of effects in the body of a
rule*. The `pattern` construct and the `apply` construct abstract a full
declaration. An `action` construct abstracts a chain of statements. The
compiler inlines the action at each call site and expands the action fully into
the durable graph:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
action review_change(who AgentRef<reviewer>, item ChangeRequest) {
  tell who as turn """markdown
  Review {{ item.title }}.
  """

  after turn succeeds as reviewed {
    done item -> record ReviewedChange {
      id item.id
      summary reviewed.summary
      status "reviewed"
    }
  }
}

rule review
  when ChangeRequest as item
  when reviewer is available
=> {
  review_change(reviewer, item)
}
```

These are the semantics:

- **The expansion is inline and hygienic.** The compiler replaces the call with
  the body of the action. The compiler substitutes each argument for its
  parameter. The compiler makes the internal bindings of the action unique for
  each call site. The internal bindings above are `turn` and `reviewed`. Thus
  two calls in one rule body never collide. The compiled rule shows the
  expanded chain. There is no call, no frame, and no recursion at run time.
- **A call has no result (v0).** A call is an independent statement. You cannot
  bind a call with `as`.
- **The shape of the chain (v0).** The body of an action can contain effect
  statements, `after` blocks, `record` statements, and `done` statements. In
  v0, the body cannot contain `complete`, `fail`, `case`, or `branch`. The body
  also cannot contain a nested call to an action. Keep the terminal logic and
  the branch logic in the rule that makes the call.

An action has no identity at run time. This is the same behavior as a pattern.
An action is reuse and not a subroutine.

### `redact`

The `redact` statement projects a binding with a record type onto a subset of
its fields. The statement makes a new binding. The new binding carries **only**
the fields that you keep:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
rule triage
  when Customer as c
=> {
  redact c keep [id, status] as safe

  complete result {
    who   safe.id
    state safe.status
  }
}
```

The `redact <source> keep [<field>, …] as <out>` statement is a synchronous and
pure restructure operation. The statement is not an effect.

The statement composes with a crossing that has a mark. A redaction of the
output of a `declassified` coercion or an `endorsed` coercion stays the carrier
of the crossing. A projection can only make the release more narrow. The fields
that you keep still obey their schema labels for each field.

The `redact` statement is the explicit crossing for information flow. At this
crossing, the analysis at the level of the rule becomes more precise. The
projection is the deliberate point where the program makes a record more narrow
before the record flows onward. An audit can find the projection. The
projection is a focused complement to the audited `declassify` hatch. The
README in `examples/infoflow` gives that hatch.

These are the semantics:

- **The type holds only the fields that you keep.** The `out` binding has a
  synthesized type. The type holds only the fields that you keep. Thus
  `safe.id` resolves. Access to a field that you dropped, such as `safe.ssn`,
  is a compile error. The schema of the source must be known. Each field that
  you keep must exist on that schema.
- **The runtime does the projection.** At run time, the runtime physically
  removes the fields that you dropped from the value that binds to `out`. Thus
  those fields can never leave through a sink. This behavior is the runtime
  support for the static removal. The proof is in
  `models/lean/Whipple/Redaction.lean`. The proof shows that the dropped fields
  do not interfere.
- **The projection refines the information flow.** Under a governance envelope,
  the checker adds a check to a fully redacted egress. Such an egress is a
  `complete result` statement, a `record <Schema>` statement, or a
  `send via <channel>` statement that references only redacted projections. The
  checker checks the egress against the join of the labels of the fields that
  you keep. The envelope keys these resources as `<Schema>.<field>`. If you keep
  a field that the sink cannot read, the checker flags the field and gives its
  name. This check is **additive**. The check does *not* exempt the egress from
  the usual read-to-sink checks of the rule. Specifically, a release of data
  that comes from a confidential **read of a resource** at a lower label is a
  declassification. Such a release still needs a `grant declassify` clause. The
  removal of a field makes the *schema* label of the field more narrow. The
  removal does not change the provenance of a confidential source. The
  projection makes only the confidentiality more narrow. The projection does
  not change the check on integrity.
- **The kinds of source.** The source can be a matched class from a
  `when Class as c` clause. The source can be the result of a `coerce`, a
  `decide`, or an `exec` statement. The source can also be the alias of an
  `after … succeeds as <alias>` branch. This is the read and then redact flow.
  A redaction can chain. The output of a redaction can be the source of a later
  redaction.
- **Projection with a bounded type, with no explicit `redact` statement.** A
  pure `from` projection is a `record <T> from <src> { f1  f2 }` statement or a
  `complete <result> from <src> { f1  f2 }` statement where each field is a
  copy in short form. The system governs such a projection automatically as a
  redaction that keeps `[f1, f2]`. The checker checks the egress against the
  labels of those fields. Thus a projection of public fields only is correct,
  and a projection that includes a confidential field is flagged with the name
  of the field. The target type is the explicit limit, and you can review the
  limit. The labels come from the source. A payload that mixes explicit value
  expressions is not a pure projection and stays conservative. This check is
  additive, as the check of an explicit `redact` statement is. The check does
  not exempt the egress from the read-to-sink checks of the rule.

### `include` and `use`

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
include "schemas/common.whip"   // contributes declarations to the bundle
include "review.coerce"           // makes coerce classes/functions available to coerce
use std.memory                  // imports a package/library by name
```

A package registers libraries, capabilities, providers, schemas, and optional
skills. An explicit `call` effect invokes the capabilities of a package. A
locked package can also authorize a form with limits that the library owns.
Memory `recall` is such a form. Such a form still lowers to a usual core
effect.

**When a `use` statement is necessary (the division of authority).** A
`use std.<pkg>` line always carries meaning. The line means that this program
selects an authority. The line is never decoration:

- **Ambient packages need no import line.** These packages are `std.agent`,
  `std.coercion`, `std.coord`, `std.tracker`, `std.time`, `std.workflow`, and
  `std.memory`. A declaration of their constructs registers the package
  automatically. The constructs are an `agent`, a `coerce`, a `lease`, a
  `tracker`, a clock `source`, and a `memory pool`.
- **Explicit packages need an import, and the checker applies the rule.** The
  `std.script` package supports `exec`. The `std.files` package supports a
  `file store` and the file effects. The `std.messaging` package supports a
  `channel` and the `send` statement. The `std.ingress` package supports a
  `signal` declaration and a `source` declaration that is not a clock. Use of
  one of these packages with no import is a check error. The codes are
  `security.package_import_required` and `security.script_disabled`.

### Tags and descriptions

These are metadata in the source. They apply to a workflow, a table, a rule,
and an assertion:

<!-- check: skip — excerpt; declarations only, no rule reaches a terminal -->
```whip
@private
@acceptance
description "Internal provider x language acceptance workflow"
workflow InternalProviderLanguageE2E
```

The compiled IR keeps the two items for the reports. The
`whip run --include-tag` flag and the `--exclude-tag` flag select the
assertions that the command evaluates. The `@service` tag, the `@bounded` tag,
and the `@external` tag have a static meaning for the
[liveness checks](#liveness-checks). The `@private` tag on a workflow has a
semantic meaning and prevents an `invoke` statement from an adjacent workflow. Each other tag does not change the
readiness, the routing, the effects, or the behavior at run time.

### Signals and sources

A `signal` declaration declares a typed external signal and its payload schema.
A `source` block declares the method that admits a signal as a durable fact. A
rule reacts to the admitted signal. A source never fires a rule directly.

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
signal triage.tick {
  scheduled_at time
  observed_at time
  occurrence_id string
  missed_count int
}

source clock as daily_triage {
  every weekday at 09:00          // recurrence: `at <hh:mm>`, `every <dur>`,
  timezone "America/New_York"     //   or `every <day|weekday|monday…> at <hh:mm>`
  missed coalesce                 // `skip` | `coalesce` | `catch_up limit <N>`

  observe as tick                 // binds the provider observation
  emit triage.tick {              // maps the observation into the declared signal
    scheduled_at tick.scheduled_at
    observed_at tick.observed_at
    occurrence_id tick.occurrence_id
    missed_count tick.missed_count
  }
}
```

A `source clock as <name>` declaration is the `clock_source` construct. The
[`std.time`](providers.md) package supplies this construct. A generic
`source <provider> as <name> { observe; emit }` declaration is the
`signal_source` construct. The two constructs belong to the
`source_declaration` family. The two constructs lower to a template for
admission. The `emit <event> { ... }` clause is the `event.emit` kind of
effect. This effect admits a durable signal.

The `emit <event> from <observe-binding>` clause copies the fields of the
observation that have the same names. The declared fields of the signal limit
the copy. This is the `record … from` projection. An optional `{ … }` block
overrides an individual field. An admission makes a fact and never fires a
rule.

These are the static checks. A recurrent clock source must declare a `missed`
policy. There is no silent default. A calendar schedule must declare a
`timezone` value. If you omit the value, the result is a check error.

The runtime admits each occurrence of a clock a maximum of one time. The
scheduled instant is the key. Thus a replay and a recovery never admit an
occurrence two times. Refer to the `admission-and-idempotency` spec and the
`std-time` spec.

At run time, the worker fires the three forms of recurrence. The forms are
`every <duration>` for an interval, `every <day|weekday|monday…> at <hh:mm>`
for a calendar, and `at <hh:mm>` for one occurrence. The worker resolves a
calendar time and an `at` time in the declared timezone. The worker obeys the
transitions of daylight saving time. A `09:00` local schedule moves its UTC
instant across the boundary of daylight saving time. The worker skips a local
time that does not exist in the spring transition.

Two more built-in providers of a source are available with `clock`: the `file`
provider and the `http` provider. Each provider admits one durable signal fact
for each unit of input. A `file` source admits one signal for each line that is
not empty. An `http` source admits one signal for each element of a JSON array
that it fetched. The two providers share the at-most-once admission of a clock
source, and the admission is safe for a replay. The index of the input is the
key. Thus a second read of a file that becomes larger admits only the new
entries. The same applies to a second poll of a feed that permits append only.

A `file` source reads a local path. Its record of the observation binds
`{ line, line_index, path }`:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
source file as feed {
  path "./inbox.txt"
  observe as obs
  emit ingress.fed {
    text obs.line
    index obs.line_index
  }
}
```

A `file` source can declare `watch "<glob>"` instead. Declare exactly one of
`path` and `watch`. The occurrence mode admits one signal for each new
occurrence of a matched file. The key is the path and the hash of the content.
Thus a new file admits one signal, a file with no change never admits again,
and a change to the content admits again. The record of the observation binds
`{ path, content_hash, watch }`. The *read* of the content stays with the
effects of `std.files`. The v1 glob is a literal directory and one file name
with a `*` wildcard. The v1 glob has no `**` wildcard.

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
source file as drops {
  watch "./drops/*.json"
  observe as obs
  emit drop.arrived {
    path obs.path
    digest obs.content_hash
  }
}
```

An `http` source does a GET operation on a URL that returns a JSON array. Its
record of the observation binds `{ item, item_index, url }`. The `item` value
is the JSON element as a string again:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
source http as feed {
  url "https://example.com/feed.json"
  observe as obs
  emit ingress.ingested {
    text obs.item
  }
}
```

A `file` source in line mode and an `http` source accept an optional
`dedup <observe>.<field>` clause. The clause names the field of the observation
that carries the delivery identity of the provider. The admission key then
comes from that field and not from the positional ordinal. Thus a feed with a
new sequence or with an insertion at the head still admits each delivery
exactly one time. For example, `dedup obs.item` removes duplicates from an
`http` feed by the content of the element. The named field must exist on the
record of the observation of the provider. The `whip check` command rejects an
unknown field. A `watch` source already uses the content as the key and takes
no `dedup` clause.

An `http` fetch uses the GET method only. Such a fetch passes through a policy
for SSRF and egress. The policy accepts only an `http` URL or an `https` URL.
The policy always blocks a private address and a loopback address. When you set
the `WHIPPLESCRIPT_HTTP_SOURCE_ALLOW` variable, the destination host must match
an entry in the variable. The entries have a comma between them, and an entry
can use a `*.` wildcard. When you do not set the variable, each public host is
permitted. The `WHIPPLESCRIPT_HTTP_SOURCE_ALLOW_PRIVATE` variable permits a
private host or a loopback host again, for a local test. A URL with no scheme,
or a URL that is not http or https, is a rejection at the time of the
`whip check` command. A web *search* is a design that is deferred. A web search
is not yet available. Refer to `ingress-file-source.whip` and
`ingress-http-source.whip` in the examples for complete workflows.

## Rules

A rule waits for facts and events. A rule can filter the facts and the events
with a guard. A rule then commits a rewrite atomically. Each fact, each effect,
each dependency, and each terminal action of the selected rule persists, or
none of them persists.

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
rule resolve_incident
  when IncidentTicket as ticket where ticket.status == "open"
  when responder is available
=> {
  tell responder as turn """markdown
  Investigate this incident and propose a mitigation plan.

  {{ ticket.title }}
  Impact: {{ ticket.impact }}
  """

  after turn succeeds as completed {
    coerce assessIncident(ticket.title, ticket.impact, completed.summary) as assessment
  }

  after assessment succeeds as checked {
    done ticket -> record IncidentResolution from ticket {
      mitigation completed.summary
      risk checked.risk
      status "resolved"
    }
  }
}
```

You can also group more than one `when` line in a block. The two forms are
equivalent:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
rule start
  when {
    WorkRequest as request
    worker is available
  }
=> { ... }
```

### Readiness patterns

| Pattern | Matches |
| --- | --- |
| `when started` | The initial `external.started` event. Use this pattern for a seed rule. |
| `when <agent> is available` | Free capacity on the agent. |
| `when Class as x [where ...]` | A fact of `Class` that no rule consumed. |
| `when <agent> completed turn ... [as x]` | An `agent.turn.completed` fact. A declared agent name matches only the turns of that agent. The generic word `worker` matches each agent. |
| `when <tracker> has ready issue as x` | An issue in a [tracker](#trackers) that a rule can claim. |
| `when fact <dotted.name> as x [where ...]` | The general form. It matches each derived fact with a name that matches the dotted path. |

Each specialized pattern above is sugar for the `when fact` form. The
`when reviewer completed turn as x` clause matches `agent.turn.completed`. The
`when backlog has ready issue as x` clause matches a readiness fact of a
tracker. Use the general `when fact <dotted.name>` form when the event that you
need has no dedicated phrase. An example is
`when fact agent.turn.completed as turn`.

A review by a person uses a [tracker](#trackers). File an issue with a
`file issue into <queue>` statement. A person then works the issue with the
`whip issue` command. A rule then reacts to the finish operation on the issue.
The rule can use a `when <queue> has ready issue as x` clause or can match the
finish operation. There is no construct that asks a person a question in the
program. There is also no suspend operation. An agent turn only completes,
fails, times out, or gets a cancel operation. A decision of a person enters as
a usual durable input. Such an input is a finish operation on a tracker or a
message on a channel.

### Guards and expressions

A `where <expr>` clause is a pure, deterministic filter on the matched facts
and on literal values. These are the supported forms:

```text
field access                    task.review.status
arithmetic                      +  -  *  /
comparison                      ==  !=  <  <=  >  >=
boolean                         and  or  not      (&&, ||, ! accepted)
membership                      x in [...]        x not in [...]
presence                        exists x          empty(x)
finite queries                  count(Class where ...)   exists(Class where ...)   empty(Class where ...)
literals                        strings, numbers, booleans, null, arrays, objects
indexing                        task.metadata["phase"]
enum / finite-domain values     Accept, codex
```

The `empty(...)` function is a structural test for emptiness. The function
operates on an array, a map, a string, a query on facts or effects, and a null
value. For an optional value, the function is true when the value is absent or
null. If the value is present, the function tests the inner value. Thus
`empty(job.note)` operates for `note string?`. The function rejects an optional
scalar such as `int?`. For an optional scalar, use `exists x` or `x == null`.

The precedence of an expression goes from the highest to the lowest:

| Level | Operators/forms | Notes |
| --- | --- | --- |
| 1 | field access, indexing, a call to a function or a query | `task.owner.name`, `metadata["phase"]`, `count(Task where ...)` |
| 2 | unary presence and boolean | `not x`, `!x`, `exists x`, `empty(x)` |
| 3 | multiplication and division | `*`, `/` |
| 4 | addition and subtraction | `+`, `-` |
| 5 | comparison and membership | `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `not in`. This is one flat level and is left-associative. |
| 6 | conjunction | `and`, `&&` |
| 7 | disjunction | `or`, `||` |

The `and` operator and the `or` operator evaluate from the left to the right
and stop when the answer is known. The compiler checks the types of a
comparison. A number compares with a number. A string compares with a string. A
boolean compares with a boolean. A finite domain compares with its own domain.
A duration compares with a duration. A time compares with a time. In a guard,
there is no implicit conversion from a string to a number, from a string to a
boolean, or from an enum to a string. If a guard cannot evaluate to a boolean,
the rule does not commit. The report of the checker or of the runtime then
points at the expression.

In new code, use the word operators:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
when Job as job where job.status == "pending" and job.attempts < 3
```

A guard never does I/O. A guard makes no query to a provider, no call to a
coercion, no read of a file, no read of a clock, and no call for a random
value. A decision that needs the judgment of a model or external data becomes
an effect. A later rule then branches on the completion of the effect.

### Rule body operations

| Operation | Meaning |
| --- | --- |
| `record Class { ... }` | Makes a typed fact. |
| `record Class from binding { ... }` | Makes a fact. The statement copies the fields of a binding and overrides the fields in the list. |
| `done binding` | Consumes a matched fact. |
| `done binding -> record ...` | Consumes a fact and replaces the fact in one atomic commit. |
| `tell agent [requires [...]] [as x] [timeout <dur>] [with access to <resource> { ... }] "..."` | Puts an `agent.tell` effect in the queue. Refer to [turn-access grants](#turn-access-grants). |
| `coerce fn(...) as x` | Puts a typed `schema.coerce` effect in the queue. |
| `decide "..." -> { ... } as x` | Puts an inline typed model decision in the queue. Refer to [Inline `decide`](#inline-decide). |
| `prompt "..." [using <provider>] as x` | Puts a free-text call to a model in the queue. The effect is a `schema.coerce` effect with a plain string as its result. Refer to [The `prompt` effect](#the-prompt-effect). |
| `file issue into <tracker> { ... }` | Files a new issue into a [tracker](#trackers). |
| `claim <issue> [as x]` | Claims an issue in a tracker. An issue that a different rule already claimed is a failure that you can branch on. |
| `release <issue>` | Returns a claimed issue to the tracker. |
| `finish <issue> [{ summary ... }] [as x]` | Marks an issue in a tracker as complete. |
| `timer <dur> as x` | Makes a [timer effect](#time-and-deadlines) that fires when the duration is due. |
| `timer until <time> as x` | Makes an absolute [timer effect](#time-and-deadlines) that fires at a typed instant or after a typed instant. |
| `cancel <binding>` | Cancels an effect that is pending or in operation. An earlier statement must bind the effect. |
| `exec "<command>" as x` | Puts a command effect with a dev-profile gate in the queue. Refer to [`exec`](#exec). |
| `exec <capability> with <record> -> Type as x` | Puts a hosted script capability effect in the queue. The stdin data and the stdout data are typed. |
| `call package.capability ... [as x]` | Puts a package capability effect in the queue. |
| `recall from <pool> for <query> as x` | The memory form that a package owns. This form needs a lock that authorizes the lowering to the memory recall capability. |
| `emit signal <name> to <instance> { ... } as x` | Puts a typed injection of a signal to a different instance in the queue. |
| `acquire <lease> for <key> as x` | Acquires a lease with the scope of the workspace. Branch on `held` or on `contended`. |
| `release <lease-binding>` | Releases a lease that an earlier statement in the progression of the rule acquired. |
| `renew <lease-binding> [until <dur>] as x` | Sends a heartbeat for a held lease and extends its TTL. Branch on the outcome of the renewal. |
| `append Type { ... } to <ledger> as x` | Appends a typed entry to a ledger with partitions. |
| `consume <counter> for <key> amount <expr> as x` | Consumes from a counter with a limit. Branch on `ok` or on `over`. |
| `invoke Workflow { ... } [with access to <resource> { ... } \| with access to { <resource> { ... } ... }] as x` | Starts a durable child workflow. The optional clause makes the start authority of the child more narrow. |
| `after x succeeds as y { ... }` | Runs when the effect `x` completes with success. |
| `after x fails as y { ... }` | Runs when the effect `x` fails. The binding `y` holds the failure base. The next section gives the base. |
| `after x completes { ... }` | Runs on each terminal status of `x`. |
| `emit milestone "<name>" of <Class> { ... }` | Projects a named durable milestone during the run, for a parent that observes the child (Family C). |
| `after p reaches "<name>" as m { ... }` | Runs when the invoked child `p` projects the milestone `<name>`. The binding `m` holds the payload of the milestone. |
| `case value { Pattern => { ... } }` | Branches on a value from a finite domain or on a value from a union. |
| `complete output { ... }` | Supplies the declared output of the workflow. The instance completes. |
| `fail failure { ... }` | Supplies the declared failure payload. The instance fails. |

The bare `emit <name>` action is no longer in the language. The `emit` keyword
must have `signal` or `milestone` after it. The `emit signal` statement injects
a directed event into a peer instance. The `emit milestone` statement projects
a milestone of a child. The next sections give the two statements. In each
other condition, a workflow appends a durable event through a usual effect and
through the facts that the completion of the effect derives.

The name of a binding that you introduce with `as` must not shadow an operation
keyword. The parser rejects `done`, `record`, `tell`, `complete`, `fail`, and
the other keywords as the name of a binding.

### Typed effect failures (`after x fails as f`)

When you bind a failure with `after x fails as f`, the binding `f` carries a
uniform **failure base**. The base has the same shape for each kind of effect:

| Field | Meaning |
|---|---|
| `f.reason` | The text of the failure for a person. |
| `f.summary` | A short summary. Frequently the summary is the same as the reason. |
| `f.effect_id` / `f.run_id` | The identifiers that find the run of the failed effect. |
| `f.kind` | The kind of the effect that failed, such as `"exec"`, `"schema.coerce"`, or `"workflow.invoke"`. |

The binding also carries **extras for each kind**. The compiler narrows the
extras statically by the kind of the effect of the binding. The kind of the
failed effect is always known at the site of the read. Thus there is no
dispatch at run time:

| Effect kind | Extra fields |
|---|---|
| `exec` | `f.exit_code` (int) — the exit status of the command. This field is absent when the system could not start the process. |
| `schema.coerce` | `f.error_class` (string: `provider_error` \| `invalid_output` \| `network`), and `f.http_status` (optional int, present on an HTTP error from a provider). |
| `agent.tell` | `f.error_class` (string) — the coarse kind of the failure of the provider. |
| `workflow.invoke` | The typed failure fields of the child, when the child declares one shared failure contract class. The binding `f` then has the type of that class, and the runtime merges the payload of the child under the base. |

A read of a field outside the schema of the kind of the binding is a check
error. A coerce binding cannot read `exit_code`. The language deliberately does
not make raw detail available. Such detail is `stderr` and the body of an error
from a provider. The set of fields of each variant is a decision about
redaction. A timeout gives no extra field. Its predicate `times out` is the
discriminator. The design is DR-0032. The failure of an effect is the
`EffectError` discriminated family. The family is a committed base and extras
for each kind behind a static narrowing. The extras came from the P3 phase of
the language-refinement campaign.

### Unhandled-failure auto-fail (rule-level net)

An effect can get to a terminal `failed` status or a terminal `timed_out`
status with **no `after` block that observes** its binding. Such a block is a
`fails` block, a `times out` block, or a `completes` block in the body of the
rule. In this condition, the effect can never advance its rule again. The
kernel does not leave the instance in the `running` state and idle for an
unlimited time. The kernel **fails the instance automatically**. The status is
`failed`. The generic reason is `unhandled failure of <binding> in rule <name>`.
There is no typed `failure` payload. These are the deliberate limits:

- **The `cancelled` status is an exception.** A rule cancels an effect
  deliberately, as in the watchdog pattern. A cancellation is never an outcome
  with no handler.
- **An `@service` workflow never fails automatically.** The runtime records
  each failure with no handler one time as a durable diagnostic. Use the
  `whip diagnostics` command. The code is `workflow.unhandled_failure`. The
  service continues to run.
- The net fires on the *terminal* failure. An effect that retries and later
  succeeds never triggers the net.

The `whip check` command shows the gap before the run. An effect that only a
`succeeds` block handles gets a prominent warning that the instance will fail
automatically. Handle the `fails` predicate, or observe the `completes`
predicate, at each position where a typed failure or a recovery is important.

### Child-milestone lifecycle (`emit milestone` / `after ... reaches`)

A child workflow can project named durable **milestones**. A parent that
invoked the child observes a milestone during the run of the child. This
mechanism generalizes the family of terminal outcomes (`succeeds`, `fails`, and
`completes`) into a lifecycle family. The family covers the states that the
child declares explicitly:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
// in the child workflow
class Progress { detail string }

rule do_work when Task as task => {
  emit milestone "work_started" of Progress { detail task.title }
  tell worker as turn """..."""
  after turn succeeds { complete result { ... } }
}

// in the parent workflow
rule orchestrate when Task as task => {
  invoke Child { task { title task.title } } as child

  after child reaches "work_started" as m {   // m : Progress
    record ParentProgress { note m.detail }
  }
  after child succeeds as r { complete result { ... } }
}
```

These are the rules:

- The emit operation declares a milestone. The
  `emit milestone "<name>" of <Class>` statement names the projection and gives
  its payload the type `<Class>`. The `of <Class>` clause is optional for a
  milestone with no payload.
- The `after p reaches "<name>" as m` arm reacts when the invoked child `p`
  projects that milestone. The binding `m` holds the payload of the milestone.
  The terminal handlers `after p succeeds` and `after p fails` are independent
  and do not change. The observation of a milestone does not replace the
  observation of a terminal.
- The name in a `reaches` arm must be a name that the invoked child declares. A
  `reaches` arm for a milestone with no declaration is a check error. A parent
  cannot observe a state that the child never projects. This is the invariant
  of observation of a terminal only.
- The delivery uses a poll operation and occurs exactly one time. The parent
  observes each emitted milestone on one derived fact. A milestone that the
  child never emits gives no reaction. The invoke step of the parent limits the
  latency of the observation.

### Turn-access grants

A `tell` statement can make the authority of the turn more narrow. The
statement gives one or more `with access to <resource> { <grant clauses> }`
modifiers. Write the modifiers between the target and the prompt:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
tell coder as turn
  with access to project_memory {
    recall for issue
    learn for issue
  }
  with access to project_files {
    read ["docs/**"]
  }
"Work the issue."
```

The parser also accepts the equivalent short form with a group. The short form
desugars to the same list of grants:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
tell coder as turn
  with access to {
    project_memory {
      recall for issue
      learn for issue
    }
    project_files {
      read ["docs/**"]
    }
  }
"Work the issue."
```

Each grant clause is a grant of an operation. The clause has the name of an
operation. The clause takes an optional `for <ref>` target. The clause takes an
optional list of path patterns in the form `["glob", …]`. The grant is metadata
on the `agent.tell` effect that makes the authority more narrow (Proposal A).
The effective authority of the turn is the intersection of the profile of the
agent and the grant. Thus a grant can only limit the authority that the profile
permits. A grant can never make that authority larger. The system records a
call to a tool in a turn as evidence. Such a call is not a durable child
effect.

A grant must list a minimum of one operation. A grant must not name the same
resource two times on one `tell` statement. For a declared `file store`
resource, a grant can use only the file operations `read`, `write`, `import`,
and `export`.

For the owned harness, a file tool is deny-by-default. A grant of a file store
in the input of the turn is necessary. The harness does not offer a file tool
with no grant to the model. The `read` operation and the `import` operation
authorize the read-like file tools. The `write` operation and the `export`
operation authorize the write-like file tools. The system checks each call
against the globs of the grant. The harness offers the `edit` tool only with a
read grant and a write grant. The `edit` tool also needs the two grants at the
time of execution, because the tool reads the content that exists before it
writes the new content.

A built-in profile also limits the tool surface of the owned harness. The
`repo-reader` profile is read-only. The
`repo-writer` profile, the `permissive` profile, and the `release-operator`
profile can change data, but the grants limit them. The `no-repo` profile and
the `internet-research` profile receive no file system tool and no bash tool.

The system also consults a registered custom profile. The owned harness maps
`repo.read`, `repo.write`, and `command.run` from `allowed_capabilities` to the
authority for the read tool, the write tool, and the bash tool. The harness
then makes an intersection with the grants of the turn. A change to a tracker
uses `tracker.file`, `tracker.claim`, `tracker.finish`, `tracker.release`,
`tracker.update`, or `tracker.write`. A selected sub-workflow tool with the
`@tool` tag uses `workflow.invoke`.

If the `tell` statement uses a `requires [...]` clause, the owned harness also
makes an intersection of the tool surface with those known capabilities of the
harness. If the target agent did not declare the capabilities, the store blocks
the turn before it starts the provider.

When an IFC governance envelope is active, that envelope must govern each
file-store resource that a grant of a turn names. If not, the system does not
admit the owned turn.

The harness offers the bash tool and executes the bash tool only in two
conditions together. First, the set of the profile, the registry, and the
required capabilities permits `command.run`. Second, the turn carries a
`with access to command { run }` grant. The bash tool then runs in the
**in-isolate Bashkit virtual shell** (DR-0039). The shell operates on the
governed file surface of the workspace. The shell is not a true OS shell. There
is no `fork` operation, no `exec` operation, no ambient file system, and no
ambient network. The usual features of a shell operate. These features are
pipes, substitution of a command, redirection to a file in the workspace, and a
fixed set of builtin commands. But these features cannot get outside the
workspace. Each file that a command reads, writes, or deletes crosses the
**same policy boundary of a labeled store as the file tools**. That boundary is
the read globs and the write globs of the granted stores. A path outside the
workspace does not exist for the shell. When an IFC governance envelope is
active, that envelope must govern the `command` resource. The interpreter has
no reach to the OS. Thus there is no allow-list of commands. The sandbox and
the policy of the workspace are the boundary that the system applies.

The tracker tool `list_todos` is read-only. The `add_todo` tool needs a
`with access to tracker { file }` grant. The `update_todo` tool needs the
applicable `claim`, `finish`, or `release` grant. As an alternative, the tool
accepts an `update` grant or a `write` grant. When an IFC governance envelope
is active, an authority that changes a tracker needs the envelope to govern the
`tracker` resource.

A turn can also draw tools from an external MCP server. The name of a
registered server is the resource, and the operations are the names of the
tools that the turn uses:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
tell coder
  with access to github { get_issue create_issue }
"Work the issue."
```

The operator registers the server with `whip mcp add`. See
[Providers & packages](providers.md) for that side. Four rules apply in the
language.

First, a grant names each tool. There is no wildcard. A name that the server
does not offer fails the turn at setup.

Second, the model sees each MCP tool under the name `mcp__<server>__<tool>`. A
server that ships a tool called `read` therefore cannot shadow the built-in
`read` tool.

Third, a name that the server does not offer as a tool resolves as a *role*. A
role is a group of tools that an operator classified. A role needs an attested
server or a written classification. Below that level the turn fails with a
message that names the missing classification. It does not silently offer a
smaller set of tools.

Fourth, the description and the result of an MCP tool are third-party content.
The system marks the description as untrusted for an unattested server. The
system treats the arguments as an egress and the result as a low-integrity
ingress, in the same way as the web tools.

When an IFC governance envelope is active, that envelope must govern the
`mcp:<server>` resource for each granted server. An envelope can also require a
minimum trust rung with a `require mcp <rung>` statement. A server below that
rung exposes no tool at all.

A provider configuration with a `profile_ids` field is also an allow-list of
endpoints. Such a configuration blocks an agent turn with a profile that does
not match, before the system starts the provider. The broader policy of the
governance envelope for labels and arguments is open implementation work. The
future maps of capabilities for providers and tools are also open
implementation work.

### Effect ordering and scope

The sequence of the source in the body of a rule does not sequence the effects.
An `after` block makes the durable dependency edge. The output of an effect is
visible only in the `after` branch that proves the terminal status of the
effect:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
tell worker as turn "Do the task."

after turn succeeds as completed {
  record TurnSummary {
    text completed.summary
  }
}
// `completed` is not in scope here
```

This behavior keeps the lowering of a rule deterministic. This behavior also
makes the causality of an event possible to explain.

### Matching and commits

Each worker pass evaluates the rules against the current projection. The pass
applies to one instance and one active version of the program. A
`when Class as x` clause covers the facts of that class that no rule consumed.
More than one fact clause makes a deterministic join. The rule is ready for
each tuple of bindings that satisfies each clause and each guard. Thus a rule
that matches three `Ticket` facts can commit three separate progressions, one
for each ticket. A consumed fact or a terminal state can prevent a later
progression.

A readiness clause that is not a fact is a projected fact or a gate for a
policy. The examples are `when worker is available` and
`when backlog has ready issue as issue`. The system checks such a clause at the
same boundary. A guard runs after the system selects the bindings and before
the system builds the commit.

The commit of a rule is atomic. The runtime records the consumed facts, the new
facts, the new effects, the dependency edges, the diagnostics and the evidence,
and the terminal actions of the workflow. The runtime records these items in
one transaction. If the runtime cannot validate a typed payload, a guard, a
branch, a dependency, or a terminal contract, no output of that rule lands.

**The sequence of the rules is deterministic, and the sequence is important.**
In one pass, the runtime commits a maximum of one rule firing in each round and
then scans again. The runtime uses a fixed sequence. The first key is the
**sequence of the declarations of the rules**. The second key is the
`(name, key)` sequence of the matched fact. Sometimes two rules are ready
against the same fact, and one rule consumes the fact with a `done` statement.
In that condition, the rule with the earlier declaration wins. The other rule
never fires, and the system gives no message.

This behavior is different from the statement that the sequence of the source
orders nothing. That statement applies only to the *statements in one body*.
Those statements sequence by their dependency on data and not by the sequence
that you wrote. The statement does **not** mean that the sequence of the
declarations of the rules is not important. If two rules race to a `complete`
statement or to a `fail` statement, the rule that commits first in this
sequence wins. The instance is then terminal.

A fact is set-like by its class and its key, when a stable key is present. A
fact that needs multiplicity must carry a different key. A consume operation
removes a fact from the future matches of the facts that no rule consumed. You
can still examine the historical record of the event and the fact. A terminal
state of a workflow absorbs the instance. After a commit gets to `complete` or
to `fail`, the system rejects each later commit of a rule.

### Pinned firings and `during`/`until` regions

**A firing that commits completes.** Each binding that a firing captures is an
immutable value for the life of the firing. The bindings come from the `when`
clauses and the readiness patterns. A `when` clause and a `where` clause
control the **admission** only. The continuations of a firing that committed run
from the recorded context of the firing. This is true even when an adjacent
rule later consumes the trigger fact. This is also true when the projection
that admitted the firing retracts, as when a `finish` operation closes its own
ready issue.

A query is a live read of the present, in each location. The queries are
`count`, `exists`, and `empty`. A consume operation controls the admission. A
`done` statement prevents a new firing. A `done` statement never stops a firing
that is in operation. A firing that the system admitted under an earlier
version of the program completes under the rule bodies of **that version**. The
firing uses the effect keys of its epoch of admission.

The `whip progressions <instance>` command lists each firing with its pinned
bindings, its effects, and the state of its region. The
`whip progression cancel <instance> <firing-id> [--reason …]` command is the
precise method for an operator to close a firing. The runtime cancels the
outstanding effects of the firing. A durable `progression.cancelled` event then
removes the firing from the open set. The lapse arm deliberately does not run,
because the abandonment by an operator is not a lapse of a condition. The
instance continues to run.

Reactivity in a progression is explicit. The construct is a **region**:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
until exists(Incident where sev == "sev1") {
  then plan <- tell deployer "Plan the deploy."
  then approved <- coerce reviewPlan(plan.summary)
} on lapse as got {
  release slot
  fail error { reason "halted before apply" }
}

then applied <- tell deployer "Apply: {{ approved.plan }}"
```

A `during <cond> { … }` region runs its steps only while the condition is true.
An `until <cond>` region has the opposite polarity. The region lapses when the
condition becomes true.

The condition is a pure query expression with the grammar of a guard. The
runtime evaluates the condition **in each pass in which the region is open**,
and it evaluates the condition atomically with the commit that the evaluation
produces. Thus there is no period between the check and the action. The runtime
also evaluates the condition in a pass in which no step can advance, because
each effect of the region is still in operation. The first evaluation that finds
the condition broken **while the region still owes work** — an action that did
not run, or an effect that did not settle — commits the lapse instead. The
commit has the actions of the mandatory `on lapse { … }` arm and a durable
`progression.region.lapsed` fact. The commit occurs exactly one time. The
runtime cancels the effects of the region that did not settle. A break that
arrives after the last action of the region committed lapses nothing.

A lapse in the middle of an effect is the purpose of the construct. A region
halts a deploy that runs at this moment. A region that waited for the next step
to advance could not.

The statements after the region are the point of no return. Those statements
read no condition. Those statements also sequence by their dependencies on
data, as each other statement does. The sequence of the source orders nothing.

These are the rules that the checker applies. The `on lapse` arm is mandatory.
The arm can reference only a binding from before the region. The arm can also
reference the optional **progress view** with `on lapse as got`. The fields of
the progress view are the effect bindings of the region. A field is present
exactly when that step **succeeded** before the lapse. A step that failed, that
timed out, or that the runtime cancelled is absent from the view, as a step that
never ran is. To tell those apart, read the reserved `steps` field of the view:
`got.steps.<step>` is that step's status, one of `completed`, `failed`,
`timed_out`, `cancelled`, `cancelled_by_lapse` (the commit of the lapse stopped a
step in operation) and `not_requested`. Thus `case got.steps.plan == "failed"`
branches on the outcome of a step. The checker types the view: a field that is
neither a step of the region nor `steps` is an error, a path through a status is
an error, and a deeper path under a step resolves against that step's own schema.
A region step may not be bound to the name `steps`. The same statuses ride the
`progression.region.lapsed` fact for audit. The runtime
pins the view at the time of the lapse. Read the view with `exists got.plan` and
then with `got.plan.summary`. A region must contain a minimum of one effect. In
v1, a rule has a maximum of one region.

A condition that breaks and then repairs **inside one pass**, before any
evaluation observed the broken condition, never lapses. The window is one pass
and not one step: a break that stands at the boundary of a pass lapses the
region, also when each effect of the region still runs and a repair follows. The
system observes a lapse at a commit. When you want a behavior that stops the
region one time and permanently, put the condition on a durable fact that
nothing consumes. The model is `models/maude/pinned-progressions.maude`.

#### Handling cross-rule retraction

A firing that committed completes, also when *a different* rule retracts its
trigger while its effect is in operation. For example, the rule
`request_signoff` runs a review turn on a `ReleaseCandidate` fact. A separate
rule then consumes that candidate, because a withdrawal arrives, while the turn
is in operation. The result still records an approval for a release that no
longer exists.

The rule that retracts the fact cannot cancel the turn. The binding of an
effect has the scope of its rule. A `cancel` statement reaches only an effect
that the same rule binds. Thus the rule that runs must handle this condition.
There are two patterns.

**The reactive pattern: a live query in the guard of the after arm.** A query
reads the present, also in a continuation. Thus an arm can check that its
trigger is still present. The arm can then compensate instead of a record
operation for progress that is no longer correct:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
after signoff completes {
  case signoff {
    Completed as decided
      where count(ReleaseCandidate where version == rc.version) == 0 => {
      record Withdrawal { version rc.version  reason "answered after withdrawal" }
    }
    Completed as decided => {
      record Approval { version rc.version  approvedBy decided.summary }
    }
    # … Failed / TimedOut / Cancelled …
  }
}
```

**The anticipatory pattern: an `until` region.** Put the turn in a region. A
withdrawal then *cancels the turn that is in operation*. The result of the turn
does not land:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
until exists(Withdrawal where version == rc.version) {
  tell reviewer as signoff "Approve {{ rc.version }}?"
  # … after signoff completes { record Approval … } …
} on lapse {
  record Withdrawal { version rc.version  reason "withdrawn while pending" }
}
```

The region is stronger, because the region stops the work that has no value.
The guard has a lower cost, because the guard only discards the result that is
no longer correct. The `whip progressions` command shows an open firing whose
pinned trigger went away. The annotation is the neutral text
`trigger no longer live`. Thus an operator can see a case of an approval that
is no longer correct, also when the program uses neither pattern. Full examples
are in `spec/decision-records/0044-retraction-examples.md`.

### `case`

A `case` statement branches deterministically on the field of an enum or on the
terminal union of an effect:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
after turn completes {
  case turn {
    Completed as completed => {
      record TurnReport { branch "completed" summary completed.summary }
    }
    Failed as failure => {
      record TurnReport { branch "failed" detail failure.reason }
    }
  }
}
```

A `case` statement also branches on a type that is a union of string literals.
An example is a field with the declaration `status "approve" | "reject"`. The
same check on exhaustiveness applies:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
case answer.choice {
  "approve" => { complete result { decision answer.choice } }
  "reject"  => { fail error { reason "rejected" } }
}
```

The value in the test must have a type with a finite domain. Such a type is an
enum, a terminal union, a union of string literals, an optional, or a `bool`. A
`bool` matches the literals `true` and `false`. The compiler rejects a `case`
statement on a plain `string`. Use guarded rules instead. A `case` statement on
a `bool` is exhaustive only when the statement covers `true` and `false`. A `_`
arm is the alternative. Refer to
[`examples/terminal-output-union.whip`](https://github.com/GaugeWright/whipplescript/blob/main/examples/terminal-output-union.whip)
for exhaustive handling of a terminal.

### Inline `decide`

A `decide` statement is an anonymous typed model decision in the body of a
rule. The statement is a coercion with its schema in position. Use the
statement when a named `coerce` declaration would occur one time only:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
decide "Is this plan safe to ship? Explain." -> { fixed bool, reason string } as verdict

after verdict succeeds as v {
  record ShipReview {
    fixed v.fixed
    reason v.reason
  }
}
```

The statement lowers to the same `schema.coerce` effect as a named `coerce`
declaration. Thus the same rules apply. The effect is durable, the effect can
fail, and its typed output is available only in an `after ... succeeds` branch.
Use a named `coerce` declaration when you use the decision again or when the
prompt needs a record. Use a `decide` statement for a local judgment that
occurs one time.

The anonymous result type of an inline `decide` statement flows across the
`after ... succeeds` binding. The behavior is exactly the behavior of a named
`coerce -> Schema` declaration. Thus you can do a field access on a `decide`
result and you can use a `case` statement on a `decide` result. To *branch* on
a decision, give the result a field with a `bool` type, an enum type, or a type
that is a union of string literals. Then use a `case` statement on that field:

<!-- check: fragment -->
```whip
decide "Is this plan safe to ship? Explain." -> { fixed bool, reason string } as verdict
after verdict succeeds as v {
  case v.fixed {
    true => { complete result { ok true } }
    false => { tell reviewer "Held: {{ v.reason }}" }
  }
}
```

A named `coerce` declaration is still correct when you use the shape of the
decision again. Its declared class is a shared contract, and the declaration is
a record of the contract:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
class ShipVerdict { decision "ship" | "hold"  reason string }

coerce assessShip(plan string) -> ShipVerdict { prompt "{{ plan }}" }

# in a rule body:
coerce assessShip(ticket.plan) as verdict
after verdict succeeds as v {
  case v.decision {
    "ship" => { complete result { decision "ship" } }
    "hold" => { tell reviewer "Held: {{ v.reason }}" }
  }
}
```

### The `prompt` effect

The `prompt` effect is the free-text equivalent of the `decide` statement. The
effect is a call to a model with no output schema. Use the effect for prose
that a person or a later prompt reads. Do not use the effect for a value that
the workflow branches on. The effect lowers to the same `schema.coerce` family.
Thus the durability, the sequence of the providers, the capability, and the
position on IFC egress are the same. The result is a plain string. The success
binding *is* the string:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
prompt "Summarize this incident for the status page: {{ ticket.title }}" as summary

after summary succeeds as text {
  record StatusUpdate { body text }
}
```

The `using <provider>` clause selects a provider for this effect. This clause
is the equivalent of the `provider` clause in the block of a coercion. There is
deliberately no field access on the result. The result is a string and not a
record. A decision that needs structure is a `coerce` statement or a `decide`
statement.

## `then` chaining

The `then <binding> <- <effect statement>` statement chains the **success** of
an effect into the remainder of the block that contains the statement. The
statement is pure sugar. Each statement after the `then` line to the end of the
block desugars to `after <handle> succeeds as <binding> { … }`. Thus the
runtime stays the deterministic rule kernel that this page gives. The `flow`
declaration is no longer in the language. The `then` statement is the surface
for a sequence.

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
rule triage
  when Ticket as ticket
=> {
  then plan <- tell triager "Plan {{ ticket.title }}."
  then verdict <- coerce reviewPlan(ticket.title, plan.summary)

  case verdict.choice {
    "approve" => { complete result { plan plan.summary } }
    "reject"  => { fail error { reason "rejected" } }
  }
}
```

These are the semantics:

- **The binding is the success payload.** The behavior is exactly the behavior
  of `after … succeeds as`. The handle of the effect is a synthetic hidden name
  in the form `__then_<binding>`. The `__then_` namespace is reserved. If you
  write such a name, the result is a check error. A step that needs the raw
  handle uses the traditional `as` and `after` form. A step that a `cancel`
  statement stops is an example.
- **A `then` statement chains success only.** If a chained step fails or times
  out, the automatic failure net at the level of the rule catches the step. The
  section above gives the net. The reason gives the name of your binding. This
  behavior is the explicit contract of the sugar. Thus the warning of the
  unhandled-failure check does not fire on a `then` step. A step that needs a
  typed failure or a recovery uses the traditional form. The two forms compose
  in one rule.
- **A `then` statement operates in each block.** The blocks are a rule body, an
  `after` block, and a `case` arm. The scope of the chain is the block that
  contains the chain.
- The `whip check` command prints the desugared rule. Thus you can always audit
  the sequence. A chain deliberately has no construct for a branch. To branch,
  use a `case` statement or divide the work into rules.

## Trackers

A tracker is durable issue tracking that you declare in the source. A tracker
is independent of a vendor. Use a tracker when work arrives as a backlog of
issues that a rule claims, works, and finishes. Do not use a tracker when the
work arrives as facts that a table seeds at the start:

<!-- check: fragment -->
```whip
tracker backlog
```

The bare form gives the provider the default value `builtin`. Today `builtin`
is the only provider. The block form `tracker backlog { provider builtin }`
states the provider explicitly. The scope of the `builtin` tracker is the
workspace. The tracker stores its issues in `.whipplescript/items.sqlite`.
Override the path with the `WHIPPLESCRIPT_ITEMS_STORE` variable. The tracker
gives sequential identifiers: `WS-1`, `WS-2`, and so on. The durable status of
an issue is `open`, `closed`, or `canceled`. The `in_progress` value is an
overlay of a claim. The value appears while an active lease holds the issue.
The value goes away when the lease releases or expires. The value is never a
stored status.

The body of a rule uses these verbs on a tracker:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
file issue into backlog { title "Fix login" body "Users report 500s." }
claim issue as work
release issue
finish issue { summary "patched and verified" }      # optional `as x` for chaining
```

React to ready work with this readiness pattern:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
rule pick_up
  when backlog has ready issue as issue
  when worker is available
=> {
  claim issue as work
  tell worker as turn "Resolve {{ work.title }}."
}
```

A `claim` statement can fail. When a different claimant already holds the item,
the claim effect fails normally. Branch on the failure with
`after work fails as f { ... }`, as you branch on each other failure. Do not
treat the failure as an error.

The instance that claims an item holds the item for the life of the instance.
Release the item explicitly with a `release` statement or a `finish` statement.
If the instance gets to a terminal first, the runtime returns the item that the
instance still holds to the `open` state. Another worker can then take the
item. The terminal includes a `whip cancel` command from an operator. A
claimant that stops never abandons its work.

An operator and an agent manage the items from the CLI:

```sh
whip issue new --tracker backlog --title "Fix login" [--body "..."] [--label bug]
whip issue list [--tracker backlog] [--status open]
whip issue show WS-1
whip issue ready backlog [--limit 5]
whip issue claim WS-1 [--actor agent:a]
whip issue renew WS-1 [--actor agent:a]
whip issue release WS-1
whip issue finish WS-1 [--summary "done"]
whip issue dep add WS-2 depends-on WS-1
```

When an agent files an item during a turn through the CLI, the runtime stamps
the item with the provenance of the identity of the run. The runtime reads the
`WHIPPLESCRIPT_RUN_ID` environment variable. Thus you can trace the growth of
the backlog to the run that caused the growth.

The internal design record for `std.tracker` gives the model in detail. The older record about work queues is superseded and
gives a banner to the current record.

## Time and deadlines

Time enters a workflow as an effect. Time never enters as an ambient read of a
clock in a guard.

A `timeout` clause limits each type of effect. If the effect did not complete
when the duration is complete, the effect ends in the `timed_out` status. An
`after ... times out` branch or an `on timeout` branch can then react:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
tell worker as turn timeout 10m "Do the work."
```

The deadline of a `timeout` clause **starts when the system makes the effect**.
The deadline does not start when the effect begins to run. Thus an effect that
waits behind a capacity gate uses its deadline *while it waits*. The gate is a
`when worker is available` clause. If two turns with a `timeout` clause compete
for one worker, the sequence of the runs decides which deadline expires in the
queue. Give a long timeout to an effect behind a capacity gate. The timeout
must cover the expected wait. As an alternative, gate on capacity that you know
is free.

A `timer` statement is an independent effect. The effect completes when its
duration is due. Use a timer for a delay, for an interval between polls, and
for a deadline that is not part of a different effect:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
timer 24h as deadline

after deadline succeeds {
  tell reviewer "24h elapsed — still waiting on review."
}
```

The `cancel <binding>` statement cancels an effect that is pending or in
operation. An earlier statement in the body must bind the effect. For example,
the statement cancels a turn of a worker after a person rejects the plan.

Write a duration in the form `<n><unit>`. The units are `s`, `m`, `h`, and `d`.
The examples are `30s`, `10m`, `24h`, and `7d`.

A timer and a timeout fire on a worker pass. There is no daemon in the
background. The `whip run --until idle` command holds a pending timer to be
idle. The command does not block for the wall clock. The `whip status` command
lists the pending time effects. Thus you can see the item that an instance
waits for. The internal design record for time records the semantics.

## `exec`

The `exec` statement has two profiles.

In the dev profile, an `exec` statement runs a local command string as an
effect with a gate:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
exec "scripts/run-tests.sh" as tests

after tests succeeds as result {
  record TestRun { passed result.exit_code == 0 }
}
```

The output binding makes `tests.exit_code` and `tests.stdout` available.

Two gates control an `exec` statement in the dev profile. The first gate is the
`use std.script` import. The second gate is the configuration of the operator.
No syntax in the source grants a command. The worker reads the
`WHIPPLESCRIPT_EXEC_ALLOW` variable. The value is a list of glob prefixes with
a colon between them. An example is `scripts/*:bin/ci-*`. If the import is
absent, or if there is no allow-list, the effect blocks at admission before any
run. The status is `blocked_by_capability` with the code
`security.script_disabled`. If the list is not empty and a command does not
match a grant, the effect fails and goes to the `after x fails` branch.

The dev profile has no sandbox. A grant is a deliberate decision by the
operator to trust a command, and the record shows the decision. Keep the
allow-list as small as the workflow needs.

In the hosted profile, the system rejects a raw command string. The source
names a script capability that the operator pinned. The source passes typed
input on stdin:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
exec backup_repo with request -> Report as backup

after backup succeeds as report {
  record BackupFinished { summary report.summary }
}
```

The operator supplies a JSON manifest outside the workspace:

```json
{
  "backup_repo": {
    "argv": ["bash", "scripts/backup.sh"],
    "sha256": "9f2c...",
    "env": { "BACKUP_TOKEN": "env:BACKUP_TOKEN" }
  }
}
```

Run a hosted check or a hosted worker with
`--exec-profile hosted --script-manifest <path>`. As an alternative, set
`WHIPPLESCRIPT_EXEC_PROFILE=hosted` and
`WHIPPLESCRIPT_SCRIPT_MANIFEST=<path>`. The worker registers `script.<name>`.
The worker verifies the bytes of the script against the `sha256` value. The
worker stages a verified copy. The worker then starts the argv list directly.
No text from the source goes into a shell. A hash mismatch fails before the
process starts. The evidence of the failure records the expected hash and the
actual hash.

## Files

A `file store` declaration declares a named directory with a root scope. A
workflow can read from the directory and write to the directory. The store is a
policy boundary. The store is not an open handle to the file system:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
file store project_files {
  root "./data"
  allow read ["docs/**", "notes/*.md"]
  allow write ["out/**"]
  provider local
}
```

**A store is read-only by default.** A read operation needs no clause, because
the mount of the root is the consent to read. An `allow read [...]` list makes
the paths that a read operation can touch more narrow. The paths are relative
to the `root` value.

The system **denies a write operation and an export operation unless the store
declares `allow write [...]`**. That list permits the operations and limits the
operations. A write operation against a store with no write policy is a check
error. The runtime applies the same denial and fails closed.

The optional `provider <name>` clause names the provider that supports the
store. The `local` provider is the default when the clause is absent. The
`local` provider is the only provider in v1. An unknown name is a check error.

The `import <format> <Schema> from <store> at <path> as <binding>` statement
decodes a structured file into one typed `<Schema>` fact for each row. The
formats are `jsonl`, `json`, and `csv`. A `when <Schema>` rule then reacts to
the facts. The runtime validates each row against the necessary fields of the
schema. The runtime admits the full batch atomically. An invalid row fails the
import, and the runtime admits nothing. If the schema marks a field with `@key`
— for example `id string @key` — the value of that field identifies each row.
Thus a second run is idempotent on that field. If no field has the mark, the
position keys each row.

The
`export <format> <Schema> to <store> at <path> { where <pred> mode <mode> } as <binding>`
statement is the inverse of the import statement. The statement serializes the
facts of `<Schema>` to a `jsonl` file, a `json` file, or a `csv` file. The
`where` filter is optional. The sequence is deterministic. The same `mode`
policy as the `write` statement applies. The set that the `where` clause
filters is a *projection with a collection value*. The projection uses the same
match operation on facts that a guard uses, but the projection gives a
collection and not a count.

The `read` statement loads one file into a typed binding as an effect with a
gate:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
read text from project_files at "notes.md" as fileResult

after fileResult succeeds as result {
  record Loaded { body result.content }
}
```

The success binding makes `result.content` and `result.bytes` available. The
`result.content` value is the body of the file. An absent file goes to the
`after fileResult fails` branch. A refused path also goes to that branch.

The `write` statement renders a body to a file. The statement needs an explicit
`mode` value. There is no silent overwrite operation:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
write text to project_files at "summary.md" {
  body result.content
  mode create
} as written

after written succeeds as w {
  record Saved { path "summary.md" }
}
```

These are the modes. The `create` mode fails when the file exists. The
`replace` mode fails when the file does not exist. The `upsert` mode operates
in the two conditions. The `append` mode adds to the end of the file. A
violation of the mode is a usual failure. An example is the `create` mode on a
file that exists. The runtime routes the failure to the `after written fails`
branch and does not change the file. The `body` value is an expression. The
runtime resolves the expression when the effect runs. Thus a write operation in
an `after <read> succeeds as r { … }` block can write `r.content`.

The `read`, `write`, `import`, and `export` statements lower to the
`file.read`, `file.write`, `file.import`, and `file.export` kinds of effect.
These statements are effects. These statements never run in a guard and never
run during a static check.

The `root` value of the store is the boundary of the scope. The system takes
the path relative to the `root` value. The system refuses a path that is
absolute. The system also refuses a path that uses `..` to go above the root.
The system refuses these paths before it touches the disk. When the store
declares the globs, the path must also match the `allow read` globs or the
`allow write` globs. A denied path fails the operation. The system does not
touch a file outside the policy.

In a `whip test` scenario, seed deterministic content for a file with the
`given file <store> at "<path>" "<content>"` clause. The harness writes the
content to a temporary directory and redirects the root of the store to that
directory. Thus the `read` operation runs against the true fixture.

These are the current limits. Refer to the `files` spec for the full design of
the package and for the plan. The `read` statement and the `write` statement
handle only the `text` codec and the `markdown` codec for a body. The
structured `json`, `csv`, and `jsonl` formats are the surface of the `import`
statement and the `export` statement. The `bytes` codec is deferred, and the
parser rejects it. The `import` statement and the `export` statement are
complete from end to end. Chapter 20 of the manual runs the round trip. The
*grants* for the `files.read` capability and the `files.write` capability are
not yet implemented.

## Gauges and campaigns (experimentation surface)

A `gauge` declaration declares a named dimension of quality. The declaration
has a judge. The declaration can bind to a site. The declaration can carry a
bar. A gauge is the stochastic equivalent of a `test` block. A test asserts a
deterministic expectation one time. A gauge makes *each* run an observation.
The `whip run` command scores the deterministic judges that have no cost
ambiently after each settled run. The `whip gauges` command shows the
accumulated evidence. The `whip improve` command optimizes against the
evidence.

<!-- check: fragment -->
```whip
gauge extract_quality on summarize.extract {
  judge via exec "./judge.py"
  expect P(due_date_correct) at least 0.9
}
```

- `judge via coerce <Name>(<args>) | prompt "<template>" | exec "<command>" | labels "<source>"`
  — a gauge has one slot for a judge and four granularities of ground truth. An
  `exec` judge is a deterministic validator. The pattern is deterministic
  validation: the context of the run as JSON on stdin, and a JSON object on
  stdout. The `WHIPPLESCRIPT_EXEC_ALLOW` variable governs the judge. A `labels`
  judge reads a JSON file that a user owns. The name of the scenario keys the
  file. An `exec` gauge and a `labels` gauge resist the law of Goodhart by
  construction, because a person cannot persuade a validator.

  A `coerce` judge binds its parameters **explicitly**. Each argument names the
  record value that supplies the parameter at that position. The forms are
  `input.<path>` and `facts.<Class>.<field>`, where the second form gives the
  last recorded fact of the class. The single reserved word `record` passes the
  full input record of the judge to a coercion with one parameter. An incorrect
  arity is a check error. An incorrect shape of a path is also a check error.
  Thus a signature that changes can never rebind a judge silently. A `coerce`
  judge with no arguments parses, but the judge honestly cannot give a score. A
  `coerce` judge and a `prompt` judge run at the time of a campaign or a settle
  operation, because they need a native provider. These judges never run
  ambiently.
- An `expect` bar has one of two shapes. A chance bar uses `P(<field>)`, where
  the field is the boolean output field of the judge. An example is
  `expect P(ok) at least 0.9`. A statistical bar operates on the distribution
  of the scores. The examples are `expect p90 at most 800` and
  `expect mean at least 0.7`. A bar uses the word forms `at least` and
  `at most`. A declaration uses words where an expression uses an operator.
  This is the same pattern as a condition of presence, which uses `is`. A
  declared bar is a hard constraint for the `whip improve` command.
- An `inputs a, b` clause declares a **derived gauge**. The `exec` judge of the
  gauge also receives the scores of the named gauges. Thus a composite
  objective and a business objective are usual gauges. There is no feature for
  weights.
- The `std.spend`, `std.latency`, and `std.tokens` gauges are built-in gauges
  for resources. These gauges are deterministic observations from the ledger of
  the run. These gauges are present with no declaration. For each of these
  gauges, a lower value is better. The `std.cache_hit` gauge ascends: a higher
  value is better. The gauge is the hit rate of the prompt cache of the
  provider. The value is the tokens that the provider read from the cache
  divided by each token on the input side. The gauge is present only when the
  provider reports the use of its cache.

A `mark` declaration declares a named cut point. The declaration gives the
position of the important moments of a run, as part of the program:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
mark "triaged" after classify
```

The runtime stamps a `mark.reached` event each time that the named rule
commits, on each run. Thus the capture is retroactive and ambient. Each past
run can become a scenario at each declared mark. Use the
`whip pin <instance> at triaged --as subject-line-case` command. A scenario
that a mark pinned freezes the *prefix* of the run. The `whip suppose` command
and the evaluation of a campaign replay that prefix. A replayed effect never
fires again. The two operations then execute only the suffix again. This is
paired regeneration at the cut. The name of a mark is stable across an edit,
but the offset of an event moves. A `mark` declaration is deliberately separate
from a milestone. A mark is a position in the event log. A milestone is a
signal about the lifecycle.

A `campaign` declaration declares objective intent. The declaration has a
version, and you can diff the declaration. The declaration is a division of the
vector of gauges. The declaration has more ceremony than an invocation of the
CLI. The `whip improve release_tuning` command adopts the declaration:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
campaign release_tuning {
  ascend    extract_quality, reply_quality
  reach     std.latency at most 800ms
  guard     tone within 2 percent
  sacrifice verbosity
}
```

A named gauge in the `ascend` clause moves toward a better value. A `reach`
clause sets a target. After the workflow meets the target, the target holds as a
hard limit. A `guard` clause makes the band of indifference of a gauge larger.
A `sacrifice` clause releases a gauge from the set of guarded gauges, and the
evidence card records this decision. A gauge with no name in the campaign is
always guarded. There are no modes.

An optional `proposer redacted` clause attaches stratified reflection to the
campaign. The proposer then sees aggregate statistics only. The proposer never
sees the name of a scenario, an input, a trace, or the reasoning of a judge.
The evidence of the campaign then carries the `proposer:redacted-view` tag. The
`whip improve --redacted-view` flag makes each campaign more strict in the same
manner. A flag can never make a declared clause less strict. Refer to
`whip improve` in the [CLI Reference](api-reference.md) for the loop of a
campaign, the policy for the holdout set, and the adoption operation.

## Channels (`std.messaging`)

A `channel` declaration declares a named route for communication through a
provider. The channel is the boundary for communication through a platform.
Slack and email are examples. The construct belongs to a package. The bare
`channel` shape is reserved for `std.messaging`. Thus a package from a third
party cannot make semantics that are similar to a channel but that have weaker
guarantees.

<!-- check: fragment -->
```whip
use std.messaging

channel release_room {
  provider local
  workspace ops
  destination "#release"
}
```

The `provider` value defaults to `local` when you omit the clause. Thus the
bare `channel release_room` declaration is sufficient for a local mailbox. The
value must name one of the v1 messaging providers. The providers are `local`, a
mailbox in a file that operates in the two directions; `desktop`, a native
notification that is outbound only; `stdio`, which operates in the two
directions over the stdio of the process; and `fixture`. As an alternative, the
value is the full binding identifier of a provider, such as
`std.messaging.local`. An unknown identifier of a provider is a check error.

The capability report of each provider limits the operations that a channel
admits. A `when message from` clause on a `desktop` channel is a check error,
because the report of that provider is outbound only. The `workspace` field and
the `destination` field are optional configuration of the provider. A secret
and a credential are always references in the configuration of a provider. They
are never literal values in the source.

A channel declaration registers the `std.messaging` library in the library
contract of the program automatically. That registration covers the inbound
`when message from <channel>` clause. The outbound `send` construct also needs
the import statement `use std.messaging`.

## Credentials (`std.custody`)

A `credential` declaration declares a handle for a secret that a custodian
holds. The material of the credential never appears in the source, in the
program, or in the address space of whip. Governance supplies the reality of
the handle through a grant, and the custodian — a separate security
principal — performs every operation with the material.

<!-- check: fragment -->
```whip
credential stripe_api      { kind bearer }
credential release_signing { kind ed25519 }
credential s3_key          { kind aws_sigv4 }
```

The `kind` clause is required. The kinds are `bearer`, `basic`, `raw`,
`hmac_sha256`, `ed25519`, `aws_sigv4`, and `jwt_rs256`. The kind lets the
checker reject an operation that the credential cannot perform statically: a
`sign` with a `bearer` credential is a check error. The registered kind at the
custodian is authoritative, and a mismatch is an error. A credential
declaration registers the `std.custody` library automatically.

### The `secret` type

The type `secret` is a built-in type beside `string` and `bool`. A value of
type `secret` can be bound, passed, stored in a field of a class, and placed
in an effect position. No operation in the language or the runtime yields the
material of a secret. A `secret` field admits no literal: a credential is a
reference, never a value. A model cannot produce a secret either — the
coercion schema of a `secret` field matches nothing.

The type carries the credential kind: `secret<ed25519>`, `secret<bearer>`,
`secret<hmac_sha256>`, and so on across the same closed set that
`credential … { kind … }` declares. A kind outside that set is a check error
rather than a silent widening.

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
class ReleaseKeys {
  signing secret<ed25519>
  webhook secret<hmac_sha256>
  anything secret
}
```

Bare `secret` remains valid and means "any kind". The discriminant exists
because the checks that depend on a credential's kind are keyed by its *name*,
and each of the four things a secret is allowed to do — bind, pass, store,
place in an effect position — leaves no name to resolve. What a stored secret
still carries is its type.

The angle brackets are a built-in constructor, as in `map<string>`, not a
type parameter: the argument ranges over a closed, protocol-owned set of
values rather than over types.

### `obtain credential`

An agent or a rule that discovers it needs authority it was not granted raises
a **governance escalation**. The statement is deliberately non-blocking: it
files a tracker item and derives a `credential.requested` fact, and the run
continues.

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
rule deploy
  when deploy.blocked as blocked
=> {
  obtain credential deploy_key into ops {
    title "deploy_key is not granted"
    body "Deploy blocked: {{ blocked.reason }}"
  } as escalation
}
```

The fact is what makes the escalation *reactable*: a rule matching
`when fact credential.requested as asked` acts on the program's own missing
authority. The item names the tracker, as every tracker write in the language
does; there is no ambient escalation queue.

Nothing waits. A run proceeds, or fails on the authority it still does not
have, and a later run — after a human edited governance — succeeds. A blocking
request would be the shape the language removed when it removed `ask_human`.

The credential must be declared. An escalation naming an undeclared handle is a
check error: it would ask a human for a credential no rule can ever use, and
the escalation would look answered while changing nothing.

### Minting a scoped child

A `mint` spends a credential at an issuer's token endpoint and gets a child
handle back. The exchange is the token request you would have written anyway:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
mint credential from stripe_api {
  at POST "https://connect.stripe.com/oauth/token"
  header "Authorization" basic stripe_api
  body "grant_type=client_credentials&scope=charges:write"
  token at "access_token"
  public ["expires_in"]
} as token
```

The custodian executes the exchange, so the minted token never enters whip. The
binding carries the child's handle, its fingerprint, and whatever `public`
names — no field on it yields material.

There is no `scope` clause and no `ttl` clause. Both are vendor protocol and
both belong in the body, which is the only place they can be true: a clause
beside the body could say something the body does not, and nothing could tell,
because the custodian does not read the body.

What bounds a mint is **the parent's egress ceiling, which the child inherits**.
The child is registered beneath its parent, so the scope lookup walks up the
name and the guarantee is one sentence: a minted credential can never reach
further than the credential it was minted from. Governance may narrow one child
further by naming it; the nearest ancestor wins.

Three refusals: minting from an undeclared credential, an exchange that
presents nothing, and an exchange that presents a *different* credential than
the one being minted from — the last because the child inherits the named
parent's ceiling, so spending another credential would produce a child bounded
by an authority it was never derived from.

### Where a credential may reach

The signed envelope bounds a credential's egress. The clause sits beside the
binding and applies to every construct that uses the credential — a rule-body
`request`, an agent turn, anything later:

```text
grant credential stripe_api -> credential:acme/stripe-live sealed at hardware
grant request    stripe_api for POST https://api.stripe.com/v1/refunds/*,
                                 GET  https://api.stripe.com/v1/charges/*
```

Each entry is `[METHOD ]scheme://host/path`; entries are separated by commas,
and a missing method matches any. There is no `to <role>` clause: reach is a
property of the credential, not of who holds it.

A request outside the scope is refused — at check time when the URL is a
literal, and at egress always, because an interpolated URL is not knowable to
the compiler. The clause applies once governance *binds* the credential; a
policy that never mentions one does not constrain it.

Matching is component-wise against a parsed URL. Method, scheme, host and path
each match their own part, so `*` never crosses from the host into the path,
and the host of `https://api.stripe.com@evil.example/v1` is `evil.example`. A
leading `*` in a host must stand for a whole label: `*.stripe.com` is the
subdomain wildcard; `*stripe.com` is a check error, because it reads as
narrowed to that host while admitting `evil-stripe.com`.

An agent turn narrows beneath that ceiling, and never widens it:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
tell deployer
  with access to credential stripe_api {
    request ["POST https://api.stripe.com/v1/refunds/*"]
  }
"Refund the disputed charge."
```

The turn is then offered a `credential_request` tool naming exactly the
credentials it was granted. A call is admitted only when both the turn's globs
and the envelope's scope admit it — the same relationship a turn's file-store
grant has with the store's own `allow` globs. The material never enters the
agent's process: the turn names a credential, and the custodian substitutes at
egress.

### The sealing rung and the governance floor

The custodian seals material at a rung that it derives from evidence:
`process` (r0, the development shim — the reply of the custodian is tagged
degraded), `os-keyring` (r1), `hardware` (r2, a TPM or a PKCS#11 token), and
`remote` (r3, a vault such as OpenBao — the material never exists on the
machine). The signed governance envelope can demand a floor:

```text
require credential hardware
grant credential stripe -> credential:acme/stripe-live readable by Ops
```

The floor lives in the signed envelope beside `require mcp` and for the same
reason: provisioning a credential must not lower the bar that judges it. The
resource identity of a credential is `credential:<name>` and is deliberately
free of the backend, so a migration from one sealing backend to another does
not invalidate the grants that name it.

Send an outbound message with a `send via <channel> { ... } as <binding>`
statement:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
rule notify
  when Ticket as ticket where ticket.status == "open"
=> {
  send via release_room {
    text "Ticket {{ ticket.id }} needs triage."
  } as sent

  after sent succeeds {
    complete result { ok "notified" }
  }
}
```

The `text` field is necessary. The `markdown` field and the `thread_id` field
are optional. The `send` statement lowers to a call to the `messaging.send`
capability. The embedded `std.messaging` package supplies the construct. Add
`use std.messaging` to the workflow. The `send` statement then needs **no**
package lock, because the manifest is in the `whip` binary. A construct from a
third party still needs the `whip package sync` command. You must declare the
named channel. A `send via <unknown>` statement is a compile error.

The `as <binding>` receipt is the typed `MessageSendReceipt` value. The fields
are `message_id`, `channel`, `provider`, `status`, `provider_message_id`,
`thread_id`, `destination`, and `accepted_at`. The `message_id` field is the
durable outbound identifier, and the identifier is stable across a replay. The
`provider` field is the provider identifier that the binding resolved and that
accepted the message. The `status` field is `accepted` in v1. A correlation
field that the provider cannot report is an empty string.

A send operation that fails is not a receipt. Such an operation settles as
`capability.call.failed` and goes to the `after <binding> fails as f` branch.

The binding drives the dispatch. The declared provider of the channel resolves
against the bindings of the `messaging.send` capability that the embedded
manifest seeds. The `local` provider maps to the mailbox in the file at
`<store>.mailbox.jsonl`. The `desktop` provider maps to a native notification.
The `stdio` provider maps to a marker line on stdout. The `fixture` provider
maps to a deterministic receipt in the process. Examine the local deliveries
with the `whip mailbox` command.

The generic inbound envelope is the built-in `Message` schema. The fields are
`message_id`, `channel`, `provider`, `received_at`, `sender`, `sender_claims`,
`thread_id`, `text`, `markdown`, `attachments`, `interaction`, `raw_ref`, and
`correlation`. Inbound messaging always supplies a generic `Message` value. The
system never supplies a domain type. The change of a message into a typed fact
is explicit. The methods are `coerce msg.text -> Decision` and a `signal`
mapping. React to a message with this readiness form:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
rule react
  when message from release_room as msg
=> {
  complete result { note msg.text }
}
```

You must declare the channel. A `when message from <unknown>` clause is a
compile error. The binding `msg` has the type `Message`. Under the fixture
provider, inject a message with the
`whip message <instance> --channel <name> --text "…" --program <file>` command.
The rule then fires. Live ingestion from Slack or from email needs the
configuration of a provider. The map of the `source interaction` provider still
needs a live messaging provider and stays on the plan. Refer to the
`messaging` spec.

## `assert`

An assertion is an executable statement about a run that completed. The
`whip run` command and the `whip accept` command evaluate an assertion after
the instance becomes idle:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
assert count(Ticket where status == "open") == 0
assert count(IncidentResolution where status == "resolved") >= 1
assert count(effect kind agent.tell where status == completed) == 3
```

An assertion reads the facts and the projections of the effects. An assertion
uses the same expression language as a guard. An assertion never changes the
execution. Put a tag on an assertion to select a subset for each run. Use the
`whip run --include-tag acceptance` command.

## Static checks

The `whip check` command and the `whip compile` command validate the bundle
before a run. The commands validate the types, the paths of the fields, the
payloads of the contracts, the targets of the effects, the names of the
bindings, and the liveness rules below. The paths of the fields include the
`{{ ... }}` references to a template in a prompt. An unknown name gets a
suggestion.

### Liveness checks

- **Each workflow must be able to end.** A minimum of one rule must get to
  `complete` or to `fail`. Add the `@service` tag to a workflow that runs
  continuously by design. A watcher and a recurrent harness are examples.
- **Each rule must be able to fire.** Some part of the program must supply each
  matched class. The source can be a table, a different rule, or an input of
  the workflow. Add the `@external` tag to a rule when its facts come from
  outside the workflow. Packages, fixtures, and external systems are examples.
- **Each check applies to every workflow of a bundle.** A file that declares
  more than one workflow gets each check on each workflow, not only on the one
  that `--root` names. A workflow that an `invoke` statement reaches is
  therefore under the same rules as the entry point, and no refusal is escapable
  by a move of the code into a second workflow.
- **An effectful cycle of rules that does not wait on the world is refused.**
  The compiler classifies the strongly connected components of the rule
  dependency graph. A component of two rules or more in which a rule runs an
  effect is a check error (`graph.unbounded_effect_recursion`) when each
  `record` of the cycle lands in the same commit as the fact that the rule
  matched. Nothing paces such a cycle, so it turns at the speed of the store. A
  cycle whose recurrence sits inside an `after` block waits for the terminal of
  an effect on every turn, and the compiler permits it with no tag: that loop is
  the long-running agent loop, and the rules of liveness above still govern it.
  A component with no effect is monotonic recursion and is allowed. A recurrence
  through an external event or a clock never enters this graph, because such a
  trigger matches no recorded class. A cycle of one rule belongs to the separate
  check on a rule that preserves its own trigger, which the `done` statement
  escapes.
- **A `@bounded` workflow may not loop with the world at all.** The `@bounded`
  tag is the opposite of the `@service` tag: it declares that the workflow
  reaches a terminal after a number of steps that the program fixes and the data
  does not. In such a workflow every produce and consume edge counts, so an
  effect-bearing cycle of rules is a check error
  (`graph.bounded_workflow_effect_cycle`) even when each turn waits on the
  world. A `@tool` workflow carries the same promise with no tag, because an
  agent invokes it inside a turn and DR-0025 requires the turn to end.
- **The invoke-tool graph must be acyclic.** An agent may call a granted `@tool`
  workflow synchronously, so a cycle of `tools` grants is an unbounded depth of
  recursion (`graph.unbounded_tool_grant_recursion`).
- **An `invoke` statement may not target a `@service` workflow.** The parent of
  an invocation observes the typed terminal output of the child, and `@service`
  is the declaration that a workflow is not required to reach one
  (`graph.invoke_awaits_service_workflow`). The refusal rests on that missing
  promise, not on a claim about the run: a `@service` workflow with a completing
  rule does terminate. The agent-tool seam applies the same rule on the tag
  alone. The tag stays legitimate: the refusal is of the await, never of the
  declaration.

```whip
@service
workflow RecurringTriage

@external
rule import_ticket
  when ExternalTicket as ticket
=> { ... }
```

### Not Gherkin

A `when` clause is a typed readiness pattern. A `when` clause is not a step in
free text. If you put Cucumber or Gherkin text into a `.whip` file, the parser
gives a specific diagnostic. The text is `Feature`, `Scenario`, `Given`,
`When`, or `Then`. The diagnostic points at `workflow`, `table`, `rule`, and
`assert`.

## Information-flow control (governance envelope)

Under a signed governance envelope, the `whip check` command applies
information-flow control. The `WHIPPLESCRIPT_IFC_ENVELOPE` variable gives the
envelope. Without an envelope, a program is ungoverned. This is dev mode, and
the program makes no claim about information flow.

**The contract is a set of denials.** Each denial is universal. The checker
denies *each* instance. A denial is not a list of blocked items. Each denial
names its only permitted crossing:

- **Confidentiality.** A value has a label that admits the reader set R. The
  checker denies that value to each sink, terminal, provider, and recorded fact
  with an audience that is not in R. A consume operation on a fact, which is a
  `when <Schema>` clause, is a read at the *computed producer reach* of the
  fact (DR-0045). The producer reach is the true upstream sources where the
  chain is attributable. Where the content is not accountable, the producer
  reach is the declared label. The checker gates labeled content on its exit as
  on its entry. A fact with a `from` vouch vouches for the writes of its
  consumers. Untrusted content cannot pass through an intermediate fact with no
  label.

  The only crossing is a `declassified` coerce statement with a source mark.
  The output schema of the coercion limits the release. The requirement for a
  grant covers the sources that get to the *arguments* of the coercion. The
  requirement chains through an intermediate coercion. Each item that is not
  attributable widens the requirement, and the widening fails closed, to the
  full read set of the rule. The trusted surface of the guarantee report prints
  the computed provenance of each crossing as `carries: …`.
- **Egress through a provider.** The checker denies the context of a turn to
  each model provider with no clearance for the data that the turn read. The
  same denial applies to the prompt of a coercion and to the result of a tool
  of an agent. A clearance for a provider is a grant from governance. A
  clearance is not a decision of an author.
- **Integrity (the dual property).** The checker denies data that a principal
  below the necessary authority of a sink influenced influence over that sink.
  Thus untrusted model output never shapes trusted state. An output of an
  effect supplies the `from` clearance of *its executor* (DR-0046). The
  outputs are a turn, a coercion, and an `exec` statement. The `from` clearance
  comes from the integrity clause of the grant for the provider. The checker
  checks each destination of the output. The destinations are a payload, the
  selector of a `case` statement, and a chain of facts. The only crossing is an
  `endorsed` coerce statement with a source mark. The grant endorses the
  executor.
- **Robust declassification (NMIF).** The checker denies data that an attacker
  can control the ability to steer its own release. A crossing that a
  discriminant with low integrity selects is itself a denial. Refer to
  `models/lean/Whipple/NMIF.lean`.
- **Redaction.** The checker denies a field that a `redact … keep` statement
  dropped to each sink, with no exception. The runtime physically removes the
  field. A proof shows the non-interference. Refer to
  `models/lean/Whipple/Redaction.lean`.
- **The identity ceiling.** The checker denies an agent that serves a user each
  read above the clearance of that user (DR-0028).

**The mechanism** that applies these denials is a comparison of the reader sets
and the acts-for relation. A label for confidentiality is a set of reader
authorities. A party can observe a value only when the party acts for each
authority in the set. The checker walks the reads and the sinks of each rule
under the delegation sequence of the envelope.

That vocabulary is also the surface for a *repair*. The vocabulary is the
grants, the clearances, and the `readable by` clause. Governance lifts a denial
with a `grant … readable by <role>` clause, a `grant declassify …` clause, or a
`grant endorse …` clause. As an alternative, the author changes the structure:
keep the contexts separate, and pass a result with limits and with a redaction.
The author alone can never lift a denial with a grant.

The diagnostics use the same structure. The message names the denied flow and
its intended audience first. The message then gives the universal rule in
parentheses. The help line gives the repair. Refer to `examples/infoflow/` for
a governed example, and to the [Guarantees](guarantees.md) page for the list of
promises.

## Semantics notes

### Workflow invocation

An `invoke` statement starts a child instance with its own event log and its
own lifecycle. The parent sees only the declared output payload or the declared
failure payload of the child:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
invoke ReviewPhase {
  phase PhaseReviewRequest {
    id phase.id
  }
} as review

after review succeeds as result {
  record ParentReviewComplete { phaseId phase.id result result }
}

after review fails as failure {
  record ParentReviewBlocked { reason failure.reason }
}
```

A provider failure in the child does not go to the parent. The `fails` branch
of the parent runs only when the child workflow itself executes a `fail`
statement.

An invocation can also carry a start grant for a specified resource:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
invoke ReviewDocs {
  task task
}
  with access to project_files {
    read ["docs/**"]
  }
  as review
```

The child has its own workflow principal and its own slot for the effective
authority of the instance. A local child uses `workflow:local/<name>`. A child
with the `@tool` tag that a package exports and that the owned harness invokes
uses the package identifier of the manifest that exports the child. Under a
governed envelope, an imported tool of a package also opens the membrane door
`invoke:<package_id>/<tool>`. The envelope of the consumer must govern that
door before the system accepts the tool or offers the tool to the model.

An `invoke` statement in a rule uses the delegating start seam. The default
authority is the declared authority of the child, and the effective authority
of the parent makes that authority more narrow. A `with access to` clause makes
the limit still more narrow. The runtime rejects a grant that would make the
authority larger than the authority of either side. The grammar accepts the
`with access to <resource> { ... }` form and the grouped short form
`with access to { <resource> { ... } ... }` on an `invoke` statement. The
grouped form desugars to the same metadata for a grant for each resource,
before the admission at run time.

### Provider failure vs. workflow failure

A provider run that fails is state of an effect and of a run, together with
events and evidence. The instance stays in the `running` state until a rule
reacts or an operator acts. A `fail` statement is the decision of the workflow
itself to end without success. The division between the two is deliberate. The
selection of the provider failures that are fatal is policy, and policy is in
the rules.

### Revision

A change to the program of an instance that runs is an operation of the control
plane. The command is `whip revise`. There is no syntax in the source. A
workflow can *propose* a change with a usual effect. A `tell` statement can ask
an agent to draft a candidate. A `coerce` statement can review the candidate. A
review turn can request an approval. But the activation occurs outside the
source. Refer to
[runtime & operations](runtime-operations.md#revising-a-running-instance).

### Prompt content types

A `tell` prompt and a `coerce` prompt can annotate the opening delimiter with a
content type. The forms are `"""markdown`, `"""json`, and a MIME value such as
`"""application/json`. The compiled input of the effect keeps the annotation as
`prompt_content_type` for the reports. The annotation does not validate the
body. The annotation does not change the behavior of the provider. Put the text
of the prompt on the line after the opening marks.

### Advanced: named harnesses

A `provider` binding on an agent is the usual path. This path covers almost
each workflow. Sometimes one family of provider needs more than one configured
endpoint. In that condition, declare named harnesses and bind an agent to one
harness:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
harness coder: codex
harness reviewer: claude

agent worker using coder { ... }
```

A registry derives the kinds of provider and the kinds of harness. Refer to the
"Open provider registry" section of `spec/std-agent.md`. The manifests of the
packages contribute the known set. The embedded `std.agent` package contributes
`owned`, `fixture`, `native-fixture`, and `command`. The `std.agent.codex`
package and the `std.agent.claude` package contribute `codex` and `claude`,
when the compiler includes the features of their adapters. A locked package
from a third party can contribute more kinds. An unknown kind is a check error
that names the absent package. Use a named harness only when a plain `provider`
binding cannot express the topology of the endpoints that you need.

## Typed data and coordination

### Sum types

A variant of an `enum` can carry a typed payload. The payload is a body in
braces with the grammar of a class field. The system synthesizes the
discriminant from the name of the variant. The discriminant lands in JSON as a
reserved `variant` field, such as `{"variant": "Approved", "score": 0.9}`. A
declaration of a field with the name `variant` is a check error. Each variant
with data lowers to a visible `<Enum>.<Variant>` class. A `case` statement on a
sum value dispatches on the variant and binds the payload with `as`. The
coverage must be exhaustive, or the statement must have a `_` arm. A run with
the fixture returns the first declared variant. The `--variant <name>` flag
selects a different arm.

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
enum ReviewOutcome {
  Approved { score float }
  Rejected { reason string }
  Blocked
}

case outcome {
  Approved as a => { complete result { note "{{ a.score }}" } }
  Rejected as r => { fail error { reason r.reason } }
  Blocked => { fail error { reason "blocked" } }
}
```

### Conditional fields

A field can declare that it exists only for one value of a literal union on the
same class:

<!-- check: fragment -->
```whip
class Change {
  kind "deploy" | "rollback"
  region string when kind is "deploy"
  revertTo string when kind is "rollback"
}
```

The named field is the discriminant. It has to be a string literal union on the
same class. An enum is not a discriminant, because the comparison is on the
literal text. A conditioned field on an undeclared discriminant, a literal
outside the union, or a discriminant that is not a literal union is a check
error. The keyword is `is`; `==` in that position is a parse error.

Admission requires the field exactly when the discriminant holds the literal. A
`Change` with `kind` of `"deploy"` and no `region` is a rejected fact. The rule
is positive only: when the discriminant holds another value the field is not
required, and a value present under that other value is neither rejected nor
validated. An undeclared key is still rejected, as for any closed class.

A read of a conditional field is legal only where the discriminant is pinned to
the matching literal, which is the matching arm of a `case` on that
discriminant:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
case change.kind {
  "deploy" => { record Deployment { region change.region } }
  "rollback" => { record Reversion { target change.revertTo } }
}
```

The arm guard is checked in the same narrowed scope. A `_` or `default` arm
pins nothing and grants no read. The check covers every read position a rule
body has: a `record`, terminal, `done` replacement, and `emit milestone` value;
a branch condition and a `case` guard; every effect operand, such as a coercion
argument, a coordination key, a timer deadline, and an invoke payload; and a
`from` projection, both the field a block names and the same-named fields such
a projection copies implicitly. A model prompt and an `exec` command line are
free text, so the check reads only inside `{{ … }}` there.

A readiness guard is not a body position and is not narrowed. In
`when Change as c where c.region == "x"` the read is accepted; pair the test
with its discriminant (`where c.kind == "deploy" && c.region == "x"`) to say
what is meant.

### JSON ingestion on `exec`

The `exec "cmd" -> Report as x` statement and the hosted
`exec capability with input -> Report as x` statement change the meaning of
success. Success means an exit code of 0 AND stdout that parses as `Report`. An
`after x succeeds as r` block binds the typed value. A failure to parse or a
failure against the schema goes to the `after x fails` branch.

The `-> each WorkItem` form parses a JSONL stream or a top-level array. The
form records one typed fact for each element. The provenance is `ingest`. The
operation is all or nothing. A line with an incorrect form fails the full
effect. A rule reacts with the usual `when WorkItem as item` fan-out.

### Deterministic validation

The `exec "<validator>" -> Schema` statement is the deterministic equivalent of
a `coerce` statement. A `coerce` statement asks a model to judge an artifact. A
deterministic validator is a checker that is not a model. The examples are the
detection of a Unicode script, a pass with a regular expression or a format
check, and a linter for a schema. The output of such a validator is
reproducible. The same input always gives the same typed result.

The workflow runs the checker. The workflow ingests the JSON decision of the
checker against a declared `class`. The workflow then branches on the decision,
as it branches on each other typed effect. The plan for the end-to-end tests
reserves this path for exact properties of a script or a fixture. Such
properties must hold in CI with no access to a provider. A `coerce` review that
a model judges and a deterministic validation are for use together.

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
exec "validate-script {{artifact.path}} {{artifact.expectedScript}}" -> ScriptCheck as check

after check succeeds as result {
  complete report { detail result.detail }
}

after check fails as failure {
  fail error { reason failure.message }   # exec failures expose `.message`
}
```

The operator supplies the binary of the validator. The operator grants the
binary through the `WHIPPLESCRIPT_EXEC_ALLOW` variable, as for each `exec`
statement in the dev profile. The program imports `std.script`. If not, the
effect blocks at admission. A validator that does not match, or a validator
with an incorrect form, is a typed failure of the effect. The runtime routes
the failure to the `after check fails` branch. The failure is never a silent
pass. Refer to `examples/deterministic-validation.whip` for a workflow that you
can run from end to end. Note that the failure binding of an `exec` statement
carries the reason at `failure.message`. The `failure.reason` field is the
field that the failure of a workflow invocation and the failure of a `coerce`
statement make available.

### Scheduled time

The `time` type is a scalar. A value is an ISO-8601 instant as a literal in
quotation marks. A
`timer until <literal-or-time-typed-path> as deadline` statement fires on the
first worker pass at the target or after the target. An
`after deadline succeeds` block reacts to the recorded firing. There is no
`now` value in a guard. The system reads the clock only at the boundary of the
worker.

### Signals

A `signal deploy.finished { service string  status string }` declaration
declares typed external ingress. React with the bare form
`when deploy.finished as d`. The form is typed and needs no `@external` tag.

Inject a signal from outside with this command:
`whip signal <instance> --name deploy.finished --data '{"service":"api","status":"ok"}' --program <workflow.whip>`.
The system validates the payload at the boundary. An optional
`--delivery-id <id>` flag makes the delivery idempotent by the identifier of
the provider or the operator. This identifier wins over the derived hash of the
payload. The same identifier two times admits one fact. This behavior continues
across the runs of the process, and the system absorbs the duplicate and
reports the duplicate.

For ingestion from a pipe or from a script, use the
`whip ingress serve --stdio --program <workflow.whip>` command. The command
reads JSONL envelopes from stdin through the same door for admission. An
envelope has the form
`{"instance", "signal", "payload", "delivery_id"?}`. The command writes one
line of JSON with the result for each envelope.

Inject a signal from a different workflow with the effect that injects a
signal:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
emit signal deploy.finished to s.target {
  service s.service
  status "ok"
} as sent
```

The target, which is `s.target` here, must be the identifier of an instance
that exists in the same store. If not, the effect fails with
`target instance <id> not found` and goes to the `after sent fails` branch.

The system generates an instance identifier at the time of the `run` command.
Thus a true identifier of a peer usually comes on a fact. An example is a
`PeerInstance` fact that the program records when the peer registers. The
identifier is not a literal. The `examples/event-bridge.whip` file uses a
placeholder identifier in a `peers` table only so that the file passes the type
check. Thus the file needs a true peer to run.

This is a minimal exercise with two instances. Run the `whip run` command on
the workflow of the peer and make a note of its identifier. Point the fact or
the table of the peer in the source at that identifier, with the same `--store`
value. Run the `whip signal` command on the source. Then run the `whip step`
command and the `whip worker` command on the source. The signal then arrives as
a `deploy.finished` fact on the peer, and the source records its
`DeploymentNotice` fact.

### Coordination resources

The coordination resources are a closed family with the scope of a workflow.
You declare each resource with a typed key and mandatory limits. Only an atomic
effect that you can branch on changes a resource:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
lease deploy_slot { key Environment  slots 1  ttl 10m }
ledger decisions  { entry Decision  partition by area  retain 90d }
counter budget    { key Customer  cap 1000  reset daily }

lease global_deploy_slot { shared  key Environment  slots 1  ttl 10m }

acquire deploy_slot for r.env as slot     # after slot held / after slot contended
release slot                              # or `acquire ... until ttl` (fire-and-forget)
append Decision { area d.area } to decisions as entry
consume budget for t.customer amount t.estTokens as spend   # after spend ok / over
```

The compiler applies the safety model. A progression holds a maximum of one
lease. The handling of the outcomes must be exhaustive: `held` and `contended`,
or `ok` and `over`. The rule must release a lease on each path that is not a
terminal.

A terminal releases each lease that the instance holds, automatically. The
terminal can be a `complete` statement or a `fail` statement from a rule. The
terminal can also be a `whip cancel` command from an operator. Thus the
lifetime of the holder limits each lease, and the TTL is only the net for a
crash.

The reset of a counter occurs at the boundary of the consume operation and not
before. The period uses the `timezone "<IANA zone>"` value of the counter, and
the behavior is correct for daylight saving time. If you omit the value, the
period uses UTC and the checker gives a warning. Each outcome of a consume
operation records the period that the runtime used. Thus a replay reads the
same boundary. Examine the shared state with the `whip leases` command, the
`whip ledger` command, and the `whip counters` command.

By default, the owner of the workflow partitions the rows of a coordination
resource. Thus two workflows that use the same name for a resource in the
source do not contend and do not communicate through the bits of an outcome.
The bare `shared` field puts the resource under the shared owner. Under
`shared`, an outcome that you can branch on is a source for a read of
information across principals, and a change is a governed sink. A resource that
only one workflow principal uses stays without a label. Such a resource is
self-coordination.

### Observability export

The `whip otel-export <instance>` command is a sidecar with a cursor. The
command reads the end of the durable log. The command emits traces as OTLP/HTTP
JSON. The name of each span comes from a construct in the source. The
attributes are structural only. The command emits each span one time across the
runs. The command obeys the `OTEL_EXPORTER_OTLP_ENDPOINT` variable and the
`OTEL_SERVICE_NAME` variable. Point the command at a local OpenTelemetry
Collector. The collector owns the TLS configuration and the distribution to the
backends. The `--dry-run` flag prints the payload.

## What WhippleScript is not

WhippleScript is not a general-purpose language. Keep the manipulation of data
small and deterministic. Move the computation into a provider, a coerce
function, a package, or a child workflow behind an explicit effect.

WhippleScript is not a framework with an implicit lifecycle. Recurrent work, a
heartbeat, memory, a review, and an escalation are usual facts, effects, and
rules. These are never hidden modes of control flow.
