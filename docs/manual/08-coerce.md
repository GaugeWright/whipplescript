# Prompts, coerce, and decide

Each operation of a workflow to this point is deterministic. This chapter adds
calls to a **large language model**. The chapter first gives the most simple
kind of call. The chapter then gives the disciplined kind that the remainder of
the manual uses.

## The most simple call to a model: the `prompt` statement

The `prompt` statement sends text to the model and receives text. The statement
is an effect, like each other effect. It is durable, it can fail, and an
`after` block observes it. Its success binding *is* the returned string:

<!-- check: skip — excerpt; `Ticket` is the surrounding program's fact -->
```whip
use std.coercion

rule summarize
  when Ticket as ticket
=> {
  prompt "Summarize this ticket in one sentence: {{ ticket.title }}" as summary

  after summary succeeds as text {
    record StatusNote { body text }
  }
}
```

The `{{ ticket.title }}` text in the string is a **template**. The template
puts the field of a bound fact into the text before the runtime sends the text.
A template is the method that gets the data of a workflow to a model. Each
string in WhippleScript that goes to a model operates in this manner.

Use the `prompt` statement when the output is prose for a person or for a
subsequent prompt. A summary, a draft, and an explanation are examples. But
note the limits of the result. The result is a string. The string cannot drive
a `case` statement. The string cannot satisfy a field with a literal union. You
cannot check the string. When the answer of a model must *decide* an item, free
text is the incorrect shape. The remainder of this chapter gives the correct
shape.

## The `coerce` statement: judgment as data

A `coerce` statement is a call to a model. A declared class limits the output
of the call. The model reasons in language. The workflow receives a value:

<!-- check: context ch08 -->
```whip
use std.coercion

class Verdict {
  priority "urgent" | "routine"
  reason string
}

coerce judgeTicket(title string, body string) -> Verdict """markdown
Classify this ticket as urgent or routine.

Title: {{ title }}
Body: {{ body }}

{{ ctx.output_format }}
"""
```

A `coerce` declaration reads as a typed function. It has named arguments, a
return class, and a prompt template that uses the arguments. Here `{{ title }}`
and `{{ body }}` put the arguments of the call into the text. The `markdown`
tag gives the type of the content. A plain `"""` string also operates. Two
details are important:

- The return class is the contract. The fields of `Verdict` are a literal union
  and a string. The runtime changes the fields into the output schema that the
  model must satisfy. The runtime then parses the response and validates the
  response into a typed `Verdict` value. A response that does not agree with
  the schema is a failed effect. It is not a damaged fact.
- The `{{ ctx.output_format }}` template gives the necessary output shape to
  the model in the prompt. End each prompt with this template.

Note the value of the field with a literal union. The model must *make a
selection* between `"urgent"` and `"routine"`. The model cannot answer "fairly
urgent, I think". The model has no third option. The result then supplies a
`case` statement with a check on exhaustiveness. The largest part of the skill
here is the design of the decision class from enums and literal unions. Make
the model answer with exactly the states that the workflow branches on.

## How to use a coercion in a rule

```whip
use std.coercion

workflow Classify

output result Done

class Done {
  priority string
  reason string
}

class Ticket {
  title string
  body string
}

class Verdict {
  priority "urgent" | "routine"
  reason string
}

table tickets as Ticket [
  {
    title "checkout is down"
    body "no orders are completing"
  }
]

coerce judgeTicket(title string, body string) -> Verdict """markdown
Classify this ticket as urgent or routine.

Title: {{ title }}
Body: {{ body }}

{{ ctx.output_format }}
"""

rule classify
  when Ticket as ticket
=> {
  coerce judgeTicket(ticket.title, ticket.body) as verdict

  after verdict succeeds as v {
    complete result {
      priority v.priority
      reason v.reason
    }
  }
}
```

The `coerce judgeTicket(…) as verdict` statement is an effect, like each other
effect. It is durable, it can fail, and an `after` block observes it. The
success binding `v` is a typed `Verdict` value. Thus `v.priority` and
`v.reason` are usual field reads.

Run the program with no configuration. The program completes. But the `check`
command first gives one warning: no branch handles the failure of `verdict`.
This is the same net from chapter 6. A subsequent section of this chapter
closes the net. If no model is configured, a coercion runs on the **fixture**.
The fixture is the deterministic replacement for a model in whip. The fixture
needs no credentials. The fixture returns a placeholder that agrees with the
schema. Here the placeholder is `{"priority": "urgent", "reason": "fixture"}`.
The fixture returns the first literal of a union and the value `"fixture"` for
a free string. A true model binds through the configuration. An environment
variable selects a provider. The providers are Anthropic, OpenAI, and each
endpoint that is compatible with OpenAI. A local endpoint is also possible. The
[providers guide](../providers.md#openai-compatible-local-models-ollama-vllm-openrouter-groq)
gives the procedures. The configuration changes. The rules do not change.

## When a coercion needs more than a prompt

The form with a string after the arrow is sufficient for the usual condition.
When a coercion needs more than its prompt, the declaration takes a block of
clauses instead:

<!-- check: in ch08 -->
```whip
coerce judgeTicket(title string, body string) -> Verdict {
  provider fixture
  prompt """markdown
  Classify this ticket as urgent or routine.

  Title: {{ title }}
  Body: {{ body }}

  {{ ctx.output_format }}
  """
}
```

The `provider <name>` clause pins this one coercion to a provider. The clause
overrides each other selection mechanism. The clause is useful in two
conditions. One decision must stay on a local model with a low cost. Or one
decision must not leave a specified backend. The block accepts exactly the
known clauses. An unknown field is a check error. A spelling error such as
`promt` is also a check error. Thus a coercion is never silently without a
prompt.

## How to branch on the verdict

The design of the decision class is correct for a `case` statement. Thus use a
`case` statement:

<!-- check: skip — an `after` block; its effect is in the surrounding rule -->
```whip
after verdict succeeds as v {
  case v.priority {
    "urgent" => {
      record Escalation { title ticket.title }
    }
    "routine" => {
      record Backlogged { title ticket.title }
    }
  }
}
```

This is the idiomatic decision loop of WhippleScript: **the judgment of a model
enters, a typed value exits, and an exhaustive branch uses the value.** Never
parse the prose of a model to select a route. If a decision needs the model,
make the decision a coercion and branch on the result.

A coercion can fail. A provider error is one cause. A response that the runtime
cannot parse is a different cause. Chapter 6 applies without change. Handle
`after verdict fails as f` where a failure needs a typed answer. Remember that
a failure with no handler fails the instance automatically with a generic
reason.

## The `decide` statement: the inline form

Sometimes a decision occurs one time, and a named declaration is unnecessary
ceremony. In this condition, the `decide` statement writes the schema in
position:

<!-- check: skip — excerpt; `Plan` is the surrounding program's fact -->
```whip
rule review
  when Plan as p
=> {
  decide "Is this plan safe to ship? {{ p.text }}" -> { safe bool, reason string } as verdict

  after verdict succeeds as v {
    case v.safe {
      true  => { complete result { branch "ship" } }
      false => { complete result { branch v.reason } }
    }
  }
}
```

The `decide` statement lowers to the same effect with the same semantics. The
effect is durable, it can fail, and it is typed. Select the form by the needs
of the program and not by the machinery. A named `coerce` declaration is a
recorded contract that you can reuse. Its class can also go across rules and
workflows. The `decide` statement is for a local judgment that occurs one time.
When the same shape of decision occurs a second time, change the shape into a
named declaration.

## Where next

Chapter 9 gives the `then` statement. The statement chains a progression that
is truly a pipeline. The statement lowers to the same rules that this part
taught. Later, Part II introduces agents. An agent is a model worker with turns
that have more than one step. The prompts of an agent are exactly the templates
that this chapter introduced.
