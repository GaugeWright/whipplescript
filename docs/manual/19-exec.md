# Exec: validation & hosted scripts

Chapter 6 introduced the `exec` statement as the escape hatch. The statement
runs a shell command. The program must import `std.script`. The operator must
also put the command in the `WHIPPLESCRIPT_EXEC_ALLOW` allow-list. The
statement has a success branch and a failure branch. Chapter 6 also gave an
honest limit: the dev profile has no sandbox, and a grant is a deliberate
decision to trust. This chapter completes the construct on the two axes that
make the construct sufficient for production: **typed results** and **pinned
execution**.

## Deterministic validation: the `exec … -> Schema` statement

A `coerce` statement asks a model for a judgment. Many checks need the
opposite. A validator gives an answer that is a *function of its input*. Format
detection, schema lint, and checksum verification are examples. In each of
these conditions, the same artifact must always give the same result. The
`exec "<command>" -> Schema` statement gives this behavior:

```whip
use std.script

workflow DeterministicValidation

output result ValidationReport
failure error ValidationFailed

class Artifact {
  path string
  expectedScript string
}

class ScriptCheck {
  isExpectedScript bool
  detail string
}

class ValidationReport {
  path string
  detail string
}

class ValidationFailed {
  reason string
}

table artifacts as Artifact [
  {
    path "target/dogfood/sample.txt"
    expectedScript "Latin"
  }
]

rule validate_artifact_script
  when Artifact as artifact
=> {
  exec "check-script --json" -> ScriptCheck as check

  after check succeeds as result {
    done artifact
    complete result {
      path artifact.path
      detail result.detail
    }
  }

  after check fails as failure {
    fail error {
      reason failure.reason
    }
  }
}
```

The command prints JSON on stdout. The arrow admits that output **only when
the output decodes against the schema**. The `result` binding is then a typed
`ScriptCheck` value. Thus `result.isExpectedScript` branches as each typed
field does. A validator that prints incorrect data gives a *typed failure of
the effect*. The runtime routes the failure to the `after check fails` branch.
Incorrect data never enters your facts without a report.

This is the division of the work with chapter 8. Use a `coerce` statement for a
judgment. Use an `exec -> Schema` statement for a deterministic answer. Use a
bare `exec` statement for plumbing. Plumbing is a command that runs for its
side effect, and the exit code checks the command.

## The hosted profile: capabilities and not command strings

The dev profile trusts the allow-list of the operator. The dev profile also
puts values into a command string. For each use outside development, use the
**hosted profile**. The hosted profile removes the two liberties. The profile
rejects a raw command string fully. The source gives the name of a **script
capability** instead. The operator pins the capability. The source passes typed
input on stdin:

```whip
use std.script

workflow Hosted

output result Done
failure error Failed

class Request {
  name string
}

class Reply {
  message string
}

class Done {
  note string
}

class Failed {
  reason string
}

table requests as Request [
  {
    name "ops"
  }
]

rule call
  when Request as request
=> {
  exec greet with request -> Reply as call

  after call succeeds as reply {
    complete result {
      note reply.message
    }
  }

  after call fails as f {
    fail error {
      reason f.reason
    }
  }
}
```

The `exec greet with request -> Reply` statement sends the `request` fact as
JSON on the stdin of the script. The statement admits the stdout of the script
through the `Reply` schema. Thus the two directions are typed. The definition
of `greet` is outside the workspace, in a manifest that the operator supplies:

```json
{
  "greet": {
    "argv": ["bash", "greet.sh"],
    "sha256": "435941dbff79…",
    "env": { "GREET_TOKEN": "env:GREET_TOKEN" }
  }
}
```

Run the workflow with the `--exec-profile hosted --script-manifest <path>`
flags. As an alternative, use the `WHIPPLESCRIPT_EXEC_PROFILE` variable and the
`WHIPPLESCRIPT_SCRIPT_MANIFEST` variable. The worker verifies the bytes of the
script against the pinned `sha256` value. The worker stages a verified copy.
The worker then starts the argv list directly. There is no shell. No source
text goes into a command line. Each secret is a *reference* to an environment
variable, and the worker resolves the reference at the start of the process.

The pin has an effect. Change one byte of the script after the pin operation:

```text
instance ins_… failed
reason: script capability `greet` hash mismatch: expected 435941db…, got f45dd87b…
```

The mismatch fails **before the start of the process**. The evidence of the
failure has the expected hash and the actual hash. Thus a change in the supply
chain is a loud failure that you can attribute. The change is not a silent
difference in the execution.

## How to select a profile

The two profiles are one construct with two positions on trust. Use the dev
profile statement `exec "cmd"` for a workspace that you already trust. Quick
validators, build steps, and small connections are examples. The import and the
allow-list are the gates. The profile is honest: it has no sandbox. Use the
hosted profile statement `exec <capability> with <input>` for each operation
that an operator must be able to audit later. The workflow states the item that
it needs, by name and by type. The operator owns the item that runs, byte for
byte. The two profiles settle through the same lifecycle of an effect from
chapter 5. Thus a workflow can start on the dev profile and move to the hosted
profile. The shape of its rules does not change. Change the command string to a
capability name, and move the definition into the manifest.

## Where next

Chapter 20 gives files. The chapter gives the `file store` declaration, the
read, write, import, and export effects, and the policy boundary that is
read-only by default. The turn grants in chapter 11 pointed at this boundary.
