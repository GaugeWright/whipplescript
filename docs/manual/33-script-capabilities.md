# Script capabilities & the bash tool

Chapter 19 gave pinned scripts to a *workflow*. This chapter gives pinned
scripts to an *agent*. This is the authority with the highest risk that a turn
can hold. This chapter also gives the shell. The answer of WhippleScript to the
shell is deliberately different from an escape hatch.

## A script capability as the authority of a turn

The hosted manifest from chapter 19 has named capabilities, a pinned argv list,
a SHA-256 value, and references to environment variables. That manifest is also
the vocabulary for the authority of an agent. The same document from the
operator bounds the operations that an agent can *execute*. The document also
bounds the operations of a workflow. Audit the document with the
`whip script list` command and the `whip script verify` command. To make the
authority of one turn more narrow, use the grant machinery from chapter 11.
Chapter 20 completed the form of that machinery for a file store:

<!-- check: skip — excerpt; `operator` is the surrounding program's agent -->
```whip
tell operator as turn
  with access to project_files {
    read ["backups/**"]
    write ["reports/**"]
  }
"""markdown
Verify last night's backup and write the report.
"""
```

The chain of ceilings is uniform, and each level can only make the authority
more narrow. The manifest bounds the operations that exist to run. The operator
owns the manifest. The profile of the agent bounds the items that this agent
can touch. The source owns the profile. The grant of the turn makes the
authority still more narrow. The rule owns the grant. The harness brokers each
call in the three limits. The ledger of the run then records the call as
evidence. The position from chapter 19 does not change. The operator owns the
item that runs, byte for byte. A hash mismatch fails before the process starts.

## The question of bash

Shell access is the point where an agent platform usually stops and gives an OS
shell behind a timeout. The design of WhippleScript refuses this choice
(DR-0039):

- **The `bash` tool is a virtual shell. It is not an OS shell.** This applies
  to the native placement and to the Durable Object placement. In a turn on the
  owned harness, the `bash` tool runs an interpreter in the process. The
  interpreter operates on a *governed snapshot of the workspace*. The system
  loads the files that the grants of the turn permit the turn to read. The
  write policy gives the files that the turn can write. The command executes
  against that snapshot. There is no ambient file system, no process table, and
  no network. The system then validates the resulting delta against the same
  policy before it imports the delta back. A command of the `grep`, `sed`, or
  `jq` class operates on exactly the files that the turn can touch. Nothing
  else exists for the command. The semantics do not depend on the placement.
  The behavior of `bash` that the model learns on a laptop is true on the edge.
- **The tool has two gates.** The profile of the harness must permit bash. If
  it does not, the message is `bash is not permitted by profile …`. The turn
  must also carry a `with access to command { run }` grant. This is the same
  chain that only makes authority more narrow. Each invocation starts a new
  process and has limits. The limits are a hard timeout for each command, size
  caps for the workspace, the files, and the output, and a fuel value for the
  count of commands. A command that the tool does not support fails honestly
  with `command not found`. The tool does not return a plausible replacement.
- **True execution of a subprocess stays separate.** A compiler, a runtime, a
  browser, and the API of a service are not bash. Each of these is an explicit
  capability with its own contract. The manifests in this chapter and the
  packages in chapter 31 give such capabilities. A general broker for
  capabilities in the form of shell escalation is exactly the item that this
  division forbids.

Use this rule when you author a workflow. The `bash` tool is for work with text
tools *in* the workspace that the grant permits. Each operation that needs a
true toolchain or an external system is a named capability with an entry in the
manifest.

## How to design the tool surface of an agent

Part V converged on a discipline. This is the discipline in one location:

1. **Give a name to the operation, not to the mechanism.** Use a manifest
   capability with the name `nightly_backup`. Do not use bash with access to
   the directory of the backup script. A named capability continues after a new
   implementation. A named capability also reads as policy.
2. **Put each deterministic check in a validator.** Each item that a machine
   can check belongs in an `exec -> Schema` statement from chapter 19 or in an
   exec judge from chapter 26. An agent *cannot* argue with such a check.
3. **Let the ledger be the audit.** Each call to a capability that an agent
   makes is an effect with evidence. The panel from chapter 30 shows the true
   history of the tools in a turn. Thus the question for a review is "was this
   call correct?". The question is never "what did the agent run?".

## Where next

Chapter 34 is the last chapter. The chapter gives the runtimes below each
construct. The chapter gives the native store that you used, the Durable Object
placement on the edge, and the true operation of the `deploy` command and the
`executor` command.
