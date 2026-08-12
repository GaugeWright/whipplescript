# Authoring packages

Part V extends the system itself. The first surface for an extension is the
**package**. A package adds capabilities, providers, profiles, schemas, and
skills to the platform. A contract governs a package. The contract keeps an
extension as honest as the core. The contract in one line: *a package exposes
an explicit effect. A package never adds a hidden control flow or a new
grammar.*

## How to consume a package

Each `use std.*` statement from chapter 6 to this point consumed a package. The
standard library is a set of embedded packages. The packages include
`std.script`, `std.files`, `std.messaging`, `std.tracker`, `std.coord`, and
`std.memory`. Thus these packages need only the import statement. The general
surface of a package is the `call` effect:

<!-- check: skip — excerpt; the package query type is not declared here -->
```whip
use std.memory

rule fetch_context
  when MemoryQuery as lookup
=> {
  call memory.query for lookup as context

  after context succeeds as found {
    tell worker as turn "We have {{ found.count }} relevant memories."

    after turn completes {
      complete result { note "done" }
    }
  }

  after context fails as problem {
    fail oops { note problem.reason }
  }
}
```

The `call <capability> for <record> as x` statement is a durable
`capability.call` effect. The effect has the full lifecycle from chapter 5: it
enters a queue, executes, settles, and branches. The record binding is the
input of the capability. Here the input is a `MemoryQuery { query string }`
fact that an earlier rule recorded. The fact agrees with the input schema of
the contract. The success binding carries the output. The `memory.query`
capability returns `pool`, `count`, and `items`.

The name of the capability resolves against the registered contract of the
package. Sometimes that contract declares `validation: runtime_boundary`. In
that condition, the runtime checks the output of the provider against the
declared `output_schema` *before* it derives a success fact. Thus an
implementation of a package with incorrect behavior gives a failed effect. Such
an implementation never gives a fact with an incorrect type.

The tracker verbs in chapter 15 and the coordination verbs in chapter 14 are
the same machinery with dedicated syntax. A `std` package can register such
sugar. A package from a third party uses the `call` statement.

## Manifests: checked and locked

A package from a third party arrives as a **manifest**. A manifest is a JSON
declaration of the libraries, the capabilities, the providers, the profiles,
and the bindings of the package. The manifest passes two gates before a
workflow can touch the package:

```sh
whip package check notes.json
```

```text
notes.json notes@0.1.0 0fc2b7d048863216…
```

```sh
whip package lock --output whip.lock notes.json
whip run workflow.whip --package-lock whip.lock
```

The `package check` command validates the manifest against the construct
catalog of the platform. The `whip package catalog` command prints the accepted
families, the scopes, and the classes of the lowering operation. This catalog
is the machine-readable limit of the claims that a package can make.

The `package lock` command pins each manifest by its exact SHA-256 value in a
`whip.lock` file. Each command finds this file automatically. The command
searches upward from the directory of the workflow. Commit the lock file
adjacent to the workflow. Update the two files together.

The rules of the lock file fail closed, in the usual manner. An edit of a
manifest after the lock operation fails the load with a stable `package_lock`
error. To repin the manifest deliberately, run the `lock` command or the `sync`
command again. An import that is not in `std.` and that has no lock file gives
a diagnostic. The diagnostic gives the items that block the import. An entry in
the lock file can never claim the reserved `std.*` namespace. The embedded
manifest always wins. Thus nothing can replace the standard library.

## The permitted content of a package

The construct catalog applies the position of the design:

- A package **can** register these items: a capability contract, which has a
  typed input, a typed output, and a validation position; a provider, which is
  an execution backend for such a capability; a profile, which is a named level
  of authority; a schema; a skill, which is a bundle of context; and a library
  declaration for the `use` statement.
- A package **cannot** do these operations: it cannot introduce grammar; it
  cannot add control flow; it cannot own semantics that are similar to a
  channel but that have weaker guarantees than `std.messaging`; and it cannot
  go around the lifecycle of an effect. The shape of a construct such as
  `channel` belongs to its `std` owner. Each operation of a package at run time
  is a `capability.call` effect in the ledger.

Thus the observability from chapter 30 and the governance from chapters 22 to
24 apply to an extension at no cost. A call to a package is an effect with
evidence. Its provider is a principal that governance can control. Its manifest
is a pinned artifact with a hash. Some parts of the package system are still
experimental. Treat a manifest as source that the system checks. Give a version
to each manifest. Use the lock file.

## Where next

Chapter 32 gives the other side of the seam. The chapter shows how to configure
the providers and harnesses that execute an agent turn and a coercion. The
chapter covers the fixture, Claude, Codex, and each endpoint that is compatible
with OpenAI.
