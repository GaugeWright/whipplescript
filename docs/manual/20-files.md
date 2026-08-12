# Files & file stores

Chapter 11 said that the turn grants of an agent would later have true
resources to make more narrow. In chapter 19, a script read and wrote each
item that the trust of the operator permitted. This chapter puts the file
system in the usual position of the language. A **file store** is a directory
that you declare. The store has a root scope and a policy limit. A store is
never an open handle to the file system. Each file operation is a usual durable
effect with a success branch and a failure branch.

## How to declare a store

<!-- check: skip — a store shown without the `use std.files` its program carries -->
```whip
file store project_files {
  root "./data"
  allow read ["docs/**"]
  allow write ["out/**"]
}
```

The `root` clause mounts one directory. Each path in each operation is relative
to the root and stays in the root. The two `allow` lists are the policy:

- **A store is read-only by default.** The mount of the root is the consent to
  read. The `allow read [...]` list *makes more narrow* the paths that a read
  operation can touch.
- **A write operation is denied until you declare it.** The
  `allow write [...]` list permits a write operation and limits a write
  operation. If you omit the list, the checker refuses each `write` operation
  and each `export` operation in the workflow. The runtime applies the same
  denial and fails closed for each operation that the static analysis did not
  see:

```text
error: rule `ingest` writes to store `project_files`, which permits no
writes — stores are read-only by default
  = help: declare `allow write ["<glob>", …]` on `file store project_files`
    to permit (and bound) writes
```

This is the same shape as each limit in Part III. The mandatory `cap` value of
a counter and the mandatory `ttl` value of a lease are equivalents. The consent
is explicit, and the default is the most narrow value.

## The four operations

The `read`, `write`, `import`, and `export` operations are effects, as each
other effect is. Each operation enters a queue, executes durably, settles, and
branches:

```whip
use std.files

workflow Digest

output result Done
failure error Failed

class Ticket {
  id string @key
  title string
}

class Done {
  note string
}

class Failed {
  reason string
}

file store project_files {
  root "./data"
  allow read ["docs/**"]
  allow write ["out/**"]
}

rule ingest
  when started
=> {
  read text from project_files at "docs/notes.md" as notes

  after notes succeeds as loaded {
    import jsonl Ticket from project_files at "docs/tickets.jsonl" as rows

    after rows succeeds {
      write text to project_files at "out/summary.md" {
        body loaded.content
        mode create
      } as written

      after written succeeds {
        export jsonl Ticket to project_files at "out/tickets-copy.jsonl" {
          mode create
        } as exported

        after exported succeeds {
          complete result {
            note "digested"
          }
        }

        after exported fails as f {
          fail error {
            reason f.reason
          }
        }
      }

      after written fails as f {
        fail error {
          reason f.reason
        }
      }
    }

    after rows fails as f {
      fail error {
        reason f.reason
      }
    }
  }

  after notes fails as f {
    fail error {
      reason f.reason
    }
  }
}
```

Make a `data/` directory. Put a `docs/notes.md` file and a
`docs/tickets.jsonl` file with two rows in the directory. Run the program. The
chain completes. The disk then has an `out/summary.md` file and an
`out/tickets-copy.jsonl` file. The instance has two `Ticket` facts. These are
the parts:

- **The `read text from <store> at <path> as x` statement** loads one file. The
  success binding makes `result.content` and `result.bytes` available. An
  absent file is a usual failure. A path that the policy refuses is also a
  usual failure. Branch on the failure.
- **The `import <format> <Schema> from <store> at <path>` statement** decodes a
  structured file into one typed fact for each row. The formats are `jsonl`,
  `json`, and `csv`. The runtime validates each row against the schema. The
  batch is atomic. One invalid row fails the full import, and the runtime
  admits *nothing*. A field with the `@key` mark identifies a row. The
  declaration form is `id string @key`. Thus a second run of the same import is
  idempotent on that field. This behavior is the fact identity from chapter 2,
  applied to a file.
- **The `write text to <store> at <path> { body …  mode … }` statement**
  renders a body. The `mode` value is mandatory. There is no silent overwrite
  operation. The `create` mode fails when the file exists. The `replace` mode
  fails when the file does not exist. The other modes are `upsert` and
  `append`. A violation of the mode is a failure that the runtime routes to a
  branch. The violation does not change the file. The `body` value is an
  expression. The runtime resolves the expression when the effect runs. Thus a
  write operation in an `after notes succeeds as loaded` block can write
  `loaded.content`.
- **The `export <format> <Schema> to <store> at <path>` statement** is the
  inverse of the import statement. The statement serializes the facts of the
  schema deterministically. A `where` clause can filter the facts. The same
  mode policy applies.

## Files and the remainder of the system

The declaration of the store is also the item that *other constructs* make more
narrow. A turn grant from chapter 11 is
`with access to project_files { read ["docs/**"] }`. The grant gives the name
of a declared store. The grant can only make the policy of the store smaller.
The same rule applies to the start grants of an invocation from chapter 18. The
harness of an agent sees exactly the part that the grant permits. The workspace
also has its own file plane, which is the content of the store. The system
versions the file plane with the facts. The system stores the body of each
written file by its content in the same database. Thus a checkpoint in chapter
21 can rewind the files, the facts, and the effects as one coherent cut.

Note the division of the work with the file *source* in chapter 17. A
`source file` declaration **admits a signal** from a file that the external
world writes. A feed and a drop directory are examples. A `file store`
declaration **is the working tree of the workflow**. The workflow itself does
the read operations and the write operations, and the policy limits them.

## Where next

Chapter 21 gives version control. The workspace becomes a database of branches
and merges. The file plane that you wrote to in this chapter becomes
branchable, mergeable, and convergent.
