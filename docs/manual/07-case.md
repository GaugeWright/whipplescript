# Branching with `case`

A guard decides *if* a rule fires. A `case` statement decides *which path* a
body takes. The statement branches on a value that has a closed set of
possibilities. The value can be an enum, a literal union, a `bool`, an
optional, or the outcome of an effect. A `_` wildcard arm can close each of
these sets. The closed set is the important property. The compiler knows each
possibility. The compiler then makes sure that you handled each one.

## How to branch on data

Chapter 2 introduced an enum and a field with a literal union. A body uses a
`case` statement to branch on one of these:

```whip
workflow Sorter

output result Done

class Done {
  note string
}

enum Genre {
  Fiction
  Reference
}

class Book {
  title string
  genre Genre
  format "print" | "ebook"
}

class Shelved {
  title string
  shelf string
}

table books as Book [
  {
    title "Dune"
    genre Fiction
    format "print"
  }
]

rule shelve
  when Book as b
=> {
  case b.genre {
    Fiction => {
      record Shelved { title b.title shelf "novels" }
    }
    Reference => {
      record Shelved { title b.title shelf "desk" }
    }
  }
}

rule finish
  when Shelved as s
=> {
  complete result { note s.shelf }
}
```

A field with a literal union operates in the same manner. The patterns are
strings:

<!-- check: skip — a `case` arm; its binding comes from the surrounding rule -->
```whip
case b.format {
  "print" => { record Shelved { title b.title shelf "stacks" } }
  "ebook" => { record Shelved { title b.title shelf "devices" } }
}
```

A `bool` value branches on the literals `true` and `false`.

## The compiler checks exhaustiveness

Delete the `Reference` arm. The `check` command then refuses the program:

```text
error: rule `shelve` has non-exhaustive case; missing Reference
```

This behavior is the practical value of a closed set. If a person adds a new
variant to `Genre` in the subsequent month, each `case` statement that does not
handle the variant becomes a compile error. The error points at itself. Thus
the change cannot go through a branch that no person examined. A guard gives no
such guarantee. A chain of guarded rules that covers each genre is complete
only until a person adds a genre.

The compiler rejects a `case` statement on a plain `string` for the equivalent
reason. Nothing limits the possibilities of a string. Thus exhaustiveness would
have no meaning. Use a guard for a value with no limit.

## How to branch on a sum type

The enums with a payload in chapter 2 exist for the `case` statement. The
variant is the value in the test. The `as` keyword binds the payload:

<!-- check: skip — an `after` block; its effect is in the surrounding rule -->
```whip
after verdict succeeds as outcome {
  case outcome {
    Approved as a => {
      complete result { note "approved at {{ a.score }}" }
    }
    Rejected as r => {
      fail error { reason r.reason }
    }
    Blocked => {
      fail error { reason "blocked" }
    }
  }
}
```

Access to the payload exists only in the arm that proved the variant. Thus
`a.score` cannot enter the `Rejected` arm. Exhaustiveness applies here also.
The `_` arm can close the set. Usually a sum value comes from a coercion.
Chapter 8 gives coercions. In a test, the fixture returns the first declared
variant. The `--variant <name>` flag selects a different arm.

## How to branch on the outcome of an effect

The previous chapter gave `after x completes` as the predicate that ignores the
outcome. With a `case` statement, the predicate becomes exhaustive. The outcome
of an effect is also a closed set. The members are `Completed`, `Failed`,
`TimedOut`, and `Cancelled`. A `case` statement branches on the set:

```whip
use std.script

workflow Runner

output result Done

class Done {
  branch string
}

rule begin
  when started
=> {
  exec "true" as attempt

  after attempt completes {
    case attempt {
      Completed as ok => {
        complete result { branch "completed" }
      }
      Failed as f => {
        complete result { branch f.reason }
      }
      TimedOut as t => {
        complete result { branch "timed out" }
      }
      Cancelled as c => {
        complete result { branch "cancelled" }
      }
    }
  }
}
```

Each arm gives an outcome and binds the outcome. The `as` keyword is necessary.
The binding carries the data of that outcome. A `Failed as f` arm reads the
same failure base as an `after x fails as f` clause. Thus `f.reason` here is
the exit message. The same exhaustiveness rule applies. An outcome with no
handler is a compile error. Thus this shape is correct for an effect where
*each* end needs a deliberate answer. This is the discipline that the chapter
on error handling asked for. The checker applies the discipline. A review by a
person is not necessary.

Select between the two styles by your intent. Use `after x succeeds` and
`after x fails` when the two paths are truly separate progressions. Use
`after x completes` and a `case` statement when the outcomes are variations of
one decision.

## Where next

Chapter 8 makes the first call to a model. The chapter gives prompts and the
`coerce` statement. A `coerce` statement changes the judgment of a model into a
typed value. That value then supplies the branches that this chapter taught.
