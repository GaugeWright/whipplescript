# Facts and types

Each item that a workflow knows is a **fact**. A fact is a typed value that the
instance holds. Rules react to facts and make new facts. The output of the full
workflow comes from facts. This chapter gives the shape of a fact (a class),
the methods that make a fact (the `record` statement and a seed table), and the
method that the instance uses to tell facts apart.

## Classes

A class declares a shape:

<!-- check: context books -->
```whip
class Book {
  title string
  pages int
}
```

Declare the type of a field after the name of the field. The scalar types are
`string`, `int`, `float`, and `bool`. A field can also hold a list
(`string[]`) or a different class:

<!-- check: in books -->
```whip
class Shelf {
  label string
  featured Book
}
```

## How to record a fact

The body of a rule makes a fact with the `record` statement. The statement
gives a value to each field:

```whip
workflow Catalog

output result Done

class Done {
  note string
}

class Book {
  title string
  pages int
}

rule begin
  when started
=> {
  record Book {
    title "Dune"
    pages 412
  }
  complete result {
    note "catalogued"
  }
}
```

Run this program and examine the instance. Chapter 1 introduced the `status`
command and the `log` command. The `facts` command completes the set. The
`facts` command lists the typed values that the instance holds:

```sh
whip run catalog.whip
whip facts ins_…
```

```text
Book  Book:07f3a1c29e44b8d2  {"pages":412,"title":"Dune"}
```

The fact is present after the run completes. The fact is typed and you can
examine it. If you record a value that does not agree with the class, the
result is an error. An absent field is one such condition. A string in the
position of an `int` field is a different such condition. In an error
condition, no operation of that rule takes effect.

To read the field of a fact, use dot notation. Chapter 4 shows how a rule gets
a `Book` fact. After the rule has the fact, `book.title` is `"Dune"`. Field
access also operates in a payload, as in `note book.title`.

## Enums

An enum declares a closed set of named values:

<!-- check: fragment -->
```whip
enum Genre {
  Fiction
  Reference
}

class Book {
  title string
  pages int
  genre Genre
}
```

A `genre` field can hold only `Fiction` or `Reference`. The compiler rejects a
different value. Use an enum when the set of values is a fixed vocabulary that
the full program uses.

A variant of an enum can also carry a typed **payload**. The payload is a body
in braces with the grammar of a class field. The payload makes the enum a *sum
type*:

<!-- check: fragment -->
```whip
enum ReviewOutcome {
  Approved { score float }
  Rejected { reason string }
  Blocked
}
```

A `ReviewOutcome` value is exactly one of the three variants. The data goes
with the variant. An `Approved` variant carries its score. A `Rejected` variant
carries its reason. A `Blocked` variant carries no data. Usually a sum value
comes from the decision of a model. A coercion in chapter 8 can return such a
value. The `case` statement in chapter 7 dispatches on the variant and binds
the payload. In JSON, the discriminant is a reserved `variant` field. If you
declare a field with the name `variant`, the check gives an error.

## Fields with a literal union

Sometimes a class has a small set of string states. In this condition, the
field can list its permitted values directly:

<!-- check: fragment -->
```whip
class Ticket {
  title string
  status "queued" | "routed"
}
```

The `status` field accepts exactly those two strings. This is the idiomatic
method to model a small state machine on a fact. The declaration shows the
states. A spelling error such as `"qeued"` is a compile error and not a silent
bug. Chapter 4 uses this pattern frequently.

## Fields that exist only for one state

A literal union names the states. Often a field belongs to just one of them: a
deploy carries a region, a rollback carries the release it reverts to. Declaring
both as ordinary fields forces every producer to supply both, and forces every
reader to guess which one is real.

A `when` clause ties a field to one value of a literal union:

<!-- check: context change -->
```whip
class Change {
  kind "deploy" | "rollback"
  region string when kind is "deploy"
  revertTo string when kind is "rollback"
}

class Deployment {
  region string
}

class Reversion {
  target string
}
```

`kind` is the discriminant. It has to be a string literal union on the same
class — an enum does not serve, because the check compares the literal text.

The clause carries two meanings. The first is admission. A `Change` whose `kind`
is `"deploy"` must carry a `region`, and one whose `kind` is `"rollback"` must
carry a `revertTo`. A missing one is a rejected fact, not an absent field later.

The second is reading. A conditional field is readable only where its
discriminant is pinned to the matching value, which means inside the matching
arm of a `case` on that discriminant:

<!-- check: in change binds change Change -->
```whip
case change.kind {
  "deploy" => {
    record Deployment {
      region change.region
    }
  }
  "rollback" => {
    record Reversion {
      target change.revertTo
    }
  }
}
```

Reading `change.region` anywhere else is a compile error, including in the
`"rollback"` arm and in a `_` arm — a `_` arm matches every remaining value, so
it pins nothing. The error names the arm to move the read into.

This is the same trade the literal union itself makes. The declaration states
which fields go together, and the compiler holds the reader to it, instead of
each rule remembering on its own.

Chapter 7 covers `case`. Chapter 3 covers optional fields, which answer a
different question: an optional field may be absent in any state, while a
conditional field is required in exactly one.

## Optional fields

A `?` symbol marks a field that can be absent:

<!-- check: context books2 -->
```whip
class Book {
  title string
  pages int
  series string?
}
```

A `record` statement can omit an optional field. Chapter 3 gives the meaning of
an absent field in a guard and in a query. Chapter 3 also shows how to test for
an absent field.

## Seed tables

To record a value that a rule computes, one `record` statement at a time is
correct. But it is better to declare source data as a **table**. A table
contains static rows. The rows are typed against a class. The instance records
the rows automatically when the instance starts:

<!-- check: in books2 -->
```whip
table books as Book [
  {
    title "Dune"
    pages 412
  }
  {
    title "A Field Guide to Moths"
    pages 214
  }
]
```

A table needs no rule. When the instance starts, each row becomes a `Book`
fact. Use a table for deterministic data that you know before the run. Examples
are the fixtures for an example program and the rows for a batch job. Data that
comes from an external source or that the program computes during the run
enters as a recorded fact instead.

## How the instance tells facts apart

The identity of a fact comes from its content. The class of the fact and the
values of its fields identify the fact. There are two results.

First, **two records of the same value give one fact**. If a table seeds
`{title "Dune", pages 412}`, and a rule later records an identical `Book` fact,
the instance holds one `Dune` fact. It does not hold two. To assert a value
that the instance knows and that is still live causes no problem. There is one
known rough edge here, and a repair is in progress. If a `done` statement
consumed a value, do not record the same value again. Treat consumed content as
absent.

Second, **facts that must exist together must be different in some field**. The
instance cannot hold two books that have identical field values apart. There is
no field that tells them apart. Usually true data has a field that makes the
difference. A title, an identifier, or a row number are examples. Give your
class such a field when more than one similar fact must exist at the same time.

```sh
whip facts ins_…
```

```text
Book  Book:07f3a1c29e44b8d2  {"pages":412,"title":"Dune"}
Book  Book:5c1d99e0b7a2f416  {"pages":214,"title":"A Field Guide to Moths"}
```

The middle column is the derived identity. The identity is the class and a hash
of the content. You never write these keys. The keys let the instance hold a
*set* of facts and not a group of duplicates.

## Where next

Chapter 3 introduces the expression language. A program uses expressions to
state a condition on the field of a fact. Chapter 3 also introduces `assert`.
An assertion changes such a condition into an executable statement about a run.
