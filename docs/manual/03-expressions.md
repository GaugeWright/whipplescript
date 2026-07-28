# Expressions and assertions

A workflow frequently states a condition on the facts. Examples are *this book
is long*, *a fiction title is present*, and *the queue is empty*. WhippleScript
has one expression language for each of these conditions. This chapter
introduces the language through `assert`. An assertion is an executable
statement about a run. You can attach an assertion to a program that you
already know how to write. Chapter 4 then uses the same expressions to control
the facts that a rule matches.

## The `assert` declaration: a statement about a run

An `assert` declaration is a top-level declaration. The `whip run` command
drives an instance until the instance becomes idle. The command then evaluates
each assertion against the run and reports the result:

```whip
workflow Catalog

output result Done

class Done {
  note string
}

class Book {
  title string
  pages int
  genre "fiction" | "reference"
  series string?
}

table books as Book [
  {
    title "Dune"
    pages 412
    genre "fiction"
    series "Dune Chronicles"
  }
  {
    title "A Field Guide to Moths"
    pages 214
    genre "reference"
  }
]

rule begin
  when started
=> {
  complete result {
    note "catalogued"
  }
}

assert count(Book where pages > 300) == 1
assert exists(Book where genre == "fiction")
assert empty(Book where pages > 1000)
```

```sh
whip run catalog.whip
```

The log of the run records `assertion.passed` or `assertion.failed` for each
statement. An assertion never changes the execution. An assertion only reads
the complete run. An assertion is the method with the least cost to record the
intended behavior of a program. The subsequent parts of this manual use
assertions in the examples.

The parts in those assertions are the expression language. The parts are the
comparisons, `count`, `exists`, and `where`. The remainder of this chapter
gives each part.

## Comparisons and arithmetic

The comparison operators are `==`, `!=`, `<`, `<=`, `>`, and `>=`. The
arithmetic operators are `+`, `-`, `*`, and `/`. An operand is the field of a
fact or a literal:

```text
pages > 300
pages + 10 <= 500
title == "Dune"
```

The comparisons are strictly typed. A number compares with a number. A string
compares with a string. A boolean compares with a boolean. There is no implicit
conversion. Thus `pages < "300"` is a compile error and not a coercion. A field
with a literal union compares against its declared literals. Thus the compiler
finds `genre == "fictoin"` as a type error. The expression does not evaluate to
false without a report.

## Boolean operators

To put conditions together, use `and`, `or`, and `not`. The language also
accepts the symbols `&&`, `||`, and `!`. In new code, use the words:

```text
pages > 300 and genre == "fiction"
not (genre == "reference")
```

The `and` operator and the `or` operator evaluate from the left to the right.
They stop when the answer becomes known.

## Membership

The `in` operator and the `not in` operator test a value against a list:

```text
genre in ["fiction", "reference"]
pages not in [0, 1]
```

## Presence: optionals, `exists`, and `empty`

An optional field such as `series string?` can be absent. The `exists` operator
tests that a value is present. The `empty(...)` function tests structural
emptiness. The function is true for an absent optional, an empty list, an empty
string, and a null value:

```text
exists series
empty(series)
series == null
```

There is one limit. The `empty(...)` function operates on a value that has
structure. Strings, lists, classes, and optionals of these types have
structure. For an optional *scalar* such as `int?`, use `exists x` or
`x == null` instead.

## Queries on the facts

The `count`, `exists`, and `empty` functions also take a class and an optional
`where` clause. In this form, the function evaluates on the facts that the
instance holds now:

```text
count(Book)
count(Book where pages > 300)
exists(Book where genre == "fiction")
empty(Book where pages > 1000)
```

In the `where` clause of a query, a field name refers directly to the class in
the query. Write `pages`. Do not write `book.pages`. There is no binding in
scope. There is only the row in the test. This is the one location where an
expression gives a field name alone.

A query operates on the facts that the instance holds now. Thus the answer of a
query can change during a run, because the program records and consumes facts.
In an `assert` declaration, a query sees the final state. In a rule, which the
next chapter gives, a query sees the state at the time of the match.

## Precedence

The precedence goes from the highest to the lowest in this sequence: field
access, index of a map or an array (`task.metadata["phase"]`), and calls; the
unary operators `not`, `exists`, and `empty`; `*` and `/`; `+` and `-`;
comparisons and membership, which are one flat level; `and`; `or`. If you are
not sure, use parentheses. The
[language reference](../language-reference.md#guards-and-expressions) gives the
full table.

## Where next

Chapter 4 uses expressions in a program. The chapter gives rules that match
facts, filter facts with a `where` clause, and rewrite facts. Rules are the
control flow of a workflow.
