# The smallest workflow

A WhippleScript program is a **workflow**. A workflow is a durable process. It
reacts to typed data until it gets to a result. This chapter shows the smallest
complete workflow. It shows how to run the workflow and how to look in a run.
Each subsequent chapter builds on the few lines that this chapter introduces.

Read this orientation before the first line of code. WhippleScript is a
**Gleam-inspired syntax on a durable, stream-backed rule engine**. It
deliberately has no arbitrary control flow. There is no `for` loop, no `while`,
and no exceptions. If you look for these constructs, the answer always has the
same shape. To branch, use `case` and pattern matching (chapter 7). To fan out,
let a rule fire one time for each matched fact (chapter 4). To make a sequence,
use a `then` chain (chapter 9). This limit is not an absent feature. This limit
lets the compiler check your orchestration and lets the runtime replay the
orchestration. The invariants of the compiler are the product.

## The program

```whip
workflow Hello

output result Done

class Done {
  message string
}

rule begin
  when started
=> {
  complete result {
    message "hello"
  }
}
```

Read the program from the top to the bottom:

- The `workflow Hello` line gives the name of the program. When you start the
  program, whip makes an **instance**. An instance is a durable run. An
  instance has its own record of each event.
- The `output result Done` line declares the data that a run supplies after
  success. The data is a value with the name `result`. The class `Done` gives
  its shape.
- The `class Done { message string }` line declares that shape. The class has
  one field with the name `message`. The field holds a string. The next chapter
  gives the full data on classes. If no other part of the program uses the
  shape, you can put the two lines together. The line
  `output result { message string }` declares the class in position.
- The `rule begin … => { … }` block is a **rule**. A rule is the unit that
  reacts and acts. This rule reacts to `started`. The `started` event starts
  each instance. This rule then completes the workflow immediately.
- The `complete result { message "hello" }` statement ends the instance with
  success. The statement supplies the declared output.

Copy this shape each time that you start a new workflow. The applicable
chapters give the full data on the parts. Chapter 2 gives the data on classes.
Chapter 4 gives the data on rules. The skeleton is always the same: a workflow,
its output contract, and a minimum of one rule that gets to an end.

## How to run the program

Save the program as `hello.whip`. Then check the program:

```sh
whip check hello.whip
```

The `check` command compiles the program and reports the problems. The command
runs no part of the program. A workflow that can never complete is an error.
Whip makes each workflow able to get to an end.

Now run the program:

```sh
whip run hello.whip
```

```text
run ins_c1f4a2…
workflow Hello
iterations 2
status completed
```

The `whip run` command starts an instance. The command drives the instance
until no work stays. Whip keeps the run in a `.whipplescript/` directory
adjacent to your program. The run contains each event and each item that the
instance knows. Thus the commands below can examine a run after the run
completes.

## How to look in a run

Each instance keeps a full record. Two commands answer the largest part of the
questions. Each command takes the instance identifier that the `run` command
printed:

```sh
whip status ins_c1f4a2…
whip log    ins_c1f4a2…
```

The `status` command shows the condition of the instance. It gives the
lifecycle state (`running`, `completed`, or `failed`), the terminal if the
instance got to one, and a summary of the pending work:

```text
instance ins_c1f4a2… completed
workflow terminal: completed result
```

The `log` command gives the history of the events in sequence. For the program
above, the history has three lines: the start, one rule that fires, and the
completion:

```text
#0001 … external.started   source=external
#0002 … rule.committed     source=kernel
#0003 … workflow.completed source=kernel
```

This check, run, and examine loop is the usual rhythm for each subject in this
manual. When an example tells you to run the program and look at the log, use
this loop.

## Where next

Chapter 2 introduces the data model. It gives classes, the types of a field,
and facts. A fact is a typed value that a workflow holds while the workflow
runs. Chapter 2 also gives the command that examines the facts. A workflow can
also *fail* deliberately with a declared error payload. Error handling has its
own chapter, after this manual introduces effects.
