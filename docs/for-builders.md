# Build your own automations

You do not write code. You describe the work that you want. An agent writes the
workflow. WhippleScript makes sure that the workflow is safe to run.

This is the part that is new. Until now, an agent could write you an automation,
but nobody could tell if the automation was safe. Thus your IT department said
no. WhippleScript answers that question with a compiler. Your IT department can
now say yes.

## Three examples

**Support triage.** A customer sends an email. An agent reads the email, finds
the customer record, and writes a reply. The reply waits for you. You approve it
from your phone. The agent sends the reply.

**A weekly report.** Each Monday, an agent collects the numbers from your
systems. The agent writes the summary. The agent files the summary for your
review. If a number looks wrong, the agent asks you before it sends the report.

**An assistant that keeps working.** An agent does one small useful task, then
looks for the next one, then does that task. It runs for weeks. It remembers
what it did last time. The core of that loop is 24 lines
([`examples/ralph.whip`](https://github.com/GaugeWright/whipplescript/blob/main/examples/ralph.whip)).

## What the automation does that a script cannot

**It waits.** A workflow can wait four days for your approval. It uses no
computer while it waits. It continues at the exact step where it stopped.

**It survives.** The machine can restart. The network can fail. The workflow
keeps its place, because each step is on durable record before it runs.

**It does each paid action one time.** If a step runs again after a failure, the
system knows that the action already occurred. The customer gets one email, not
four.

**It has a way to stop.** The compiler refuses to build a workflow with no path
to an end. A workflow that runs continuously by design must say so, and an agent
that starts other agents cannot start a chain that never returns.

**It cannot leak.** Your IT department sets the rules one time, for the whole
company. The compiler applies the rules to each workflow that anybody writes.
An agent cannot write a workflow that breaks them. It cannot even build one.

## How you start

Use **GaugeDesk**. GaugeDesk is the workbench for WhippleScript. It gives you a
chat window, an agent, and a record of the work. WhippleScript runs below it as
the governed engine. You install nothing.

[Start in GaugeDesk](https://gaugewright.com/gaugedesk/)

Tell the agent what you want in your own words. The agent writes the workflow
and runs it against a test provider first. You see the result before the
workflow touches a real system.

## How you bring this to your organization

Two objections stop most automation projects. This page answers the first one.
Send the second one to the person who approves your tools:

[For IT and data owners](for-it.md)

That page is short. It states what the compiler refuses to build, and it names
the evidence for each refusal.

## Next

- [Quickstart](quickstart.md) — run a workflow on your own machine in five
  minutes. You need no credentials.
- [Tutorials](tutorials/index.md) — three guided builds. Start with the root
  agent.
- [Examples](examples.md) — the catalog of workflows that CI checks.
