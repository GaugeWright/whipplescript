# Messaging & ingress

To this point, the workspace made each fact. Rules recorded facts. Tables
seeded facts. Trackers projected facts. But a true workflow speaks to a world
that did not agree to use whip. That world has persons in chat rooms, feeds,
files that other systems put in a directory, and adjacent instances. This
chapter opens the two doors. In the outbound direction, a **channel** carries a
message to a communication platform. In the inbound direction, a **signal** is
the one point of admission. Each external item becomes a durable typed fact
through a signal. A **source** makes the admission automatic.

## Channels: the outbound door

```whip
use std.messaging

workflow Notify

output result Done
failure error Failed

class Ticket {
  id string
}

class Done {
  note string
}

class Failed {
  reason string
}

channel release_room

table tickets as Ticket [
  {
    id "T-1"
  }
]

rule notify
  when Ticket as ticket
=> {
  send via release_room {
    text "Ticket {{ ticket.id }} needs triage."
  } as sent

  after sent succeeds as receipt {
    complete result {
      note receipt.message_id
    }
  }

  after sent fails {
    fail error {
      reason "send failed"
    }
  }
}
```

A bare `channel release_room` declaration makes a named route with the `local`
provider. The `local` provider is a mailbox in a file adjacent to the store.
The provider is correct for development. The provider of a channel is
*configuration and not code*. This is the same rule as for the provider of an
agent. The block form selects `desktop`, which gives a native notification. The
block form can also select `stdio` or `fixture`. The block form also takes an
optional `workspace` configuration and an optional `destination` configuration.
A change of the provider changes no rule. A credential is always a reference in
the configuration of the provider. A credential is never a literal in the
source.

The `send via <channel> { text … }` statement is a usual effect. It is durable,
you can branch on it, and it is idempotent. Its success binding is a typed
receipt. The receipt has the fields `message_id`, `provider`, `status`, and
`thread_id`. The `message_id` field is stable across a replay. A send that
fails is not a receipt. Such a send goes to the `after sent fails` branch, as
each failure in chapter 6 does. The `markdown` field and the `thread_id` field
are optional. The `text` field is necessary. Examine the local deliveries:

```sh
whip mailbox outbound
```

```text
key_a7e6b455…	release_room	2026-07-22T02:24:57Z	Ticket T-1 needs triage.
```

## Inbound messages

A provider that operates in the two directions also *receives*. An inbound
message never arrives as a domain type. An inbound message is always the
built-in generic `Message` envelope. The envelope has the fields `message_id`,
`channel`, `sender`, `text`, `markdown`, `thread_id`, and `attachments`. A rule
matches the envelope with a readiness form from the family in chapter 12:

```whip
use std.messaging

@service
workflow Helpdesk

class Seen {
  text string
  sender string
}

channel support

rule react
  when message from support as msg
=> {
  record Seen {
    text msg.text
    sender msg.sender
  }
}
```

During development, inject a message from the shell. The rule then fires:

```sh
whip message ins_4fc608… --channel support --text "printer on fire" --by "sam" --program helpdesk.whip
```

```text
delivered message on `support` to ins_4fc608… at event #3
```

Two limits are deliberate. First, the envelope stays *generic*. To change prose
into a typed decision, use an explicit step: a `coerce` statement from chapter
8 on `msg.text`. The runtime never parses the prose implicitly. Second, the
compiler checks the capability statically. A `when message from` clause on a
`desktop` channel is a compile error. The capability report of that provider
says that the provider is outbound only.

## Asking a person

There is no construct that stops a turn to wait for someone. `ask_human` was
removed in 0.3.0 (DR-0050) because it fused two separate things — communication
and control flow — and named neither the party nor the channel.

Use the two constructs that do. Send on a channel when you want to *tell* or
*ask* someone something, and let a `when message from` rule react to the reply.
File an issue into a tracker (chapter 15) when you want someone to *do* work;
its assignee names who should act and its claim decides who does.

Either way the turn settles. The reply arrives later and fires a rule of its
own, so the workflow survives a restart as durable rows rather than as a held
conversation.

## Signals: the door for admission

Chapter 10 introduced the `signal` declaration in its most simple form, for a
clock tick. This section gives the full data. A `signal <dotted.name> { fields }`
declaration declares the *only* method that changes external data into a fact.
The signal has a typed payload. The runtime validates the payload at the
boundary. The runtime then admits the payload as a durable fact. A rule matches
the fact by the dotted name.

```whip
use std.ingress

@service
workflow Deploys

class Landed {
  service string
  status string
}

signal deploy.finished {
  service string
  status string
}

rule land
  when deploy.finished as d
=> {
  record Landed {
    service d.service
    status d.status
  }
}
```

The door for an operator is the `whip signal` command:

```sh
whip signal ins_6b4a41… --name deploy.finished --data '{"service":"api","status":"ok"}' --program deploys.whip
```

```text
signaled ins_6b4a41… with `deploy.finished` at event #2
```

The runtime rejects a payload with an incorrect form *at this boundary*. Thus a
fact with an incorrect type can never enter. A delivery is idempotent. The
`--delivery-id <id>` flag keys the admission. The same identifier two times
admits one fact. This behavior continues across a restart of the process.
Without the flag, a derived hash of the payload removes the duplicates from a
retry. For ingestion from a script, use the `whip ingress serve --stdio`
command. The command reads JSONL envelopes through the same door. Remember the
set semantics from chapter 2. Two admissions with *identical content* become
one fact. For more than one fact, add a field that makes a difference. An
identifier of the occurrence and a timestamp are examples.

## Peer signals: an instance that speaks to an instance

A signal also travels *between* instances in the same store. The injection is
an effect:

```whip
use std.ingress

workflow Bridge

output result Done
failure error Failed

class Done {
  note string
}

class Failed {
  reason string
}

signal peer.registered {
  target string
}

signal deploy.finished {
  service string
  status string
}

rule forward
  when peer.registered as reg
=> {
  emit signal deploy.finished to reg.target {
    service "api"
    status "ok"
  } as sent

  after sent succeeds {
    complete result {
      note "forwarded"
    }
  }

  after sent fails {
    fail error {
      reason "peer missing"
    }
  }
}
```

The `emit signal <name> to <target> { … }` statement delivers a declared signal
to an instance. The `<target>` value holds the identifier of that instance. On
the peer instance, the signal arrives exactly as a `whip signal` command
delivers a signal. The runtime validates the signal, removes duplicates, and
matches the signal by its dotted name. An absent target is a usual failure of
an effect. Note the source of the identifier. The runtime makes an instance
identifier at the time of the `run` command. Thus a true peer identifier always
arrives *as data*. The data can be a registration signal, as in this example. As
alternatives, the data can be a recorded fact or an issue in a tracker. The
identifier is never a literal in the source.

## Sources: automatic admission

A `source` block changes an external feed into signal admissions. An operator
is not necessary. The clock in chapter 10 was the first source. The `file`
source and the `http` source complete the built-in set. The three sources share
the same guarantee: **admission a maximum of one time**. The key is the unit of
input.

```whip
use std.ingress

@service
workflow Feed

class FedLine {
  text string
  index int
}

signal ingress.fed {
  text string
  index int
}

source file as inbox {
  path "./inbox.txt"

  observe as obs
  emit ingress.fed {
    text obs.line
    index obs.line_index
  }
}

rule record_line
  when ingress.fed as f
=> {
  record FedLine {
    text f.text
    index f.index
  }
}
```

A `file` source admits one signal for each line that is not empty. Its record
of the observation binds `{ line, line_index, path }`. The `observe` clause and
the `emit` clause map the observation onto the signal. This is the same
behavior as the clock source. Run the program against a file with two lines.
Two `FedLine` facts arrive. Add a third line to the file and drive the instance
again. The runtime admits exactly one more fact. A second read of a file that
becomes larger admits only the new data, because the line index keys the
admission. The `watch "<dir>/*.ext"` variant is different. It admits one signal
for each occurrence of a file, and the key is the path and the hash of the
content. An `http` source does a GET operation on a URL that returns a JSON
array. The source then admits one signal for each element. In each condition,
the source only *admits* a durable signal fact. The rules do each reaction.

## Where next

Signals, channels, and trackers connect a workflow to the world in the
horizontal direction. Chapter 18 connects workflows to each other in the
vertical direction. The `invoke` statement starts a child workflow and reacts
to its outcome. The `pattern` construct and the `include` construct reuse
source across programs.
