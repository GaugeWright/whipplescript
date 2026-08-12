#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

WHIP=(cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p whipplescript --)

"$ROOT/scripts/check-docs-quickstart.sh" >/dev/null
"$ROOT/scripts/check-docs-examples.sh" >/dev/null

cat > "$TMPDIR/tutorial-triage.whip" <<'WHIP'
workflow TicketTriage

use std.tracker

output result TriageDecision
failure error TriageBlocked

class Ticket {
  id string
  title string
  severity string
  status string
}

class TriagedTicket {
  id string
  title string
  severity string
  plan string
  status "triaged"
}

class TriageDecision {
  decision string
}

class TriageBlocked {
  reason string
}

class AwaitingSignoff {
  request string
}

agent triager {
  provider fixture
  profile "repo-reader"
  capacity 1
}

tracker approvals
tracker answers

table tickets as Ticket [
  {
    id "T-31"
    title "Login returns 500 on empty password"
    severity "high"
    status "open"
  }
  {
    id "T-32"
    title "Typo in footer copyright"
    severity "low"
    status "open"
  }
]

rule triage_open_ticket
  when Ticket as ticket where ticket.status == "open"
  when triager is available
=> {
  tell triager as turn """markdown
  Suggest an owner and a fix plan for this ticket:

  {{ ticket.title }} (severity: {{ ticket.severity }})
  """

  after turn succeeds as triaged {
    done ticket -> record TriagedTicket {
      id ticket.id
      title ticket.title
      severity ticket.severity
      plan triaged.summary
      status "triaged"
    }
  }

  after turn fails as oops {
    fail error {
      reason oops.reason
    }
  }
}

rule request_signoff
  when TriagedTicket as ticket where ticket.severity == "high"
=> {
  then req <- file issue into approvals {
    title "Approve the triage plan for {{ ticket.id }}?"
    body "{{ ticket.plan }}"
  }

  record AwaitingSignoff {
    request req.id
  }
}

rule approve_plan
  when AwaitingSignoff as p
  when answers has ready issue as a where a.body == p.request && a.title == "approve"
=> {
  claim a as hold

  after hold succeeds {
    then closed <- finish a {
      summary "applied"
    }
    done p
    complete result {
      decision "approve"
    }
  }

  after hold fails {
    # another claimant took this answer; wait for the next
  }
}

rule reject_plan
  when AwaitingSignoff as p
  when answers has ready issue as a where a.body == p.request && a.title == "reject"
=> {
  claim a as hold

  after hold succeeds {
    then closed <- finish a {
      summary "acknowledged"
    }
    done p
    fail error {
      reason "triage plan rejected"
    }
  }

  after hold fails {
    # another claimant took this answer; wait for the next
  }
}

assert count(Ticket where status == "open") == 0
assert count(TriagedTicket) == 2
WHIP

"${WHIP[@]}" check "$TMPDIR/tutorial-triage.whip" >/dev/null

printf 'docs snippets check passed\n'
