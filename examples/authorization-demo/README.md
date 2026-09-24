# The authorization demo

The first admission loop of the norm plane, as a workspace
([the admission fixture](../../spec/norm-plane-admission-fixtures.md)). An
owner `O` and a worker `W`, one requirement, one four-case check, one
exclusive reservation, and a gated mainline.

- `src/auth.py` is the subject of `custody-authorization`: an owner is always
  authorized, and anyone else only under an allowing grant. It calls
  `src/parser.py` to read the grant, so the requirement depends on a file
  beyond its subject.
- `checks/q0.json` is Q0, the check: the function it calls and its four cases,
  owner/worker by allow/deny. A requirement installs it as its support
  contract over the host's pinned protected runtime.
- `charter.json` is C0. It declares `requirement`, `decision`,
  `observation`, the kernel's `local-observation`, the `incorporates` and
  `supports` relations as the engineering charter does, and a `reservation`
  that only the owner's `reservation.grant` authority grants, releases or
  expires. Its `authorization` domain is `src`, `checks` and `config`.

## The loop

```sh
whip norm bootstrap --as <owner> --creator <worker> --charter examples/authorization-demo/charter.json
whip norm create requirement@1 --as <owner> --fields r0.json      # support_contract: Q0
whip norm transition <R0> accepted --as <owner>
whip norm create decision@1 --as <worker> --fields d0.json
whip norm transition <D0> accepted --as <owner>                   # W's acceptance is refused
whip norm create incorporates@1 --as <owner> --fields fold.json \
  --family-basis <basis> --references <D0-revision>,<R0-revision>
whip norm create reservation@1 --as <worker> --fields claim.json  # src/**, exclusive
whip norm transition <claim> granted --as <owner>                 # its event id is the token
whip stream promote work --token <token>
```

Bootstrapping the ledger leases the mainline to its gate, so from then on
`main` moves only through a door: `stream promote`, `branch transport …
--onto main`, `merge`, `restore`, `undo` and `undo-op`. Each door judges the
exact result `main` would hold. It admits only when every gated requirement
is supported there by verified published evidence and every exclusive
reservation that result touches is presented with its current token. A
refusal names the requirement and the work its support needs, or the
reservation and why.

`the_authorization_demo_repairs_a_violated_requirement_under_a_current_token`
runs this loop natively. W's stream edits only the parser, and support at
the first result does not carry to it. Q0 then finds the `worker-deny`
counterexample, and promotion is refused naming the requirement. W repairs
the parser, and fresh support admits the repair under the current token,
after an expired one is refused. The folding and the first support stay in
the ledger's history throughout. Its evidence is supplied executor receipts
recovered through the verified publication path, not a physical run of
Q0.
