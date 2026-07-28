# Contributing

WhippleScript is open source, but not open contribution. Issues are welcome
from anyone; code is written by the maintainer and a small set of invited
contributors.

This is a deliberate trade. The codebase carries a lot of context that is not
visible in any single diff — formal models, information-flow discipline,
design records, and gate scripts that encode invariants the code alone does
not state. Reviewing a change from someone without that context usually costs
more than making the change directly, so review bandwidth is spent where it
goes furthest.

## What is welcome from everyone

**Bug reports and questions.** Open an issue. A good report includes the
`.whip` source (or a minimal reduction), the command you ran, what you
expected, and what happened. `whip --version` output helps.

**Diagnoses and proposed solutions.** This is the most valuable thing an
outside contributor can do. If you have dug into a bug and understand *why*
it happens — the mechanism, not just the symptom — write that up as a comment
on the issue: the root cause, the code paths involved, and how you would fix
it. A clear diagnosis is reviewable in minutes, carries no merge burden, and
can be turned into a landed fix quickly. It is worth far more than an
unsolicited patch.

When a fix lands based on your diagnosis, you are credited in the commit
(`Co-authored-by:` or a `Diagnosis-by:` line referencing the issue).

**Design discussion.** Comments on issues about language design, semantics,
or tooling are welcome, especially when grounded in a concrete use.

## What is not accepted

**Unsolicited pull requests.** PRs from outside the invited contributor set
are closed, regardless of quality. This is not a judgment of your work — it
is a statement about where review time goes. If you have a fix, post the
diagnosis on an issue instead; that path actually gets your insight into the
project.

## Becoming a contributor

Contributor access is by invitation, and invitations come out of
conversation, not cold patches. Engage with the project: file good issues,
write diagnoses, take part in design discussion. People who have shown they
understand how the project fits together get invited to contribute code
directly.

## For invited contributors

The workspace is plain Cargo:

```text
crates/whipplescript-core     shared types and contracts
crates/whipplescript-parser   .whip parser and typed IR
crates/whipplescript-store    SQLite-backed runtime store
crates/whipplescript-kernel   deterministic rule/effect kernel
crates/whipplescript-cli      the whip CLI
crates/whipplescript-host-do  Cloudflare Durable Object cloud host
docs/                         user documentation
spec/                         design records and implementation trackers
models/                       formal models (Maude, TLA+)
```

Before sending changes:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`scripts/check-release-readiness.sh` is the authoritative aggregate gate.
Significant changes should be discussed before implementation; design records
live in `spec/`.

## Licensing

WhippleScript is dual-licensed under [Apache-2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT), at your option. Unless you explicitly state otherwise,
any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual-licensed as above, without
any additional terms or conditions. There is no CLA.

The same applies to written material: per Apache-2.0 §5 and the [GitHub Terms
of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service#6-contributions-under-repository-license),
a diagnosis or proposed solution posted on an issue is contributed under the
project license, which is what allows a fix to be implemented directly from
your writeup.
