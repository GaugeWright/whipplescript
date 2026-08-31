# Programs the documentation renders a diagnostic from

Every `error[code]: …` / `warning[code]: …` block printed in `docs/` is generated
from a program by `scripts/regen-docs-diagnostics.sh`, and the page names its
source in a `<!-- render: … -->` comment beside the sample. Most of those sources
already existed: the diagnostics guide renders from the `examples/invalid/`
fixture its own prose names, and the information-flow chapters render from
`examples/infoflow/`.

This directory holds the remainder — a program that exists nowhere else because
the page is showing what its own example does once you break it the way the page
says to ("delete the `Reference` arm", "delete the `after attempt fails`
branch"). Each file is that chapter's program, in that broken state, under that
chapter's names, so the prose around the sample stays true.

They are not under `examples/invalid/` for two reasons. Half of them are accepted
programs — a `warning` is not a refusal, and `whip check` exits 0 — while every
fixture under `examples/invalid/` must be refused, which its gate asserts on the
exit status. And these exist to serve a page rather than to pin a refusal: the
refusal corpus should be readable as the corpus, not as a mix.

The guard is not weaker for it. The sample's directive names the code it renders,
and a program that stops emitting that code fails
`scripts/regen-docs-diagnostics.sh --check` by name — which is a sharper
statement than an exit status, and the only one available for a warning.

To change one: edit the program, run `scripts/regen-docs-diagnostics.sh`, and the
pages that render from it are rewritten. Never edit a rendered sample by hand.
