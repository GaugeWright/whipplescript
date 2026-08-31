#!/usr/bin/env bash
# Regenerate — or check — the rendered diagnostic samples printed in docs/.
#
#   scripts/regen-docs-diagnostics.sh          rewrite every rendered sample in
#                                              docs/ from the program it names
#   scripts/regen-docs-diagnostics.sh --check  fail (exit 1) if any sample is
#                                              stale, naming the page, the line,
#                                              and the command that fixes it
#
# WHY. The documentation prints about two dozen blocks of compiler output —
# `error[code]: …` with its `-->` line, gutter, caret, `= note:` and `= help:`.
# Nothing checked one of them against the compiler. When the rendering shape
# changed (the diagnostic-quality tracker's D3, which put a stable code in every
# head line), every sample in the corpus went stale at once and was corrected BY
# HAND, page by page — which is the same position, one wording change later.
# `examples/invalid/*.diagnostics` had exactly this shape until it was gated, and
# seven of its fifteen snapshots had rotted by the time anyone read them.
#
# So a rendered sample is now GENERATED from a program, the same way an IR golden
# is, and the page is the file the generator writes into.
#
# WHAT COUNTS AS A SAMPLE, and this is the guard rather than the mechanism: any
# fenced block in docs/ carrying a line that starts `error[<code>]:` or
# `warning[<code>]:`. That is the compiler's own rendering, so a block shaped like
# one either came out of the compiler or is claiming to have. Such a block MUST
# carry a directive; an undirected one fails this check, naming the page and the
# line. A sample nobody can regenerate is therefore impossible to add.
#
# INDENTED FENCES COUNT. The first version of this check anchored its fence and
# head regexes at column 0, so a fenced block indented under a list item — the
# ordinary markdown shape — was invisible to it: the same fabricated sample was
# caught at column 0 and passed silently one list level in. A gate with a blind
# spot in a common markdown shape is the defect this check exists to remove, so
# the fence's own indent is captured, the body is measured with that indent
# removed, and a regenerated sample is written back WITH it (closing fence
# included) so the block stays inside the item it belongs to.
#
# HOW MANY SAMPLES EACH PAGE CARRIES is pinned in `EXPECTED` below, for the same
# reason check-docs-fences.sh pins its own counts: detection reads the page, so
# anything that stops a block LOOKING like a sample drops it out of the set and
# a gate that only reports failures stays green. The indent blind spot was
# exactly that failure. A page that carries fewer samples than recorded is an
# error, and carrying more is a deliberate edit to this script.
#
# THE DIRECTIVE is an HTML comment on the line before the fence. It renders as
# nothing and it is greppable — the same shape check-docs-fences.sh uses for the
# ```whip fences beside these samples:
#
#   <!-- render: <program.whip> [envelope <policy>] [code <code>]… -->
#   <!-- render: skip — <reason> -->
#
# `<program.whip>` is a repo-relative path. It is never a copy of a program the
# repository already has: nine samples in the diagnostics guide render from the
# `examples/invalid/` fixture the guide already names in its prose, and the
# information-flow samples render from `examples/infoflow/`. A sample whose
# program exists nowhere else — a manual chapter showing what its own program
# does once you break it the way the chapter says to — gets a companion under
# `examples/diagnostics/`, which is where those live and the only thing they are
# for.
#
# `code <code>` selects the diagnostic blocks with that code, in the order the
# codes are given; repeat it for a sample that shows several. A `code` that the
# program no longer emits is an ERROR, not an empty sample: that is what makes a
# companion program a regression fixture rather than a decoration. It is the same
# guard regen-invalid-diagnostics.sh gets from its exit-status check, and it
# reaches further, because a program that only WARNS still exits 0.
#
# WITH NO `code` the sample is the run's WHOLE stderr, verbatim — not just its
# diagnostic blocks. The two are the same thing for most programs and are not the
# same thing under an IFC envelope, where `whip check` prints the guarantee
# report ahead of the diagnostics: block selection dropped everything before the
# first head line, so the governance tutorial's sample silently lost the
# `violations caught in this program: 2` line the page teaches a section about.
# "Whole output" now means whole output, and a page that wants only one
# diagnostic says `code`.
#
# `envelope <policy>` sets WHIPPLESCRIPT_IFC_ENVELOPE for the run. The
# information-flow chapters need it: an ungoverned check makes no IFC claim at
# all, so without an envelope those pages would be documenting silence.
#
# `skip` requires a reason after an em dash, and skips are COUNTED and printed on
# every run — an exemption is meant to be visible and countable, not silent. The
# only honest reason is that the sample illustrates a SHAPE rather than a
# specific program's output.
#
# WHAT IS RENDERED is the program's stderr. `whip check` puts BOTH its
# diagnostics and its information-flow guarantee report there; stdout is the IR
# dump, which is a different artifact with a different gate and is never part of
# a diagnostic sample. (An earlier note here said the guarantee report was on
# stdout. It is not — measured, not read: `whip check` under an envelope writes
# an empty stdout for a refused program and the whole report to stderr.)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Every `-->` line inside a sample is the path handed to the binary, so the run
# has to happen from the repository root with a repo-relative argument. Anything
# else bakes this checkout's absolute path into a committed page.
cd "$ROOT"

# Build first, then invoke the built binary directly: a "Compiling …" or
# "Blocking waiting for file lock" line on cargo's stderr would otherwise land
# inside a page, because stderr is exactly the channel being captured.
cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p whipplescript --bin whip
WHIP="${CARGO_TARGET_DIR:-$ROOT/target}/debug/whip"
if [[ ! -x "$WHIP" ]]; then
  echo "no whip binary at $WHIP after a successful build" >&2
  exit 1
fi

# Write mode REWRITES every sample, so an unrecognized argument must not fall
# through to it: a typo in a future gate wiring (`--chek`) would otherwise turn
# this gate into a blesser that rewrites every page and exits 0.
mode="write"
case "${1:-}" in
  "") ;;
  --check) mode="check" ;;
  *)
    echo "usage: scripts/regen-docs-diagnostics.sh [--check]" >&2
    exit 2
    ;;
esac
if [[ $# -gt 1 ]]; then
  echo "usage: scripts/regen-docs-diagnostics.sh [--check]" >&2
  exit 2
fi

# `docs/**/*.md` is walked in the shell's collation order, which LC_ALL pins, so
# two machines visit the same pages in the same order.
export LC_ALL=C

WHIP="$WHIP" MODE="$mode" python3 - <<'PY'
import os
import pathlib
import re
import subprocess
import sys

WHIP = os.environ["WHIP"]
MODE = os.environ["MODE"]

# The fence, its own indent, and its body — so a directive can be read from the
# line before it and a regenerated sample can be written back under the same
# indent. Anchoring the fence at column 0 (which this did) hid every block
# indented under a list item, which is the ordinary markdown shape for a sample
# that belongs to a list step.
FENCE = re.compile(
    r"(?m)^(?P<indent>[ \t]*)```[A-Za-z0-9_-]*[ \t]*\n"
    r"(?P<body>.*?)"
    r"^[ \t]*```[ \t]*$",
    re.S,
)
DIRECTIVE = re.compile(r"<!--\s*render:\s*(.*?)\s*-->\s*$")
# The compiler's own head line. Severity, code in brackets, colon. This is the
# detector, so it is deliberately the rendering itself rather than a list of
# pages or a list of codes.
HEAD = re.compile(r"^(error|warning)\[([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)\]:")
# The same head, allowed to sit under leading whitespace. `blocks()` splits the
# compiler's own output, which is never indented, so it keeps the strict HEAD;
# DETECTION runs over a page, where the block may be indented under a list item
# and where a residual indent must never buy a sample an exemption.
SAMPLE_HEAD = re.compile(
    r"^[ \t]*(?:error|warning)\[[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\]:"
)

# HOW MANY SAMPLES EACH PAGE CARRIES. See the header: detection reads the page,
# so a sample that stops being DETECTED leaves the set silently and a gate that
# only reports failures stays green. That is exactly how the column-0 fence
# regex hid every indented block. Compared after the run: fewer than recorded is
# an error, more is a deliberate edit here.
EXPECTED = {
    "docs/diagnostics.md": 10,
    "docs/manual/06-error-handling.md": 1,
    "docs/manual/07-case.md": 1,
    "docs/manual/13-agent-patterns.md": 1,
    "docs/manual/14-coordination.md": 3,
    "docs/manual/16-progressions.md": 2,
    "docs/manual/20-files.md": 1,
    "docs/manual/22-infoflow-labels.md": 1,
    "docs/manual/23-infoflow-egress.md": 2,
    "docs/troubleshooting.md": 2,
    "docs/tutorials/build-a-workflow.md": 1,
    "docs/tutorials/governance.md": 1,
}

failures = []
generated = 0
exempt = []
per_page = {}
rendered_cache = {}


def strip_indent(body, indent):
    """`body` with the fence's own indent removed from each line it starts."""
    if not indent:
        return body
    return "\n".join(
        line[len(indent):] if line.startswith(indent) else line
        for line in body.split("\n")
    )


def apply_indent(text, indent):
    """`text` written back under the fence's indent; blank lines stay blank.

    A blank line must not gain trailing whitespace: the rendered output already
    has none, and a regenerated sample that adds some would be a diff every
    whitespace linter reopens.
    """
    if not indent:
        return text
    return "".join(
        (indent + line if line.strip() else line) + "\n"
        for line in text.split("\n")[:-1]
    )


def render(program, envelope):
    """The diagnostic output of `whip check <program>`, as a list of lines."""
    key = (program, envelope)
    if key in rendered_cache:
        return rendered_cache[key]
    env = dict(os.environ)
    if envelope:
        env["WHIPPLESCRIPT_IFC_ENVELOPE"] = envelope
    else:
        env.pop("WHIPPLESCRIPT_IFC_ENVELOPE", None)
    proc = subprocess.run(
        [WHIP, "check", program],
        capture_output=True,
        text=True,
        env=env,
    )
    # stdout is the IR dump; stderr carries the diagnostics AND, under an IFC
    # envelope, the guarantee report that precedes them. The exit status is NOT
    # the signal here: a program whose documented diagnostic is a warning exits
    # 0, and the `code` selector below is the real guard.
    lines = proc.stderr.rstrip("\n").split("\n") if proc.stderr.strip() else []
    rendered_cache[key] = lines
    return lines


def blocks(lines):
    """Split rendered output into (code, block-lines) pairs.

    A block runs from one head line to the line before the next one. Anything
    before the first head line is not a diagnostic and is dropped.
    """
    out = []
    for line in lines:
        head = HEAD.match(line)
        if head:
            out.append((head.group(2), [line]))
        elif out:
            out[-1][1].append(line)
    return out


def parse(spec, where):
    """Parse a render directive into (skip_reason, program, envelope, codes)."""
    tokens = spec.split()
    if not tokens:
        failures.append(f"{where}: empty `render:` directive")
        return None
    if tokens[0] == "skip":
        rest = spec[len("skip"):].strip()
        # An em dash, exactly as check-docs-fences.sh requires of its own skips.
        # A reason that is not there cannot be weighed.
        if not rest.startswith("—") or not rest[1:].strip():
            failures.append(
                f"{where}: `render: skip` needs a reason after an em dash, "
                "e.g. `<!-- render: skip — illustrates the shape, not one "
                "program's output -->`"
            )
            return None
        return (rest[1:].strip(), None, None, [])
    program = tokens[0]
    if not program.endswith(".whip"):
        failures.append(
            f"{where}: `render: {program}` is not a .whip path; the source of a "
            "rendered sample is the program it comes out of"
        )
        return None
    envelope = None
    codes = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "code" and index + 1 < len(tokens):
            codes.append(tokens[index + 1])
            index += 2
        elif token == "envelope" and index + 1 < len(tokens):
            envelope = tokens[index + 1]
            index += 2
        else:
            failures.append(
                f"{where}: unknown `render:` token `{token}` "
                "(expected `code <code>` or `envelope <policy>`)"
            )
            return None
    return (None, program, envelope, codes)


for page in sorted(pathlib.Path("docs").rglob("*.md")):
    text = page.read_text()
    edits = []
    for match in FENCE.finditer(text):
        indent = match.group("indent")
        raw_body = match.group("body")
        # Everything downstream works in the sample's own coordinates: the
        # rendered output has no indent, so the block is measured with the
        # fence's indent removed and written back with it restored.
        body = strip_indent(raw_body, indent)
        line_no = text[: match.start()].count("\n") + 1
        where = f"{page}:{line_no}"

        # The directive sits on the line before the fence opener. `search` rather
        # than `match`, so the comment may carry the list item's indent too.
        before = text[: match.start()].rstrip("\n")
        previous = before.rsplit("\n", 1)[-1] if before else ""
        directive_match = DIRECTIVE.search(previous)

        # Detection reads the RAW body under the indent-tolerant head: a sample
        # whose lines are indented differently from its fence is still a sample,
        # and must not slip past the directive requirement.
        is_sample = any(SAMPLE_HEAD.match(line) for line in raw_body.split("\n"))

        if not is_sample:
            if directive_match:
                failures.append(
                    f"{where}: a `render:` directive on a block that is not a "
                    "rendered diagnostic — remove it, or the directive is "
                    "describing nothing"
                )
            continue

        if not directive_match:
            failures.append(
                f"{where}: rendered diagnostic with no `render:` directive.\n"
                "  Put one on the line before the fence:\n"
                "    <!-- render: <program.whip> [envelope <policy>] "
                "[code <code>]… -->\n"
                "  or, if it illustrates a shape rather than one program's "
                "output:\n"
                "    <!-- render: skip — <reason> -->"
            )
            continue

        per_page[str(page)] = per_page.get(str(page), 0) + 1

        parsed = parse(directive_match.group(1), where)
        if parsed is None:
            continue
        skip_reason, program, envelope, codes = parsed
        if skip_reason is not None:
            exempt.append((where, skip_reason))
            continue

        for path in [program] + ([envelope] if envelope else []):
            if not pathlib.Path(path).is_file():
                failures.append(f"{where}: `render:` names a missing file: {path}")
                break
        else:
            rendered = render(program, envelope)
            output = blocks(rendered)
            if codes:
                selected = []
                for code in codes:
                    hit = [lines for c, lines in output if c == code]
                    if not hit:
                        emitted = ", ".join(sorted({c for c, _ in output})) or "nothing"
                        failures.append(
                            f"{where}: {program} no longer emits `{code}` "
                            f"(it emits: {emitted}).\n"
                            "  Either the program stopped producing the "
                            "diagnostic this page documents, or the code moved."
                        )
                        selected = None
                        break
                    for lines in hit:
                        selected.extend(lines)
                if selected is None:
                    continue
            else:
                # No `code`: the WHOLE stderr, verbatim. Not `blocks()` — that
                # drops everything before the first head line, which under an
                # envelope is the guarantee report the page is documenting.
                selected = list(rendered)
                if not output:
                    failures.append(
                        f"{where}: {program} emits no diagnostics at all; "
                        "there is nothing for this sample to render"
                    )
                    continue
            expected = "\n".join(selected) + "\n"
            generated += 1
            if expected != body:
                if MODE == "check":
                    failures.append(
                        f"{where}: STALE sample — run "
                        "scripts/regen-docs-diagnostics.sh"
                    )
                else:
                    # Replace the body AND the closing fence, so a regenerated
                    # sample carries the opening fence's indent throughout and
                    # the block stays inside the list item it belongs to.
                    edits.append(
                        (
                            match.start("body"),
                            match.end(),
                            apply_indent(expected, indent) + indent + "```",
                        )
                    )

    if MODE != "check" and edits:
        for start, end, replacement in reversed(edits):
            text = text[:start] + replacement + text[end:]
        page.write_text(text)

for page in sorted(set(EXPECTED) | set(per_page)):
    want, got = EXPECTED.get(page, 0), per_page.get(page, 0)
    if got < want:
        failures.append(
            f"{page}: carries {got} rendered samples, expected {want} — a block "
            "stopped being DETECTED as one. If that is deliberate, lower the "
            "count in scripts/regen-docs-diagnostics.sh."
        )
    elif got > want:
        failures.append(
            f"{page}: carries {got} rendered samples, expected {want} — raise "
            "the count in scripts/regen-docs-diagnostics.sh to record it."
        )

for line in failures:
    print(line, file=sys.stderr)

print(
    f"Docs diagnostic samples: {generated} generated, {len(exempt)} exempt.",
    file=sys.stderr if failures else sys.stdout,
)
for where, reason in exempt:
    print(f"  exempt: {where} — {reason}", file=sys.stderr if failures else sys.stdout)

sys.exit(1 if failures else 0)
PY
