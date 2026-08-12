#!/usr/bin/env bash
# Compile the ```whip programs printed in the documentation.
#
# Until now nothing did. The docs corpus checks ran `examples/` and a set of
# tutorial programs transcribed into check-docs-snippets.sh, so a fence inside a
# page could be broken indefinitely — verified by corrupting one and watching the
# green bar stay green.
#
# WHICH FENCES ARE COMPILED. A ```whip fence is a program when it declares a
# top-level `workflow` and contains no ellipsis, which is how a page says "and
# the rest" — on its own line or inline, as in `=> { ... }`. Those are compiled
# and must succeed. Everything else is a fragment — a rule body, a class, a
# `case` arm — and is not a program in any grammar, so it is skipped. No fence
# that compiles today contains an ellipsis, so the rule costs no coverage.
#
# The default therefore checks a NEW whole program automatically, which is the
# direction that matters: an unchecked fence should require someone to say so.
#
# SAYING SO. An HTML comment on the line before the fence overrides the default.
# It renders as nothing, and it is greppable:
#
#   <!-- check: skip — sketch, references an include that does not exist -->
#   <!-- check: fails -->            the page is DEMONSTRATING a diagnostic
#   <!-- check: root <Name> -->      several workflows; name the root
#
# `skip` requires a reason after an em dash. An unknown directive is an error, so
# a typo disables nothing silently. A `skip` on a fence that would in fact
# compile is also an error, so the skip list cannot rot into a list of things
# that were once broken.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Build once; the per-fence runs then cost a process each rather than a compile.
cargo build --quiet -p whipplescript --bin whip
WHIP="$ROOT/target/debug/whip"
[ -x "$WHIP" ] || WHIP="$ROOT/target/release/whip"

WHIP="$WHIP" python3 - <<'PY'
import os, pathlib, re, subprocess, sys, tempfile

WHIP = os.environ["WHIP"]
FENCE = re.compile(r"^```whip\n(.*?)^```", re.S | re.M)
DIRECTIVE = re.compile(r"<!--\s*check:\s*(.*?)\s*-->\s*$")
ELISION = re.compile(r"\.\.\.|…")
WORKFLOW = re.compile(r"^\s*workflow\s", re.M)

# HOW MANY PROGRAMS EACH PAGE CONTRIBUTES.
#
# Selection reads the fence body, so an edit that stops a fence LOOKING like a
# program — mistyping `workflow`, most obviously — would drop it out of the set
# silently and the gate would still pass. That is the failure this whole check
# exists to end, so it is not acceptable here either. These counts are compared
# after the run: a page that checks fewer programs than it did is an error, and
# adding one is a deliberate edit rather than a side effect.
EXPECTED = {
    "docs/diagnostics.md": 2,
    "docs/manual/01-smallest-workflow.md": 1,
    "docs/manual/02-facts-and-types.md": 1,
    "docs/manual/03-expressions.md": 1,
    "docs/manual/04-rules.md": 1,
    "docs/manual/05-effects.md": 2,
    "docs/manual/06-error-handling.md": 2,
    "docs/manual/07-case.md": 2,
    "docs/manual/08-coerce.md": 1,
    "docs/manual/09-then.md": 1,
    "docs/manual/10-time.md": 1,
    "docs/manual/11-agents.md": 1,
    "docs/manual/13-agent-patterns.md": 3,
    "docs/manual/14-coordination.md": 3,
    "docs/manual/15-trackers.md": 2,
    "docs/manual/16-progressions.md": 2,
    "docs/manual/17-messaging.md": 5,
    "docs/manual/18-composition.md": 2,
    "docs/manual/19-exec.md": 2,
    "docs/manual/20-files.md": 1,
    "docs/tutorials/root-agent.md": 1,
}

checked = failed_as_expected = 0
per_file: dict[str, int] = {}
skips: list[tuple[str, str]] = []
problems: list[str] = []


def directive_for(text: str, start: int):
    """The `<!-- check: … -->` on the last non-blank line before the fence."""
    for line in reversed(text[:start].splitlines()):
        if not line.strip():
            continue
        m = DIRECTIVE.search(line.strip())
        return m.group(1) if m else None
    return None


def run(body: str, root: str | None):
    with tempfile.NamedTemporaryFile("w", suffix=".whip", delete=False) as handle:
        handle.write(body)
        path = handle.name
    try:
        argv = [WHIP, "check", path] + (["--root", root] if root else [])
        return subprocess.run(argv, capture_output=True, text=True)
    finally:
        os.unlink(path)


def first_error(result) -> str:
    for line in (result.stdout + result.stderr).splitlines():
        if line.startswith("error"):
            return line.strip()
    return (result.stderr or result.stdout).strip().splitlines()[:1] or ["(no output)"]


for md in sorted(pathlib.Path("docs").rglob("*.md")):
    text = md.read_text()
    for match in FENCE.finditer(text):
        body = match.group(1)
        where = f"{md}:{text[:match.start()].count(chr(10)) + 1}"
        raw = directive_for(text, match.start())

        root = None
        expect_failure = False
        if raw is not None:
            if raw.startswith("skip"):
                reason = raw[4:].strip(" —-").strip()
                if not reason:
                    problems.append(f"{where}: `check: skip` needs a reason after an em dash")
                    continue
                # A skip that is no longer true is a stale exemption, so prove it.
                if WORKFLOW.search(body) and not ELISION.search(body):
                    if run(body, None).returncode == 0:
                        problems.append(
                            f"{where}: marked `check: skip` but it compiles — drop the directive"
                        )
                        continue
                skips.append((where, reason))
                continue
            if raw == "fails":
                expect_failure = True
            elif raw.startswith("root "):
                root = raw[5:].strip()
            else:
                problems.append(f"{where}: unknown directive `check: {raw}`")
                continue
        elif not WORKFLOW.search(body) or ELISION.search(body):
            continue

        result = run(body, root)
        if expect_failure:
            if result.returncode == 0:
                problems.append(
                    f"{where}: marked `check: fails` but it compiles — the page no longer "
                    "demonstrates a diagnostic"
                )
            else:
                failed_as_expected += 1
                per_file[str(md)] = per_file.get(str(md), 0) + 1
        elif result.returncode != 0:
            problems.append(f"{where}: {first_error(result)}")
        else:
            checked += 1
            per_file[str(md)] = per_file.get(str(md), 0) + 1

for page in sorted(set(EXPECTED) | set(per_file)):
    want, got = EXPECTED.get(page, 0), per_file.get(page, 0)
    if got < want:
        problems.append(
            f"{page}: checks {got} programs, expected {want} — a fence stopped being "
            "selected. If that is deliberate, mark it `check: skip <reason>` and lower "
            "the count in this script."
        )
    elif got > want:
        problems.append(
            f"{page}: checks {got} programs, expected {want} — raise the count in this "
            "script to record the new coverage."
        )

if problems:
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    sys.exit(f"\n{len(problems)} documented program(s) do not check")

print(
    f"docs fences: {checked} compiled, {failed_as_expected} failed as documented, "
    f"{len(skips)} skipped"
)
for where, reason in skips:
    print(f"  skipped {where}: {reason}")
PY
