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
# And it does — an untagged fragment is an ERROR, not a quiet skip. Two survived
# the first curation pass because the sweep that tagged the manual decided
# "already done" per FILE, so a partially curated page kept its untagged fences
# and nothing said so. A corpus that can silently re-accumulate unchecked
# examples is the state this whole check exists to leave.
#
# SAYING SO. An HTML comment on the line before the fence overrides the default.
# It renders as nothing, and it is greppable:
#
#   <!-- check: skip — sketch, references an include that does not exist -->
#   <!-- check: fails <text> -->     the page is DEMONSTRATING a diagnostic, and
#                                    the error must contain <text>. Without the
#                                    text a `fails` fence passes on ANY error,
#                                    including one the wrapper caused, which
#                                    would certify the page teaches a diagnostic
#                                    it no longer produces.
#   <!-- check: root <Name> -->      several workflows; name the root
#   <!-- check: fragment -->         wrap and compile this fragment on its own
#   <!-- check: context <name> -->   this fence's declarations become reusable
#   <!-- check: in <name> -->        compile this fragment inside that context
#   <!-- check: … binds <b> <Class> -->  the synthetic rule matches <Class> as <b>
#
# A rule-BODY fragment (a `case` arm, an `after` block, a `tell`) reads bindings
# its surrounding rule established, which no amount of context can supply — the
# binding comes from a `when` clause, not a declaration. `binds` writes that
# clause into the synthetic rule, so `case change.kind { … }` can be compiled by
# saying it assumes `when Change as change`.
#
# FRAGMENTS AND CONTEXT. A fragment is not a program, but most of them are only
# missing a few declarations — overwhelmingly "rule X matches unknown class Y",
# a rule shown without the class it reads. `context`/`in` supply those: a fence
# marked `context ch` contributes its declarations to the page-scoped context
# named `ch`, and a later fence marked `in ch` is compiled inside it, wrapped in
# a synthetic workflow (and, for a rule-body fragment, a synthetic rule).
#
# The context is NAMED and OPT-IN rather than accumulated down the page. Simply
# accumulating was tried and is worse than nothing: pages legitimately redeclare
# a class between illustrations, and a `pattern` fence swallows whatever follows
# it, so accumulation turned 24 compiling fragments into 12.
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
    "docs/language-reference.md": 8,
    "docs/manual.md": 2,
    "docs/manual/01-smallest-workflow.md": 1,
    "docs/manual/02-facts-and-types.md": 10,
    "docs/manual/03-expressions.md": 1,
    "docs/manual/04-rules.md": 5,
    "docs/manual/05-effects.md": 2,
    "docs/manual/06-error-handling.md": 3,
    "docs/manual/07-case.md": 2,
    "docs/manual/08-coerce.md": 3,
    "docs/manual/09-then.md": 1,
    "docs/manual/10-time.md": 2,
    "docs/manual/11-agents.md": 4,
    "docs/manual/13-agent-patterns.md": 3,
    "docs/manual/14-coordination.md": 3,
    "docs/manual/15-trackers.md": 4,
    "docs/manual/16-progressions.md": 2,
    "docs/manual/17-messaging.md": 5,
    "docs/manual/18-composition.md": 2,
    "docs/manual/19-exec.md": 2,
    "docs/manual/20-files.md": 1,
    "docs/manual/26-gauges.md": 2,
    "docs/manual/32-providers.md": 1,
    "docs/manual/35-memory.md": 1,
    "docs/providers.md": 2,
    "docs/tutorials/root-agent.md": 1,
}

# Declaration keywords, for deciding whether a fragment is wrapped in a
# synthetic workflow (a class, an agent, a coerce) or additionally inside a
# synthetic rule (a `tell`, an `after`, a `case` arm).
DECLARATION_KEYWORDS = {
    "use", "class", "enum", "agent", "coerce", "lease", "ledger", "counter",
    "channel", "table", "credential", "memory", "pattern", "action", "redact",
    "include", "input", "output", "failure", "rule", "test", "source", "signal",
    "event", "tracker", "gauge", "mark", "campaign", "queue", "workspace",
    "@service", "@external", "@internal",
}

# `file` is both: `file store …` declares one, `file issue into q` is a body
# statement. The second word decides.
def is_declaration(first_line: str) -> bool:
    words = first_line.split()
    if not words:
        return False
    if words[0] == "file":
        return len(words) > 1 and words[1] == "store"
    return words[0] in DECLARATION_KEYWORDS

WRAPPER_WORKFLOW = "workflow DocFence\n"
WRAPPER_CONTRACT = """
output result FenceOk

class FenceOk {
  ok bool
}
"""
WRAPPER_RULE = """
rule doc_fence_terminates
  when started
=> {
  complete result { ok true }
}
"""


CLASS_BLOCK = re.compile(r"^class\s+(\w+)\s*\{(.*?)^\}", re.S | re.M)
ENUM_BLOCK = re.compile(r"^enum\s+(\w+)\s*\{(.*?)^\}", re.S | re.M)
MATCHES = re.compile(r"^\s*when\s+([A-Z]\w*)\s+as\s", re.M)


def seed_value(ty: str, classes: dict, enums: dict, depth: int = 0) -> str | None:
    """A literal of `ty` for a seed row. None means "omit this field"."""
    ty = ty.strip()
    if ty.endswith("?") or ty.endswith("[]"):
        return None if ty.endswith("?") else "[]"
    if ty.startswith('"'):                      # literal union: take the first
        return ty.split("|")[0].strip()
    if ty in ("string",):
        return '"x"'
    if ty == "int":
        return "1"
    if ty == "float":
        return "1.0"
    if ty == "bool":
        return "true"
    if ty == "time":
        return '"2027-01-01T00:00:00Z"'
    if ty == "duration":
        return "1s"
    if ty in enums:
        return enums[ty]
    if ty in classes and depth < 3:
        return seed_row(ty, classes, enums, depth + 1)
    return None


def seed_row(name: str, classes: dict, enums: dict, depth: int = 0) -> str:
    fields = []
    for line in classes.get(name, "").splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("//"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        value = seed_value(parts[1], classes, enums, depth)
        if value is not None:
            fields.append(f"{parts[0]} {value}")
    return "{ " + "  ".join(fields) + " }"


def seed_tables(source: str) -> str:
    """A one-row seed for each class the source MATCHES but nothing produces.

    A fragment shows a rule without the table, effect, or signal that feeds it,
    and `whip check` rightly refuses a rule that can never fire. The seed stands
    in for the producer the surrounding program would have. It is generated from
    the class declaration rather than guessed, so a class the generator cannot
    represent yields no table and the fence fails visibly instead of silently.
    """
    classes = {m.group(1): m.group(2) for m in CLASS_BLOCK.finditer(source)}
    enums = {
        m.group(1): next(
            (l.strip() for l in m.group(2).splitlines() if l.strip() and not l.strip().startswith("#")),
            "",
        )
        for m in ENUM_BLOCK.finditer(source)
    }
    produced = set(re.findall(r"^\s*record\s+(\w+)", source, re.M))
    produced |= set(re.findall(r"^\s*table\s+\w+\s+as\s+(\w+)", source, re.M))
    out = []
    for name in dict.fromkeys(MATCHES.findall(source)):
        if name in produced or name not in classes:
            continue
        out.append(f"table doc_seed_{name.lower()} as {name} [ {seed_row(name, classes, enums)} ]")
    return "\n".join(out)


def wrap(fragment: str, context: str, binds: list[tuple[str, str]] | None = None) -> str:
    """A fragment plus its context, as the smallest program that carries them."""
    lines = (context + "\n" + fragment).splitlines()
    # `use` has to lead the file, so hoist it out of wherever the fences put it.
    uses = list(dict.fromkeys(l for l in lines if l.strip().startswith("use ")))
    rest = [l for l in lines if not l.strip().startswith("use ")]
    body = "\n".join(rest)

    first = next((l.strip() for l in fragment.splitlines() if l.strip()), "")
    # A fence that declares its own terminal contract does not want the synthetic
    # one: two `output result` declarations are an error, and the fragment's
    # `complete result { … }` names fields the synthetic FenceOk does not have.
    # A context or fragment that declares its own terminal contract keeps it; the
    # synthetic one would be a second `output result` and its FenceOk lacks the
    # fields the fragment completes with.
    own_contract = bool(re.search(r"^\s*output\s", context + "\n" + fragment, re.M))
    head = WRAPPER_WORKFLOW + ("" if own_contract else WRAPPER_CONTRACT)
    tail = "" if own_contract else WRAPPER_RULE
    if is_declaration(first):
        program = head + "\n" + body + "\n" + seed_tables(body) + "\n" + tail
    else:
        # A rule-body fragment needs a rule to sit in. The context keeps its own
        # top-level position; only the fragment moves inside.
        ctx = "\n".join(l for l in context.splitlines() if not l.strip().startswith("use "))
        whens = (
            "".join(f"  when {cls} as {name}\n" for name, cls in binds)
            if binds else "  when started\n"
        )
        seeds = seed_tables(ctx + "\n" + "".join(f"when {c} as {n}\n" for n, c in (binds or [])))
        program = (
            head + "\n" + ctx + "\n" + seeds
            + "\n\nrule doc_fence\n" + whens + "=> {\n"
            + fragment + ("\n}\n" if own_contract else "\n  complete result { ok true }\n}\n")
        )
    return ("\n".join(uses) + "\n" if uses else "") + program


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
    contexts: dict[str, str] = {}
    for match in FENCE.finditer(text):
        body = match.group(1)
        where = f"{md}:{text[:match.start()].count(chr(10)) + 1}"
        raw = directive_for(text, match.start())

        root = None
        expect_failure = False
        expected_text = ""
        if raw is not None and raw.startswith("context ") and WORKFLOW.search(body):
            # A PROGRAM may also serve as a context: it is compiled as the program
            # it is, and its declarations become reusable. The page already shows
            # them, so nothing invisible is invented.
            # Types, contracts, agents and coercions — not the rules. A fragment
            # in this context is usually a variation on one of those rules, and
            # two declarations of the same rule name are a duplicate node.
            kept, in_rule = [], False
            for l in body.splitlines():
                if re.match(r"^\s*(rule|@external|@service)\s", l) or re.match(r"^\s*rule\s", l):
                    in_rule = True
                    continue
                if in_rule:
                    if l.startswith("}"):
                        in_rule = False
                    continue
                if re.match(r"^\s*(workflow|@)", l):
                    continue
                kept.append(l)
            contexts[raw.split(None, 1)[1].strip()] = "\n".join(kept) + "\n"
            raw = None
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
            if raw == "fails" or raw.startswith("fails "):
                expected_text = raw[6:].strip()
                if not expected_text:
                    problems.append(
                        f"{where}: `check: fails` needs the text the error must contain. "
                        "Without it the fence passes on ANY error, including one the "
                        "wrapper caused."
                    )
                    continue
                expect_failure = True
            elif raw.startswith("root "):
                root = raw[5:].strip()
            elif raw == "fragment" or raw.startswith("context ") or raw.startswith("in "):
                spec = raw.split(None, 1)[1].strip() if " " in raw else ""
                binds = []
                if " binds " in f" {spec} ":
                    spec, _, bindspec = spec.partition(" binds ")
                    words = bindspec.split()
                    binds = list(zip(words[0::2], words[1::2]))
                name = spec.strip()
                if raw.startswith("in ") and name not in contexts:
                    problems.append(
                        f"{where}: `check: in {name}` names a context this page has not "
                        "defined above it"
                    )
                    continue
                result = run(wrap(body, contexts.get(name, ""), binds), None)
                if raw.startswith("context "):
                    contexts[name] = (contexts.get(name, "") + "\n" + body).strip() + "\n"
                if result.returncode != 0:
                    problems.append(f"{where}: {first_error(result)}")
                else:
                    checked += 1
                    per_file[str(md)] = per_file.get(str(md), 0) + 1
                continue
            else:
                problems.append(f"{where}: unknown directive `check: {raw}`")
                continue
        elif ELISION.search(body):
            continue
        elif not WORKFLOW.search(body):
            problems.append(
                f"{where}: this fragment carries no `check:` directive. Mark it "
                "`fragment`, `in <context>`, or `skip <reason>`."
            )
            continue


        result = run(body, root)
        if expect_failure:
            if result.returncode == 0:
                problems.append(
                    f"{where}: marked `check: fails` but it compiles — the page no longer "
                    "demonstrates a diagnostic"
                )
            elif expected_text and expected_text not in result.stdout + result.stderr:
                problems.append(
                    f"{where}: marked `check: fails {expected_text}` but the error is "
                    f"{first_error(result)} — the page teaches a diagnostic it no longer "
                    "produces, or the wrapper failed first"
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
