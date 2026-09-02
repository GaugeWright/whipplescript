"""Find refusals that no test reaches.

A check that reports success because nothing reached it is indistinguishable
from a passing one. This sweep tells them apart: it neutralises one refusal at a
time and runs the suite. If the suite still passes, nothing was exercising that
refusal, and the compiler is free to stop refusing without any gate noticing.

The sweep is itself an instrument that can fail silently — a mutation that never
lands reports every refusal as covered. So it self-tests first: it plants
refusals nothing can reach and requires the sweep to report them as
unexercised. If a planted refusal comes back "caught", the sweep is broken and
the run fails before reporting anything about real code.

Usage:
    mutation_sweep.py --target <file> --filter <cargo test filter> [--limit N]

Cost: one crate rebuild per refusal. A whole file is hours, which is why this is
a dispatch-only deep suite and not part of the green bar.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass

# A refusal is either pushed onto a diagnostic list or returned as an error.
PUSH_PATTERNS = ("diagnostics.push(", "errors.push(")

# The same call WITH its receiver path, so `self.diagnostics.push(` and
# `self.inner.errors.push(` are neutralised whole rather than leaving a
# `self.drop(` that does not compile.
PUSH_CALL = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_]*\.)*(?:diagnostics|errors)\.push\(")

# `Err(` in expression position. Both `return Err(...)` and a tail-position
# `Err(...)` are refusals; `Err(e) =>` and `if let Err(e)` are patterns.
ERR_CALL = re.compile(r"\bErr\(")

# A refusal that never writes `Err`: `opt.ok_or_else(|| StoreError::Conflict(…))`
# turns an absent value into one. The tree carries 78 of these outside tests,
# and until 2026-08-26 the sweep counted none of them — so a whole refusal
# idiom was exempt from the one instrument that asks whether a refusal is
# exercised. Found because a change ADDED one and `check-new-refusals.sh`
# reported "no refusal sites were added or edited".
#
# Deliberately narrow: an explicit error constructor, not any `ok_or_else`.
# `ok_or_else(|| 0)` and `ok_or_else(Vec::new)` supply defaults, and a gate that
# swept those would report unexercised "refusals" that are not refusals, which
# is how an instrument gets ignored.
OK_OR_REFUSAL = re.compile(
    r"\.ok_or(?:_else)?\(\s*(?:\|\|\s*)?\{?\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*Error::"
)

# The same call, before we know what it constructs. `rustfmt` puts the closure
# body on its own line as soon as the expression is long — which is most of
# them — so the constructor that identifies a refusal is usually NOT on the line
# that opens the call. A rule that reads one line at a time therefore matches
# the shape nobody writes and misses the shape the formatter produces, which is
# how the first version of this rule found nothing in the very file that
# prompted it.
OK_OR_OPEN = re.compile(r"\.ok_or(?:_else)?\(")

# How far to look for the constructor. Three lines covers the closure-body form
# `rustfmt` emits; more would start joining unrelated statements.
OK_OR_WINDOW = 3

# A refusal that is neither `Err` nor a push: a domain enum whose VARIANT NAME
# says it refused. `EnvelopeStatus::Rejected(...)`, `DeliveryOutcome::Refused(...)`,
# `AdvanceOutcome::Rejected { ... }`. The function's contract is not `Result`, so
# there is no `Err` to find, and the tree carries 88 of these across eight types
# — ingress delivery, signal admission, restore preflight, boundary runs, ref
# advance — every one of them invisible to this sweep until 2026-09-02.
#
# Found the way the `ok_or` gap was: a change ADDED one (`EnvelopeStatus::Rejected`
# closing an IFC fail-open) and `check-new-refusals.sh` reported the file as
# carrying one touched site, having never seen it.
#
# Deliberately narrow, for the reason `OK_OR_REFUSAL` is: the variant name must
# itself be a refusal word. A sweep that took every `Type::Variant(` would report
# unexercised "refusals" that are ordinary values, which is how an instrument
# gets ignored.
REFUSAL_VARIANT = re.compile(
    r"\b[A-Z][A-Za-z0-9_]*::(?:Rejected|Refused|Denied)\s*[({]"
)

# The brace form is a PATTERN, not a construction, when it binds rather than
# supplies: `RestoreDecision::Refused { .. }` and
# `AdvanceOutcome::Rejected { ref current, .. }` both destructure. A construction
# names fields with values (`Refused { reason: format!(...) }`).
VARIANT_PATTERN_BODY = re.compile(r"^\s*(?:\.\.|ref\b|[a-z_][a-z0-9_]*\s*(?:,|\}|$))")

# A pattern binds a name or wildcard and closes immediately: `Err(e)`, `Err(_)`,
# `Err(ref error)`. An expression opens a call or a literal instead.
ERR_BINDING = re.compile(r"^(?:ref\s+|mut\s+)*(?:_|[a-z][a-z0-9_]*)\s*[),]")

# `if let Err(…) = `, `while let Err(…) = `, `let Err(…) = ` destructure rather
# than construct, whatever shape the bound pattern takes.
LET_PATTERN = re.compile(r"\blet\s+$")

# A match arm that hands back a value it was just given:
#
#     Err(message) => Err((None, message))
#     Err(error) => Err(error)
#
# The refusal is wherever `message` was BUILT; this arm only carries it. Counted
# as a refusal it is a site with no message to rewrite and no guard to falsify,
# so it reports as unmeasured forever and drags whole files red whenever an edit
# lands within its extent.
#
# Deliberately narrow: the payload must be identifiers and `None` only. Any
# literal, call, macro or `Type::Variant` means something is being CONSTRUCTED
# at this line and the site stands — `Err((None, format!("...")))` and
# `Err(CustodyError::Revoked { .. })` are both still refusals.
#
# The tradeoff is stated rather than hidden: an arm forwarding a message built
# on an earlier line stops being reported. Those sites are already unmeasurable
# — the text is outside the window `mutate_message` rewrites — so this moves
# them from "unmeasured" to "not a site", and the instrument stops asking for a
# test that could not be written.
FORWARDED_PAYLOAD = re.compile(
    r"^[\s(]*(?:None|[a-z_][a-z0-9_]*)(?:\s*,\s*(?:None|[a-z_][a-z0-9_]*))*[\s)]*$"
)


def err_payload(line: str, open_paren: int) -> str | None:
    """The text inside the `Err(` whose opening paren is at `open_paren`."""
    depth = 0
    for index in range(open_paren, len(line)):
        if line[index] == "(":
            depth += 1
        elif line[index] == ")":
            depth -= 1
            if depth == 0:
                return line[open_paren + 1 : index]
    return None


# Lines where an `Err(...)` is being matched against rather than constructed.
# Matched as calls, not substrings: a refusal's own message may well say
# "assertion failed".
ERR_NOT_A_REFUSAL = re.compile(r"\b(?:matches!|(?:debug_)?assert\w*!)\s*\(|\.expect_err\(")

# Where a refusal's user-facing text lives, for labelling a survivor.
MESSAGE = re.compile(r'"([^"]{4,})')

# A format string's placeholders, once `{{` and `}}` escapes are removed.
BRACE_ESCAPE = re.compile(r"\{\{|\}\}")
PLACEHOLDER = re.compile(r"\{[^{}]*\}")

PASSED = "passed"
CAUGHT = "caught"
BUILD_FAILED = "build failed"


@dataclass(frozen=True)
class Site:
    line: int  # 1-indexed line carrying the push/return
    label: str


def err_is_refusal(line: str) -> bool:
    """True when the line constructs a refusal, rather than matching one."""
    if ERR_NOT_A_REFUSAL.search(line):
        return False
    if OK_OR_REFUSAL.search(line):
        return True
    for found in ERR_CALL.finditer(line):
        rest = line[found.end() :]
        # `Err(e) => …` and `Ok(_) | Err(_) => …` are match arms, not refusals.
        if "=>" in rest:
            continue
        # `if let Err(error) = …` and `let Err((status, message)) = …` bind.
        if ERR_BINDING.match(rest) or LET_PATTERN.search(line[: found.start()]):
            continue
        # `Err(message) => Err((None, message))` and `return Err((None, reason))`
        # carry a refusal rather than making one. See `FORWARDED_PAYLOAD`.
        payload = err_payload(line, found.end() - 1)
        if payload is not None and FORWARDED_PAYLOAD.match(payload):
            continue
        return True
    return False


def cfg_test_extent(lines: list[str], index: int) -> str | None:
    """The closing brace that ends the item a `#[cfg(test)]` at `index` annotates.

    `#[cfg(test)]` does not always annotate a module. It also annotates a single
    test-only helper — a method inside an `impl`, a `use`, a `const`. Treating
    every occurrence as "a test module starts here, skip to the next column-zero
    `}`" swallows the production code that follows the helper, and every refusal
    in it, while still letting the sweep report the file clean. That is the exact
    silent-instrument failure this script exists to detect, so the extent is the
    annotated item's own, whatever kind of item it is.

    The extent is found by the closing brace at the item's own indentation
    column, NOT by counting braces. Counting is what a first draft does, and it
    is wrong here: `json!({…})` and `format!("{}")` put braces inside string
    literals and macros, so in a file like rule_lowering.rs the depth never
    returns to zero and every refusal after the first test module disappears.
    rustfmt closes a block at the indentation of the line that opened it, which
    is unambiguous and needs no lexer.

    Returns the sentinel closing-brace line, or None when the annotated item is
    contained on a single line and nothing needs skipping.
    """
    cursor = index + 1
    # Further attributes, comments, and blank lines sit between the attribute and
    # the item it applies to.
    while cursor < len(lines) and cursor <= index + 20:
        stripped = lines[cursor].strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#["):
            cursor += 1
            continue
        indent = lines[cursor][: len(lines[cursor]) - len(lines[cursor].lstrip())]
        if stripped.endswith("{"):
            return indent + "}"
        if stripped.endswith(";") or stripped.endswith("}"):
            # `mod tests;`, a `use`, or a body that fits on one line.
            return None
        # A signature rustfmt broke across lines: keep looking for its brace.
        cursor += 1
    return None


def variant_is_refusal(line: str) -> bool:
    """True when the line CONSTRUCTS a refusal-named enum variant.

    Excludes the two shapes that merely name one: a match arm (`=> `after it)
    and a destructuring pattern (`{ .. }`, `{ ref x, .. }`).
    """
    if ERR_NOT_A_REFUSAL.search(line):
        return False
    for found in REFUSAL_VARIANT.finditer(line):
        rest = line[found.end() :]
        # `EnvelopeStatus::Rejected(message) => ...` is an arm, not a refusal.
        if "=>" in rest:
            continue
        # `let RestoreDecision::Refused { .. } = ...` destructures.
        if LET_PATTERN.search(line[: found.start()]):
            continue
        if line[found.end() - 1] == "{" and VARIANT_PATTERN_BODY.match(rest):
            continue
        if line[found.end() - 1] == "(" and ERR_BINDING.match(rest.lstrip()):
            continue
        return True
    return False


# An `Option` refusal, declared. `None` IS the refusal here -- the contract has
# no error type and no message, so nothing in the line says a decision was made,
# and `return None` is far too common to key on. The author says so instead:
#
#     // REFUSAL: a source the grammar cannot read has no trustworthy split
#     if !parsed.diagnostics.is_empty() {
#         return None;
#     }
#
# The marker names the guard BELOW it, which `neutralise_guard` then falsifies,
# so the mutation asks the right question -- does anything notice this stopped
# refusing -- rather than rewriting a message that does not exist.
#
# Opt-in on purpose. There is no rule that separates a fail-closed `None` from
# an ordinary absent value by looking at it; a sweep that guessed would report
# hundreds of non-refusals and be ignored. This gives the idiom a way to be
# measured at all, which it did not have: `source_merge`'s fail-closed wall was
# a refusal the gate structurally could not ask about.
REFUSAL_MARKER = re.compile(r"^\s*//\s*REFUSAL\b:?\s*(.*)$")


def find_sites(lines: list[str]) -> list[Site]:
    """Every refusal site outside the file's own test-only items.

    A `#[cfg(test)]` item's own pushes are test scaffolding, not refusals. See
    `cfg_test_extent` for how far that skipping reaches, and why not further.
    """
    sites: list[Site] = []
    skip_until: str | None = None
    for index, line in enumerate(lines):
        if skip_until is not None:
            if line.rstrip() == skip_until:
                skip_until = None
            continue
        stripped = line.strip()
        if stripped == "#[cfg(test)]":
            skip_until = cfg_test_extent(lines, index)
            continue
        marked = REFUSAL_MARKER.match(line)
        if marked:
            # The marker names the next GUARD, so the site is that guard's
            # line -- `neutralise_guard` scans back from a site to find it.
            for offset in range(1, 4):
                if index + offset >= len(lines):
                    break
                if GUARD_LINE.match(lines[index + offset]):
                    # The site IS the guard line: `neutralise_guard` probes
                    # from the site line and falsifies the first guard it
                    # finds, so pointing at the guard makes the mutation exact.
                    guard_line = index + offset + 1
                    label = marked.group(1).strip()[:70]
                    sites.append(Site(guard_line, label or f"line {guard_line}"))
                    break
            continue
        if stripped.startswith("//"):
            continue
        is_site = (
            any(pattern in line for pattern in PUSH_PATTERNS)
            or err_is_refusal(line)
            or variant_is_refusal(line)
        )
        if not is_site and OK_OR_OPEN.search(line):
            # Joined only for THIS rule. Running the `Err(` rule over a joined
            # window would read a match arm on the next line as a construction.
            window = " ".join(
                text.strip() for text in lines[index : index + OK_OR_WINDOW]
            )
            is_site = bool(OK_OR_REFUSAL.search(window))
        if not is_site:
            continue
        label = None
        for offset in range(0, 6):
            if index + offset >= len(lines):
                break
            found = MESSAGE.search(lines[index + offset])
            if found:
                label = found.group(1)[:70]
                break
        sites.append(Site(index + 1, label or f"line {index + 1}"))
    return sites


def neutralise(line: str) -> str | None:
    """Make a refusal stop reporting, without changing what the code returns.

    `push` becomes `drop`, which still consumes its argument and still
    typechecks. An error expression has no such rewrite — the function's contract
    needs a value — so those sites are mutated by their message text instead,
    which only catches tests that assert on the text. That is a real limit and it
    is reported rather than papered over.
    """
    # The RECEIVER goes too. `self.diagnostics.push(x)` rewritten to
    # `self.drop(x)` is a call to a method that does not exist, so the mutation
    # does not compile and the site cannot be measured at all — 48 of the
    # parser's refusals were unknown for exactly this reason, every one of them
    # a `self.`-qualified push. Replacing the whole receiver path leaves the
    # free function `drop`, which consumes the argument and typechecks anywhere.
    mutated = PUSH_CALL.sub("drop(", line, count=1)
    return mutated if mutated != line else None


# A refusal guarded by a condition on one of the preceding lines:
#
#     if entry.revoked {
#         return Err(CustodyError::Revoked { credential: name });
#
# `if` or `else if`, opening a block that ends the line. The guard is what
# decides whether the refusal fires, so falsifying it is a true neutralisation —
# the refusal stops refusing and the code still typechecks, because the branch
# is merely dead.
GUARD_LINE = re.compile(r"^(\s*)(\}\s*else\s+if|if)\s+(?!let\b).+\{\s*$")


def neutralise_guard(lines: list[str], index: int) -> list[str] | None:
    """Falsify the guard that decides whether a refusal fires.

    This exists because `mutate_message` is the only tool for an error
    expression, and it can only catch tests that assert on the TEXT. A refusal
    built from a typed variant carries no text at all —
    `Err(CustodyError::Revoked { credential })` — so a whole idiom was
    unmeasurable, and the custodian's core admission path (unknown, revoked,
    kind mismatch) was invisible to the one instrument that asks whether a
    refusal is exercised.

    Falsifying the guard is strictly a better mutation than rewriting a message
    where both apply, so it is tried first: it asks whether anything notices the
    refusal STOPPED, rather than whether anything reads what it said.

    Scans back a few lines because `rustfmt` puts a long condition and its
    `return Err(` on separate lines, and stops at the first guard so a nested
    `if` cannot falsify its parent.

    COMMENT lines do not count against that budget. A comment is not code, and
    counting it meant that explaining a refusal moved it out of reach of the one
    instrument that asks whether anything exercises it — write four lines about
    why a refusal exists and the refusal silently became unmeasurable. Found
    that way, by a comment of exactly that length.
    """
    budget = 4
    probe = index
    while budget > 0 and probe >= 0:
        if lines[probe].strip().startswith("//"):
            probe -= 1
            continue
        budget -= 1
        found = GUARD_LINE.match(lines[probe])
        if not found:
            probe -= 1
            continue
        mutated = list(lines)
        mutated[probe] = f"{found.group(1)}{found.group(2)} false {{"
        return mutated
    return None


def mutate_message(line: str) -> str | None:
    """Replace a message's text while keeping its format placeholders.

    The placeholders have to survive. A refusal like
    `format!("{label} wants `{}`", lowering.id)` whose string is replaced
    wholesale leaves `lowering.id` unused, the mutation does not compile, and
    cargo's nonzero status is indistinguishable from a test catching the
    refusal — the sweep would report a false catch. `run_suite` tells the two
    apart as a second line of defence, but the mutation should compile.
    """
    for start, end, body in string_literals(line):
        if len(body) < 4:
            continue
        if CODE_MACRO_ARG.search(line[:start]):
            # A diagnostic code, not a message. The codes are a closed register
            # looked up at COMPILE time, so rewriting one does not weaken a
            # refusal — it stops the crate building, and the sweep reports "not
            # measured" for a site it never tested. Skipping it lets the search
            # walk on to the real message, usually a few lines below.
            continue
        placeholders = PLACEHOLDER.findall(BRACE_ESCAPE.sub("", body))
        mutated = " ".join(["MUTATED-BY-SWEEP", *placeholders])
        return line[:start] + '"' + mutated + '"' + line[end + 1 :]
    return None


def string_literals(line: str) -> list[tuple[int, int, str]]:
    """Every complete `"…"` on the line, as (open index, close index, body).

    Pairing the quotes matters rather than matching `"([^"]{4,}?)"`: that pattern
    cannot cross a quote, so on a line carrying TWO literals it fails on the
    first and then matches from the first literal's CLOSING quote to the second
    literal's opening one — a span that is not a literal at all, and rewriting it
    produces a line that does not parse. The idiom that hits this is a one-line
    `Diagnostic { code: …!("a.b"), message: "…" }`.
    """
    quotes = [found.start() for found in UNESCAPED_QUOTE.finditer(line)]
    return [
        (quotes[index], quotes[index + 1], line[quotes[index] + 1 : quotes[index + 1]])
        for index in range(0, len(quotes) - 1, 2)
    ]


# The argument to a code-minting macro, which is never a message. The idiom is
# `code: diagnostic_code!("graph.unbounded_effect_recursion"),` and the literal
# is a key into a compile-time register, so a rewritten one is a build failure
# rather than a weakened refusal. Four sites in the parser reported "not
# measured" for exactly this reason, and the shape they use — an `Err` carrying
# a code above its message, with no falsifiable guard in reach — is the
# dominant one, so the class was larger than the count suggested.
CODE_MACRO_ARG = re.compile(r"\b\w*code!\(\s*$")

# A `"` that actually opens or closes a literal, rather than one escaped inside
# one. An odd count on a line means the literal continues onto the next.
UNESCAPED_QUOTE = re.compile(r'(?<!\\)"')

# Raw strings do not follow the escape rules above, and a refusal message is
# never one. Skipped rather than mis-parsed.
RAW_STRING = re.compile(r'r#*"')


def mutate_wrapped_message(lines: list[str], index: int) -> list[str] | None:
    r"""Replace a message whose literal is `\`-continued across lines.

    [`mutate_message`] needs a complete `"…"` on one line, and this repository
    writes its long refusals wrapped:

        Conflict(format!(
            "manifest tree node `{id}` is not a node; the manifest is not \
             the shape its root says it is"
        ))

    so the opening line has no closing quote and the closing line has no opener.
    Neither matched, no mutation was applied, and the sweep reported the site
    UNMEASURED — honest, but it means a whole class of refusal, the ones long
    enough to need explaining, could never be pinned.
    """
    if RAW_STRING.search(lines[index]):
        return None
    quotes = [found.start() for found in UNESCAPED_QUOTE.finditer(lines[index])]
    if not quotes or len(quotes) % 2 == 0:
        return None
    open_at = quotes[-1]
    for end in range(index + 1, min(index + 12, len(lines))):
        if RAW_STRING.search(lines[end]):
            return None
        closing = [found.start() for found in UNESCAPED_QUOTE.finditer(lines[end])]
        if len(closing) % 2 == 0:
            continue
        close_at = closing[0]
        body = "".join(
            [lines[index][open_at + 1 :]] + lines[index + 1 : end] + [lines[end][:close_at]]
        )
        if len(body) < 4:
            return None
        placeholders = PLACEHOLDER.findall(BRACE_ESCAPE.sub("", body))
        replacement = " ".join(["MUTATED-BY-SWEEP", *placeholders])
        merged = (
            lines[index][:open_at] + '"' + replacement + '"' + lines[end][close_at + 1 :]
        )
        return lines[:index] + [merged] + lines[end + 1 :]
    return None


def apply_mutation(lines: list[str], site: Site) -> list[str] | None:
    mutated = list(lines)
    index = site.line - 1
    replaced = neutralise(mutated[index])
    if replaced is not None:
        mutated[index] = replaced
        return mutated
    # Before the message rewrite: falsifying the guard asks the stronger
    # question, and it is the only one available to a refusal with no message.
    guarded = neutralise_guard(mutated, index)
    if guarded is not None:
        return guarded
    for offset in range(0, 6):
        if index + offset >= len(mutated):
            break
        replaced = mutate_message(mutated[index + offset])
        if replaced is not None:
            mutated[index + offset] = replaced
            return mutated
        wrapped = mutate_wrapped_message(mutated, index + offset)
        if wrapped is not None:
            return wrapped
    return None


def run_suite(filter_expr: str) -> str:
    """PASSED when nothing caught the mutation, CAUGHT when a test failed.

    BUILD_FAILED when the mutated tree does not compile. That third case must not
    collapse into CAUGHT: a mutation that fails to build never ran, so reading
    cargo's nonzero status as "a test caught this refusal" invents coverage that
    does not exist.
    """
    # A flag-style filter is a cargo argument LIST (`-p whipplescript-parser`)
    # and has to be split: passed whole, cargo receives one argv element
    # containing a space and rejects it, which reads as BUILD_FAILED for every
    # site and reports a whole file unmeasured. Anything else is a test-name
    # filter and goes after `--`; an empty filter runs the workspace.
    command = ["cargo", "test", "-q"]
    if filter_expr.startswith("-"):
        command += shlex.split(filter_expr)
    elif filter_expr:
        command += ["--", filter_expr]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0:
        return PASSED
    if "could not compile" in result.stdout + result.stderr:
        return BUILD_FAILED
    return CAUGHT


def sweep(
    target: str, filter_expr: str, sites: list[Site], backup: str
) -> tuple[list[Site], list[Site]]:
    """Returns (unexercised refusals, sites the sweep could not measure)."""
    survivors: list[Site] = []
    unmeasured: list[Site] = []
    source = open(backup).read().split("\n")
    for number, site in enumerate(sites, 1):
        mutated = apply_mutation(source, site)
        if mutated is None:
            print(f"  {number:4d}/{len(sites)}  SKIP (no mutation)  {site.label}", flush=True)
            unmeasured.append(site)
            continue
        open(target, "w").write("\n".join(mutated))
        outcome = run_suite(filter_expr)
        if outcome == PASSED:
            survivors.append(site)
            print(f"  {number:4d}/{len(sites)}  UNEXERCISED  {target}:{site.line}  {site.label}", flush=True)
        elif outcome == BUILD_FAILED:
            unmeasured.append(site)
            print(f"  {number:4d}/{len(sites)}  BUILD FAILED (not measured)  {target}:{site.line}  {site.label}", flush=True)
        else:
            print(f"  {number:4d}/{len(sites)}  caught       {site.label}", flush=True)
    return survivors, unmeasured


# Five plants, one per refusal SHAPE the scanner claims to see: a pushed
# diagnostic that neutralises to `drop`, a tail-position error whose message
# carries a positional placeholder (so a mutation that drops placeholders stops
# compiling and the self test fails instead of the sweep reporting false
# catches), an `ok_or_else` that turns an absent value into an error, and a
# GUARDED refusal carrying no message at all.
#
# The third was added 2026-08-26 with the scanner rule that finds it. A
# detection rule with nothing planted against it is the same defect this script
# exists to catch, one level up: the rule could stop matching and every sweep
# would still come back clean.
#
# The sixth was added 2026-09-01 with the code-literal skip. It is the second
# plant whose point is being MEASURED at all: its mutation used to rewrite a
# compile-time code register key, so the crate failed to build and the site
# reported "not measured" — indistinguishable, in a summary, from a refusal the
# sweep had actually asked about and could not answer.
#
# The fifth was added 2026-08-31 with `neutralise_guard`, and it is the one that
# has to be MEASURED rather than merely reported. A message-less refusal has no
# text to rewrite, so before that mutation the sweep skipped it — and a skip and
# an unreachable plant both read as "not caught" unless the self test insists on
# the difference. This plant fails if the guard mutation stops landing.
PLANT = """
// `unused_variables` is allowed because the mutation this plant exists to test
// rewrites the push to `drop`, which leaves `diagnostics` unused. A crate that
// denies warnings would otherwise fail the self test's build.
#[allow(dead_code, unused_variables)]
fn mutation_sweep_self_test_refusal(diagnostics: &mut Vec<String>, reached: bool) {
    if reached {
        diagnostics.push("mutation sweep self test refusal".to_owned());
    }
}

#[allow(dead_code)]
fn mutation_sweep_self_test_tail_refusal(reached: bool, detail: &str) -> Result<(), String> {
    if reached {
        return Ok(());
    }
    Err(format!(
        "mutation sweep self test tail refusal at {}",
        detail
    ))
}

#[allow(dead_code)]
#[derive(Debug)]
enum MutationSweepSelfTestError {
    Missing(String),
    // No payload, so a refusal built from it carries no message to rewrite —
    // the shape `neutralise_guard` exists for.
    Guarded,
}

// A refusal with NO message, fired by a guard. This is the custodian's
// admission shape (`if entry.revoked { return Err(CustodyError::Revoked { … }) }`)
// and the whole class was unmeasurable until the guard mutation: `mutate_message`
// finds no text, so the sweep skipped it and reported "unknown, not covered".
#[allow(dead_code)]
fn mutation_sweep_self_test_guarded_refusal(
    reached: bool,
) -> Result<(), MutationSweepSelfTestError> {
    if reached {
        return Err(MutationSweepSelfTestError::Guarded);
    }
    Ok(())
}

// TWO plants, because the two shapes are found by different code and only one
// of them is what real code looks like. `rustfmt` moves the closure body to its
// own line as soon as the expression is long, so the constructor that marks
// this a refusal is usually not on the line that opens the call — and a rule
// that reads one line at a time misses every formatted site while a one-line
// plant reports it working.
#[allow(dead_code)]
fn mutation_sweep_self_test_ok_or_refusal(value: Option<u8>, detail: &str) -> Result<u8, MutationSweepSelfTestError> {
    value.ok_or_else(|| MutationSweepSelfTestError::Missing(format!("mutation sweep self test ok_or refusal at {}", detail)))
}

// A refusal whose CODE is minted above its message. `mutation_sweep_self_test_code!`
// stands in for `diagnostic_code!`: one literal arm, so a rewritten argument
// matches no rule and the crate stops building — which is what made four real
// parser sites report "not measured" rather than answering the question. The
// plant only bites while the code sits ABOVE the message inside the search
// window, because that is the ordering that makes the code the first literal
// found.
macro_rules! mutation_sweep_self_test_code {
    ("mutation-sweep.self-test") => {
        "mutation-sweep.self-test"
    };
}

#[allow(dead_code)]
struct MutationSweepSelfTestDiagnostic {
    code: &'static str,
    message: String,
}

#[allow(dead_code)]
fn mutation_sweep_self_test_coded_refusal(
    reached: Option<&str>,
    detail: &str,
) -> Result<(), MutationSweepSelfTestDiagnostic> {
    // An `if let`, not an `if`, and that is the whole plant. `neutralise_guard`
    // excludes `let` bindings — falsifying one leaves the binding unused and the
    // arm below unreachable — so this refusal falls through to the message
    // rewrite, which is where the code literal was being hit. Behind a plain
    // `if` the guard mutation fires first and the bug is never reached.
    if let Some(_reached) = reached {
        return Ok(());
    }
    Err(MutationSweepSelfTestDiagnostic {
        code: mutation_sweep_self_test_code!("mutation-sweep.self-test"),
        message: format!("mutation sweep self test coded refusal at {}", detail),
    })
}

#[allow(dead_code)]
fn mutation_sweep_self_test_wrapped_ok_or_refusal(
    value: Option<u8>,
    detail: &str,
) -> Result<u8, MutationSweepSelfTestError> {
    value.ok_or_else(|| {
        MutationSweepSelfTestError::Missing(format!(
            "mutation sweep self test wrapped ok_or refusal, whose message is itself \
             continued across lines, at {}",
            detail
        ))
    })
}

// A refusal whose contract is not `Result`: the VARIANT NAME is what says it
// refused. Message-carrying, so `mutate_message` reaches it; the brace form
// without a message is measured through its guard instead.
#[allow(dead_code)]
enum MutationSweepSelfTestOutcome {
    Admitted,
    Refused(String),
}

#[allow(dead_code)]
fn mutation_sweep_self_test_variant_refusal(
    reached: bool,
    detail: &str,
) -> MutationSweepSelfTestOutcome {
    if reached {
        return MutationSweepSelfTestOutcome::Admitted;
    }
    MutationSweepSelfTestOutcome::Refused(format!(
        "mutation sweep self test variant refusal at {}",
        detail
    ))
}

// A fail-closed `Option` refusal, declared by its marker. `None` carries no
// message and no error type, so this plant is measured ONLY through the guard
// the marker names — it fails if marker parsing or the guard mutation stops
// landing.
#[allow(dead_code)]
fn mutation_sweep_self_test_option_refusal(reached: bool) -> Option<u8> {
    // REFUSAL: mutation sweep self test option refusal
    if !reached {
        return None;
    }
    Some(1)
}
"""

# How many refusals `PLANT` contains. Asserted rather than counted so that
# adding a plant without teaching the self test about it fails loudly.
#
# Two were added 2026-09-02 with the variant and marker rules. Both are shapes
# the scanner could not see at all before, so a plant that reports "caught"
# means the new rule found a site the mutator cannot actually falsify — which
# is the failure mode this count exists to make loud.
PLANT_COUNT = 8


def self_test(target: str, filter_expr: str, backup: str) -> bool:
    """Plant refusals nothing can reach, and require the sweep to find them.

    This is the sweep's own bite test. Its failure mode — a mutation that never
    lands, so every refusal reports as covered — looks exactly like a clean
    result, and would turn this script into the thing it exists to detect.
    """
    source = open(backup).read()
    # Plants are selected by POSITION, not by their message. The fifth plant is
    # a message-less guarded refusal — the shape `neutralise_guard` exists for —
    # so a marker match would silently drop the one plant whose whole point is
    # having no text, and the self test would keep reporting four of four.
    original_lines = len(source.split("\n"))
    open(target, "w").write(source + PLANT)
    planted = find_sites(open(target).read().split("\n"))
    matching = [site for site in planted if site.line >= original_lines]
    if len(matching) != PLANT_COUNT:
        print(
            f"SELF TEST FAILED: the site scanner found {len(matching)} of the "
            f"{PLANT_COUNT} planted refusals",
            file=sys.stderr,
        )
        return False
    survivors, unmeasured = sweep(target, filter_expr, matching, target)
    if unmeasured:
        print(
            "SELF TEST FAILED: the sweep could not measure a planted refusal, so "
            "its mutations do not compile",
            file=sys.stderr,
        )
        return False
    if len(survivors) != PLANT_COUNT:
        print(
            "SELF TEST FAILED: the sweep reported an unreachable planted refusal "
            "as exercised, so its mutations are not landing",
            file=sys.stderr,
        )
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="source file to sweep")
    parser.add_argument("--filter", required=True, help="cargo test filter to run per mutation")
    parser.add_argument("--limit", type=int, default=0, help="sweep only the first N sites")
    parser.add_argument(
        "--only-lines",
        default="",
        help="comma-separated 1-indexed lines; sweep only the sites on them. "
        "Confirming a cheap per-crate run's candidates against the workspace "
        "otherwise re-runs every site in the file, and the whole point of the "
        "two-phase shape is that the expensive phase is small.",
    )
    parser.add_argument(
        "--list-sites",
        action="store_true",
        help="print the refusal sites as `<line>\\t<label>` and exit, mutating "
        "nothing. A caller that wants to sweep only the sites a diff touched "
        "has to know which lines hold one first: passing every changed line to "
        "--only-lines instead would report each ordinary line as a stale "
        "candidate, which is a true statement about the wrong question.",
    )
    args = parser.parse_args()

    target = args.target
    if not os.path.exists(target):
        print(f"no such target: {target}", file=sys.stderr)
        return 2

    if args.list_sites:
        for site in find_sites(open(target).read().split("\n")):
            print(f"{site.line}\t{site.label}")
        return 0

    backup = target + ".sweepbak"
    missing: set[int] = set()
    shutil.copy(target, backup)
    try:
        print("== self test ==", flush=True)
        if not self_test(target, args.filter, backup):
            return 1
        shutil.copy(backup, target)

        sites = find_sites(open(backup).read().split("\n"))
        if args.only_lines:
            wanted = {int(part) for part in args.only_lines.split(",") if part.strip()}
            sites = [site for site in sites if site.line in wanted]
            # A line that names no site is a stale candidate list — the file
            # moved under it. Say so rather than silently confirming fewer
            # refusals than were asked about, which would read as "the rest are
            # fine". It also fails the run: a requested site that was never
            # measured is unknown, and unknown must not exit 0.
            missing = wanted - {site.line for site in sites}
            if missing:
                print(
                    f"note: {len(missing)} requested line(s) hold no refusal site "
                    f"and were NOT measured: {sorted(missing)}",
                    flush=True,
                )
        if args.limit:
            print(f"note: sweeping {args.limit} of {len(sites)} sites", flush=True)
            sites = sites[: args.limit]
        print(f"== sweeping {len(sites)} refusals in {target} ==", flush=True)
        survivors, unmeasured = sweep(target, args.filter, sites, backup)
    finally:
        shutil.copy(backup, target)
        os.remove(backup)

    print(f"\n{len(survivors)} of {len(sites)} refusals unexercised by `{args.filter}`")
    for site in survivors:
        print(f"  {target}:{site.line}  {site.label}")
    if unmeasured:
        print(
            f"\n{len(unmeasured)} of {len(sites)} refusals were not measured — no "
            f"mutation applied, or the mutation did not compile. These are "
            f"unknown, not covered."
        )
        for site in unmeasured:
            print(f"  {target}:{site.line}  {site.label}")
    if missing:
        print(
            f"\n{len(missing)} requested line(s) held no refusal site and were "
            f"NOT measured — the candidate list is stale against this file. "
            f"These are unknown, not covered."
        )
        for line in sorted(missing):
            print(f"  {target}:{line}  (no refusal site)")
    return 1 if survivors or unmeasured or missing else 0


if __name__ == "__main__":
    sys.exit(main())
