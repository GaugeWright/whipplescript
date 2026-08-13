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
import shutil
import subprocess
import sys
from dataclasses import dataclass

# A refusal is either pushed onto a diagnostic list or returned as an error.
PUSH_PATTERNS = ("diagnostics.push(", "errors.push(")

# `Err(` in expression position. Both `return Err(...)` and a tail-position
# `Err(...)` are refusals; `Err(e) =>` and `if let Err(e)` are patterns.
ERR_CALL = re.compile(r"\bErr\(")

# A pattern binds a name or wildcard and closes immediately: `Err(e)`, `Err(_)`,
# `Err(ref error)`. An expression opens a call or a literal instead.
ERR_BINDING = re.compile(r"^(?:ref\s+|mut\s+)*(?:_|[a-z][a-z0-9_]*)\s*[),]")

# `if let Err(…) = `, `while let Err(…) = `, `let Err(…) = ` destructure rather
# than construct, whatever shape the bound pattern takes.
LET_PATTERN = re.compile(r"\blet\s+$")

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
    """True when the line constructs an `Err`, rather than matching one."""
    if ERR_NOT_A_REFUSAL.search(line):
        return False
    for found in ERR_CALL.finditer(line):
        rest = line[found.end() :]
        # `Err(e) => …` and `Ok(_) | Err(_) => …` are match arms, not refusals.
        if "=>" in rest:
            continue
        # `if let Err(error) = …` and `let Err((status, message)) = …` bind.
        if ERR_BINDING.match(rest) or LET_PATTERN.search(line[: found.start()]):
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
        if stripped.startswith("//"):
            continue
        if not any(pattern in line for pattern in PUSH_PATTERNS) and not err_is_refusal(line):
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
    for pattern in PUSH_PATTERNS:
        if pattern in line:
            return line.replace(pattern, "drop(", 1)
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
    found = re.search(r'"([^"]{4,}?)"', line)
    if not found:
        return None
    placeholders = PLACEHOLDER.findall(BRACE_ESCAPE.sub("", found.group(1)))
    mutated = " ".join(["MUTATED-BY-SWEEP", *placeholders])
    return line[: found.start()] + '"' + mutated + '"' + line[found.end() :]


def apply_mutation(lines: list[str], site: Site) -> list[str] | None:
    mutated = list(lines)
    index = site.line - 1
    replaced = neutralise(mutated[index])
    if replaced is not None:
        mutated[index] = replaced
        return mutated
    for offset in range(0, 6):
        if index + offset >= len(mutated):
            break
        replaced = mutate_message(mutated[index + offset])
        if replaced is not None:
            mutated[index + offset] = replaced
            return mutated
    return None


def run_suite(filter_expr: str) -> str:
    """PASSED when nothing caught the mutation, CAUGHT when a test failed.

    BUILD_FAILED when the mutated tree does not compile. That third case must not
    collapse into CAUGHT: a mutation that fails to build never ran, so reading
    cargo's nonzero status as "a test caught this refusal" invents coverage that
    does not exist.
    """
    result = subprocess.run(
        ["cargo", "test", "-q", filter_expr] if filter_expr.startswith("-")
        else ["cargo", "test", "-q", "--", filter_expr],
        capture_output=True,
        text=True,
    )
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


# Two plants, one per mutation strategy: a pushed diagnostic that neutralises to
# `drop`, and a tail-position error whose message carries a positional
# placeholder, so a mutation that drops placeholders stops compiling and the self
# test fails instead of the sweep silently reporting false catches.
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
"""

PLANT_MARKER = "mutation sweep self test"


def self_test(target: str, filter_expr: str, backup: str) -> bool:
    """Plant refusals nothing can reach, and require the sweep to find them.

    This is the sweep's own bite test. Its failure mode — a mutation that never
    lands, so every refusal reports as covered — looks exactly like a clean
    result, and would turn this script into the thing it exists to detect.
    """
    source = open(backup).read()
    open(target, "w").write(source + PLANT)
    planted = find_sites(open(target).read().split("\n"))
    matching = [site for site in planted if PLANT_MARKER in site.label]
    if len(matching) != 2:
        print(
            f"SELF TEST FAILED: the site scanner found {len(matching)} of the 2 "
            f"planted refusals",
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
    if len(survivors) != 2:
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
    args = parser.parse_args()

    target = args.target
    if not os.path.exists(target):
        print(f"no such target: {target}", file=sys.stderr)
        return 2

    backup = target + ".sweepbak"
    shutil.copy(target, backup)
    try:
        print("== self test ==", flush=True)
        if not self_test(target, args.filter, backup):
            return 1
        shutil.copy(backup, target)

        sites = find_sites(open(backup).read().split("\n"))
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
    return 1 if survivors or unmeasured else 0


if __name__ == "__main__":
    sys.exit(main())
