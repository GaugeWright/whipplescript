#!/usr/bin/env bash
# Regenerate — or check — the diagnostic code registers.
#
#   scripts/regen-diagnostic-codes.sh          rewrite the registers from the sources
#   scripts/regen-diagnostic-codes.sh --check  fail (exit 1) if any register is stale
#
# Three artifacts, one source of truth. The source of truth is the set of
# `diagnostic_code!("…")` and `runtime_diagnostic_code!("…")` literals in the
# shipped crate sources — what the compiler and runtime ACTUALLY emit, which is
# the only thing a register may not drift from:
#
#   crates/whipplescript-core/src/diagnostic_code_register.rs
#       the arrays `diagnostic_code!` / `runtime_diagnostic_code!` select from.
#       This is what makes the macro the only door: `DiagnosticCode` has no
#       constructor, so the only codes that EXIST are the entries here, and a
#       literal the array does not carry fails the build at the site that wrote
#       it. A register that is merely CHECKED can be bypassed by anything that
#       does not run the check; a register that is INDEXED cannot.
#   spec/diagnostic-codes.txt
#       the human-facing append-only register of the check plane, with the
#       coverage column below.
#   spec/diagnostic-codes-runtime.txt
#       the same for the runtime plane (`expect diagnostic` matches this space).
#
# THE COVERAGE COLUMN. Every check-plane code is marked COVERED or PROVISIONAL:
#
#   COVERED      some `.whip` file in this repository makes `whip check` emit it.
#   PROVISIONAL  nothing in the corpus reaches it. The code has never been seen
#                to come out of the compiler, so a classification error in it is
#                invisible to every gate.
#
# WHICH CORPUS. Every `.whip` file `git ls-files` returns — not just
# `examples/invalid/`. That includes `examples/diagnostics/`, the companion
# programs the documentation's rendered samples are generated from, and it is
# deliberate: the guarantee COVERED buys is "a gate would notice if this code
# stopped coming out of the compiler", and those programs are asserted on every
# run by `scripts/regen-docs-diagnostics.sh --check`, which fails by page and
# line when a documented code goes missing. The corpus is heterogeneous, though,
# so a coverage number is only interpretable with its corpus named: say which
# files a figure was measured over whenever one is quoted.
#
# The language specification's "Code Governance" section hangs the append-only
# guarantee off that column: a COVERED code is frozen, a PROVISIONAL one may
# still be corrected. That is why the column is GENERATED, never hand-written —
# hand-maintained, it would be a claim about coverage rather than a measurement
# of it, and the first stale line would freeze a code nobody has ever seen.
#
# Coverage is measured through `whip check` AND `whip lint`, because both are
# the compiler emitting a registered code over this corpus, and both are gated:
# a code that stops coming out of either is caught. `whip lint` joined when the
# linter's codes joined the register — before that the linter minted its codes
# as bare strings, so its 25 codes were in no register and no coverage question
# could be asked about them at all. A code reachable only through `whip test` or
# the LSP still reads as PROVISIONAL, which is honest: this corpus does not
# reach it.
#
# The two surfaces are grepped apart because they RENDER apart: `whip check`
# heads a diagnostic `error[code]:` while `whip lint` writes
# `path:line:col: warning [code] message (action)`. Reading the lint corpus with
# the check pattern would have found nothing and marked every lint code
# PROVISIONAL, which is the quiet failure this comment exists to prevent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export LC_ALL=C

mode="write"
case "${1:-}" in
  "") ;;
  --check) mode="check" ;;
  *)
    echo "usage: scripts/regen-diagnostic-codes.sh [--check]" >&2
    exit 2
    ;;
esac
if [[ $# -gt 1 ]]; then
  echo "usage: scripts/regen-diagnostic-codes.sh [--check]" >&2
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

REGISTER="crates/whipplescript-core/src/diagnostic_code_register.rs"
LEDGER="spec/diagnostic-codes.txt"
RUNTIME_LEDGER="spec/diagnostic-codes-runtime.txt"

# ---------------------------------------------------------------------------
# 1. Read the emitted set out of the sources.
#
# The same scan `diagnostic_code_ledger_tests` in whipplescript-core performs,
# including its `#[cfg(test)]` / `#[cfg(any())]` stripping and its `*_tests`
# exclusions — a code that exists only in a fixture or a retired module is not
# shipped. The two implementations are a deliberate mutual check: if this scan
# and that test ever disagree, the test fails, naming the code.
# ---------------------------------------------------------------------------
python3 - "$work" <<'PYTHON'
import os
import re
import sys

work = sys.argv[1]
ATTRIBUTES = ("#[cfg(test)]", "#[cfg(any())]")


def strip_inactive_blocks(source):
    lines = source.split("\n")
    kept = []
    index = 0
    skipping = False
    while index < len(lines):
        line = lines[index]
        if not skipping and line in ATTRIBUTES:
            item = index + 1
            while item < len(lines) and (not lines[item].strip() or lines[item].startswith("#[")):
                item += 1
            skipping = item < len(lines) and lines[item].rstrip().endswith("{")
            index = item + 1
            continue
        if skipping:
            if line == "}":
                skipping = False
            index += 1
            continue
        kept.append(line)
        index += 1
    return "\n".join(kept)


def literals(text, macro):
    # Tolerant of whitespace between `!(` and the literal: `cargo fmt` breaks a
    # long invocation across lines, and a scanner that only matched `!("` would
    # silently miss exactly the codes whose call sites are longest.
    return re.findall(macro + r'!\s*\(\s*"([^"]*)"', text)


def shipped_sources():
    for crate in sorted(os.listdir("crates")):
        src = os.path.join("crates", crate, "src")
        if not os.path.isdir(src):
            continue
        for directory, subdirectories, files in os.walk(src):
            subdirectories[:] = sorted(
                name for name in subdirectories
                if not name.endswith("_tests") and name != "tests"
            )
            for name in sorted(files):
                if name.endswith(".rs") and not name[:-3].endswith("_tests"):
                    yield os.path.join(directory, name)


check, runtime = set(), set()
files = 0
for path in shipped_sources():
    files += 1
    with open(path, encoding="utf-8") as handle:
        text = strip_inactive_blocks(handle.read())
    # Order matters: `runtime_diagnostic_code!` ends in `diagnostic_code!`, so
    # take the runtime literals first and blank them out before the check scan
    # would claim them as its own.
    for code in literals(text, "runtime_diagnostic_code"):
        runtime.add(code)
    text = text.replace("runtime_diagnostic_code!(", "RUNTIME_TAKEN(")
    for code in literals(text, "diagnostic_code"):
        check.add(code)

if files <= 100:
    sys.exit(
        f"found only {files} source files — the scan is not seeing the workspace, "
        "and an empty scan would report every shipped code as removed"
    )

with open(os.path.join(work, "check-codes"), "w", encoding="utf-8") as handle:
    handle.write("".join(f"{code}\n" for code in sorted(check)))
with open(os.path.join(work, "runtime-codes"), "w", encoding="utf-8") as handle:
    handle.write("".join(f"{code}\n" for code in sorted(runtime)))
PYTHON

# ---------------------------------------------------------------------------
# 2. The Rust register, which the macros index.
# ---------------------------------------------------------------------------
{
  cat <<'HEADER'
//! The diagnostic code registers, GENERATED by
//! `scripts/regen-diagnostic-codes.sh` from the `diagnostic_code!` and
//! `runtime_diagnostic_code!` literals in the shipped sources. Do not edit.
//!
//! These arrays are not a list of codes; they are the codes. `DiagnosticCode`
//! and `RuntimeDiagnosticCode` have no constructor, so every code that exists
//! in the workspace is an entry here, and the macros resolve a literal to an
//! index rather than minting a value. A code outside the register cannot be
//! built — not in const context, not at runtime, not by a caller who found the
//! validator and called it directly.

use crate::{DiagnosticCode, RuntimeDiagnosticCode};

/// Every code `whip check` may emit — the check plane of
/// `spec/diagnostic-codes.txt`.
pub const DIAGNOSTIC_CODES: &[DiagnosticCode] = &[
HEADER
  sed 's/^/    DiagnosticCode("/;s/$/"),/' "$work/check-codes"
  cat <<'MIDDLE'
];

/// Every code a run may record durably — `spec/diagnostic-codes-runtime.txt`.
pub const RUNTIME_DIAGNOSTIC_CODES: &[RuntimeDiagnosticCode] = &[
MIDDLE
  sed 's/^/    RuntimeDiagnosticCode("/;s/$/"),/' "$work/runtime-codes"
  echo "];"
} > "$work/register.rs"

# ---------------------------------------------------------------------------
# 3. The runtime ledger.
# ---------------------------------------------------------------------------
{
  echo "# The RUNTIME diagnostic code register — the \"Runtime Plane Codes\""
  echo "# section of the error-handling specification. GENERATED by"
  echo "# scripts/regen-diagnostic-codes.sh from the runtime_diagnostic_code!"
  echo "# literals in the sources; do not hand-edit."
  echo "#"
  echo "# These are the codes a RUN records durably and \`expect diagnostic\` matches"
  echo "# against. They carry no coverage column: this repository has no corpus that"
  echo "# drives a runtime plane the way examples/*.whip drives \`whip check\`, so"
  echo "# claiming coverage here would be a claim rather than a measurement."
  cat "$work/runtime-codes"
} > "$work/runtime-ledger"

compare_or_write() {
  local generated="$1" committed="$2" hint="$3"
  if [[ "$mode" == "check" ]]; then
    if [[ ! -f "$committed" ]]; then
      echo "MISSING: $committed — run scripts/regen-diagnostic-codes.sh" >&2
      return 1
    fi
    if ! diff -u "$committed" "$generated" >&2; then
      echo "STALE: $committed — $hint" >&2
      return 1
    fi
  else
    cp "$generated" "$committed"
  fi
  return 0
}

status=0
compare_or_write "$work/register.rs" "$REGISTER" \
  "run scripts/regen-diagnostic-codes.sh" || status=1
compare_or_write "$work/runtime-ledger" "$RUNTIME_LEDGER" \
  "a runtime code was allocated or stopped being emitted" || status=1

# A stale register in check mode means the build below would fail with a macro
# panic instead of the message above, so stop here and let the reader see the
# diff that explains it.
if [[ "$status" -ne 0 ]]; then
  exit 1
fi

# ---------------------------------------------------------------------------
# 4. Measure coverage: which codes does the corpus actually make come out?
# ---------------------------------------------------------------------------
cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p whipplescript
WHIP="${CARGO_TARGET_DIR:-$ROOT/target}/debug/whip"
if [[ ! -x "$WHIP" ]]; then
  echo "no whip binary at $WHIP after a successful build" >&2
  exit 1
fi

: > "$work/raw"
: > "$work/raw-lint"
corpus=0
while read -r whip; do
  [[ -n "$whip" ]] || continue
  corpus=$((corpus + 1))
  args=()
  if [[ -f "${whip%.whip}.check-args" ]]; then
    # shellcheck disable=SC2207 # word splitting is the point: one flag per word
    args=($(cat "${whip%.whip}.check-args"))
  fi
  # A refused fixture exits non-zero; that is the normal case here, not a fault.
  "$WHIP" check "$whip" "${args[@]}" >>"$work/raw" 2>&1 || true
  # The advisory plane, kept in its own file so the two renderings are read by
  # their own patterns. A program `check` refuses never reaches a lint rule —
  # `lint` reports the compile failure and stops — so this adds coverage only
  # where a program compiles, which is exactly where a lint code can be emitted.
  "$WHIP" lint "$whip" "${args[@]}" >>"$work/raw-lint" 2>&1 || true
done < <(git ls-files '*.whip')

if [[ "$corpus" -lt 50 ]]; then
  echo "found only $corpus .whip files — the corpus scan is not seeing the" >&2
  echo "  repository, and an empty scan would mark every code PROVISIONAL." >&2
  exit 1
fi

{
  grep -Eho '^(error|warning|info|hint)\[[a-z0-9_.]+\]' "$work/raw" || true
  grep -Eho ' (error|warning|info|hint) \[[a-z0-9_.]+\]' "$work/raw-lint" || true
} | sed 's/.*\[//;s/\]//' | sort -u > "$work/emitted"

# ---------------------------------------------------------------------------
# 5. The check-plane ledger, with the coverage column.
# ---------------------------------------------------------------------------
{
  echo "# The diagnostic code register — the \"Codes\" section of the"
  echo "# error-handling specification. GENERATED by"
  echo "# scripts/regen-diagnostic-codes.sh from the diagnostic_code! literals"
  echo "# in the sources; do not hand-edit."
  echo "#"
  echo "# Second column: whether any .whip file in this repository makes"
  echo "# \`whip check\` or \`whip lint\` emit the code. The corpus is every"
  echo "# .whip git tracks — examples/invalid/ and examples/diagnostics/ (the"
  echo "# companion programs the docs' rendered samples come from) alike, plus"
  echo "# the crate fixtures and the dogfood solutions. A code reached only by a"
  echo "# companion program still counts: scripts/regen-docs-diagnostics.sh"
  echo "# --check fails when one stops emitting the code its page documents,"
  echo "# which is the guarantee the COVERED mark stands for. Quote a coverage"
  echo "# figure with the corpus it was measured over; the count alone does not"
  echo "# say."
  echo "#"
  echo "# Both surfaces are the compiler emitting a registered code, and both are"
  echo "# gated, so both count. \`whip lint\` joined when the lint codes"
  echo "# joined the register: before that the linter minted them as bare"
  echo "# strings, and no coverage question could be asked about them at all."
  echo "#"
  echo "#   COVERED      the corpus reaches it. Append-only: it may not be renamed"
  echo "#                or removed."
  echo "#   PROVISIONAL  nothing reaches it. Never observed coming out of the"
  echo "#                compiler, so it is NOT yet under the append-only"
  echo "#                guarantee and may still be corrected. It becomes stable"
  echo "#                the moment a fixture reaches it."
  while read -r code; do
    [[ -n "$code" ]] || continue
    if grep -qxF "$code" "$work/emitted"; then
      printf '%s %s\n' "$code" "COVERED"
    else
      printf '%s %s\n' "$code" "PROVISIONAL"
    fi
  done < "$work/check-codes"
} > "$work/ledger"

compare_or_write "$work/ledger" "$LEDGER" \
  "a code was allocated, stopped being emitted, or changed coverage" || status=1

# Rows only. These counts are read back off the generated file, and the header
# above is prose that legitimately names both marks — a `grep ' COVERED$'` that
# does not exclude comments counts a sentence ending in the word as a code, which
# it did the first time this header was written.
covered=$(grep -c '^[^#].* COVERED$' "$work/ledger" || true)
provisional=$(grep -c '^[^#].* PROVISIONAL$' "$work/ledger" || true)
total=$((covered + provisional))
if [[ "$mode" == "check" ]]; then
  if [[ "$status" -eq 0 ]]; then
    echo "Diagnostic code registers OK: $total codes, $covered covered, $provisional provisional."
  fi
else
  echo "Diagnostic code registers refreshed: $total codes, $covered covered, $provisional provisional."
fi
exit "$status"
