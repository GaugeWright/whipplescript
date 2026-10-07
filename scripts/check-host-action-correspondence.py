#!/usr/bin/env python3
"""Hold the host-action formal witness to the code that realises it (HA-1).

    python3 scripts/check-host-action-correspondence.py
    python3 scripts/check-host-action-correspondence.py --root <dir>

models/maude/host-actions.maude and host-action-recovery.maude state the
host-action safety boundary as rewrite rules, and each negative-control module
adds exactly one forbidden transition. Those searches say the MODEL is safe.
Nothing said which store or kernel function a rule stands for, or which test
would fail if the implementation took the forbidden transition, so a model and
an implementation could drift apart with both still green.

models/host-action-correspondence.tsv is that mapping, one row per rule. This
check fails when:

  - a rule in either model has no row, or a row names a rule that is gone;
  - a row's role disagrees with its module (`forbids` belongs to a control
    module, `realizes`/`environment` to a base module);
  - a control module is exercised by no search in its test file, so its
    invariant has no witness that it bites;
  - a non-environment row names no implementation, or any row no regression;
  - a named function is no longer a `fn` in its file, or a named regression is
    no longer a `#[test]` function there, or is `#[ignore]`d.

It reads names, not what a test asserts. That a regression bites is the
test's own business; this keeps the claim that it exists from going stale.
It needs no Maude and no build, so it runs in the bar rather than beside the
deep formal suite (scripts/check-formal-models.sh), which runs the searches.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

TABLE = "models/host-action-correspondence.tsv"
MODELS = ("host-actions.maude", "host-action-recovery.maude")
COLUMNS = ["model", "module", "rule", "role", "implementation", "regressions"]
ROLES = {"realizes", "environment", "forbids"}

MODULE = re.compile(r"^\s*mod\s+([A-Z0-9-]+)\s+is\b")
END = re.compile(r"^\s*endm\b")
INCLUDING = re.compile(r"^\s*(?:including|extending)\s+[A-Z0-9-]+\s*\.")
RULE = re.compile(r"^\s*c?rl\s+\[([a-z0-9-]+)\]\s*:")
SEARCH = re.compile(r"^\s*search\s+(?:\[[^\]]*\]\s+)?in\s+([A-Z0-9-]+)\s*:")


def parse_model(text: str) -> tuple[dict[tuple[str, str], bool], set[str]]:
    """Return {(module, rule): is_control} and the set of control modules."""
    rules: dict[tuple[str, str], bool] = {}
    controls: set[str] = set()
    module = None
    pending: list[str] = []
    for line in text.splitlines():
        line = line.split("---", 1)[0]
        found = MODULE.match(line)
        if found:
            module, pending = found.group(1), []
            continue
        if module is None:
            continue
        if INCLUDING.match(line):
            controls.add(module)
        found = RULE.match(line)
        if found:
            pending.append(found.group(1))
        if END.match(line):
            for rule in pending:
                key = (module, rule)
                if key in rules:
                    raise ValueError(f"{module} declares rule [{rule}] twice")
                rules[key] = module in controls
            module = None
    return rules, controls


def searched_modules(text: str) -> set[str]:
    return {m.group(1) for line in text.splitlines() if (m := SEARCH.match(line))}


def functions(text: str) -> dict[str, list[bool]]:
    """Map each `fn` name to whether each definition is a live #[test]."""
    lines = text.splitlines()
    found: dict[str, list[bool]] = {}
    for index, line in enumerate(lines):
        match = re.match(r"^\s*(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\b", line)
        if not match:
            continue
        attributes = []
        cursor = index - 1
        # The attributes directly above the definition; doc comments may sit
        # among them, and a blank line or any other line ends them.
        while cursor >= 0:
            above = lines[cursor].strip()
            if above.startswith("#["):
                attributes.append(above)
            elif not above.startswith("//"):
                break
            cursor -= 1
        is_test = any(a.startswith("#[test]") for a in attributes) and not any(
            a.startswith("#[ignore") for a in attributes
        )
        found.setdefault(match.group(1), []).append(is_test)
    return found


def check(root: Path) -> list[str]:
    problems: list[str] = []
    table = root / TABLE
    if not table.is_file():
        return [f"{TABLE} is missing"]

    modelled: dict[tuple[str, str, str], bool] = {}
    controls: dict[str, set[str]] = {}
    for model in MODELS:
        path = root / "models/maude" / model
        tests = root / "models/maude/tests" / model
        if not path.is_file() or not tests.is_file():
            problems.append(f"models/maude/{model} or its test file is missing")
            continue
        try:
            rules, model_controls = parse_model(path.read_text())
        except ValueError as error:
            problems.append(f"{model}: {error}")
            continue
        controls[model] = model_controls
        for (module, rule), is_control in rules.items():
            modelled[(model, module, rule)] = is_control
        searched = searched_modules(tests.read_text())
        for module in sorted(model_controls - searched):
            problems.append(
                f"{model}: control module {module} is exercised by no search in "
                f"models/maude/tests/{model}, so its invariant has no biting witness"
            )

    sources: dict[str, dict[str, list[bool]] | None] = {}

    def source(path: str):
        if path not in sources:
            file = root / path
            sources[path] = functions(file.read_text()) if file.is_file() else None
        return sources[path]

    rows: set[tuple[str, str, str]] = set()
    body = [line for line in table.read_text().splitlines() if line.strip() and not line.startswith("#")]
    if not body or body[0].split("\t") != COLUMNS:
        return problems + [f"{TABLE}: the first row must be the header {' '.join(COLUMNS)}"]
    for number, line in enumerate(body[1:], start=2):
        cells = line.split("\t")
        if len(cells) != len(COLUMNS):
            problems.append(f"{TABLE} row {number}: expected {len(COLUMNS)} tab-separated cells")
            continue
        model, module, rule, role, implementation, regressions = cells
        where = f"{model} {module} [{rule}]"
        key = (model, module, rule)
        if key in rows:
            problems.append(f"{where}: more than one row")
        rows.add(key)
        if key not in modelled:
            problems.append(f"{where}: the row names a rule the model no longer has")
            continue
        if role not in ROLES:
            problems.append(f"{where}: unknown role {role!r}")
        elif (role == "forbids") != modelled[key]:
            expected = "forbids" if modelled[key] else "realizes or environment"
            problems.append(f"{where}: role {role} disagrees with its module; expected {expected}")

        named = [] if implementation == "-" else [item for item in implementation.split(",") if item]
        if not named and role != "environment":
            problems.append(f"{where}: names no implementation")
        for item in named:
            path, _, name = item.partition("#")
            defined = source(path)
            if defined is None:
                problems.append(f"{where}: implementation file {path} does not exist")
            elif name not in defined:
                problems.append(f"{where}: {path} no longer defines fn {name}")

        tests = [item for item in regressions.split(",") if item and item != "-"]
        if not tests:
            problems.append(f"{where}: names no regression")
        for item in tests:
            path, _, name = item.partition("#")
            defined = source(path)
            if defined is None:
                problems.append(f"{where}: regression file {path} does not exist")
            elif name not in defined:
                problems.append(f"{where}: regression {name} is no longer in {path}")
            elif not any(defined[name]):
                problems.append(f"{where}: {name} in {path} is not a live #[test]")

    for key in sorted(set(modelled) - rows):
        model, module, rule = key
        problems.append(f"{model} {module} [{rule}]: no row in {TABLE}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    problems = check(args.root)
    if problems:
        for problem in problems:
            print(f"host-action correspondence: {problem}", file=sys.stderr)
        return 1
    print("host-action correspondence: every modelled rule names its implementation and regression")
    return 0


if __name__ == "__main__":
    sys.exit(main())
