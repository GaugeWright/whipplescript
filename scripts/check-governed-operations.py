#!/usr/bin/env python3
"""The governed-operation inventory (HA-4), checked beside the governed doors.

Every production function that starts an effect run is listed here with the
handler family it belongs to and HOW it starts the run:

  fresh   `start_dispatch_observed` / `start_dispatch`: new sink I/O needs a
          fresh claim, compared with the exact effect definition inside the
          dispatch transaction. On an admitted action instance it also needs
          the facade's single-use execution grant, whose principal,
          delegation and observation evidence is written into the run.
  legacy  `start_run` / `start_run_for_admission`: may reattach a recorded
          run. It refuses every admitted action instance outright, so the
          family is closed to actions but carries no action provenance yet.
  door    the kernel's own wrappers around the store primitives.

The inventory is the migration ledger: a family listed in MIGRATED may only
contain fresh rows, so a handler that slides back to `start_run` fails here
even when the count is unchanged. A new run-starting function anywhere in
production code fails until it is classified, and a row the tree no longer
has fails until the table shrinks with it.

The VCS write surface (promote, selective verbs, reservations) starts no run
of its own; its callers are pinned by `check-governed-doors.sh`.

Scanned: tracked and nonignored untracked `crates/**/*.rs` outside
`tests/`, `examples/` and `benches/`, excluding the store implementations
that define the primitives (`whipplescript-store`, the DO's `do_store`).
Items under a `cfg(test)` / `cfg(any(test, feature = "test-support"))`
attribute, and `#[path]` modules declared under one, are not production.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

FAMILIES = {
    "file", "export", "external-effect", "tool", "process", "provider",
    "topology", "tracker", "coordination", "time", "custody", "norm", "door",
}
# Families whose every run-start must be fresh governed dispatch.
MIGRATED = {"file", "export", "external-effect"}

# family|status|file|function|primitive|count
# The DO's `run_effect` starts its agent turns and coercion inline, and fails
# a kind it cannot execute through one more `start_run`; all four are counted
# under provider. Its exec start is the process family.
INVENTORY = """\
external-effect|fresh|crates/whipplescript-kernel/src/effect_handlers.rs|run_event_effect_generic|start_dispatch_observed|1
external-effect|fresh|crates/whipplescript-kernel/src/effect_handlers.rs|run_notify_effect_generic|start_dispatch_observed|1
file|fresh|crates/whipplescript-kernel/src/effect_handlers.rs|run_file_effect_generic|start_dispatch_observed|1
file|fresh|crates/whipplescript-kernel/src/effect_handlers.rs|run_file_write_effect_generic|start_dispatch_observed|1
file|fresh|crates/whipplescript-kernel/src/effect_handlers.rs|run_file_import_effect_generic|start_dispatch_observed|1
export|fresh|crates/whipplescript-kernel/src/effect_handlers.rs|run_file_export_effect_generic|start_dispatch_observed|1
tracker|fresh|crates/whipplescript-kernel/src/tracker_closure.rs|run|start_dispatch_observed|1
tracker|fresh|crates/whipplescript-kernel/src/tracker_control.rs|run|start_dispatch_observed|1
tracker|fresh|crates/whipplescript-kernel/src/tracker_filing.rs|run|start_dispatch_observed|1
tracker|fresh|crates/whipplescript-kernel/src/resolution_recording.rs|run|start_dispatch_observed|1
tracker|legacy|crates/whipplescript-kernel/src/effect_handlers.rs|run_queue_effect_generic|start_run|1
tool|legacy|crates/whipplescript-kernel/src/effect_handlers.rs|run_capability_effect_generic|start_run|1
coordination|legacy|crates/whipplescript-kernel/src/effect_handlers.rs|fail_coordination_effect|start_run|1
coordination|legacy|crates/whipplescript-kernel/src/effect_handlers.rs|run_coordination_effect_generic_ctx|start_run|1
time|legacy|crates/whipplescript-kernel/src/time_pass.rs|resolve_due_time_effects|start_run|1
provider|legacy|crates/whipplescript-kernel/src/lib.rs|run_agent_turn_with_metadata|start_run|1
provider|legacy|crates/whipplescript-kernel/src/lib.rs|run_brokered_agent_turn|start_run|1
provider|legacy|crates/whipplescript-kernel/src/lib.rs|run_coerce|start_run|1
provider|legacy|crates/whipplescript-kernel/src/lib.rs|run_native_agent_turn_with_metadata|start_run|1
provider|legacy|crates/whipplescript-cli/src/main.rs|cancel_coerce_effect|start_run|1
process|legacy|crates/whipplescript-cli/src/main.rs|run_exec_effect|start_run_for_admission|1
norm|legacy|crates/whipplescript-cli/src/norm_exec_native.rs|execute|start_run_for_admission|1
norm|legacy|crates/whipplescript-cli/src/native_executor/norm_admission.rs|admit_at|start_run_for_admission|1
topology|legacy|crates/whipplescript-cli/src/main.rs|run_workflow_invoke_effect|start_run|2
custody|legacy|crates/whipplescript-cli/src/main.rs|run_custody_lifecycle_effect|start_run|1
custody|legacy|crates/whipplescript-cli/src/main.rs|run_custody_mint_effect|start_run|1
custody|legacy|crates/whipplescript-cli/src/main.rs|run_custody_request_effect|start_run|1
provider|legacy|crates/whipplescript-host-do/src/do_instance.rs|run_effect|start_run|4
process|legacy|crates/whipplescript-host-do/src/do_instance.rs|run_effect|start_run_for_admission|1
door|door|crates/whipplescript-kernel/src/lib.rs|start_run_selected|start_run|1
door|door|crates/whipplescript-kernel/src/lib.rs|start_run_selected|start_run_for_admission|1
door|door|crates/whipplescript-kernel/src/lib.rs|start_dispatch|start_dispatch|1
door|door|crates/whipplescript-kernel/src/lib.rs|start_dispatch_observed|start_dispatch_observed|1
"""

PRIMITIVE = re.compile(r"\.\s*(start_run|start_run_for_admission|start_dispatch|start_dispatch_observed)\s*\(")
STATUS_OF = {
    "start_dispatch_observed": "fresh",
    "start_dispatch": "fresh",
    "start_run": "legacy",
    "start_run_for_admission": "legacy",
}


RAW_STRING = re.compile(r'b?r(#*)"')


def blank(source):
    """Source with comments and string/char literal bodies replaced by spaces
    (newlines kept), so braces and names inside them are not code."""
    out = []
    i, n = 0, len(source)
    keep = lambda text: "".join("\n" if c == "\n" else " " for c in text)
    while i < n:
        c = source[i]
        if source.startswith("//", i):
            j = source.find("\n", i)
            j = n if j < 0 else j
            out.append(keep(source[i:j]))
            i = j
        elif source.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if source.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif source.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            out.append(keep(source[i:j]))
            i = j
        elif (m := RAW_STRING.match(source, i)) and (i == 0 or not (source[i - 1].isalnum() or source[i - 1] == "_")):
            close = '"' + m.group(1)
            j = source.find(close, m.end())
            j = n if j < 0 else j + len(close)
            out.append(keep(source[i:j]))
            i = j
        elif c == '"' or (c == "b" and source.startswith('b"', i) and (i == 0 or not (source[i - 1].isalnum() or source[i - 1] == "_"))):
            j = i + (2 if c == "b" else 1)
            while j < n and source[j] != '"':
                j += 2 if source[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(keep(source[i:j]))
            i = j
        elif c == "'":
            if source.startswith("\\", i + 1):
                j = source.find("'", i + 2)
                j = n if j < 0 else j + 1
            elif i + 2 < n and source[i + 2] == "'":
                j = i + 3
            else:
                out.append(c)  # a lifetime
                i += 1
                continue
            out.append(keep(source[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


TEST_CFG = re.compile(r"#\s*\[\s*cfg\s*\((.*?)\)\s*\]", re.S)


def is_test_cfg(body):
    return re.search(r"\btest\b", re.sub(r"not\s*\([^()]*\)", "", body)) is not None


def scan(path, source):
    """Return (function, primitive) for every production call, the module
    files declared under a test cfg, and every module file declared."""
    code = blank(source)
    raw_paths = {m.start(): m.group(1) for m in re.finditer(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]', source)}
    calls, test_files, children = [], set(), set()
    stack = [(None, False)]  # (function, test)
    pending_test = False
    pending_fn = None
    pending_path = None
    pending_mod = None
    # A file's child modules live beside it (lib.rs, main.rs, mod.rs) or in
    # the directory named after it.
    home = path.parent if path.name in ("lib.rs", "main.rs", "mod.rs") else path.with_suffix("")
    token = re.compile(r"#\s*\[\s*cfg\s*\(|#\s*\[\s*path\b|\bmod\s+(\w+)|\bfn\s+(\w+)|[{};]|" + PRIMITIVE.pattern)
    for m in token.finditer(code):
        text = m.group(0)
        if text.startswith("#") and "cfg" in text:
            attr = TEST_CFG.match(code, m.start())
            if attr and is_test_cfg(attr.group(1)):
                pending_test = True
        elif text.startswith("#"):
            pending_path = raw_paths.get(m.start())
        elif m.group(1):
            pending_mod = m.group(1)
        elif m.group(2):
            pending_fn = m.group(2)
        elif text == "{":
            fn, test = stack[-1]
            stack.append((pending_fn or fn, test or pending_test))
            pending_test, pending_fn, pending_path, pending_mod = False, None, None, None
        elif text == "}":
            if len(stack) > 1:
                stack.pop()
        elif text == ";":
            declared = set()
            if pending_path:
                declared.add((path.parent / pending_path).resolve())
            elif pending_mod:
                declared.add((home / f"{pending_mod}.rs").resolve())
                declared.add((home / pending_mod / "mod.rs").resolve())
            children |= declared
            if pending_test or stack[-1][1]:
                test_files |= declared
            pending_test, pending_fn, pending_path, pending_mod = False, None, None, None
        else:
            fn, test = stack[-1]
            if not test:
                calls.append((fn, m.group(3)))
    return calls, test_files, children


def tracked_sources(root):
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "--", "crates/*.rs"],
        cwd=root, check=True, capture_output=True, text=True,
    ).stdout.split()
    for name in sorted(set(listed)):
        parts = name.split("/")
        if {"tests", "examples", "benches"} & set(parts):
            continue
        if name.startswith("crates/whipplescript-store/") or name.startswith(
            "crates/whipplescript-host-do/src/do_store"
        ):
            continue
        if (root / name).is_file():
            yield name


def observe(root):
    counts, test_files = {}, set()
    scanned, children = {}, {}
    for name in tracked_sources(root):
        calls, tests, declared = scan(root / name, (root / name).read_text())
        test_files |= tests
        resolved = (root / name).resolve()
        scanned[resolved] = (name, calls)
        children[resolved] = declared
    # A module declared by a test-only file is test-only too.
    frontier = list(test_files)
    while frontier:
        for child in children.get(frontier.pop(), ()):
            if child not in test_files:
                test_files.add(child)
                frontier.append(child)
    for resolved, (name, calls) in scanned.items():
        if resolved in test_files:
            continue
        for fn, primitive in calls:
            key = (name, fn or "<module>", primitive)
            counts[key] = counts.get(key, 0) + 1
    return counts


def parse_inventory(text):
    rows, problems = {}, []
    for line in text.splitlines():
        family, status, name, fn, primitive, count = line.split("|")
        key = (name, fn, primitive)
        if key in rows:
            problems.append(f"duplicate inventory row: {line}")
        if family not in FAMILIES:
            problems.append(f"unknown family `{family}`: {line}")
        expected = "door" if family == "door" else STATUS_OF.get(primitive)
        if status != expected:
            problems.append(f"`{primitive}` is {expected} dispatch, not {status}: {line}")
        if family in MIGRATED and status != "fresh":
            problems.append(f"migrated family `{family}` must take fresh governed dispatch: {line}")
        rows[key] = (family, status, int(count))
    return rows, problems


def check(root=ROOT, inventory=INVENTORY):
    rows, problems = parse_inventory(inventory)
    observed = observe(root)
    for key, count in sorted(observed.items()):
        if key not in rows:
            problems.append(
                f"> {'|'.join(key)}|{count}: an unclassified run-starting function; "
                "add it to the inventory with its family"
            )
        elif rows[key][2] != count:
            problems.append(f"> {'|'.join(key)}|{count}: pinned {rows[key][2]}")
    for key, (_, _, count) in sorted(rows.items()):
        if key not in observed:
            problems.append(f"< {'|'.join(key)}|{count}: the tree no longer has this run start")
    return problems


def main():
    problems = check()
    if problems:
        print("governed-operations inventory: the run-start table changed (HA-4).", file=sys.stderr)
        print(file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(file=sys.stderr)
        print("  Classify every run-starting function in scripts/check-governed-operations.py;", file=sys.stderr)
        print("  a migrated family must keep fresh observed dispatch.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
