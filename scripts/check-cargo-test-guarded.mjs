#!/usr/bin/env node
// Enforcement lint for the `cargo_test_named` guard (findings 5.1, 5.2, 5.3).
//
// `cargo test <filter>` exits 0 when the filter matches nothing, so a gate built
// on a raw filtered run keeps passing after the test it names is renamed, moved,
// or deleted — it silently stops asserting anything (the DR-0024 failure that
// scripts/lib-cargo-test.sh's cargo_test_named was written to close). That guard
// only helps where it is adopted, and nothing stopped a new gate script from
// reintroducing a raw filtered run. This static lint is that missing control: it
// scans the tracked gate scripts and fails on any `cargo test` that carries a
// positional test-name (or prefix) filter without going through cargo_test_named.
//
// Exempt by construction, because they carry no filter to guard:
//   - `cargo test --workspace`            (whole workspace)
//   - `cargo test -p <pkg> --lib`         (whole lib, no name)
//   - `cargo test ... --test <name>`      (a whole integration-test target)
//   - `cargo test ... --no-run`           (compile only)
// A converted call (`cargo_test_named ...`) contains no `cargo test ` token and
// is never considered.
//
// Run standalone to lint the tree; `--selftest` runs the classifier over
// fixtures so the classifier's own logic is guarded too.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

// Flags that take a following value; the value must be consumed so a bare
// package/target/name token (e.g. `-p whipplescript`, `--test control_plane`,
// both of which look like positional filters) is not itself flagged.
const VALUE_FLAGS = new Set([
  "-p",
  "--package",
  "--manifest-path",
  "--test",
  "--bin",
  "--bench",
  "--example",
  "--features",
  "--target",
  "--profile",
  "-j",
  "--jobs",
]);

// Shell operators that end the cargo command inside a larger logical line
// (e.g. an embedded `bash -c "cd X && cargo test ... && node ..."`), so trailing
// command words are not mistaken for a test filter.
const COMMAND_TERMINATORS = new Set(["&&", "||", ";", "|", ">", ">>", "&", "2>&1"]);

const POSITIONAL = /^[a-z][a-z0-9_]*$/;

// Classify the region of a logical line that starts at its first `cargo test `.
// Returns the offending positional token, or null when the run carries no
// name/prefix filter (and is therefore already safe or exempt).
export function classify(logicalLine) {
  const marker = "cargo test ";
  const at = logicalLine.indexOf(marker);
  if (at === -1) return null; // no raw `cargo test ` (cargo_test_named has none)

  const region = logicalLine.slice(at + marker.length);
  const tokens = region.split(/\s+/).filter((t) => t.length > 0);

  for (let i = 0; i < tokens.length; i++) {
    const raw = tokens[i];
    if (raw === "--") break; // everything after `--` is test-harness args
    if (COMMAND_TERMINATORS.has(raw)) break; // end of this cargo command

    if (VALUE_FLAGS.has(raw)) {
      i++; // consume the flag's value
      continue;
    }
    if (raw.startsWith("-")) continue; // any other flag, incl. --flag=val

    // A bare positional. Strip surrounding quotes and one trailing quote left by
    // an enclosing shell string, then decide.
    const token = raw.replace(/^['"]/, "").replace(/['"]$/, "");
    if (POSITIONAL.test(token)) return token;
    // Anything else (a variable like $filter, a path, a `::`-qualified name, an
    // upper-case env token) is not a bare lower-case filter; keep scanning.
  }
  return null;
}

// Join backslash-continued physical lines into logical lines, dropping comments.
// Yields { startLine, text } with startLine 1-indexed at the first physical line.
function* logicalLines(source) {
  const physical = source.split("\n");
  let i = 0;
  while (i < physical.length) {
    const startLine = i + 1;
    let text = physical[i];
    while (text.endsWith("\\") && i + 1 < physical.length) {
      text = text.slice(0, -1) + " " + physical[i + 1];
      i++;
    }
    i++;
    if (text.trimStart().startsWith("#")) continue; // whole-line comment (prose)
    yield { startLine, text };
  }
}

// file:line entries known to be unconvertible; empty by design. Add an entry
// only when a genuinely unconvertible site emerges, with a comment saying why.
const SKIP = new Set([]);

function lintTree() {
  const files = execFileSync("git", ["ls-files", "scripts/*.sh"], {
    encoding: "utf8",
  })
    .split("\n")
    .map((f) => f.trim())
    .filter((f) => f.length > 0);

  const violations = [];
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    for (const { startLine, text } of logicalLines(source)) {
      const token = classify(text);
      if (token !== null && !SKIP.has(`${file}:${startLine}`)) {
        violations.push({ file, line: startLine, token });
      }
    }
  }

  if (violations.length > 0) {
    console.error(
      "raw filtered `cargo test` found in gate scripts (findings 5.1/5.2/5.3):",
    );
    for (const v of violations) {
      console.error(`  ${v.file}:${v.line}  filter \`${v.token}\``);
    }
    console.error(
      "a filtered `cargo test` must go through cargo_test_named " +
        "(scripts/lib-cargo-test.sh) so a zero-match fails instead of exiting 0.",
    );
    process.exit(1);
  }
  console.log(
    `cargo-test guard: ${files.length} gate scripts scanned, no raw filtered cargo test`,
  );
}

function selftest() {
  const cases = [
    ["cargo test -p whipplescript foo_bar", "foo_bar"],
    [
      'cargo test --quiet --manifest-path X -p whipplescript --test control_plane foo',
      "foo",
    ],
    ["cargo_test_named whipplescript foo --test control_plane", null],
    ["cargo test --workspace", null],
    ["cargo test -p whipplescript-custodian --test openbao_live --no-run", null],
    ["cargo test -p whipplescript-provider-claude --lib", null],
    // Extra guards for the shapes this repo actually carries:
    [
      'cargo test --quiet --manifest-path "$ROOT/Cargo.toml" -p whipplescript --test control_plane step_materializes_minimal_noop_fact',
      "step_materializes_minimal_noop_fact",
    ],
    ["cargo test -p whipplescript-store workspace --lib", "workspace"],
    ["cargo test -p whipplescript --test e2e", null],
    [
      'matched="$(cargo test -q -p "$package" "$@" "$filter" -- --list 2>/dev/null',
      null,
    ],
    [
      "cargo test -p whipplescript-custodian --test openbao_live -- --nocapture",
      null,
    ],
    [
      "run_check required workspace \"cd '$ROOT' && cargo test --workspace\"",
      null,
    ],
    // A `::`-qualified name is not a bare lower-case filter, so it is not caught
    // (documented limit); it is still converted in the scripts by hand.
    ["cargo test --quiet -p whipplescript-kernel --lib -- trace::tests::foo", null],
  ];

  let failed = 0;
  for (const [input, expected] of cases) {
    const got = classify(input);
    const ok = got === expected;
    if (!ok) {
      failed++;
      console.error(
        `selftest FAIL: classify(${JSON.stringify(input)}) => ${JSON.stringify(
          got,
        )}, expected ${JSON.stringify(expected)}`,
      );
    }
  }
  if (failed > 0) {
    console.error(`cargo-test guard selftest: ${failed} case(s) failed`);
    process.exit(1);
  }
  console.log(`cargo-test guard selftest: ${cases.length} cases passed`);
}

if (process.argv.includes("--selftest")) {
  selftest();
} else {
  lintTree();
}
