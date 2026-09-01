#!/usr/bin/env node
// The Durable Object's table layout is written out three times, and nothing
// checked that the three agreed.
//
//   1. crates/whipplescript-host-do/worker/do_schema.sql
//      what a FRESH production object is provisioned with.
//   2. crates/whipplescript-host-do/src/do_store.rs, the `r#"..."#` block in the
//      test-support `store()` fn — what every Rust-side DO test runs against.
//   3. crates/whipplescript-host-do/worker/src/index.ts, the lazy
//      `ALTER TABLE ... ADD COLUMN` / `CREATE TABLE IF NOT EXISTS` block — what
//      upgrades an object an EARLIER deploy created.
//
// (2) drifting from (1) is the dangerous one: the Rust tests prove things about
// a schema production does not have, so they go green over a store that cannot
// run. DR-0077 added `instance_revisions.rule_carries_json` to (2) alone; the
// column is read on every rule pass, so every step failed, and it surfaced as
// eight session-integration tests reporting 502 with nothing naming a column.
// Worse and older, and found by this check: `register_skill` has been inserting
// into `skills(body)` while (1) never declared that column, so the write could
// only ever have failed on a real object.
//
// (3) drifting is quieter still — nothing in the suite provisions an object from
// an older deploy, so a missing lazy add fails no test at all and waits for
// production. That half is checked differentially, against the merge base:
// a column this change adds to (1) must also be added lazily in (3).
//
// Run standalone to check the tree; `--selftest` runs the parsers and both
// rules over fixtures, so the checker's own logic is guarded too.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const WORKER_SCHEMA = "crates/whipplescript-host-do/worker/do_schema.sql";
const RUST_STORE = "crates/whipplescript-host-do/src/do_store.rs";
const WORKER_INDEX = "crates/whipplescript-host-do/worker/src/index.ts";

// A clause that opens with one of these is a TABLE constraint, not a column.
const TABLE_CONSTRAINT = /^(PRIMARY|UNIQUE|CHECK|FOREIGN|CONSTRAINT)\b/i;
const BARE_IDENTIFIER = /^[a-z][a-z0-9_]*$/;

/// Split a table body on its top-level commas. Parens matter (a column may
/// carry `CHECK (kind IN ('a', 'b'))`, whose commas are not column separators)
/// and so do single-quoted literals (a DEFAULT may contain either).
export function splitTopLevel(body) {
  const parts = [];
  let depth = 0;
  let quoted = false;
  let current = "";
  for (const ch of body) {
    if (quoted) {
      current += ch;
      if (ch === "'") quoted = false;
      continue;
    }
    if (ch === "'") {
      quoted = true;
      current += ch;
      continue;
    }
    if (ch === "(") depth += 1;
    if (ch === ")") depth -= 1;
    if (ch === "," && depth === 0) {
      parts.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim()) parts.push(current);
  return parts;
}

/// Every `CREATE TABLE` in `sql`, as table name -> set of column names. Types
/// and constraints are deliberately NOT compared: the two schemas legitimately
/// differ there (the worker carries CHECK constraints the Rust fixture does
/// not), and a check that failed on those would be turned off rather than
/// obeyed. What must agree is which columns exist.
export function parseTables(sql) {
  const text = sql.replace(/--[^\n]*/g, "");
  const tables = new Map();
  const opener = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(/gi;
  let match;
  while ((match = opener.exec(text)) !== null) {
    const name = match[1];
    let depth = 1;
    let index = opener.lastIndex;
    let quoted = false;
    while (index < text.length && depth > 0) {
      const ch = text[index];
      if (quoted) {
        if (ch === "'") quoted = false;
      } else if (ch === "'") quoted = true;
      else if (ch === "(") depth += 1;
      else if (ch === ")") depth -= 1;
      index += 1;
    }
    const columns = splitTopLevel(text.slice(opener.lastIndex, index - 1))
      .map((clause) => clause.trim())
      .filter((clause) => clause && !TABLE_CONSTRAINT.test(clause))
      .map((clause) => clause.split(/\s+/)[0]);
    if (!tables.has(name)) tables.set(name, new Set());
    for (const column of columns) tables.get(name).add(column);
  }
  return tables;
}

/// The bootstrap schema the Rust DO tests provision, which is the raw string
/// holding `CREATE TABLE schema_migrations`. Anchoring on that statement rather
/// than on a line number keeps the narrower single-table fixtures elsewhere in
/// the file (a legacy-object test builds one `events` table on purpose) out of
/// the comparison.
export function rustBootstrapSchema(source) {
  const anchor = source.indexOf("CREATE TABLE schema_migrations");
  if (anchor === -1) return null;
  const start = source.lastIndexOf('r#"', anchor);
  const end = source.indexOf('"#', anchor);
  if (start === -1 || end === -1) return null;
  return source.slice(start + 3, end);
}

/// The (table, column) pairs the lazy-upgrade block adds to an object an
/// earlier deploy created. Two spellings are in use: a literal
/// `ALTER TABLE t ADD COLUMN c ...`, and a loop whose `ALTER` interpolates a
/// definition from an array of names just above it. Both are read, because a
/// check that only understood the first would pass a change that used the
/// second and mean nothing.
export function lazyColumnAdds(source) {
  const adds = new Map();
  const add = (table, column) => {
    if (!adds.has(table)) adds.set(table, new Set());
    adds.get(table).add(column);
  };
  const literal = /ALTER\s+TABLE\s+([A-Za-z_][A-Za-z0-9_]*)\s+ADD\s+COLUMN\s+([A-Za-z_][A-Za-z0-9_]*)/gi;
  let match;
  while ((match = literal.exec(source)) !== null) add(match[1], match[2]);

  const templated = /ALTER\s+TABLE\s+([A-Za-z_][A-Za-z0-9_]*)\s+ADD\s+COLUMN\s+\$\{/gi;
  while ((match = templated.exec(source)) !== null) {
    const table = match[1];
    // The names being looped over sit between the enclosing `for (` and this
    // statement. Only bare identifiers count, so the `"c TEXT NOT NULL"`
    // definition half of a `[name, definition]` pair contributes nothing.
    const loop = source.lastIndexOf("for (", match.index);
    if (loop === -1) continue;
    for (const quoted of source.slice(loop, match.index).matchAll(/"([^"]+)"/g)) {
      if (BARE_IDENTIFIER.test(quoted[1])) add(table, quoted[1]);
    }
  }
  return adds;
}

/// The tables the lazy-upgrade block provisions whole.
export function lazyCreatedTables(source) {
  const created = new Set();
  const re = /CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+([A-Za-z_][A-Za-z0-9_]*)/gi;
  let match;
  while ((match = re.exec(source)) !== null) created.add(match[1]);
  return created;
}

/// Rule 1. Everything the Rust fixture declares must exist in the production
/// schema. Only that direction: production may legitimately carry tables the
/// Rust store never queries (`inbox_items` and `public_turn_binding` are the
/// worker's own), and forcing those into a test fixture would be noise standing
/// in for coverage.
export function fixtureDrift(rustTables, workerTables) {
  const findings = [];
  for (const [table, columns] of rustTables) {
    if (!workerTables.has(table)) {
      findings.push(`table \`${table}\` is in ${RUST_STORE} but not ${WORKER_SCHEMA}`);
      continue;
    }
    const production = workerTables.get(table);
    for (const column of columns) {
      if (!production.has(column)) {
        findings.push(
          `\`${table}.${column}\` is in ${RUST_STORE} but not ${WORKER_SCHEMA}: ` +
            `the Rust DO tests exercise a column a fresh object does not have`,
        );
      }
    }
  }
  return findings;
}

/// Rule 2. What this change adds to the production schema must also reach an
/// object an earlier deploy created.
export function upgradeGaps(baseTables, headTables, adds, createdLazily) {
  const findings = [];
  for (const [table, columns] of headTables) {
    if (!baseTables.has(table)) {
      if (!createdLazily.has(table)) {
        findings.push(
          `table \`${table}\` is new in ${WORKER_SCHEMA} but ${WORKER_INDEX} has no ` +
            `\`CREATE TABLE IF NOT EXISTS ${table}\`: an object from an earlier deploy never gets it`,
        );
      }
      continue;
    }
    const before = baseTables.get(table);
    for (const column of columns) {
      if (before.has(column)) continue;
      if (adds.get(table)?.has(column)) continue;
      findings.push(
        `\`${table}.${column}\` is new in ${WORKER_SCHEMA} but ${WORKER_INDEX} never adds it: ` +
          `an object from an earlier deploy fails every read that names it`,
      );
    }
  }
  return findings;
}

function mergeBaseSchema() {
  try {
    execFileSync("git", ["rev-parse", "--verify", "origin/main"], { stdio: "ignore" });
  } catch {
    return null;
  }
  let base;
  try {
    base = execFileSync("git", ["merge-base", "origin/main", "HEAD"], {
      encoding: "utf8",
    }).trim();
  } catch {
    // origin/main exists but shares no reachable ancestor with HEAD — the
    // depth-1 CI checkout, where the decision-record gate fetches the ref as a
    // shallow tip earlier in check.sh. Before that fetch this function bailed
    // on the rev-parse above; a base the history cannot reach is the same
    // condition, so it degrades the same way rather than crashing the gate.
    return null;
  }
  try {
    return execFileSync("git", ["show", `${base}:${WORKER_SCHEMA}`], { encoding: "utf8" });
  } catch {
    return null; // the schema file did not exist at the base
  }
}

function selftest() {
  const cases = [];
  const check = (name, actual, expected) => {
    const ok = JSON.stringify(actual) === JSON.stringify(expected);
    cases.push({ name, ok, actual, expected });
  };

  // A CHECK constraint's commas are not column separators, a quoted DEFAULT's
  // parens are not nesting, and a table-level UNIQUE is not a column.
  const parsed = parseTables(`
    CREATE TABLE t (
      a TEXT PRIMARY KEY,
      b TEXT NOT NULL CHECK (b IN ('x', 'y')),
      c TEXT NOT NULL DEFAULT '(,)',
      UNIQUE(a, b)
    );
  `);
  check("columns, not constraints", [...parsed.get("t")], ["a", "b", "c"]);

  check(
    "comments are stripped",
    [...parseTables("CREATE TABLE t (\n a TEXT, -- b TEXT\n c TEXT\n);").get("t")],
    ["a", "c"],
  );

  check(
    "IF NOT EXISTS parses",
    [...parseTables("CREATE TABLE IF NOT EXISTS t (a TEXT);").keys()],
    ["t"],
  );

  check(
    "the bootstrap block is the one anchored on schema_migrations",
    rustBootstrapSchema('x(r#"\n CREATE TABLE schema_migrations (v INT);\n"#);').trim(),
    "CREATE TABLE schema_migrations (v INT);",
  );

  check(
    "a literal lazy add is read",
    [...lazyColumnAdds("sql.exec(`ALTER TABLE t ADD COLUMN c TEXT`)").get("t")],
    ["c"],
  );

  check(
    "a templated lazy add is read from its loop",
    [
      ...lazyColumnAdds(
        'for (const [column, definition] of [["c", "c TEXT NOT NULL"]] as const) {\n' +
          "  sql.exec(`ALTER TABLE t ADD COLUMN ${definition}`);\n}",
      ).get("t"),
    ],
    ["c"],
  );

  const rust = new Map([["t", new Set(["a", "b"])]]);
  check(
    "a column only the fixture has is a finding",
    fixtureDrift(rust, new Map([["t", new Set(["a"])]])).length,
    1,
  );
  check(
    "a table only production has is not",
    fixtureDrift(rust, new Map([["t", new Set(["a", "b"])], ["u", new Set(["a"])]])),
    [],
  );

  const base = new Map([["t", new Set(["a"])]]);
  const head = new Map([["t", new Set(["a", "b"])], ["u", new Set(["a"])]]);
  check(
    "a new column with no lazy add is a finding",
    upgradeGaps(base, head, new Map(), new Set(["u"])).length,
    1,
  );
  check(
    "a new column with a lazy add is not",
    upgradeGaps(base, head, new Map([["t", new Set(["b"])]]), new Set(["u"])),
    [],
  );
  check(
    "a new table with no lazy create is a finding",
    upgradeGaps(base, head, new Map([["t", new Set(["b"])]]), new Set()).length,
    1,
  );

  const failed = cases.filter((c) => !c.ok);
  for (const c of failed) {
    console.error(`selftest FAILED: ${c.name}`);
    console.error(`  expected ${JSON.stringify(c.expected)}`);
    console.error(`  actual   ${JSON.stringify(c.actual)}`);
  }
  if (failed.length) process.exit(1);
  console.log(`do-schema selftest: ${cases.length} cases passed`);
}

if (process.argv.includes("--selftest")) {
  selftest();
  process.exit(0);
}

const workerTables = parseTables(readFileSync(WORKER_SCHEMA, "utf8"));
const rustSource = readFileSync(RUST_STORE, "utf8");
const bootstrap = rustBootstrapSchema(rustSource);
if (bootstrap === null) {
  console.error(
    `could not find the bootstrap schema in ${RUST_STORE}; it is anchored on the ` +
      "raw string containing `CREATE TABLE schema_migrations`",
  );
  process.exit(1);
}
const rustTables = parseTables(bootstrap);
const indexSource = readFileSync(WORKER_INDEX, "utf8");

const findings = fixtureDrift(rustTables, workerTables);

const baseSchema = mergeBaseSchema();
let differential;
if (baseSchema === null) {
  differential = `skipped (no origin/main, or ${WORKER_SCHEMA} is new)`;
} else {
  findings.push(
    ...upgradeGaps(
      parseTables(baseSchema),
      workerTables,
      lazyColumnAdds(indexSource),
      lazyCreatedTables(indexSource),
    ),
  );
  differential = "checked against the merge base";
}

if (findings.length) {
  console.error("durable object schema sources disagree:");
  for (const finding of findings) console.error(`  - ${finding}`);
  process.exit(1);
}

console.log(
  `durable object schema: ${workerTables.size} tables in the production schema, ` +
    `${rustTables.size} in the Rust fixture, all present; lazy upgrades ${differential}`,
);
