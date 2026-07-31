// Local end-to-end validation of the DO runtime WITHOUT Cloudflare (DR-0033 5d):
// drives the ACTUAL wasm module through the REAL wasm-bindgen boundary, backed by
// real SQLite (node:sqlite) as the DoSqlBridge. This is the live worker path minus
// only Cloudflare's `state.storage.sql` (swapped for node:sqlite) + `wrangler deploy`.
const assert = require("node:assert");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
const { WasmDurableInstance } = require("./pkg/whipplescript_host_do.js");

const schema = fs.readFileSync(path.join(__dirname, "do_schema.sql"), "utf8");

// A fresh DO SQLite + the DoSqlBridge the wasm core imports.
function freshInstanceEnv(seedSql) {
  const db = new DatabaseSync(":memory:");
  db.exec(schema);
  for (const stmt of seedSql) db.exec(stmt);
  const bridge = {
    exec(sql, paramsJson) {
      const params = JSON.parse(paramsJson);
      return Number(db.prepare(sql).run(...params).changes);
    },
    query(sql, paramsJson) {
      const params = JSON.parse(paramsJson);
      const rows = db.prepare(sql).all(...params);
      // Positional in SELECT order; BigInt -> Number so JSON.stringify is safe.
      const positional = rows.map((row) =>
        Object.values(row).map((v) => (typeof v === "bigint" ? Number(v) : v)),
      );
      return JSON.stringify(positional);
    },
  };
  return { bridge, db };
}

// 1) An effect-free workflow drives to a terminal in one step.
function testEffectFree() {
  const source = [
    "workflow MinimalNoop", "", "output result StartupSeen", "",
    'class StartupSeen {', "  source string", '  state "observed"', "}", "",
    "rule observe_start", "  when started", "=> {",
    '  record StartupSeen {', '    source "external.started"', '    state "observed"', "  }", "",
    "  complete result {", '    source "external.started"', '    state "observed"', "  }", "}",
  ].join("\n");
  const { bridge } = freshInstanceEnv([]);
  const inst = WasmDurableInstance.create(bridge, source, "{}", "local/MinimalNoop", undefined, undefined, undefined);
  const outcome = JSON.parse(inst.step(undefined, Date.now()));
  assert.strictEqual(outcome.kind, "terminal", `effect-free: ${JSON.stringify(outcome)}`);
  assert.strictEqual(inst.status(), "completed");
  console.log("PASS  effect-free workflow -> completed (one step)");
}

// 2) A coerce workflow SUSPENDS on fetch and RESUMES to a terminal across two
//    separate step() calls -- the real durable-object sans-IO pattern, through wasm.
function testCoerceSuspendResume() {
  const source = [
    "workflow CoerceScore", "", "output result Decision", "",
    "class Decision {", "  score float", "}", "",
    "coerce scoreIt() -> Decision {", '  prompt """', "  Score it.", "  {{ ctx.output_format }}", '  """', "}", "",
    "rule go", "  when started", "=> {", "  coerce scoreIt() as review",
    "  after review succeeds as decision {", "    complete result { score decision.score }", "  }",
    "  after review fails {", "    complete result { score 0.0 }", "  }", "}",
  ].join("\n");
  const seed = [
    "INSERT INTO capability_schemas (capability, description, schema_json) VALUES ('schema.coerce', 'Coerce.', '{}')",
    "INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) VALUES ('provider_coerce_builtin', 'schema.coerce', 'builtin-coerce', 'schema.coerce', '{}')",
    "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) VALUES ('binding_coerce_builtin', NULL, 'schema.coerce', 'builtin-coerce', '{}')",
  ];
  const { bridge } = freshInstanceEnv(seed);
  const coerceConfig = JSON.stringify({
    provider: "anthropic", base_url: "https://api.anthropic.com",
    api_key: "test-key", model: "claude-test", max_tokens: 1024,
  });
  const inst = WasmDurableInstance.create(bridge, source, "{}", "local/CoerceScore", coerceConfig, undefined, undefined);

  // First step: the coerce effect suspends on `fetch`.
  const first = JSON.parse(inst.step(undefined, Date.now()));
  assert.strictEqual(first.kind, "needs_http", `coerce step1: ${JSON.stringify(first)}`);
  assert.ok(first.request.url.includes("anthropic"), "request targets the provider");

  // The shell performs the fetch; feed a canned Anthropic structured output back.
  const response = JSON.stringify({
    status: 200,
    body: {
      content: [{ type: "tool_use", name: "Decision", input: { score: 0.9 } }],
      usage: { input_tokens: 1, output_tokens: 1 },
    },
  });
  const second = JSON.parse(inst.step(response, Date.now()));
  assert.strictEqual(second.kind, "terminal", `coerce step2: ${JSON.stringify(second)}`);
  assert.strictEqual(inst.status(), "completed");
  console.log("PASS  coerce workflow -> needs_http -> (fetch) -> terminal (two steps)");
}

// 3) An AGENT workflow: the multi-round turn's first model call SUSPENDS on fetch
//    (the real Anthropic messages request the MessagesApiClient built), and a canned
//    final reply RESUMES it to a terminal -- the agent counterpart to (2), through wasm.
function testAgentSuspendResume() {
  const source = [
    "workflow AgentDemo", "", "output result Done", "",
    "class Done {", "  ok int", "}", "",
    "agent helper {", "  provider owned", '  profile "repo-reader"', "  capacity 1", "}", "",
    "rule go", "  when started", "=> {", '  tell helper as reply """', "  Do the thing.", '  """', "",
    "  after reply succeeds {", "    complete result { ok 1 }", "  }", "",
    "  after reply fails {", "    complete result { ok 0 }", "  }", "}",
  ].join("\n");
  const seed = [
    "INSERT INTO capability_schemas (capability, description, schema_json) VALUES ('agent.tell', 'Run an agent turn.', '{}')",
    "INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) VALUES ('provider_agent_tell_builtin', 'agent.tell', 'builtin-agent-harness', 'agent.tell', '{}')",
    "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) VALUES ('binding_agent_tell_builtin', NULL, 'agent.tell', 'builtin-agent-harness', '{}')",
    "INSERT INTO profiles (profile_id, name, description, enforcement_mode, allowed_capabilities, config_json) VALUES ('profile_repo_reader', 'repo-reader', 'reads', 'enforce', '[\"agent.tell\"]', '{}')",
  ];
  const { bridge } = freshInstanceEnv(seed);
  const agentConfig = JSON.stringify({
    provider: "anthropic", base_url: "https://api.anthropic.com",
    api_key: "test-key", model: "claude-test", max_tokens: 4096,
  });
  const inst = WasmDurableInstance.create(bridge, source, "{}", "local/AgentDemo", undefined, agentConfig, undefined);

  // First step: the agent turn's first model call suspends on `fetch`.
  const first = JSON.parse(inst.step(undefined, Date.now()));
  assert.strictEqual(first.kind, "needs_http", `agent step1: ${JSON.stringify(first)}`);
  assert.ok(first.request.url.endsWith("/v1/messages"), "request targets the messages endpoint");

  // The shell performs the fetch; feed a canned Anthropic final reply (no tool calls).
  const response = JSON.stringify({
    status: 200,
    body: {
      content: [{ type: "text", text: "did the thing" }],
      usage: { input_tokens: 1, output_tokens: 1 },
    },
  });
  const second = JSON.parse(inst.step(response, Date.now()));
  assert.strictEqual(second.kind, "terminal", `agent step2: ${JSON.stringify(second)}`);
  assert.strictEqual(inst.status(), "completed");
  console.log("PASS  agent workflow -> needs_http -> (fetch) -> terminal (two steps)");
}


// 3b) An AGENT workflow that CALLS A TOOL (DO parity P4): the turn's first model
//     call suspends on fetch; a canned Anthropic `tool_use` reply drives the
//     in-isolate `write` tool (against the DO `files` table over the shared DoSql);
//     the turn then issues the NEXT model call, and a canned final text reply
//     settles it to a terminal. The written bytes land in the `files` table -- the
//     tool executed through the REAL wasm boundary, no fetch for the tool itself.
function testAgentToolCall() {
  const source = [
    "workflow AgentTool", "", "output result Done", "",
    "class Done {", "  ok int", "}", "",
    "agent helper {", "  provider owned", '  profile "repo-writer"', "  capacity 1", "}", "",
    "rule go", "  when started", "=> {", '  tell helper as reply """', "  Write the greeting.", '  """', "",
    "  after reply succeeds {", "    complete result { ok 1 }", "  }", "",
    "  after reply fails {", "    complete result { ok 0 }", "  }", "}",
  ].join("\n");
  const seed = [
    "INSERT INTO capability_schemas (capability, description, schema_json) VALUES ('agent.tell', 'Run an agent turn.', '{}')",
    "INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) VALUES ('provider_agent_tell_builtin', 'agent.tell', 'builtin-agent-harness', 'agent.tell', '{}')",
    "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) VALUES ('binding_agent_tell_builtin', NULL, 'agent.tell', 'builtin-agent-harness', '{}')",
    "INSERT INTO profiles (profile_id, name, description, enforcement_mode, allowed_capabilities, config_json) VALUES ('profile_repo_writer', 'repo-writer', 'writes', 'enforce', '[\"agent.tell\"]', '{}')",
  ];
  const { bridge, db } = freshInstanceEnv(seed);
  const agentConfig = JSON.stringify({
    provider: "anthropic", base_url: "https://api.anthropic.com",
    api_key: "test-key", model: "claude-test", max_tokens: 4096,
  });
  const inst = WasmDurableInstance.create(bridge, source, "{}", "local/AgentTool", undefined, agentConfig, undefined);

  // First step: the agent turn's first model call suspends on `fetch`, and it
  // advertises the DO tool set (P4) built into the messages request.
  const first = JSON.parse(inst.step(undefined, Date.now()));
  assert.strictEqual(first.kind, "needs_http", `agent-tool step1: ${JSON.stringify(first)}`);
  assert.ok(first.request.url.endsWith("/v1/messages"), "request targets the messages endpoint");
  const toolNames = (first.request.body.tools || []).map((t) => t.name);
  assert.ok(toolNames.includes("write"), `write tool is advertised: ${JSON.stringify(toolNames)}`);

  // The shell performs the fetch; feed a canned Anthropic reply that CALLS `write`.
  const toolUse = JSON.stringify({
    status: 200,
    body: {
      content: [{
        type: "tool_use", id: "tc1", name: "write",
        input: { path: "greeting.md", content: "hello from the model" },
      }],
      usage: { input_tokens: 1, output_tokens: 1 },
    },
  });
  // The turn runs `write` in-isolate against DO SQLite, then issues the next call.
  const second = JSON.parse(inst.step(toolUse, Date.now()));
  assert.strictEqual(second.kind, "needs_http", `agent-tool step2: ${JSON.stringify(second)}`);

  // The tool's effect already landed in the `files` table -- keyed flat by path.
  const row = db.prepare("SELECT content FROM files WHERE key = ?").get("greeting.md");
  assert.strictEqual(row && row.content, "hello from the model", "write tool bytes landed in DO SQLite");
  // RC-1 history: the body is captured content-addressed like the file.write effect.
  const blobs = db.prepare("SELECT COUNT(*) AS n FROM content_blobs").get();
  assert.ok(Number(blobs.n) >= 1, "write tool captured an RC-1 history blob");

  // Feed the canned FINAL reply (no tool calls) -> terminal.
  const finalReply = JSON.stringify({
    status: 200,
    body: {
      content: [{ type: "text", text: "wrote the greeting" }],
      usage: { input_tokens: 1, output_tokens: 1 },
    },
  });
  const third = JSON.parse(inst.step(finalReply, Date.now()));
  assert.strictEqual(third.kind, "terminal", `agent-tool step3: ${JSON.stringify(third)}`);
  assert.strictEqual(inst.status(), "completed");
  console.log("PASS  agent workflow -> tool_use (write in-isolate) -> terminal (three steps)");
}

// 4) A Class-A EXEC workflow (compute plane P8): the exec.command effect builds a
//    whip-executor/1 request and SUSPENDS on fetch; the sidecar's canned response
//    RESUMES it to a terminal -- and the delta-kernel cache entry is recorded.
function testExecSuspendResume() {
  const source = [
    "workflow ExecJudge", "", "use std.script", "", "output result Verdict", "",
    "class CheckInput {", "  n int", "}", "",
    "class Verdict {", "  ok int", "}", "",
    "rule seed", "  when started", "=> {", "  record CheckInput { n 1 }", "}", "",
    "rule go", "  when CheckInput as request", "=> {", "  exec judge with request as check", "",
    "  after check succeeds {", "    complete result { ok 1 }", "  }", "",
    "  after check fails {", "    complete result { ok 0 }", "  }", "}",
  ].join("\n");
  const seed = [
    "INSERT INTO capability_schemas (capability, description, schema_json) VALUES ('script.judge', 'Run an operator-pinned script.', '{}')",
    "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) VALUES ('binding_script_judge', NULL, 'script.judge', 'builtin-script', '{}')",
  ];
  const { bridge } = freshInstanceEnv(seed);
  const body = "echo ok\n";
  const sha = crypto.createHash("sha256").update(body).digest("hex");
  const execConfig = JSON.stringify({ base_url: "http://executor:8080", environment_epoch: "test-epoch" });
  const scripts = JSON.stringify([
    { name: "judge", argv: ["sh", "{script}"], sha256: sha, hermetic: true, body },
  ]);
  const inst = WasmDurableInstance.create(
    bridge, source, "{}", "local/ExecJudge",
    undefined, undefined, undefined, execConfig, scripts,
  );

  // First step: the exec effect suspends on the sidecar fetch.
  const first = JSON.parse(inst.step(undefined, Date.now()));
  assert.strictEqual(first.kind, "needs_http", `exec step1: ${JSON.stringify(first)}`);
  assert.ok(first.request.url.endsWith("/exec"), "request targets the executor");
  assert.strictEqual(first.request.body.protocol, "whip-executor/1");
  assert.strictEqual(first.request.body.script_sha256, sha);

  // The shell performs the fetch; feed the sidecar's canned result back.
  const response = JSON.stringify({
    status: 200,
    body: {
      protocol: "whip-executor/1", effect_id: "e", exit_code: 0,
      timed_out: false, stdout: "ok\n", stderr: "",
    },
  });
  const second = JSON.parse(inst.step(response, Date.now()));
  assert.strictEqual(second.kind, "terminal", `exec step2: ${JSON.stringify(second)}`);
  assert.strictEqual(inst.status(), "completed");
  console.log("PASS  exec workflow -> needs_http (whip-executor/1) -> terminal (two steps)");
}


// 5) A Class-B AGENT workflow (compute plane P8): with a turn container
//    configured, the agent turn dispatches WHOLE to the container as one
//    blocking whip-turn/1 round and the outcome settles to a terminal.
function testTurnContainerAgent() {
  const source = [
    "workflow AgentDemo", "", "output result Done", "",
    "class Done {", "  ok int", "}", "",
    "agent helper {", "  provider owned", '  profile "repo-reader"', "  capacity 1", "}", "",
    "rule go", "  when started", "=> {", '  tell helper as reply """', "  Do the thing.", '  """', "",
    "  after reply succeeds {", "    complete result { ok 1 }", "  }", "",
    "  after reply fails {", "    complete result { ok 0 }", "  }", "}",
  ].join("\n");
  const seed = [
    "INSERT INTO capability_schemas (capability, description, schema_json) VALUES ('agent.tell', 'Run an agent turn.', '{}')",
    "INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) VALUES ('provider_agent_tell_builtin', 'agent.tell', 'builtin-agent-harness', 'agent.tell', '{}')",
    "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) VALUES ('binding_agent_tell_builtin', NULL, 'agent.tell', 'builtin-agent-harness', '{}')",
    "INSERT INTO profiles (profile_id, name, description, enforcement_mode, allowed_capabilities, config_json) VALUES ('profile_repo_reader', 'repo-reader', 'reads', 'enforce', '[\"agent.tell\"]', '{}')",
  ];
  const { bridge } = freshInstanceEnv(seed);
  const turnConfig = JSON.stringify({ base_url: "http://turn", provider: { provider: "fixture" } });
  const inst = WasmDurableInstance.create(
    bridge, source, "{}", "local/AgentDemo",
    undefined, undefined, undefined, undefined, undefined, turnConfig,
  );

  // First step: the whole turn dispatches to the per-turn container.
  const first = JSON.parse(inst.step(undefined, Date.now()));
  assert.strictEqual(first.kind, "needs_http", `turn step1: ${JSON.stringify(first)}`);
  assert.ok(first.request.url.endsWith("/turn"), "request targets the turn container");
  assert.strictEqual(first.request.body.protocol, "whip-turn/1");
  assert.strictEqual(first.request.body.tools, "file");
  const turnId = first.request.body.turn_id;

  // The shell performs the (blocking) container round; feed the outcome back.
  const response = JSON.stringify({
    status: 200,
    body: {
      protocol: "whip-turn/1", turn_id: turnId, resumed: false,
      outcome: { status: "completed", summary: "container did the thing", steps: 2, usage: { output_tokens: 3 } },
    },
  });
  const second = JSON.parse(inst.step(response, Date.now()));
  assert.strictEqual(second.kind, "terminal", `turn step2: ${JSON.stringify(second)}`);
  assert.strictEqual(inst.status(), "completed");
  console.log("PASS  agent workflow -> whip-turn/1 container round -> terminal (two steps)");
}

// 6) A FILE-WRITE workflow (P1 — the DO file plane): the file.write effect
//    resolves IN-ISOLATE against DO SQLite (no fetch) — one step to terminal —
//    and the bytes land in the `files` table, with RC-1 content-addressed
//    history captured in `content_blobs`.
function testFileWrite() {
  const source = [
    "workflow FileWrite", "", "output result Done", "",
    "class Done {", "  status string", "}", "",
    'file store out_files {', '  root "/ws"', "}", "",
    "rule pick", "  when started", "=> {",
    '  write text to out_files at "note.md" {', '    body "hello DO"', "    mode create", "  } as written", "",
    "  after written succeeds as result {", '    complete result { status "wrote" }', "  }", "}",
  ].join("\n");
  const { bridge, db } = freshInstanceEnv([]);
  // No files port is configured — P1 wires a real DoFileStore over DO SQLite by
  // default, so file.* effects work with no extra deploy config.
  const inst = WasmDurableInstance.create(bridge, source, "{}", "local/FileWrite", undefined, undefined, undefined);

  const outcome = JSON.parse(inst.step(undefined, Date.now()));
  assert.strictEqual(outcome.kind, "terminal", `file-write: ${JSON.stringify(outcome)}`);
  assert.strictEqual(inst.status(), "completed");

  // The bytes are in the file plane, keyed by the full resolved path.
  const row = db.prepare("SELECT content FROM files WHERE key = ?").get("/ws/note.md");
  assert.strictEqual(row && row.content, "hello DO", "note.md bytes landed in the files table");
  // RC-1: the same bytes are captured content-addressed in the history blobs.
  const blobs = db.prepare("SELECT COUNT(*) AS n FROM content_blobs").get();
  assert.ok(Number(blobs.n) >= 1, "RC-1 history blob captured on the DO");
  console.log("PASS  file-write workflow -> terminal (in-isolate) + bytes in DO SQLite");
}

// 7) CHECKPOINT + RESTORE on the DO (P3): a file-write workflow writes note.md;
//    an operator checkpoint captures the cut; the file plane is then tampered;
//    restore reverts it to the cut content and reports the auto-checkpoint that
//    makes the restore undoable. An unknown cut refuses (throws), mutating
//    nothing.
function testCheckpointRestore() {
  const source = [
    "workflow FileRestore", "", "output result Done", "",
    "class Done {", "  status string", "}", "",
    'file store out_files {', '  root "/ws"', "}", "",
    "rule pick", "  when started", "=> {",
    '  write text to out_files at "note.md" {', '    body "V1"', "    mode create", "  } as written", "",
    "  after written succeeds as result {", '    complete result { status "wrote" }', "  }", "}",
  ].join("\n");
  const { bridge, db } = freshInstanceEnv([]);
  const inst = WasmDurableInstance.create(bridge, source, "{}", "local/FileRestore", undefined, undefined, undefined);
  assert.strictEqual(JSON.parse(inst.step(undefined, Date.now())).kind, "terminal");
  assert.strictEqual(db.prepare("SELECT content FROM files WHERE key = ?").get("/ws/note.md").content, "V1");

  // Operator checkpoint.
  const cp = JSON.parse(inst.checkpoint("cut-1"));
  assert.strictEqual(cp.cut_id, "cut-1");
  assert.strictEqual(cp.file_count, 1, `checkpoint: ${JSON.stringify(cp)}`);

  // Tamper the file plane (drift away from the cut).
  db.exec("UPDATE files SET content = 'TAMPERED' WHERE key = '/ws/note.md'");
  assert.strictEqual(db.prepare("SELECT content FROM files WHERE key = ?").get("/ws/note.md").content, "TAMPERED");

  // Restore: note.md reverts to V1, and the restore is itself undoable.
  const r = JSON.parse(inst.restore("cut-1"));
  assert.strictEqual(r.files_written, 1, `restore: ${JSON.stringify(r)}`);
  assert.strictEqual(r.auto_checkpoint, "auto-before-cut-1");
  assert.strictEqual(
    db.prepare("SELECT content FROM files WHERE key = ?").get("/ws/note.md").content,
    "V1",
    "the DO file plane reverted to the checkpoint content",
  );

  // An unknown cut refuses (throws), with no mutation.
  assert.throws(() => inst.restore("no-such-cut"), /refused/);
  console.log("PASS  checkpoint + restore reverts the DO file plane");
}

// 8) The DO schema provisions EVERY table the tracker store queries (DR-0054
//    Phase A). `do_schema.sql` drifted from the production `do_store.rs`
//    tracker paths — `tracker_aliases` / `tracker_comments` / `tracker_evidence`
//    and the content-addressed `tracker_events.event_id` / `parents_json`
//    columns existed only in the Rust test schema, so every deployed DO failed
//    those reads. This drives the exact production SQL shapes against the
//    bundled schema so a fresh object provably supports them.
function testTrackerSchemaParity() {
  const { db } = freshInstanceEnv([]);
  // The production INSERT shapes (do_store.rs do_tracker_append_raw & co).
  db.prepare(
    "INSERT OR IGNORE INTO tracker_events \
     (event_id, parents_json, issue_id, kind, payload_json, actor, created_at) \
     VALUES (?, ?, ?, ?, ?, ?, ?)",
  ).run("ev-root", "[]", "content-1", "issue.created", "{}", "tester", "2026-07-31 00:00:00");
  // Dedup by event_id relies on the unique index; the same append must be a no-op.
  const dup = db.prepare(
    "INSERT OR IGNORE INTO tracker_events \
     (event_id, parents_json, issue_id, kind, payload_json, actor, created_at) \
     VALUES (?, ?, ?, ?, ?, ?, ?)",
  ).run("ev-root", "[]", "content-1", "issue.created", "{}", "tester", "2026-07-31 00:00:00");
  assert.strictEqual(Number(dup.changes), 0, "tracker_events dedups by event_id");
  db.prepare("INSERT INTO tracker_aliases (content_id, alias) VALUES (?, ?)")
    .run("content-1", "WS-1");
  db.prepare(
    "INSERT OR IGNORE INTO tracker_comments (comment_id, issue_id, author, body, created_at) \
     VALUES (?, ?, ?, ?, ?)",
  ).run("cm-1", "content-1", "tester", "a comment", "2026-07-31 00:00:00");
  db.prepare(
    "INSERT OR IGNORE INTO tracker_evidence \
     (evidence_id, issue_id, kind, reference, note, added_by, created_at) \
     VALUES (?, ?, ?, ?, ?, ?, ?)",
  ).run("evd-1", "content-1", "link", "https://example.test", "note", "tester", "2026-07-31 00:00:00");
  // The production SELECT shapes.
  assert.strictEqual(
    db.prepare("SELECT content_id FROM tracker_aliases WHERE alias = ?").get("WS-1").content_id,
    "content-1",
  );
  assert.strictEqual(
    db.prepare(
      "SELECT comment_id, author, body, created_at FROM tracker_comments \
       WHERE issue_id = ? ORDER BY created_at, comment_id",
    ).get("content-1").comment_id,
    "cm-1",
  );
  assert.strictEqual(
    db.prepare(
      "SELECT evidence_id, kind, reference, note, added_by, created_at \
       FROM tracker_evidence WHERE issue_id = ? ORDER BY created_at, evidence_id",
    ).get("content-1").evidence_id,
    "evd-1",
  );
  const heads = db.prepare(
    "SELECT e.event_id FROM tracker_events e \
     WHERE e.issue_id = ? AND e.event_id IS NOT NULL \
       AND NOT EXISTS ( \
         SELECT 1 FROM tracker_events c \
         WHERE c.issue_id = ? \
           AND instr(c.parents_json, '\"' || e.event_id || '\"') > 0)",
  ).all("content-1", "content-1");
  assert.strictEqual(heads.length, 1, "head query walks event_id/parents_json");
  assert.strictEqual(heads[0].event_id, "ev-root");
  console.log("PASS  fresh DO schema supports every production tracker table and column");
}

testEffectFree();
testTrackerSchemaParity();
testCoerceSuspendResume();
testAgentSuspendResume();
testAgentToolCall();
testExecSuspendResume();
testTurnContainerAgent();
testFileWrite();
testCheckpointRestore();
console.log("\nALL PASS: the wasm DO runtime drives real workflows over real SQLite through the wasm-bindgen boundary.");
