#!/usr/bin/env node

import { createInterface } from "node:readline";
import { stdin, stdout, stderr, env, cwd } from "node:process";

const fakeMode = env.WHIPPLESCRIPT_CLAUDE_AGENT_SDK_FAKE === "1";
// DR-0035 Decision 7: the whip sidecar dialect version. Exchanged via the
// `hello` handshake before any run starts; the client blocks the binding on a
// mismatch instead of failing mid-turn.
const PROTOCOL_VERSION = "whip-sidecar/1";
const activeRuns = new Map();

function emit(message) {
  stdout.write(`${JSON.stringify(message)}\n`);
}

function emitError(runId, code, message, extra = {}) {
  emit({
    type: "run/error",
    run_id: runId || null,
    payload: {
      code,
      message,
      ...extra,
    },
  });
}

function shape(value) {
  if (value === null || value === undefined) {
    return { type: "null" };
  }
  if (Array.isArray(value)) {
    return { type: "array", items: value.length };
  }
  if (typeof value === "object") {
    return { type: "object", keys: Object.keys(value).length };
  }
  if (typeof value === "string") {
    return { type: "string", chars: [...value].length };
  }
  return { type: typeof value };
}

function summarizeContentBlocks(content) {
  if (!Array.isArray(content)) {
    return null;
  }
  const typeCounts = {};
  const toolNameCounts = {};
  for (const block of content) {
    const type = typeof block === "object" && block !== null ? block.type || "object" : typeof block;
    typeCounts[type] = (typeCounts[type] || 0) + 1;
    if (type === "tool_use" && typeof block.name === "string") {
      toolNameCounts[block.name] = (toolNameCounts[block.name] || 0) + 1;
    }
  }
  return {
    items: content.length,
    type_counts: typeCounts,
    tool_name_counts: toolNameCounts,
  };
}

function summarizeMessage(message) {
  const summary = {
    message_type: message?.type || null,
    subtype: message?.subtype || null,
    session_id: message?.session_id || message?.data?.session_id || null,
  };
  if (Object.hasOwn(message || {}, "usage")) {
    summary.usage_shape = shape(message.usage);
  }
  if (Object.hasOwn(message || {}, "result")) {
    summary.result_shape = shape(message.result);
  }
  const content = Object.hasOwn(message || {}, "content") ? message.content : message?.message?.content;
  if (content !== undefined) {
    summary.content_shape = shape(content);
    const contentBlocks = summarizeContentBlocks(content);
    if (contentBlocks) {
      summary.content_blocks = contentBlocks;
    }
  }
  return summary;
}

function terminalTypeForMessage(message) {
  if (message?.type !== "result") {
    return null;
  }
  if (message.subtype === "success") {
    return "claude.turn.completed";
  }
  if (message.subtype === "error_max_turns" || message.subtype === "error_during_execution") {
    return "claude.turn.failed";
  }
  return "claude.turn.completed";
}

async function runFake(request) {
  const runId = request.run_id;
  const sessionId = `fake-claude-session-${runId}`;
  activeRuns.set(runId, { cancelled: false });
  emit({
    type: "claude.session.started",
    run_id: runId,
    payload: {
      session_id: sessionId,
      sdk: "fake",
      cwd: request.cwd || cwd(),
    },
  });
  emit({
    type: "claude.stream.message",
    run_id: runId,
    payload: {
      message_type: "system",
      subtype: "init",
      session_id: sessionId,
    },
  });
  await new Promise((resolve) => setTimeout(resolve, 10));
  if (activeRuns.get(runId)?.cancelled) {
    emit({
      type: "claude.turn.cancelled",
      run_id: runId,
      payload: {
        session_id: sessionId,
        acknowledgement: "fake-cancelled",
      },
    });
    activeRuns.delete(runId);
    return;
  }
  emit({
    type: "claude.stream.message",
    run_id: runId,
    payload: {
      message_type: "assistant",
      content_shape: { type: "array", items: 1 },
    },
  });
  if (env.WHIPPLESCRIPT_CLAUDE_AGENT_SDK_FAKE_ARTIFACT === "1" || request.artifact_fixture) {
    emit({
      type: "claude.artifact.captured",
      run_id: runId,
      payload: {
        session_id: sessionId,
        artifacts: [
          {
            id: "fake-artifact-1",
            kind: "attachment",
            uri: `provider://claude/runs/${runId}/artifacts/fake-artifact-1`,
            mime_type: "text/plain",
            content_hash: "sha256:fake",
            required: false,
            content: "secret fake artifact bytes",
          },
        ],
      },
    });
  }
  emit({
    type: "claude.turn.completed",
    run_id: runId,
    payload: {
      session_id: sessionId,
      subtype: "success",
      result_shape: { type: "string", chars: 31 },
      usage_shape: { type: "object", keys: 2 },
    },
  });
  activeRuns.delete(runId);
}

async function runLive(request) {
  const runId = request.run_id;
  // Policy-free transport (spec/std-agent.md slice 4): the sidecar carries NO
  // compiled-in tool-policy defaults. The whip client computes the policy from
  // the std.agent profile table and sends it explicitly; a run/start without
  // explicit arrays is refused rather than silently defaulted.
  if (!Array.isArray(request.allowed_tools) || !Array.isArray(request.disallowed_tools)) {
    emitError(
      runId,
      "missing_tool_policy",
      "run/start requires explicit allowed_tools and disallowed_tools arrays (the sidecar is policy-free transport)"
    );
    return;
  }
  const { query } = await import("@anthropic-ai/claude-agent-sdk");
  const abortController = new AbortController();
  activeRuns.set(runId, { abortController, cancelled: false, sessionId: null });
  const options = {
    abortController,
    cwd: request.cwd || cwd(),
    model: request.model || undefined,
    allowedTools: request.allowed_tools,
    disallowedTools: request.disallowed_tools,
    permissionMode: request.permission_mode || "default",
    allowDangerouslySkipPermissions: Boolean(request.allow_dangerously_skip_permissions),
    mcpServers: request.mcp_servers || undefined,
    maxTurns: request.max_turns || 1,
    settingSources: request.setting_sources || [],
    pathToClaudeCodeExecutable: request.path_to_claude || undefined,
    env: {
      ...env,
      ...(request.env || {}),
    },
  };
  let sawTerminal = false;
  const claudeQuery = query({ prompt: request.prompt || "", options });
  activeRuns.set(runId, {
    abortController,
    query: claudeQuery,
    cancelled: false,
    sessionId: null,
  });
  try {
    for await (const message of claudeQuery) {
      const summary = summarizeMessage(message);
      const run = activeRuns.get(runId);
      if (run && summary.session_id) {
        run.sessionId = summary.session_id;
      }
      if (summary.message_type === "system" && summary.subtype === "init") {
        emit({
          type: "claude.session.started",
          run_id: runId,
          payload: summary,
        });
      }
      const terminalType = terminalTypeForMessage(message);
      if (terminalType && run?.cancelled) {
        sawTerminal = true;
        emit({
          type: "claude.turn.cancelled",
          run_id: runId,
          payload: {
            ...summary,
            acknowledgement: "interrupt",
          },
        });
        continue;
      }
      emit({
        type: terminalType || "claude.stream.message",
        run_id: runId,
        payload: summary,
      });
      if (terminalType) {
        sawTerminal = true;
      }
    }
  } catch (error) {
    const run = activeRuns.get(runId);
    if (run?.cancelled || error?.name === "AbortError") {
      sawTerminal = true;
      emit({
        type: "claude.turn.cancelled",
        run_id: runId,
        payload: {
          session_id: run?.sessionId || null,
          acknowledgement: error?.name === "AbortError" ? "abort-controller" : "interrupt",
          error_shape: shape(error?.message || String(error)),
        },
      });
      activeRuns.delete(runId);
      return;
    }
    throw error;
  }
  const run = activeRuns.get(runId);
  if (!sawTerminal) {
    sawTerminal = true;
    emit({
      type: run?.cancelled ? "claude.turn.cancelled" : "claude.turn.completed",
      run_id: runId,
      payload: run?.cancelled
        ? {
            session_id: run.sessionId || null,
            acknowledgement: "stream-closed-after-cancel",
          }
        : {
            subtype: "stream_closed",
          },
    });
  }
  activeRuns.delete(runId);
}

async function handleStart(message) {
  const request = message.request || {};
  const runId = message.run_id || request.run_id;
  if (!runId) {
    emitError(null, "missing_run_id", "run/start requires a run_id");
    return;
  }
  request.run_id = runId;
  try {
    if (fakeMode) {
      await runFake(request);
    } else {
      await runLive(request);
    }
  } catch (error) {
    activeRuns.delete(runId);
    emitError(runId, "claude_agent_sdk_failed", error?.message || String(error));
  }
}

async function handleCancel(message) {
  const runId = message.run_id;
  const run = activeRuns.get(runId);
  if (!run) {
    emitError(runId, "run_not_active", "cannot cancel inactive Claude run");
    return;
  }
  run.cancelled = true;
  if (run.query && typeof run.query.interrupt === "function") {
    try {
      await run.query.interrupt();
      return;
    } catch (error) {
      if (error?.name !== "AbortError") {
        stderr.write(`${error?.stack || error}\n`);
      }
    }
  }
  if (run.abortController) {
    run.abortController.abort();
  }
}

const rl = createInterface({ input: stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) {
    return;
  }
  let message;
  try {
    message = JSON.parse(line);
  } catch (error) {
    emitError(null, "invalid_json", error.message);
    return;
  }
  if (message.type === "hello") {
    emit({
      type: "hello",
      run_id: null,
      payload: { protocol: PROTOCOL_VERSION },
    });
  } else if (message.type === "run/start") {
    void handleStart(message);
  } else if (message.type === "run/cancel") {
    void handleCancel(message);
  } else if (message.type === "run/close") {
    rl.close();
  } else {
    emitError(message.run_id || null, "unknown_command", `unknown command ${message.type}`);
  }
});

rl.on("close", () => {
  for (const run of activeRuns.values()) {
    if (run.abortController) {
      run.abortController.abort();
    }
  }
});

process.on("unhandledRejection", (error) => {
  stderr.write(`${error?.stack || error}\n`);
  emitError(null, "unhandled_rejection", error?.message || String(error));
});
