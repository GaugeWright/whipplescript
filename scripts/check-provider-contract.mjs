#!/usr/bin/env node
// The provider contract has one owning source (WhippleScript DR-0205):
// crates/whipplescript-kernel/src/provider_contract.json. The kernel embeds it
// (provider_contract.rs) and the Durable Object worker imports it
// (worker/src/provider-contract.ts). A consumer that writes one of its facts
// out again is a second copy, and a second copy is how the v0.1.1 pricing bugs
// happened: two implementations disagreeing about a contract neither declared.
//
// So this fails when a consumer's production code spells a fact the artifact
// holds: a default base URL, a request path, a credential, fixed or
// identity-specific header name, or a fixed header value. It reads the facts
// from the artifact, so a fact added there is checked here with no edit.
//
// CONSUMERS is the files that build, route or validate provider requests. A new
// one is added here in the change that creates it. What is scanned is code, not
// prose: whole-line comments are skipped, and so are a Rust file's tests (from
// its `#[cfg(test)]` module on) and the worker's `*.test.ts` files, which
// assert concrete URLs on purpose — a test pins what the artifact produces.
// The readers themselves (provider_contract.rs, provider-contract.ts) are the
// one place a header name is mapped from its contract spelling, and are not
// consumers.
//
//   node scripts/check-provider-contract.mjs             check the tree
//   node scripts/check-provider-contract.mjs --selftest  check the checker

import { readFileSync } from "node:fs";

const ARTIFACT = "crates/whipplescript-kernel/src/provider_contract.json";

export const CONSUMERS = [
  "crates/whipplescript-kernel/src/coerce_native.rs",
  "crates/whipplescript-kernel/src/harness_model.rs",
  "crates/whipplescript-cli/src/native_provider_transport.rs",
  "crates/whipplescript-cli/src/coerce_runtime.rs",
  "crates/whipplescript-cli/src/harness_tools.rs",
  "crates/whipplescript-host-do/worker/src/model-broker.ts",
  "crates/whipplescript-host-do/worker/src/provider-realization.ts",
];

const AUTH_HEADER_NAMES = { "x-api-key": "x-api-key", "authorization-bearer": null };

/** Every fact a consumer must look up rather than spell, with what it is. */
export function facts(contract) {
  const out = new Map();
  const add = (needle, what) => {
    const key = JSON.stringify(needle);
    const prior = out.get(key);
    out.set(key, { needle, what: prior ? `${prior.what} and ${what}` : what });
  };
  for (const [name, wire] of Object.entries(contract.wires)) {
    add({ path: wire.path }, `wire ${name}'s path`);
    const header = AUTH_HEADER_NAMES[wire.auth_header];
    if (header) add({ literal: header }, `wire ${name}'s credential header`);
    for (const [headerName, value] of Object.entries(wire.fixed_headers)) {
      add({ literal: headerName }, `wire ${name}'s fixed header`);
      add({ literal: value }, `wire ${name}'s ${headerName} value`);
    }
  }
  for (const [name, entry] of Object.entries(contract.providers)) {
    if (entry.default_base_url) {
      add({ literal: entry.default_base_url }, `${name}'s default base URL`);
    }
    if (entry.path) add({ path: entry.path }, `${name}'s request path`);
    for (const [headerName, value] of Object.entries(entry.extra_headers)) {
      add({ literal: headerName }, `${name}'s ${headerName} header`);
      if (!value.startsWith("<")) add({ literal: value }, `${name}'s ${headerName} value`);
    }
    const carried = entry.cache_key_carrier.match(/^header:(.+)$/);
    if (carried) add({ literal: carried[1] }, `${name}'s cache-key header`);
  }
  return [...out.values()].map(({ needle, what }) => ({ ...needle, what }));
}

function escape(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** The pattern that finds one fact spelled in code. A literal is a whole
 *  string literal; a path is a string or template literal that ends with it,
 *  which is how a URL is built from a base (`"{}/v1/messages"`,
 *  `` `${base}/chat/completions` ``). */
function pattern(fact) {
  if (fact.literal !== undefined) {
    return new RegExp(`["'\`]${escape(fact.literal)}["'\`]`, "i");
  }
  return new RegExp(`${escape(fact.path)}["'\`]`);
}

/** The production code of one consumer, as `[lineNumber, text]` pairs. */
export function codeLines(path, source) {
  const lines = source.split("\n");
  let end = lines.length;
  if (path.endsWith(".rs")) {
    const test = lines.findIndex((line, i) =>
      line.trim() === "#[cfg(test)]" && /^\s*(pub\s+)?mod\s+\w+/.test(lines[i + 1] ?? "")
    );
    if (test >= 0) end = test;
  }
  const out = [];
  let inBlockComment = false;
  for (let i = 0; i < end; i += 1) {
    const trimmed = lines[i].trim();
    if (inBlockComment) {
      if (trimmed.includes("*/")) inBlockComment = false;
      continue;
    }
    if (trimmed.startsWith("/*")) {
      if (!trimmed.includes("*/")) inBlockComment = true;
      continue;
    }
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
    out.push([i + 1, lines[i]]);
  }
  return out;
}

export function findings(contract, sources) {
  const all = facts(contract).map((fact) => ({ fact, re: pattern(fact) }));
  const found = [];
  for (const [path, source] of Object.entries(sources)) {
    for (const [line, text] of codeLines(path, source)) {
      for (const { fact, re } of all) {
        if (re.test(text)) found.push(`${path}:${line}: spells ${fact.what}; look it up in the provider contract`);
      }
    }
  }
  return found;
}

function selftest() {
  const contract = {
    wires: {
      w: {
        path: "/v1/messages",
        auth_header: "x-api-key",
        fixed_headers: { "anthropic-version": "2023-06-01" },
      },
    },
    providers: {
      p: {
        default_base_url: "https://api.example.com",
        path: "/backend/x",
        extra_headers: { "chatgpt-account-id": "<account>" },
        cache_key_carrier: "header:x-conv",
      },
    },
  };
  const expectFound = (path, source, count) => {
    const got = findings(contract, { [path]: source });
    if (got.length !== count) {
      throw new Error(`selftest: ${path} expected ${count} finding(s), got ${JSON.stringify(got)}`);
    }
  };
  expectFound("a.rs", 'let url = format!("{}/v1/messages", base);', 1);
  expectFound("a.ts", "const url = `${base}/v1/messages`;", 1);
  expectFound("a.rs", 'headers.push(("x-api-key".into(), key));', 1);
  expectFound("a.rs", '("anthropic-version", "2023-06-01")', 2);
  expectFound("a.ts", 'const base = "https://api.example.com";', 1);
  expectFound("a.ts", 'h.set("X-Conv", key);', 1);
  expectFound("a.ts", '"chatgpt-account-id"', 1);
  expectFound("a.rs", 'format!("{}/backend/x", base)', 1);
  // Prose and tests are not code.
  expectFound("a.rs", "// posts to /v1/messages\" with x-api-key", 0);
  expectFound("a.ts", " * `https://api.example.com`", 0);
  expectFound("a.rs", 'fn f() {}\n#[cfg(test)]\nmod tests {\n    let u = "https://api.example.com";\n}', 0);
  // A longer URL that merely starts with a base is not the base.
  expectFound("a.ts", 'const u = "https://api.example.com/v2";', 0);
  console.log("check-provider-contract selftest: ok");
}

function main() {
  if (process.argv.includes("--selftest")) {
    selftest();
    return;
  }
  const contract = JSON.parse(readFileSync(ARTIFACT, "utf8"));
  const sources = Object.fromEntries(CONSUMERS.map((path) => [path, readFileSync(path, "utf8")]));
  const found = findings(contract, sources);
  if (found.length) {
    console.error(`provider contract: ${found.length} hard-coded fact(s) the artifact holds (${ARTIFACT}):`);
    for (const line of found) console.error(`  ${line}`);
    process.exit(1);
  }
  console.log(`provider contract: ${CONSUMERS.length} consumers read ${ARTIFACT}; none spells a fact it holds`);
}

main();
