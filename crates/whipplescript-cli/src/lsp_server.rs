//! The `whip lsp` language-server loop and its document/position helpers.
//!
//! Moved verbatim out of `main.rs`; `use super::*` keeps the imports and
//! sibling helpers it already resolved against in scope.

use super::*;
/// Read one LSP message off `reader`: the `Content-Length` header block (each
/// header `\r\n`-terminated, ended by a blank line) followed by exactly that many
/// bytes of JSON body. Returns `None` at EOF (the editor closed the pipe).
fn lsp_read_message<R: std::io::BufRead>(reader: &mut R) -> Option<String> {
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("Content-Length:") {
            content_length = rest.trim().parse().ok()?;
        }
    }
    if content_length == 0 {
        return None;
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).ok()?;
    String::from_utf8(body).ok()
}

/// Write one LSP message: the `Content-Length` framing then the JSON body.
fn lsp_write<W: std::io::Write>(writer: &mut W, value: &Value) {
    let body = value.to_string();
    let _ = write!(writer, "Content-Length: {}\r\n\r\n{}", body.len(), body);
    let _ = writer.flush();
}

/// LSP `Position` (0-based `line`, UTF-16 `character`) for a byte offset.
pub(crate) fn lsp_byte_to_position(text: &str, offset: usize) -> (u32, u32) {
    let offset = offset.min(text.len());
    let mut line = 0u32;
    let mut character = 0u32;
    for (index, ch) in text.char_indices() {
        if index >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            character = 0;
        } else {
            character += ch.len_utf16() as u32;
        }
    }
    (line, character)
}

/// Byte offset of an LSP `Position` (0-based `line`, UTF-16 `character`). Clamps a
/// past-the-line-end character to the line's newline, and an out-of-range line to
/// the document end.
fn lsp_position_to_byte(text: &str, line: u32, character: u32) -> usize {
    let mut current_line = 0u32;
    let mut current_char = 0u32;
    for (index, ch) in text.char_indices() {
        if current_line == line && current_char == character {
            return index;
        }
        if ch == '\n' {
            if current_line == line {
                return index;
            }
            current_line += 1;
            current_char = 0;
        } else {
            current_char += ch.len_utf16() as u32;
        }
    }
    text.len()
}

/// The identifier token spanning byte `offset`, or `None` if `offset` is not on an
/// identifier. With `include_dot`, dotted names (e.g. a `signal deploy.finished`)
/// are read as one token. Identifiers are ASCII, so byte indexing is safe.
fn lsp_identifier_at(text: &str, offset: usize, include_dot: bool) -> Option<&str> {
    let bytes = text.as_bytes();
    let is_token = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || (include_dot && b == b'.');
    if offset > bytes.len() {
        return None;
    }
    let mut start = offset;
    while start > 0 && is_token(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = offset;
    while end < bytes.len() && is_token(bytes[end]) {
        end += 1;
    }
    (start < end).then(|| &text[start..end])
}

/// Byte ranges of every whole-token occurrence of `name` in `text`. "Whole token"
/// means the characters immediately around it are not identifier-continuation
/// chars (dotted names like `deploy.finished` treat `.` as a continuation char so
/// they match as a unit). Identifiers are ASCII, so byte indexing is safe.
pub(crate) fn lsp_find_occurrences(text: &str, name: &str) -> Vec<(usize, usize)> {
    if name.is_empty() {
        return Vec::new();
    }
    let dotted = name.contains('.');
    let is_continuation = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || (dotted && b == b'.');
    let bytes = text.as_bytes();
    let mut occurrences = Vec::new();
    let mut from = 0;
    while let Some(rel) = text[from..].find(name) {
        let start = from + rel;
        let end = start + name.len();
        let before_ok = start == 0 || !is_continuation(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_continuation(bytes[end]);
        if before_ok && after_ok {
            occurrences.push((start, end));
        }
        from = end;
    }
    occurrences
}

/// Converts a `file://` URI to a filesystem path (Linux/macOS form, minimal
/// percent-decoding). Returns `None` for non-`file` URIs.
fn lsp_uri_to_path(uri: &str) -> Option<PathBuf> {
    let path = uri.strip_prefix("file://")?;
    Some(PathBuf::from(path.replace("%20", " ")))
}

/// Converts a filesystem path to a `file://` URI.
fn lsp_path_to_uri(path: &Path) -> String {
    format!("file://{}", path.display())
}

/// Recursively collects `.whip` files under `dir`, skipping VCS/build/hidden
/// directories so the workspace scan stays bounded.
/// Recursion-depth ceiling for the LSP workspace scan: a guard against a
/// pathologically deep tree exhausting the stack. With the symlink skip below,
/// a crafted workspace (e.g. a `evil -> .` directory-symlink cycle, or one
/// pointing at `/`) can neither loop the scanner nor walk outside the project.
const LSP_MAX_SCAN_DEPTH: usize = 64;

pub(crate) fn lsp_collect_whip_files(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth >= LSP_MAX_SCAN_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        // `file_type()` reports the entry WITHOUT resolving a final symlink, so
        // a symlink is never recursed into or read — a directory-symlink cycle
        // can't loop the scan and a symlink out of the tree can't escape it.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if file_type.is_dir() {
            if name.starts_with('.') || name == "target" || name == "node_modules" {
                continue;
            }
            lsp_collect_whip_files(&path, out, depth + 1);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("whip") {
            out.push(path);
        }
    }
}

/// The workspace document set for cross-file features: every `.whip` file under
/// the workspace roots, with OPEN (in-memory) documents overriding their on-disk
/// content (so unsaved edits win). With no roots it degrades to just the open
/// documents, matching the single-document behavior.
fn lsp_workspace_documents(
    roots: &[PathBuf],
    open: &std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, String> {
    let mut docs = std::collections::HashMap::new();
    for root in roots {
        let mut files = Vec::new();
        lsp_collect_whip_files(root, &mut files, 0);
        for file in files {
            if let Ok(text) = std::fs::read_to_string(&file) {
                docs.insert(lsp_path_to_uri(&file), text);
            }
        }
    }
    for (uri, text) in open {
        docs.insert(uri.clone(), text.clone());
    }
    docs
}

/// Map a `DeclSymbol` kind tag to an LSP `SymbolKind` number.
fn lsp_symbol_kind(kind: &str) -> i32 {
    match kind {
        "workflow" => 2,                             // Module
        "class" => 5,                                // Class
        "enum" => 10,                                // Enum
        "rule" | "coerce" | "flow" | "action" => 12, // Function
        "signal" => 24,                              // Event
        "table" => 18,                               // Array
        "pattern" => 11,                             // Interface
        _ => 19,                                     // Object (coordination resources etc.)
    }
}

/// Map a `DeclSymbol` kind tag to an LSP `CompletionItemKind` number.
fn lsp_completion_kind(kind: &str) -> i32 {
    match kind {
        "workflow" => 9,                            // Module
        "class" => 7,                               // Class
        "enum" => 13,                               // Enum
        "rule" | "coerce" | "flow" | "action" => 3, // Function
        "signal" => 23,                             // Event
        "pattern" => 8,                             // Interface
        _ => 6,                                     // Variable (coordination resources, agent)
    }
}

/// The WhippleScript keywords offered as completions (top-level declaration
/// introducers + rule-body statement verbs). A flat list — editors filter by the
/// typed prefix; context-aware filtering is future work.
pub(crate) const LSP_KEYWORDS: &[&str] = &[
    "workflow", "class", "enum", "agent", "rule", "coerce", "flow", "action", "signal", "source",
    "table", "tracker", "channel", "lease", "ledger", "counter", "output", "failure", "input",
    "when", "record", "done", "tell", "decide", "exec", "call", "invoke", "with", "access", "to",
    "read", "write", "import", "export", "recall", "learn", "emit", "after", "case", "complete",
    "fail", "timer", "cancel", "claim", "release", "finish", "file", "acquire", "renew", "append",
    "consume",
];

/// Compile `text` and publish its diagnostics (errors + warnings) for `uri`. This
/// is the live error-squiggle path — it reuses the same compiler as `whip check`.
fn lsp_publish_diagnostics<W: std::io::Write>(writer: &mut W, uri: &str, text: &str) {
    let compiled = whipplescript_parser::compile_program(text);
    let to_lsp = |diagnostic: &Diagnostic| {
        let (start_line, start_char) = lsp_byte_to_position(text, diagnostic.span.start);
        let (end_line, end_char) = lsp_byte_to_position(text, diagnostic.span.end);
        let mut message = diagnostic.message.clone();
        if let Some(suggestion) = &diagnostic.suggestion {
            message.push_str(&format!("\nhelp: {suggestion}"));
        }
        let mut entry = json!({
            "range": {
                "start": { "line": start_line, "character": start_char },
                "end": { "line": end_line, "character": end_char },
            },
            // Severity and code come from the diagnostic itself. `lsp_code`
            // is the identity map the spec's 1:1 alignment promises, so an
            // editor gets the same level `whip check` printed.
            "severity": diagnostic.severity.lsp_code(),
            "code": diagnostic.code.as_str(),
            "source": "whip",
            "message": message,
        });
        // Secondary spans map to LSP `relatedInformation` (the editor renders
        // them as linked "note" locations), omitted when empty.
        if !diagnostic.related.is_empty() {
            let related: Vec<Value> = diagnostic
                .related
                .iter()
                .map(|info| {
                    let (rs_line, rs_char) = lsp_byte_to_position(text, info.span.start);
                    let (re_line, re_char) = lsp_byte_to_position(text, info.span.end);
                    json!({
                        "location": {
                            "uri": uri,
                            "range": {
                                "start": { "line": rs_line, "character": rs_char },
                                "end": { "line": re_line, "character": re_char },
                            },
                        },
                        "message": info.message,
                    })
                })
                .collect();
            entry
                .as_object_mut()
                .expect("diagnostic json is object")
                .insert("relatedInformation".to_owned(), Value::Array(related));
        }
        entry
    };
    // One pass over both channels: each diagnostic now names its own severity,
    // so the loop no longer decides it from which vector the diagnostic sat in.
    let mut diagnostics = Vec::new();
    for diagnostic in compiled.diagnostics.iter().chain(&compiled.warnings) {
        diagnostics.push(to_lsp(diagnostic));
    }
    // Lint findings (only when the program compiles, since they need the IR) surface
    // as diagnostics tagged `whip lint` — distinct from `whip` correctness diagnostics
    // via that `source` and the `lint.*` code, while keeping the LSP severity faithful
    // to the finding's own severity. Each carries the span resolved by `lint_program`.
    if let Some(ir) = &compiled.ir {
        for finding in lint_program(text, ir) {
            let Some(span) = finding.span else { continue };
            let (start_line, start_char) = lsp_byte_to_position(text, span.start);
            let (end_line, end_char) = lsp_byte_to_position(text, span.end);
            diagnostics.push(json!({
                "range": {
                    "start": { "line": start_line, "character": start_char },
                    "end": { "line": end_line, "character": end_char },
                },
                "severity": finding.severity.lsp_code(),
                "source": "whip lint",
                "code": finding.code,
                "message": finding.message,
            }));
        }
    }
    lsp_write(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": { "uri": uri, "diagnostics": diagnostics },
        }),
    );
}

/// `whip lsp`: a minimal Language Server over stdio (spec/editor-tooling.md). v0
/// is the diagnostics-on-edit core — `initialize`, full-sync `didOpen`/`didChange`
/// (re-compile and publish diagnostics), and `didClose` (clear them). It is
/// hand-rolled JSON-RPC (no async/LSP crate, consistent with the workspace's
/// no-runtime-dependency stance). Hover/definition/completion are future work.
pub(crate) fn lsp(_options: &CliOptions) -> ExitCode {
    let stdin = std::io::stdin();
    let mut reader = std::io::BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    let mut documents: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    // Workspace roots (from `initialize`), used to scan `.whip` files on disk for
    // cross-file definition/references and filesystem-wide `workspace/symbol`.
    let mut workspace_roots: Vec<PathBuf> = Vec::new();

    while let Some(message) = lsp_read_message(&mut reader) {
        let Ok(value) = serde_json::from_str::<Value>(&message) else {
            continue;
        };
        let method = value.get("method").and_then(Value::as_str).unwrap_or("");
        let id = value.get("id").cloned();
        let params = value.get("params").cloned().unwrap_or(Value::Null);
        let document_text = |params: &Value| -> Option<(String, String)> {
            let document = params.get("textDocument")?;
            let uri = document.get("uri").and_then(Value::as_str)?.to_owned();
            // Full-sync: didOpen carries `textDocument.text`; didChange's last
            // content change carries the whole document.
            let text = document
                .get("text")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| {
                    params
                        .get("contentChanges")
                        .and_then(Value::as_array)
                        .and_then(|changes| changes.last())
                        .and_then(|change| change.get("text"))
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })?;
            Some((uri, text))
        };
        match method {
            "initialize" => {
                // Capture workspace roots from rootUri / rootPath / workspaceFolders
                // so cross-file features can scan the project's `.whip` files.
                if let Some(uri) = params.get("rootUri").and_then(Value::as_str) {
                    if let Some(path) = lsp_uri_to_path(uri) {
                        workspace_roots.push(path);
                    }
                } else if let Some(path) = params.get("rootPath").and_then(Value::as_str) {
                    workspace_roots.push(PathBuf::from(path));
                }
                if let Some(folders) = params.get("workspaceFolders").and_then(Value::as_array) {
                    for folder in folders {
                        if let Some(uri) = folder.get("uri").and_then(Value::as_str) {
                            if let Some(path) = lsp_uri_to_path(uri) {
                                workspace_roots.push(path);
                            }
                        }
                    }
                }
                workspace_roots.sort();
                workspace_roots.dedup();
                lsp_write(
                    &mut writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "capabilities": {
                                "textDocumentSync": 1, // 1 = Full
                                "documentSymbolProvider": true,
                                "definitionProvider": true,
                                "hoverProvider": true,
                                "completionProvider": {},
                                "referencesProvider": true,
                                "renameProvider": true,
                                "documentFormattingProvider": true,
                                "documentHighlightProvider": true,
                                "workspaceSymbolProvider": true,
                            },
                            "serverInfo": { "name": "whip-lsp", "version": "0" },
                        },
                    }),
                );
            }
            "initialized" => {}
            "textDocument/didOpen" | "textDocument/didChange" => {
                if let Some((uri, text)) = document_text(&params) {
                    documents.insert(uri.clone(), text.clone());
                    lsp_publish_diagnostics(&mut writer, &uri, &text);
                }
            }
            "textDocument/completion" => {
                // A flat candidate list: language keywords plus the document's
                // declared top-level names. Editors filter by the typed prefix;
                // context/scope-aware filtering is future work.
                let mut items: Vec<Value> = LSP_KEYWORDS
                    .iter()
                    .map(|keyword| json!({ "label": keyword, "kind": 14 })) // 14 = Keyword
                    .collect();
                if let Some(text) = params
                    .get("textDocument")
                    .and_then(|document| document.get("uri"))
                    .and_then(Value::as_str)
                    .and_then(|uri| documents.get(uri))
                {
                    for symbol in whipplescript_parser::document_symbols(text) {
                        items.push(json!({
                            "label": symbol.name,
                            "detail": symbol.kind,
                            "kind": lsp_completion_kind(symbol.kind),
                        }));
                    }
                }
                lsp_write(
                    &mut writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": { "isIncomplete": false, "items": items },
                    }),
                );
            }
            "textDocument/formatting" => {
                // Format the whole document via the same comment-preserving formatter
                // as `whip fmt`. Returns one whole-document edit, or no edits when
                // the document doesn't parse or `fmt` would refuse it (so it never
                // corrupts content).
                let edits = (|| {
                    let document = params.get("textDocument")?;
                    let uri = document.get("uri").and_then(Value::as_str)?;
                    let text = documents.get(uri)?;
                    let formatted = whipplescript_parser::format_program_preserving_comments(text)?;
                    if formatted == *text {
                        return Some(Vec::new());
                    }
                    let (end_line, end_char) = lsp_byte_to_position(text, text.len());
                    Some(vec![json!({
                        "range": {
                            "start": { "line": 0, "character": 0 },
                            "end": { "line": end_line, "character": end_char },
                        },
                        "newText": formatted,
                    })])
                })();
                lsp_write(
                    &mut writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": edits.map(Value::Array).unwrap_or(Value::Null),
                    }),
                );
            }
            "textDocument/rename" => {
                // Rename a top-level symbol across the document. Like references but
                // EDITING — so occurrences inside string literals or comments (e.g. a
                // class name mentioned in a prompt) are excluded to avoid corrupting
                // text. Names are program-unique, so every code occurrence is the
                // symbol.
                let edit = (|| {
                    let document = params.get("textDocument")?;
                    let uri = document.get("uri").and_then(Value::as_str)?;
                    let text = documents.get(uri)?;
                    let new_name = params.get("newName").and_then(Value::as_str)?;
                    let position = params.get("position")?;
                    let line = position.get("line").and_then(Value::as_u64)? as u32;
                    let character = position.get("character").and_then(Value::as_u64)? as u32;
                    let offset = lsp_position_to_byte(text, line, character);
                    let symbols = whipplescript_parser::document_symbols(text);
                    let regions = whipplescript_parser::string_and_comment_spans(text);
                    let in_string_or_comment =
                        |start: usize| regions.iter().any(|r| r.start <= start && start < r.end);
                    for include_dot in [true, false] {
                        let Some(token) = lsp_identifier_at(text, offset, include_dot) else {
                            continue;
                        };
                        let Some(symbol) = symbols.iter().find(|symbol| symbol.name == token)
                        else {
                            continue;
                        };
                        let edits = lsp_find_occurrences(text, &symbol.name)
                            .into_iter()
                            .filter(|(start, _)| !in_string_or_comment(*start))
                            .map(|(start, end)| {
                                let (start_line, start_char) = lsp_byte_to_position(text, start);
                                let (end_line, end_char) = lsp_byte_to_position(text, end);
                                json!({
                                    "range": {
                                        "start": { "line": start_line, "character": start_char },
                                        "end": { "line": end_line, "character": end_char },
                                    },
                                    "newText": new_name,
                                })
                            })
                            .collect::<Vec<_>>();
                        return Some(json!({ "changes": { uri: edits } }));
                    }
                    None
                })();
                lsp_write(
                    &mut writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": edit.unwrap_or(Value::Null),
                    }),
                );
            }
            "workspace/symbol" => {
                // Symbols across the whole workspace matching the query (a
                // case-insensitive substring; empty query matches all). Scans every
                // `.whip` file under the workspace roots, with open documents
                // overriding their on-disk content; with no roots this degrades to
                // the open documents.
                let query = params
                    .get("query")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_lowercase();
                let mut results = Vec::new();
                let workspace = lsp_workspace_documents(&workspace_roots, &documents);
                for (uri, text) in &workspace {
                    for symbol in whipplescript_parser::document_symbols(text) {
                        if !query.is_empty() && !symbol.name.to_lowercase().contains(&query) {
                            continue;
                        }
                        let (start_line, start_char) =
                            lsp_byte_to_position(text, symbol.span.start);
                        let (end_line, end_char) = lsp_byte_to_position(text, symbol.span.end);
                        results.push(json!({
                            "name": symbol.name,
                            "kind": lsp_symbol_kind(symbol.kind),
                            "location": {
                                "uri": uri,
                                "range": {
                                    "start": { "line": start_line, "character": start_char },
                                    "end": { "line": end_line, "character": end_char },
                                },
                            },
                        }));
                    }
                }
                lsp_write(
                    &mut writer,
                    &json!({ "jsonrpc": "2.0", "id": id, "result": results }),
                );
            }
            "textDocument/documentHighlight" => {
                // Highlight every occurrence of the symbol under the cursor in the
                // current document (the editor's always-on cursor highlighting).
                // Same occurrence scan as references, shaped as DocumentHighlight[].
                let highlights = (|| {
                    let document = params.get("textDocument")?;
                    let uri = document.get("uri").and_then(Value::as_str)?;
                    let text = documents.get(uri)?;
                    let position = params.get("position")?;
                    let line = position.get("line").and_then(Value::as_u64)? as u32;
                    let character = position.get("character").and_then(Value::as_u64)? as u32;
                    let offset = lsp_position_to_byte(text, line, character);
                    let symbols = whipplescript_parser::document_symbols(text);
                    for include_dot in [true, false] {
                        let Some(token) = lsp_identifier_at(text, offset, include_dot) else {
                            continue;
                        };
                        let Some(symbol) = symbols.iter().find(|symbol| symbol.name == token)
                        else {
                            continue;
                        };
                        let highlights = lsp_find_occurrences(text, &symbol.name)
                            .into_iter()
                            .map(|(start, end)| {
                                let (start_line, start_char) = lsp_byte_to_position(text, start);
                                let (end_line, end_char) = lsp_byte_to_position(text, end);
                                json!({
                                    "range": {
                                        "start": { "line": start_line, "character": start_char },
                                        "end": { "line": end_line, "character": end_char },
                                    },
                                    "kind": 1, // Text
                                })
                            })
                            .collect::<Vec<_>>();
                        return Some(highlights);
                    }
                    None
                })();
                lsp_write(
                    &mut writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": highlights.map(Value::Array).unwrap_or(Value::Null),
                    }),
                );
            }
            "textDocument/references" => {
                // All whole-token occurrences of the top-level symbol under the
                // cursor, ACROSS the workspace. Top-level names are program-unique,
                // so every occurrence in any `.whip` file is a reference to the same
                // symbol. Honors `context.includeDeclaration` (only the declaration
                // file's own declaration-span occurrence is filtered).
                let locations = (|| {
                    let document = params.get("textDocument")?;
                    let uri = document.get("uri").and_then(Value::as_str)?;
                    let text = documents.get(uri)?;
                    let position = params.get("position")?;
                    let line = position.get("line").and_then(Value::as_u64)? as u32;
                    let character = position.get("character").and_then(Value::as_u64)? as u32;
                    let offset = lsp_position_to_byte(text, line, character);
                    let include_declaration = params
                        .get("context")
                        .and_then(|context| context.get("includeDeclaration"))
                        .and_then(Value::as_bool)
                        .unwrap_or(true);
                    let symbols = whipplescript_parser::document_symbols(text);
                    let workspace = lsp_workspace_documents(&workspace_roots, &documents);
                    for include_dot in [true, false] {
                        let Some(token) = lsp_identifier_at(text, offset, include_dot) else {
                            continue;
                        };
                        let Some(symbol) = symbols.iter().find(|symbol| symbol.name == token)
                        else {
                            continue;
                        };
                        let mut locations = Vec::new();
                        for (doc_uri, doc_text) in &workspace {
                            // The declaration span only applies to the file that
                            // declares the symbol (the current document).
                            let declaration_span = (doc_uri == uri).then_some(symbol.span);
                            for (start, end) in lsp_find_occurrences(doc_text, &symbol.name) {
                                if !include_declaration {
                                    if let Some(decl) = declaration_span {
                                        if start >= decl.start && start < decl.end {
                                            continue;
                                        }
                                    }
                                }
                                let (start_line, start_char) =
                                    lsp_byte_to_position(doc_text, start);
                                let (end_line, end_char) = lsp_byte_to_position(doc_text, end);
                                locations.push(json!({
                                    "uri": doc_uri,
                                    "range": {
                                        "start": { "line": start_line, "character": start_char },
                                        "end": { "line": end_line, "character": end_char },
                                    },
                                }));
                            }
                        }
                        return Some(locations);
                    }
                    None
                })();
                lsp_write(
                    &mut writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": locations.map(Value::Array).unwrap_or(Value::Null),
                    }),
                );
            }
            "textDocument/hover" => {
                // Show the declaration source for the symbol under the cursor (so
                // hovering a reference reveals the target's definition). Reuses the
                // same name→declaration resolution as go-to-definition.
                let contents = (|| {
                    let document = params.get("textDocument")?;
                    let uri = document.get("uri").and_then(Value::as_str)?;
                    let text = documents.get(uri)?;
                    let position = params.get("position")?;
                    let line = position.get("line").and_then(Value::as_u64)? as u32;
                    let character = position.get("character").and_then(Value::as_u64)? as u32;
                    let offset = lsp_position_to_byte(text, line, character);
                    let symbols = whipplescript_parser::document_symbols(text);
                    for include_dot in [true, false] {
                        let Some(token) = lsp_identifier_at(text, offset, include_dot) else {
                            continue;
                        };
                        if let Some(symbol) = symbols.iter().find(|symbol| symbol.name == token) {
                            let end = symbol.span.end.min(text.len());
                            let start = symbol.span.start.min(end);
                            // Cap long declarations (e.g. rule bodies) for a tidy hover.
                            let snippet = text.get(start..end)?;
                            let shown: Vec<&str> = snippet.lines().take(40).collect();
                            return Some(format!("```whip\n{}\n```", shown.join("\n")));
                        }
                    }
                    None
                })();
                let result = match contents {
                    Some(value) => json!({ "contents": { "kind": "markdown", "value": value } }),
                    None => Value::Null,
                };
                lsp_write(
                    &mut writer,
                    &json!({ "jsonrpc": "2.0", "id": id, "result": result }),
                );
            }
            "textDocument/definition" => {
                // Resolve the identifier under the cursor to a top-level
                // declaration. Top-level names are program-unique, so a name match
                // is the definition (no scope analysis needed yet). Dotted signal
                // names are tried first, then the bare identifier. The current
                // document is searched first; a name declared in another workspace
                // file resolves cross-file.
                let location = (|| {
                    let document = params.get("textDocument")?;
                    let uri = document.get("uri").and_then(Value::as_str)?;
                    let text = documents.get(uri)?;
                    let position = params.get("position")?;
                    let line = position.get("line").and_then(Value::as_u64)? as u32;
                    let character = position.get("character").and_then(Value::as_u64)? as u32;
                    let offset = lsp_position_to_byte(text, line, character);
                    let symbols = whipplescript_parser::document_symbols(text);
                    let location_json = |doc_uri: &str, doc_text: &str, span: SourceSpan| {
                        let (start_line, start_char) = lsp_byte_to_position(doc_text, span.start);
                        let (end_line, end_char) = lsp_byte_to_position(doc_text, span.end);
                        json!({
                            "uri": doc_uri,
                            "range": {
                                "start": { "line": start_line, "character": start_char },
                                "end": { "line": end_line, "character": end_char },
                            },
                        })
                    };
                    let mut workspace: Option<std::collections::HashMap<String, String>> = None;
                    for include_dot in [true, false] {
                        let Some(token) = lsp_identifier_at(text, offset, include_dot) else {
                            continue;
                        };
                        // Same-document declaration wins.
                        if let Some(symbol) = symbols.iter().find(|symbol| symbol.name == token) {
                            return Some(location_json(uri, text, symbol.span));
                        }
                        // Otherwise search the rest of the workspace (scanned lazily).
                        let workspace = workspace.get_or_insert_with(|| {
                            lsp_workspace_documents(&workspace_roots, &documents)
                        });
                        for (doc_uri, doc_text) in workspace.iter() {
                            if doc_uri == uri {
                                continue;
                            }
                            if let Some(symbol) = whipplescript_parser::document_symbols(doc_text)
                                .into_iter()
                                .find(|symbol| symbol.name == token)
                            {
                                return Some(location_json(doc_uri, doc_text, symbol.span));
                            }
                        }
                    }
                    None
                })();
                lsp_write(
                    &mut writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": location.unwrap_or(Value::Null),
                    }),
                );
            }
            "textDocument/documentSymbol" => {
                let symbols = params
                    .get("textDocument")
                    .and_then(|document| document.get("uri"))
                    .and_then(Value::as_str)
                    .and_then(|uri| documents.get(uri))
                    .map(|text| {
                        whipplescript_parser::document_symbols(text)
                            .into_iter()
                            .map(|symbol| {
                                let (start_line, start_char) =
                                    lsp_byte_to_position(text, symbol.span.start);
                                let (end_line, end_char) =
                                    lsp_byte_to_position(text, symbol.span.end);
                                let range = json!({
                                    "start": { "line": start_line, "character": start_char },
                                    "end": { "line": end_line, "character": end_char },
                                });
                                json!({
                                    "name": symbol.name,
                                    "detail": symbol.kind,
                                    "kind": lsp_symbol_kind(symbol.kind),
                                    "range": range,
                                    "selectionRange": range,
                                })
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                lsp_write(
                    &mut writer,
                    &json!({ "jsonrpc": "2.0", "id": id, "result": symbols }),
                );
            }
            "textDocument/didClose" => {
                if let Some(uri) = params
                    .get("textDocument")
                    .and_then(|d| d.get("uri"))
                    .and_then(Value::as_str)
                {
                    documents.remove(uri);
                    lsp_write(
                        &mut writer,
                        &json!({
                            "jsonrpc": "2.0",
                            "method": "textDocument/publishDiagnostics",
                            "params": { "uri": uri, "diagnostics": [] },
                        }),
                    );
                }
            }
            "shutdown" => {
                lsp_write(
                    &mut writer,
                    &json!({ "jsonrpc": "2.0", "id": id, "result": Value::Null }),
                );
            }
            "exit" => break,
            _ => {
                // Respond to unknown *requests* (those with an id) so the client is
                // not left awaiting; ignore unknown notifications.
                if matches!(&id, Some(value) if !value.is_null()) {
                    lsp_write(
                        &mut writer,
                        &json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": { "code": -32601, "message": format!("unhandled method `{method}`") },
                        }),
                    );
                }
            }
        }
    }
    ExitCode::SUCCESS
}
