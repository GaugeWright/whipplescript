//! The lexer and the recursive-descent parser: tokens, clause bags, and the `Parser` impl that builds the AST.
//!
//! Moved verbatim out of `lib.rs`; `use super::*` keeps the IR types and
//! helpers it already resolved against in scope.

use super::*;
/// Stage marker retained for the CLI scaffold.
pub fn parser_stage() -> &'static str {
    whipplescript_core::IMPLEMENTATION_STAGE
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Lexed {
    pub(crate) tokens: Vec<Token>,
    diagnostics: Vec<Diagnostic>,
    comments: Vec<Comment>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Token {
    kind: TokenKind,
    span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TokenKind {
    Ident(String),
    String(String),
    Number(String),
    Arrow,
    ThinArrow,
    Symbol(char),
}

impl TokenKind {
    fn label(&self) -> String {
        match self {
            Self::Ident(value) => format!("identifier `{value}`"),
            Self::String(_) => "string literal".to_owned(),
            Self::Number(_) => "number literal".to_owned(),
            Self::Arrow => "`=>`".to_owned(),
            Self::ThinArrow => "`->`".to_owned(),
            Self::Symbol(value) => format!("`{value}`"),
        }
    }
}

pub(crate) fn lex(source: &str) -> Lexed {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut diagnostics = Vec::new();
    let mut comments = Vec::new();
    let mut index = 0;

    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }

        if byte == b'#' {
            let end = skip_line(bytes, index + 1);
            comments.push(Comment {
                marker: CommentMarker::Hash,
                text: source[index + 1..end].trim().to_owned(),
                span: SourceSpan { start: index, end },
            });
            index = end;
            continue;
        }

        if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            let end = skip_line(bytes, index + 2);
            comments.push(Comment {
                marker: CommentMarker::Slash,
                text: source[index + 2..end].trim().to_owned(),
                span: SourceSpan { start: index, end },
            });
            index = end;
            continue;
        }

        if is_ident_start(byte) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_ident_continue(bytes[index]) {
                index += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Ident(source[start..index].to_owned()),
                span: SourceSpan { start, end: index },
            });
            continue;
        }

        if byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Number(source[start..index].to_owned()),
                span: SourceSpan { start, end: index },
            });
            continue;
        }

        if byte == b'"' {
            let (token, next, diagnostic) = lex_string(source, index);
            tokens.push(token);
            if let Some(diagnostic) = diagnostic {
                diagnostics.push(diagnostic);
            }
            index = next;
            continue;
        }

        if byte == b'=' && bytes.get(index + 1) == Some(&b'>') {
            tokens.push(Token {
                kind: TokenKind::Arrow,
                span: SourceSpan {
                    start: index,
                    end: index + 2,
                },
            });
            index += 2;
            continue;
        }

        if byte == b'=' && bytes.get(index + 1) == Some(&b'=') {
            index += 2;
            continue;
        }

        if byte == b'!' && bytes.get(index + 1) == Some(&b'=') {
            index += 2;
            continue;
        }

        if matches!(byte, b'<' | b'>') && bytes.get(index + 1) == Some(&b'=') {
            index += 2;
            continue;
        }

        if matches!(byte, b'&' | b'|') && bytes.get(index + 1) == Some(&byte) {
            index += 2;
            continue;
        }

        if byte == b'-' && bytes.get(index + 1) == Some(&b'>') {
            tokens.push(Token {
                kind: TokenKind::ThinArrow,
                span: SourceSpan {
                    start: index,
                    end: index + 2,
                },
            });
            index += 2;
            continue;
        }

        // Arithmetic operators appear inside guard and field-value
        // expressions, which are re-parsed from raw source slices; the
        // file-level lexer only needs to step over them.
        if matches!(byte, b'*' | b'/' | b'-') {
            index += 1;
            continue;
        }

        if b"{}[]()<>,?|.+!:@".contains(&byte) {
            tokens.push(Token {
                kind: TokenKind::Symbol(byte as char),
                span: SourceSpan {
                    start: index,
                    end: index + 1,
                },
            });
            index += 1;
            continue;
        }

        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: SourceSpan {
                start: index,
                end: index + 1,
            },
            message: format!("unexpected character `{}`", byte as char),
            suggestion: None,
        });
        index += 1;
    }

    Lexed {
        tokens,
        diagnostics,
        comments,
    }
}

/// Extract the comments from a source program, in source order. Comments are not
/// part of the token stream or AST; this is the entry point tooling (`whip fmt`,
/// the LSP) uses to preserve them.
pub fn lex_comments(source: &str) -> Vec<Comment> {
    lex(source).comments
}

/// Byte-span regions of string literals and comments in `source`. A tool that
/// edits identifier occurrences (e.g. `whip lsp` rename) consults these to avoid
/// touching text inside a prompt string or a comment — only code identifiers are
/// real references.
pub fn string_and_comment_spans(source: &str) -> Vec<SourceSpan> {
    let lexed = lex(source);
    let mut spans: Vec<SourceSpan> = lexed
        .tokens
        .iter()
        .filter(|token| matches!(token.kind, TokenKind::String(_)))
        .map(|token| token.span)
        .collect();
    spans.extend(lexed.comments.iter().map(|comment| comment.span));
    spans
}

pub(crate) fn skip_line(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index] != b'\n' {
        index += 1;
    }
    index
}

pub(crate) fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

pub(crate) fn is_ident_continue(byte: u8) -> bool {
    is_ident_start(byte) || byte.is_ascii_digit() || byte == b'-'
}

pub(crate) fn lex_string(source: &str, start: usize) -> (Token, usize, Option<Diagnostic>) {
    let bytes = source.as_bytes();
    let triple = bytes.get(start..start + 3) == Some(b"\"\"\"");
    let content_start = if triple { start + 3 } else { start + 1 };
    let mut index = content_start;

    while index < bytes.len() {
        if triple && bytes.get(index..index + 3) == Some(b"\"\"\"") {
            let end = index + 3;
            return (
                Token {
                    kind: TokenKind::String(source[content_start..index].to_owned()),
                    span: SourceSpan { start, end },
                },
                end,
                None,
            );
        }

        if !triple && bytes[index] == b'"' {
            let end = index + 1;
            return (
                Token {
                    kind: TokenKind::String(source[content_start..index].to_owned()),
                    span: SourceSpan { start, end },
                },
                end,
                None,
            );
        }

        if !triple && bytes[index] == b'\\' && index + 1 < bytes.len() {
            index += 2;
        } else {
            index += 1;
        }
    }

    (
        Token {
            kind: TokenKind::String(source[content_start..].to_owned()),
            span: SourceSpan {
                start,
                end: source.len(),
            },
        },
        source.len(),
        Some(Diagnostic {
            related: Vec::new(),
            span: SourceSpan {
                start,
                end: source.len(),
            },
            message: "unterminated string literal".to_owned(),
            suggestion: Some("close the string literal".to_owned()),
        }),
    )
}

/// The value kind of a `declaration_block` clause (Shape 1, DR-0011 amended
/// 2026-07-08 with `Duration`/`Glob`/`Schema`/`Scalar`/`Flag`). The order-free
/// analog of `body::SlotKind` for top-level declarations. A `Flag` clause is a
/// bare presence clause carrying no value.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) enum ClauseKind {
    Identifier,
    Expression,
    Duration,
    Glob,
    Schema,
    Scalar,
    Flag,
}

/// The typed AST node a migrated declaration lowers to — the one hand-written
/// seam of the otherwise data-driven Shape 1 pipeline. `effect_operation`
/// lowers to a uniform node, but the seven decls each build a distinct typed
/// node, so a future dispatch slice switches on this. Unused in D2.0 beyond
/// being carried in the spec.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) enum DeclAstKind {
    Tracker,
    Channel,
    Counter,
    Lease,
    Ledger,
    MemoryPool,
    FileStore,
    Stream,
    Credential,
}

/// One order-free clause of a `declaration_block` construct: a named value
/// (`words` = the build-time-split clause-name tokens; single-word names are a
/// one-element slice), an optional `connective` consumed before the value
/// (`Some("by")` for ledger `partition by`; shares Shape 2's vocabulary plus
/// `by`), a value `kind`, whether it is a `[ ... ]` `list`, and the
/// `unknown_hint` shown when a sibling clause name is not recognized. The
/// order-free analog of `body::EffectSlotSpec`.
///
/// `required`/`missing_summary` are NOT carried here: required-ness is a
/// validation concern, not a parse concern. For the std decls it is enforced
/// by the typed-node builder (`item_from_decl_ast`, the hand-written seam,
/// which also owns the bespoke domain guidance); the manifest still declares
/// `required`/`missing_summary` as the third-party contract validated by the
/// CLI manifest validator.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ClauseSpec {
    pub(crate) name: &'static str,
    pub(crate) words: &'static [&'static str],
    pub(crate) connective: Option<&'static str>,
    pub(crate) kind: ClauseKind,
    pub(crate) list: bool,
    unknown_hint: &'static str,
}

/// The full grammar of one `declaration_block` construct (Shape 1). `keyword`
/// is the full head phrase (`"memory pool"`/`"file store"`); `keyword_words`
/// is its whitespace-split tokens (head-word dispatch reads `keyword_words[0]`).
/// `ast_kind` is the hand-written builder seam.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct DeclarationBlockSpec {
    pub(crate) keyword: &'static str,
    pub(crate) keyword_words: &'static [&'static str],
    ast_kind: DeclAstKind,
    pub(crate) clauses: &'static [ClauseSpec],
}

// The table itself is generated at build time from the grammar-only manifests
// (std/grammars/*.json) by build.rs, mirroring `EFFECT_OPERATION_GRAMMAR`: each
// declaration_block construct's DR-0011 `grammar` object transcribes into one
// `DeclarationBlockSpec` row, so the manifests are the single source of parse
// grammar and the table can never drift from them. D2.0 builds the table and
// unit-tests it; nothing dispatches through it yet.
include!(concat!(env!("OUT_DIR"), "/declaration_block_grammar.rs"));

/// The parsed value of one matched `declaration_block` clause. A `Scalar` clause
/// is literal-polymorphic: `cap`/`slots`/`context limit` carry a `Number`, while
/// file-store `root` and channel `destination` carry `Str` — the grammar marks
/// both `scalar` and the per-decl builder casts to the field's width/shape.
/// `Missing` records a clause whose name matched but whose value failed to parse,
/// so the first-word span is still captured (file-store `root_span` is set on the
/// clause keyword regardless of the value's fate).
#[derive(Clone, Debug)]
pub(crate) enum ClauseValue {
    Ident(Ident),
    Idents(Vec<Ident>),
    Duration(u64),
    Number(u32),
    Str(StringLiteral),
    Globs(Vec<String>),
    Flag,
    Missing,
}

/// The order-free accumulator a generic `parse_declaration_block` fills as it
/// reads a decl's brace block, keyed by the spec clause `name`; the per-decl
/// typed-node builder reads it by name. Each record also carries the FIRST
/// clause-name-word token span (file-store/memory-pool serialize these into the
/// AST for `whip fmt`). Last write wins, matching the hand parsers' field
/// overwrite. The Shape-1 analog of the ordered field vector Shape 2 builds.
pub(crate) struct ClauseBag {
    records: Vec<(&'static str, SourceSpan, ClauseValue)>,
}

impl ClauseBag {
    fn new() -> Self {
        ClauseBag {
            records: Vec::new(),
        }
    }

    fn record(&mut self, name: &'static str, first_word_span: SourceSpan, value: ClauseValue) {
        self.records.push((name, first_word_span, value));
    }

    fn get(&self, name: &str) -> Option<&(&'static str, SourceSpan, ClauseValue)> {
        self.records
            .iter()
            .rev()
            .find(|(clause, _, _)| *clause == name)
    }

    fn ident(&self, name: &str) -> Option<Ident> {
        match self.get(name) {
            Some((_, _, ClauseValue::Ident(ident))) => Some(ident.clone()),
            _ => None,
        }
    }

    fn idents(&self, name: &str) -> Option<Vec<Ident>> {
        match self.get(name) {
            Some((_, _, ClauseValue::Idents(idents))) => Some(idents.clone()),
            _ => None,
        }
    }

    fn duration(&self, name: &str) -> Option<u64> {
        match self.get(name) {
            Some((_, _, ClauseValue::Duration(seconds))) => Some(*seconds),
            _ => None,
        }
    }

    fn number(&self, name: &str) -> Option<u32> {
        match self.get(name) {
            Some((_, _, ClauseValue::Number(value))) => Some(*value),
            _ => None,
        }
    }

    fn text(&self, name: &str) -> Option<String> {
        self.text_literal(name).map(|literal| literal.value)
    }

    fn text_literal(&self, name: &str) -> Option<StringLiteral> {
        match self.get(name) {
            Some((_, _, ClauseValue::Str(literal))) => Some(literal.clone()),
            _ => None,
        }
    }

    fn globs(&self, name: &str) -> Vec<String> {
        match self.get(name) {
            Some((_, _, ClauseValue::Globs(values))) => values.clone(),
            _ => Vec::new(),
        }
    }

    fn flag(&self, name: &str) -> bool {
        matches!(self.get(name), Some((_, _, ClauseValue::Flag)))
    }

    fn span(&self, name: &str) -> Option<SourceSpan> {
        self.get(name).map(|(_, span, _)| *span)
    }
}

pub(crate) struct Parser<'a> {
    pub(crate) source: &'a str,
    pub(crate) tokens: Vec<Token>,
    pub(crate) pos: usize,
    pub(crate) diagnostics: Vec<Diagnostic>,
    /// S7 inline contract payloads: classes synthesized from `output result {
    /// … }`-style blocks, appended to the item list after the parse loop.
    pub(crate) pending_contract_classes: Vec<ClassDecl>,
}

pub(crate) struct ParsedWorkflow {
    decl: WorkflowDecl,
    explicit_body: bool,
}

impl Parser<'_> {
    fn parse_program(&mut self) -> Program {
        let mut workflow = None;
        let mut workflow_tags = Vec::new();
        let mut workflow_description = None;
        let mut workflows = Vec::new();
        let mut patterns = Vec::new();
        let mut items = Vec::new();
        let mut pending_tags = Vec::new();
        let mut pending_description = None;

        while !self.is_at_end() {
            if self.at_symbol('@') {
                if let Some(tag) = self.parse_tag() {
                    pending_tags.push(tag);
                }
            } else if self.at_ident("description") {
                self.parse_pending_description(&mut pending_description);
            } else if self.at_ident("workflow") {
                if let Some(parsed_workflow) = self.parse_workflow(
                    std::mem::take(&mut pending_tags),
                    pending_description.take(),
                ) {
                    if parsed_workflow.explicit_body {
                        workflows.push(parsed_workflow.decl);
                    } else {
                        if workflow.is_some() {
                            self.diagnostics.push(Diagnostic { related: Vec::new(),
                                span: parsed_workflow.decl.name.span,
                                message: "multiple implicit workflow headers are not supported"
                                    .to_owned(),
                                suggestion: Some(
                                    "use explicit `workflow Name { ... }` declarations with `--root`"
                                        .to_owned(),
                                ),
                            });
                        }
                        workflow_tags = parsed_workflow.decl.tags;
                        workflow_description = parsed_workflow.decl.description;
                        // A header-form workflow carries no block, so its only
                        // items are the compact-signature contracts (if any);
                        // those are top-level for a single-workflow program.
                        items.extend(parsed_workflow.decl.items);
                        workflow = Some(parsed_workflow.decl.name);
                    }
                }
            } else if self.at_ident("pattern") {
                self.reject_pending_tags(&mut pending_tags, "pattern");
                self.reject_pending_description(&mut pending_description, "pattern");
                if let Some(pattern) = self.parse_pattern() {
                    patterns.push(pattern);
                }
            } else if let Some(item) =
                self.parse_declaration_item(&mut pending_tags, &mut pending_description)
            {
                items.push(item);
            } else if self.reject_gherkin_misuse() {
                continue;
            } else {
                if self.is_at_end() {
                    break;
                }
                self.unexpected("top-level declaration");
                if !self.is_at_end() {
                    self.advance();
                }
            }
        }

        // S7: classes synthesized from inline contract payloads join the item
        // list like ordinary declarations.
        items.extend(
            std::mem::take(&mut self.pending_contract_classes)
                .into_iter()
                .map(Item::Class),
        );

        Program {
            workflow,
            workflow_tags,
            workflow_description,
            workflows,
            patterns,
            items,
        }
    }

    fn parse_workflow(
        &mut self,
        tags: Vec<TagDecl>,
        description: Option<StringLiteral>,
    ) -> Option<ParsedWorkflow> {
        let start = self.expect_keyword("workflow")?.span.start;
        let name = self.expect_ident("workflow name")?;
        let mut explicit_body = false;
        let mut items = Vec::new();
        let mut end = name.span.end;
        // Optional compact contract signature: `Name(in: T, ...) -> Out [! Fail]`.
        // Desugars to the same `input`/`output`/`failure` contract decls as the
        // keyword form, with the output named `result` and the failure `error`
        // (the conventional names). Both forms are legal; `whip fmt` re-emits the
        // keyword lines (one canonical stored shape).
        if self.at_symbol('(') {
            if let Some((contracts, signature_end)) = self.parse_compact_contract_signature() {
                end = signature_end;
                items.extend(contracts.into_iter().map(Item::WorkflowContract));
            }
        }
        if self.at_symbol('{') {
            explicit_body = true;
            self.expect_symbol('{')?;
            let mut pending_tags = Vec::new();
            let mut pending_description = None;
            while !self.is_at_end() && !self.at_symbol('}') {
                if self.at_symbol('@') {
                    if let Some(tag) = self.parse_tag() {
                        pending_tags.push(tag);
                    }
                    continue;
                }
                if self.at_ident("description") {
                    self.parse_pending_description(&mut pending_description);
                    continue;
                }
                if self.at_ident("workflow") || self.at_ident("pattern") {
                    self.reject_pending_tags(&mut pending_tags, "workflow body declaration");
                    self.reject_pending_description(
                        &mut pending_description,
                        "workflow body declaration",
                    );
                    self.unexpected("workflow body declaration");
                    self.advance();
                    continue;
                }
                if let Some(item) =
                    self.parse_declaration_item(&mut pending_tags, &mut pending_description)
                {
                    items.push(item);
                } else if self.reject_gherkin_misuse() {
                    continue;
                } else {
                    if self.is_at_end() {
                        break;
                    }
                    self.reject_pending_tags(&mut pending_tags, "workflow body declaration");
                    self.reject_pending_description(
                        &mut pending_description,
                        "workflow body declaration",
                    );
                    self.unexpected("workflow body declaration");
                    if !self.is_at_end() {
                        self.advance();
                    }
                }
            }
            if let Some(close) = self.expect_symbol('}') {
                end = close.span.end;
            }
        }
        // S7: classes synthesized from this workflow's inline contract payloads
        // stay in ITS scope (braced-workflow schemas are workflow-scoped), so
        // two workflows can both write `output result { … }` without their
        // `output.result` classes colliding.
        items.extend(
            std::mem::take(&mut self.pending_contract_classes)
                .into_iter()
                .map(Item::Class),
        );
        Some(ParsedWorkflow {
            decl: WorkflowDecl {
                name,
                tags,
                description,
                items,
                span: SourceSpan { start, end },
            },
            explicit_body,
        })
    }

    /// Parses a compact contract signature `(name: Type, ...) -> Output [! Failure]`
    /// into the same contract decls the keyword form produces. The output binding
    /// is named `result` and the failure `error` — the conventional names used by
    /// `complete result` / `fail error`. Returns the contracts and the signature's
    /// end offset (so the workflow span covers it).
    fn parse_compact_contract_signature(&mut self) -> Option<(Vec<WorkflowContractDecl>, usize)> {
        self.expect_symbol('(')?;
        let mut contracts = Vec::new();
        while !self.is_at_end() && !self.at_symbol(')') {
            let name = self.expect_ident("workflow input name")?;
            self.expect_symbol(':')?;
            let ty = self.parse_type()?;
            let span = name.span.join(ty.span());
            contracts.push(WorkflowContractDecl {
                kind: WorkflowContractKind::Input,
                name,
                ty,
                span,
            });
            if self.at_symbol(',') {
                self.advance();
            } else if !self.at_symbol(')') {
                self.unexpected("`,` or `)`");
                while !self.is_at_end() && !self.at_symbol(')') && !self.at_symbol(',') {
                    self.advance();
                }
            }
        }
        self.expect_symbol(')')?;
        self.expect_thin_arrow()?;
        let output_ty = self.parse_type()?;
        let output_span = output_ty.span();
        let mut end = output_span.end;
        contracts.push(WorkflowContractDecl {
            kind: WorkflowContractKind::Output,
            name: Ident {
                name: "result".to_owned(),
                span: output_span,
            },
            ty: output_ty,
            span: output_span,
        });
        if self.at_symbol('!') {
            self.advance();
            let failure_ty = self.parse_type()?;
            let failure_span = failure_ty.span();
            end = failure_span.end;
            contracts.push(WorkflowContractDecl {
                kind: WorkflowContractKind::Failure,
                name: Ident {
                    name: "error".to_owned(),
                    span: failure_span,
                },
                ty: failure_ty,
                span: failure_span,
            });
        }
        Some((contracts, end))
    }

    fn parse_tag(&mut self) -> Option<TagDecl> {
        let at = self.expect_symbol('@')?;
        let name_start = at.span.end;
        let mut name_end = name_start;
        for (offset, ch) in self.source[name_start..].char_indices() {
            if ch.is_whitespace() {
                break;
            }
            name_end = name_start + offset + ch.len_utf8();
        }
        let name = self.source[name_start..name_end].to_owned();
        while !self.is_at_end() && self.peek().is_some_and(|token| token.span.start < name_end) {
            self.advance();
        }
        let span = SourceSpan {
            start: at.span.start,
            end: name_end,
        };
        if name.is_empty() {
            self.diagnostics.push(Diagnostic {
                related: Vec::new(),
                span,
                message: "tag is missing a name".to_owned(),
                suggestion: Some("write a tag such as `@fixture`".to_owned()),
            });
            return None;
        }
        if !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | '.'))
        {
            self.diagnostics.push(Diagnostic {
                related: Vec::new(),
                span,
                message: format!("tag `@{name}` contains unsupported characters"),
                suggestion: Some(
                    "use letters, digits, `_`, `-`, `.`, or `:` in tag names".to_owned(),
                ),
            });
            return None;
        }
        Some(TagDecl { name, span })
    }

    fn reject_pending_tags(&mut self, pending_tags: &mut Vec<TagDecl>, target: &str) {
        for tag in pending_tags.drain(..) {
            self.diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: tag.span,
                message: format!("tag `@{}` cannot be attached to {target}", tag.name),
                suggestion: Some(
                    "place tags on workflows, matrices, assertions, or rules".to_owned(),
                ),
            });
        }
    }

    fn parse_pending_description(&mut self, pending_description: &mut Option<StringLiteral>) {
        let Some(description) = self.parse_description() else {
            return;
        };
        if let Some(previous) = pending_description.replace(description) {
            self.diagnostics.push(Diagnostic { related: Vec::new(),
                span: previous.span,
                message: "description is not attached to a declaration".to_owned(),
                suggestion: Some(
                    "place only one `description \"...\"` immediately before the target declaration"
                        .to_owned(),
                ),
            });
        }
    }

    fn parse_description(&mut self) -> Option<StringLiteral> {
        let description = self.expect_keyword("description")?;
        let Some(value) = self.expect_string("description string") else {
            return Some(StringLiteral {
                value: String::new(),
                span: description.span,
            });
        };
        Some(value)
    }

    fn reject_pending_description(
        &mut self,
        pending_description: &mut Option<StringLiteral>,
        target: &str,
    ) {
        if let Some(description) = pending_description.take() {
            self.diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: description.span,
                message: format!("description cannot be attached to {target}"),
                suggestion: Some(
                    "place descriptions on workflows, matrices, assertions, or rules".to_owned(),
                ),
            });
        }
    }

    fn reject_gherkin_misuse(&mut self) -> bool {
        let Some(token) = self.peek() else {
            return false;
        };
        let TokenKind::Ident(keyword) = &token.kind else {
            return false;
        };
        if !is_gherkin_keyword(keyword) {
            return false;
        }
        let span = token.span;
        self.diagnostics.push(Diagnostic { related: Vec::new(),
            span,
            message: format!(
                "Gherkin keyword `{keyword}` is not WhippleScript workflow syntax"
            ),
            suggestion: Some(
                "use `workflow`, `table`, `rule ... when ... => { ... }`, and `assert` instead of free-text Given/When/Then steps"
                    .to_owned(),
            ),
        });
        self.advance_to_line_end(span.start);
        true
    }

    fn advance_to_line_end(&mut self, line_start: usize) {
        let line_end = self.source[line_start..]
            .find('\n')
            .map(|offset| line_start + offset)
            .unwrap_or(self.source.len());
        while self.peek().is_some_and(|token| token.span.start < line_end) {
            self.advance();
        }
    }

    fn parse_declaration_item(
        &mut self,
        pending_tags: &mut Vec<TagDecl>,
        pending_description: &mut Option<StringLiteral>,
    ) -> Option<Item> {
        // Data-driven `declaration_block` dispatch (Shape 1), the first check —
        // the analog of `body.rs`'s `effect_operation_spec` hook. Head-word peek;
        // the five real exceptions (harness/agent/signal/source/coerce) and all
        // core decls are absent from the grammar table, so table membership is
        // the partition. Every declaration-family construct parses through
        // `parse_declaration_block` + its typed-node builder — no hand parsers.
        if let Some(spec) = self.declaration_block_spec_at() {
            self.reject_pending_tags(pending_tags, spec.keyword);
            self.reject_pending_description(pending_description, spec.keyword);
            return self.parse_declaration_block(spec);
        }
        if self.at_ident("include") {
            self.reject_pending_tags(pending_tags, "include");
            self.reject_pending_description(pending_description, "include");
            self.parse_include().map(Item::Include)
        } else if self.at_ident("use") {
            self.reject_pending_tags(pending_tags, "use");
            self.reject_pending_description(pending_description, "use");
            self.parse_use().map(Item::Use)
        } else if self.at_ident("pattern") {
            self.reject_pending_tags(pending_tags, "pattern");
            self.reject_pending_description(pending_description, "pattern");
            self.parse_pattern().map(Item::Pattern)
        } else if self.at_ident("apply") {
            self.reject_pending_tags(pending_tags, "apply");
            self.reject_pending_description(pending_description, "apply");
            self.parse_apply().map(Item::Apply)
        } else if self.at_ident("input") || self.at_ident("output") || self.at_ident("failure") {
            self.reject_pending_tags(pending_tags, "workflow contract");
            self.reject_pending_description(pending_description, "workflow contract");
            self.parse_workflow_contract().map(Item::WorkflowContract)
        } else if self.at_ident("flow") {
            // R2 (language-refinement campaign): the `flow` declaration was
            // REMOVED — sequential pipelines are written as a rule chaining
            // steps with `then <binding> <- <effect>`.
            let span = self
                .peek()
                .map(|token| token.span)
                .unwrap_or(SourceSpan { start: 0, end: 0 });
            self.diagnostics.push(Diagnostic {
                related: Vec::new(),
                span,
                message: "the `flow` declaration was removed".to_owned(),
                suggestion: Some(
                    "write a `rule` and chain sequential steps with `then <binding> <- <effect>`"
                        .to_owned(),
                ),
            });
            // Recovery: swallow the whole flow declaration (headers + balanced
            // body) so the body's statements don't each re-error as bogus
            // top-level declarations.
            let mut depth = 0usize;
            while !self.is_at_end() {
                let token = self.advance();
                match &token.kind {
                    TokenKind::Symbol('{') => depth += 1,
                    TokenKind::Symbol('}') => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            None
        } else if self.at_ident("action") {
            self.reject_pending_tags(pending_tags, "action");
            self.reject_pending_description(pending_description, "action");
            self.parse_action().map(Item::Action)
        } else if self.at_ident("harness") {
            self.reject_pending_tags(pending_tags, "harness");
            self.reject_pending_description(pending_description, "harness");
            self.parse_harness().map(Item::Harness)
        } else if self.at_ident("agent") {
            self.reject_pending_tags(pending_tags, "agent");
            self.reject_pending_description(pending_description, "agent");
            self.parse_agent().map(Item::Agent)
        } else if self.at_ident("enum") {
            self.reject_pending_tags(pending_tags, "enum");
            self.reject_pending_description(pending_description, "enum");
            self.parse_enum().map(Item::Enum)
        } else if self.at_ident("signal") {
            self.reject_pending_tags(pending_tags, "signal");
            self.reject_pending_description(pending_description, "signal");
            self.parse_event().map(Item::Event)
        } else if self.at_ident("gauge") {
            self.reject_pending_tags(pending_tags, "gauge");
            self.reject_pending_description(pending_description, "gauge");
            self.parse_gauge().map(Item::Gauge)
        } else if self.at_ident("campaign") {
            self.reject_pending_tags(pending_tags, "campaign");
            self.reject_pending_description(pending_description, "campaign");
            self.parse_campaign().map(Item::Campaign)
        } else if self.at_ident("mark") {
            self.reject_pending_tags(pending_tags, "mark");
            self.reject_pending_description(pending_description, "mark");
            self.parse_mark().map(Item::Mark)
        } else if self.at_ident("source") {
            self.reject_pending_tags(pending_tags, "source");
            self.reject_pending_description(pending_description, "source");
            self.parse_source()
                .map(|source| Item::Source(Box::new(source)))
        } else if self.at_ident("test") {
            self.reject_pending_tags(pending_tags, "test");
            self.reject_pending_description(pending_description, "test");
            self.parse_test().map(Item::Test)
        } else if self.at_ident("class") {
            self.reject_pending_tags(pending_tags, "class");
            self.reject_pending_description(pending_description, "class");
            self.parse_class().map(Item::Class)
        } else if self.at_ident("table") {
            self.parse_table(std::mem::take(pending_tags), pending_description.take())
                .map(Item::Table)
        } else if self.at_ident("coerce") {
            self.reject_pending_tags(pending_tags, "coerce");
            self.reject_pending_description(pending_description, "coerce");
            self.parse_coerce().map(Item::Coerce)
        } else if self.at_ident("assert") {
            self.parse_assert(std::mem::take(pending_tags), pending_description.take())
                .map(Item::Assert)
        } else if self.at_ident("rule") {
            self.parse_rule(std::mem::take(pending_tags), pending_description.take())
                .map(Item::Rule)
        } else {
            None
        }
    }

    /// Peek (without consuming) the `declaration_block` grammar whose keyword
    /// head word matches the current token. Head-word dispatch only
    /// (`keyword_words[0]`, NOT a 2-token peek — a 2-token peek mis-routes a
    /// malformed `file <x>` to the wrong diagnostic; tail validation belongs in
    /// the per-decl parser). The exact analog of `body::effect_operation_spec`.
    pub(crate) fn declaration_block_spec_at(&self) -> Option<&'static DeclarationBlockSpec> {
        let head = match self.peek().map(|token| &token.kind) {
            Some(TokenKind::Ident(value)) => value.as_str(),
            _ => return None,
        };
        DECLARATION_BLOCK_GRAMMAR
            .iter()
            .find(|spec| spec.keyword_words.first() == Some(&head))
    }

    /// The single generic top-level `declaration_block` parser (Shape 1) — the
    /// analog of `body::parse_effect_operation`. The head word is already matched
    /// by `declaration_block_spec_at`; this consumes the keyword (validating any
    /// tail word, e.g. `store` after `file`), the name, and an order-free brace
    /// block of clauses into a `ClauseBag`, then hands off to the per-decl typed
    /// node builder (`item_from_decl_ast`). Unknown clauses emit the spec's
    /// `unknown_hint` and resynchronize (file-store precedent).
    fn parse_declaration_block(&mut self, spec: &'static DeclarationBlockSpec) -> Option<Item> {
        let head = *spec.keyword_words.first()?;
        let start = self.expect_keyword(head)?.span.start;
        for tail in &spec.keyword_words[1..] {
            if !self.consume_ident(tail) {
                self.expected(format!("`{tail}` after `{head}`"));
                return None;
            }
        }
        let name = self.expect_ident(&format!("{} name", spec.keyword))?;
        // Surface-defaults batch (R4 S1/S2): the block is optional. A bare
        // declaration (`tracker backlog`) parses with an empty clause bag;
        // constructs whose clauses are all optional/defaulted accept it, and
        // ones with required clauses report their own missing-field
        // diagnostics (better than "expected `{`").
        if !self.at_symbol('{') {
            let span = SourceSpan {
                start,
                end: name.span.end,
            };
            let bag = ClauseBag::new();
            return self.item_from_decl_ast(spec.ast_kind, &bag, name, span);
        }
        self.expect_symbol('{')?;
        let field_label = format!("{} field", spec.keyword);
        let mut bag = ClauseBag::new();
        while !self.is_at_end() && !self.at_symbol('}') {
            let Some(field) = self.expect_ident(&field_label) else {
                self.synchronize_to_block_item();
                continue;
            };
            // Greedy multi-word clause-name match: `field` is the first word;
            // extend with follow words while some clause name is a longer prefix
            // match (file-store `allow read`/`allow write`, memory `context limit`).
            let first_word_span = field.span;
            let mut words = vec![field.name];
            let matched = loop {
                let depth = words.len();
                if let Some(clause) = spec.clauses.iter().find(|clause| {
                    clause.words.len() == depth
                        && clause
                            .words
                            .iter()
                            .zip(&words)
                            .all(|(a, b)| *a == b.as_str())
                }) {
                    break Some(clause);
                }
                let extendable = spec.clauses.iter().any(|clause| {
                    clause.words.len() > depth
                        && clause
                            .words
                            .iter()
                            .zip(&words)
                            .all(|(a, b)| *a == b.as_str())
                });
                if !extendable {
                    break None;
                }
                let Some(next) = self.expect_ident("clause name") else {
                    break None;
                };
                words.push(next.name);
            };
            let Some(clause) = matched else {
                let hint = spec.clauses.first().map(|clause| clause.unknown_hint);
                self.diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: first_word_span,
                    message: format!("unknown {} field `{}`", spec.keyword, words.join(" ")),
                    suggestion: hint.map(str::to_owned),
                });
                self.synchronize_to_block_item();
                continue;
            };
            // Clause connective (ledger `partition by`): mandatory (M2) — a
            // missing connective is a parse error, like a Shape 2 slot connective.
            if let Some(connective) = clause.connective {
                if !self.consume_ident(connective) {
                    self.diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: first_word_span,
                        message: format!("expected `{connective}` after `{}`", clause.name),
                        suggestion: Some(format!("write `{} {connective} <field>`", clause.name)),
                    });
                    self.synchronize_to_block_item();
                    continue;
                }
            }
            let value = self.parse_clause_value(clause);
            bag.record(clause.name, first_word_span, value);
        }
        let close = self.expect_symbol('}')?;
        let span = SourceSpan {
            start,
            end: close.span.end,
        };
        self.item_from_decl_ast(spec.ast_kind, &bag, name, span)
    }

    /// Parse one clause's value by its `ClauseKind`, recording `Missing` on a
    /// failed parse so the clause's first-word span is still captured. A `Scalar`
    /// is literal-polymorphic (number or string); the builder casts.
    fn parse_clause_value(&mut self, clause: &ClauseSpec) -> ClauseValue {
        match clause.kind {
            // DR-0011 vocabulary amendment (DR-0052 grammar pass,
            // 2026-07-31): `list` extends to `identifier` clauses — a
            // bracketed bare-ident list (`members [worker, reviewer]`),
            // parsed by the same list parser the agent `tools` grant uses.
            ClauseKind::Identifier if clause.list => self
                .parse_ident_list()
                .map_or(ClauseValue::Missing, |(idents, _)| {
                    ClauseValue::Idents(idents)
                }),
            ClauseKind::Identifier | ClauseKind::Schema => self
                .expect_ident(&format!("{} value", clause.name))
                .map_or(ClauseValue::Missing, ClauseValue::Ident),
            ClauseKind::Duration => self
                .parse_decl_duration_seconds(&format!("{} duration", clause.name))
                .map_or(ClauseValue::Missing, ClauseValue::Duration),
            ClauseKind::Scalar => match self.peek().map(|token| &token.kind) {
                Some(TokenKind::String(_)) => self
                    .expect_string(&format!("{} value", clause.name))
                    .map_or(ClauseValue::Missing, ClauseValue::Str),
                _ => self
                    .expect_u32(&format!("{} value", clause.name))
                    .map_or(ClauseValue::Missing, |(value, _)| {
                        ClauseValue::Number(value)
                    }),
            },
            ClauseKind::Glob if clause.list => {
                // Route glob lists through the shared list parser UNCHANGED — it
                // keeps its "skill string" element label (avoids file-store
                // negative-fixture churn).
                let globs = self
                    .parse_string_list()
                    .map(|(literals, _)| literals.into_iter().map(|l| l.value).collect())
                    .unwrap_or_default();
                ClauseValue::Globs(globs)
            }
            ClauseKind::Glob => self
                .expect_string(&format!("{} value", clause.name))
                .map_or(ClauseValue::Missing, ClauseValue::Str),
            ClauseKind::Flag => ClauseValue::Flag,
            // No migrated decl carries an expression clause; recorded inert.
            ClauseKind::Expression => ClauseValue::Missing,
        }
    }

    /// The one hand-written seam of the data-driven pipeline: build the distinct
    /// typed AST node each `declaration_block` lowers to from the order-free
    /// `ClauseBag`, reproducing each hand parser's required-field check, bespoke
    /// missing-field diagnostic, and field-width casts exactly (so success `.ir`
    /// and coord IR fields are byte-identical).
    fn item_from_decl_ast(
        &mut self,
        ast_kind: DeclAstKind,
        bag: &ClauseBag,
        name: Ident,
        span: SourceSpan,
    ) -> Option<Item> {
        match ast_kind {
            DeclAstKind::Tracker => {
                // S1: `tracker <name>` bare — provider defaults to `builtin`,
                // today's only provider.
                let provider = bag.ident("provider").unwrap_or_else(|| Ident {
                    name: "builtin".to_owned(),
                    span,
                });
                Some(Item::Tracker(TrackerDecl {
                    name,
                    provider,
                    span,
                }))
            }
            DeclAstKind::Channel => {
                // S2: `channel <name>` bare — provider defaults to `local`.
                let provider = bag.ident("provider").unwrap_or_else(|| Ident {
                    name: "local".to_owned(),
                    span,
                });
                Some(Item::Channel(ChannelDecl {
                    name,
                    provider,
                    workspace: bag.ident("workspace"),
                    destination: bag.text_literal("destination"),
                    span,
                }))
            }
            DeclAstKind::Credential => {
                let Some(kind) = bag.ident("kind") else {
                    self.diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span,
                        message: format!("credential `{}` must declare its kind", name.name),
                        suggestion: Some(format!(
                            "add `kind <kind>` inside the credential block ({})",
                            crate::credential_kind_spellings().join(" | ")
                        )),
                    });
                    return None;
                };
                Some(Item::Credential(CredentialDecl { name, kind, span }))
            }
            DeclAstKind::Stream => {
                let Some(members) = bag.idents("members").filter(|idents| !idents.is_empty())
                else {
                    self.diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span,
                        message: format!("stream `{}` must declare its members", name.name),
                        suggestion: Some(
                            "a stream is a declared collaboration: name its member \
                             agents with `members [<agent>, ...]`"
                                .to_owned(),
                        ),
                    });
                    return None;
                };
                Some(Item::Stream(StreamDecl {
                    name,
                    members,
                    staleness_seconds: bag.duration("staleness"),
                    span,
                }))
            }
            DeclAstKind::Counter => {
                let key_type = bag.ident("key");
                let cap = bag.number("cap").map(i64::from);
                // `reset`: identifier + membership check; an invalid period keeps
                // the value (matching the hand parser) but emits the enum diagnostic.
                let reset = bag.ident("reset").map(|period| {
                    if !matches!(
                        period.name.as_str(),
                        "hourly" | "daily" | "weekly" | "monthly"
                    ) {
                        self.diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: period.span,
                            message: format!("unknown reset period `{}`", period.name),
                            suggestion: Some(
                                "use `hourly`, `daily`, `weekly`, or `monthly`".to_owned(),
                            ),
                        });
                    }
                    period.name
                });
                let shared = bag.flag("shared");
                let (Some(key_type), Some(cap), Some(reset)) = (key_type, cap, reset) else {
                    self.diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span,
                        message: format!(
                            "counter `{}` must declare `key`, `cap`, and `reset`",
                            name.name
                        ),
                        suggestion: Some(
                            "every counter is bounded: declare all three fields".to_owned(),
                        ),
                    });
                    return None;
                };
                Some(Item::Counter(CounterDecl {
                    name,
                    key_type,
                    cap,
                    reset,
                    timezone: bag.text("timezone"),
                    shared,
                    span,
                }))
            }
            DeclAstKind::Lease => {
                let key_type = bag.ident("key");
                let slots = bag.number("slots").unwrap_or(1);
                let ttl_seconds = bag.duration("ttl");
                let shared = bag.flag("shared");
                let (Some(key_type), Some(ttl_seconds)) = (key_type, ttl_seconds) else {
                    self.diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span,
                        message: format!(
                            "lease `{}` must declare a `key` type and a `ttl` backstop",
                            name.name
                        ),
                        suggestion: Some(
                            "every lease is bounded: declare `key <Type>` and `ttl <duration>`"
                                .to_owned(),
                        ),
                    });
                    return None;
                };
                Some(Item::Lease(LeaseDecl {
                    name,
                    key_type,
                    slots,
                    ttl_seconds,
                    shared,
                    span,
                }))
            }
            DeclAstKind::Ledger => {
                let entry_schema = bag.ident("entry");
                let partition_field = bag.ident("partition");
                let retain_seconds = bag.duration("retain");
                let shared = bag.flag("shared");
                let (Some(entry_schema), Some(partition_field), Some(retain_seconds)) =
                    (entry_schema, partition_field, retain_seconds)
                else {
                    self.diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span,
                        message: format!(
                            "ledger `{}` must declare `entry`, `partition by`, and `retain`",
                            name.name
                        ),
                        suggestion: Some(
                            "every ledger is bounded and partitioned: declare all three fields"
                                .to_owned(),
                        ),
                    });
                    return None;
                };
                Some(Item::Ledger(LedgerDecl {
                    name,
                    entry_schema,
                    partition_field,
                    retain_seconds,
                    shared,
                    span,
                }))
            }
            DeclAstKind::FileStore => {
                let root_span = bag.span("root");
                let read_span = bag.span("allow read");
                let write_span = bag.span("allow write");
                let provider_span = bag.span("provider");
                let read_globs = bag.globs("allow read");
                let write_globs = bag.globs("allow write");
                let provider = bag.ident("provider");
                let Some(root) = bag.text("root") else {
                    self.diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span,
                        message: format!("file store `{}` is missing a root", name.name),
                        suggestion: Some(
                            "add `root \"<dir>\"` inside the file store block".to_owned(),
                        ),
                    });
                    return None;
                };
                Some(Item::FileStore(FileStoreDecl {
                    name,
                    root,
                    read_globs,
                    write_globs,
                    provider,
                    root_span,
                    read_span,
                    write_span,
                    provider_span,
                    span,
                }))
            }
            DeclAstKind::MemoryPool => {
                let context_limit = bag.number("context limit").map(u64::from);
                // The span serializes only alongside a value (hand parser sets it
                // inside the successful-parse branch).
                let context_limit_span = context_limit.and(bag.span("context limit"));
                Some(Item::MemoryPool(MemoryPoolDecl {
                    name,
                    context_limit,
                    context_limit_span,
                    span,
                }))
            }
        }
    }

    fn parse_pattern(&mut self) -> Option<PatternDecl> {
        let start = self.expect_keyword("pattern")?.span.start;
        let name = self.expect_ident("pattern name")?;
        let type_params = self.parse_type_param_list().unwrap_or_default();
        let open = self.expect_symbol('{')?;
        let mut items = Vec::new();
        let mut pending_tags = Vec::new();
        let mut pending_description = None;
        while !self.is_at_end() && !self.at_symbol('}') {
            if self.at_symbol('@') {
                if let Some(tag) = self.parse_tag() {
                    pending_tags.push(tag);
                }
                continue;
            }
            if self.at_ident("description") {
                self.parse_pending_description(&mut pending_description);
                continue;
            }
            if self.at_ident("workflow") || self.at_ident("pattern") {
                self.reject_pending_tags(&mut pending_tags, "pattern body declaration");
                self.reject_pending_description(
                    &mut pending_description,
                    "pattern body declaration",
                );
                self.unexpected("pattern body declaration");
                self.advance();
                continue;
            }
            if let Some(item) =
                self.parse_declaration_item(&mut pending_tags, &mut pending_description)
            {
                items.push(item);
            } else if self.reject_gherkin_misuse() {
                continue;
            } else {
                if self.is_at_end() {
                    break;
                }
                self.reject_pending_tags(&mut pending_tags, "pattern body declaration");
                self.reject_pending_description(
                    &mut pending_description,
                    "pattern body declaration",
                );
                self.unexpected("pattern body declaration");
                self.advance();
            }
        }
        let end = self
            .expect_symbol('}')
            .map(|token| token.span.end)
            .unwrap_or(open.span.end);
        Some(PatternDecl {
            name,
            type_params,
            items,
            span: SourceSpan { start, end },
        })
    }

    fn parse_type_param_list(&mut self) -> Option<Vec<Ident>> {
        if !self.at_symbol('<') {
            return Some(Vec::new());
        }
        self.expect_symbol('<')?;
        let mut params = Vec::new();
        while !self.is_at_end() && !self.at_symbol('>') {
            params.push(self.expect_ident("type parameter")?);
            if self.at_symbol(',') {
                self.advance();
            } else if !self.at_symbol('>') {
                self.unexpected("`,` or `>`");
                while !self.is_at_end() && !self.at_symbol('>') && !self.at_symbol(',') {
                    self.advance();
                }
            }
        }
        self.expect_symbol('>')?;
        Some(params)
    }

    fn parse_type_arg_list(&mut self) -> Option<Vec<TypeSyntax>> {
        if !self.at_symbol('<') {
            return Some(Vec::new());
        }
        self.expect_symbol('<')?;
        let mut args = Vec::new();
        while !self.is_at_end() && !self.at_symbol('>') {
            args.push(self.parse_type()?);
            if self.at_symbol(',') {
                self.advance();
            } else if !self.at_symbol('>') {
                self.unexpected("`,` or `>`");
                while !self.is_at_end() && !self.at_symbol('>') && !self.at_symbol(',') {
                    self.advance();
                }
            }
        }
        self.expect_symbol('>')?;
        Some(args)
    }

    fn parse_apply(&mut self) -> Option<ApplyDecl> {
        let start = self.expect_keyword("apply")?.span.start;
        let pattern = self.expect_ident("pattern name")?;
        let type_args = self.parse_type_arg_list().unwrap_or_default();
        self.expect_keyword("as")?;
        let alias = self.expect_ident("pattern application alias")?;
        let body = self.parse_block_source()?;
        let span = SourceSpan {
            start,
            end: body.span.end,
        };
        Some(ApplyDecl {
            pattern,
            type_args,
            alias,
            body,
            span,
        })
    }

    fn parse_include(&mut self) -> Option<IncludeDecl> {
        self.expect_keyword("include")?;
        Some(IncludeDecl {
            path: self.expect_string("include path")?,
        })
    }

    fn parse_workflow_contract(&mut self) -> Option<WorkflowContractDecl> {
        let keyword = self.advance().clone();
        let kind = match &keyword.kind {
            TokenKind::Ident(value) if value == "input" => WorkflowContractKind::Input,
            TokenKind::Ident(value) if value == "output" => WorkflowContractKind::Output,
            TokenKind::Ident(value) if value == "failure" => WorkflowContractKind::Failure,
            _ => return None,
        };
        let name = self.expect_ident("workflow contract name")?;
        // S7 (surface-defaults batch): an inline payload block synthesizes a
        // hygienic anonymous class (the `decide` precedent) — `output result {
        // message string }` declares the class `output.result` implicitly. The
        // dotted name cannot collide with a user class (identifiers cannot
        // contain `.`).
        if self.at_symbol('{') {
            self.advance();
            let mut fields = Vec::new();
            while !self.is_at_end() && !self.at_symbol('}') {
                let Some(field_name) = self.expect_ident("contract payload field name") else {
                    self.synchronize_to_block_item();
                    continue;
                };
                let Some(field_ty) = self.parse_type() else {
                    self.synchronize_to_block_item();
                    continue;
                };
                let field_span = field_name.span.join(field_ty.span());
                fields.push(ClassField {
                    name: field_name,
                    ty: field_ty,
                    is_key: false,
                    presence_condition: None,
                    span: field_span,
                });
            }
            let close_span = self.peek().map(|token| token.span);
            self.expect_symbol('}')?;
            let contract_keyword = match kind {
                WorkflowContractKind::Input => "input",
                WorkflowContractKind::Output => "output",
                WorkflowContractKind::Failure => "failure",
            };
            let class_name = format!("{contract_keyword}.{}", name.name);
            let end = close_span.map(|span| span.end).unwrap_or(name.span.end);
            let span = SourceSpan {
                start: keyword.span.start,
                end,
            };
            self.pending_contract_classes.push(ClassDecl {
                name: Ident {
                    name: class_name.clone(),
                    span,
                },
                fields,
                span,
            });
            return Some(WorkflowContractDecl {
                kind,
                name,
                ty: TypeSyntax::Ref {
                    name: Ident {
                        name: class_name,
                        span,
                    },
                },
                span,
            });
        }
        let ty = self.parse_type()?;
        let span = keyword.span.join(ty.span());
        Some(WorkflowContractDecl {
            kind,
            name,
            ty,
            span,
        })
    }

    fn parse_use(&mut self) -> Option<UseDecl> {
        self.expect_keyword("use")?;
        if self.at_ident("plugin") || self.at_ident("skill") {
            let removed_kind = self.advance().clone();
            let removed_label = match &removed_kind.kind {
                TokenKind::Ident(value) => value.as_str(),
                _ => "",
            };
            self.diagnostics.push(Diagnostic { related: Vec::new(),
                span: removed_kind.span,
                message: format!("`use {removed_label}` is no longer supported"),
                suggestion: Some(
                    "write `use std.memory` for package libraries; attach skills with `agent { skills [...] }`"
                        .to_owned(),
                ),
            });
        }
        Some(UseDecl {
            name: self.expect_use_name("package library name")?,
        })
    }

    /// Parses `<n><unit>` durations at declaration level (`ttl 10m`,
    /// `retain 90d`) — the lexer splits them into a number and a unit ident.
    fn parse_decl_duration_seconds(&mut self, label: &str) -> Option<u64> {
        let (value, span) = self.expect_u32(label)?;
        let unit = self.expect_ident(label)?;
        match body::parse_short_duration_seconds(&format!("{value}{}", unit.name)) {
            Some(seconds) if seconds > 0 => Some(seconds),
            _ => {
                self.diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: span.join(unit.span),
                    message: format!("invalid duration `{value}{}`", unit.name),
                    suggestion: Some("use `<n><unit>` with unit s, m, h, or d".to_owned()),
                });
                None
            }
        }
    }

    fn parse_harness(&mut self) -> Option<HarnessDecl> {
        let start = self.expect_keyword("harness")?.span.start;
        let name = self.expect_ident("harness name")?;
        self.expect_symbol(':')?;
        let kind = self.expect_ident("harness kind")?;
        let span = SourceSpan {
            start,
            end: kind.span.end,
        };
        Some(HarnessDecl { name, kind, span })
    }

    fn parse_agent(&mut self) -> Option<AgentDecl> {
        let start = self.expect_keyword("agent")?.span.start;
        let name = self.expect_ident("agent name")?;
        let harness = if self.at_ident("using") {
            self.advance();
            Some(self.expect_ident("harness name")?)
        } else {
            None
        };
        let delegated_to = if harness.is_none() && self.at_ident("delegated") {
            self.advance();
            self.expect_keyword("to")?;
            Some(self.expect_ident("delegate provider")?)
        } else {
            None
        };
        // A bare declaration (`agent researcher`) is valid: every field has a
        // default (managed provider, least-authority profile, capacity 1).
        if !self.at_symbol('{') {
            let end = delegated_to
                .as_ref()
                .map(|ident| ident.span.end)
                .or_else(|| harness.as_ref().map(|ident| ident.span.end))
                .unwrap_or(name.span.end);
            return Some(AgentDecl {
                name,
                harness,
                delegated_to,
                fields: Vec::new(),
                span: SourceSpan { start, end },
            });
        }
        let open = self.expect_symbol('{')?;
        let mut fields = Vec::new();

        while !self.is_at_end() && !self.at_symbol('}') {
            let Some(field_name) = self.expect_ident("agent field") else {
                self.synchronize_to_block_item();
                continue;
            };

            match field_name.name.as_str() {
                "provider" => {
                    if let Some(provider) = self.expect_ident("provider name") {
                        fields.push(AgentField::Provider(provider));
                    } else {
                        self.synchronize_to_block_item();
                    }
                }
                "profile" => {
                    if let Some(value) = self.expect_string("profile string") {
                        fields.push(AgentField::Profile(value));
                    } else {
                        self.synchronize_to_block_item();
                    }
                }
                "capacity" => {
                    if let Some((value, span)) = self.expect_u32("capacity value") {
                        fields.push(AgentField::Capacity(value, span));
                    } else {
                        self.synchronize_to_block_item();
                    }
                }
                "skills" => {
                    if let Some((skills, span)) = self.parse_string_list() {
                        fields.push(AgentField::Skills(skills, span));
                    } else {
                        self.synchronize_to_block_item();
                    }
                }
                "capabilities" => {
                    if let Some((capabilities, span)) = self.parse_string_list() {
                        fields.push(AgentField::Capabilities(capabilities, span));
                    } else {
                        self.synchronize_to_block_item();
                    }
                }
                "requires" => {
                    if let Some((classes, span)) = self.parse_feature_class_list() {
                        fields.push(AgentField::Requires(classes, span));
                    } else {
                        self.synchronize_to_block_item();
                    }
                }
                "tools" => {
                    if let Some((tools, span)) = self.parse_ident_list() {
                        fields.push(AgentField::Tools(tools, span));
                    } else {
                        self.synchronize_to_block_item();
                    }
                }
                "compaction" => {
                    if let Some(strategy) = self.expect_ident("compaction strategy") {
                        fields.push(AgentField::Compaction(strategy));
                    } else {
                        self.synchronize_to_block_item();
                    }
                }
                "thread" => {
                    if let Some(mode) = self.expect_ident("thread mode") {
                        fields.push(AgentField::Thread(mode));
                    } else {
                        self.synchronize_to_block_item();
                    }
                }
                "settings" => {
                    if let Some(sources) = self.expect_ident("settings source") {
                        fields.push(AgentField::Settings(sources));
                    } else {
                        self.synchronize_to_block_item();
                    }
                }
                _ => {
                    let span = field_name.span;
                    fields.push(AgentField::Unknown {
                        name: field_name,
                        span,
                    });
                    self.synchronize_to_block_item();
                }
            }
        }

        let end = self
            .expect_symbol('}')
            .map(|token| token.span.end)
            .unwrap_or(open.span.end);

        Some(AgentDecl {
            name,
            harness,
            delegated_to,
            fields,
            span: SourceSpan { start, end },
        })
    }

    fn parse_enum(&mut self) -> Option<EnumDecl> {
        let start = self.expect_keyword("enum")?.span.start;
        let name = self.expect_ident("enum name")?;
        let open = self.expect_symbol('{')?;
        let mut variants = Vec::new();

        let mut previous_variant_end: Option<usize> = None;
        while !self.is_at_end() && !self.at_symbol('}') {
            let Some(variant) = self.expect_ident("enum variant") else {
                self.synchronize_to_block_item();
                continue;
            };
            // One variant per line: two variants sharing a line is almost
            // always pasted prose or a forgotten `#` — and the stray words
            // would otherwise become variants that pollute the domain (and
            // reach coerce output schemas).
            if let Some(previous_end) = previous_variant_end {
                let line_of = |offset: usize| {
                    self.source[..offset.min(self.source.len())]
                        .bytes()
                        .filter(|byte| *byte == b'\n')
                        .count()
                };
                if line_of(previous_end) == line_of(variant.span.start) {
                    self.diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: variant.span,
                        message: format!(
                            "enum `{}` declares variant `{}` on the same line as the previous variant",
                            name.name, variant.name
                        ),
                        suggestion: Some("write one enum variant per line".to_owned()),
                    });
                }
            }
            // A brace body makes this a data-carrying variant; the body
            // reuses the class field grammar (sum types, spec/sum-types.md).
            let mut fields = Vec::new();
            let mut end = variant.span.end;
            if self.at_symbol('{') {
                self.expect_symbol('{');
                while !self.is_at_end() && !self.at_symbol('}') {
                    let Some(field_name) = self.expect_ident("variant field name") else {
                        self.synchronize_to_block_item();
                        continue;
                    };
                    let Some(ty) = self.parse_type() else {
                        self.synchronize_to_block_item();
                        continue;
                    };
                    fields.push(ClassField {
                        span: field_name.span.join(ty.span()),
                        name: field_name,
                        ty,
                        is_key: false,
                        presence_condition: None,
                    });
                }
                if let Some(close) = self.expect_symbol('}') {
                    end = close.span.end;
                }
            }
            let span = SourceSpan {
                start: variant.span.start,
                end,
            };
            previous_variant_end = Some(end);
            variants.push(EnumVariantDecl {
                name: variant,
                fields,
                span,
            });
        }

        let end = self
            .expect_symbol('}')
            .map(|token| token.span.end)
            .unwrap_or(open.span.end);

        Some(EnumDecl {
            name,
            variants,
            span: SourceSpan { start, end },
        })
    }

    fn parse_event(&mut self) -> Option<EventDecl> {
        let start = self.expect_keyword("signal")?.span.start;
        // Dotted lowercase name (`deploy.finished`), matching the `when fact`
        // convention and distinct from PascalCase classes.
        let first = self.expect_ident("signal name")?;
        let mut name = first.name.clone();
        let mut name_span = first.span;
        while self.at_symbol('.') {
            self.expect_symbol('.');
            let segment = self.expect_ident("signal name segment")?;
            name.push('.');
            name.push_str(&segment.name);
            name_span = name_span.join(segment.span);
        }
        if !name.contains('.')
            || name
                .split('.')
                .any(|segment| segment.chars().next().is_some_and(char::is_uppercase))
        {
            self.diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: name_span,
                message: format!("signal name `{name}` must be dotted lowercase"),
                suggestion: Some(
                    "use a dotted lowercase name such as `deploy.finished`".to_owned(),
                ),
            });
        }
        let open = self.expect_symbol('{')?;
        let mut fields = Vec::new();
        while !self.is_at_end() && !self.at_symbol('}') {
            let Some(field_name) = self.expect_ident("signal field name") else {
                self.synchronize_to_block_item();
                continue;
            };
            let Some(ty) = self.parse_type() else {
                self.synchronize_to_block_item();
                continue;
            };
            let presence_condition = self.parse_field_presence_condition();
            fields.push(ClassField {
                span: field_name.span.join(ty.span()),
                name: field_name,
                ty,
                is_key: false,
                presence_condition,
            });
        }
        let end = self
            .expect_symbol('}')
            .map(|token| token.span.end)
            .unwrap_or(open.span.end);
        Some(EventDecl {
            name,
            name_span,
            fields,
            span: SourceSpan { start, end },
        })
    }

    /// A dotted name (`summarize.extract`, `std.spend`) as one string + span.
    fn parse_dotted_name_spanned(&mut self, label: &str) -> Option<(String, SourceSpan)> {
        let first = self.expect_ident(label)?;
        let mut name = first.name.clone();
        let mut span = first.span;
        while self.at_symbol('.') {
            self.expect_symbol('.');
            let segment = self.expect_ident(label)?;
            name.push('.');
            name.push_str(&segment.name);
            span = span.join(segment.span);
        }
        Some((name, span))
    }

    fn parse_gauge_ref(&mut self, label: &str) -> Option<GaugeRef> {
        let (name, span) = self.parse_dotted_name_spanned(label)?;
        Some(GaugeRef { name, span })
    }

    /// A comma-separated gauge-reference list (`ascend a, std.spend`).
    fn parse_gauge_ref_list(&mut self, label: &str, into: &mut Vec<GaugeRef>) -> Option<()> {
        into.push(self.parse_gauge_ref(label)?);
        while self.at_symbol(',') {
            self.expect_symbol(',');
            into.push(self.parse_gauge_ref(label)?);
        }
        Some(())
    }

    /// A numeric literal as exact source text: `800` or `0.9`. The
    /// declaration lexer emits digits-only Number tokens, so a fraction is
    /// Number `.` Number.
    fn parse_decl_number_text(&mut self, label: &str) -> Option<(String, SourceSpan)> {
        let token = self.peek()?;
        let TokenKind::Number(whole) = token.kind.clone() else {
            self.expected(label);
            return None;
        };
        let mut span = token.span;
        let mut text = whole;
        self.advance();
        if self.at_symbol('.') {
            self.expect_symbol('.');
            let token = self.peek()?;
            let TokenKind::Number(fraction) = token.kind.clone() else {
                self.expected(format!("{label} fraction digits"));
                return None;
            };
            text.push('.');
            text.push_str(&fraction);
            span = span.join(token.span);
            self.advance();
        }
        Some((text, span))
    }

    /// Bar direction: `at least` (true) / `at most` (false). The declaration
    /// tokenizer steps over `>=`/`<=` silently (the `is` precedent), so a
    /// user writing an operator gets a targeted diagnostic instead of a
    /// direction-less bar: the raw source gap before the next token is
    /// inspected for the dropped operator.
    fn parse_bar_direction(&mut self, label: &str) -> Option<bool> {
        if self.consume_ident("at") {
            if self.consume_ident("least") {
                return Some(true);
            }
            if self.consume_ident("most") {
                return Some(false);
            }
            self.expected(format!("`least` or `most` after `at` in {label}"));
            return None;
        }
        let gap_start = self.last_span_end();
        let gap_end = self
            .peek()
            .map(|token| token.span.start)
            .unwrap_or(gap_start);
        let gap = &self.source[gap_start..gap_end.max(gap_start)];
        let suggestion = if gap.contains(">=") {
            Some("write `at least` (the declaration grammar uses words, not `>=`)".to_owned())
        } else if gap.contains("<=") {
            Some("write `at most` (the declaration grammar uses words, not `<=`)".to_owned())
        } else {
            Some("write `at least <n>` or `at most <n>`".to_owned())
        };
        self.diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: SourceSpan {
                start: gap_start,
                end: gap_end.max(gap_start),
            },
            message: format!("expected `at least` or `at most` in {label}"),
            suggestion,
        });
        None
    }

    /// `mark "<name>" after <site>`.
    fn parse_mark(&mut self) -> Option<MarkDecl> {
        let start = self.expect_keyword("mark")?.span.start;
        let name = self.expect_string("mark name")?;
        if !self.consume_ident("after") {
            self.expected("`after` and a committing site in the mark declaration");
            return None;
        }
        let (site, site_span) = self.parse_dotted_name_spanned("mark site")?;
        Some(MarkDecl {
            name,
            site,
            span: SourceSpan {
                start,
                end: site_span.end,
            },
        })
    }

    /// `gauge <name> [on <site>] { judge via <form> [expect <bar>]
    /// [inputs <gauges>] }`.
    fn parse_gauge(&mut self) -> Option<GaugeDecl> {
        let start = self.expect_keyword("gauge")?.span.start;
        let name = self.expect_ident("gauge name")?;
        let site = if self.consume_ident("on") {
            Some(self.parse_dotted_name_spanned("gauge site")?.0)
        } else {
            None
        };
        let open = self.expect_symbol('{')?;
        let mut judge: Option<GaugeJudge> = None;
        let mut expect: Option<GaugeBar> = None;
        let mut inputs: Vec<GaugeRef> = Vec::new();
        while !self.is_at_end() && !self.at_symbol('}') {
            if self.at_ident("judge") {
                let keyword = self.advance().clone();
                if !self.consume_ident("via") {
                    self.expected("`via` after `judge`");
                    self.synchronize_to_block_item();
                    continue;
                }
                let form = if self.consume_ident("coerce") {
                    self.expect_ident("coerce judge name").and_then(|name| {
                        let mut args = Vec::new();
                        if self.at_symbol('(') {
                            self.expect_symbol('(');
                            loop {
                                let (path, _) = self.parse_dotted_name_spanned("judge argument")?;
                                args.push(path);
                                if !self.at_symbol(',') {
                                    break;
                                }
                                self.expect_symbol(',')?;
                            }
                            self.expect_symbol(')')?;
                        }
                        Some(GaugeJudge::Coerce(name, args))
                    })
                } else if self.consume_ident("prompt") {
                    self.expect_string("prompt judge template")
                        .map(GaugeJudge::Prompt)
                } else if self.consume_ident("exec") {
                    self.expect_string("exec judge command")
                        .map(GaugeJudge::Exec)
                } else if self.consume_ident("labels") {
                    self.expect_string("labels source").map(GaugeJudge::Labels)
                } else {
                    self.diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: keyword.span,
                        message: "unknown judge form".to_owned(),
                        suggestion: Some(
                            "judge forms are `coerce <Name>`, `prompt \"<template>\"`, \
                             `exec \"<command>\"`, and `labels \"<source>\"`"
                                .to_owned(),
                        ),
                    });
                    None
                };
                let Some(form) = form else {
                    self.synchronize_to_block_item();
                    continue;
                };
                if judge.is_some() {
                    self.diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: keyword.span,
                        message: "gauge declares more than one judge".to_owned(),
                        suggestion: Some("a gauge has exactly one judge".to_owned()),
                    });
                } else {
                    judge = Some(form);
                }
            } else if self.at_ident("expect") {
                let keyword = self.advance().clone();
                let subject_ident = match self.expect_ident("bar subject") {
                    Some(ident) => ident,
                    None => {
                        self.synchronize_to_block_item();
                        continue;
                    }
                };
                let subject = if subject_ident.name == "P" && self.at_symbol('(') {
                    self.expect_symbol('(');
                    let Some(field) = self.expect_ident("chance bar field") else {
                        self.synchronize_to_block_item();
                        continue;
                    };
                    if self.expect_symbol(')').is_none() {
                        self.synchronize_to_block_item();
                        continue;
                    }
                    GaugeBarSubject::Chance { field }
                } else {
                    let stat = &subject_ident.name;
                    let is_quantile = stat.len() > 1
                        && stat.starts_with('p')
                        && stat[1..].chars().all(|ch| ch.is_ascii_digit());
                    if stat != "mean" && !is_quantile {
                        self.diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: subject_ident.span,
                            message: format!("unknown bar statistic `{stat}`"),
                            suggestion: Some(
                                "bars are chance-shaped (`P(<field>)`) or stat-shaped \
                                 (`mean`, `p10`, `p90`, ...)"
                                    .to_owned(),
                            ),
                        });
                    }
                    GaugeBarSubject::Stat {
                        stat: subject_ident,
                    }
                };
                let Some(at_least) = self.parse_bar_direction("the gauge bar") else {
                    self.synchronize_to_block_item();
                    continue;
                };
                let Some((threshold, threshold_span)) =
                    self.parse_decl_number_text("bar threshold")
                else {
                    self.synchronize_to_block_item();
                    continue;
                };
                if expect.is_some() {
                    self.diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: keyword.span,
                        message: "gauge declares more than one bar".to_owned(),
                        suggestion: Some("a gauge has at most one `expect` bar".to_owned()),
                    });
                } else {
                    expect = Some(GaugeBar {
                        subject,
                        at_least,
                        threshold,
                        span: keyword.span.join(threshold_span),
                    });
                }
            } else if self.at_ident("inputs") {
                self.advance();
                if self
                    .parse_gauge_ref_list("input gauge name", &mut inputs)
                    .is_none()
                {
                    self.synchronize_to_block_item();
                }
            } else {
                let span = self.peek().map(|token| token.span).unwrap_or(open.span);
                self.diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span,
                    message: "unknown gauge clause".to_owned(),
                    suggestion: Some(
                        "gauge clauses are `judge via`, `expect`, and `inputs`".to_owned(),
                    ),
                });
                self.synchronize_to_block_item();
            }
        }
        let end = self
            .expect_symbol('}')
            .map(|token| token.span.end)
            .unwrap_or(open.span.end);
        let Some(judge) = judge else {
            self.diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: name.span,
                message: format!("gauge `{}` declares no judge", name.name),
                suggestion: Some(
                    "add `judge via coerce <Name>`, `judge via prompt \"<template>\"`, \
                     `judge via exec \"<command>\"`, or `judge via labels \"<source>\"`"
                        .to_owned(),
                ),
            });
            return None;
        };
        Some(GaugeDecl {
            name,
            site,
            judge,
            expect,
            inputs,
            span: SourceSpan { start, end },
        })
    }

    /// `campaign <name> { ascend … [reach …] [guard …] [sacrifice …] }`.
    fn parse_campaign(&mut self) -> Option<CampaignDecl> {
        let start = self.expect_keyword("campaign")?.span.start;
        let name = self.expect_ident("campaign name")?;
        let open = self.expect_symbol('{')?;
        let mut ascend: Vec<GaugeRef> = Vec::new();
        let mut reach: Vec<CampaignReach> = Vec::new();
        let mut guard: Vec<CampaignGuard> = Vec::new();
        let mut sacrifice: Vec<GaugeRef> = Vec::new();
        let mut proposer_redacted = false;
        while !self.is_at_end() && !self.at_symbol('}') {
            if self.at_ident("ascend") {
                self.advance();
                if self
                    .parse_gauge_ref_list("ascend gauge name", &mut ascend)
                    .is_none()
                {
                    self.synchronize_to_block_item();
                }
            } else if self.at_ident("reach") {
                let keyword = self.advance().clone();
                let Some(gauge) = self.parse_gauge_ref("reach gauge name") else {
                    self.synchronize_to_block_item();
                    continue;
                };
                let Some(at_least) = self.parse_bar_direction("the reach target") else {
                    self.synchronize_to_block_item();
                    continue;
                };
                let Some((threshold, threshold_span)) =
                    self.parse_decl_number_text("reach threshold")
                else {
                    self.synchronize_to_block_item();
                    continue;
                };
                // A trailing duration unit (`800ms`) lexes as a separate
                // ident; a clause keyword never collides with the unit set.
                let unit = if self
                    .peek()
                    .map(|token| {
                        matches!(&token.kind, TokenKind::Ident(name)
                            if matches!(name.as_str(), "ms" | "s" | "m" | "h" | "d"))
                    })
                    .unwrap_or(false)
                {
                    self.expect_ident("unit").map(|ident| ident.name)
                } else {
                    None
                };
                reach.push(CampaignReach {
                    gauge,
                    at_least,
                    threshold,
                    unit,
                    span: keyword.span.join(threshold_span),
                });
            } else if self.at_ident("guard") {
                let keyword = self.advance().clone();
                let Some(gauge) = self.parse_gauge_ref("guard gauge name") else {
                    self.synchronize_to_block_item();
                    continue;
                };
                if !self.consume_ident("within") {
                    self.expected("`within` after the guarded gauge");
                    self.synchronize_to_block_item();
                    continue;
                }
                let Some((band_percent, band_span)) = self.parse_decl_number_text("guard band")
                else {
                    self.synchronize_to_block_item();
                    continue;
                };
                if !self.consume_ident("percent") {
                    self.expected("`percent` after the guard band");
                    self.synchronize_to_block_item();
                    continue;
                }
                guard.push(CampaignGuard {
                    gauge,
                    band_percent,
                    span: keyword.span.join(band_span),
                });
            } else if self.at_ident("sacrifice") {
                self.advance();
                if self
                    .parse_gauge_ref_list("sacrifice gauge name", &mut sacrifice)
                    .is_none()
                {
                    self.synchronize_to_block_item();
                }
            } else if self.at_ident("proposer") {
                self.advance();
                if self.consume_ident("redacted") {
                    proposer_redacted = true;
                } else {
                    self.expected("`redacted` after `proposer`");
                    self.synchronize_to_block_item();
                }
            } else {
                let span = self.peek().map(|token| token.span).unwrap_or(open.span);
                self.diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span,
                    message: "unknown campaign clause".to_owned(),
                    suggestion: Some(
                        "campaign clauses are `ascend`, `reach`, `guard`, `sacrifice`, \
                         and `proposer redacted`"
                            .to_owned(),
                    ),
                });
                self.synchronize_to_block_item();
            }
        }
        let end = self
            .expect_symbol('}')
            .map(|token| token.span.end)
            .unwrap_or(open.span.end);
        if ascend.is_empty() && reach.is_empty() {
            self.diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: name.span,
                message: format!("campaign `{}` names nothing to improve", name.name),
                suggestion: Some("add an `ascend` or `reach` clause".to_owned()),
            });
        }
        Some(CampaignDecl {
            name,
            ascend,
            reach,
            guard,
            sacrifice,
            proposer_redacted,
            span: SourceSpan { start, end },
        })
    }

    fn last_span_end(&self) -> usize {
        self.pos
            .checked_sub(1)
            .and_then(|index| self.tokens.get(index))
            .map(|token| token.span.end)
            .unwrap_or(0)
    }

    fn parse_dotted_name(&mut self, label: &str) -> Option<String> {
        let first = self.expect_ident(label)?;
        let mut name = first.name.clone();
        while self.at_symbol('.') {
            self.advance();
            let segment = self.expect_ident(label)?;
            name.push('.');
            name.push_str(&segment.name);
        }
        Some(name)
    }

    /// Capture the source text of an expression from the current token to end of
    /// line (the `assert`/guard idiom), advancing past the consumed tokens.
    fn capture_expr_to_line_end(&mut self) -> (String, SourceSpan) {
        let start = self
            .peek()
            .map(|token| token.span.start)
            .unwrap_or(self.source.len());
        let line_end = self.source[start..]
            .find('\n')
            .map(|offset| start + offset)
            .unwrap_or(self.source.len());
        let mut end = start;
        while !self.is_at_end() {
            let Some(token) = self.peek() else { break };
            if token.span.start >= line_end {
                break;
            }
            let token_end = token.span.end.min(line_end);
            self.advance();
            end = token_end;
        }
        let span = SourceSpan { start, end };
        trimmed_source_text(self.source_text(span), span)
    }

    /// Capture source text up to (but not including) a terminator identifier or a
    /// closing brace — used for a predicate bounded by `is`.
    fn capture_expr_until_ident(&mut self, terminator: &str) -> (String, SourceSpan) {
        let start = self
            .peek()
            .map(|token| token.span.start)
            .unwrap_or(self.source.len());
        let mut end = start;
        while !self.is_at_end() && !self.at_ident(terminator) && !self.at_symbol('}') {
            let Some(token) = self.peek() else { break };
            let token_end = token.span.end;
            self.advance();
            end = token_end;
        }
        let span = SourceSpan { start, end };
        trimmed_source_text(self.source_text(span), span)
    }

    fn parse_test(&mut self) -> Option<TestDecl> {
        let start = self.expect_keyword("test")?.span.start;
        let name = self.expect_string("test name")?;
        let open = self.expect_symbol('{')?;
        let mut workflow = None;
        let mut clauses = Vec::new();
        while !self.is_at_end() && !self.at_symbol('}') {
            if self.at_ident("workflow") {
                self.advance();
                match self.expect_ident("workflow name") {
                    Some(name) => {
                        if workflow.is_some() {
                            self.diagnostics.push(Diagnostic {
                                related: Vec::new(),
                                span: name.span,
                                message: "a test scenario binds at most one `workflow`".to_owned(),
                                suggestion: Some(
                                    "remove the extra `workflow <Name>` header".to_owned(),
                                ),
                            });
                        }
                        workflow = Some(name);
                    }
                    None => self.synchronize_to_block_item(),
                }
            } else if self.at_ident("given") {
                match self.parse_given() {
                    Some(clause) => clauses.push(TestClause::Given(clause)),
                    None => self.synchronize_to_block_item(),
                }
            } else if self.at_ident("stub") {
                match self.parse_stub() {
                    Some(clause) => clauses.push(TestClause::Stub(clause)),
                    None => self.synchronize_to_block_item(),
                }
            } else if self.at_ident("run") {
                match self.parse_run() {
                    Some(clause) => clauses.push(TestClause::Run(clause)),
                    None => self.synchronize_to_block_item(),
                }
            } else if self.at_ident("expect") {
                match self.parse_expect() {
                    Some(clause) => clauses.push(TestClause::Expect(clause)),
                    None => self.synchronize_to_block_item(),
                }
            } else {
                self.unexpected("a test clause (`workflow`, `given`, `stub`, `run`, or `expect`)");
                self.synchronize_to_block_item();
            }
        }
        let end = self
            .expect_symbol('}')
            .map(|token| token.span.end)
            .unwrap_or(open.span.end);
        Some(TestDecl {
            name,
            workflow,
            clauses,
            span: SourceSpan { start, end },
        })
    }

    fn parse_test_record(&mut self) -> Option<(Vec<TestField>, usize)> {
        let open = self.expect_symbol('{')?;
        let mut fields = Vec::new();
        while !self.is_at_end() && !self.at_symbol('}') {
            let Some(name) = self.expect_ident("test field name") else {
                self.synchronize_to_block_item();
                continue;
            };
            let (value, value_span) = self.capture_expr_to_line_end();
            fields.push(TestField {
                span: name.span.join(value_span),
                name,
                value,
            });
        }
        let end = self
            .expect_symbol('}')
            .map(|token| token.span.end)
            .unwrap_or(open.span.end);
        Some((fields, end))
    }

    fn parse_given(&mut self) -> Option<GivenClause> {
        let start = self.expect_keyword("given")?.span.start;
        if self.consume_ident("input") {
            let (fields, end) = self.parse_test_record()?;
            Some(GivenClause::Input {
                fields,
                span: SourceSpan { start, end },
            })
        } else if self.consume_ident("fact") {
            let ty = self.expect_ident("fact type")?;
            let (fields, end) = self.parse_test_record()?;
            Some(GivenClause::Fact {
                ty,
                fields,
                span: SourceSpan { start, end },
            })
        } else if self.consume_ident("signal") {
            let name = self.parse_dotted_name("signal name")?;
            let (fields, end) = self.parse_test_record()?;
            Some(GivenClause::Signal {
                name,
                fields,
                span: SourceSpan { start, end },
            })
        } else if self.consume_ident("clock") {
            if !self.consume_ident("at") {
                self.expected("`at <timestamp>` after `given clock`");
            }
            let at = self.expect_string("clock timestamp")?;
            let end = at.span.end;
            Some(GivenClause::Clock {
                at,
                span: SourceSpan { start, end },
            })
        } else if self.consume_ident("tracker") {
            let tracker = self.parse_dotted_name("tracker name")?;
            if !self.consume_ident("issue") {
                self.expected("`issue { … }` after `given tracker <name>`");
            }
            let (fields, end) = self.parse_test_record()?;
            Some(GivenClause::Tracker {
                tracker,
                fields,
                span: SourceSpan { start, end },
            })
        } else if self.consume_ident("file") {
            let store = self.parse_dotted_name("file store name")?;
            if !self.consume_ident("at") {
                self.expected("`at <path> \"<content>\"` after `given file <store>`");
            }
            let path = self.expect_string("file path")?;
            let content = self.expect_string("file content")?;
            let end = content.span.end;
            Some(GivenClause::File {
                store,
                path,
                content,
                span: SourceSpan { start, end },
            })
        } else {
            self.unexpected(
                "`input`, `fact`, `signal`, `clock`, `tracker`, or `file` after `given`",
            );
            None
        }
    }

    fn parse_stub(&mut self) -> Option<StubClause> {
        let start = self.expect_keyword("stub")?.span.start;
        // Surface path: dotted-name segments up to the outcome, all on the `stub`
        // line. The trailing segment (before a `{`, string, or end-of-line) is the
        // outcome; the rest is the surface. v0 keeps this lexical: at least one
        // surface segment + one outcome.
        let line_end = self.source[start..]
            .find('\n')
            .map(|offset| start + offset)
            .unwrap_or(self.source.len());
        let mut segments = Vec::new();
        while matches!(
            self.peek().map(|token| &token.kind),
            Some(TokenKind::Ident(_))
        ) && self.peek().is_some_and(|token| token.span.start < line_end)
        {
            match self.parse_dotted_name("stub surface") {
                Some(segment) => segments.push(segment),
                None => break,
            }
        }
        if segments.len() < 2 {
            self.diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: SourceSpan {
                    start,
                    end: self.last_span_end(),
                },
                message: "stub needs a surface and an outcome (e.g. `stub agent triager succeeds`)"
                    .to_owned(),
                suggestion: Some("write `stub <surface...> <outcome> [payload]`".to_owned()),
            });
            return None;
        }
        let outcome = segments.pop().expect("outcome present");
        let surface = segments;
        let payload = if self.at_symbol('{') {
            let (fields, _) = self.parse_test_record()?;
            Some(StubPayload::Record(fields))
        } else if matches!(
            self.peek().map(|token| &token.kind),
            Some(TokenKind::String(_))
        ) {
            Some(StubPayload::Message(self.expect_string("stub message")?))
        } else {
            None
        };
        let end = self.last_span_end();
        Some(StubClause {
            surface,
            outcome,
            payload,
            span: SourceSpan { start, end },
        })
    }

    fn parse_run(&mut self) -> Option<RunClause> {
        let start = self.expect_keyword("run")?.span.start;
        let kind = if self.consume_ident("until") {
            if self.consume_ident("idle") {
                RunKind::UntilIdle
            } else if self.consume_ident("workflow") {
                if self.consume_ident("completed") {
                    RunKind::UntilWorkflowCompleted
                } else if self.consume_ident("failed") {
                    RunKind::UntilWorkflowFailed
                } else {
                    self.expected("`completed` or `failed` after `workflow`");
                    return None;
                }
            } else {
                self.expected("`idle` or `workflow completed|failed` after `until`");
                return None;
            }
        } else if self.consume_ident("for") {
            let (steps, _) = self.expect_u32("step count")?;
            if !self.consume_ident("steps") {
                self.expected("`steps` after the step count");
            }
            RunKind::ForSteps(steps)
        } else {
            self.expected("`until ...` or `for <N> steps` after `run`");
            return None;
        };
        let end = self.last_span_end();
        Some(RunClause {
            kind,
            span: SourceSpan { start, end },
        })
    }

    fn parse_expect(&mut self) -> Option<ExpectClause> {
        let start = self.expect_keyword("expect")?.span.start;
        let target = if self.consume_ident("workflow") {
            if self.consume_ident("completed") {
                ExpectTarget::WorkflowCompleted
            } else if self.consume_ident("failed") {
                let failure = if self.consume_ident("with") {
                    self.expect_ident("failure type")
                } else {
                    None
                };
                ExpectTarget::WorkflowFailed { failure }
            } else {
                self.expected("`completed` or `failed` after `workflow`");
                return None;
            }
        } else if self.consume_ident("rule") {
            let name = self.expect_ident("rule name")?;
            let status = if self.consume_ident("fired") {
                if matches!(
                    self.peek().map(|token| &token.kind),
                    Some(TokenKind::Number(_))
                ) {
                    let (count, _) = self.expect_u32("fired count")?;
                    if !self.consume_ident("times") {
                        self.expected("`times` after the fired count");
                    }
                    RuleStatus::FiredTimes(count)
                } else {
                    RuleStatus::Fired
                }
            } else if self.consume_ident("did") {
                if !self.consume_ident("not") {
                    self.expected("`not` in `did not fire`");
                }
                if !self.consume_ident("fire") {
                    self.expected("`fire` in `did not fire`");
                }
                RuleStatus::DidNotFire
            } else {
                self.expected("`fired`, `fired <N> times`, or `did not fire`");
                return None;
            };
            ExpectTarget::Rule { name, status }
        } else if self.consume_ident("effect") {
            let name = self.parse_dotted_name("effect name")?;
            let status = if self.consume_ident("requested") {
                EffectStatus::Requested
            } else if self.consume_ident("completed") {
                EffectStatus::Completed
            } else if self.consume_ident("failed") {
                EffectStatus::Failed
            } else {
                self.expected("`requested`, `completed`, or `failed` after the effect name");
                return None;
            };
            ExpectTarget::Effect { name, status }
        } else if self.consume_ident("diagnostic") {
            let code = self.parse_dotted_name("diagnostic code")?;
            ExpectTarget::Diagnostic { code }
        } else if self.consume_ident("no") {
            let name = self.parse_dotted_name("forbidden effect name")?;
            ExpectTarget::NoEffect { name }
        } else {
            let noun = self.parse_dotted_name("projection noun")?;
            let kind = self.parse_proj_query_kind()?;
            let end = self.last_span_end();
            ExpectTarget::Projection(ProjQuery {
                noun,
                kind,
                span: SourceSpan { start, end },
            })
        };
        let end = self.last_span_end();
        Some(ExpectClause {
            target,
            span: SourceSpan { start, end },
        })
    }

    fn parse_proj_query_kind(&mut self) -> Option<ProjQueryKind> {
        if self.consume_ident("exists") {
            return Some(ProjQueryKind::Exists);
        }
        if self.consume_ident("count") {
            if !self.consume_ident("where") {
                self.expected("`where <predicate> is <N>` after `count`");
                return None;
            }
            let (predicate, _) = self.capture_expr_until_ident("is");
            if !self.consume_ident("is") {
                self.expected("`is <N>` after the count predicate");
                return None;
            }
            let (count, _) = self.expect_u32("count value")?;
            return Some(ProjQueryKind::Count { predicate, count });
        }
        if self.consume_ident("where") {
            let (predicate, _) = self.capture_expr_to_line_end();
            return Some(ProjQueryKind::Where { predicate });
        }
        self.expected("`exists`, `count where ... is <N>`, or `where ...`");
        None
    }

    fn parse_source(&mut self) -> Option<SourceDecl> {
        let start = self.expect_keyword("source")?.span.start;
        let provider = self.expect_ident("source provider")?;
        let is_clock = provider.name == "clock";
        if !self.consume_ident("as") {
            self.expected("`as <name>` after the source provider");
            return None;
        }
        let name = self.expect_ident("source name")?;
        let open = self.expect_symbol('{')?;

        let mut recurrence: Option<Recurrence> = None;
        let mut timezone: Option<StringLiteral> = None;
        let mut missed: Option<MissedPolicy> = None;
        let mut path: Option<StringLiteral> = None;
        let mut watch: Option<StringLiteral> = None;
        let mut url: Option<StringLiteral> = None;
        let mut dedup: Option<SourceValue> = None;
        let mut observe_binding: Option<Ident> = None;
        let mut emit: Option<SourceEmit> = None;

        while !self.is_at_end() && !self.at_symbol('}') {
            if self.at_ident("every") || self.at_ident("at") {
                if let Some(parsed) = self.parse_recurrence() {
                    recurrence = Some(parsed);
                } else {
                    self.synchronize_to_block_item();
                }
            } else if self.at_ident("timezone") {
                self.advance();
                timezone = self.expect_string("timezone string");
            } else if self.at_ident("path") {
                self.advance();
                path = self.expect_string("path string");
            } else if self.at_ident("watch") {
                self.advance();
                watch = self.expect_string("watch glob string");
            } else if self.at_ident("url") {
                self.advance();
                url = self.expect_string("url string");
            } else if self.at_ident("dedup") {
                self.advance();
                dedup = self.parse_source_value();
            } else if self.at_ident("missed") {
                missed = self.parse_missed_policy();
            } else if self.at_ident("observe") {
                self.advance();
                if !self.consume_ident("as") {
                    self.expected("`as <binding>` after `observe`");
                }
                observe_binding = self.expect_ident("observe binding");
            } else if self.at_ident("emit") {
                emit = self.parse_source_emit();
            } else {
                self.unexpected(
                    "a source clause (`every`/`at`, `timezone`, `path`, `watch`, `url`, `dedup`, `missed`, `observe`, `emit`)",
                );
                self.synchronize_to_block_item();
            }
        }
        let end = self
            .expect_symbol('}')
            .map(|token| token.span.end)
            .unwrap_or(open.span.end);
        let span = SourceSpan { start, end };

        let observe_binding = match observe_binding {
            Some(binding) => binding,
            None => {
                self.diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span,
                    message: format!("source `{}` must declare `observe as <binding>`", name.name),
                    suggestion: Some("add `observe as tick`".to_owned()),
                });
                return None;
            }
        };
        let emit = match emit {
            Some(emit) => emit,
            None => {
                self.diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span,
                    message: format!(
                        "source `{}` must declare `emit <signal> {{ ... }}`",
                        name.name
                    ),
                    suggestion: Some("add `emit triage.tick { ... }`".to_owned()),
                });
                return None;
            }
        };

        let clock = if is_clock {
            let recurrence = match recurrence {
                Some(recurrence) => recurrence,
                None => {
                    self.diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span,
                        message: format!("clock source `{}` must declare a recurrence", name.name),
                        suggestion: Some(
                            "add `every weekday at 09:00`, `every 5m`, or `at 09:00`".to_owned(),
                        ),
                    });
                    return None;
                }
            };
            Some(ClockPolicy {
                recurrence,
                timezone,
                missed,
                span,
            })
        } else {
            if recurrence.is_some() || timezone.is_some() || missed.is_some() {
                self.diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span,
                    message: format!(
                        "source `{}` uses clock-only clauses but its provider is `{}`, not `clock`",
                        name.name, provider.name
                    ),
                    suggestion: Some(
                        "use `source clock as ...` for recurrence, timezone, or missed clauses"
                            .to_owned(),
                    ),
                });
            }
            None
        };

        Some(SourceDecl {
            name,
            provider,
            clock,
            path,
            watch,
            url,
            dedup,
            observe_binding,
            emit,
            span,
        })
    }

    fn parse_recurrence(&mut self) -> Option<Recurrence> {
        if self.at_ident("at") {
            let at = self.expect_keyword("at")?;
            let time = self.parse_time_of_day()?;
            return Some(Recurrence::At {
                span: at.span.join(time.span),
                time,
            });
        }
        let every = self.expect_keyword("every")?;
        if matches!(
            self.peek().map(|token| &token.kind),
            Some(TokenKind::Number(_))
        ) {
            let (value, _) = self.expect_u32("recurrence interval")?;
            let unit = self.expect_ident("duration unit (`s`, `m`, `h`, or `d`)")?;
            let seconds = match unit.name.as_str() {
                "s" => value as u64,
                "m" => value as u64 * 60,
                "h" => value as u64 * 3_600,
                "d" => value as u64 * 86_400,
                other => {
                    self.diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: unit.span,
                        message: format!("unknown duration unit `{other}`"),
                        suggestion: Some("use `s`, `m`, `h`, or `d`".to_owned()),
                    });
                    return None;
                }
            };
            return Some(Recurrence::EveryDuration {
                seconds,
                source: format!("{value}{}", unit.name),
                span: every.span.join(unit.span),
            });
        }
        let pattern_ident =
            self.expect_ident("calendar pattern (`day`, `weekday`, or a weekday)")?;
        let pattern = match pattern_ident.name.as_str() {
            "day" => CalendarPattern::Day,
            "weekday" => CalendarPattern::Weekday,
            "monday" => CalendarPattern::Weekly(Weekday::Monday),
            "tuesday" => CalendarPattern::Weekly(Weekday::Tuesday),
            "wednesday" => CalendarPattern::Weekly(Weekday::Wednesday),
            "thursday" => CalendarPattern::Weekly(Weekday::Thursday),
            "friday" => CalendarPattern::Weekly(Weekday::Friday),
            "saturday" => CalendarPattern::Weekly(Weekday::Saturday),
            "sunday" => CalendarPattern::Weekly(Weekday::Sunday),
            other => {
                self.diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: pattern_ident.span,
                    message: format!("unknown calendar pattern `{other}`"),
                    suggestion: Some(
                        "use `day`, `weekday`, or a weekday such as `monday`".to_owned(),
                    ),
                });
                return None;
            }
        };
        if !self.consume_ident("at") {
            self.expected("`at <hh:mm>` after the calendar pattern");
            return None;
        }
        let time = self.parse_time_of_day()?;
        Some(Recurrence::EveryCalendar {
            pattern,
            span: every.span.join(time.span),
            time,
        })
    }

    fn parse_time_of_day(&mut self) -> Option<TimeOfDay> {
        let (hour, hour_span) = self.expect_u32("hour")?;
        self.expect_symbol(':')?;
        let (minute, minute_span) = self.expect_u32("minute")?;
        if hour > 23 || minute > 59 {
            self.diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: hour_span.join(minute_span),
                message: format!("invalid time of day `{hour:02}:{minute:02}`"),
                suggestion: Some("use a 24-hour `hh:mm` such as `09:00`".to_owned()),
            });
            return None;
        }
        Some(TimeOfDay {
            hour: hour as u8,
            minute: minute as u8,
            span: hour_span.join(minute_span),
        })
    }

    fn parse_missed_policy(&mut self) -> Option<MissedPolicy> {
        self.expect_keyword("missed")?;
        if self.consume_ident("skip") {
            return Some(MissedPolicy::Skip);
        }
        if self.consume_ident("coalesce") {
            return Some(MissedPolicy::Coalesce);
        }
        if self.consume_ident("catch_up") {
            if !self.consume_ident("limit") {
                self.expected("`limit <N>` after `catch_up`");
                return None;
            }
            let (limit, _) = self.expect_u32("catch_up limit")?;
            return Some(MissedPolicy::CatchUp { limit });
        }
        self.expected("`skip`, `coalesce`, or `catch_up limit <N>`");
        None
    }

    fn parse_source_emit(&mut self) -> Option<SourceEmit> {
        let emit = self.expect_keyword("emit")?;
        let first = self.expect_ident("emit signal name")?;
        let mut signal = first.name.clone();
        let mut signal_span = first.span;
        while self.at_symbol('.') {
            self.advance();
            let segment = self.expect_ident("signal name segment")?;
            signal.push('.');
            signal.push_str(&segment.name);
            signal_span = signal_span.join(segment.span);
        }
        let from = if self.consume_ident("from") {
            Some(self.expect_ident("binding name after `from`")?)
        } else {
            None
        };
        if from.is_some() && !self.at_symbol('{') {
            let end = from.as_ref().map(|ident| ident.span.end).unwrap_or(0);
            return Some(SourceEmit {
                signal,
                signal_span,
                from,
                fields: Vec::new(),
                span: SourceSpan {
                    start: emit.span.start,
                    end,
                },
            });
        }
        let open = self.expect_symbol('{')?;
        let mut fields = Vec::new();
        while !self.is_at_end() && !self.at_symbol('}') {
            let Some(field_name) = self.expect_ident("emit field name") else {
                self.synchronize_to_block_item();
                continue;
            };
            let Some(value) = self.parse_source_value() else {
                self.synchronize_to_block_item();
                continue;
            };
            let value_span = match &value {
                SourceValue::Path { span, .. } => *span,
                SourceValue::String(literal) => literal.span,
                SourceValue::Number(_, span) => *span,
            };
            fields.push(SourceEmitField {
                span: field_name.span.join(value_span),
                name: field_name,
                value,
            });
        }
        let end = self
            .expect_symbol('}')
            .map(|token| token.span.end)
            .unwrap_or(open.span.end);
        Some(SourceEmit {
            signal,
            signal_span,
            from,
            fields,
            span: SourceSpan {
                start: emit.span.start,
                end,
            },
        })
    }

    fn parse_source_value(&mut self) -> Option<SourceValue> {
        match self.peek().map(|token| &token.kind) {
            Some(TokenKind::String(_)) => self.expect_string("value").map(SourceValue::String),
            Some(TokenKind::Number(_)) => {
                let token = self.advance().clone();
                if let TokenKind::Number(value) = token.kind {
                    Some(SourceValue::Number(value, token.span))
                } else {
                    None
                }
            }
            Some(TokenKind::Ident(_)) => {
                let binding = self.expect_ident("value path")?;
                let mut segments = Vec::new();
                let mut span = binding.span;
                while self.at_symbol('.') {
                    self.advance();
                    let segment = self.expect_ident("path segment")?;
                    span = span.join(segment.span);
                    segments.push(segment);
                }
                Some(SourceValue::Path {
                    binding,
                    segments,
                    span,
                })
            }
            _ => {
                self.expected("a value (observation path, string, or number)");
                None
            }
        }
    }

    fn parse_class(&mut self) -> Option<ClassDecl> {
        let start = self.expect_keyword("class")?.span.start;
        let name = self.expect_ident("class name")?;
        let open = self.expect_symbol('{')?;
        let mut fields = Vec::new();

        while !self.is_at_end() && !self.at_symbol('}') {
            let Some(field_name) = self.expect_ident("class field name") else {
                self.synchronize_to_block_item();
                continue;
            };
            let Some(ty) = self.parse_type() else {
                self.synchronize_to_block_item();
                continue;
            };
            // `@key`: mark this field as the class's natural key (import per-row
            // idempotency, spec/files.md).
            let mut is_key = false;
            if self.at_symbol('@') {
                if let Some(tag) = self.parse_tag() {
                    if tag.name == "key" {
                        is_key = true;
                    } else {
                        self.diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: tag.span,
                            message: format!("unknown field tag `@{}`", tag.name),
                            suggestion: Some(
                                "the only field tag is `@key` (the class natural key)".to_owned(),
                            ),
                        });
                    }
                }
            }
            let presence_condition = self.parse_field_presence_condition();
            let span = field_name.span.join(ty.span());
            fields.push(ClassField {
                span,
                name: field_name,
                ty,
                is_key,
                presence_condition,
            });
        }

        let end = self
            .expect_symbol('}')
            .map(|token| token.span.end)
            .unwrap_or(open.span.end);

        Some(ClassDecl {
            name,
            fields,
            span: SourceSpan { start, end },
        })
    }

    fn parse_table(
        &mut self,
        tags: Vec<TagDecl>,
        description: Option<StringLiteral>,
    ) -> Option<TableDecl> {
        let start = self.expect_keyword("table")?.span.start;
        let name = self.expect_ident("table name")?;
        self.expect_keyword("as")?;
        let schema = self.expect_ident("table row class")?;
        let open = self.expect_symbol('[')?;
        let mut rows = Vec::new();

        while !self.is_at_end() && !self.at_symbol(']') {
            if self.at_symbol(',') {
                self.advance();
                continue;
            }
            if !self.at_symbol('{') {
                self.unexpected("table row `{ ... }`");
                self.synchronize_to_table_row();
                continue;
            }
            if let Some(row) = self.parse_table_row() {
                rows.push(row);
            }
            if self.at_symbol(',') {
                self.advance();
            }
        }

        let end = self
            .expect_symbol(']')
            .map(|token| token.span.end)
            .unwrap_or(open.span.end);
        Some(TableDecl {
            name,
            tags,
            description,
            schema,
            rows,
            span: SourceSpan { start, end },
        })
    }

    fn parse_table_row(&mut self) -> Option<TableRow> {
        let open = self.expect_symbol('{')?;
        let body_start = open.span.end;
        let mut depth = 1usize;
        let mut body_end = body_start;
        let mut close_end = open.span.end;

        while !self.is_at_end() {
            let token = self.advance().clone();
            match token.kind {
                TokenKind::Symbol('{') => {
                    depth += 1;
                    body_end = token.span.end;
                }
                TokenKind::Symbol('}') => {
                    depth -= 1;
                    if depth == 0 {
                        body_end = token.span.start;
                        close_end = token.span.end;
                        break;
                    }
                    body_end = token.span.end;
                }
                _ => body_end = token.span.end,
            }
        }

        if depth != 0 {
            self.diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: SourceSpan {
                    start: open.span.start,
                    end: body_end,
                },
                message: "unterminated table row".to_owned(),
                suggestion: Some("close the table row with `}`".to_owned()),
            });
            return None;
        }

        let body_span = SourceSpan {
            start: body_start,
            end: body_end,
        };
        let (text, span) = trimmed_source_text(self.source_text(body_span), body_span);
        Some(TableRow {
            body: BlockSource { text, span },
            span: SourceSpan {
                start: open.span.start,
                end: close_end,
            },
        })
    }

    fn parse_coerce(&mut self) -> Option<CoerceDecl> {
        let start = self.expect_keyword("coerce")?.span.start;
        let name = self.expect_ident("coerce name")?;
        let params = self.parse_param_list()?;
        self.expect_thin_arrow()?;
        let output = self.parse_type()?;
        // Block-less prompt-only form: `coerce f(a) -> T """…"""` — sugar for
        // a block whose sole clause is the prompt. Desugared here to the same
        // body text (`prompt <raw string>`), so lowering, prompt extraction,
        // and fingerprints are byte-for-byte the block form's.
        if !self.at_symbol('{') {
            if let Some(TokenKind::String(_)) = self.peek().map(|token| &token.kind) {
                let token = self.advance().clone();
                let raw = self
                    .source_text(SourceSpan {
                        start: token.span.start,
                        end: token.span.end,
                    })
                    .to_owned();
                let body = BlockSource {
                    text: format!("prompt {raw}"),
                    span: token.span,
                };
                let span = SourceSpan {
                    start,
                    end: body.span.end,
                };
                return Some(CoerceDecl {
                    name,
                    params,
                    output,
                    body,
                    span,
                });
            }
        }
        let body = self.parse_block_source()?;
        let span = SourceSpan {
            start,
            end: body.span.end,
        };
        Some(CoerceDecl {
            name,
            params,
            output,
            body,
            span,
        })
    }

    fn parse_param_list(&mut self) -> Option<Vec<ParamDecl>> {
        self.expect_symbol('(')?;
        let mut params = Vec::new();

        while !self.is_at_end() && !self.at_symbol(')') {
            let name = self.expect_ident("parameter name")?;
            let ty = self.parse_type()?;
            params.push(ParamDecl {
                span: name.span.join(ty.span()),
                name,
                ty,
            });

            if self.at_symbol(',') {
                self.advance();
            } else if !self.at_symbol(')') {
                self.unexpected("`,` or `)`");
                while !self.is_at_end() && !self.at_symbol(')') && !self.at_symbol(',') {
                    self.advance();
                }
            }
        }

        self.expect_symbol(')')?;
        Some(params)
    }

    /// `action <name>(<param: type>, …) { <effect chain> }` (DR-0023). The body
    /// is captured as a block source; expansion at call sites is a later slice.
    fn parse_action(&mut self) -> Option<ActionDecl> {
        let start = self.expect_keyword("action")?.span.start;
        let name = self.expect_ident("action name")?;
        self.expect_symbol('(')?;
        let mut params = Vec::new();
        while !self.is_at_end() && !self.at_symbol(')') {
            let param_name = self.expect_ident("action parameter name")?;
            let ty = self.parse_type()?;
            let span = param_name.span.join(ty.span());
            params.push(ActionParam {
                name: param_name,
                ty,
                span,
            });
            if self.at_symbol(',') {
                self.advance();
            }
        }
        self.expect_symbol(')')?;
        let body = self.parse_block_source()?;
        let span = SourceSpan {
            start,
            end: body.span.end,
        };
        Some(ActionDecl {
            name,
            params,
            body,
            span,
        })
    }

    fn parse_rule(
        &mut self,
        tags: Vec<TagDecl>,
        description: Option<StringLiteral>,
    ) -> Option<RuleDecl> {
        let start = self.expect_keyword("rule")?.span.start;
        let name = self.expect_ident("rule name")?;
        let mut whens = Vec::new();

        while !self.is_at_end() && !self.at_arrow() {
            if self.at_ident("when") {
                whens.extend(self.parse_when_clauses()?);
            } else if self.at_ident("with") {
                let span = self
                    .peek()
                    .map(|token| token.span)
                    .unwrap_or(SourceSpan { start, end: start });
                self.diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span,
                    message: "`with` is not a rule readiness clause".to_owned(),
                    suggestion: Some("use `when` for rule conditions".to_owned()),
                });
                self.advance();
            } else {
                self.unexpected("`when` clause or `=>`");
                self.advance();
            }
        }

        self.expect_arrow()?;
        let body = self.parse_block_source()?;
        let span = SourceSpan {
            start,
            end: body.span.end,
        };
        Some(RuleDecl {
            name,
            tags,
            description,
            whens,
            body,
            span,
        })
    }

    fn parse_when_clauses(&mut self) -> Option<Vec<WhenClause>> {
        let when = self.expect_keyword("when")?;
        if self.at_symbol('{') {
            return self.parse_grouped_when_clauses(when.span);
        }

        Some(vec![self.parse_when_clause_after_keyword(when.span)?])
    }

    fn parse_assert(
        &mut self,
        tags: Vec<TagDecl>,
        description: Option<StringLiteral>,
    ) -> Option<AssertDecl> {
        let assert = self.expect_keyword("assert")?;
        let expr_start = assert.span.end;
        let line_end = self.source[expr_start..]
            .find('\n')
            .map(|offset| expr_start + offset)
            .unwrap_or(self.source.len());
        let mut expr_end = line_end;

        while !self.is_at_end() && self.peek()?.span.start < line_end {
            expr_end = self.peek()?.span.end.min(line_end);
            self.advance();
        }
        expr_end = Self::extend_span_over_skipped_operators(self.source, expr_end, line_end);

        let span = SourceSpan {
            start: expr_start,
            end: expr_end,
        };
        let (expr, span) = trimmed_source_text(self.source_text(span), span);
        Some(AssertDecl {
            tags,
            description,
            expr,
            span,
        })
    }

    /// A rule header terminates at `=>`.
    fn parse_when_clause_after_keyword(&mut self, when: SourceSpan) -> Option<WhenClause> {
        let text_start = when.end;
        let mut text_end = text_start;

        while !(self.is_at_end()
            || self.at_arrow()
            || self.at_ident("when")
            || self.at_ident("rule"))
        {
            text_end = self.peek()?.span.end;
            self.advance();
        }
        let limit = self
            .peek()
            .map(|token| token.span.start)
            .unwrap_or(self.source.len());
        text_end = Self::extend_span_over_skipped_operators(self.source, text_end, limit);

        let span = SourceSpan {
            start: text_start,
            end: text_end,
        };
        let (text, span) = trimmed_source_text(self.source_text(span), span);
        Some(WhenClause { text, span })
    }

    /// The file-level lexer steps over expression operators (`==`, `!=`,
    /// `<=`, `>=`, `&&`, `||`, `*`, `/`, `-`) without emitting tokens —
    /// expressions are re-parsed from raw source slices. A raw capture that
    /// walks TOKEN spans therefore stops short when the clause ends in a
    /// dangling operator, silently truncating `assert a ==` to `assert a`
    /// (which then mis-diagnoses as a non-boolean expression instead of a
    /// syntax error). Extend `end` across same-line trailing operator bytes
    /// so the expression parser sees the dangling operator. `=>`/`->` are
    /// real tokens and `//` starts a comment; neither is consumed here.
    fn extend_span_over_skipped_operators(source: &str, mut end: usize, limit: usize) -> usize {
        let bytes = source.as_bytes();
        loop {
            let mut cursor = end;
            while cursor < limit && bytes[cursor].is_ascii_whitespace() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
            let width = match (bytes.get(cursor), bytes.get(cursor + 1)) {
                _ if cursor >= limit => break,
                (Some(b'='), Some(b'='))
                | (Some(b'!'), Some(b'='))
                | (Some(b'<'), Some(b'='))
                | (Some(b'>'), Some(b'='))
                | (Some(b'&'), Some(b'&'))
                | (Some(b'|'), Some(b'|')) => 2,
                (Some(b'/'), Some(b'/')) => break,
                (Some(b'-'), Some(b'>')) => break,
                (Some(b'*' | b'/' | b'-'), _) => 1,
                _ => break,
            };
            if cursor + width > limit {
                break;
            }
            end = cursor + width;
        }
        end
    }

    fn parse_grouped_when_clauses(&mut self, when: SourceSpan) -> Option<Vec<WhenClause>> {
        let open = self.expect_symbol('{')?;
        let body_start = open.span.end;
        let mut depth = 1usize;
        let mut body_end = body_start;
        let mut close_end = open.span.end;

        while !self.is_at_end() {
            let token = self.advance().clone();
            match token.kind {
                TokenKind::Symbol('{') => {
                    depth += 1;
                    body_end = token.span.end;
                }
                TokenKind::Symbol('}') => {
                    depth -= 1;
                    if depth == 0 {
                        body_end = token.span.start;
                        close_end = token.span.end;
                        break;
                    }
                    body_end = token.span.end;
                }
                _ => body_end = token.span.end,
            }
        }

        if depth != 0 {
            self.diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: SourceSpan {
                    start: when.start,
                    end: body_end,
                },
                message: "unterminated grouped `when` block".to_owned(),
                suggestion: Some("close the grouped readiness block with `}`".to_owned()),
            });
            return Some(Vec::new());
        }

        let body_span = SourceSpan {
            start: body_start,
            end: body_end,
        };
        let mut clauses = Vec::new();
        let mut offset = 0usize;
        for line in self.source_text(body_span).split_inclusive('\n') {
            let line_without_newline = line.trim_end_matches('\n');
            let line_start = body_span.start + offset;
            offset += line.len();
            let leading = line_without_newline.len() - line_without_newline.trim_start().len();
            let trailing = line_without_newline.len() - line_without_newline.trim_end().len();
            let trimmed_start = line_start + leading;
            let trimmed_end = line_start + line_without_newline.len().saturating_sub(trailing);
            if trimmed_start >= trimmed_end {
                continue;
            }
            clauses.push(WhenClause {
                text: self.source[trimmed_start..trimmed_end].to_owned(),
                span: SourceSpan {
                    start: trimmed_start,
                    end: trimmed_end,
                },
            });
        }

        if clauses.is_empty() {
            self.diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: SourceSpan {
                    start: when.start,
                    end: close_end,
                },
                message: "grouped `when` block has no readiness clauses".to_owned(),
                suggestion: Some(
                    "add one condition per line, such as `started` or `Class as binding`"
                        .to_owned(),
                ),
            });
        }

        Some(clauses)
    }

    fn parse_block_source(&mut self) -> Option<BlockSource> {
        let open = self.expect_symbol('{')?;
        let body_start = open.span.end;
        let mut depth = 1usize;
        let mut body_end = body_start;

        while !self.is_at_end() {
            let token = self.advance().clone();
            match token.kind {
                TokenKind::Symbol('{') => {
                    depth += 1;
                    body_end = token.span.end;
                }
                TokenKind::Symbol('}') => {
                    depth -= 1;
                    if depth == 0 {
                        body_end = token.span.start;
                        return Some(BlockSource {
                            text: self
                                .source_text(SourceSpan {
                                    start: body_start,
                                    end: body_end,
                                })
                                .trim()
                                .to_owned(),
                            span: SourceSpan {
                                start: open.span.start,
                                end: token.span.end,
                            },
                        });
                    }
                    body_end = token.span.end;
                }
                _ => {
                    body_end = token.span.end;
                }
            }
        }

        self.diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: SourceSpan {
                start: open.span.start,
                end: body_end,
            },
            message: "unterminated block".to_owned(),
            suggestion: Some("add a closing `}`".to_owned()),
        });
        Some(BlockSource {
            text: self
                .source_text(SourceSpan {
                    start: body_start,
                    end: body_end,
                })
                .trim()
                .to_owned(),
            span: SourceSpan {
                start: open.span.start,
                end: body_end,
            },
        })
    }

    fn parse_type(&mut self) -> Option<TypeSyntax> {
        let first = self.parse_type_atom()?;
        let first = self.parse_type_suffixes(first);

        if !self.at_symbol('|') {
            return Some(first);
        }

        let start = first.span().start;
        let mut end = first.span().end;
        let mut variants = vec![first];

        while self.at_symbol('|') {
            self.advance();
            let variant = self.parse_type_atom()?;
            let variant = self.parse_type_suffixes(variant);
            end = variant.span().end;
            variants.push(variant);
        }

        Some(TypeSyntax::Union {
            variants,
            span: SourceSpan { start, end },
        })
    }

    fn parse_type_atom(&mut self) -> Option<TypeSyntax> {
        Some(if self.at_ident("AgentRef") {
            let agent_ref = self.advance().clone();
            self.expect_symbol('<')?;
            let mut agents = Vec::new();
            while !self.is_at_end() && !self.at_symbol('>') {
                if self.at_symbol('|') {
                    self.advance();
                    continue;
                }
                let Some(agent) = self.expect_ident("agent reference") else {
                    break;
                };
                agents.push(agent);
            }
            let close = self.expect_symbol('>')?;
            TypeSyntax::AgentRef {
                agents,
                span: agent_ref.span.join(close.span),
            }
        } else if self.at_ident("map") {
            let map = self.advance().clone();
            self.expect_symbol('<')?;
            let inner = self.parse_type()?;
            let close = self.expect_symbol('>')?;
            TypeSyntax::Map {
                span: map.span.join(close.span),
                inner: Box::new(inner),
            }
        } else if self.at_ident("secret") {
            // DR-0053 §15. Intercepted before the primitive branch below so
            // there is ONE representation of `secret`: bare and parameterised
            // are the same variant with and without a discriminant, rather
            // than a primitive and a constructor that must be kept agreeing.
            let secret = self.advance().clone();
            if !self.at_symbol('<') {
                return Some(TypeSyntax::Secret {
                    kind: None,
                    span: secret.span,
                });
            }
            self.expect_symbol('<')?;
            let kind = self.expect_ident("credential kind")?;
            let close = self.expect_symbol('>')?;
            TypeSyntax::Secret {
                span: secret.span.join(close.span),
                kind: Some(kind),
            }
        } else if self.at_ident("sealed") {
            // DR-0074 §10. Spelled after `map<...>` above, deliberately: a
            // built-in constructor over one type, not a generic.
            let sealed = self.advance().clone();
            self.expect_symbol('<')?;
            let inner = self.parse_type()?;
            let close = self.expect_symbol('>')?;
            TypeSyntax::Sealed {
                span: sealed.span.join(close.span),
                inner: Box::new(inner),
            }
        } else if matches!(
            self.peek().map(|token| &token.kind),
            Some(TokenKind::String(_))
        ) {
            let literal = self.expect_string("literal type")?;
            TypeSyntax::LiteralString {
                value: literal.value,
                span: literal.span,
            }
        } else {
            let ident = self.expect_ident("type name")?;
            if is_primitive_type(&ident.name) {
                TypeSyntax::Primitive {
                    name: ident.name,
                    span: ident.span,
                }
            } else {
                TypeSyntax::Ref { name: ident }
            }
        })
    }

    fn parse_type_suffixes(&mut self, mut ty: TypeSyntax) -> TypeSyntax {
        loop {
            if self.at_symbol('?') {
                let question = self.advance().clone();
                ty = TypeSyntax::Optional {
                    span: ty.span().join(question.span),
                    inner: Box::new(ty),
                };
            } else if self.at_symbol('[') {
                self.advance();
                let Some(close) = self.expect_symbol(']') else {
                    return ty;
                };
                ty = TypeSyntax::Array {
                    span: ty.span().join(close.span),
                    inner: Box::new(ty),
                };
            } else {
                return ty;
            }
        }
    }

    fn parse_string_list(&mut self) -> Option<(Vec<StringLiteral>, SourceSpan)> {
        let open = self.expect_symbol('[')?;
        let mut values = Vec::new();

        while !self.is_at_end() && !self.at_symbol(']') {
            values.push(self.expect_string("skill string")?);
            if self.at_symbol(',') {
                self.advance();
            } else if !self.at_symbol(']') {
                self.unexpected("`,` or `]`");
                self.synchronize_to_block_item();
                break;
            }
        }

        let close = self.expect_symbol(']')?;
        Some((values, open.span.join(close.span)))
    }

    /// Parse a bracketed list of identifiers, e.g. `[WordCount, OpenPr]`. Used for
    /// the agent `tools` grant, whose entries reference declared workflows by name.
    fn parse_ident_list(&mut self) -> Option<(Vec<Ident>, SourceSpan)> {
        let open = self.expect_symbol('[')?;
        let mut values = Vec::new();

        while !self.is_at_end() && !self.at_symbol(']') {
            values.push(self.expect_ident("tool workflow name")?);
            if self.at_symbol(',') {
                self.advance();
            } else if !self.at_symbol(']') {
                self.unexpected("`,` or `]`");
                self.synchronize_to_block_item();
                break;
            }
        }

        let close = self.expect_symbol(']')?;
        Some((values, open.span.join(close.span)))
    }

    /// Parse a bracketed list of dotted feature-class names, e.g.
    /// `[session.resume, turn.cancel]` (agent `requires`, DR-0015 taxonomy).
    /// Each entry is one or more identifiers joined by `.`; taxonomy
    /// membership is validated at lowering.
    fn parse_feature_class_list(&mut self) -> Option<(Vec<Ident>, SourceSpan)> {
        let open = self.expect_symbol('[')?;
        let mut values = Vec::new();

        while !self.is_at_end() && !self.at_symbol(']') {
            let head = self.expect_ident("feature class")?;
            let mut name = head.name.clone();
            let mut span = head.span;
            while self.at_symbol('.') {
                self.advance();
                let part = self.expect_ident("feature class segment")?;
                name.push('.');
                name.push_str(&part.name);
                span = span.join(part.span);
            }
            values.push(Ident { name, span });
            if self.at_symbol(',') {
                self.advance();
            } else if !self.at_symbol(']') {
                self.unexpected("`,` or `]`");
                self.synchronize_to_block_item();
                break;
            }
        }

        let close = self.expect_symbol(']')?;
        Some((values, open.span.join(close.span)))
    }

    fn expect_keyword(&mut self, keyword: &str) -> Option<Token> {
        if self.at_ident(keyword) {
            Some(self.advance().clone())
        } else {
            self.expected(format!("`{keyword}`"));
            None
        }
    }

    fn expect_ident(&mut self, label: &str) -> Option<Ident> {
        let token = self.peek()?;
        if let TokenKind::Ident(name) = &token.kind {
            let ident = Ident {
                name: name.clone(),
                span: token.span,
            };
            self.advance();
            Some(ident)
        } else {
            self.expected(label);
            None
        }
    }

    /// Family B: an optional `when <discriminant> is "<literal>"` suffix on a
    /// schema/signal field — the field is present only when the literal-union
    /// discriminant field equals the literal. `is` is used instead of `==` to stay
    /// within the declaration tokenizer; the meaning is equality
    /// (spec/decision-records/discriminated-families-design.md §5.7).
    fn parse_field_presence_condition(&mut self) -> Option<(String, String)> {
        if !self.at_ident("when") {
            return None;
        }
        self.advance(); // `when`
        let disc = self.expect_ident("discriminant field name after `when`")?;
        if self.at_ident("is") {
            self.advance();
        } else {
            self.expected("`is` after the discriminant field");
            return None;
        }
        let literal = self.expect_string("discriminant literal value")?;
        Some((disc.name, literal.value))
    }

    fn expect_string(&mut self, label: &str) -> Option<StringLiteral> {
        let token = self.peek()?;
        if let TokenKind::String(value) = &token.kind {
            let literal = StringLiteral {
                value: value.clone(),
                span: token.span,
            };
            self.advance();
            Some(literal)
        } else {
            self.expected(label);
            None
        }
    }

    fn expect_use_name(&mut self, label: &str) -> Option<StringLiteral> {
        let token = self.peek()?;
        match &token.kind {
            // A package name may be a dotted path (`std.messaging`, `std.coord`)
            // or a bare ident (`memory`); a string literal is also accepted.
            TokenKind::Ident(value) => {
                let mut name = value.clone();
                let mut span = token.span;
                self.advance();
                while self.at_symbol('.') {
                    self.expect_symbol('.');
                    let Some(segment) = self.expect_ident("package name segment") else {
                        break;
                    };
                    name.push('.');
                    name.push_str(&segment.name);
                    span = span.join(segment.span);
                }
                Some(StringLiteral { value: name, span })
            }
            TokenKind::String(value) => {
                let literal = StringLiteral {
                    value: value.clone(),
                    span: token.span,
                };
                self.advance();
                Some(literal)
            }
            _ => {
                self.expected(label);
                None
            }
        }
    }

    fn expect_u32(&mut self, label: &str) -> Option<(u32, SourceSpan)> {
        let token = self.peek()?;
        if let TokenKind::Number(value) = &token.kind {
            let span = token.span;
            let parsed = value.parse::<u32>();
            self.advance();
            match parsed {
                Ok(value) => Some((value, span)),
                Err(_) => {
                    self.diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span,
                        message: format!("{label} must fit in u32"),
                        suggestion: Some("use a non-negative integer such as `1`".to_owned()),
                    });
                    None
                }
            }
        } else {
            self.expected(label);
            None
        }
    }

    fn expect_symbol(&mut self, symbol: char) -> Option<Token> {
        if self.at_symbol(symbol) {
            Some(self.advance().clone())
        } else {
            self.expected(format!("`{symbol}`"));
            None
        }
    }

    fn expect_arrow(&mut self) -> Option<Token> {
        if self.at_arrow() {
            Some(self.advance().clone())
        } else {
            self.expected("`=>`");
            None
        }
    }

    fn expect_thin_arrow(&mut self) -> Option<Token> {
        if self.at_thin_arrow() {
            Some(self.advance().clone())
        } else {
            self.expected("`->`");
            None
        }
    }

    fn at_ident(&self, expected: &str) -> bool {
        matches!(self.peek().map(|token| &token.kind), Some(TokenKind::Ident(value)) if value == expected)
    }

    fn consume_ident(&mut self, expected: &str) -> bool {
        if self.at_ident(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn at_symbol(&self, expected: char) -> bool {
        matches!(self.peek().map(|token| &token.kind), Some(TokenKind::Symbol(value)) if *value == expected)
    }

    fn at_arrow(&self) -> bool {
        matches!(self.peek().map(|token| &token.kind), Some(TokenKind::Arrow))
    }

    fn at_thin_arrow(&self) -> bool {
        matches!(
            self.peek().map(|token| &token.kind),
            Some(TokenKind::ThinArrow)
        )
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> &Token {
        let index = self.pos;
        self.pos += 1;
        &self.tokens[index]
    }

    fn is_at_end(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn expected(&mut self, expected: impl fmt::Display) {
        let expected = expected.to_string();
        let (span, found) = match self.peek() {
            Some(token) => (token.span, token.kind.label()),
            None => (
                SourceSpan {
                    start: self.source.len(),
                    end: self.source.len(),
                },
                "end of file".to_owned(),
            ),
        };
        self.diagnostics.push(Diagnostic {
            related: Vec::new(),
            span,
            message: format!("expected {expected}, found {found}"),
            suggestion: suggestion_for_expected(&expected),
        });
    }

    fn unexpected(&mut self, expected: impl fmt::Display) {
        let Some(token) = self.peek() else {
            self.expected(expected);
            return;
        };
        let expected = expected.to_string();
        self.diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: token.span,
            message: format!("expected {expected}, found {}", token.kind.label()),
            suggestion: suggestion_for_expected(&expected),
        });
    }

    fn synchronize_to_block_item(&mut self) {
        while !self.is_at_end() {
            if self.at_symbol('}')
                || self.at_ident("profile")
                || self.at_ident("provider")
                || self.at_ident("capacity")
                || self.at_ident("skills")
                || self.at_ident("capabilities")
                || self.at_ident("tools")
                || self.at_ident("compaction")
                || self.at_ident("settings")
            {
                return;
            }
            self.advance();
        }
    }

    fn synchronize_to_table_row(&mut self) {
        while !self.is_at_end() {
            if self.at_symbol('{') || self.at_symbol(']') {
                return;
            }
            self.advance();
        }
    }

    fn source_text(&self, span: SourceSpan) -> &str {
        &self.source[span.start..span.end]
    }
}

pub(crate) fn trimmed_source_text(source: &str, span: SourceSpan) -> (String, SourceSpan) {
    let leading = source.len() - source.trim_start().len();
    let trailing = source.len() - source.trim_end().len();
    let end = source.len().saturating_sub(trailing);
    if leading > end {
        return (
            String::new(),
            SourceSpan {
                start: span.end,
                end: span.end,
            },
        );
    }
    (
        source[leading..end].to_owned(),
        SourceSpan {
            start: span.start + leading,
            end: span.start + end,
        },
    )
}

pub(crate) fn is_primitive_type(name: &str) -> bool {
    matches!(
        name,
        "string"
            | "int"
            | "float"
            | "bool"
            | "null"
            | "duration"
            | "time"
            | "image"
            | "audio"
            | "pdf"
            | "video"
    )
}

pub(crate) fn is_gherkin_keyword(keyword: &str) -> bool {
    matches!(
        keyword,
        "Feature"
            | "Rule"
            | "Background"
            | "Scenario"
            | "ScenarioOutline"
            | "Scenario-Outline"
            | "Examples"
            | "Given"
            | "When"
            | "Then"
            | "And"
            | "But"
    )
}

pub(crate) fn suggestion_for_expected(expected: &str) -> Option<String> {
    match expected {
        "`{`" => Some("add a `{ ... }` block".to_owned()),
        "`=>`" => Some("add `=> { ... }` after the rule conditions".to_owned()),
        "`->`" => Some("add `-> OutputType` before the coerce prompt block".to_owned()),
        "profile string" => Some("write `profile \"profile-name\"`".to_owned()),
        "capacity value" => Some("write `capacity 1`".to_owned()),
        "package library name" => Some("write a package library name, such as `memory`".to_owned()),
        "type name" => Some("write a primitive type or schema name".to_owned()),
        _ => None,
    }
}

/// Parses a source file into a recoverable AST plus diagnostics.
pub fn parse_program(source: &str) -> ParseOutput {
    let lexed = lex(source);
    let mut parser = Parser {
        source,
        tokens: lexed.tokens,
        pos: 0,
        diagnostics: lexed.diagnostics,
        pending_contract_classes: Vec::new(),
    };

    let program = parser.parse_program();
    ParseOutput {
        program,
        diagnostics: parser.diagnostics,
    }
}
