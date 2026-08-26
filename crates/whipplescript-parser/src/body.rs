//! Rule and flow body parsing: a real AST over body text.
//!
//! Bodies were historically re-scanned line-by-line at lowering time, which
//! made whitespace load-bearing and let unknown statement forms slip through
//! silently. This module is the statement-form gate: every body must parse
//! into [`BodyAst`], unknown tokens are spanned errors, and lowering consumes
//! structure instead of strings.

use crate::{parse_expression, Diagnostic, Expr, SourceSpan};

/// Parses short durations: `<integer><unit>` with unit `s`, `m`, `h`, or `d`.
pub fn parse_short_duration_seconds(value: &str) -> Option<u64> {
    let unit = value.chars().last()?;
    let number = value.get(..value.len() - 1)?.parse::<u64>().ok()?;
    let multiplier = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return None,
    };
    number.checked_mul(multiplier)
}

/// Structural ISO-8601 instant check (`YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)`)
/// for `time` literals, with calendar-field range validation. Kept
/// dependency-free: the runtime compares instants via SQLite `strftime`.
pub fn is_iso8601_instant(value: &str) -> bool {
    let bytes = value.as_bytes();
    let digits = |range: std::ops::Range<usize>| {
        bytes
            .get(range)
            .is_some_and(|slice| !slice.is_empty() && slice.iter().all(u8::is_ascii_digit))
    };
    let field = |range: std::ops::Range<usize>| -> u32 {
        value
            .get(range)
            .and_then(|text| text.parse().ok())
            .unwrap_or(u32::MAX)
    };
    if !(digits(0..4) && bytes.get(4) == Some(&b'-') && digits(5..7))
        || bytes.get(7) != Some(&b'-')
        || !digits(8..10)
        || bytes.get(10) != Some(&b'T')
        || !digits(11..13)
        || bytes.get(13) != Some(&b':')
        || !digits(14..16)
        || bytes.get(16) != Some(&b':')
        || !digits(17..19)
    {
        return false;
    }
    if !(1..=12).contains(&field(5..7))
        || !(1..=31).contains(&field(8..10))
        || field(11..13) > 23
        || field(14..16) > 59
        || field(17..19) > 60
    {
        return false;
    }
    let mut index = 19;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    match bytes.get(index) {
        Some(b'Z') => index + 1 == bytes.len(),
        Some(b'+') | Some(b'-') => {
            digits(index + 1..index + 3)
                && bytes.get(index + 3) == Some(&b':')
                && digits(index + 4..index + 6)
                && index + 6 == bytes.len()
                && field(index + 1..index + 3) <= 23
                && field(index + 4..index + 6) <= 59
        }
        _ => false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyAst {
    pub statements: Vec<BodyStmt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyStmt {
    Record(RecordStmt),
    /// `done x` / `done x -> record ...` — marks a fact terminal, optionally
    /// replacing it with a record.
    Done {
        binding: String,
        replacement: Option<RecordStmt>,
        span: SourceSpan,
    },
    Effect(EffectStmt),
    After(AfterBlock),
    Region(RegionBlock),
    Case(CaseBlock),
    Terminal(TerminalStmt),
    Cancel {
        binding: String,
        span: SourceSpan,
    },
    /// `emit milestone "<name>" of <PayloadClass> { fields }` (Family C,
    /// child-milestone lifecycle): a synchronous durable fact the child workflow
    /// projects mid-flight for an observing parent. It is NOT an async effect —
    /// it derives a `workflow.milestone:<name>` fact in the child's own base at
    /// rule-commit time, mirroring `record`. `payload_class` types the parent's
    /// `after p reaches "<name>" as m` binding. See
    /// spec/decision-records/discriminated-families-design.md section 7.3.
    Milestone {
        name: String,
        payload_class: Option<String>,
        fields: Vec<FieldAssign>,
        span: SourceSpan,
    },
    /// `redact <source> keep [<field>, …] as <out>` (DR-0027 redact): an explicit,
    /// audited PROJECTION of the record bound to `source` onto the kept field set,
    /// producing a new binding `out`. It is the information-flow crossing the
    /// rule-level opaque join box is refined at — the projection carries only the
    /// labels of the KEPT fields (the dropped fields are non-interfering, proven in
    /// models/lean/Whipple/Redaction.lean: `canRead_redact`). It is NOT an async
    /// effect: it is a synchronous, pure restructure (like a record projection), so
    /// it never becomes an `IrEffectKind` — it is rule metadata the IFC checker and
    /// the runtime projection both read. `out`'s type is the source schema projected
    /// to the kept fields (`redact.<rule>.<out>`); accessing a dropped field on `out`
    /// is a type error.
    Redact {
        source: String,
        keep: Vec<String>,
        binding: String,
        span: SourceSpan,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordStmt {
    pub schema: String,
    pub from: Option<String>,
    pub fields: Vec<FieldAssign>,
    pub span: SourceSpan,
}

/// How a credential handle is presented in a `request` slot (DR-0053 §5).
///
/// The handle in the slot **is** the declaration of use; there is no separate
/// `with credential` modifier. Each form lowers to a sentinel that the
/// custodian substitutes at egress, so the program text never contains the
/// material and the language has no way to ask for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialPresentation {
    /// `Authorization: Bearer <material>`.
    Bearer,
    /// `Authorization: Basic <material>`.
    Basic,
    /// The material alone, for schemes whose framing the author writes.
    Raw,
}

impl CredentialPresentation {
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "bearer" => Some(Self::Bearer),
            "basic" => Some(Self::Basic),
            "raw" => Some(Self::Raw),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::Basic => "basic",
            Self::Raw => "raw",
        }
    }
}

/// One `header "<name>" <value>` line of a `request` block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestHeader {
    pub name: String,
    pub value: RequestHeaderValue,
    pub span: SourceSpan,
}

/// A header value: either an ordinary expression, or a credential in one of the
/// presentation forms — which is the *marked slot* the custodian fills.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestHeaderValue {
    /// Both the source text and the parsed node, matching `FieldValue::Expr`:
    /// the checker reads the text, the lowering reads the node.
    Expr { source: String, expr: Expr },
    Credential {
        presentation: CredentialPresentation,
        handle: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldAssign {
    pub name: String,
    pub value: FieldValue,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FieldValue {
    /// Bare field in a `from` block: copy the same-named field.
    Shorthand,
    /// An expression, kept with its exact source text for template
    /// rendering and lowering compatibility.
    Expr { source: String, expr: Expr },
    /// Nested typed payload, e.g. invoke input: `phase PhaseReview { ... }`.
    Nested {
        schema: String,
        fields: Vec<FieldAssign>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectStmt {
    pub kind: BodyEffectKind,
    pub binding: Option<String>,
    pub requires: Vec<String>,
    /// `timeout <duration>` in seconds, creation-anchored.
    pub timeout_seconds: Option<u64>,
    pub prompt: Option<Prompt>,
    pub span: SourceSpan,
}

/// Access grant metadata (`with access to <resource> { <grant clauses> }`) on an
/// effect. On `tell`, it narrows the turn's effective authority per Proposal A
/// (spec/agent-harness.md). On `invoke`, it is the explicit start-grant surface for
/// narrowing the child workflow's authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessGrant {
    pub resource: String,
    pub operations: Vec<AccessGrantOp>,
    pub span: SourceSpan,
}

/// One operation clause inside a turn-access grant block — an operation name with its
/// optional `for <target>` reference and/or `["glob", …]` path patterns (e.g.
/// `recall for issue`, `read ["docs/**"]`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessGrantOp {
    pub operation: String,
    pub target: Option<String>,
    pub globs: Vec<String>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyEffectKind {
    Tell {
        target: String,
        access_grants: Vec<AccessGrant>,
        /// Turn-scoped `with skills [...]` (context-assembly Phase 7): skills pinned
        /// into this turn's provenance. Does NOT filter the discover-all catalogue.
        skills: Vec<String>,
        /// `on stream <name>` (std.vcs, DR-0052 Decision 5): the per-turn
        /// homing exception — this turn's bound line homes to the named
        /// stream instead of the agent's declared membership.
        on_stream: Option<String>,
    },
    Coerce {
        name: String,
        args: Vec<String>,
        /// the `endorsed` source marker (DR-0027 I-IFC3): the author declares this
        /// coerce is an integrity-raising crossing, making the trusted surface
        /// visible at the crossing point. Authorization still lives in governance.
        endorsed: bool,
        /// the `declassified` source marker (DR-0027 I-IFC3): the author declares
        /// this coerce a confidentiality-lowering crossing. The coerce's OUTPUT
        /// SCHEMA is the bounded type that bounds the leak — you cannot declassify
        /// without passing through a bounded type. Authorization lives in governance.
        declassified: bool,
    },
    /// Bare free-text model prompt: `prompt "<text>" [using <provider>] as x`.
    /// It lowers through the same model/backend path as `coerce`, but its
    /// completed value is a plain string.
    Prompt {
        provider: Option<String>,
    },
    /// Inline anonymous coercion: `decide "<prompt>" -> { field type, ... } as x`.
    Decide {
        result_fields: Vec<(String, String)>,
    },
    Call {
        capability: String,
        argument: Option<String>,
    },
    ConstructCapabilityCall {
        keyword: String,
        target_capability: String,
        fields: Vec<ConstructUseField>,
    },
    Invoke {
        workflow: String,
        payload: Vec<FieldAssign>,
        access_grants: Vec<AccessGrant>,
    },
    Timer {
        duration_seconds: u64,
        duration_source: String,
        /// Absolute deadline expression (a time literal or a time-typed
        /// path); `None` for a relative `timer <duration>`.
        until: Option<String>,
    },
    /// `request <METHOD> "<url>" { header … body … } [signed with <h>] as <b>`
    /// — the authenticated outbound egress of DR-0053 §5.
    ///
    /// Spelled `call` in the record until the 2026-08-25 amendment: `call` was
    /// already package capability invocation, and a keyword carries one
    /// meaning.
    HttpRequest {
        method: String,
        url: String,
        headers: Vec<RequestHeader>,
        body: Option<(String, Expr)>,
        /// `signed with <handle>` — canonicalized and signed custodian-side.
        signed_with: Option<String>,
    },
    Exec {
        target: ExecTarget,
        /// `-> Schema` / `-> each Schema`: deterministic JSON ingestion of
        /// stdout at the effect-result boundary (spec/json-ingestion.md).
        parse_target: Option<ExecParse>,
    },
    /// Work-queue verbs (`file issue into q { ... }`, `claim x`, `release x`,
    /// `finish x [{ ... }]`).
    TrackerFile {
        queue: String,
        fields: Vec<FieldAssign>,
    },
    TrackerClaim {
        item: String,
        /// `ttl <duration>`: the claim-TTL, in seconds. `Some(n)` records a
        /// timed lease (`expires_at = now + n`) that `ready`/`claim` reclaim
        /// once past-due; `None` is the untimed backstop lease (T3).
        ttl_seconds: Option<u64>,
        /// The `endorsed` source marker (DR-0051 §2), the same crossing
        /// `coerce … endorsed` carries: the author declares that adopting this
        /// party's decision is the integrity raise. Honoured only when the
        /// claimed tracker is itself vouched (§3) — otherwise an agent could
        /// file its own issue and claim it, laundering its own output through a
        /// two-step it fully controls.
        endorsed: bool,
    },
    TrackerRelease {
        item: String,
    },
    TrackerFinish {
        item: String,
        fields: Vec<FieldAssign>,
    },
    /// Coordination verbs (spec/coordination.md): one atomic attempt each,
    /// with branchable sum-typed outcomes.
    LeaseAcquire {
        resource: String,
        key_expr: String,
        /// `until ttl`: fire-and-forget; TTL is the sole release.
        until_ttl: bool,
        /// `wait <duration>`: bounded retry on contention. `Some(seconds)` retries
        /// the acquire until it is `held` or the wait elapses (then `contended`);
        /// `None` reports `contended` on the first attempt.
        wait_seconds: Option<u64>,
    },
    /// `renew <acquire-binding> [until <ttl>] as <b>`: extend a held lease's
    /// TTL before it expires (spec/coordination.md). Names the acquire's `as`
    /// binding and works on the same lease; `Renewed`/`NotHeld` outcomes.
    LeaseRenew {
        /// The `as` binding of the `acquire` this renew extends.
        acquire_binding: String,
        /// `until <duration>`: the new TTL in seconds. `None` reuses the
        /// acquire's declared TTL.
        ttl_seconds: Option<u64>,
    },
    LedgerAppend {
        ledger: String,
        schema: String,
        fields: Vec<FieldAssign>,
    },
    CounterConsume {
        counter: String,
        key_expr: String,
        amount_expr: String,
    },
    /// `emit signal <name> to <instance-expr> { payload }`: inject a typed,
    /// durable event into a known peer instance — directed fire-and-forget
    /// (spec/event-ingress.md, spec/coordination.md messaging).
    Notify {
        target_expr: String,
        event: String,
        /// S6: `emit signal <name> to <target> from <binding> { overrides }` —
        /// copy the source binding's same-named fields (bounded to the signal's
        /// declared fields), with the block overriding; mirrors `record … from`.
        from: Option<String>,
        fields: Vec<FieldAssign>,
    },
    /// `read <format> from <store> at <path> as <binding>` (std.files): a typed
    /// file read lowering through `typed_effect_call`. v0 paths are literal
    /// strings.
    FileRead {
        format: String,
        store: String,
        path: String,
    },
    /// `write <format> to <store> at <path> { body <expr> mode <mode> } as
    /// <binding>` (std.files): a typed file write lowering through
    /// `typed_effect_call`. v0 formats are `text`/`markdown` body codecs; the
    /// `mode` (create/replace/upsert/append) is required (no silent overwrite),
    /// and `body` is an expression resolved at effect-input time.
    FileWrite {
        format: String,
        store: String,
        path: String,
        body: String,
        mode: String,
    },
    /// `import <format> <Schema> from <store> at <path> as <binding>`
    /// (std.files): decode a structured file into typed `<Schema>` facts (one per
    /// row) via the platform fact-batch admission primitive. v0 formats are
    /// `jsonl`/`json`/`csv`.
    FileImport {
        format: String,
        schema: String,
        store: String,
        path: String,
    },
    /// `export <format> <Schema> to <store> at <path> { [where <pred>] mode
    /// <mode> } as <binding>` (std.files): serialize the collection of `<Schema>`
    /// facts (optionally filtered by `where`, per DR-0022 collection-valued
    /// projections) to a structured file. v0 formats are `jsonl`/`json`/`csv`;
    /// `mode` is required (no silent overwrite).
    FileExport {
        format: String,
        schema: String,
        store: String,
        path: String,
        predicate: Option<String>,
        mode: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstructUseField {
    pub name: String,
    pub source: String,
}

// --- DR-0011 `effect_operation` meta-grammar (compiled-in table) -------------
//
// The shipped std package constructs (`recall`, `learn`, `curate`, `send`)
// share one rule-body shape: `<keyword> [<connective> <slot>]* [{
// <payload-field>* }]? as <binding>`. Rather than one hand-written parser per
// keyword, each is described by an `EffectOperationSpec` row and parsed
// generically by `parse_effect_operation`. The spec types below stay
// hand-written; the table const is generated by build.rs from the embedded std
// manifests' `grammar` objects (std/manifests/*.json — the single source of
// grammar). See spec/construct-grammar.md, "DR-0011 Two-Shape Meta-Grammar
// (S6 build)".

/// A slot's value kind: a bare identifier or a value expression.
#[derive(Clone, Copy, Debug)]
enum SlotKind {
    Identifier,
    Expression,
}

/// The trailing `as <binding>` policy for an effect operation. Both shipped
/// constructs require a binding; `Optional`/`None` complete the DR-0011 mode
/// vocabulary and are enforced by `parse_effect_operation` when a construct
/// registers them.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
enum BindingMode {
    Required,
    Optional,
    None,
}

/// One ordered slot: a named value, optionally introduced by a fixed connective
/// word consumed before it (`recall <pool>` has none; `send via <channel>` uses
/// `via`). Connectives are drawn from {`from`, `for`, `into`, `to`, `via`}.
#[derive(Clone, Copy, Debug)]
struct EffectSlotSpec {
    name: &'static str,
    kind: SlotKind,
    connective: Option<&'static str>,
}

/// One field inside the optional `{ ... }` payload block: a named expression,
/// required or not.
#[derive(Clone, Copy, Debug)]
struct PayloadFieldSpec {
    name: &'static str,
    required: bool,
}

/// The full grammar of one `effect_operation` construct.
#[derive(Clone, Copy, Debug)]
struct EffectOperationSpec {
    keyword: &'static str,
    slots: &'static [EffectSlotSpec],
    payload: Option<&'static [PayloadFieldSpec]>,
    binding: BindingMode,
    target_capability: &'static str,
}

// The table itself is generated at build time from the canonical embedded std
// manifests (std/manifests/*.json) by build.rs: each construct's DR-0011
// `grammar` object transcribes into one `EffectOperationSpec` row, so the
// manifests are the single source of parse grammar and the table can never
// drift from them.
include!(concat!(env!("OUT_DIR"), "/effect_operation_grammar.rs"));

/// Look up the `effect_operation` grammar for a leading rule-body keyword.
fn effect_operation_spec(keyword: &str) -> Option<&'static EffectOperationSpec> {
    EFFECT_OPERATION_GRAMMAR
        .iter()
        .find(|spec| spec.keyword == keyword)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecTarget {
    RawCommand(String),
    Capability { name: String, stdin_binding: String },
}

/// The `->` ingestion contract on an `exec`: stdout must parse as `schema`
/// (one object) or, with `each`, as a JSONL/array stream of `schema`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecParse {
    pub schema: String,
    pub each: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Prompt {
    pub text: String,
    pub content_type: Option<String>,
}

/// DR-0043 Decision 5: a `during <cond> { … } on lapse [as x] { … }` region
/// (`until <cond>` is the negated polarity). The region's steps commit only
/// while the condition holds — checked atomically inside each advancing
/// commit — and the first advancing commit under a broken condition commits
/// the lapse arm instead, exactly once. Statements after the region are the
/// point of no return.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionBlock {
    /// `until` negates: the region runs while the condition is FALSE and
    /// lapses when it becomes true.
    pub until: bool,
    /// The condition's raw expression text (guard grammar; pure queries).
    pub condition: String,
    pub body: Vec<BodyStmt>,
    /// `on lapse as <binding>`: the synthesized optional progress view.
    pub lapse_binding: Option<String>,
    pub lapse_body: Vec<BodyStmt>,
    /// Source extent of the region BODY content (inside its braces), for the
    /// compile-path variant splices.
    pub body_span: SourceSpan,
    /// Source extent of the lapse-arm content (inside its braces).
    pub lapse_span: SourceSpan,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AfterBlock {
    pub binding: String,
    pub predicate: AfterPredicate,
    pub alias: Option<String>,
    /// For `after p reaches "<name>" as m`: the child milestone name being
    /// observed (Family C). `None` for every other predicate. The name lives
    /// here rather than on `AfterPredicate` so the predicate stays a fieldless
    /// `Copy` enum (see `AfterPredicate::Reaches`).
    pub milestone: Option<String>,
    pub body: Vec<BodyStmt>,
    pub span: SourceSpan,
}

impl AfterPredicate {
    /// The kernel text-scanner's spelling of this predicate (what
    /// `after <binding> <predicate>` looks like in body text).
    pub fn kernel_str(&self) -> &'static str {
        match self {
            AfterPredicate::Succeeds => "succeeds",
            AfterPredicate::Fails => "fails",
            AfterPredicate::Completes => "completes",
            AfterPredicate::Cancelled => "cancelled",
            AfterPredicate::TimedOut => "times out",
            AfterPredicate::Reaches => "reaches",
            AfterPredicate::Held => "held",
            AfterPredicate::Contended => "contended",
            AfterPredicate::Ok => "ok",
            AfterPredicate::Over => "over",
            AfterPredicate::Promoted => "promoted",
            AfterPredicate::Conflicted => "conflicted",
            AfterPredicate::Applied => "applied",
            AfterPredicate::Stranded => "stranded",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AfterPredicate {
    Succeeds,
    Fails,
    Completes,
    /// Terminal statuses from the canonical terminal union
    /// (spec/expression-kernel.md): the effect reached a non-success terminal
    /// state. `TimedOut` is spelled `times out`; `Cancelled` is `cancelled`.
    TimedOut,
    Cancelled,
    /// Coordination outcomes (spec/coordination.md): the effect completed
    /// and its sum-typed value carries the matching `variant`.
    Held,
    Contended,
    Ok,
    Over,
    /// std.vcs promotion outcomes (DR-0052 grammar pass, the acquire
    /// pattern one tier up): the boundary hop COMPLETES with variant
    /// Promoted|Conflicted — refusal is data, and `succeeds` is refused
    /// on a promote binding so no workflow proceeds "as if promoted" on
    /// a conflicted boundary.
    Promoted,
    Conflicted,
    /// std.vcs selective-verb outcomes (DR-0052 R4): `undo` and
    /// `transport` COMPLETE with Applied|Stranded / Applied|Conflicted —
    /// the proposal landed, or the dependency-closure / certified
    /// precondition refused, as data. Same enforcement as
    /// promote/acquire.
    Applied,
    Stranded,
    /// `after p reaches "<name>" as m` (Family C, child-milestone lifecycle): the
    /// invoked child workflow `p` projected the named milestone mid-flight. The
    /// milestone name is carried on `AfterBlock.milestone`, keeping this variant
    /// fieldless/`Copy`. See spec/decision-records/discriminated-families-design.md
    /// section 7.3.
    Reaches,
}

impl AfterPredicate {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Succeeds => "succeeds",
            Self::Fails => "fails",
            Self::Completes => "completes",
            Self::TimedOut => "times out",
            Self::Cancelled => "cancelled",
            Self::Held => "held",
            Self::Contended => "contended",
            Self::Ok => "ok",
            Self::Over => "over",
            Self::Promoted => "promoted",
            Self::Conflicted => "conflicted",
            Self::Applied => "applied",
            Self::Stranded => "stranded",
            // The milestone name is rendered separately by the serializer
            // (it lives on `AfterBlock.milestone`), so the bare keyword is
            // all `as_str` carries here.
            Self::Reaches => "reaches",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseBlock {
    pub scrutinee: String,
    pub branches: Vec<CaseBranch>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseBranch {
    pub pattern: String,
    pub binding: Option<String>,
    pub guard: Option<String>,
    pub body: Vec<BodyStmt>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalStmt {
    pub kind: TerminalKind,
    pub name: String,
    /// `complete <T> from <binding>`: a bounded-type projection egress — the payload
    /// is the source binding projected to `T`'s fields (the shorthand copies), the
    /// dual of `record <T> from <binding>`. `None` for the ordinary explicit-field
    /// form. Only meaningful for `Complete`.
    pub from: Option<String>,
    pub fields: Vec<FieldAssign>,
    /// A bare scalar payload: `complete result 0.9` / `fail error "reason"`. Set
    /// when the terminal is written without a `{ … }` block; mutually exclusive
    /// with `fields` (which is empty) and `from` (a projection needs a block).
    /// Validated against a scalar (`number`/`string`/`bool`) output/failure
    /// contract. `None` for the ordinary field-block form.
    pub scalar: Option<FieldValue>,
    pub span: SourceSpan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalKind {
    Complete,
    Fail,
}

/// A field assignment extracted from a record/payload body without braces.
/// `value` is `None` for shorthand-copy fields; otherwise it is the exact
/// source text of the value expression.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SplitFieldAssignment {
    pub name: String,
    pub value: Option<String>,
}

/// Token-level field splitting for record/terminal/table-row bodies. The
/// structure comes from tokens, never from line breaks, so single-line and
/// multi-line blocks behave identically. Shorthand (bare name, `from` blocks
/// only at the call site) is line-delimited: a name with no same-line value
/// is shorthand.
/// The source text of every token that appeared where a FIELD NAME was
/// expected, and was therefore skipped.
///
/// The splitter drops such a token silently, which loses what the author wrote
/// with no diagnostic anywhere:
///
/// ```text
/// record Out {
///   title
///   "hello"
/// }
/// ```
///
/// `title` is a line-delimited shorthand field (documented, and correct), and
/// `"hello"` is then a value with no field name. That compiled clean and the
/// recorded fact took the shorthand's value instead, so the author's literal
/// was silently replaced by a different one.
///
/// This shares ONE scan with `split_field_assignments` rather than mirroring
/// it. A second copy would drift, and two scans of the same text disagreeing is
/// the defect this exists to report.
pub fn stray_value_tokens(source: &str) -> Vec<String> {
    let mut stray = Vec::new();
    split_fields_inner(source, Some(&mut stray));
    stray
}

pub fn split_field_assignments(source: &str) -> Vec<SplitFieldAssignment> {
    split_fields_inner(source, None)
}

fn split_fields_inner(
    source: &str,
    mut stray: Option<&mut Vec<String>>,
) -> Vec<SplitFieldAssignment> {
    let mut diagnostics = Vec::new();
    let tokens = lex_body(source, 0, &mut diagnostics);
    let mut parser = BodyParser {
        source,
        base: 0,
        tokens,
        pos: 0,
        diagnostics,
    };
    let mut assignments = Vec::new();
    while let Some(token) = parser.peek() {
        let name_line = token.line;
        let (stray_start, stray_end) = (token.start, token.end);
        let Tok::Ident(name) = token.tok.clone() else {
            if let Some(sink) = stray.as_deref_mut() {
                sink.push(
                    source
                        .get(stray_start..stray_end)
                        .unwrap_or_default()
                        .to_owned(),
                );
            }
            parser.pos += 1;
            continue;
        };
        parser.pos += 1;
        let is_shorthand = match parser.peek() {
            None => true,
            Some(next) => next.line != name_line,
        };
        if is_shorthand {
            assignments.push(SplitFieldAssignment { name, value: None });
            continue;
        }
        let value_start = parser.pos;
        if !parser.consume_value_atom() {
            parser.pos += 1;
            continue;
        }
        loop {
            match parser.peek().map(|t| t.tok.clone()) {
                Some(Tok::Op(_)) | Some(Tok::Sym('+')) | Some(Tok::Sym('-'))
                | Some(Tok::Sym('*')) | Some(Tok::Sym('/')) | Some(Tok::Sym('<'))
                | Some(Tok::Sym('>')) => {
                    parser.pos += 1;
                    if !parser.consume_value_atom() {
                        break;
                    }
                }
                Some(Tok::Ident(word)) if word == "and" || word == "or" || word == "in" => {
                    parser.pos += 1;
                    if !parser.consume_value_atom() {
                        break;
                    }
                }
                Some(Tok::Sym('[')) => {
                    parser.consume_balanced('[', ']');
                }
                // A brace body after a value atom is a nested payload —
                // variant construction `Approved { score 0.9 }`
                // (spec/sum-types.md) — captured whole, not flattened.
                Some(Tok::Sym('{')) => {
                    parser.consume_balanced('{', '}');
                    break;
                }
                _ => break,
            }
        }
        let first = &parser.tokens[value_start];
        let last = &parser.tokens[parser.pos - 1];
        assignments.push(SplitFieldAssignment {
            name,
            value: Some(source[first.start..last.end].to_owned()),
        });
    }
    assignments
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    TripleStr {
        text: String,
        content_type: Option<String>,
    },
    Number(String),
    Sym(char),
    Arrow,    // ->
    FatArrow, // =>
    Op(&'static str),
}

#[derive(Clone, Debug)]
struct Token {
    tok: Tok,
    start: usize,
    end: usize,
    line: usize,
}

fn line_of(source: &str, offset: usize) -> usize {
    source[..offset].bytes().filter(|b| *b == b'\n').count()
}

fn lex_body(source: &str, base: usize, diagnostics: &mut Vec<Diagnostic>) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        if source[i..].starts_with("\"\"\"") {
            // Triple-quoted prompt with optional content-type on the opener.
            let opener_end = source[i + 3..]
                .find('\n')
                .map(|offset| i + 3 + offset)
                .unwrap_or(source.len());
            let annotation = source[i + 3..opener_end].trim();
            let content_type = (!annotation.is_empty()).then(|| annotation.to_owned());
            let Some(close) = source[opener_end..].find("\"\"\"").map(|o| opener_end + o) else {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: SourceSpan {
                        start: base + start,
                        end: base + source.len(),
                    },
                    message: "unterminated multiline string".to_owned(),
                    suggestion: Some("close the prompt with `\"\"\"`".to_owned()),
                });
                break;
            };
            let raw = &source[opener_end..close];
            let text = dedent_prompt(raw);
            tokens.push(Token {
                tok: Tok::TripleStr { text, content_type },
                start,
                end: close + 3,
                line: line_of(source, start),
            });
            i = close + 3;
            continue;
        }
        if c == '"' {
            let mut j = i + 1;
            let mut value = String::new();
            let mut closed = false;
            while j < bytes.len() {
                let cj = bytes[j] as char;
                if cj == '\\' && j + 1 < bytes.len() {
                    value.push(bytes[j + 1] as char);
                    j += 2;
                    continue;
                }
                if cj == '"' {
                    closed = true;
                    break;
                }
                if cj == '\n' {
                    break;
                }
                value.push(cj);
                j += 1;
            }
            if !closed {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: SourceSpan {
                        start: base + start,
                        end: base + j,
                    },
                    message: "unterminated string".to_owned(),
                    suggestion: Some("close the string with `\"`".to_owned()),
                });
                i = j;
                continue;
            }
            tokens.push(Token {
                tok: Tok::Str(value),
                start,
                end: j + 1,
                line: line_of(source, start),
            });
            i = j + 1;
            continue;
        }
        if c.is_ascii_digit()
            || (c == '-'
                && bytes
                    .get(i + 1)
                    .is_some_and(|b| (*b as char).is_ascii_digit()))
        {
            let mut j = i + 1;
            while j < bytes.len() {
                let cj = bytes[j] as char;
                if cj.is_ascii_alphanumeric() || cj == '.' || cj == '_' {
                    j += 1;
                } else {
                    break;
                }
            }
            tokens.push(Token {
                tok: Tok::Number(source[i..j].to_owned()),
                start,
                end: j,
                line: line_of(source, start),
            });
            i = j;
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let mut j = i + 1;
            while j < bytes.len() {
                let cj = bytes[j] as char;
                if cj.is_ascii_alphanumeric() || cj == '_' || cj == '.' {
                    j += 1;
                } else {
                    break;
                }
            }
            // Trailing dots belong to punctuation, not identifiers.
            let mut end = j;
            while end > i && bytes[end - 1] as char == '.' {
                end -= 1;
            }
            tokens.push(Token {
                tok: Tok::Ident(source[i..end].to_owned()),
                start,
                end,
                line: line_of(source, start),
            });
            i = end.max(i + 1);
            continue;
        }
        if source[i..].starts_with("->") {
            tokens.push(Token {
                tok: Tok::Arrow,
                start,
                end: i + 2,
                line: line_of(source, i),
            });
            i += 2;
            continue;
        }
        if source[i..].starts_with("=>") {
            tokens.push(Token {
                tok: Tok::FatArrow,
                start,
                end: i + 2,
                line: line_of(source, i),
            });
            i += 2;
            continue;
        }
        let two_char = [
            ("==", "=="),
            ("!=", "!="),
            ("<=", "<="),
            (">=", ">="),
            ("&&", "&&"),
            ("||", "||"),
        ]
        .iter()
        .find(|(text, _)| source[i..].starts_with(text))
        .map(|(_, op)| *op);
        if let Some(op) = two_char {
            tokens.push(Token {
                tok: Tok::Op(op),
                start,
                end: i + 2,
                line: line_of(source, i),
            });
            i += 2;
            continue;
        }
        if c == '#' || (c == '/' && bytes.get(i + 1) == Some(&b'/')) {
            // Full-line `#` / `//` comments are legal in rule bodies (ruling
            // 2026-07-21), matching the top-level lexer's two markers: a line
            // whose first non-whitespace characters open a comment is skipped
            // to its end. A comment after code on the same line falls through
            // (trailing comments stay top-level-only; a mid-line `/` is the
            // division operator).
            let mut k = i;
            let mut line_leading = true;
            while k > 0 {
                let prev = bytes[k - 1] as char;
                if prev == '\n' {
                    break;
                }
                if prev != ' ' && prev != '\t' {
                    line_leading = false;
                    break;
                }
                k -= 1;
            }
            if line_leading {
                while i < bytes.len() && bytes[i] as char != '\n' {
                    i += 1;
                }
                continue;
            }
        }
        match c {
            '{' | '}' | '[' | ']' | '(' | ')' | ',' | '.' | '+' | '-' | '*' | '/' | '<' | '>'
            | '!' | ':' | ';' => {
                tokens.push(Token {
                    tok: Tok::Sym(c),
                    start,
                    end: i + 1,
                    line: line_of(source, start),
                });
                i += 1;
            }
            _ => {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: SourceSpan {
                        start: base + i,
                        end: base + i + 1,
                    },
                    message: format!("unexpected character `{c}` in rule body"),
                    suggestion: None,
                });
                i += 1;
            }
        }
    }
    tokens
}

/// Blanks full-line `#` comments in rule-body TEXT, byte-preservingly: every
/// byte of a comment line except its newline becomes a space, so all spans
/// and offsets downstream still point at the original source. Raw-string
/// (`"""`) interiors are untouched -- a markdown heading inside a prompt is
/// content, not a comment. The compile path runs this once per rule body
/// before action/`then` expansion, so the kernel and every line-based
/// analysis see comment-free text, while `whip fmt` (which re-emits the raw
/// body text) preserves the comments.
pub fn blank_full_line_comments(text: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(text.len());
    let mut in_fence = false;
    for line in text.split_inclusive('\n') {
        let (content, has_newline) = match line.strip_suffix('\n') {
            Some(content) => (content, true),
            None => (line, false),
        };
        let lead = content.trim_start();
        if !in_fence && (lead.starts_with('#') || lead.starts_with("//")) {
            out.resize(out.len() + content.len(), b' ');
        } else {
            out.extend_from_slice(content.as_bytes());
            if content.matches("\"\"\"").count() % 2 == 1 {
                in_fence = !in_fence;
            }
        }
        if has_newline {
            out.push(b'\n');
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn dedent_prompt(raw: &str) -> String {
    let lines: Vec<&str> = raw.lines().collect();
    let indent = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start().len())
        .min()
        .unwrap_or(0);
    let mut text = lines
        .iter()
        .map(|line| {
            if line.len() >= indent {
                &line[indent..]
            } else {
                line.trim_start()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    while text.starts_with('\n') {
        text.remove(0);
    }
    while text.ends_with('\n') || text.ends_with(' ') {
        text.pop();
    }
    text
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parses exactly ONE statement from the front of `source` (used by `then`
/// expansion to consume the chained effect statement without parsing — and
/// spuriously diagnosing — the remainder of the enclosing block). Returns the
/// statement and only the diagnostics that single parse produced.
pub fn parse_first_statement(source: &str, base: usize) -> (Option<BodyStmt>, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let tokens = lex_body(source, base, &mut diagnostics);
    let mut parser = BodyParser {
        source,
        base,
        tokens,
        pos: 0,
        diagnostics,
    };
    let statement = parser.parse_statement();
    (statement, parser.diagnostics)
}

pub fn parse_rule_body(source: &str, base: usize) -> (BodyAst, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let tokens = lex_body(source, base, &mut diagnostics);
    let mut parser = BodyParser {
        source,
        base,
        tokens,
        pos: 0,
        diagnostics,
    };
    let statements = parser.parse_statements(false);
    (BodyAst { statements }, parser.diagnostics)
}

struct BodyParser<'a> {
    source: &'a str,
    base: usize,
    tokens: Vec<Token>,
    pos: usize,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> BodyParser<'a> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn peek_at(&self, offset: usize) -> Option<&Token> {
        self.tokens.get(self.pos + offset)
    }

    fn advance(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).cloned();
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    fn at_ident(&self, value: &str) -> bool {
        matches!(self.peek().map(|t| &t.tok), Some(Tok::Ident(v)) if v == value)
    }

    fn at_sym(&self, value: char) -> bool {
        matches!(self.peek().map(|t| &t.tok), Some(Tok::Sym(v)) if *v == value)
    }

    fn consume_ident(&mut self, value: &str) -> bool {
        if self.at_ident(value) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn consume_sym(&mut self, value: char) -> bool {
        if self.at_sym(value) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn span_here(&self) -> SourceSpan {
        match self.peek() {
            Some(token) => SourceSpan {
                start: self.base + token.start,
                end: self.base + token.end,
            },
            None => SourceSpan {
                start: self.base + self.source.len(),
                end: self.base + self.source.len(),
            },
        }
    }

    fn span_from(&self, start_token: usize) -> SourceSpan {
        let start = self
            .tokens
            .get(start_token)
            .map(|t| self.base + t.start)
            .unwrap_or(self.base);
        let end = self
            .tokens
            .get(self.pos.saturating_sub(1))
            .map(|t| self.base + t.end)
            .unwrap_or(start);
        SourceSpan { start, end }
    }

    fn error(&mut self, span: SourceSpan, message: impl Into<String>, suggestion: Option<String>) {
        self.diagnostics.push(Diagnostic {
            related: Vec::new(),
            span,
            message: message.into(),
            suggestion,
        });
    }

    fn ident_text(&mut self, what: &str) -> Option<String> {
        match self.peek().map(|t| t.tok.clone()) {
            Some(Tok::Ident(value)) => {
                self.pos += 1;
                Some(value)
            }
            _ => {
                let span = self.span_here();
                self.error(span, format!("expected {what}"), None);
                None
            }
        }
    }

    /// Skip to a safe resync point after an error: the next statement keyword
    /// at the current depth or a closing brace.
    fn recover(&mut self) {
        let mut depth = 0usize;
        while let Some(token) = self.peek() {
            match &token.tok {
                Tok::Sym('{') => depth += 1,
                Tok::Sym('}') if depth == 0 => return,
                Tok::Sym('}') => depth -= 1,
                Tok::Ident(value)
                    if depth == 0
                        && STATEMENT_KEYWORDS.contains(&value.as_str())
                        && self.pos != 0 =>
                {
                    return
                }
                _ => {}
            }
            self.pos += 1;
        }
    }

    fn parse_statements(&mut self, in_block: bool) -> Vec<BodyStmt> {
        let mut statements = Vec::new();
        loop {
            if self.peek().is_none() {
                if in_block {
                    let span = self.span_here();
                    self.error(
                        span,
                        "unclosed block in rule body",
                        Some("add `}`".to_owned()),
                    );
                }
                return statements;
            }
            if self.at_sym('}') {
                if in_block {
                    self.pos += 1;
                }
                return statements;
            }
            let before = self.pos;
            if let Some(statement) = self.parse_statement() {
                statements.push(statement);
            }
            if self.pos == before {
                // No progress: recover to avoid an infinite loop.
                self.pos += 1;
                self.recover();
            }
        }
    }

    fn parse_statement(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        let keyword = match self.peek().map(|t| t.tok.clone()) {
            Some(Tok::Ident(value)) => value,
            _ => {
                let span = self.span_here();
                let package_verbs = EFFECT_OPERATION_GRAMMAR
                    .iter()
                    .map(|spec| spec.keyword)
                    .collect::<Vec<_>>()
                    .join(", ");
                self.error(
                    span,
                    "expected a rule body statement".to_owned(),
                    Some(format!(
                        "statements start with record, done, consume, during, until, tell, \
                         coerce, prompt, decide, call, invoke, read, write, import, export, \
                         after, case, complete, fail, timer, cancel, exec, file, claim, \
                         release, finish, acquire, renew, append, emit, redact, or a package \
                         effect verb ({package_verbs})"
                    )),
                );
                self.recover();
                return None;
            }
        };
        // Data-driven `effect_operation` constructs (DR-0011): a leading keyword
        // registered in the compiled-in grammar table is parsed generically.
        if let Some(spec) = effect_operation_spec(&keyword) {
            return self.parse_effect_operation(spec);
        }
        match keyword.as_str() {
            "record" => self.parse_record_statement().map(BodyStmt::Record),
            // `consume <counter> for <key> ...` is the counter verb
            // (spec/coordination.md). The bare `consume <binding>` alias for
            // `done` was removed after its deprecation window (shipped v0.2).
            "consume" if self.looks_like_counter_consume() => self.parse_counter_consume(),
            "consume" => self.removed_consume_alias(),
            "done" => self.parse_done_statement(),
            "during" => self.parse_region(false),
            "until" => self.parse_region(true),
            "tell" => self.parse_tell(),
            "coerce" => self.parse_coerce_call(),
            "prompt" => self.parse_prompt_effect(),
            "decide" => self.parse_decide(),
            "call" => self.parse_call(),
            "request" => self.parse_http_request(),
            "invoke" => self.parse_invoke(),
            "read" => self.parse_read(),
            "write" => self.parse_write(),
            "import" => self.parse_import(),
            "export" => self.parse_export(),
            "after" => self.parse_after(),
            "case" => self.parse_case(),
            "complete" | "fail" => self.parse_terminal(),
            "timer" => self.parse_timer(),
            "cancel" => self.parse_cancel(),
            "exec" => self.parse_exec(),
            "file" => self.parse_tracker_file(),
            "claim" => self.parse_tracker_claim(),
            "release" => self.parse_tracker_release(),
            "finish" => self.parse_tracker_finish(),
            "acquire" => self.parse_lease_acquire(),
            "renew" => self.parse_lease_renew(),
            "append" => self.parse_ledger_append(),
            "emit" => self.parse_emit_signal(),
            "redact" => self.parse_redact(),
            "when" | "on" => {
                let span = self.span_here();
                self.error(
                    span,
                    format!("`{keyword}` blocks are not rule body statements"),
                    Some(
                        "branch with `case`, guard the rule's `when` clause, or chain \
                         effects with `then <binding> <- <effect>`"
                            .to_owned(),
                    ),
                );
                self.pos += 1;
                self.recover();
                None
            }
            other => {
                let span = self.span_here();
                self.error(
                    span,
                    format!("unknown rule body statement `{other}`"),
                    Some(
                        "statements start with record, done, tell, coerce, claim, \
                         release, finish, file, call, recall, invoke, emit, after, case, complete, \
                         fail, timer, cancel, decide, prompt, or exec"
                            .to_owned(),
                    ),
                );
                self.pos += 1;
                self.recover();
                None
            }
        }
        .inspect(|_| {
            let _ = start;
        })
    }

    // -- record ------------------------------------------------------------

    fn parse_record_statement(&mut self) -> Option<RecordStmt> {
        let start = self.pos;
        self.pos += 1; // record
        let schema = self.ident_text("class name after `record`")?;
        let from = if self.consume_ident("from") {
            Some(self.ident_text("binding name after `from`")?)
        } else {
            None
        };
        let fields = self.parse_field_block(from.is_some())?;
        Some(RecordStmt {
            schema,
            from,
            fields,
            span: self.span_from(start),
        })
    }

    fn parse_done_statement(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // `done`
        let binding = self.ident_text("fact binding after `done`")?;
        let replacement = if matches!(self.peek().map(|t| &t.tok), Some(Tok::Arrow)) {
            self.pos += 1;
            if !self.consume_ident("record") {
                let span = self.span_here();
                self.error(span, "expected `record` after `->`", None);
                return None;
            }
            self.pos -= 1; // parse_record_statement expects to consume `record`
            Some(self.parse_record_statement()?)
        } else {
            None
        };
        Some(BodyStmt::Done {
            binding,
            replacement,
            span: self.span_from(start),
        })
    }

    /// The bare `consume <binding>` alias for `done` was removed after its
    /// deprecation window (one release; shipped in v0.2). Emit a clear
    /// diagnostic instead of the generic unknown-statement error. The live
    /// counter verb `consume <counter> for ...` is dispatched ahead of this by
    /// `looks_like_counter_consume`, so only the removed alias reaches here.
    fn removed_consume_alias(&mut self) -> Option<BodyStmt> {
        let span = self.span_here();
        self.error(
            span,
            "`consume` was removed; use `done`",
            Some("replace `consume` with `done`".to_owned()),
        );
        // Swallow the whole statement (binding and any `-> record { ... }`) so
        // the removed alias yields ONE diagnostic, not a cascade from the
        // leftover binding being re-scanned as an unknown statement.
        self.pos += 1; // past `consume`
        self.recover();
        None
    }

    /// Parse `{ field value ... }`. Values are expressions; in `from` blocks a
    /// bare field name is shorthand-copy. Single-line and multi-line forms are
    /// equivalent: structure comes from tokens, never line breaks.
    fn parse_field_block(&mut self, allow_shorthand: bool) -> Option<Vec<FieldAssign>> {
        if !self.consume_sym('{') {
            let span = self.span_here();
            self.error(span, "expected `{` to open a field block", None);
            return None;
        }
        let mut fields = Vec::new();
        loop {
            if self.consume_sym('}') {
                return Some(fields);
            }
            if self.peek().is_none() {
                let span = self.span_here();
                self.error(span, "unclosed field block", Some("add `}`".to_owned()));
                return Some(fields);
            }
            let field_start = self.pos;
            let Some(name) = self.ident_text("field name") else {
                self.recover();
                continue;
            };
            // Nested typed payload: `binding Schema { ... }`.
            if matches!(self.peek().map(|t| &t.tok), Some(Tok::Ident(next))
                if next.chars().next().is_some_and(char::is_uppercase))
                && matches!(self.peek_at(1).map(|t| &t.tok), Some(Tok::Sym('{')))
            {
                let schema = self.ident_text("payload class name")?;
                let nested = self.parse_field_block(false)?;
                fields.push(FieldAssign {
                    name,
                    value: FieldValue::Nested {
                        schema,
                        fields: nested,
                    },
                    span: self.span_from(field_start),
                });
                continue;
            }
            // `from` blocks support shorthand: a bare field name copies the
            // same-named field. Shorthand is line-delimited (the historical
            // and documented form): a name is shorthand when the next token
            // sits on a different line or closes the block.
            if allow_shorthand {
                let name_line = self
                    .tokens
                    .get(field_start)
                    .map(|t| t.line)
                    .unwrap_or_default();
                let is_shorthand = match self.peek() {
                    None => true,
                    Some(token) => matches!(token.tok, Tok::Sym('}')) || token.line != name_line,
                };
                if is_shorthand {
                    fields.push(FieldAssign {
                        name,
                        value: FieldValue::Shorthand,
                        span: self.span_from(field_start),
                    });
                    continue;
                }
            }
            let Some((source, expr)) = self.parse_value_expression() else {
                self.recover();
                continue;
            };
            fields.push(FieldAssign {
                name,
                value: FieldValue::Expr { source, expr },
                span: self.span_from(field_start),
            });
        }
    }

    /// Capture one expression's source slice by walking atoms and operators,
    /// then parse it with the shared expression parser.
    fn parse_value_expression(&mut self) -> Option<(String, Expr)> {
        let start_token = self.pos;
        if !self.consume_value_atom() {
            let span = self.span_here();
            self.error(span, "expected a field value expression", None);
            return None;
        }
        loop {
            match self.peek().map(|t| t.tok.clone()) {
                Some(Tok::Op(_)) | Some(Tok::Sym('+')) | Some(Tok::Sym('-'))
                | Some(Tok::Sym('*')) | Some(Tok::Sym('/')) | Some(Tok::Sym('<'))
                | Some(Tok::Sym('>')) => {
                    self.pos += 1;
                    if !self.consume_value_atom() {
                        let span = self.span_here();
                        self.error(span, "expected expression after operator", None);
                        return None;
                    }
                }
                Some(Tok::Ident(word)) if word == "and" || word == "or" || word == "in" => {
                    self.pos += 1;
                    if !self.consume_value_atom() {
                        let span = self.span_here();
                        self.error(span, "expected expression after operator", None);
                        return None;
                    }
                }
                Some(Tok::Sym('[')) => {
                    // index continuation
                    self.consume_balanced('[', ']');
                }
                _ => break,
            }
        }
        let first = self.tokens.get(start_token)?;
        let last = self.tokens.get(self.pos.saturating_sub(1))?;
        let source = self.source[first.start..last.end].to_owned();
        match parse_expression(&source) {
            Ok(expr) => Some((source, expr)),
            Err(message) => {
                let span = SourceSpan {
                    start: self.base + first.start,
                    end: self.base + last.end,
                };
                self.error(
                    span,
                    format!("invalid field value expression: {message}"),
                    None,
                );
                None
            }
        }
    }

    fn consume_value_atom(&mut self) -> bool {
        match self.peek().map(|t| t.tok.clone()) {
            Some(Tok::Str(_)) | Some(Tok::Number(_)) | Some(Tok::TripleStr { .. }) => {
                self.pos += 1;
                true
            }
            Some(Tok::Sym('[')) => self.consume_balanced('[', ']'),
            Some(Tok::Sym('{')) => self.consume_balanced('{', '}'),
            Some(Tok::Sym('(')) => self.consume_balanced('(', ')'),
            Some(Tok::Sym('!')) | Some(Tok::Sym('-')) => {
                self.pos += 1;
                self.consume_value_atom()
            }
            Some(Tok::Ident(word)) if word == "not" => {
                self.pos += 1;
                self.consume_value_atom()
            }
            Some(Tok::Ident(_)) => {
                self.pos += 1;
                // call like count(...) / exists(...)
                if self.at_sym('(') {
                    self.consume_balanced('(', ')');
                }
                true
            }
            _ => false,
        }
    }

    fn consume_balanced(&mut self, open: char, close: char) -> bool {
        if !self.consume_sym(open) {
            return false;
        }
        let mut depth = 1;
        while depth > 0 {
            match self.advance().map(|t| t.tok) {
                Some(Tok::Sym(c)) if c == open => depth += 1,
                Some(Tok::Sym(c)) if c == close => depth -= 1,
                Some(_) => {}
                None => {
                    let span = self.span_here();
                    self.error(span, format!("unclosed `{open}`"), None);
                    return false;
                }
            }
        }
        true
    }

    // -- effects -----------------------------------------------------------

    fn parse_effect_modifiers(
        &mut self,
        binding: &mut Option<String>,
        requires: &mut Vec<String>,
        timeout_seconds: &mut Option<u64>,
    ) -> bool {
        loop {
            if self.consume_ident("as") {
                match self.ident_text("binding name after `as`") {
                    Some(name) => *binding = Some(name),
                    None => return false,
                }
                continue;
            }
            if self.consume_ident("requires") {
                match self.parse_string_array() {
                    Some(values) => *requires = values,
                    None => return false,
                }
                continue;
            }
            if self.consume_ident("timeout") {
                let span = self.span_here();
                let Some(Tok::Number(value)) = self.peek().map(|t| t.tok.clone()) else {
                    self.error(
                        span,
                        "expected a duration after `timeout`".to_owned(),
                        Some(
                            "use `<n><unit>` with unit s, m, h, or d, e.g. `timeout 10m`"
                                .to_owned(),
                        ),
                    );
                    return false;
                };
                self.pos += 1;
                match parse_short_duration_seconds(&value) {
                    Some(seconds) if seconds > 0 => *timeout_seconds = Some(seconds),
                    _ => {
                        self.error(
                            span,
                            format!("invalid timeout duration `{value}`"),
                            Some("use `<n><unit>` with unit s, m, h, or d".to_owned()),
                        );
                        return false;
                    }
                }
                continue;
            }
            return true;
        }
    }

    fn parse_string_array(&mut self) -> Option<Vec<String>> {
        if !self.consume_sym('[') {
            let span = self.span_here();
            self.error(span, "expected `[` to open a string list", None);
            return None;
        }
        let mut values = Vec::new();
        loop {
            if self.consume_sym(']') {
                return Some(values);
            }
            match self.advance().map(|t| t.tok) {
                Some(Tok::Str(value)) => values.push(value),
                Some(Tok::Sym(',')) => {}
                other => {
                    let span = self.span_here();
                    self.error(
                        span,
                        format!("expected a string in list, found {other:?}"),
                        None,
                    );
                    return None;
                }
            }
        }
    }

    fn parse_prompt(&mut self) -> Option<Prompt> {
        match self.advance().map(|t| t.tok) {
            Some(Tok::Str(text)) => Some(Prompt {
                text,
                content_type: None,
            }),
            Some(Tok::TripleStr { text, content_type }) => Some(Prompt { text, content_type }),
            _ => {
                let span = self.span_here();
                self.error(span, "expected a prompt string", None);
                None
            }
        }
    }

    fn parse_tell(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // tell
        let target = self.ident_text("agent target after `tell`")?;
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        let mut access_grants = Vec::new();
        let mut skills = Vec::new();
        let mut on_stream = None;
        // Pre-prompt modifiers may interleave the standard ones (`as`/`requires`/
        // `timeout`) with `with access to` grants, `with skills [...]`, and
        // `on stream <name>`.
        if !self.parse_effect_modifiers_with_access(
            &mut binding,
            &mut requires,
            &mut timeout_seconds,
            &mut access_grants,
            Some(&mut skills),
            Some(&mut on_stream),
        ) {
            return None;
        }
        let prompt = self.parse_prompt()?;
        if !self.parse_effect_modifiers_with_access(
            &mut binding,
            &mut requires,
            &mut timeout_seconds,
            &mut access_grants,
            Some(&mut skills),
            Some(&mut on_stream),
        ) {
            return None;
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::Tell {
                target,
                access_grants,
                skills,
                on_stream,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: Some(prompt),
            span: self.span_from(start),
        }))
    }

    /// Parse effect modifiers, interleaving the shared effect modifiers with
    /// `with access to` grants until neither matches.
    fn parse_effect_modifiers_with_access(
        &mut self,
        binding: &mut Option<String>,
        requires: &mut Vec<String>,
        timeout_seconds: &mut Option<u64>,
        access_grants: &mut Vec<AccessGrant>,
        mut skills: Option<&mut Vec<String>>,
        mut on_stream: Option<&mut Option<String>>,
    ) -> bool {
        loop {
            if !self.parse_effect_modifiers(binding, requires, timeout_seconds) {
                return false;
            }
            // `on stream <name>` (std.vcs): only where a homing slot is
            // offered (`tell`); elsewhere `on` is not consumed.
            if self.at_ident("on")
                && matches!(self.peek_at(1).map(|t| &t.tok), Some(Tok::Ident(v)) if v == "stream")
            {
                if let Some(slot) = on_stream.as_deref_mut() {
                    self.pos += 2; // on stream
                    let Some(name) = self.ident_text("stream name after `on stream`") else {
                        return false;
                    };
                    *slot = Some(name);
                    continue;
                }
            }
            if self.at_ident("with") {
                // Turn-scoped `with skills [...]` (Phase 7) vs `with access to …`.
                // `with skills` is only valid where a skills accumulator is offered
                // (`tell`); elsewhere it falls through to the access-grant error.
                if matches!(self.peek_at(1).map(|t| &t.tok), Some(Tok::Ident(v)) if v == "skills") {
                    if let Some(acc) = skills.as_deref_mut() {
                        if !self.parse_with_skills(acc) {
                            return false;
                        }
                        continue;
                    }
                }
                if !self.parse_access_grant(access_grants) {
                    return false;
                }
                continue;
            }
            return true;
        }
    }

    /// Parse `with skills ["a", "b"]` (context-assembly Phase 7): turn-scoped skills
    /// pinned into the turn's provenance. Assumes the cursor is at `with`.
    fn parse_with_skills(&mut self, skills: &mut Vec<String>) -> bool {
        self.pos += 1; // with
        self.pos += 1; // skills (peeked by the caller)
        if !self.at_sym('[') {
            let span = self.span_here();
            self.error(
                span,
                "expected `[\"skill\", …]` after `with skills`".to_owned(),
                None,
            );
            return false;
        }
        match self.parse_string_array() {
            Some(values) => {
                skills.extend(values);
                true
            }
            None => false,
        }
    }

    /// Parse `with access to <resource> { <op clauses> }`, or the resource-less
    /// shorthand `with access to { <resource> { <op clauses> } ... }`. Each clause is
    /// an operation name with an optional `for <target>` ref and/or `["glob", …]`
    /// paths. `with context`/`with skills` modifiers are not yet supported and are
    /// reported as such.
    fn parse_access_grant(&mut self, grants: &mut Vec<AccessGrant>) -> bool {
        let start = self.pos;
        self.pos += 1; // with
        if !self.consume_ident("access") {
            let span = self.span_here();
            let detail = if self.at_ident("context") || self.at_ident("skills") {
                "`with context`/`with skills` turn modifiers are not supported yet"
            } else {
                "expected `access to <resource> { ... }` after `with`"
            };
            self.error(span, detail.to_owned(), None);
            return false;
        }
        if !self.consume_ident("to") {
            let span = self.span_here();
            self.error(span, "expected `to` after `with access`".to_owned(), None);
            return false;
        }
        if self.consume_sym('{') {
            let mut resources = 0usize;
            loop {
                if self.consume_sym('}') {
                    break;
                }
                resources += 1;
                let grant_start = self.pos;
                let Some(resource) =
                    self.ident_text("resource in the access-grant shorthand block")
                else {
                    return false;
                };
                if !self.consume_sym('{') {
                    let span = self.span_here();
                    self.error(
                        span,
                        "expected `{` to open the resource access-grant block".to_owned(),
                        None,
                    );
                    return false;
                }
                let Some(operations) = self.parse_access_grant_operations() else {
                    return false;
                };
                grants.push(AccessGrant {
                    resource,
                    operations,
                    span: self.span_from(grant_start),
                });
            }
            if resources == 0 {
                let span = self.span_from(start);
                self.error(
                    span,
                    "access-grant shorthand block grants no resources".to_owned(),
                    Some(
                        "write `with access to <resource> { ... }`, or add resource blocks inside the shorthand"
                            .to_owned(),
                    ),
                );
                return false;
            }
            return true;
        }
        let Some(resource) = self.ident_text("resource after `with access to`") else {
            return false;
        };
        if !self.consume_sym('{') {
            let span = self.span_here();
            self.error(
                span,
                "expected `{` to open the access-grant block".to_owned(),
                None,
            );
            return false;
        }
        let Some(operations) = self.parse_access_grant_operations() else {
            return false;
        };
        grants.push(AccessGrant {
            resource,
            operations,
            span: self.span_from(start),
        });
        true
    }

    fn parse_access_grant_operations(&mut self) -> Option<Vec<AccessGrantOp>> {
        let mut operations = Vec::new();
        loop {
            if self.consume_sym('}') {
                return Some(operations);
            }
            let op_start = self.pos;
            let operation = self.ident_text("operation in the access-grant block")?;
            let mut target = None;
            if self.consume_ident("for") {
                target = Some(self.ident_text("target after `for`")?);
            }
            let mut globs = Vec::new();
            if self.at_sym('[') {
                globs = self.parse_string_array()?;
            }
            operations.push(AccessGrantOp {
                operation,
                target,
                globs,
                span: self.span_from(op_start),
            });
        }
    }

    fn parse_coerce_call(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // coerce
        let name = self.ident_text("coerce function name")?;
        if !self.consume_sym('(') {
            let span = self.span_here();
            self.error(span, "expected `(` after coerce function name", None);
            return None;
        }
        let mut args = Vec::new();
        loop {
            if self.consume_sym(')') {
                break;
            }
            if self.peek().is_none() {
                let span = self.span_here();
                self.error(span, "unclosed coerce argument list", None);
                return None;
            }
            let (source, _) = self.parse_value_expression()?;
            args.push(source);
            self.consume_sym(',');
        }
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        // optional trailing source-crossing markers (I-IFC3); must come last.
        let mut endorsed = false;
        let mut declassified = false;
        loop {
            if self.consume_ident("endorsed") {
                endorsed = true;
            } else if self.consume_ident("declassified") {
                declassified = true;
            } else {
                break;
            }
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::Coerce {
                name,
                args,
                endorsed,
                declassified,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    fn parse_prompt_effect(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // prompt
        let prompt = self.parse_prompt()?;
        let provider = if self.consume_ident("using") {
            Some(self.ident_text("provider after `using`")?)
        } else {
            None
        };
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        if binding.is_none() {
            let span = self.span_from(start);
            self.error(
                span,
                "`prompt` requires an `as` binding".to_owned(),
                Some("write `prompt \"Summarize this\" as summary`".to_owned()),
            );
            return None;
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::Prompt { provider },
            binding,
            requires,
            timeout_seconds,
            prompt: Some(prompt),
            span: self.span_from(start),
        }))
    }

    fn parse_decide(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // decide
        let prompt = self.parse_prompt()?;
        if !matches!(self.advance().map(|t| t.tok), Some(Tok::Arrow)) {
            let span = self.span_here();
            self.error(
                span,
                "expected `->` after the decide prompt".to_owned(),
                Some("write `decide \"...\" -> { field type, ... } as name`".to_owned()),
            );
            return None;
        }
        if !self.consume_sym('{') {
            let span = self.span_here();
            self.error(span, "expected `{` to open the decide result shape", None);
            return None;
        }
        let mut result_fields = Vec::new();
        loop {
            if self.consume_sym('}') {
                break;
            }
            let name = self.ident_text("result field name")?;
            let ty = self.ident_text("result field type")?;
            result_fields.push((name, ty));
            self.consume_sym(',');
        }
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        if binding.is_none() {
            let span = self.span_from(start);
            self.error(
                span,
                "`decide` requires an `as` binding".to_owned(),
                Some(
                    "the typed result is only reachable through `after <binding> succeeds`"
                        .to_owned(),
                ),
            );
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::Decide { result_fields },
            binding,
            requires,
            timeout_seconds,
            prompt: Some(prompt),
            span: self.span_from(start),
        }))
    }

    /// `request <METHOD> "<url>" { header "<name>" <value> … body <expr> }
    /// [signed with <handle>] as <binding>` (DR-0053 §5).
    fn parse_http_request(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // request
                       // The METHOD is an uppercase bare word rather than a string, so a
                       // lowercase typo reads as a method rather than silently becoming a URL.
        let method = match self.peek().map(|t| t.tok.clone()) {
            Some(Tok::Ident(word)) if word.chars().all(|c| c.is_ascii_uppercase()) => {
                self.pos += 1;
                word
            }
            _ => {
                let span = self.span_here();
                self.error(
                    span,
                    "expected an HTTP method after `request`".to_owned(),
                    Some(
                        "write `request POST \"https://example.com/path\" { … } as reply`"
                            .to_owned(),
                    ),
                );
                return None;
            }
        };
        let Some(Tok::Str(url)) = self.peek().map(|t| t.tok.clone()) else {
            let span = self.span_here();
            self.error(
                span,
                format!("expected a quoted URL after `request {method}`"),
                Some(format!(
                    "write `request {method} \"https://example.com/path\" {{ … }} as reply`"
                )),
            );
            return None;
        };
        self.pos += 1;

        let mut headers = Vec::new();
        let mut body = None;
        if self.at_sym('{') {
            self.pos += 1;
            loop {
                if self.at_sym('}') {
                    self.pos += 1;
                    break;
                }
                match self.peek().map(|t| t.tok.clone()) {
                    Some(Tok::Ident(word)) if word == "header" => {
                        let header_start = self.pos;
                        self.pos += 1;
                        let Some(Tok::Str(name)) = self.peek().map(|t| t.tok.clone()) else {
                            let span = self.span_here();
                            self.error(
                                span,
                                "expected a quoted header name after `header`".to_owned(),
                                Some(
                                    "write `header \"Authorization\" bearer stripe_api`".to_owned(),
                                ),
                            );
                            return None;
                        };
                        self.pos += 1;
                        // A presentation form is `bearer|basic|raw <handle>`;
                        // anything else is an ordinary expression.
                        let value = match self.peek().map(|t| t.tok.clone()) {
                            Some(Tok::Ident(word))
                                if CredentialPresentation::parse(&word).is_some()
                                    && matches!(
                                        self.peek_at(1).map(|t| t.tok.clone()),
                                        Some(Tok::Ident(_))
                                    ) =>
                            {
                                let presentation = CredentialPresentation::parse(&word)
                                    .expect("guarded by the match");
                                self.pos += 1;
                                let handle =
                                    self.ident_text("credential handle after the presentation")?;
                                RequestHeaderValue::Credential {
                                    presentation,
                                    handle,
                                }
                            }
                            _ => {
                                let (source, expr) = self.parse_value_expression()?;
                                RequestHeaderValue::Expr { source, expr }
                            }
                        };
                        headers.push(RequestHeader {
                            name,
                            value,
                            span: self.span_from(header_start),
                        });
                    }
                    Some(Tok::Ident(word)) if word == "body" => {
                        if body.is_some() {
                            let span = self.span_here();
                            self.error(
                                span,
                                "a request carries at most one `body`".to_owned(),
                                None,
                            );
                            return None;
                        }
                        self.pos += 1;
                        body = Some(self.parse_value_expression()?);
                    }
                    _ => {
                        let span = self.span_here();
                        self.error(
                            span,
                            "expected `header` or `body` inside a request block".to_owned(),
                            None,
                        );
                        return None;
                    }
                }
            }
        }

        let signed_with = if self.at_ident("signed") {
            self.pos += 1;
            if !self.consume_ident("with") {
                let span = self.span_here();
                self.error(
                    span,
                    "expected `with <credential>` after `signed`".to_owned(),
                    Some("write `} signed with release_signing as put`".to_owned()),
                );
                return None;
            }
            Some(self.ident_text("credential handle after `signed with`")?)
        } else {
            None
        };

        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::HttpRequest {
                method,
                url,
                headers,
                body,
                signed_with,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    fn parse_call(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // call
        let capability = self.ident_text("package capability after `call`")?;
        let argument = if self.consume_ident("for") {
            Some(self.ident_text("argument binding after `for`")?)
        } else {
            None
        };
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::Call {
                capability,
                argument,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    /// Parse a data-driven `effect_operation` construct (DR-0011). Reproduces
    /// the byte-identical success lowering the hand-written `recall`/`send`
    /// parsers emitted: consume the keyword, then each slot (its connective, if
    /// any, then its value), then the optional payload block (required/unknown
    /// checks, expression-typed, in encounter order), then the effect modifiers,
    /// enforcing the binding mode, and build one `ConstructCapabilityCall` whose
    /// fields are the slots followed by the payload fields, in order.
    fn parse_effect_operation(&mut self, spec: &EffectOperationSpec) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // keyword
        let mut fields: Vec<ConstructUseField> = Vec::new();
        for slot in spec.slots {
            if let Some(connective) = slot.connective {
                if !self.consume_ident(connective) {
                    let span = self.span_here();
                    self.error(
                        span,
                        format!("expected `{connective}` after `{}`", spec.keyword),
                        None,
                    );
                    return None;
                }
            }
            let source = match slot.kind {
                SlotKind::Identifier => self.ident_text(slot.name)?,
                SlotKind::Expression => self.parse_value_expression()?.0,
            };
            fields.push(ConstructUseField {
                name: slot.name.to_owned(),
                source,
            });
        }
        if let Some(payload) = spec.payload {
            let block_fields = self.parse_field_block(false)?;
            let mut seen: Vec<&'static str> = Vec::new();
            for field in &block_fields {
                let Some(field_spec) = payload.iter().find(|f| f.name == field.name) else {
                    self.error(
                        field.span,
                        format!("unknown `{}` block field `{}`", spec.keyword, field.name),
                        None,
                    );
                    return None;
                };
                let FieldValue::Expr { source, .. } = &field.value else {
                    self.error(
                        field.span,
                        format!(
                            "`{}` field `{}` must be an expression",
                            spec.keyword, field.name
                        ),
                        None,
                    );
                    return None;
                };
                seen.push(field_spec.name);
                fields.push(ConstructUseField {
                    name: field.name.clone(),
                    source: source.clone(),
                });
            }
            for required in payload.iter().filter(|f| f.required) {
                if !seen.contains(&required.name) {
                    let span = self.span_from(start);
                    self.error(
                        span,
                        format!("`{}` requires a `{}` field", spec.keyword, required.name),
                        None,
                    );
                    return None;
                }
            }
        }
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        match spec.binding {
            BindingMode::Required if binding.is_none() => {
                let span = self.span_from(start);
                self.error(
                    span,
                    format!("`{}` requires an `as` binding", spec.keyword),
                    None,
                );
                return None;
            }
            BindingMode::None if binding.is_some() => {
                let span = self.span_from(start);
                self.error(
                    span,
                    format!("`{}` does not take an `as` binding", spec.keyword),
                    None,
                );
                return None;
            }
            _ => {}
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::ConstructCapabilityCall {
                keyword: spec.keyword.to_owned(),
                target_capability: spec.target_capability.to_owned(),
                fields,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    fn parse_read(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // read
        let usage = "write `read <format> from <store> at <path> as <binding>`".to_owned();
        let format = self.ident_text("file format after `read`")?;
        // v0 `read` is a body read: `text`/`markdown` decode to a UTF-8 content
        // body. Structured codecs (json/jsonl/csv) are typed row/value data —
        // that is the `import` surface (fact-batch admission), not `read`; and
        // `bytes` (an artifact with a content hash) is a deferred read codec.
        // Reject anything else here so `read <format>` is honest rather than
        // silently decoding every format as text.
        if !matches!(format.as_str(), "text" | "markdown") {
            let span = self.span_from(start);
            self.error(
                span,
                format!(
                    "`read {format}` is not supported in v0 — `read` decodes only `text` or `markdown` bodies"
                ),
                Some(
                    "use `read text`/`read markdown` for a body, `import <format> <Schema>` for structured rows, or `read text` + `coerce` to interpret structured content".to_owned(),
                ),
            );
            return None;
        }
        if !self.consume_ident("from") {
            let span = self.span_here();
            self.error(
                span,
                "expected `from` after read format".to_owned(),
                Some(usage),
            );
            return None;
        }
        let store = self.ident_text("file store after `from`")?;
        if !self.consume_ident("at") {
            let span = self.span_here();
            self.error(
                span,
                "expected `at` after read store".to_owned(),
                Some(usage),
            );
            return None;
        }
        let (path, _) = self.parse_value_expression()?;
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        if binding.is_none() {
            let span = self.span_from(start);
            self.error(
                span,
                "`read` requires an `as` binding".to_owned(),
                Some(usage),
            );
            return None;
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::FileRead {
                format,
                store,
                path,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    fn parse_write(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // write
        let usage =
            "write `write <format> to <store> at <path> { body <expr> mode <mode> } as <binding>`"
                .to_owned();
        let format = self.ident_text("file format after `write`")?;
        // v0 `write` renders the `text`/`markdown` body codecs (UTF-8 bodies).
        // Rendering typed values as json/csv is `export` (deferred, fact-batch).
        if !matches!(format.as_str(), "text" | "markdown") {
            let span = self.span_from(start);
            self.error(
                span,
                format!(
                    "`write {format}` is not supported in v0 — `write` renders only `text` or `markdown` bodies"
                ),
                Some(
                    "use `write text`/`write markdown` for a body; structured `export <format> <Schema>` is deferred".to_owned(),
                ),
            );
            return None;
        }
        if !self.consume_ident("to") {
            let span = self.span_here();
            self.error(
                span,
                "expected `to` after write format".to_owned(),
                Some(usage),
            );
            return None;
        }
        let store = self.ident_text("file store after `to`")?;
        if !self.consume_ident("at") {
            let span = self.span_here();
            self.error(
                span,
                "expected `at` after write store".to_owned(),
                Some(usage),
            );
            return None;
        }
        let (path, _) = self.parse_value_expression()?;
        let fields = self.parse_field_block(false)?;
        let mut body = None;
        let mut mode = None;
        for field in &fields {
            match field.name.as_str() {
                "body" => {
                    if let FieldValue::Expr { source, .. } = &field.value {
                        body = Some(source.clone());
                    }
                }
                "mode" => {
                    if let FieldValue::Expr { source, .. } = &field.value {
                        mode = Some(source.trim().trim_matches('"').to_owned());
                    }
                }
                other => {
                    self.error(
                        field.span,
                        format!(
                            "unknown `write` block field `{other}` (expected `body` or `mode`)"
                        ),
                        Some(usage.clone()),
                    );
                    return None;
                }
            }
        }
        let Some(body) = body else {
            let span = self.span_from(start);
            self.error(
                span,
                "`write` requires a `body` field".to_owned(),
                Some(usage),
            );
            return None;
        };
        // The mode is required: "no silent overwrite" (spec/files.md).
        let Some(mode) = mode else {
            let span = self.span_from(start);
            self.error(
                span,
                "`write` requires an explicit `mode` (create/replace/upsert/append) — no silent overwrite".to_owned(),
                Some(usage),
            );
            return None;
        };
        if !matches!(mode.as_str(), "create" | "replace" | "upsert" | "append") {
            let span = self.span_from(start);
            self.error(
                span,
                format!("unknown write mode `{mode}` (expected create/replace/upsert/append)"),
                Some(usage),
            );
            return None;
        }
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        if binding.is_none() {
            let span = self.span_from(start);
            self.error(
                span,
                "`write` requires an `as` binding".to_owned(),
                Some(usage),
            );
            return None;
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::FileWrite {
                format,
                store,
                path,
                body,
                mode,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    fn parse_import(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // import
        let usage =
            "write `import <format> <Schema> from <store> at <path> as <binding>`".to_owned();
        let format = self.ident_text("import format after `import`")?;
        // v0 `import` decodes the structured row codecs into typed facts.
        if !matches!(format.as_str(), "jsonl" | "json" | "csv") {
            let span = self.span_from(start);
            self.error(
                span,
                format!(
                    "`import {format}` is not supported in v0 — `import` decodes `jsonl`, `json`, or `csv`"
                ),
                Some(usage),
            );
            return None;
        }
        let schema = self.ident_text("row schema after import format")?;
        if !self.consume_ident("from") {
            let span = self.span_here();
            self.error(
                span,
                "expected `from` after import schema".to_owned(),
                Some(usage),
            );
            return None;
        }
        let store = self.ident_text("file store after `from`")?;
        if !self.consume_ident("at") {
            let span = self.span_here();
            self.error(
                span,
                "expected `at` after import store".to_owned(),
                Some(usage),
            );
            return None;
        }
        let (path, _) = self.parse_value_expression()?;
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        if binding.is_none() {
            let span = self.span_from(start);
            self.error(
                span,
                "`import` requires an `as` binding".to_owned(),
                Some(usage),
            );
            return None;
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::FileImport {
                format,
                schema,
                store,
                path,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    fn parse_export(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // export
        let usage =
            "write `export <format> <Schema> to <store> at <path> { [where <pred>] mode <mode> } as <binding>`"
                .to_owned();
        let format = self.ident_text("export format after `export`")?;
        if !matches!(format.as_str(), "jsonl" | "json" | "csv") {
            let span = self.span_from(start);
            self.error(
                span,
                format!(
                    "`export {format}` is not supported in v0 — `export` writes `jsonl`, `json`, or `csv`"
                ),
                Some(usage),
            );
            return None;
        }
        let schema = self.ident_text("row schema after export format")?;
        if !self.consume_ident("to") {
            let span = self.span_here();
            self.error(
                span,
                "expected `to` after export schema".to_owned(),
                Some(usage),
            );
            return None;
        }
        let store = self.ident_text("file store after `to`")?;
        if !self.consume_ident("at") {
            let span = self.span_here();
            self.error(
                span,
                "expected `at` after export store".to_owned(),
                Some(usage),
            );
            return None;
        }
        let (path, _) = self.parse_value_expression()?;
        if !self.consume_sym('{') {
            let span = self.span_here();
            self.error(
                span,
                "expected `{` to open the export block".to_owned(),
                Some(usage),
            );
            return None;
        }
        // Block: an optional `where <pred>` collection filter (DR-0022) + a
        // required `mode`. The schema's facts are the collection; `where` narrows
        // it. `mode` follows the `write` policy (no silent overwrite).
        let mut predicate = None;
        let mut mode = None;
        loop {
            if self.consume_sym('}') {
                break;
            }
            if self.peek().is_none() {
                let span = self.span_here();
                self.error(span, "unclosed export block".to_owned(), Some(usage));
                return None;
            }
            if self.consume_ident("where") {
                let (source, _) = self.parse_value_expression()?;
                predicate = Some(source);
            } else if self.consume_ident("mode") {
                let value = self.ident_text("write mode after `mode`")?;
                mode = Some(value);
            } else {
                let span = self.span_here();
                self.error(
                    span,
                    "unknown export block field (expected `where` or `mode`)".to_owned(),
                    Some(usage.clone()),
                );
                self.recover();
            }
        }
        let Some(mode) = mode else {
            let span = self.span_from(start);
            self.error(
                span,
                "`export` requires an explicit `mode` (create/replace/upsert/append) — no silent overwrite".to_owned(),
                Some(usage),
            );
            return None;
        };
        if !matches!(mode.as_str(), "create" | "replace" | "upsert" | "append") {
            let span = self.span_from(start);
            self.error(
                span,
                format!("unknown write mode `{mode}` (expected create/replace/upsert/append)"),
                Some(usage),
            );
            return None;
        }
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        if binding.is_none() {
            let span = self.span_from(start);
            self.error(
                span,
                "`export` requires an `as` binding".to_owned(),
                Some(usage),
            );
            return None;
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::FileExport {
                format,
                schema,
                store,
                path,
                predicate,
                mode,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    fn parse_invoke(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // invoke
        let workflow = self.ident_text("workflow name after `invoke`")?;
        let payload = self.parse_field_block(false)?;
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        let mut access_grants = Vec::new();
        if !self.parse_effect_modifiers_with_access(
            &mut binding,
            &mut requires,
            &mut timeout_seconds,
            &mut access_grants,
            None,
            None,
        ) {
            return None;
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::Invoke {
                workflow,
                payload,
                access_grants,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    fn parse_timer(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // timer
        let span = self.span_here();
        // Absolute deadline: `timer until <time-expr>` (spec/scheduled-time.md).
        if matches!(self.peek().map(|t| &t.tok), Some(Tok::Ident(word)) if word == "until") {
            self.pos += 1; // until
            let until = match self.peek().map(|t| t.tok.clone()) {
                Some(Tok::Str(literal)) => {
                    self.pos += 1;
                    if !is_iso8601_instant(&literal) {
                        self.error(
                            span,
                            format!("invalid time literal `{literal}`"),
                            Some(
                                "use an ISO-8601 instant such as `\"2026-06-15T09:00:00Z\"`"
                                    .to_owned(),
                            ),
                        );
                        return None;
                    }
                    literal
                }
                Some(Tok::Ident(path)) => {
                    // a time-typed path, possibly dotted
                    let mut text = path;
                    self.pos += 1;
                    while matches!(self.peek().map(|t| &t.tok), Some(Tok::Sym('.'))) {
                        self.pos += 1;
                        if let Some(Tok::Ident(seg)) = self.peek().map(|t| t.tok.clone()) {
                            text.push('.');
                            text.push_str(&seg);
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                    text
                }
                _ => {
                    self.error(
                        span,
                        "expected a time literal or path after `timer until`".to_owned(),
                        Some("e.g. `timer until \"2026-06-15T09:00:00Z\" as deadline` or `timer until ticket.dueAt as deadline`".to_owned()),
                    );
                    return None;
                }
            };
            let mut binding = None;
            let mut requires = Vec::new();
            let mut timeout_seconds = None;
            if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
                return None;
            }
            if binding.is_none() {
                let span = self.span_from(start);
                self.error(
                    span,
                    "`timer` requires an `as` binding".to_owned(),
                    Some("rules react to the timer with `after <binding> succeeds`".to_owned()),
                );
            }
            return Some(BodyStmt::Effect(EffectStmt {
                kind: BodyEffectKind::Timer {
                    duration_seconds: 0,
                    duration_source: String::new(),
                    until: Some(until),
                },
                binding,
                requires,
                timeout_seconds,
                prompt: None,
                span: self.span_from(start),
            }));
        }
        let Some(Tok::Number(value)) = self.peek().map(|t| t.tok.clone()) else {
            self.error(
                span,
                "expected a duration after `timer`".to_owned(),
                Some(
                    "use `<n><unit>` with unit s, m, h, or d, e.g. `timer 24h as deadline`"
                        .to_owned(),
                ),
            );
            return None;
        };
        self.pos += 1;
        let Some(duration_seconds) = parse_short_duration_seconds(&value).filter(|s| *s > 0) else {
            self.error(
                span,
                format!("invalid timer duration `{value}`"),
                Some("use `<n><unit>` with unit s, m, h, or d".to_owned()),
            );
            return None;
        };
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        if binding.is_none() {
            let span = self.span_from(start);
            self.error(
                span,
                "`timer` requires an `as` binding".to_owned(),
                Some("rules react to the timer with `after <binding> succeeds`".to_owned()),
            );
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::Timer {
                duration_seconds,
                duration_source: value,
                until: None,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    fn parse_cancel(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // cancel
        let binding = self.ident_text("effect binding after `cancel`")?;
        Some(BodyStmt::Cancel {
            binding,
            span: self.span_from(start),
        })
    }

    /// `redact <source> keep [<field>, …] as <out>` (DR-0027): an explicit
    /// information-flow projection. Parses the source binding, the bracketed
    /// comma-separated kept-field list, and the `as` output binding. A redaction
    /// must keep at least one field (keeping nothing releases nothing).
    fn parse_redact(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // redact
        let source = self.ident_text("binding to redact after `redact`")?;
        if !self.consume_ident("keep") {
            let span = self.span_here();
            self.error(
                span,
                "expected `keep [<field>, …]` after the binding".to_owned(),
                Some("write `redact customer keep [id, status] as safe`".to_owned()),
            );
            return None;
        }
        if !self.consume_sym('[') {
            let span = self.span_here();
            self.error(
                span,
                "expected `[` to open the kept-field list".to_owned(),
                Some("write `keep [id, status]`".to_owned()),
            );
            return None;
        }
        let mut keep = Vec::new();
        loop {
            if self.consume_sym(']') {
                break;
            }
            if self.peek().is_none() {
                let span = self.span_here();
                self.error(
                    span,
                    "unclosed kept-field list".to_owned(),
                    Some("add `]`".to_owned()),
                );
                return None;
            }
            let field = self.ident_text("kept field name")?;
            keep.push(field);
            if !self.consume_sym(',') && !self.at_sym(']') {
                let span = self.span_here();
                self.error(
                    span,
                    "expected `,` or `]` in the kept-field list".to_owned(),
                    None,
                );
                return None;
            }
        }
        if !self.consume_ident("as") {
            let span = self.span_here();
            self.error(
                span,
                "`redact` requires an `as <binding>`".to_owned(),
                Some("write `redact customer keep [id] as safe`".to_owned()),
            );
            return None;
        }
        let binding = self.ident_text("output binding after `as`")?;
        if keep.is_empty() {
            let span = self.span_from(start);
            self.error(
                span,
                "`redact` must keep at least one field".to_owned(),
                Some("a redaction that keeps nothing has no value to release".to_owned()),
            );
            return None;
        }
        Some(BodyStmt::Redact {
            source,
            keep,
            binding,
            span: self.span_from(start),
        })
    }

    /// `acquire <lease> for <key-expr> [until ttl] as <slot>`: one atomic
    /// attempt with branchable `held`/`contended` outcomes
    /// (spec/coordination.md).
    fn parse_lease_acquire(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // acquire
        let resource = self.ident_text("lease name after `acquire`")?;
        if !self.consume_ident("for") {
            let span = self.span_here();
            self.error(
                span,
                "expected `for <key>` after the lease name".to_owned(),
                Some("write `acquire deploy_slot for r.env as slot`".to_owned()),
            );
            return None;
        }
        let key_expr = self.dotted_path_text("lease key expression")?;
        let mut until_ttl = false;
        if self.at_ident("until") {
            self.pos += 1;
            if !self.consume_ident("ttl") {
                let span = self.span_here();
                self.error(
                    span,
                    "expected `ttl` after `until`".to_owned(),
                    Some("`acquire ... until ttl` is the fire-and-forget form".to_owned()),
                );
                return None;
            }
            until_ttl = true;
        }
        // `wait <duration>`: bounded retry on contention (spec/coordination.md). The
        // acquire re-attempts on each worker pass until it is `held` or the wait
        // elapses, then reports `contended`.
        let mut wait_seconds = None;
        if self.at_ident("wait") {
            self.pos += 1; // wait
            let span = self.span_here();
            let Some(Tok::Number(value)) = self.peek().map(|t| t.tok.clone()) else {
                self.error(
                    span,
                    "expected a duration after `wait`".to_owned(),
                    Some("use `<n><unit>` with unit s, m, h, or d, e.g. `wait 30s`".to_owned()),
                );
                return None;
            };
            self.pos += 1;
            match parse_short_duration_seconds(&value) {
                Some(seconds) if seconds > 0 => wait_seconds = Some(seconds),
                _ => {
                    self.error(
                        span,
                        format!("invalid wait duration `{value}`"),
                        Some("use `<n><unit>` with unit s, m, h, or d".to_owned()),
                    );
                    return None;
                }
            }
        }
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        if binding.is_none() {
            let span = self.span_from(start);
            self.error(
                span,
                "`acquire` requires an `as` binding".to_owned(),
                Some(
                    "branch on it with `after <binding> held` and `after <binding> contended`"
                        .to_owned(),
                ),
            );
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::LeaseAcquire {
                resource,
                key_expr,
                until_ttl,
                wait_seconds,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    /// `renew <acquire-binding> [until <ttl>] as <b>`: extend a held lease's
    /// TTL before it expires (spec/coordination.md). It names the `as` binding
    /// of the `acquire` it extends, so resource/key never drift, and yields a
    /// branchable `renewed`/`notHeld` outcome.
    fn parse_lease_renew(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // renew
        let acquire_binding = self.ident_text("lease binding after `renew`")?;
        // `until <duration>`: the new TTL. Unlike `acquire`'s `until ttl` keyword
        // (fire-and-forget), renew's `until` takes a duration value, e.g.
        // `until 300s`.
        let mut ttl_seconds = None;
        if self.at_ident("until") {
            self.pos += 1; // until
            let span = self.span_here();
            let Some(Tok::Number(value)) = self.peek().map(|t| t.tok.clone()) else {
                self.error(
                    span,
                    "expected a duration after `until`".to_owned(),
                    Some("use `<n><unit>` with unit s, m, h, or d, e.g. `until 300s`".to_owned()),
                );
                return None;
            };
            self.pos += 1;
            match parse_short_duration_seconds(&value) {
                Some(seconds) if seconds > 0 => ttl_seconds = Some(seconds),
                _ => {
                    self.error(
                        span,
                        format!("invalid ttl duration `{value}`"),
                        Some("use `<n><unit>` with unit s, m, h, or d".to_owned()),
                    );
                    return None;
                }
            }
        }
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        if binding.is_none() {
            let span = self.span_from(start);
            self.error(
                span,
                "`renew` requires an `as` binding".to_owned(),
                Some(
                    "branch on it with `after <binding> renewed` and `after <binding> notHeld`"
                        .to_owned(),
                ),
            );
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::LeaseRenew {
                acquire_binding,
                ttl_seconds,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    /// `append <Schema> { fields } to <ledger> [as x]` (spec/coordination.md).
    fn parse_ledger_append(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // append
        let schema = self.ident_text("entry schema after `append`")?;
        let fields = self.parse_field_block(false)?;
        if !self.consume_ident("to") {
            let span = self.span_here();
            self.error(
                span,
                "expected `to <ledger>` after the entry payload".to_owned(),
                Some("write `append Decision { ... } to decisions`".to_owned()),
            );
            return None;
        }
        let ledger = self.ident_text("ledger name after `to`")?;
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::LedgerAppend {
                ledger,
                schema,
                fields,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    fn looks_like_counter_consume(&self) -> bool {
        matches!(self.peek_at(1).map(|t| &t.tok), Some(Tok::Ident(_)))
            && matches!(self.peek_at(2).map(|t| &t.tok), Some(Tok::Ident(word)) if word == "for")
    }

    /// `consume <counter> for <key-expr> amount <expr> as <binding>`: one
    /// atomic consume with branchable `ok`/`over` outcomes
    /// (spec/coordination.md).
    fn parse_counter_consume(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // consume
        let counter = self.ident_text("counter name after `consume`")?;
        if !self.consume_ident("for") {
            let span = self.span_here();
            self.error(
                span,
                "expected `for <key>` after the counter name".to_owned(),
                Some(
                    "write `consume model_budget for t.customer amount t.estTokens as spend`"
                        .to_owned(),
                ),
            );
            return None;
        }
        let key_expr = self.dotted_path_text("counter key expression")?;
        if !self.consume_ident("amount") {
            let span = self.span_here();
            self.error(
                span,
                "expected `amount <expr>` after the counter key".to_owned(),
                Some(
                    "write `consume model_budget for t.customer amount t.estTokens as spend`"
                        .to_owned(),
                ),
            );
            return None;
        }
        let amount_expr = match self.peek().map(|t| t.tok.clone()) {
            Some(Tok::Number(value)) => {
                self.pos += 1;
                value
            }
            Some(Tok::Ident(_)) => self.dotted_path_text("consume amount")?,
            _ => {
                let span = self.span_here();
                self.error(
                    span,
                    "expected a number or path after `amount`".to_owned(),
                    None,
                );
                return None;
            }
        };
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        if binding.is_none() {
            let span = self.span_from(start);
            self.error(
                span,
                "`consume` requires an `as` binding".to_owned(),
                Some(
                    "branch on it with `after <binding> ok` and `after <binding> over`".to_owned(),
                ),
            );
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::CounterConsume {
                counter,
                key_expr,
                amount_expr,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    /// `emit signal <dotted.name> to <instance-expr> { payload }`.
    fn parse_emit_signal(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // emit
                       // `emit milestone "<name>" [of <PayloadClass>] { fields }` (Family C): a
                       // synchronous milestone projection, distinct from the directed
                       // `emit signal ... to ...` effect.
        if self.at_ident("milestone") {
            return self.parse_emit_milestone(start);
        }
        if !self.consume_ident("signal") {
            let span = self.span_here();
            self.error(
                span,
                "the bare `emit <name>` statement was removed from the language; \
                 `emit` must be followed by `signal` or `milestone`"
                    .to_owned(),
                Some("write `emit signal deploy.finished to peer.id { ... }`".to_owned()),
            );
            return None;
        }
        let event = self.dotted_path_text("signal name after `signal`")?;
        if !self.consume_ident("to") {
            let span = self.span_here();
            self.error(
                span,
                "expected `to <target>` after the signal name".to_owned(),
                Some("write `emit signal deploy.finished to peer.id { ... }`".to_owned()),
            );
            return None;
        }
        let target_expr = self.dotted_path_text("target instance after `to`")?;
        // S6: optional `from <binding>` projection (the `record … from`
        // precedent) — shorthand fields become allowed inside the block.
        let from = if self.consume_ident("from") {
            Some(self.ident_text("binding name after `from`")?)
        } else {
            None
        };
        let fields = if from.is_some() && !self.at_sym('{') {
            Vec::new()
        } else {
            self.parse_field_block(from.is_some())?
        };
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::Notify {
                target_expr,
                event,
                from,
                fields,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    /// `emit milestone "<name>" [of <PayloadClass>] { fields }` (Family C). The
    /// caller has consumed `emit`; `self` is positioned at the `milestone`
    /// keyword. `start` is the `emit` token index for span tracking.
    fn parse_emit_milestone(&mut self, start: usize) -> Option<BodyStmt> {
        self.pos += 1; // milestone
        let Some(Tok::Str(name)) = self.peek().map(|t| t.tok.clone()) else {
            let span = self.span_here();
            self.error(
                span,
                "expected a quoted milestone name after `milestone`".to_owned(),
                Some(
                    "write `emit milestone \"canary_live\" of CanaryInfo { region \"us\" }`"
                        .to_owned(),
                ),
            );
            return None;
        };
        self.pos += 1;
        // `of <PayloadClass>` is optional: a bare milestone carries no payload
        // and the parent observes it with `after p reaches "<name>"` (no `as`).
        let payload_class = if self.consume_ident("of") {
            Some(self.ident_text("payload class after `of`")?)
        } else {
            None
        };
        let fields = if matches!(self.peek().map(|t| &t.tok), Some(Tok::Sym('{'))) {
            self.parse_field_block(false)?
        } else {
            Vec::new()
        };
        Some(BodyStmt::Milestone {
            name,
            payload_class,
            fields,
            span: self.span_from(start),
        })
    }

    /// A possibly-dotted identifier path, returned as source text.
    fn dotted_path_text(&mut self, label: &str) -> Option<String> {
        let mut text = self.ident_text(label)?;
        while matches!(self.peek().map(|t| &t.tok), Some(Tok::Sym('.'))) {
            self.pos += 1;
            let Some(Tok::Ident(segment)) = self.peek().map(|t| t.tok.clone()) else {
                break;
            };
            text.push('.');
            text.push_str(&segment);
            self.pos += 1;
        }
        Some(text)
    }

    fn parse_exec(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // exec
        let target = match self.advance().map(|t| t.tok) {
            Some(Tok::Str(value)) => ExecTarget::RawCommand(value),
            Some(Tok::Ident(name)) => {
                if !self.at_ident("with") {
                    let span = self.span_here();
                    self.error(
                        span,
                        "expected `with <binding>` after exec capability name".to_owned(),
                        Some(format!(
                            "write `exec {name} with input -> Report as result`"
                        )),
                    );
                    return None;
                }
                self.pos += 1; // with
                let Some(Tok::Ident(stdin_binding)) = self.peek().map(|t| t.tok.clone()) else {
                    let span = self.span_here();
                    self.error(
                        span,
                        "expected a record binding after `with`".to_owned(),
                        Some(format!(
                            "write `exec {name} with input -> Report as result`"
                        )),
                    );
                    return None;
                };
                self.pos += 1;
                ExecTarget::Capability {
                    name,
                    stdin_binding,
                }
            }
            _ => {
                let span = self.span_here();
                self.error(
                    span,
                    "expected a command string or capability name after `exec`".to_owned(),
                    Some(
                        "write `exec \"scripts/run-tests.sh\" as tests` or `exec backup_repo with input -> Report as result`"
                            .to_owned(),
                    ),
                );
                return None;
            }
        };
        // `-> Schema` / `-> each Schema`: typed stdout ingestion
        // (spec/json-ingestion.md).
        let mut parse_target = None;
        if matches!(self.peek().map(|t| &t.tok), Some(Tok::Arrow)) {
            self.pos += 1; // ->
            let each = if self.at_ident("each") {
                self.pos += 1;
                true
            } else {
                false
            };
            let Some(Tok::Ident(schema)) = self.peek().map(|t| t.tok.clone()) else {
                let span = self.span_here();
                self.error(
                    span,
                    "expected a schema name after `->`".to_owned(),
                    Some(
                        "write `exec \"report.sh\" -> Report as x` or `exec \"list.sh\" -> each WorkItem`"
                            .to_owned(),
                    ),
                );
                return None;
            };
            self.pos += 1;
            parse_target = Some(ExecParse { schema, each });
        }
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        match &parse_target {
            Some(parse) if parse.each && binding.is_some() => {
                let span = self.span_from(start);
                self.error(
                    span,
                    "`-> each` produces a stream of facts, not a single binding".to_owned(),
                    Some("drop the `as` binding and react with `when <Schema> as item`".to_owned()),
                );
            }
            Some(parse) if !parse.each && binding.is_none() => {
                let span = self.span_from(start);
                self.error(
                    span,
                    "`->` without `each` parses one value and needs an `as` binding".to_owned(),
                    Some("write `exec \"report.sh\" -> Report as x` and read it with `after x succeeds as r`".to_owned()),
                );
            }
            _ => {}
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::Exec {
                target,
                parse_target,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    // -- tracker verbs ---------------------------------------------------------

    fn parse_tracker_file(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // file
        if !self.consume_ident("issue") {
            let span = self.span_here();
            self.error(
                span,
                "expected `issue` after `file`",
                Some("write `file issue into <tracker> { ... }`".to_owned()),
            );
            return None;
        }
        if !self.consume_ident("into") {
            let span = self.span_here();
            self.error(span, "expected `into <tracker>` after `file issue`", None);
            return None;
        }
        let queue = self.ident_text("tracker name")?;
        let fields = self.parse_field_block(false)?;
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::TrackerFile { queue, fields },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    fn parse_tracker_claim(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // claim
        let item = self.ident_text("issue binding after `claim`")?;
        if self.at_ident("with") {
            let span = self.span_here();
            self.error(
                span,
                "`claim <issue> with ...` is not supported".to_owned(),
                Some("declare a `tracker` and write `claim <issue> [ttl <dur>] [as x]`".to_owned()),
            );
            self.pos += 1;
            let _ = self.advance();
        }
        // `ttl <duration>`: the claim-TTL clause (spec/std-tracker.md, T3). It
        // takes a duration value, e.g. `claim issue ttl 30m as c`.
        let mut ttl_seconds = None;
        if self.at_ident("ttl") {
            self.pos += 1; // ttl
            let span = self.span_here();
            let Some(Tok::Number(value)) = self.peek().map(|t| t.tok.clone()) else {
                self.error(
                    span,
                    "expected a duration after `ttl`".to_owned(),
                    Some("use `<n><unit>` with unit s, m, h, or d, e.g. `ttl 30m`".to_owned()),
                );
                return None;
            };
            self.pos += 1;
            match parse_short_duration_seconds(&value) {
                Some(seconds) if seconds > 0 => ttl_seconds = Some(seconds),
                _ => {
                    self.error(
                        span,
                        format!("invalid ttl duration `{value}`"),
                        Some("use `<n><unit>` with unit s, m, h, or d".to_owned()),
                    );
                    return None;
                }
            }
        }
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        // The trailing `endorsed` source marker (DR-0051 §2); must come last,
        // exactly as on a `coerce`.
        let endorsed = self.consume_ident("endorsed");
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::TrackerClaim {
                item,
                ttl_seconds,
                endorsed,
            },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    fn parse_tracker_release(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // release
        let item = self.ident_text("issue binding after `release`")?;
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::TrackerRelease { item },
            binding: None,
            requires: Vec::new(),
            timeout_seconds: None,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    fn parse_tracker_finish(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // finish
        let item = self.ident_text("issue binding after `finish`")?;
        let fields = if self.at_sym('{') {
            self.parse_field_block(false)?
        } else {
            Vec::new()
        };
        // `as <binding>` after the payload — required for `then x <- finish
        // item { … }`, whose desugar re-serializes the finish with a synthetic
        // handle and observes it with `after`.
        let mut binding = None;
        let mut requires = Vec::new();
        let mut timeout_seconds = None;
        if !self.parse_effect_modifiers(&mut binding, &mut requires, &mut timeout_seconds) {
            return None;
        }
        Some(BodyStmt::Effect(EffectStmt {
            kind: BodyEffectKind::TrackerFinish { item, fields },
            binding,
            requires,
            timeout_seconds,
            prompt: None,
            span: self.span_from(start),
        }))
    }

    // -- blocks --------------------------------------------------------------

    /// `during <cond> { … } on lapse [as x] { … }` / `until <cond> { … }`
    /// (DR-0043 Decision 5). The arm is mandatory; the parser accepts the arm
    /// on the region's closing line (`}} on lapse {{`) or on its own line —
    /// tokens carry no line structure.
    fn parse_region(&mut self, until: bool) -> Option<BodyStmt> {
        let start = self.pos;
        let keyword = if until { "until" } else { "during" };
        self.pos += 1;
        let cond_start = self.pos;
        while self.pos < self.tokens.len() && !self.at_sym('{') {
            self.pos += 1;
        }
        if !self.at_sym('{') {
            let span = self.span_here();
            self.error(
                span,
                format!("expected `{{` to open the `{keyword}` region"),
                Some(format!(
                    "write `{keyword} <condition> {{ … }} on lapse {{ … }}`"
                )),
            );
            return None;
        }
        let condition = if self.pos > cond_start {
            let from = self.tokens[cond_start].start;
            let to = self.tokens[self.pos - 1].end;
            self.source[from..to].trim().to_owned()
        } else {
            String::new()
        };
        if condition.is_empty() {
            let span = self.span_from(start);
            self.error(
                span,
                format!("`{keyword}` requires a condition"),
                Some("the condition is a pure query expression, like a guard".to_owned()),
            );
            return None;
        }
        let body_open = self.pos;
        self.pos += 1; // {
        let body_content_start = self
            .tokens
            .get(self.pos)
            .map(|token| self.base + token.start)
            .unwrap_or_else(|| self.base + self.tokens[body_open].end);
        let body = self.parse_statements(true);
        // parse_statements consumed the closing `}` (token before self.pos).
        let body_content_end = self
            .tokens
            .get(self.pos.saturating_sub(1))
            .map(|token| self.base + token.start)
            .unwrap_or(body_content_start);
        let body_span = SourceSpan {
            start: body_content_start,
            end: body_content_end,
        };
        if !(self.consume_ident("on") && self.consume_ident("lapse")) {
            let span = self.span_here();
            self.error(
                span,
                format!("a `{keyword}` region requires its `on lapse {{ … }}` arm"),
                Some(
                    "a reactive condition with no declared consequence would lapse silently; \
                     write `on lapse { … }` (optionally `on lapse as <view> { … }`)"
                        .to_owned(),
                ),
            );
            return None;
        }
        let lapse_binding = if self.consume_ident("as") {
            Some(self.ident_text("progress-view binding after `as`")?)
        } else {
            None
        };
        if !self.consume_sym('{') {
            let span = self.span_here();
            self.error(span, "expected `{` to open the `on lapse` arm", None);
            return None;
        }
        let lapse_open = self.pos - 1;
        let lapse_content_start = self
            .tokens
            .get(self.pos)
            .map(|token| self.base + token.start)
            .unwrap_or_else(|| self.base + self.tokens[lapse_open].end);
        let lapse_body = self.parse_statements(true);
        let lapse_content_end = self
            .tokens
            .get(self.pos.saturating_sub(1))
            .map(|token| self.base + token.start)
            .unwrap_or(lapse_content_start);
        Some(BodyStmt::Region(RegionBlock {
            until,
            condition,
            body,
            lapse_binding,
            lapse_body,
            body_span,
            lapse_span: SourceSpan {
                start: lapse_content_start,
                end: lapse_content_end,
            },
            span: self.span_from(start),
        }))
    }

    fn parse_after(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // after
        let binding = self.ident_text("effect binding after `after`")?;
        let mut milestone = None;
        let predicate = match self.advance().map(|t| t.tok) {
            Some(Tok::Ident(word)) => match word.as_str() {
                "succeeds" => AfterPredicate::Succeeds,
                "fails" => AfterPredicate::Fails,
                "completes" => AfterPredicate::Completes,
                "cancelled" => AfterPredicate::Cancelled,
                // `after p reaches "<name>" as m` (Family C): the next token is a
                // string literal naming the child milestone being observed. The
                // name is stashed on `AfterBlock.milestone`.
                "reaches" => {
                    let Some(Tok::Str(name)) = self.peek().map(|t| t.tok.clone()) else {
                        let span = self.span_here();
                        self.error(
                            span,
                            "expected a quoted milestone name after `reaches`".to_owned(),
                            Some("write `after p reaches \"canary_live\" as m { ... }`".to_owned()),
                        );
                        return None;
                    };
                    self.pos += 1;
                    milestone = Some(name);
                    AfterPredicate::Reaches
                }
                // `times out` is the two-token spelling of the `TimedOut`
                // terminal status (spec/expression-kernel.md).
                "times" => {
                    if !self.consume_ident("out") {
                        let span = self.span_here();
                        self.error(span, "expected `out` after `times`", None);
                        return None;
                    }
                    AfterPredicate::TimedOut
                }
                "held" => AfterPredicate::Held,
                "contended" => AfterPredicate::Contended,
                "ok" => AfterPredicate::Ok,
                "over" => AfterPredicate::Over,
                "promoted" => AfterPredicate::Promoted,
                "conflicted" => AfterPredicate::Conflicted,
                "applied" => AfterPredicate::Applied,
                "stranded" => AfterPredicate::Stranded,
                other => {
                    let span = self.span_from(start);
                    self.error(
                        span,
                        format!("unsupported `after` predicate `{other}`"),
                        Some(
                            "use `succeeds`, `fails`, `completes`, `times out`, `cancelled`, or a coordination outcome (`held`, `contended`, `ok`, `over`)"
                                .to_owned(),
                        ),
                    );
                    return None;
                }
            },
            _ => {
                let span = self.span_here();
                self.error(
                    span,
                    "expected `succeeds`, `fails`, `completes`, `times out`, or `cancelled`",
                    None,
                );
                return None;
            }
        };
        let alias = if self.consume_ident("as") {
            Some(self.ident_text("alias after `as`")?)
        } else {
            None
        };
        if !self.consume_sym('{') {
            let span = self.span_here();
            self.error(span, "expected `{` to open the `after` block", None);
            return None;
        }
        let body = self.parse_statements(true);
        Some(BodyStmt::After(AfterBlock {
            binding,
            predicate,
            alias,
            milestone,
            body,
            span: self.span_from(start),
        }))
    }

    fn parse_case(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        self.pos += 1; // case
        let scrutinee = self.ident_text("case scrutinee path")?;
        if !self.consume_sym('{') {
            let span = self.span_here();
            self.error(span, "expected `{` to open the `case` block", None);
            return None;
        }
        let mut branches = Vec::new();
        loop {
            if self.consume_sym('}') {
                break;
            }
            if self.peek().is_none() {
                let span = self.span_here();
                self.error(span, "unclosed `case` block", Some("add `}`".to_owned()));
                break;
            }
            let branch_start = self.pos;
            let pattern = match self.advance().map(|t| t.tok) {
                Some(Tok::Ident(value)) => value,
                Some(Tok::Str(value)) => format!("{value:?}"),
                _ => {
                    let span = self.span_here();
                    self.error(span, "expected a case pattern", None);
                    self.recover();
                    continue;
                }
            };
            let binding = match self.peek().map(|t| t.tok.clone()) {
                // `Variant as binding` (sum types, spec/sum-types.md) — `as`
                // is how every other binding in the language is introduced.
                Some(Tok::Ident(value)) if value == "as" => {
                    self.pos += 1;
                    match self.peek().map(|t| t.tok.clone()) {
                        Some(Tok::Ident(name)) => {
                            self.pos += 1;
                            Some(name)
                        }
                        _ => {
                            let span = self.span_here();
                            self.error(
                                span,
                                "expected a binding name after `as`".to_owned(),
                                Some("write `Variant as payload => { ... }`".to_owned()),
                            );
                            None
                        }
                    }
                }
                Some(Tok::Ident(value)) if value != "where" => {
                    self.pos += 1;
                    Some(value)
                }
                _ => None,
            };
            let guard = if self.consume_ident("where") {
                let guard_start = self.pos;
                // Consume guard tokens up to `=>`.
                while self.peek().is_some()
                    && !matches!(self.peek().map(|t| &t.tok), Some(Tok::FatArrow))
                {
                    self.pos += 1;
                }
                let first = self.tokens.get(guard_start);
                let last = self.tokens.get(self.pos.saturating_sub(1));
                match (first, last) {
                    (Some(first), Some(last)) if guard_start < self.pos => {
                        Some(self.source[first.start..last.end].to_owned())
                    }
                    _ => None,
                }
            } else {
                None
            };
            if !matches!(self.advance().map(|t| t.tok), Some(Tok::FatArrow)) {
                let span = self.span_here();
                self.error(span, "expected `=>` after case pattern", None);
                self.recover();
                continue;
            }
            if !self.consume_sym('{') {
                let span = self.span_here();
                self.error(span, "expected `{` to open the case branch", None);
                self.recover();
                continue;
            }
            let body = self.parse_statements(true);
            branches.push(CaseBranch {
                pattern,
                binding,
                guard,
                body,
                span: self.span_from(branch_start),
            });
        }
        Some(BodyStmt::Case(CaseBlock {
            scrutinee,
            branches,
            span: self.span_from(start),
        }))
    }

    fn parse_terminal(&mut self) -> Option<BodyStmt> {
        let start = self.pos;
        let keyword = match self.advance()?.tok {
            Tok::Ident(value) => value,
            _ => return None,
        };
        let kind = if keyword == "complete" {
            TerminalKind::Complete
        } else {
            TerminalKind::Fail
        };
        let name = self.ident_text("terminal contract name")?;
        // `complete <T> from <binding> { … }`: bounded-type projection. Only valid on
        // `complete` (a failure carries an explicit payload). Shorthand fields in the
        // block copy the source binding's same-named fields, as in `record … from`.
        let from = if kind == TerminalKind::Complete && self.consume_ident("from") {
            Some(self.ident_text("binding name after `from`")?)
        } else {
            None
        };
        // A field block (`complete result { … }`) is the class-shaped form; a bare
        // value (`complete result 0.9`) is the scalar form. `from` always projects
        // fields, so it requires a block.
        let (fields, scalar) =
            if from.is_none() && !matches!(self.peek().map(|t| &t.tok), Some(Tok::Sym('{'))) {
                let (source, expr) = self.parse_value_expression()?;
                (Vec::new(), Some(FieldValue::Expr { source, expr }))
            } else {
                (self.parse_field_block(from.is_some())?, None)
            };
        Some(BodyStmt::Terminal(TerminalStmt {
            kind,
            name,
            from,
            fields,
            scalar,
            span: self.span_from(start),
        }))
    }
}

const STATEMENT_KEYWORDS: &[&str] = &[
    "record", "done", "consume", "tell", "coerce", "prompt", "claim", "release", "renew", "finish",
    "file", "call", "recall", "send", "invoke", "read", "write", "import", "export", "after",
    "case", "complete", "fail", "timer", "cancel", "decide", "exec", "when", "on", "else", "then",
    "redact",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(source: &str) -> BodyAst {
        let (ast, diagnostics) = parse_rule_body(source, 0);
        assert!(diagnostics.is_empty(), "diagnostics: {diagnostics:?}");
        ast
    }

    #[test]
    fn full_line_comments_tokenize_as_nothing() {
        let ast = parse_ok(
            "# leading comment\nrecord Done {\n  note \"x\"\n}\n  # indented comment with braces { } and \"quotes\"\n// slash comments match the top-level lexer\ndone item\n",
        );
        assert_eq!(ast.statements.len(), 2, "comments contribute no statements");
    }

    #[test]
    fn trailing_hash_still_errors() {
        let (_, diagnostics) = parse_rule_body("done item # trailing\n", 0);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("unexpected character `#`")),
            "trailing comments stay illegal: {diagnostics:?}"
        );
    }

    #[test]
    fn blank_full_line_comments_is_byte_preserving_and_fence_aware() {
        let text = "  # a comment\n  tell a as t \"\"\"markdown\n  # heading is content\n  \"\"\"\n  # after fence\n";
        let blanked = blank_full_line_comments(text);
        assert_eq!(blanked.len(), text.len(), "byte length preserved");
        assert!(!blanked.contains("# a comment"));
        assert!(!blanked.contains("# after fence"));
        assert!(
            blanked.contains("# heading is content"),
            "fence interior untouched: {blanked}"
        );
    }

    #[test]
    fn generated_effect_operation_grammar_covers_the_std_constructs() {
        // Drift canary for the build.rs codegen: the table generated from the
        // embedded std manifests (std/manifests/*.json) must contain exactly
        // the seven shipped effect_operation keywords with their target
        // capabilities. A manifest edit that adds, drops, or retargets a
        // keyword shows up here before it shows up in parse behavior.
        let table = EFFECT_OPERATION_GRAMMAR
            .iter()
            .map(|spec| (spec.keyword, spec.target_capability))
            .collect::<Vec<_>>();
        assert_eq!(
            table,
            vec![
                ("recall", "memory.query"),
                ("learn", "memory.write"),
                ("curate", "memory.curate"),
                ("send", "messaging.send"),
                ("promote", "vcs.promote"),
                ("undo", "vcs.undo"),
                ("transport", "vcs.transport"),
            ]
        );
    }

    #[test]
    fn parses_redact_projection() {
        let ast = parse_ok("redact customer keep [id, status] as safe");
        let BodyStmt::Redact {
            source,
            keep,
            binding,
            ..
        } = &ast.statements[0]
        else {
            panic!("expected redact, got {:?}", ast.statements[0]);
        };
        assert_eq!(source, "customer");
        assert_eq!(keep, &["id".to_owned(), "status".to_owned()]);
        assert_eq!(binding, "safe");
    }

    #[test]
    fn parses_complete_from_projection() {
        let ast = parse_ok("complete result from cust {\n  id\n  status\n}");
        let BodyStmt::Terminal(terminal) = &ast.statements[0] else {
            panic!("expected terminal, got {:?}", ast.statements[0]);
        };
        assert_eq!(terminal.kind, TerminalKind::Complete);
        assert_eq!(terminal.name, "result");
        assert_eq!(terminal.from.as_deref(), Some("cust"));
        assert_eq!(terminal.fields.len(), 2);
        assert!(terminal
            .fields
            .iter()
            .all(|f| matches!(f.value, FieldValue::Shorthand)));
    }

    #[test]
    fn rejects_redact_keeping_nothing() {
        let (_, diagnostics) = parse_rule_body("redact customer keep [] as safe", 0);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("keep at least one field")),
            "expected empty-keep rejection, got {diagnostics:?}"
        );
    }

    #[test]
    fn parses_single_line_record_fields() {
        let ast = parse_ok(r#"record Item { id "a" status "done" }"#);
        let BodyStmt::Record(record) = &ast.statements[0] else {
            panic!("expected record");
        };
        assert_eq!(record.schema, "Item");
        assert_eq!(record.fields.len(), 2);
        assert_eq!(record.fields[0].name, "id");
        assert_eq!(record.fields[1].name, "status");
    }

    #[test]
    fn parses_multi_line_record_with_expressions() {
        let ast = parse_ok(
            "record Job {\n  id job.id\n  attempts job.attempts + 1\n  status \"pending\"\n}",
        );
        let BodyStmt::Record(record) = &ast.statements[0] else {
            panic!("expected record");
        };
        assert_eq!(record.fields[1].name, "attempts");
        let FieldValue::Expr { source, .. } = &record.fields[1].value else {
            panic!("expected expression value");
        };
        assert_eq!(source, "job.attempts + 1");
    }

    #[test]
    fn parses_done_with_replacement() {
        let ast = parse_ok("done task -> record Done {\n  id task.id\n}");
        let BodyStmt::Done {
            binding,
            replacement,
            ..
        } = &ast.statements[0]
        else {
            panic!("expected done");
        };
        assert_eq!(binding, "task");
        assert!(replacement.is_some());
    }

    #[test]
    fn consume_done_alias_is_removed() {
        // The bare `consume <binding>` alias for `done` was removed; it now
        // errors with a migration hint rather than parsing as a done terminal.
        let (ast, diagnostics) = parse_rule_body("consume task", 0);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("`consume` was removed")),
            "expected a removed-alias diagnostic, got {diagnostics:?}"
        );
        assert!(
            !matches!(ast.statements.first(), Some(BodyStmt::Done { .. })),
            "removed alias must not parse as a done terminal"
        );
    }

    #[test]
    fn counter_consume_verb_still_parses() {
        // The live counter verb `consume <counter> for ...` is unaffected.
        let ast = parse_ok("consume budget for t.id amount 1 as spend");
        assert!(
            matches!(
                ast.statements.first(),
                Some(BodyStmt::Effect(EffectStmt {
                    kind: BodyEffectKind::CounterConsume { .. },
                    ..
                }))
            ),
            "counter consume must still parse, got {:?}",
            ast.statements.first()
        );
    }

    #[test]
    fn parses_tell_with_modifiers_and_prompt() {
        let ast = parse_ok(
            "tell worker requires [\"agent.tell\"] as turn timeout 10m \"\"\"markdown\nDo it.\n\"\"\"",
        );
        let BodyStmt::Effect(effect) = &ast.statements[0] else {
            panic!("expected effect");
        };
        assert_eq!(effect.binding.as_deref(), Some("turn"));
        assert_eq!(effect.requires, vec!["agent.tell".to_owned()]);
        assert_eq!(effect.timeout_seconds, Some(600));
        let prompt = effect.prompt.as_ref().expect("prompt");
        assert_eq!(prompt.content_type.as_deref(), Some("markdown"));
        assert_eq!(prompt.text, "Do it.");
    }

    #[test]
    fn parses_prompt_effect() {
        let ast = parse_ok(
            "prompt \"\"\"markdown\nSummarize this.\n\"\"\" using fixture requires [\"model.invoke\"] as answer timeout 10m",
        );
        let BodyStmt::Effect(effect) = &ast.statements[0] else {
            panic!("expected effect");
        };
        let BodyEffectKind::Prompt { provider } = &effect.kind else {
            panic!("expected prompt");
        };
        assert_eq!(provider.as_deref(), Some("fixture"));
        assert_eq!(effect.binding.as_deref(), Some("answer"));
        assert_eq!(effect.requires, vec!["model.invoke".to_owned()]);
        assert_eq!(effect.timeout_seconds, Some(600));
        let prompt = effect.prompt.as_ref().expect("prompt");
        assert_eq!(prompt.content_type.as_deref(), Some("markdown"));
        assert_eq!(prompt.text, "Summarize this.");
    }

    #[test]
    fn parses_tell_with_access_grants() {
        let ast = parse_ok(
            "tell coder as turn\n  with access to project_memory {\n    recall for issue\n    learn for issue\n  }\n  with access to project_files {\n    read [\"docs/**\"]\n  }\n\"Work the issue.\"",
        );
        let BodyStmt::Effect(effect) = &ast.statements[0] else {
            panic!("expected effect");
        };
        let BodyEffectKind::Tell {
            target,
            access_grants,
            ..
        } = &effect.kind
        else {
            panic!("expected tell");
        };
        assert_eq!(target, "coder");
        assert_eq!(effect.binding.as_deref(), Some("turn"));
        assert_eq!(access_grants.len(), 2);

        let memory = &access_grants[0];
        assert_eq!(memory.resource, "project_memory");
        assert_eq!(memory.operations.len(), 2);
        assert_eq!(memory.operations[0].operation, "recall");
        assert_eq!(memory.operations[0].target.as_deref(), Some("issue"));
        assert_eq!(memory.operations[1].operation, "learn");

        let files = &access_grants[1];
        assert_eq!(files.resource, "project_files");
        assert_eq!(files.operations.len(), 1);
        assert_eq!(files.operations[0].operation, "read");
        assert_eq!(files.operations[0].globs, vec!["docs/**".to_owned()]);
    }

    #[test]
    fn reports_unsupported_with_context_modifier() {
        let (_, diagnostics) = parse_rule_body("tell coder with context memory \"go\"", 0);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("not supported yet")),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn parses_tell_with_turn_scoped_skills() {
        // `with skills [...]` interleaves with `with access to` around the prompt.
        let ast = parse_ok(
            "tell coder as turn\n  with skills [\"review\", \"lint\"]\n  with access to project_files {\n    read [\"src/**\"]\n  }\n\"Work it.\"",
        );
        let BodyStmt::Effect(effect) = &ast.statements[0] else {
            panic!("expected effect");
        };
        let BodyEffectKind::Tell {
            skills,
            access_grants,
            ..
        } = &effect.kind
        else {
            panic!("expected tell");
        };
        assert_eq!(skills, &vec!["review".to_owned(), "lint".to_owned()]);
        assert_eq!(
            access_grants.len(),
            1,
            "access grant still parsed alongside"
        );

        // `invoke ... with skills` is NOT accepted (skills are tell-scoped).
        let (_, diagnostics) = parse_rule_body("invoke Build { x task.x } with skills [\"a\"]", 0);
        assert!(
            !diagnostics.is_empty(),
            "invoke must reject a turn-scoped skills pin"
        );
    }

    #[test]
    fn rejects_unknown_statement() {
        let (_, diagnostics) = parse_rule_body("frobnicate task", 0);
        assert!(diagnostics.iter().any(|d| d
            .message
            .contains("unknown rule body statement `frobnicate`")));
    }

    #[test]
    fn parses_emit_signal() {
        let ast = parse_ok(
            "emit signal deploy.finished to peer.id {\n  service deployed.service\n  status deployed.status\n} as sent",
        );
        let BodyStmt::Effect(effect) = &ast.statements[0] else {
            panic!("expected effect");
        };
        assert_eq!(effect.binding.as_deref(), Some("sent"));
        let BodyEffectKind::Notify {
            target_expr,
            event,
            fields,
            ..
        } = &effect.kind
        else {
            panic!("expected signal delivery effect");
        };
        assert_eq!(target_expr, "peer.id");
        assert_eq!(event, "deploy.finished");
        assert_eq!(fields.len(), 2);
    }

    #[test]
    fn rejects_emit_without_signal_delivery_shape() {
        let (_, diagnostics) = parse_rule_body("emit event.name", 0);
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("was removed from the language")));
    }

    #[test]
    fn parses_nested_after_blocks() {
        let ast = parse_ok(
            "tell worker as turn \"go\"\n\nafter turn succeeds as done {\n  coerce review(done.summary) as verdict\n\n  after verdict succeeds as v {\n    record Out {\n      ok v.ok\n    }\n  }\n}",
        );
        assert_eq!(ast.statements.len(), 2);
        let BodyStmt::After(after) = &ast.statements[1] else {
            panic!("expected after");
        };
        assert_eq!(after.predicate, AfterPredicate::Succeeds);
        assert_eq!(after.alias.as_deref(), Some("done"));
        assert!(matches!(after.body[1], BodyStmt::After(_)));
    }

    #[test]
    fn parses_after_times_out_branch() {
        let ast = parse_ok(
            "exec \"report.sh\" -> Report as job\n\nafter job times out as t {\n  cancel job\n}",
        );
        let BodyStmt::After(after) = &ast.statements[1] else {
            panic!("expected after");
        };
        assert_eq!(after.predicate, AfterPredicate::TimedOut);
        assert_eq!(after.predicate.as_str(), "times out");
        assert_eq!(after.alias.as_deref(), Some("t"));
    }

    #[test]
    fn parses_after_cancelled_branch() {
        let ast = parse_ok(
            "exec \"report.sh\" -> Report as job\n\nafter job cancelled as c {\n  cancel job\n}",
        );
        let BodyStmt::After(after) = &ast.statements[1] else {
            panic!("expected after");
        };
        assert_eq!(after.predicate, AfterPredicate::Cancelled);
        assert_eq!(after.predicate.as_str(), "cancelled");
        assert_eq!(after.alias.as_deref(), Some("c"));
    }

    #[test]
    fn rejects_times_without_out() {
        let (_, diagnostics) = parse_rule_body("after job times { cancel job }", 0);
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("expected `out` after `times`")));
    }

    #[test]
    fn rejects_unknown_after_predicate() {
        let (_, diagnostics) = parse_rule_body("after job explodes { cancel job }", 0);
        assert!(diagnostics.iter().any(|d| d
            .message
            .contains("unsupported `after` predicate `explodes`")));
    }

    #[test]
    fn parses_timer_and_cancel() {
        let ast =
            parse_ok("timer 24h as deadline\n\nafter deadline succeeds {\n  cancel signoff\n}");
        let BodyStmt::Effect(effect) = &ast.statements[0] else {
            panic!("expected timer effect");
        };
        assert!(matches!(
            effect.kind,
            BodyEffectKind::Timer {
                duration_seconds: 86400,
                ..
            }
        ));
        let BodyStmt::After(after) = &ast.statements[1] else {
            panic!("expected after");
        };
        assert!(matches!(after.body[0], BodyStmt::Cancel { .. }));
    }

    #[test]
    fn parses_decide_with_result_shape() {
        let ast = parse_ok("decide \"Fixed?\" -> { fixed bool, reason string } as verdict");
        let BodyStmt::Effect(effect) = &ast.statements[0] else {
            panic!("expected effect");
        };
        let BodyEffectKind::Decide { result_fields } = &effect.kind else {
            panic!("expected decide");
        };
        assert_eq!(result_fields.len(), 2);
        assert_eq!(effect.binding.as_deref(), Some("verdict"));
    }

    #[test]
    fn parses_tracker_verbs() {
        let ast = parse_ok(
            "file issue into backlog {\n  title \"Fix login\"\n  body \"Repro...\"\n}\n\nclaim item as lease\nrelease item\nfinish item {\n  summary turn.summary\n}",
        );
        assert_eq!(ast.statements.len(), 4);
        assert!(matches!(
            &ast.statements[0],
            BodyStmt::Effect(EffectStmt { kind: BodyEffectKind::TrackerFile { queue, .. }, .. }) if queue == "backlog"
        ));
        assert!(matches!(
            &ast.statements[1],
            BodyStmt::Effect(EffectStmt { kind: BodyEffectKind::TrackerClaim { .. }, binding: Some(b), .. }) if b == "lease"
        ));
    }

    #[test]
    fn parses_exec() {
        let ast = parse_ok("exec \"scripts/run-tests.sh\" as tests timeout 5m");
        let BodyStmt::Effect(effect) = &ast.statements[0] else {
            panic!("expected effect");
        };
        assert!(matches!(&effect.kind, BodyEffectKind::Exec {
                target: ExecTarget::RawCommand(command),
                ..
            } if command == "scripts/run-tests.sh"));
        assert_eq!(effect.timeout_seconds, Some(300));
    }

    #[test]
    fn parses_coerce_endorsed_marker() {
        // the trailing `endorsed` source marker (I-IFC3) sets the flag.
        let ast = parse_ok("coerce classify(msg.content) as verdict endorsed");
        let BodyStmt::Effect(effect) = &ast.statements[0] else {
            panic!("expected effect");
        };
        assert!(matches!(
            &effect.kind,
            BodyEffectKind::Coerce { name, endorsed: true, .. } if name == "classify"
        ));
        // without the marker, the flag is false.
        let plain = parse_ok("coerce classify(msg.content) as verdict");
        let BodyStmt::Effect(effect) = &plain.statements[0] else {
            panic!("expected effect");
        };
        assert!(matches!(
            &effect.kind,
            BodyEffectKind::Coerce {
                endorsed: false,
                declassified: false,
                ..
            }
        ));
        // `declassified` sets its flag; both markers may appear together.
        let both = parse_ok("coerce classify(msg.content) as verdict endorsed declassified");
        let BodyStmt::Effect(effect) = &both.statements[0] else {
            panic!("expected effect");
        };
        assert!(matches!(
            &effect.kind,
            BodyEffectKind::Coerce {
                endorsed: true,
                declassified: true,
                ..
            }
        ));
    }

    #[test]
    fn parses_exec_capability() {
        let ast = parse_ok("exec backup_repo with request -> Report as result");
        let BodyStmt::Effect(effect) = &ast.statements[0] else {
            panic!("expected effect");
        };
        assert!(matches!(&effect.kind, BodyEffectKind::Exec {
            target: ExecTarget::Capability { name, stdin_binding },
            parse_target: Some(ExecParse { schema, each: false }),
        } if name == "backup_repo" && stdin_binding == "request" && schema == "Report"));
        assert_eq!(effect.binding.as_deref(), Some("result"));
    }

    #[test]
    fn parses_case_with_branches() {
        let ast = parse_ok(
            "after turn completes {\n  case turn {\n    Completed as done => {\n      record Ok {\n        summary done.summary\n      }\n    }\n    Failed as failure => {\n      record Bad {\n        reason failure.reason\n      }\n    }\n  }\n}",
        );
        let BodyStmt::After(after) = &ast.statements[0] else {
            panic!("expected after");
        };
        let BodyStmt::Case(case) = &after.body[0] else {
            panic!("expected case");
        };
        assert_eq!(case.branches.len(), 2);
        assert_eq!(case.branches[0].pattern, "Completed");
        assert_eq!(case.branches[0].binding.as_deref(), Some("done"));
    }

    #[test]
    fn rule_mode_rejects_flow_statements() {
        let (_, diagnostics) = parse_rule_body("on fails {\n  cancel x\n}", 0);
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("not rule body statements")));
    }

    #[test]
    fn unknown_effect_modifier_is_rejected_with_span() {
        let (_, diagnostics) = parse_rule_body("tell worker as turn frobnicate \"go\"", 0);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("expected a prompt string")),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn from_block_supports_shorthand_and_overrides() {
        let ast = parse_ok(
            "done task -> record ReviewedPoem from task {\n  provider poet\n  language\n  topic\n  turn poemTurn\n  status \"reviewed\"\n}",
        );
        let BodyStmt::Done {
            replacement: Some(record),
            ..
        } = &ast.statements[0]
        else {
            panic!("expected replacement record");
        };
        assert_eq!(record.from.as_deref(), Some("task"));
        let names: Vec<_> = record.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["provider", "language", "topic", "turn", "status"]
        );
        assert!(matches!(record.fields[1].value, FieldValue::Shorthand));
        assert!(matches!(record.fields[3].value, FieldValue::Expr { .. }));
    }

    #[test]
    fn invoke_with_nested_payload() {
        let ast = parse_ok(
            "invoke ReviewPhase {\n  phase PhaseReviewRequest {\n    id phase.id\n    title phase.title\n  }\n} as review",
        );
        let BodyStmt::Effect(effect) = &ast.statements[0] else {
            panic!("expected effect");
        };
        let BodyEffectKind::Invoke {
            workflow, payload, ..
        } = &effect.kind
        else {
            panic!("expected invoke");
        };
        assert_eq!(workflow, "ReviewPhase");
        assert!(matches!(payload[0].value, FieldValue::Nested { .. }));
    }

    #[test]
    fn parses_invoke_with_access_grants() {
        let ast = parse_ok(
            "invoke Child {\n  task Task { id ticket.id }\n}\n  with access to project_files {\n    read [\"docs/**\"]\n  }\n  as child",
        );
        let BodyStmt::Effect(effect) = &ast.statements[0] else {
            panic!("expected effect");
        };
        let BodyEffectKind::Invoke {
            workflow,
            payload,
            access_grants,
        } = &effect.kind
        else {
            panic!("expected invoke");
        };
        assert_eq!(workflow, "Child");
        assert_eq!(effect.binding.as_deref(), Some("child"));
        assert!(matches!(payload[0].value, FieldValue::Nested { .. }));
        assert_eq!(access_grants.len(), 1);
        assert_eq!(access_grants[0].resource, "project_files");
        assert_eq!(access_grants[0].operations[0].operation, "read");
        assert_eq!(
            access_grants[0].operations[0].globs,
            vec!["docs/**".to_owned()]
        );
    }

    #[test]
    fn parses_invoke_with_resource_less_access_grant_shorthand() {
        let ast = parse_ok(
            "invoke Child {\n  task Task { id ticket.id }\n}\n  with access to {\n    project_memory {\n      recall for ticket\n    }\n    project_files {\n      read [\"docs/**\"]\n    }\n  }\n  as child",
        );
        let BodyStmt::Effect(effect) = &ast.statements[0] else {
            panic!("expected effect");
        };
        let BodyEffectKind::Invoke { access_grants, .. } = &effect.kind else {
            panic!("expected invoke");
        };
        assert_eq!(effect.binding.as_deref(), Some("child"));
        assert_eq!(access_grants.len(), 2);

        let memory = &access_grants[0];
        assert_eq!(memory.resource, "project_memory");
        assert_eq!(memory.operations[0].operation, "recall");
        assert_eq!(memory.operations[0].target.as_deref(), Some("ticket"));

        let files = &access_grants[1];
        assert_eq!(files.resource, "project_files");
        assert_eq!(files.operations[0].operation, "read");
        assert_eq!(files.operations[0].globs, vec!["docs/**".to_owned()]);
    }

    #[test]
    fn rejects_empty_resource_less_access_grant_shorthand() {
        let (_, diagnostics) = parse_rule_body(
            "invoke Child { task task }\n  with access to {\n  }\n  as child",
            0,
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("grants no resources")),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn single_line_terminal_payload_parses() {
        let ast = parse_ok("complete result { total 2 }");
        let BodyStmt::Terminal(terminal) = &ast.statements[0] else {
            panic!("expected terminal");
        };
        assert_eq!(terminal.fields.len(), 1);
        assert_eq!(terminal.fields[0].name, "total");
    }

    #[test]
    fn spans_are_absolute() {
        let (ast, _) = parse_rule_body("record Item {\n  id \"a\"\n}", 100);
        let BodyStmt::Record(record) = &ast.statements[0] else {
            panic!("expected record");
        };
        assert_eq!(record.span.start, 100);
        assert!(record.span.end > 100);
    }
}
