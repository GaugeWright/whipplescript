//! Source parser for `.whip` programs.
//!
//! The v0 grammar is still stabilizing, so this crate uses a small
//! hand-written parser. It preserves source spans and keeps rule/effect bodies
//! as source text until the typed IR is ready to lower them.

mod action_expand;
mod canonical;
pub use canonical::{canonical_declarations, canonical_program_hash, DeclCanon};
pub mod body;
mod body_print;
mod format;
mod lowering;
use format::*;
pub use format::{format_program, format_program_preserving_comments, FormatOutput};
use lowering::*;
mod syntax;
// The lexer/parser front end moved out whole; these three were public API
// before the move and are re-exported so the crate's surface is unchanged.
use syntax::*;
pub use syntax::{lex_comments, parse_program, parser_stage, string_and_comment_spans};
mod then_expand;

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};
use whipplescript_core::{
    ContractRegistry, EffectContract, LibraryRegistration, TypedOutputValidation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
}

impl SourceSpan {
    fn join(self, other: Self) -> Self {
        Self {
            start: self.start,
            end: other.end,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub span: SourceSpan,
    pub message: String,
    pub suggestion: Option<String>,
    /// Secondary spans carrying supporting context (spec/error-handling.md "Spans
    /// And Labels"): a `note`-style related-information label pointing at a
    /// definition, prior claim, or other related site. Empty for most
    /// diagnostics; surfaced in CLI text, JSON reports, and LSP
    /// `relatedInformation`.
    pub related: Vec<RelatedInfo>,
}

/// A secondary span + short label attached to a [`Diagnostic`] as related
/// information (never a top-level diagnostic of its own).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedInfo {
    pub span: SourceSpan,
    pub message: String,
}

impl Diagnostic {
    /// Attaches a related-information label at `span` (builder style, so the
    /// common no-related case stays a plain struct literal that only needs the
    /// new field defaulted).
    pub fn with_related(mut self, span: SourceSpan, message: impl Into<String>) -> Self {
        self.related.push(RelatedInfo {
            span,
            message: message.into(),
        });
        self
    }
}

/// The marker that introduced a comment, preserved so a formatter can re-emit it
/// faithfully.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommentMarker {
    /// `# …`
    Hash,
    /// `// …`
    Slash,
}

/// A source comment captured by the lexer. Comments are kept out of the token
/// stream (so the parser is unaffected) but retained here so tooling — `whip fmt`,
/// the LSP — can preserve them. `text` is the trimmed content after the marker;
/// `span` covers the marker through end of line (exclusive of the newline).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Comment {
    pub marker: CommentMarker,
    pub text: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ident {
    pub name: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StringLiteral {
    pub value: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Program {
    pub workflow: Option<Ident>,
    pub workflow_tags: Vec<TagDecl>,
    pub workflow_description: Option<StringLiteral>,
    pub explicit_workflow_body: bool,
    pub workflows: Vec<WorkflowDecl>,
    pub patterns: Vec<PatternDecl>,
    pub items: Vec<Item>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowDecl {
    pub name: Ident,
    pub tags: Vec<TagDecl>,
    pub description: Option<StringLiteral>,
    pub items: Vec<Item>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Item {
    Include(IncludeDecl),
    Use(UseDecl),
    Pattern(PatternDecl),
    Apply(ApplyDecl),
    WorkflowContract(WorkflowContractDecl),
    Harness(HarnessDecl),
    Tracker(TrackerDecl),
    Channel(ChannelDecl),
    Credential(CredentialDecl),
    Stream(StreamDecl),
    Gauge(GaugeDecl),
    Mark(MarkDecl),
    Campaign(CampaignDecl),
    FileStore(FileStoreDecl),
    MemoryPool(MemoryPoolDecl),
    Action(ActionDecl),
    Agent(AgentDecl),
    Enum(EnumDecl),
    Event(EventDecl),
    // Boxed: SourceDecl carries the ingress path/url/emit surface and is by far
    // the largest Item variant; boxing keeps the enum small (clippy large_enum_variant).
    Source(Box<SourceDecl>),
    Test(TestDecl),
    Lease(LeaseDecl),
    Ledger(LedgerDecl),
    Counter(CounterDecl),
    Class(ClassDecl),
    Table(TableDecl),
    Coerce(CoerceDecl),
    Assert(AssertDecl),
    Rule(RuleDecl),
}

impl Item {
    /// Source span of this top-level item, used to interleave preserved comments.
    fn span(&self) -> SourceSpan {
        match self {
            Self::Include(decl) => decl.path.span,
            Self::Use(decl) => decl.name.span,
            Self::Pattern(decl) => decl.span,
            Self::Apply(decl) => decl.span,
            Self::WorkflowContract(decl) => decl.span,
            Self::Harness(decl) => decl.span,
            Self::Tracker(decl) => decl.span,
            Self::Channel(decl) => decl.span,
            Self::Credential(decl) => decl.span,
            Self::Stream(decl) => decl.span,
            Self::Gauge(decl) => decl.span,
            Self::Mark(decl) => decl.span,
            Self::Campaign(decl) => decl.span,
            Self::FileStore(decl) => decl.span,
            Self::MemoryPool(decl) => decl.span,
            Self::Action(decl) => decl.span,
            Self::Agent(decl) => decl.span,
            Self::Enum(decl) => decl.span,
            Self::Event(decl) => decl.span,
            Self::Source(decl) => decl.span,
            Self::Test(decl) => decl.span,
            Self::Lease(decl) => decl.span,
            Self::Ledger(decl) => decl.span,
            Self::Counter(decl) => decl.span,
            Self::Class(decl) => decl.span,
            Self::Table(decl) => decl.span,
            Self::Coerce(decl) => decl.span,
            Self::Assert(decl) => decl.span,
            Self::Rule(decl) => decl.span,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatternDecl {
    pub name: Ident,
    pub type_params: Vec<Ident>,
    pub items: Vec<Item>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyDecl {
    pub pattern: Ident,
    pub type_args: Vec<TypeSyntax>,
    pub alias: Ident,
    pub body: BlockSource,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncludeDecl {
    pub path: StringLiteral,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowContractDecl {
    pub kind: WorkflowContractKind,
    pub name: Ident,
    pub ty: TypeSyntax,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowContractKind {
    Input,
    Output,
    Failure,
}

impl WorkflowContractKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
            Self::Failure => "failure",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssertDecl {
    pub tags: Vec<TagDecl>,
    pub description: Option<StringLiteral>,
    pub expr: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagDecl {
    pub name: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UseDecl {
    pub name: StringLiteral,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarnessDecl {
    pub name: Ident,
    pub kind: Ident,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackerDecl {
    pub name: Ident,
    pub provider: Ident,
    pub span: SourceSpan,
}

/// `channel <name> { provider <p> [workspace <w>] [destination "<d>"] }`
/// (std.messaging): a named communication route through a provider. The bare
/// `channel` construct shape is reserved by the platform for `std.messaging`
/// (spec/messaging.md), so third-party packages cannot author channel-like
/// semantics with weaker guarantees. Lowers to a `metadata_only` declaration
/// (like `queue`); the runtime messaging provider is later-stage work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelDecl {
    pub name: Ident,
    pub provider: Ident,
    pub workspace: Option<Ident>,
    pub destination: Option<StringLiteral>,
    pub span: SourceSpan,
}

/// `credential <name> { kind <kind> }` (std.custody; DR-0053 §5): a bare
/// handle naming a custodian entry — governance supplies reality via
/// `grant credential … -> credential:<addr>`, and material never appears in
/// source. `kind` exists so the checker can statically reject an operation
/// the credential cannot perform (`sign … with` a `bearer`); the custodian's
/// registered kind is authoritative and mismatch is a check error. Kinds are
/// spelled with underscores in source (`hmac_sha256`) and normalize to the
/// protocol's kebab-case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialDecl {
    pub name: Ident,
    pub kind: Ident,
    pub span: SourceSpan,
}

/// `stream <name> { members [<agent>, ...] [staleness <duration>] }`
/// (std.vcs; DR-0052 Decision 5): a declared collaboration — a named
/// shared line whose member agents' session lines home to it, syncing
/// greedily in-stream and promoting to mainline through one gated
/// boundary. Members are agent declarations (every session of that
/// agent homes here); `staleness` is the §7.1 bound. Metadata-only
/// lowering, like `queue`/`channel`; the runtime workstream tier is the
/// enforcement seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamDecl {
    pub name: Ident,
    pub members: Vec<Ident>,
    pub staleness_seconds: Option<u64>,
    pub span: SourceSpan,
}

/// `mark "<name>" after <site>` (experimentation subsystem §4.2): a named
/// cut point. The runtime stamps a `mark.reached` event when the named
/// site commits on any run, so every run's meaningful moments are
/// addressable — `whip pin <run> at <mark>` freezes the prefix as a
/// scenario, and regeneration replays that prefix and re-executes only
/// the suffix. Names are stable across edits (event offsets shift, marks
/// don't). Deliberately a separate declaration from `milestone`
/// (child→parent lifecycle signaling vs. event-log position).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarkDecl {
    pub name: StringLiteral,
    /// The committing site the cut rides: a rule name (dotted for
    /// flow-generated segments).
    pub site: String,
    pub site_span: SourceSpan,
    pub span: SourceSpan,
}

/// `gauge <name> [on <site>] { judge via ... [expect ...] [inputs ...] }`
/// (experimentation subsystem §4.2): a named quality dimension — a site, a
/// judge, optionally a bar. The sibling of `test`: deterministic expectation
/// vs. stochastic expectation, one family. Core grammar (hand-parsed): the
/// `judge via` tagged union and the bar form are outside the declaration
/// family's shape. Bars use the word forms `at least` / `at most` because
/// the declaration tokenizer deliberately steps over `>=`/`<=` (the same
/// reason field presence conditions use `is`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GaugeDecl {
    pub name: Ident,
    /// Optional `on <dotted.site>` designation. v1 records it (identity and
    /// forward-compat with site-scoped judging); ambient scoring judges the
    /// run's terminal view.
    pub site: Option<String>,
    pub site_span: Option<SourceSpan>,
    pub judge: GaugeJudge,
    pub expect: Option<GaugeBar>,
    /// Derived gauges: other gauges whose scores feed this gauge's exec
    /// judge (`inputs a, b`). Deterministic composition — the settled cure
    /// for composite objectives (no weights feature, ever).
    pub inputs: Vec<GaugeRef>,
    pub span: SourceSpan,
}

/// The generalized judge slot: `judge via coerce <Name>(<args>) |
/// prompt "<t>" | exec "<cmd>" | labels "<source>"`. Coerce judges carry
/// EXPLICIT argument paths (settled 2026-07-14): each names the record
/// value feeding the parameter (`input.ticket.title`,
/// `facts.Assessment.priority`), or the single reserved `record` passes
/// the whole judge-input record — the binding is written down and
/// versioned, never inferred.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GaugeJudge {
    Coerce(Ident, Vec<String>),
    Prompt(StringLiteral),
    Exec(StringLiteral),
    Labels(StringLiteral),
}

/// An optional bar: the default decision bar for settle/campaign gates.
/// `expect P(<field>) at least 0.9` (chance-shaped) or
/// `expect p10 at least 0.7` / `expect mean at most 800` (stat-shaped).
/// Thresholds keep their exact source text (`Eq`-safe, format-exact);
/// consumers parse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GaugeBar {
    pub subject: GaugeBarSubject,
    /// `true` = `at least`, `false` = `at most`.
    pub at_least: bool,
    pub threshold: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GaugeBarSubject {
    /// `P(<field>)`: probability the judge's boolean output field holds.
    Chance { field: Ident },
    /// A named statistic of the score distribution: `mean`, `p10`, `p90`, …
    Stat { stat: Ident },
}

/// A (possibly dotted) gauge reference: user gauges are bare idents, the
/// built-in resource gauges are namespaced (`std.spend` / `std.latency` /
/// `std.tokens`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GaugeRef {
    pub name: String,
    pub span: SourceSpan,
}

/// `campaign <name> { ascend … [reach …] [guard …] [sacrifice …] }`
/// (improve design note §3): versioned, diffable objective intent at higher
/// ceremony than a CLI invocation — the partition of the gauge vector.
/// Unnamed gauges are guarded by default; `guard` widens a band, `sacrifice`
/// releases a gauge, `reach` sets a target that becomes a hard bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignDecl {
    pub name: Ident,
    pub ascend: Vec<GaugeRef>,
    pub reach: Vec<CampaignReach>,
    pub guard: Vec<CampaignGuard>,
    pub sacrifice: Vec<GaugeRef>,
    /// `proposer redacted`: campaign-attached stratified reflection — the
    /// proposer sees aggregates only, never scenario contents (leakage
    /// policy, improve note §7; settled 2026-07-11).
    pub proposer_redacted: bool,
    pub span: SourceSpan,
}

/// `reach <gauge> at least 0.9` / `reach std.latency at most 800ms`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignReach {
    pub gauge: GaugeRef,
    pub at_least: bool,
    pub threshold: String,
    /// Optional trailing unit ident (`ms`, `s`); recorded verbatim.
    pub unit: Option<String>,
    pub span: SourceSpan,
}

/// `guard <gauge> within 2 percent`: an indifference-band override.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignGuard {
    pub gauge: GaugeRef,
    pub band_percent: String,
    pub span: SourceSpan,
}

/// `file store <name> { root "<dir>" }` (std.files): a capability-scoped file
/// store identity with a literal root directory. v0 is a local storage boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileStoreDecl {
    pub name: Ident,
    pub root: String,
    pub read_globs: Vec<String>,
    pub write_globs: Vec<String>,
    /// Optional `provider <name>` clause (std.files v1, spec/std-files.md
    /// "Surface"): the store's backing provider, defaulting to `local` when
    /// absent. Unknown providers are rejected at check time.
    pub provider: Option<Ident>,
    /// Source spans of each clause keyword (`root` / the `allow` of read / write),
    /// so `whip fmt` can interleave own-line and trailing body comments by position
    /// (the body otherwise rebuilds from the AST, dropping comments).
    pub root_span: Option<SourceSpan>,
    pub read_span: Option<SourceSpan>,
    pub write_span: Option<SourceSpan>,
    pub provider_span: Option<SourceSpan>,
    pub span: SourceSpan,
}

/// `memory pool <name> { context limit <n> }` (std.memory, MEM-1): a named
/// durable memory place. Mirrors `file store` as a `declaration_block` /
/// `metadata_only` construct providing `Resource<MemoryPool>`. v1 pools are
/// provider-less; `context limit <n>` (optional, non-negative) is the recall
/// packing budget. Unknown clauses are rejected (file-store precedent).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryPoolDecl {
    pub name: Ident,
    pub context_limit: Option<u64>,
    /// Source span of the `context` clause keyword, so `whip fmt` can interleave
    /// body comments by position (file-store precedent).
    pub context_limit_span: Option<SourceSpan>,
    pub span: SourceSpan,
}

/// One typed parameter of an `action` template (DR-0023).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionParam {
    pub name: Ident,
    pub ty: TypeSyntax,
    pub span: SourceSpan,
}

/// `action <name>(<param: type>, …) { <effect chain> }` (DR-0023): a static,
/// hygienic, inline-expanded template over rule-body effect chains. Consumed by
/// `expand_action_calls` before lowering; never a runtime construct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionDecl {
    pub name: Ident,
    pub params: Vec<ActionParam>,
    pub body: BlockSource,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentDecl {
    pub name: Ident,
    pub harness: Option<Ident>,
    /// `agent Foo delegated to <provider>` (DR-0034 Decision 2): the surface
    /// spelling of a Delegated agent. Names the foreign provider kind directly;
    /// `agent Foo { … }` without it is Managed by default.
    pub delegated_to: Option<Ident>,
    pub fields: Vec<AgentField>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentField {
    Provider(Ident),
    Profile(StringLiteral),
    Capacity(u32, SourceSpan),
    Skills(Vec<StringLiteral>, SourceSpan),
    Capabilities(Vec<StringLiteral>, SourceSpan),
    /// `requires [session.resume, turn.cancel]`: portable feature-class
    /// requirements (DR-0015 taxonomy; spec/std-agent.md slice 6). Entries are
    /// dotted feature-class names, validated for taxonomy membership at
    /// lowering and against the provider's feature report by the CLI.
    Requires(Vec<Ident>, SourceSpan),
    /// `tools [Foo, Bar]`: the workflows this agent may invoke as typed tools
    /// (DR-0025). Entries are workflow names resolved against the program/packages.
    Tools(Vec<Ident>, SourceSpan),
    /// `compaction <strategy>`: the owned-harness conversation-compaction strategy
    /// (context-assembly Phase 5). One of `summarize`, `hard_reset`, `tool_results`,
    /// `none`.
    Compaction(Ident),
    /// `thread <mode>`: owned-harness conversation continuation across tells
    /// (the chat-shaped instance v1). `continue` seeds each
    /// new tell from the agent's latest completed-turn transcript in this
    /// instance; `fresh` (the default) starts every tell from scratch.
    Thread(Ident),
    /// `settings <sources>`: which ambient-config sources a Delegated harness may
    /// read when assembling its own context (DR-0034 Decision 4). One of `project`,
    /// `user`, `none`. Unset means the provider's own default.
    Settings(Ident),
    Unknown {
        name: Ident,
        span: SourceSpan,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumDecl {
    pub name: Ident,
    pub variants: Vec<EnumVariantDecl>,
    pub span: SourceSpan,
}

/// One enum variant: bare (`Accept`) or data-carrying with a brace body that
/// reuses the class field grammar (sum types, spec/sum-types.md).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumVariantDecl {
    pub name: Ident,
    pub fields: Vec<ClassField>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassDecl {
    pub name: Ident,
    pub fields: Vec<ClassField>,
    pub span: SourceSpan,
}

/// Coordination resources (spec/coordination.md): a closed family of shared,
/// workspace-scoped resources with typed keys, atomic branchable operations,
/// and mandatory bounds (`ttl`/`retain`/`cap`+`reset`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseDecl {
    pub name: Ident,
    pub key_type: Ident,
    pub slots: u32,
    pub ttl_seconds: u64,
    pub shared: bool,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerDecl {
    pub name: Ident,
    pub entry_schema: Ident,
    pub partition_field: Ident,
    pub retain_seconds: u64,
    pub shared: bool,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterDecl {
    pub name: Ident,
    pub key_type: Ident,
    pub cap: i64,
    pub reset: String,
    /// IANA timezone anchoring the reset-period boundary (std.coord slice 3);
    /// `None` anchors to UTC and draws a default-UTC warning.
    pub timezone: Option<String>,
    pub shared: bool,
    pub span: SourceSpan,
}

/// A typed external-signal declaration (`signal deploy.finished { ... }`):
/// the ingress manifest naming a dotted event and its payload schema
/// (spec/event-ingress.md).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDecl {
    /// Dotted lowercase signal name (`deploy.finished`).
    pub name: String,
    pub name_span: SourceSpan,
    pub fields: Vec<ClassField>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassField {
    pub name: Ident,
    pub ty: TypeSyntax,
    /// `@key`: this field is the class's natural key (used for import per-row
    /// idempotency, spec/std-library/files.md). At most one per class in v0.
    pub is_key: bool,
    /// Family B (discriminant-string schemas): `<field> <Type> when <disc> == "<lit>"`
    /// — this field is present only when the literal-union discriminant field `disc`
    /// equals `lit`. `(discriminant field name, required literal)`.
    pub presence_condition: Option<(String, String)>,
    pub span: SourceSpan,
}

/// A top-level source declaration: `source <provider> as <name> { ... }` or
/// `source clock as <name> { ... }`. Lowers through the `source_declaration`
/// construct family to a `signal_source` (generic provider) or `clock_source`
/// (the `clock` provider) admission template (spec/std-time.md,
/// spec/construct-grammar.md). A source admits a durable signal fact; it never
/// fires a rule directly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceDecl {
    /// `as <name>` — the source instance name.
    pub name: Ident,
    /// The provider keyword (`clock`) or a generic provider identifier.
    pub provider: Ident,
    /// Recurrence/timezone/missed policy; `Some` only for the `clock` provider.
    pub clock: Option<ClockPolicy>,
    /// `path "<file>"` — `file` provider, line mode (exactly one of
    /// `path`/`watch`); rejected elsewhere. The file is read line-by-line; each
    /// non-empty line is admitted once as a durable signal fact
    /// (spec/std-time.md admission semantics, append-only).
    pub path: Option<StringLiteral>,
    /// `watch "<glob>"` — `file` provider, occurrence mode (exactly one of
    /// `path`/`watch`); rejected elsewhere (spec/std-ingress.md I2a). Each
    /// matched file is admitted once per new (path, content-hash) occurrence:
    /// a dropped file admits once, an unchanged file never re-admits, a
    /// content change re-admits. Content READING stays std.files.
    pub watch: Option<StringLiteral>,
    /// `url "<url>"` — required for the `http` provider, rejected elsewhere. The
    /// URL is GET'd and its JSON-array body admitted one element per signal,
    /// keyed by (source, element index) so re-polls are idempotent (append-only).
    pub url: Option<StringLiteral>,
    /// `dedup <observe>.<field>` — optional provider delivery-id source for
    /// `file` (line mode) and `http` sources (spec/std-ingress.md I2a): the
    /// named observation field becomes the admission key instead of the
    /// positional ordinal, so a re-ordered or head-inserted feed still admits
    /// each delivery exactly once.
    pub dedup: Option<SourceValue>,
    /// `observe as <binding>` — binds the provider observation schema.
    pub observe_binding: Ident,
    /// `emit <signal> { <field> <value> ... }` — maps the observation into the
    /// declared signal payload.
    pub emit: SourceEmit,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockPolicy {
    pub recurrence: Recurrence,
    pub timezone: Option<StringLiteral>,
    pub missed: Option<MissedPolicy>,
    pub span: SourceSpan,
}

/// Recurrence forms from spec/std-time.md (conservative first surface).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Recurrence {
    /// `at <hh:mm>` — a single scheduled occurrence.
    At { time: TimeOfDay, span: SourceSpan },
    /// `every <duration>` — interval occurrences.
    EveryDuration {
        seconds: u64,
        source: String,
        span: SourceSpan,
    },
    /// `every <calendar-pattern> at <hh:mm>` — calendar occurrences.
    EveryCalendar {
        pattern: CalendarPattern,
        time: TimeOfDay,
        span: SourceSpan,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalendarPattern {
    Day,
    Weekday,
    Weekly(Weekday),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeOfDay {
    pub hour: u8,
    pub minute: u8,
    pub span: SourceSpan,
}

/// Missed-occurrence policy from spec/std-time.md. No silent default: a recurring
/// source must declare one (enforced by the checker).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissedPolicy {
    Skip,
    Coalesce,
    CatchUp { limit: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceEmit {
    /// Dotted lowercase signal name materialized by this source.
    pub signal: String,
    pub signal_span: SourceSpan,
    /// S6: `emit <signal> from <binding> [{ overrides }]` — copy the
    /// observation's same-named fields, bounded to the signal's declared
    /// fields, with the block overriding (the `record … from` semantics).
    pub from: Option<Ident>,
    pub fields: Vec<SourceEmitField>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceEmitField {
    pub name: Ident,
    pub value: SourceValue,
    pub span: SourceSpan,
}

/// A value mapped into an emitted signal field: an observation path
/// (`tick.scheduled_at`) or a literal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceValue {
    Path {
        binding: Ident,
        segments: Vec<Ident>,
        span: SourceSpan,
    },
    String(StringLiteral),
    Number(String, SourceSpan),
}

/// A deterministic test scenario (spec/workflow-testing.md). Validated by
/// `whip check`; excluded from compile/run IR; executed by `whip test`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestDecl {
    pub name: StringLiteral,
    /// Optional `workflow <Name>` header binding the scenario to one workflow
    /// in a multi-workflow bundle (spec/workflow-testing.md). Single-workflow
    /// files may omit it and bind implicitly.
    pub workflow: Option<Ident>,
    pub clauses: Vec<TestClause>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TestClause {
    Given(GivenClause),
    Stub(StubClause),
    Run(RunClause),
    Expect(ExpectClause),
}

/// A `<field> <expr>` mapping inside a `given` record body. `value` is the source
/// text of the expression (parsed via `parse_expression` when validated), matching
/// how guards and assertions capture expressions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestField {
    pub name: Ident,
    pub value: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GivenClause {
    Input {
        fields: Vec<TestField>,
        span: SourceSpan,
    },
    Fact {
        ty: Ident,
        fields: Vec<TestField>,
        span: SourceSpan,
    },
    Signal {
        name: String,
        fields: Vec<TestField>,
        span: SourceSpan,
    },
    Clock {
        at: StringLiteral,
        span: SourceSpan,
    },
    Tracker {
        tracker: String,
        fields: Vec<TestField>,
        span: SourceSpan,
    },
    /// `given file <store> at <path> "<content>"` seeds a fixture file in the
    /// named `file store` so a `read` during `whip test` resolves deterministic
    /// content (the harness redirects the store root to a temp dir).
    File {
        store: String,
        path: StringLiteral,
        content: StringLiteral,
        span: SourceSpan,
    },
}

/// `stub <surface…> <outcome> [record | string]`. The surface path and outcome
/// are kept as tokens; provider-specific validation happens in the harness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StubClause {
    /// Surface path segments (each may be dotted, e.g. `script.run`); the trailing
    /// segment is the outcome.
    pub surface: Vec<String>,
    pub outcome: String,
    pub payload: Option<StubPayload>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StubPayload {
    Record(Vec<TestField>),
    Message(StringLiteral),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunClause {
    pub kind: RunKind,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunKind {
    UntilIdle,
    UntilWorkflowCompleted,
    UntilWorkflowFailed,
    ForSteps(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectClause {
    pub target: ExpectTarget,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpectTarget {
    WorkflowCompleted,
    WorkflowFailed { failure: Option<Ident> },
    Rule { name: Ident, status: RuleStatus },
    Effect { name: String, status: EffectStatus },
    Diagnostic { code: String },
    NoEffect { name: String },
    Projection(ProjQuery),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuleStatus {
    Fired,
    FiredTimes(u32),
    DidNotFire,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectStatus {
    Requested,
    Completed,
    Failed,
}

/// A projection query: `<noun> exists | count <predicate> is <N> | where <predicate>`.
/// The predicate reuses the guard expression kernel, restricted to projection
/// fields. The noun is a dotted fact name, so a scenario can assert over runtime
/// facts such as `agent.turn.completed` as well as single-identifier user facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjQuery {
    pub noun: String,
    pub kind: ProjQueryKind,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjQueryKind {
    Exists,
    Count { predicate: String, count: u32 },
    Where { predicate: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableDecl {
    pub name: Ident,
    pub tags: Vec<TagDecl>,
    pub description: Option<StringLiteral>,
    pub schema: Ident,
    pub rows: Vec<TableRow>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableRow {
    pub body: BlockSource,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoerceDecl {
    pub name: Ident,
    pub params: Vec<ParamDecl>,
    pub output: TypeSyntax,
    pub body: BlockSource,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParamDecl {
    pub name: Ident,
    pub ty: TypeSyntax,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypeSyntax {
    Primitive {
        name: String,
        span: SourceSpan,
    },
    LiteralString {
        value: String,
        span: SourceSpan,
    },
    Ref {
        name: Ident,
    },
    AgentRef {
        agents: Vec<Ident>,
        span: SourceSpan,
    },
    Optional {
        inner: Box<TypeSyntax>,
        span: SourceSpan,
    },
    Array {
        inner: Box<TypeSyntax>,
        span: SourceSpan,
    },
    Map {
        inner: Box<TypeSyntax>,
        span: SourceSpan,
    },
    /// DR-0074 §10: `sealed<T>`. Spelled after `map<string>`, an existing
    /// lowercase built-in constructor with an angle-bracketed argument.
    Sealed {
        inner: Box<TypeSyntax>,
        span: SourceSpan,
    },
    /// DR-0053 §15: `secret` or `secret<ed25519>`.
    ///
    /// A DISCRIMINANT rather than a type parameter — the argument ranges over
    /// the protocol's closed `CredentialKind` set, which is `Finite`'s shape
    /// rather than `Map`'s. `None` is the bare spelling and means "any kind";
    /// it stays valid, so there is no source break.
    ///
    /// Kinds are spelled with underscores in source (`hmac_sha256`) because
    /// the lexer reads one identifier, and normalize to the protocol's
    /// kebab-case — the same convention `credential … { kind … }` already
    /// uses.
    Secret {
        kind: Option<Ident>,
        span: SourceSpan,
    },
    Union {
        variants: Vec<TypeSyntax>,
        span: SourceSpan,
    },
}

impl TypeSyntax {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Primitive { span, .. }
            | Self::LiteralString { span, .. }
            | Self::Optional { span, .. }
            | Self::Array { span, .. }
            | Self::Map { span, .. }
            | Self::Sealed { span, .. }
            | Self::Secret { span, .. }
            | Self::Union { span, .. }
            | Self::AgentRef { span, .. } => *span,
            Self::Ref { name } => name.span,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleDecl {
    pub name: Ident,
    pub tags: Vec<TagDecl>,
    pub description: Option<StringLiteral>,
    pub whens: Vec<WhenClause>,
    pub body: BlockSource,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WhenClause {
    pub text: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockSource {
    pub text: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseOutput {
    pub program: Program,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompileOutput {
    pub ir: Option<IrProgram>,
    pub diagnostics: Vec<Diagnostic>,
    /// Non-fatal diagnostics (deprecations, style); never block compilation.
    pub warnings: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrProgram {
    pub workflow: String,
    pub source_tags: Vec<IrSourceTag>,
    pub source_descriptions: Vec<IrSourceDescription>,
    pub includes: Vec<IrInclude>,
    pub pattern_applications: Vec<IrPatternApplication>,
    pub workflow_contracts: Vec<IrWorkflowContract>,
    pub uses: Vec<IrUse>,
    pub harnesses: Vec<IrHarness>,
    pub trackers: Vec<IrTracker>,
    pub streams: Vec<IrStream>,
    pub channels: Vec<IrChannel>,
    pub credentials: Vec<IrCredential>,
    pub gauges: Vec<IrGauge>,
    pub marks: Vec<IrMark>,
    pub campaigns: Vec<IrCampaign>,
    pub file_stores: Vec<IrFileStore>,
    pub memory_pools: Vec<IrMemoryPool>,
    pub events: Vec<IrEvent>,
    pub sources: Vec<IrSource>,
    pub tests: Vec<IrTest>,
    pub leases: Vec<IrLease>,
    pub ledgers: Vec<IrLedger>,
    pub counters: Vec<IrCounter>,
    pub shared_coordination_usage: Vec<IrSharedCoordinationUsage>,
    pub schemas: Vec<IrSchema>,
    pub agents: Vec<IrAgent>,
    pub coerces: Vec<IrCoerce>,
    pub assertions: Vec<IrAssertion>,
    pub rules: Vec<IrRule>,
    pub rule_dependencies: Vec<IrRuleDependency>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrSharedCoordinationUsage {
    pub resource: String,
    pub workflow_principals: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrSourceTag {
    pub name: String,
    pub target_kind: String,
    pub target: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrSourceDescription {
    pub value: String,
    pub target_kind: String,
    pub target: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrPatternApplication {
    pub pattern: String,
    pub alias: String,
    pub type_args: Vec<IrType>,
    pub value_args: Vec<IrPatternArgument>,
    pub generated: Vec<String>,
    /// Source span of the `pattern <Name> { ... }` DEFINITION this application
    /// expanded, so provenance can point back at where the reused shape lives.
    pub definition_span: SourceSpan,
    /// Source span of the `apply <Name> as <alias> { ... }` APPLICATION site.
    pub application_span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrPatternArgument {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrWorkflowContract {
    pub kind: IrWorkflowContractKind,
    pub name: String,
    pub ty: IrType,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IrWorkflowContractKind {
    Input,
    Output,
    Failure,
}

impl IrWorkflowContractKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
            Self::Failure => "failure",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrInclude {
    pub path: String,
    pub source_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrAssertion {
    pub expr: IrExpression,
    pub projection_reads: Vec<IrProjectionRead>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrExpression {
    pub source: String,
    pub expr: Expr,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrUse {
    pub kind: IrUseKind,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IrUseKind {
    Package,
}

/// One lowered `stream` declaration (std.vcs): the workstream tier's
/// declared membership + staleness bound. Runtime homing reads this.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrStream {
    pub name: String,
    pub members: Vec<String>,
    pub member_spans: Vec<SourceSpan>,
    pub staleness_seconds: Option<u64>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrTracker {
    pub name: String,
    pub provider: String,
    pub span: SourceSpan,
}

/// A lowered `channel` declaration (std.messaging): the channel identity, its
/// provider, and optional workspace/destination config. Lowering class is
/// `metadata_only`; the runtime messaging provider consumes it later.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrChannel {
    pub name: String,
    pub provider: String,
    pub workspace: Option<String>,
    pub destination: Option<String>,
    pub span: SourceSpan,
}

/// A lowered `credential` declaration (DR-0053 §5): a handle plus its
/// declared kind, normalized to the custody protocol's kebab-case. Metadata
/// only — reality (material, sealing rung, grants) lives with the custodian
/// and governance, never in the program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrCredential {
    pub name: String,
    /// Kebab-case credential kind (`bearer`, `hmac-sha256`, …).
    pub kind: String,
    pub span: SourceSpan,
}

/// A lowered `mark` declaration: a named cut point riding a committing
/// site. `metadata_only`; the runtime stamps `mark.reached` events, the
/// improve store pins scenarios at them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrMark {
    pub name: String,
    pub site: String,
    pub span: SourceSpan,
}

/// A lowered `gauge` declaration (experimentation subsystem): the binding of
/// a judge to a quality dimension, versioning with the program. Lowering
/// class is `metadata_only`; the evidence engine (`whip evidence` /
/// `whip improve`) consumes it at runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrGauge {
    pub name: String,
    pub site: Option<String>,
    /// `coerce` | `prompt` | `exec` | `labels`.
    pub judge_kind: String,
    /// The judge target: coerce name, prompt template, exec command, or
    /// labels source path.
    pub judge_target: String,
    /// Coerce judges only: the explicit record paths feeding the coerce
    /// function's parameters, in declaration order (`input.…`,
    /// `facts.<Class>.<field>`, or the single reserved `record`). Empty =
    /// declared without arguments (parses, but is not scoreable).
    pub judge_args: Vec<String>,
    pub expect: Option<IrGaugeBar>,
    pub inputs: Vec<String>,
    pub span: SourceSpan,
}

/// A lowered gauge bar. `form` is `chance` (`P(field)`) or `stat`
/// (`p10`/`mean`/…); `op` is `>=` (`at least`) or `<=` (`at most`);
/// `threshold` keeps its exact source text — consumers parse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrGaugeBar {
    pub form: String,
    pub subject: String,
    pub op: String,
    pub threshold: String,
}

/// A lowered `campaign` declaration (improve design note §3): the named,
/// versioned partition of the gauge vector. `metadata_only`; consumed by
/// `whip improve <name>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrCampaign {
    pub name: String,
    pub ascend: Vec<String>,
    pub reach: Vec<IrCampaignReach>,
    pub guard: Vec<IrCampaignGuard>,
    pub sacrifice: Vec<String>,
    /// Campaign-attached stratified reflection (`proposer redacted`).
    pub proposer_redacted: bool,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrCampaignReach {
    pub gauge: String,
    pub op: String,
    pub threshold: String,
    pub unit: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrCampaignGuard {
    pub gauge: String,
    pub band_percent: String,
}

/// A lowered `file store` declaration (std.files): the store identity + its
/// literal local root directory, consumed by the runtime file provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrFileStore {
    pub name: String,
    pub root: String,
    /// Path globs (relative to `root`) a `read` may touch; empty = any path
    /// inside the root (mounting the root is the read consent). Enforced at
    /// runtime in addition to root-containment.
    pub read_globs: Vec<String>,
    /// Path globs a `write` may touch. S4: stores are READ-ONLY by default —
    /// empty means writes are DENIED (checked at compile time and enforced
    /// fail-closed at runtime); declaring `allow write [...]` permits and
    /// bounds them.
    pub write_globs: Vec<String>,
    /// Declared `provider <name>` clause; `None` = the default `local`
    /// provider (spec/std-files.md "Providers"). Serialized to the snapshot
    /// only when declared, so provider-less stores keep their prior `.ir`.
    pub provider: Option<String>,
}

/// A lowered `memory pool` declaration (std.memory, MEM-1): the pool identity +
/// its optional recall context-limit budget. `metadata_only` — provides
/// `Resource<MemoryPool>`; providers read `context_limit` from the effect input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrMemoryPool {
    pub name: String,
    /// Optional recall packing budget (`context limit <n>`); providers read it
    /// from the `capability.call` effect input like any other argument.
    pub context_limit: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrHarness {
    pub name: String,
    pub kind: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IrSchema {
    Enum(IrEnum),
    Class(IrClass),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrEnum {
    pub name: String,
    pub variants: Vec<String>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrClass {
    pub name: String,
    pub fields: Vec<IrClassField>,
    pub span: SourceSpan,
}

/// A declared external event: the typed ingress manifest
/// (spec/event-ingress.md). Dotted name, class-shaped payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrEvent {
    pub name: String,
    pub fields: Vec<IrClassField>,
    pub span: SourceSpan,
}

/// A lowered source declaration (spec/std-time.md). `is_clock` selects the
/// `clock_source` lowering; otherwise `signal_source`. Both lower through the
/// `source_declaration` construct family and admit a durable signal fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrSource {
    pub name: String,
    pub provider: String,
    pub is_clock: bool,
    /// The `file` provider: reads `path` line-by-line and admits one signal per
    /// non-empty line, keyed by (source, line index) so re-reads are idempotent.
    pub is_file: bool,
    /// The `http` provider: GETs `url`, parses a JSON array, and admits one
    /// signal per element, keyed by (source, element index) so re-polls are
    /// idempotent.
    pub is_http: bool,
    pub recurrence: Option<Recurrence>,
    pub timezone: Option<String>,
    pub missed: Option<MissedPolicy>,
    /// `path "<file>"` — the file read line-by-line by a `file` source in line
    /// mode (`None` otherwise; exactly one of `path`/`watch`).
    pub path: Option<String>,
    /// `watch "<glob>"` — the glob a `file` source polls in occurrence mode
    /// (`None` otherwise): one signal per new (path, content-hash) occurrence.
    pub watch: Option<String>,
    /// `url "<url>"` — the endpoint GET'd by an `http` source (`None` otherwise).
    pub url: Option<String>,
    /// `dedup <observe>.<field>` — the observation field carrying the provider
    /// delivery id for `file` (line mode) / `http` sources; replaces the
    /// positional-ordinal admission key when declared.
    pub dedup_field: Option<String>,
    pub observe_binding: String,
    pub emit_signal: String,
    /// S6 `emit … from` — the projection source binding; when set, the
    /// signal's declared fields not overridden in `emit_fields` are expanded
    /// to copies off this binding after all declarations lower.
    pub emit_from: Option<String>,
    pub emit_fields: Vec<IrSourceEmitField>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrSourceEmitField {
    pub name: String,
    pub value: SourceValue,
    pub span: SourceSpan,
}

/// A lowered test scenario (spec/workflow-testing.md). Tests are excluded from
/// the executable IR (`compile`/`run` ignore them); `whip check` validates them
/// and `whip test` runs them. The clause detail is retained for the harness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrTest {
    pub name: String,
    pub workflow: Option<String>,
    pub clauses: Vec<TestClause>,
    pub span: SourceSpan,
}

/// Coordination resources (spec/coordination.md), lowered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrLease {
    pub name: String,
    pub key_type: String,
    pub slots: u32,
    pub ttl_seconds: u64,
    pub shared: bool,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrLedger {
    pub name: String,
    pub entry_schema: String,
    pub partition_field: String,
    pub retain_seconds: u64,
    pub shared: bool,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrCounter {
    pub name: String,
    pub key_type: String,
    pub cap: i64,
    pub reset: String,
    /// IANA timezone anchoring the reset-period boundary; `None` = UTC.
    pub timezone: Option<String>,
    pub shared: bool,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrClassField {
    pub name: String,
    pub ty: IrType,
    /// `@key`: this field is the class's natural key (import per-row idempotency).
    pub is_key: bool,
    /// Family B presence condition: `(discriminant field name, required literal)`.
    /// When set, the field is present only when the discriminant equals the literal
    /// (spec/decision-records/discriminated-families-design.md §5.7).
    pub presence_condition: Option<(String, String)>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IrType {
    Primitive(IrPrimitiveType),
    LiteralString(String),
    Ref(String),
    AgentRef(Vec<String>),
    Object(Vec<IrClassField>),
    Optional(Box<IrType>),
    Array(Box<IrType>),
    Map(Box<IrType>),
    /// DR-0074 §10: ciphertext whose payload type is `T`. A built-in
    /// constructor over one type, like `Map` — not a generic, which this
    /// language excludes.
    Sealed(Box<IrType>),
    Union(Vec<IrType>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IrPrimitiveType {
    String,
    Int,
    Float,
    Bool,
    Null,
    Duration,
    Time,
    Image,
    Audio,
    Pdf,
    Video,
    /// DR-0053 §5: the carrier of credential custody. A `secret` value can be
    /// bound, passed, stored in a field, and placed in an effect position —
    /// and no operation anywhere in the language or runtime yields its
    /// material (`models/maude/credential-no-eliminator.maude`).
    ///
    /// DR-0053 §15 parameterises it by the credential's kind. The kind-
    /// conditioned checks are name-keyed — they resolve a handle through a
    /// `name -> kind` map — and every one of the four things §5 permits a
    /// secret to do leaves no name to resolve. The discriminant is what a
    /// bound, passed, or stored secret still carries. `None` is the bare
    /// spelling and means "any kind".
    Secret(Option<whipplescript_custody::CredentialKind>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrAgent {
    pub name: String,
    /// Where the declaration sits, so a diagnostic about this agent's PROVIDER
    /// can point at the line that binds it rather than only at the `tell` that
    /// tripped over it (DR-0062). The binding is per-agent and the fix is almost
    /// always here, not at the call site.
    ///
    /// Not part of the `.ir` snapshot: analysis-facing metadata, like
    /// `IrEffectNode::agent`.
    pub span: SourceSpan,
    pub harness: Option<String>,
    pub provider: Option<String>,
    pub profile: Option<String>,
    pub capacity: Option<u32>,
    pub skills: Vec<String>,
    pub capabilities: Vec<String>,
    /// Portable feature requirements (`requires [<feature.class>]`, DR-0015 /
    /// spec/std-agent.md slice 6): taxonomy classes the selected provider's
    /// accepted feature report must state as supported.
    pub requires: Vec<String>,
    /// Workflows this agent may invoke as typed tools (DR-0025 `tools [...]`).
    pub tools: Vec<String>,
    /// Owned-harness conversation-compaction strategy (context-assembly Phase 5):
    /// `summarize` (default), `hard_reset`, `tool_results`, or `none`. `None` uses
    /// the harness default.
    pub compaction: Option<String>,
    /// Owned-harness thread continuation across tells:
    /// `continue` or `fresh`. `None` = `fresh` (every tell starts from scratch).
    pub thread: Option<String>,
    /// Ambient-config sources a Delegated harness may read (DR-0034 Decision 4):
    /// `project`, `user`, or `none`. `None` means the provider's own default —
    /// deliberately NOT the crippled empty set.
    pub settings: Option<String>,
    /// The harness class (DR-0034): `Managed` (WhippleScript is the runtime) vs
    /// `Delegated` (a foreign runtime that assembles its own context). Derived from
    /// the resolved provider/harness kind at lowering.
    pub harness_class: HarnessClass,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrCoerce {
    pub name: String,
    /// Where the declaration sits, so a diagnostic about the endpoint this
    /// coerce reaches can point at its `provider` clause (DR-0062), the same way
    /// an agent's does. Not part of the `.ir` snapshot.
    pub span: SourceSpan,
    pub params: Vec<IrParam>,
    pub output: IrType,
    pub body: String,
    /// The backend named by the declaration's `provider <name>` clause, surfaced
    /// so information-flow analysis can treat THIS endpoint as the principal a
    /// `coerce` egresses to (DR-0062). `None` when the declaration names none —
    /// the backend is then whatever the selection ladder resolves at runtime, so
    /// there is no static endpoint identity to govern by.
    ///
    /// Not part of the `.ir` snapshot: like `IrEffectNode::agent`, this is
    /// analysis-facing metadata, not lowered program shape.
    pub provider: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrParam {
    pub name: String,
    pub ty: IrType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrRule {
    pub name: String,
    pub whens: Vec<IrWhen>,
    pub body: String,
    pub metadata: IrRuleMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrWhen {
    pub source: String,
    pub pattern: String,
    pub guard: Option<IrExpression>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrRuleDependency {
    pub producer: String,
    pub consumer: String,
    pub fact: String,
}

/// DR-0043 Decision 5: one effect the region contains, with the level-1
/// `after` scope the kernel keys its effect id under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrRegionEffect {
    pub binding: String,
    pub scope: Option<(String, String)>,
}

/// DR-0043 Decision 5: a rule's `during`/`until` region, pre-rendered as the
/// three body variants the kernel lowers against. `IrRule.body` itself is the
/// condition-HOLDS variant (region spliced inline), so every existing text
/// scanner and effect-id derivation is untouched; the kernel swaps in
/// `body_removed` (region gone -- post-lapse suppression) or `body_lapsed`
/// (region replaced by its arm) per the region's durable state. NOT rendered
/// into the .ir snapshot (derived, deterministic).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrRegion {
    pub until: bool,
    /// Guard-grammar condition text; the kernel parses and evaluates it
    /// atomically inside each advancing commit.
    pub condition: String,
    pub lapse_binding: Option<String>,
    pub effects: Vec<IrRegionEffect>,
    pub body_removed: String,
    pub body_lapsed: String,
    /// The `on lapse` arm's own text, without the ambient statements that
    /// `body_lapsed` splices around it. The arm is the only part of the rule no
    /// other pass sees (the canonical body is the HOLDS variant), so it is
    /// validated separately and must not re-report the ambient lines.
    pub arm_content: String,
    /// The `(scrutinee, pattern)` chain of the `case` arms enclosing the region,
    /// outermost first. Family B narrowing of the lapse arm starts from the
    /// allowances those arms grant, not from the rule top.
    pub arm_case_arms: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IrRuleMetadata {
    pub fact_reads: Vec<String>,
    pub projection_reads: Vec<IrProjectionRead>,
    pub fact_writes: Vec<String>,
    pub record_sources: Vec<IrRecordSource>,
    pub fact_consumes: Vec<String>,
    pub effects: Vec<IrEffectNode>,
    pub dependencies: Vec<IrEffectDependency>,
    /// DR-0043: the rule's `during`/`until` region (at most one in v1).
    pub region: Option<IrRegion>,
    pub case_branches: Vec<IrRuleCaseBranch>,
    pub terminal_outputs: Vec<IrTerminalOutput>,
    pub terminal_branches: Vec<IrTerminalCaseBranch>,
    /// Envelope fields read off an untyped `Completed` payload — see
    /// `IrEnvelopeFieldOnPayload`. Lint-only (NOT in the `.ir` snapshot).
    pub envelope_reads_on_payload: Vec<IrEnvelopeFieldOnPayload>,
    /// The output bindings this rule `complete`s (the `name` of each `complete
    /// <binding> {…}` in the body, recursing into after/case/branch/handler blocks).
    /// Surfaced for the information-flow checker: a `complete result` returns a value
    /// to the workflow's invoker, an egress sink at the invoker boundary (DR-0030 X2).
    /// IFC-only — deliberately NOT rendered in the `.ir` snapshot, so it adds no
    /// golden/hash churn.
    pub terminal_completes: Vec<String>,
    /// The `redact <source> keep [..] as <out>` projections in this rule body
    /// (recursing into after/case/branch/handler blocks). Surfaced for the
    /// information-flow value-flow engine: a redaction is the explicit crossing at
    /// which the rule-level opaque join box is refined — the projected binding
    /// carries only the kept fields' labels (DR-0027, proven in
    /// models/lean/Whipple/Redaction.lean). IFC-only — NOT rendered in the `.ir`
    /// snapshot, so it adds no golden/hash churn.
    pub redactions: Vec<IrRedaction>,
    /// Per egress sink, the set of binding roots its payload references (union
    /// across branches), keyed by the sink string the IFC engine uses: a `complete
    /// <binding>` by its binding, a `record <Schema>` by `fact:<Schema>`, a `send via
    /// <channel>` by the channel. IFC-only (NOT in the `.ir` snapshot). The engine
    /// uses this to recognize a FULLY-REDACTED egress — one whose payload references
    /// only redaction outputs — and govern its leak check by the projection's
    /// per-field label rather than the rule's whole read set (DR-0027 redact, the
    /// static refinement).
    pub egress_payload_reads: BTreeMap<String, BTreeSet<String>>,
    /// The output roots of `coerce … declassified` crossings in this rule: the
    /// coerce's binding plus its `after <binding> succeeds|completes as <alias>`
    /// aliases (the names an egress payload actually references). The IFC engine
    /// waives the read×sink leak check for an egress carried ENTIRELY by these
    /// roots when a matching `grant declassify` covers the sink (DR-0027
    /// I-IFC3 — grants authorize marked crossings only). IFC-only (NOT in the
    /// `.ir` snapshot).
    pub declassified_roots: BTreeSet<String>,
    /// The `endorsed` dual of `declassified_roots`: output roots of `coerce …
    /// endorsed` crossings, and (DR-0051 §2) the claimed *item* of `claim …
    /// endorsed` crossings. Consulted by the inject check. IFC-only (NOT in the
    /// `.ir` snapshot).
    pub endorsed_roots: BTreeSet<String>,
    /// DR-0051 §3: the *item* bindings of `claim … endorsed` effects — the
    /// names a `when <tracker> has ready issue as <binding>` trigger bound, not
    /// the claim's own `as` binding.
    ///
    /// Carried separately from `endorsed_roots` because the two answer different
    /// questions. `endorsed_roots` says which values crossed; this says which
    /// queue the crossing drew its authority from, so the checker can refuse a
    /// marker whose tracker nobody vouched. IFC-only (NOT in the `.ir`
    /// snapshot).
    pub endorsed_claim_items: BTreeSet<String>,
    /// DR-0051 §4: per-field binding roots for each `record <Schema> { … }`
    /// egress — the same shape as `complete_field_reads`, keyed by
    /// `fact:<Schema>` and then by field name.
    ///
    /// `egress_payload_reads` collapses a record's roots to one set, which is
    /// enough to decide whether a *sink* is carried by a marked crossing but not
    /// which *field* it shaped. §4 needs the finer grain: a verdict field shaped
    /// by an endorsement must be schema-closed, while a sibling field holding a
    /// constant is nobody's business. IFC-only (NOT in the `.ir` snapshot).
    pub record_field_reads: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    /// Per-coerce argument roots: for EVERY `coerce f(args…) as <binding>` in
    /// the rule (marked or not), the binding roots its argument expressions
    /// reference. The IFC engine resolves these to governed sources for
    /// input-side provenance narrowing at marked crossings — including chaining
    /// through unmarked coerces (a model call is a total mixing point: its
    /// output carries the join of all its inputs). IFC-only (NOT in the `.ir`
    /// snapshot).
    pub carried_input_roots: BTreeMap<String, BTreeSet<String>>,
    /// `after <effect-binding> succeeds|completes as <alias>` → the effect
    /// binding, so the IFC engine can resolve payload and argument roots
    /// through the aliases bodies actually reference. IFC-only (NOT in the
    /// `.ir` snapshot).
    pub after_aliases: BTreeMap<String, String>,
    /// Per egress sink, the binding roots of every enclosing `case` scrutinee
    /// (DR-0046): a sink inside a `case` arm is INFLUENCED by the scrutinee —
    /// branching on model output and recording per-arm constants is the
    /// classic implicit channel. Covers record/complete/milestone/send/write
    /// uniformly. IFC-only (NOT in the `.ir` snapshot).
    pub egress_case_influence: BTreeMap<String, BTreeSet<String>>,
    /// Per `complete <binding>` egress, the binding roots each RESULT FIELD
    /// references — a two-level map `binding -> field -> {roots}`. Where
    /// `egress_payload_reads` joins all of a sink's fields into one set (enough for the
    /// fully-redacted recognizer), this keeps them SEPARATE so the IFC engine can
    /// compute a PER-FIELD flow signature (DR-0030 X2 v2): the reads reaching each
    /// result field, refined at fact granularity. IFC-only (NOT in the `.ir`
    /// snapshot). Union across branches; a `Shorthand` field resolves to the
    /// terminal's `from` binding.
    pub complete_field_reads: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    /// Per `emit milestone "<name>"` egress, the binding roots each MILESTONE FIELD
    /// references — same shape and purpose as `complete_field_reads`, but keyed by
    /// milestone name. Milestone payloads are child-to-parent egresses, so IFC needs
    /// their per-field flow signature too (D3′). IFC-only (NOT in the `.ir`
    /// snapshot). Union across branches.
    pub milestone_field_reads: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    /// Bounded-type projection egresses (`record <T> from <src>`): each is governed
    /// by the kept fields' per-field label join, like an explicit `redact`. IFC-only
    /// (NOT in the `.ir` snapshot). DR-0027 auto-redaction, the bounded-type reading.
    pub bounded_egresses: Vec<IrBoundedEgress>,
    /// Maximum nesting depth of `after` blocks in the rule body (0 = no `after`,
    /// 1 = a top-level `after`, 2 = an `after` inside an `after`, …). Surfaced for the
    /// `lint.deep_after_nesting` maintainability check.
    pub max_after_depth: usize,
}

/// A bounded-type projection egress (`record <T> from <src>`): the recorded fact
/// keeps exactly `T`'s fields, copied from `src`, so the egress carries only the
/// kept fields' per-field labels — the "bounded-type" auto-redaction reading
/// (DR-0027). The bound is the declared target type `T`; the labels are the
/// SOURCE schema's (a target field mislabelled public is still caught against the
/// source's label). The IFC engine governs it exactly like an explicit `redact`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrBoundedEgress {
    /// The engine's sink string (`fact:<T>` for a record).
    pub sink: String,
    /// The schema of the `from` source binding, whose per-field labels bound the
    /// projection.
    pub source_schema: String,
    /// The kept field names (the target type `T`'s fields).
    pub keep: Vec<String>,
}

/// A `redact <source> keep [..] as <binding>` projection, surfaced for the
/// information-flow value-flow engine (DR-0027). `source` is the binding being
/// projected, `keep` the kept field names, `binding` the projected output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrRedaction {
    pub source: String,
    pub keep: Vec<String>,
    pub binding: String,
    /// The schema of the source binding, when resolvable (a matched class, a
    /// coerce/decide/exec result, an `after … as` alias, or an earlier redaction's
    /// output). The information-flow engine derives the projection's confidentiality
    /// from the kept fields of this schema (`<schema>.<field>` labels), so a redacted
    /// egress needs only the kept fields' clearance, not the whole record's. `None`
    /// when the source type is not statically known (the engine then stays
    /// conservative for that redaction).
    pub source_schema: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrRecordSource {
    pub schema: String,
    pub construct: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrProjectionRead {
    pub kind: QueryKind,
    pub head: String,
    pub guard: Option<String>,
}

impl IrProjectionRead {
    fn to_snapshot(&self) -> String {
        let prefix = match self.kind {
            QueryKind::Fact => format!("fact:{}", self.head),
            QueryKind::Effect => format!("effect:{}", self.head),
        };
        match &self.guard {
            Some(guard) => format!("{prefix} where {guard}"),
            None => prefix,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrEffectNode {
    pub id: String,
    pub kind: IrEffectKind,
    pub binding: Option<String>,
    pub required_capabilities: Vec<String>,
    pub construct_use: Option<IrConstructUse>,
    pub idempotency_key: String,
    pub span: SourceSpan,
    /// Creation-anchored deadline from a `timeout <duration>` clause.
    pub timeout_seconds: Option<u64>,
    /// Turn-access grants (`with access to …`) lowered onto an `agent.tell` effect as
    /// authority-narrowing metadata (Proposal A). Empty for non-grant effects.
    pub access_grants: Vec<IrAccessGrant>,
    /// Turn-scoped skills (`with skills [...]`) pinned onto an `agent.tell` effect as
    /// provenance (context-assembly Phase 7). Recorded, not enforced — the owned
    /// catalogue stays discover-all. Empty for effects without a skill pin.
    pub turn_skills: Vec<String>,
    /// `on stream <name>` (std.vcs): the tell's per-turn homing exception.
    /// `None` = the agent's declared membership decides.
    pub on_stream: Option<String>,
    /// The raw selection-slot source of an `undo`/`transport` effect
    /// (std.vcs R4). A string LITERAL validates statically against the
    /// selection grammar; a dynamic expression validates at execution.
    pub selection_source: Option<String>,
    /// The `onto <target>` of a `transport` effect: `mainline` or a
    /// declared stream, validated post-lowering.
    pub transport_onto: Option<String>,
    /// The named resource (file store / channel) a direct effect touches, if any —
    /// e.g. the store of a `read`/`write`. Surfaced so information-flow analysis can
    /// see rule-body data flows, not just turn-access grants. `None` for effects
    /// that touch no named resource. Not part of the `.ir` snapshot.
    pub resource: Option<String>,
    /// The agent a `tell` addresses (its `target`), surfaced so information-flow
    /// analysis can model the turn's egress to that agent's provider. `None` for
    /// non-`tell` effects. Not part of the `.ir` snapshot.
    pub agent: Option<String>,
    /// The `coerce` declaration this effect invokes, surfaced for the same reason
    /// `agent` is: it is how the analysis reaches the declaration's `provider`
    /// clause and so the endpoint this egress actually reaches. `None` for
    /// non-coerce effects AND for an inline `decide`, which names no declaration
    /// and therefore no backend. Not part of the `.ir` snapshot.
    pub coerce_target: Option<String>,
    /// The workflow an `invoke` addresses, surfaced so information-flow analysis can
    /// enumerate and govern invoke membrane ports. `None` for non-`invoke` effects.
    /// Not part of the `.ir` snapshot.
    pub workflow_target: Option<String>,
    /// The `endorsed` source marker (DR-0027 I-IFC3): the author declared this effect
    /// (a `coerce`) an integrity-raising crossing. Surfaced so the trusted surface is
    /// visible at the source crossing point. Not part of the `.ir` snapshot.
    pub endorsed: bool,
    /// The `declassified` source marker (DR-0027 I-IFC3): the author declared this
    /// `coerce` a confidentiality-lowering crossing (its output schema bounds the
    /// leak). Surfaced for audit. Not part of the `.ir` snapshot.
    pub declassified: bool,
    /// The innermost `case <scrutinee> { <pattern> => … }` arm this effect sits in,
    /// as `(scrutinee, pattern)` — the discriminated-families *selector*. Lets the
    /// IFC checker apply NMIF-on-the-selector: a crossing (`endorsed`/`declassified`)
    /// selected by a low-integrity discriminant is rejected (DR §5.6 / §7.4). `None`
    /// for effects outside any `case`. Not part of the `.ir` snapshot.
    pub selected_by: Option<(String, String)>,
    /// The `exec` surface form — raw command string vs manifest capability
    /// (spec/std-script.md "Static checks" item 2) — surfaced so check-time
    /// gates (hosted-raw demotion, manifest resolution) classify the effect
    /// from the AST instead of re-scanning rule-body text. `None` for
    /// non-`exec` effects. Not part of the `.ir` snapshot.
    pub exec_target: Option<IrExecTarget>,
    /// Present exactly on `IrEffectKind::HttpRequest`.
    pub http_request: Option<IrHttpRequest>,
    /// Present exactly on `IrEffectKind::MintCredential`.
    pub mint_credential: Option<IrMintCredential>,
}

/// The two `exec` source forms (spec/std-script.md): a raw command string
/// (`exec "cmd"`, dev-profile only) or an operator-manifest capability
/// (`exec <name> with <record>`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IrExecTarget {
    Raw,
    Capability { name: String },
}

/// The payload of a `request` effect (DR-0053 §5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<IrRequestHeader>,
    /// Expression source for the body, if any.
    pub body: Option<String>,
    /// `signed with <handle>` — canonicalized and signed custodian-side.
    pub signed_with: Option<String>,
}

/// DR-0053 §5 as amended: a credential exchange. The exchange itself reuses
/// `IrHttpRequest` because it IS one — the same headers, the same marked slots,
/// the same body — and only the extraction is new.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrMintCredential {
    /// The credential the exchange spends, and whose egress ceiling the minted
    /// child inherits.
    pub parent: String,
    pub exchange: IrHttpRequest,
    pub token_path: String,
    pub public_paths: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrRequestHeader {
    pub name: String,
    pub value: IrRequestHeaderValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IrRequestHeaderValue {
    /// Expression source.
    Expr(String),
    /// A MARKED SLOT: the position the custodian substitutes material into.
    /// The count of these is what the custodian is told out of band, so a
    /// sentinel arriving inside interpolated data cannot silently become a
    /// slot the author never wrote.
    Credential {
        presentation: String,
        handle: String,
    },
}

impl IrHttpRequest {
    /// How many marked slots the author placed. Declared to the custodian out
    /// of band from the request text (`CustodyOp::Request::slots`).
    pub fn slot_count(&self) -> usize {
        self.headers
            .iter()
            .filter(|header| matches!(header.value, IrRequestHeaderValue::Credential { .. }))
            .count()
    }

    /// Every credential handle this request names, in order.
    pub fn credential_handles(&self) -> Vec<&str> {
        let mut handles: Vec<&str> = self
            .headers
            .iter()
            .filter_map(|header| match &header.value {
                IrRequestHeaderValue::Credential { handle, .. } => Some(handle.as_str()),
                IrRequestHeaderValue::Expr(_) => None,
            })
            .collect();
        if let Some(signed) = &self.signed_with {
            handles.push(signed.as_str());
        }
        handles
    }
}

/// A lowered turn-access grant: the granted operations narrow the turn's effective
/// authority on `resource` (modeled in `models/maude/turn-access-grant.maude`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrAccessGrant {
    pub resource: String,
    pub operations: Vec<IrAccessGrantOp>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrAccessGrantOp {
    pub operation: String,
    pub target: Option<String>,
    pub globs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrConstructUse {
    pub keyword: String,
    pub scope: String,
    pub construct_family: String,
    pub lowering_target: String,
    pub target_capability: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IrEffectKind {
    AgentTell,
    SchemaCoerce,
    CapabilityCall,
    EventEmit,
    WorkflowInvoke,
    TimerWait,
    ExecCommand,
    /// Authenticated outbound HTTP (DR-0053 §5). Distinct from `web`, which is
    /// a GET-only unauthenticated harness tool rather than language surface.
    HttpRequest,
    /// DR-0053 §5 as amended: a credential exchange, custodian-executed so the
    /// minted token never enters this process.
    MintCredential,
    TrackerFile,
    TrackerClaim,
    TrackerRenew,
    TrackerRelease,
    TrackerFinish,
    LeaseAcquire,
    LeaseRenew,
    LedgerAppend,
    CounterConsume,
    SignalEmit,
    FileRead,
    FileWrite,
    FileImport,
    FileExport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrEffectDependency {
    pub upstream: String,
    pub predicate: DependencyPredicate,
    pub downstream: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrRuleCaseBranch {
    pub scrutinee: String,
    pub scrutinee_type: IrType,
    pub pattern: IrCasePattern,
    pub guard: Option<IrExpression>,
    pub body_hash: String,
    pub pattern_span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IrCasePattern {
    EnumVariant(String),
    LiteralString(String),
    Agent(String),
    OptionalSome { binding: String },
    OptionalNone,
    Wildcard,
}

impl IrCasePattern {
    fn to_snapshot(&self) -> String {
        match self {
            IrCasePattern::EnumVariant(value) => format!("enum:{value}"),
            IrCasePattern::LiteralString(value) => format!("literal:\"{value}\""),
            IrCasePattern::Agent(value) => format!("agent:{value}"),
            IrCasePattern::OptionalSome { binding } => format!("some:{binding}"),
            IrCasePattern::OptionalNone => "none".to_owned(),
            IrCasePattern::Wildcard => "_".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrTerminalOutput {
    pub binding: String,
    pub alternatives: Vec<IrTerminalAlternative>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrTerminalAlternative {
    pub tag: String,
    pub payload_type: IrType,
    pub source_span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrTerminalCaseBranch {
    pub scrutinee: String,
    pub tag: Option<String>,
    pub binding: Option<String>,
    pub guard: Option<IrExpression>,
    pub body_hash: String,
    pub pattern_span: SourceSpan,
}

/// A read of a terminal-ENVELOPE field off a `Completed` PAYLOAD binding whose
/// shape is not statically known.
///
/// `after x completes as o` binds the envelope — `{tag, status, summary,
/// effect_id, run_id}` — while `case o { Completed as v => … }` binds the
/// effect's own output. When the effect declares no output schema (an
/// `agent.tell`, say) `v` has no type, so `check_field_path` returns `Unbound`
/// and every field name on it is accepted. That is correct: reading real output
/// fields off `v` is the construct's purpose, and the shape is a runtime
/// boundary.
///
/// It stops being correct when the field named is one the ENVELOPE carries.
/// `terminal_payload_for_tag("Completed")` returns the effect's result, and the
/// runtime lifts none of the five envelope fields into it — unlike the failure
/// tags, which do carry `summary`/`effect_id`/`run_id`. So the read resolves
/// only if the model's output happens to have a key by that name, and the
/// author almost certainly meant the alias that is in scope one line up.
///
/// Recorded rather than refused: an output CAN legitimately contain a
/// `summary` key, so this is a lint (`lint.envelope_field_on_payload`), not a
/// diagnostic. Lint-only metadata — deliberately NOT rendered in the `.ir`
/// snapshot, so it adds no golden/hash churn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrEnvelopeFieldOnPayload {
    /// The envelope alias the field is available on (`after x completes as o`).
    pub scrutinee: String,
    /// The payload binding it was read off instead (`Completed as v`).
    pub binding: String,
    /// The envelope field named.
    pub field: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DependencyPredicate {
    Succeeds,
    Fails,
    TimedOut,
    Cancelled,
    Completes,
}

#[derive(Clone, Debug)]
struct SemanticContext {
    workflow: Option<String>,
    schemas: SchemaIndex,
    agents: BTreeSet<String>,
    agent_capabilities: BTreeMap<String, BTreeSet<String>>,
    coerce_outputs: BTreeMap<String, TypeSyntax>,
    coerce_params: BTreeMap<String, Vec<ParamDecl>>,
    workflow_inputs: BTreeMap<String, WorkflowInputSurface>,
    /// Declared coordination resources (spec/coordination.md).
    leases: BTreeSet<String>,
    ledgers: BTreeSet<String>,
    counters: BTreeSet<String>,
    /// Declared `channel` names (std.messaging); `send via <channel>` must name one.
    channels: BTreeSet<String>,
    /// Declared channel providers by channel name (std.messaging): the
    /// capability-report-conditioned checks (send requires outbound-capable,
    /// `when message from` requires inbound-capable) resolve the report
    /// through this map.
    channel_providers: BTreeMap<String, String>,
    /// Declared `credential` kinds by name (std.custody; DR-0053 §5): the
    /// kind-conditioned static checks (`sign … with` needs a signing kind,
    /// presentation forms need a presentable kind) resolve through this map.
    /// Kinds are stored kebab-case, matching the custody protocol.
    /// Consumed by the `request` presentation check below; `verify` follows.
    credentials: BTreeMap<String, String>,
    /// Declared `memory pool` names (std.memory); `recall`/`learn`/`curate`
    /// must name one (MEM-1 check 1).
    memory_pools: BTreeSet<String>,
    /// Declared `tracker` names (std.tracker). A `when <tracker> has ready
    /// issue as <b>` trigger is matched against these rather than on the shape
    /// of the words alone, so a fact class followed by `has ready issue` is not
    /// mistaken for a queue — the same discipline `ifc.rs` applies on its side.
    trackers: BTreeSet<String>,
    /// DR-0043 regions by rule name, stashed by `extract_rule_regions` before the
    /// rule body was rewritten to its condition-HOLDS variant. The `on lapse` arm
    /// is spliced out of that body, so it reaches no other pass; analysis reads it
    /// back from here to type the arm (Decision 7 obligation 2).
    regions: BTreeMap<String, IrRegion>,
}

#[derive(Clone, Debug, Default)]
struct WorkflowInputSurface {
    inputs: BTreeMap<String, TypeSyntax>,
    /// The workflow's `output` contract types by name. A parent's
    /// `after <invoke-binding> succeeds as r` binds `r` to this contract so
    /// `r.<field>` type-checks against the child's declared output (the runtime
    /// already carries the child's terminal payload into that binding).
    outputs: BTreeMap<String, TypeSyntax>,
    /// The workflow's `failure` contract types by name. A parent's
    /// `after <invoke-binding> fails as f` binds `f` to this contract (when it is
    /// a shared top-level class) so `f.<field>` type-checks against the child's
    /// declared failure shape, instead of the generic DR-0032 `TerminalFailed`
    /// base. Falls back to the base when the failure class is child-local or the
    /// child declares zero/several failures.
    failures: BTreeMap<String, TypeSyntax>,
    schemas: SchemaIndex,
    /// Milestones the workflow may project (Family C): name -> payload class
    /// (empty string for a bare, payload-less milestone). Derived by scanning the
    /// workflow's rule bodies for `emit milestone "<name>" [of <Class>]`. This is
    /// the `declared(S)` set a parent's `after p reaches "<name>"` validates
    /// against (reject-undeclared) and the source of the observing binding's type.
    milestones: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default)]
struct SchemaIndex {
    classes: BTreeMap<String, BTreeMap<String, TypeSyntax>>,
    enums: BTreeMap<String, BTreeSet<String>>,
    /// Declared external signals (spec/event-ingress.md); their payload
    /// schemas live in `classes` keyed by the dotted signal name.
    events: BTreeSet<String>,
    /// Family B: per-schema field presence conditions, `schema -> field ->
    /// (discriminant field, required literal)`. A conditioned field is readable
    /// only inside a matching `case <root>.<disc>` arm.
    presence: BTreeMap<String, BTreeMap<String, (String, String)>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum BlockFrame {
    After {
        binding: String,
        predicate: DependencyPredicate,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LiteralExpr<'a> {
    String(&'a str),
    Number(&'a str),
    Bool,
    Null,
    Ident(&'a str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ExprType {
    Bool,
    Int,
    Float,
    String,
    Duration,
    Time,
    /// DR-0053: distinct from `String` so no operator, comparison, or
    /// interpolation accepts a secret where prose is expected — the
    /// expression-level face of the no-eliminator property. Deliberately NOT
    /// `Unknown`, which type-checks everywhere.
    ///
    /// §15 carries the credential kind. `None` is the bare spelling and means
    /// "any kind": it accepts every parameterised secret, and a parameterised
    /// position accepts only its own kind. Narrowing in one direction only is
    /// what makes the bare form a widening rather than an escape.
    Secret(Option<whipplescript_custody::CredentialKind>),
    Null,
    Object,
    Optional(Box<ExprType>),
    Array(Box<ExprType>),
    Map(Box<ExprType>),
    /// DR-0074 §10: `sealed<T>`, ciphertext whose payload type is `T`. Like
    /// `Secret` it unifies with nothing else, so no operator, comparison, or
    /// interpolation accepts it; unlike `Secret` it has exactly one
    /// eliminator, the `open` region of §3 (Slice 2, not yet built).
    Sealed(Box<ExprType>),
    Finite {
        label: String,
        values: Vec<String>,
    },
    Collection,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expr {
    Literal(ExprLiteral),
    Path(Vec<String>),
    Index {
        target: Box<Expr>,
        key: Box<Expr>,
    },
    Array(Vec<Expr>),
    Object(Vec<ExprObjectField>),
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Call {
        name: String,
        args: Vec<Expr>,
    },
    Query {
        kind: QueryKind,
        head: String,
        guard: Option<Box<Expr>>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExprObjectField {
    pub key: String,
    pub value: Expr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExprLiteral {
    String(String),
    Number(String),
    Bool(bool),
    Null,
    Ident(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnaryOp {
    Not,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    NotIn,
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryKind {
    Fact,
    Effect,
}

/// Parses a deterministic expression used by guards, assertions, and branch guards.
pub fn parse_expression(expr: &str) -> Result<Expr, String> {
    ExprParser::new(expr).parse()
}

impl Expr {
    pub fn to_snapshot(&self) -> String {
        match self {
            Self::Literal(literal) => literal.to_snapshot(),
            Self::Path(path) => path.join("."),
            Self::Index { target, key } => {
                format!(
                    "{}[{}]",
                    target.to_snapshot_with_parentheses(),
                    key.to_snapshot()
                )
            }
            Self::Array(items) => {
                let items = items
                    .iter()
                    .map(Self::to_snapshot)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{items}]")
            }
            Self::Object(fields) => {
                let fields = fields
                    .iter()
                    .map(|field| format!("{} {}", field.key, field.value.to_snapshot()))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{{{fields}}}")
            }
            Self::Unary { op, expr } => match op {
                UnaryOp::Not => format!("!{}", expr.to_snapshot_with_parentheses()),
            },
            Self::Binary { op, left, right } => format!(
                "{} {} {}",
                left.to_snapshot_with_parentheses(),
                op.to_snapshot(),
                right.to_snapshot_with_parentheses()
            ),
            Self::Call { name, args } => {
                let args = args
                    .iter()
                    .map(Self::to_snapshot)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{name}({args})")
            }
            Self::Query { kind, head, guard } => {
                let prefix = match kind {
                    QueryKind::Fact => head.clone(),
                    QueryKind::Effect => format!("effect {head}"),
                };
                match guard {
                    Some(guard) => format!("{prefix} where {}", guard.to_snapshot()),
                    None => prefix,
                }
            }
        }
    }

    fn to_snapshot_with_parentheses(&self) -> String {
        match self {
            Self::Binary { .. } => format!("({})", self.to_snapshot()),
            _ => self.to_snapshot(),
        }
    }
}

impl ExprLiteral {
    fn to_snapshot(&self) -> String {
        match self {
            Self::String(value) => format!("{value:?}"),
            Self::Number(value) | Self::Ident(value) => value.clone(),
            Self::Bool(value) => value.to_string(),
            Self::Null => "null".to_owned(),
        }
    }
}

impl BinaryOp {
    fn to_snapshot(self) -> &'static str {
        match self {
            Self::Or => "||",
            Self::And => "&&",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::In => "in",
            Self::NotIn => "not in",
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
        }
    }
}

/// Parses and lowers a source file into deterministic typed IR.
pub fn compile_program(source: &str) -> CompileOutput {
    compile_program_with_root(source, None)
}

/// Parses and lowers a source bundle into deterministic typed IR with an
/// optional explicit root workflow selection.
/// Every workflow this bundle declares, in declaration order.
///
/// A caller that must apply a per-workflow check to the WHOLE bundle needs the
/// name list before it can select roots, and `compile_program_with_root` hands
/// back exactly one workflow — `select_root_workflow` drops the rest. Returns an
/// empty vec for a source that does not parse; the caller's own compile reports
/// that.
pub fn workflow_names(source: &str) -> Vec<String> {
    let parsed = parse_program(source);
    if !parsed.diagnostics.is_empty() {
        return Vec::new();
    }
    let mut names = Vec::new();
    if let Some(root) = &parsed.program.workflow {
        names.push(root.name.clone());
    }
    for workflow in &parsed.program.workflows {
        names.push(workflow.name.name.clone());
    }
    names
}

pub fn compile_program_with_root(source: &str, root: Option<&str>) -> CompileOutput {
    let parsed = parse_program(source);
    if !parsed.diagnostics.is_empty() {
        return CompileOutput {
            ir: None,
            diagnostics: parsed.diagnostics,
            warnings: Vec::new(),
        };
    }

    // Program-level static check over ALL workflows (before root selection):
    // transitive runtime invocation cycles have no compile-time convergence proof
    // and are rejected (RESOLVED 2026-07-01). Direct self-invocation is caught
    // per-rule during lowering.
    let mut invoke_recursion_diagnostics = Vec::new();
    detect_workflow_invoke_recursion(&parsed.program, &mut invoke_recursion_diagnostics);
    detect_private_workflow_invocations(&parsed.program, &mut invoke_recursion_diagnostics);
    // The same "no compile-time convergence proof" argument at the two seams the
    // invoke-recursion check does not reach: the agent `tools [...]` grant graph
    // (DR-0025), and awaiting a callee that declares it never terminates.
    detect_agent_tool_grant_recursion(&parsed.program, &mut invoke_recursion_diagnostics);
    detect_service_workflow_invocations(&parsed.program, &mut invoke_recursion_diagnostics);
    if !invoke_recursion_diagnostics.is_empty() {
        return CompileOutput {
            ir: None,
            diagnostics: invoke_recursion_diagnostics,
            warnings: Vec::new(),
        };
    }

    let workflow_inputs = collect_workflow_input_surfaces(&parsed.program);
    let shared_coordination_usage = collect_shared_coordination_usage(&parsed.program);

    // Whole-program validation (RESOLVED 2026-07-01): when a program declares
    // more than one explicit `workflow`, validate EVERY workflow — not only the
    // selected root — so a broken sibling is caught in a single compile
    // regardless of which `--root` is chosen. Each workflow is lowered against
    // its own scope (top-level globals + that workflow's local block items),
    // which is exactly the scoped program `select_root_workflow` builds for that
    // name. Root selection below still produces the single entry IR for
    // `dev`/`deploy`; this pass only adds validation coverage and never changes
    // the emitted IR (when it finds no errors it returns nothing, so the root is
    // lowered once more, cleanly, below). See models/maude/workflow-scoping.maude.
    if parsed.program.workflows.len() > 1 {
        // Names declared at the top level are global (shared across every
        // workflow); names declared inside a `workflow { ... }` block are private
        // to it. Map each workflow-local name to its owning workflow(s) so that
        // when a workflow references a name that is really a sibling's local, the
        // resulting unknown-name error can point the author at where it lives —
        // the "names do not leak into sibling workflows" guarantee, surfaced.
        let global_names: BTreeSet<String> = parsed
            .program
            .items
            .iter()
            .filter_map(|item| referenced_decl_name(item).map(|(name, _)| name))
            .collect();
        let mut sibling_locals: BTreeMap<String, Vec<(String, SourceSpan)>> = BTreeMap::new();
        for workflow in &parsed.program.workflows {
            for item in &workflow.items {
                if let Some((name, span)) = referenced_decl_name(item) {
                    sibling_locals
                        .entry(name)
                        .or_default()
                        .push((workflow.name.name.clone(), span));
                }
            }
        }

        let mut aggregated = Vec::new();
        for workflow in &parsed.program.workflows {
            let name = workflow.name.name.clone();
            let own_locals: BTreeSet<String> = workflow
                .items
                .iter()
                .filter_map(|item| referenced_decl_name(item).map(|(name, _)| name))
                .collect();
            let mut diagnostics = match select_root_workflow(parsed.program.clone(), Some(&name)) {
                Ok(scoped) => {
                    lower_program(
                        scoped,
                        workflow_inputs.clone(),
                        shared_coordination_usage.clone(),
                    )
                    .diagnostics
                }
                Err(diagnostics) => diagnostics,
            };
            for diagnostic in &mut diagnostics {
                annotate_cross_workflow_leak(
                    diagnostic,
                    &name,
                    &own_locals,
                    &global_names,
                    &sibling_locals,
                );
            }
            aggregated.extend(diagnostics);
        }
        if !aggregated.is_empty() {
            return CompileOutput {
                ir: None,
                diagnostics: aggregated,
                warnings: Vec::new(),
            };
        }
    }

    match select_root_workflow(parsed.program, root) {
        Ok(program) => lower_program(program, workflow_inputs, shared_coordination_usage),
        Err(diagnostics) => CompileOutput {
            ir: None,
            diagnostics,
            warnings: Vec::new(),
        },
    }
}

/// One top-level declaration for an editor outline (`whip lsp`'s
/// `textDocument/documentSymbol`): its name, a coarse kind tag, and source span.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclSymbol {
    pub name: String,
    pub kind: &'static str,
    pub span: SourceSpan,
}

/// Top-level declarations of `source` in source order, for an editor outline. On a
/// parse error it returns whatever declarations parsed (best-effort outline).
pub fn document_symbols(source: &str) -> Vec<DeclSymbol> {
    let program = parse_program(source).program;
    let mut symbols = Vec::new();
    if let Some(workflow) = &program.workflow {
        symbols.push(DeclSymbol {
            name: workflow.name.clone(),
            kind: "workflow",
            span: workflow.span,
        });
    }
    for workflow in &program.workflows {
        symbols.push(DeclSymbol {
            name: workflow.name.name.clone(),
            kind: "workflow",
            span: workflow.span,
        });
    }
    for pattern in &program.patterns {
        symbols.push(DeclSymbol {
            name: pattern.name.name.clone(),
            kind: "pattern",
            span: pattern.span,
        });
    }
    for item in &program.items {
        let symbol = match item {
            Item::Class(decl) => ("class", decl.name.name.clone(), decl.span),
            Item::Enum(decl) => ("enum", decl.name.name.clone(), decl.span),
            Item::Agent(decl) => ("agent", decl.name.name.clone(), decl.span),
            Item::Rule(decl) => ("rule", decl.name.name.clone(), decl.span),
            Item::Coerce(decl) => ("coerce", decl.name.name.clone(), decl.span),
            Item::Action(decl) => ("action", decl.name.name.clone(), decl.span),
            Item::Lease(decl) => ("lease", decl.name.name.clone(), decl.span),
            Item::Ledger(decl) => ("ledger", decl.name.name.clone(), decl.span),
            Item::Counter(decl) => ("counter", decl.name.name.clone(), decl.span),
            Item::Tracker(decl) => ("tracker", decl.name.name.clone(), decl.span),
            Item::Channel(decl) => ("channel", decl.name.name.clone(), decl.span),
            Item::Credential(decl) => ("credential", decl.name.name.clone(), decl.span),
            Item::FileStore(decl) => ("file store", decl.name.name.clone(), decl.span),
            Item::MemoryPool(decl) => ("memory pool", decl.name.name.clone(), decl.span),
            Item::Event(decl) => ("signal", decl.name.clone(), decl.span),
            Item::Table(decl) => ("table", decl.name.name.clone(), decl.span),
            Item::Gauge(decl) => ("gauge", decl.name.name.clone(), decl.span),
            Item::Campaign(decl) => ("campaign", decl.name.name.clone(), decl.span),
            Item::Mark(decl) => ("mark", decl.name.value.clone(), decl.span),
            _ => continue,
        };
        symbols.push(DeclSymbol {
            name: symbol.1,
            kind: symbol.0,
            span: symbol.2,
        });
    }
    symbols
}

/// Zero-based source line of a byte offset.
fn line_index(source: &str, offset: usize) -> usize {
    source.as_bytes()[..offset]
        .iter()
        .filter(|&&byte| byte == b'\n')
        .count()
}

/// Classify the comments inside `body` (a field-list declaration's brace region)
/// against its `members` (each member's span + already-formatted lines, in source
/// order). Returns the own-line comments to interleave between members, plus a
/// per-member optional trailing comment (appended to that member's last line).
/// Returns `None` when a comment cannot be placed safely — a comment inside a
/// *multi-line* member's own body (a deeper level this pass does not place), or a
/// trailing comment with no single-line member on its line — so the caller refuses
/// the file rather than misplace it. `comments` must be sorted by `span.start`.
fn classify_body_comments<'a>(
    source: &str,
    body: SourceSpan,
    members: &[(SourceSpan, Vec<String>)],
    comments: &'a [Comment],
) -> Option<(Vec<&'a Comment>, Vec<Option<&'a Comment>>)> {
    let mut own_line: Vec<&Comment> = Vec::new();
    let mut trailing: Vec<Option<&Comment>> = vec![None; members.len()];
    for comment in comments {
        if comment.span.start <= body.start || comment.span.start >= body.end {
            continue;
        }
        // A comment inside a multi-line member's own braces is a deeper level we do
        // not place here (e.g. a data-carrying `enum` variant's nested field).
        if members.iter().any(|(span, lines)| {
            lines.len() > 1 && span.start < comment.span.start && comment.span.start < span.end
        }) {
            return None;
        }
        let line_start = source[..comment.span.start]
            .rfind('\n')
            .map(|index| index + 1)
            .unwrap_or(0);
        if source[line_start..comment.span.start].trim().is_empty() {
            own_line.push(comment);
            continue;
        }
        // Trailing: attach to a single-line member sharing the comment's line.
        let comment_line = line_index(source, comment.span.start);
        let mut placed = false;
        for (index, (span, lines)) in members.iter().enumerate() {
            if lines.len() == 1 && line_index(source, span.start) == comment_line {
                if trailing[index].is_some() {
                    return None;
                }
                trailing[index] = Some(comment);
                placed = true;
                break;
            }
        }
        if !placed {
            return None;
        }
    }
    Some((own_line, trailing))
}

/// Emit each member's lines, interleaving `own_line` comments by source position
/// (at `indent`) and appending each member's `trailing` comment to its last line.
/// `members` and `own_line` must be in ascending `span.start` order; `trailing`
/// is parallel to `members`.
fn emit_members_with_comments(
    members: &[(SourceSpan, Vec<String>)],
    own_line: &[&Comment],
    trailing: &[Option<&Comment>],
    indent: &str,
    formatted: &mut String,
) {
    let mut next = 0;
    for (index, (span, lines)) in members.iter().enumerate() {
        while next < own_line.len() && own_line[next].span.start < span.start {
            push_line(
                formatted,
                format!("{indent}{}", format_comment(own_line[next])),
            );
            next += 1;
        }
        let last = lines.len().saturating_sub(1);
        for (offset, line) in lines.iter().enumerate() {
            match trailing[index] {
                Some(comment) if offset == last => {
                    push_line(formatted, format!("{line}  {}", format_comment(comment)));
                }
                _ => push_line(formatted, line.clone()),
            }
        }
    }
    while next < own_line.len() {
        push_line(
            formatted,
            format!("{indent}{}", format_comment(own_line[next])),
        );
        next += 1;
    }
}

/// Format a `class` body with its own-line and trailing comments preserved.
/// Returns `false` (caller refuses the file) when a body comment cannot be placed
/// safely.
fn try_format_class_with_comments(
    class_decl: &ClassDecl,
    source: &str,
    comments: &[Comment],
    formatted: &mut String,
) -> bool {
    let members: Vec<(SourceSpan, Vec<String>)> = class_decl
        .fields
        .iter()
        .map(|field| {
            let key = if field.is_key { " @key" } else { "" };
            (
                field.span,
                vec![format!(
                    "  {} {}{key}",
                    field.name.name,
                    field.ty.to_source()
                )],
            )
        })
        .collect();
    let Some((own_line, trailing)) =
        classify_body_comments(source, class_decl.span, &members, comments)
    else {
        return false;
    };
    push_line(formatted, format!("class {} {{", class_decl.name.name));
    emit_members_with_comments(&members, &own_line, &trailing, "  ", formatted);
    push_line(formatted, "}");
    true
}

/// Format a `queue` body (its single `tracker` member) with own-line and trailing
/// comments preserved. Returns `false` (caller refuses the file) when a body
/// comment cannot be placed safely.
fn try_format_tracker_with_comments(
    queue: &TrackerDecl,
    source: &str,
    comments: &[Comment],
    formatted: &mut String,
) -> bool {
    let members: Vec<(SourceSpan, Vec<String>)> = vec![(
        queue.provider.span,
        vec![format!("  provider {}", queue.provider.name)],
    )];
    let Some((own_line, trailing)) = classify_body_comments(source, queue.span, &members, comments)
    else {
        return false;
    };
    push_line(formatted, format!("tracker {} {{", queue.name.name));
    emit_members_with_comments(&members, &own_line, &trailing, "  ", formatted);
    push_line(formatted, "}");
    true
}

/// Format a `file store` body (its `root` and optional `allow read`/`allow write`
/// clauses) with own-line and trailing comments preserved, interleaved by the
/// clause spans captured during parsing. Returns `false` (caller refuses the file)
/// when a body comment cannot be placed safely.
fn try_format_filestore_with_comments(
    file_store: &FileStoreDecl,
    source: &str,
    comments: &[Comment],
    formatted: &mut String,
) -> bool {
    let render = |globs: &[String]| {
        globs
            .iter()
            .map(|glob| format!("{glob:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut members: Vec<(SourceSpan, Vec<String>)> = Vec::new();
    if let Some(span) = file_store.root_span {
        members.push((span, vec![format!("  root {:?}", file_store.root)]));
    }
    if !file_store.read_globs.is_empty() {
        if let Some(span) = file_store.read_span {
            members.push((
                span,
                vec![format!("  allow read [{}]", render(&file_store.read_globs))],
            ));
        }
    }
    if !file_store.write_globs.is_empty() {
        if let Some(span) = file_store.write_span {
            members.push((
                span,
                vec![format!(
                    "  allow write [{}]",
                    render(&file_store.write_globs)
                )],
            ));
        }
    }
    if let Some(provider) = &file_store.provider {
        if let Some(span) = file_store.provider_span {
            members.push((span, vec![format!("  provider {}", provider.name)]));
        }
    }
    members.sort_by_key(|(span, _)| span.start);
    let Some((own_line, trailing)) =
        classify_body_comments(source, file_store.span, &members, comments)
    else {
        return false;
    };
    push_line(formatted, format!("file store {} {{", file_store.name.name));
    emit_members_with_comments(&members, &own_line, &trailing, "  ", formatted);
    push_line(formatted, "}");
    true
}

/// Format a `signal` body (a typed payload schema of `ClassField`s, like a class)
/// with its own-line and trailing comments preserved. Returns `false` (caller
/// refuses the file) when a body comment cannot be placed safely.
fn try_format_event_with_comments(
    event: &EventDecl,
    source: &str,
    comments: &[Comment],
    formatted: &mut String,
) -> bool {
    let members: Vec<(SourceSpan, Vec<String>)> = event
        .fields
        .iter()
        .map(|field| {
            (
                field.span,
                vec![format!("  {} {}", field.name.name, field.ty.to_source())],
            )
        })
        .collect();
    let Some((own_line, trailing)) = classify_body_comments(source, event.span, &members, comments)
    else {
        return false;
    };
    push_line(formatted, format!("signal {} {{", event.name));
    emit_members_with_comments(&members, &own_line, &trailing, "  ", formatted);
    push_line(formatted, "}");
    true
}

fn agent_field_span(field: &AgentField) -> SourceSpan {
    match field {
        AgentField::Provider(ident) => ident.span,
        AgentField::Profile(profile) => profile.span,
        AgentField::Capacity(_, span)
        | AgentField::Skills(_, span)
        | AgentField::Capabilities(_, span)
        | AgentField::Requires(_, span)
        | AgentField::Tools(_, span) => *span,
        AgentField::Compaction(strategy) => strategy.span,
        AgentField::Thread(mode) => mode.span,
        AgentField::Settings(sources) => sources.span,
        AgentField::Unknown { span, .. } => *span,
    }
}

fn agent_field_line(field: &AgentField) -> String {
    match field {
        AgentField::Provider(provider) => format!("  provider {}", provider.name),
        AgentField::Profile(profile) => format!("  profile {:?}", profile.value),
        AgentField::Capacity(capacity, _) => format!("  capacity {capacity}"),
        AgentField::Skills(skills, _) => {
            let skills = skills
                .iter()
                .map(|skill| format!("{:?}", skill.value))
                .collect::<Vec<_>>()
                .join(", ");
            format!("  skills [{skills}]")
        }
        AgentField::Capabilities(capabilities, _) => {
            let capabilities = capabilities
                .iter()
                .map(|capability| format!("{:?}", capability.value))
                .collect::<Vec<_>>()
                .join(", ");
            format!("  capabilities [{capabilities}]")
        }
        AgentField::Requires(classes, _) => {
            let classes = classes
                .iter()
                .map(|class| class.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            format!("  requires [{classes}]")
        }
        AgentField::Tools(tools, _) => {
            let tools = tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            format!("  tools [{tools}]")
        }
        AgentField::Compaction(strategy) => format!("  compaction {}", strategy.name),
        AgentField::Thread(mode) => format!("  thread {}", mode.name),
        AgentField::Settings(sources) => format!("  settings {}", sources.name),
        AgentField::Unknown { name, .. } => format!("  {}", name.name),
    }
}

/// Format an `agent` body with its own-line and trailing comments preserved.
/// Returns `false` (caller refuses the file) when a body comment cannot be placed
/// safely.
fn try_format_agent_with_comments(
    agent: &AgentDecl,
    source: &str,
    comments: &[Comment],
    formatted: &mut String,
) -> bool {
    let members: Vec<(SourceSpan, Vec<String>)> = agent
        .fields
        .iter()
        .map(|field| (agent_field_span(field), vec![agent_field_line(field)]))
        .collect();
    let Some((own_line, trailing)) = classify_body_comments(source, agent.span, &members, comments)
    else {
        return false;
    };
    let harness = agent
        .harness
        .as_ref()
        .map(|harness| format!(" using {}", harness.name))
        .or_else(|| {
            agent
                .delegated_to
                .as_ref()
                .map(|delegate| format!(" delegated to {}", delegate.name))
        })
        .unwrap_or_default();
    push_line(
        formatted,
        format!("agent {}{} {{", agent.name.name, harness),
    );
    emit_members_with_comments(&members, &own_line, &trailing, "  ", formatted);
    push_line(formatted, "}");
    true
}

/// Lines for one enum variant, with comments inside a data-carrying variant's
/// nested field block preserved (own-line interleaved, trailing appended) — the
/// block is a field list in braces, so it reuses the same classify/emit one level
/// deeper. Returns `None` when a nested comment cannot be placed safely.
fn enum_variant_lines_with_comments(
    variant: &EnumVariantDecl,
    source: &str,
    comments: &[Comment],
) -> Option<Vec<String>> {
    if variant.fields.is_empty() {
        return Some(vec![format!("  {}", variant.name.name)]);
    }
    let members: Vec<(SourceSpan, Vec<String>)> = variant
        .fields
        .iter()
        .map(|field| {
            (
                field.span,
                vec![format!("    {} {}", field.name.name, field.ty.to_source())],
            )
        })
        .collect();
    // `comments` is filtered to this variant's span by classify (via variant.span).
    let (own_line, trailing) = classify_body_comments(source, variant.span, &members, comments)?;
    let mut block = String::new();
    emit_members_with_comments(&members, &own_line, &trailing, "    ", &mut block);
    let mut lines = vec![format!("  {} {{", variant.name.name)];
    lines.extend(block.lines().map(str::to_owned));
    lines.push("  }".to_owned());
    Some(lines)
}

/// Format an `enum` body with its comments preserved at both levels: between
/// variants (own-line interleaved, trailing appended to a bare variant's line) and
/// inside a data-carrying variant's nested field block. Each brace-body filters
/// comments by its own span, so the two levels never double-count. Returns `false`
/// (caller refuses the file) when a comment cannot be placed safely.
fn try_format_enum_with_comments(
    enum_decl: &EnumDecl,
    source: &str,
    comments: &[Comment],
    formatted: &mut String,
) -> bool {
    let mut members: Vec<(SourceSpan, Vec<String>)> = Vec::with_capacity(enum_decl.variants.len());
    for variant in &enum_decl.variants {
        let Some(lines) = enum_variant_lines_with_comments(variant, source, comments) else {
            return false;
        };
        members.push((variant.span, lines));
    }
    // Enum-body-level comments are those NOT inside a data variant's nested block
    // (those are placed by `enum_variant_lines_with_comments`); pass only those to
    // the body-level classify so the nested ones are not counted twice.
    let body_level: Vec<Comment> = comments
        .iter()
        .filter(|comment| {
            !enum_decl.variants.iter().any(|variant| {
                !variant.fields.is_empty()
                    && variant.span.start < comment.span.start
                    && comment.span.start < variant.span.end
            })
        })
        .cloned()
        .collect();
    let Some((own_line, trailing)) =
        classify_body_comments(source, enum_decl.span, &members, &body_level)
    else {
        return false;
    };
    push_line(formatted, format!("enum {} {{", enum_decl.name.name));
    emit_members_with_comments(&members, &own_line, &trailing, "  ", formatted);
    push_line(formatted, "}");
    true
}

/// The name a top-level named declaration introduces, paired with its span, when
/// it is a kind that another workflow can reference by name (schemas, agents,
/// coordination resources, signals). Rules/tests/asserts/apply/contracts/patterns
/// introduce no such cross-referenced name here. Mirrors `document_symbols`'
/// named-decl set. Used to attach a "declared in workflow B" note when a
/// workflow references a name that is really private to a sibling.
fn referenced_decl_name(item: &Item) -> Option<(String, SourceSpan)> {
    match item {
        Item::Class(decl) => Some((decl.name.name.clone(), decl.span)),
        Item::Enum(decl) => Some((decl.name.name.clone(), decl.span)),
        Item::Agent(decl) => Some((decl.name.name.clone(), decl.span)),
        Item::Coerce(decl) => Some((decl.name.name.clone(), decl.span)),
        Item::Lease(decl) => Some((decl.name.name.clone(), decl.span)),
        Item::Ledger(decl) => Some((decl.name.name.clone(), decl.span)),
        Item::Counter(decl) => Some((decl.name.name.clone(), decl.span)),
        Item::Tracker(decl) => Some((decl.name.name.clone(), decl.span)),
        Item::Channel(decl) => Some((decl.name.name.clone(), decl.span)),
        Item::FileStore(decl) => Some((decl.name.name.clone(), decl.span)),
        Item::MemoryPool(decl) => Some((decl.name.name.clone(), decl.span)),
        Item::Event(decl) => Some((decl.name.clone(), decl.span)),
        Item::Table(decl) => Some((decl.name.name.clone(), decl.span)),
        Item::Gauge(decl) => Some((decl.name.name.clone(), decl.span)),
        Item::Campaign(decl) => Some((decl.name.name.clone(), decl.span)),
        Item::Mark(decl) => Some((decl.name.value.clone(), decl.span)),
        _ => None,
    }
}

/// If `diagnostic` (produced while validating workflow `current`) reports an
/// unknown name that is actually declared *private to a sibling workflow*, attach
/// a related note pointing at that sibling's declaration. This turns a bare
/// "unknown class `X`" into an actionable "…and `X` lives in workflow `B`; move
/// it to the top level to share it." A name that is global or one of `current`'s
/// own locals is legitimately in scope and never annotated.
fn annotate_cross_workflow_leak(
    diagnostic: &mut Diagnostic,
    current: &str,
    own_locals: &BTreeSet<String>,
    global_names: &BTreeSet<String>,
    sibling_locals: &BTreeMap<String, Vec<(String, SourceSpan)>>,
) {
    for (name, owners) in sibling_locals {
        if global_names.contains(name) || own_locals.contains(name) {
            continue;
        }
        // Only names actually referenced (as `` `name` ``) in this diagnostic, and
        // owned by some workflow other than the one being validated.
        if !diagnostic.message.contains(&format!("`{name}`")) {
            continue;
        }
        let Some((owner, span)) = owners.iter().find(|(owner, _)| owner != current) else {
            continue;
        };
        diagnostic.related.push(RelatedInfo {
            span: *span,
            message: format!(
                "`{name}` is declared inside workflow `{owner}`, which makes it \
                 private to that workflow; move it to a top-level declaration to \
                 share it across workflows"
            ),
        });
        return;
    }
}

fn select_root_workflow(
    mut program: Program,
    root: Option<&str>,
) -> Result<Program, Vec<Diagnostic>> {
    // A runnable program requires at least one explicit `workflow`. The implicit
    // compatibility root is removed (RESOLVED 2026-07-01): a source that declares
    // no `workflow` at all (neither the header form nor a `workflow Name { ... }`
    // block) is a library fragment, not a program, and is rejected here rather
    // than silently compiled as an anonymous root.
    if program.workflow.is_none() && program.workflows.is_empty() {
        return Err(vec![Diagnostic {
            related: Vec::new(),
            span: SourceSpan { start: 0, end: 0 },
            message: "program declares no `workflow`".to_owned(),
            suggestion: Some(
                "add an explicit `workflow Name { ... }` declaration; a runnable \
                 program requires at least one workflow (files that only declare \
                 shared types or patterns are libraries, meant to be `include`d)"
                    .to_owned(),
            ),
        }]);
    }

    if program.workflows.is_empty() {
        if let Some(root) = root {
            match program.workflow.as_ref() {
                Some(workflow) if workflow.name == root => {}
                Some(workflow) => {
                    return Err(vec![Diagnostic {
                        related: Vec::new(),
                        span: workflow.span,
                        message: format!("root workflow `{root}` was not found"),
                        suggestion: Some(format!("available workflow: `{}`", workflow.name)),
                    }]);
                }
                None => {
                    return Err(vec![Diagnostic {
                        related: Vec::new(),
                        span: SourceSpan { start: 0, end: 0 },
                        message: format!("root workflow `{root}` was not found"),
                        suggestion: Some(
                            "add an explicit `workflow Name { ... }` declaration".to_owned(),
                        ),
                    }]);
                }
            }
        }
        return Ok(program);
    }

    let selected_index = match root {
        Some(root) => match program
            .workflows
            .iter()
            .position(|workflow| workflow.name.name == root)
        {
            Some(index) => index,
            None => {
                let names = program
                    .workflows
                    .iter()
                    .map(|workflow| format!("`{}`", workflow.name.name))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(vec![Diagnostic {
                    related: Vec::new(),
                    span: SourceSpan { start: 0, end: 0 },
                    message: format!("root workflow `{root}` was not found"),
                    suggestion: Some(format!("available workflows: {names}")),
                }]);
            }
        },
        None if program.workflows.len() == 1 => 0,
        None => {
            let names = program
                .workflows
                .iter()
                .map(|workflow| format!("`{}`", workflow.name.name))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(vec![Diagnostic {
                related: Vec::new(),
                span: SourceSpan { start: 0, end: 0 },
                message: "multiple workflow declarations require an explicit root".to_owned(),
                suggestion: Some(format!(
                    "pass `--root <name>`; available workflows: {names}"
                )),
            }]);
        }
    };

    let selected = program.workflows.remove(selected_index);
    let mut items = program.items;
    let workflow_tags = selected.tags;
    let workflow_description = selected.description;
    items.extend(selected.items);
    Ok(Program {
        workflow: Some(selected.name),
        workflow_tags,
        workflow_description,
        explicit_workflow_body: true,
        workflows: Vec::new(),
        patterns: program.patterns,
        items,
    })
}

impl IrProgram {
    pub fn construct_uses(&self) -> Vec<&IrConstructUse> {
        self.rules
            .iter()
            .flat_map(|rule| rule.metadata.effects.iter())
            .filter_map(|effect| effect.construct_use.as_ref())
            .collect()
    }

    pub fn contract_registry(&self) -> ContractRegistry {
        let mut libraries = BTreeMap::<String, LibraryRegistration>::new();
        let mut contracts = BTreeMap::<(String, String), EffectContract>::new();

        for use_decl in &self.uses {
            libraries
                .entry(use_decl.name.clone())
                .or_insert_with(|| LibraryRegistration {
                    id: use_decl.name.clone(),
                    version: "unlocked".to_owned(),
                    standard: false,
                });
        }

        if !self.harnesses.is_empty() || !self.agents.is_empty() {
            register_standard_library(&mut libraries, "std.agent");
        }
        if !self.trackers.is_empty() {
            register_standard_library(&mut libraries, "std.tracker");
        }
        if !self.events.is_empty() {
            register_standard_library(&mut libraries, "std.ingress");
        }
        if !self.leases.is_empty() || !self.ledgers.is_empty() || !self.counters.is_empty() {
            register_standard_library(&mut libraries, "std.coord");
        }
        if !self.channels.is_empty() {
            register_standard_library(&mut libraries, "std.messaging");
        }
        if !self.credentials.is_empty() {
            register_standard_library(&mut libraries, "std.custody");
        }
        // A bare `file store` declaration registers the owning library even
        // before any rule uses a file effect (spec/std-files.md "Manifest":
        // the declaration alone previously registered nothing).
        if !self.file_stores.is_empty() {
            register_standard_library(&mut libraries, "std.files");
        }
        if self.sources.iter().any(|source| source.is_clock) {
            register_standard_library(&mut libraries, "std.time");
        }
        if !self.coerces.is_empty() {
            register_standard_library(&mut libraries, "std.coercion");
            register_effect_contract(
                &mut libraries,
                &mut contracts,
                IrEffectKind::SchemaCoerce,
                Vec::new(),
            );
        }

        for rule in &self.rules {
            for effect in &rule.metadata.effects {
                register_effect_contract(
                    &mut libraries,
                    &mut contracts,
                    effect.kind.clone(),
                    effect.required_capabilities.clone(),
                );
            }
        }

        // Package-owned construct registrations (e.g. `send`, `recall`) are NOT
        // registered here: they come from a package manifest — embedded std
        // manifests included — merged in by the CLI when the owning package is
        // imported (`use std.messaging`). Modeled in
        // `models/maude/std-construct-authorization.maude`.
        ContractRegistry {
            libraries: libraries.into_values().collect(),
            constructs: Vec::new(),
            effect_contracts: contracts.into_values().collect(),
        }
    }

    pub fn to_snapshot(&self) -> String {
        let mut snapshot = String::new();
        push_line(&mut snapshot, format!("workflow {}", self.workflow));

        if !self.source_tags.is_empty() {
            push_line(&mut snapshot, "source_tags");
            for tag in &self.source_tags {
                push_line(
                    &mut snapshot,
                    format!("@{} {} {}", tag.name, tag.target_kind, tag.target),
                );
            }
        }

        if !self.source_descriptions.is_empty() {
            push_line(&mut snapshot, "source_descriptions");
            for description in &self.source_descriptions {
                push_line(
                    &mut snapshot,
                    format!(
                        "{:?} {} {}",
                        description.value, description.target_kind, description.target
                    ),
                );
            }
        }

        if !self.shared_coordination_usage.is_empty() {
            push_line(&mut snapshot, "shared_coordination_usage");
            for usage in &self.shared_coordination_usage {
                push_line(
                    &mut snapshot,
                    format!(
                        "{} <- {}",
                        usage.resource,
                        usage.workflow_principals.join(",")
                    ),
                );
            }
        }

        if !self.includes.is_empty() {
            push_line(&mut snapshot, "includes");
            for include in &self.includes {
                match &include.source_hash {
                    Some(source_hash) => {
                        push_line(
                            &mut snapshot,
                            format!("  {} hash {}", include.path, source_hash),
                        );
                    }
                    None => push_line(&mut snapshot, format!("  {}", include.path)),
                }
            }
        }

        if !self.pattern_applications.is_empty() {
            push_line(&mut snapshot, "pattern_applications");
            for application in &self.pattern_applications {
                let type_args = application
                    .type_args
                    .iter()
                    .map(IrType::to_snapshot)
                    .collect::<Vec<_>>()
                    .join(", ");
                push_line(
                    &mut snapshot,
                    format!(
                        "  {} as {}<{}>",
                        application.pattern, application.alias, type_args
                    ),
                );
                push_line(
                    &mut snapshot,
                    format!(
                        "    defined-at {}..{}",
                        application.definition_span.start, application.definition_span.end
                    ),
                );
                push_line(
                    &mut snapshot,
                    format!(
                        "    applied-at {}..{}",
                        application.application_span.start, application.application_span.end
                    ),
                );
                for argument in &application.value_args {
                    push_line(
                        &mut snapshot,
                        format!("    arg {} {}", argument.name, argument.value),
                    );
                }
                for generated in &application.generated {
                    push_line(&mut snapshot, format!("    generated {generated}"));
                }
            }
        }

        if !self.workflow_contracts.is_empty() {
            push_line(&mut snapshot, "workflow_contracts");
            for contract in &self.workflow_contracts {
                push_line(
                    &mut snapshot,
                    format!(
                        "  {} {} {}",
                        contract.kind.as_str(),
                        contract.name,
                        contract.ty.to_snapshot()
                    ),
                );
            }
        }

        if !self.uses.is_empty() {
            push_line(&mut snapshot, "uses");
            for use_decl in &self.uses {
                push_line(
                    &mut snapshot,
                    format!("  {} {}", use_decl.kind.as_str(), use_decl.name),
                );
            }
        }

        if !self.schemas.is_empty() {
            push_line(&mut snapshot, "schemas");
            for schema in &self.schemas {
                match schema {
                    IrSchema::Enum(enum_decl) => {
                        push_line(
                            &mut snapshot,
                            format!(
                                "  enum {} {{ {} }}",
                                enum_decl.name,
                                enum_decl.variants.join(", ")
                            ),
                        );
                    }
                    IrSchema::Class(class_decl) => {
                        push_line(&mut snapshot, format!("  class {}", class_decl.name));
                        for field in &class_decl.fields {
                            // `@key` is serialized only when set, so non-keyed
                            // classes keep their prior snapshot (no ripple).
                            let key = if field.is_key { " @key" } else { "" };
                            push_line(
                                &mut snapshot,
                                format!("    {} {}{key}", field.name, field.ty.to_snapshot()),
                            );
                        }
                    }
                }
            }
        }

        if !self.harnesses.is_empty() {
            push_line(&mut snapshot, "harnesses");
            for harness in &self.harnesses {
                push_line(
                    &mut snapshot,
                    format!("  harness {} kind={}", harness.name, harness.kind),
                );
            }
        }
        if !self.trackers.is_empty() {
            push_line(&mut snapshot, "trackers");
            for queue in &self.trackers {
                push_line(
                    &mut snapshot,
                    format!("  tracker {} provider={}", queue.name, queue.provider),
                );
            }
        }
        if !self.streams.is_empty() {
            push_line(&mut snapshot, "streams");
            for stream in &self.streams {
                push_line(
                    &mut snapshot,
                    format!(
                        "  stream {} members=[{}]{}",
                        stream.name,
                        stream.members.join(","),
                        stream
                            .staleness_seconds
                            .map(|seconds| format!(" staleness={seconds}s"))
                            .unwrap_or_default()
                    ),
                );
            }
        }

        if !self.channels.is_empty() {
            push_line(&mut snapshot, "channels");
            for channel in &self.channels {
                let mut line = format!("  channel {} provider={}", channel.name, channel.provider);
                if let Some(workspace) = &channel.workspace {
                    line.push_str(&format!(" workspace={workspace}"));
                }
                if let Some(destination) = &channel.destination {
                    line.push_str(&format!(" destination={destination:?}"));
                }
                push_line(&mut snapshot, line);
            }
        }

        if !self.credentials.is_empty() {
            push_line(&mut snapshot, "credentials");
            for credential in &self.credentials {
                push_line(
                    &mut snapshot,
                    format!("  credential {} kind={}", credential.name, credential.kind),
                );
            }
        }

        if !self.gauges.is_empty() {
            push_line(&mut snapshot, "gauges");
            for gauge in &self.gauges {
                let mut line = format!(
                    "  gauge {} judge={}:{}",
                    gauge.name, gauge.judge_kind, gauge.judge_target
                );
                if !gauge.judge_args.is_empty() {
                    line.push_str(&format!(" args=({})", gauge.judge_args.join(",")));
                }
                if let Some(site) = &gauge.site {
                    line.push_str(&format!(" site={site}"));
                }
                if let Some(bar) = &gauge.expect {
                    line.push_str(&format!(
                        " expect={}:{}{}{}",
                        bar.form, bar.subject, bar.op, bar.threshold
                    ));
                }
                if !gauge.inputs.is_empty() {
                    line.push_str(&format!(" inputs={}", gauge.inputs.join(",")));
                }
                push_line(&mut snapshot, line);
            }
        }

        if !self.marks.is_empty() {
            push_line(&mut snapshot, "marks");
            for mark in &self.marks {
                push_line(
                    &mut snapshot,
                    format!("  mark {:?} after {}", mark.name, mark.site),
                );
            }
        }

        if !self.campaigns.is_empty() {
            push_line(&mut snapshot, "campaigns");
            for campaign in &self.campaigns {
                let mut line = format!("  campaign {}", campaign.name);
                if !campaign.ascend.is_empty() {
                    line.push_str(&format!(" ascend={}", campaign.ascend.join(",")));
                }
                for reach in &campaign.reach {
                    line.push_str(&format!(
                        " reach={}{}{}{}",
                        reach.gauge,
                        reach.op,
                        reach.threshold,
                        reach.unit.as_deref().unwrap_or("")
                    ));
                }
                for guard in &campaign.guard {
                    line.push_str(&format!(
                        " guard={}:within:{}%",
                        guard.gauge, guard.band_percent
                    ));
                }
                if !campaign.sacrifice.is_empty() {
                    line.push_str(&format!(" sacrifice={}", campaign.sacrifice.join(",")));
                }
                if campaign.proposer_redacted {
                    line.push_str(" proposer=redacted");
                }
                push_line(&mut snapshot, line);
            }
        }

        if !self.file_stores.is_empty() {
            push_line(&mut snapshot, "file_stores");
            for file_store in &self.file_stores {
                push_line(
                    &mut snapshot,
                    format!(
                        "  file store {} root={:?}",
                        file_store.name, file_store.root
                    ),
                );
                // Globs are serialized only when present, so stores without an
                // `allow` clause keep their prior snapshot (no ripple).
                if !file_store.read_globs.is_empty() {
                    push_line(
                        &mut snapshot,
                        format!("    allow read {:?}", file_store.read_globs),
                    );
                }
                if !file_store.write_globs.is_empty() {
                    push_line(
                        &mut snapshot,
                        format!("    allow write {:?}", file_store.write_globs),
                    );
                }
                // The provider likewise serializes only when declared (unset =
                // the `local` default), so provider-less stores keep their
                // prior `.ir` byte-identically (slice F5 zero-churn gate).
                if let Some(provider) = &file_store.provider {
                    push_line(&mut snapshot, format!("    provider {provider}"));
                }
            }
        }

        if !self.memory_pools.is_empty() {
            push_line(&mut snapshot, "memory_pools");
            for pool in &self.memory_pools {
                push_line(&mut snapshot, format!("  memory pool {}", pool.name));
                // The context limit is serialized only when present, so pools
                // without it keep a minimal snapshot (no ripple).
                if let Some(limit) = pool.context_limit {
                    push_line(&mut snapshot, format!("    context limit {limit}"));
                }
            }
        }

        if !self.agents.is_empty() {
            push_line(&mut snapshot, "agents");
            for agent in &self.agents {
                let profile = agent.profile.as_deref().unwrap_or("<missing>");
                let harness = agent.harness.as_deref().unwrap_or("<fallback>");
                let provider = agent.provider.as_deref().unwrap_or("<fallback>");
                let capacity = agent
                    .capacity
                    .map(|capacity| capacity.to_string())
                    .unwrap_or_else(|| "<missing>".to_owned());
                let skills = if agent.skills.is_empty() {
                    "[]".to_owned()
                } else {
                    format!("[{}]", agent.skills.join(", "))
                };
                let capabilities = if agent.capabilities.is_empty() {
                    "[]".to_owned()
                } else {
                    format!("[{}]", agent.capabilities.join(", "))
                };
                let tools = if agent.tools.is_empty() {
                    "[]".to_owned()
                } else {
                    format!("[{}]", agent.tools.join(", "))
                };
                // Feature requirements append only when declared, so agents
                // without `requires` keep an unchanged .ir snapshot (no ripple).
                let requires = if agent.requires.is_empty() {
                    String::new()
                } else {
                    format!(" requires=[{}]", agent.requires.join(", "))
                };
                // Compaction strategy appends only when set, so agents that take the
                // harness default keep an unchanged .ir snapshot (no ripple).
                let compaction = agent
                    .compaction
                    .as_deref()
                    .map(|strategy| format!(" compaction={strategy}"))
                    .unwrap_or_default();
                // Settings likewise appends only when set (unset = provider default).
                let settings = agent
                    .settings
                    .as_deref()
                    .map(|sources| format!(" settings={sources}"))
                    .unwrap_or_default();
                // Thread mode likewise appends only when set (unset = fresh).
                let thread = agent
                    .thread
                    .as_deref()
                    .map(|mode| format!(" thread={mode}"))
                    .unwrap_or_default();
                // Harness class (DR-0034): Managed is the default/substrate, so only
                // Delegated agents emit a class token — Managed agents' .ir is unchanged.
                let class = match agent.harness_class {
                    HarnessClass::Delegated => " class=delegated",
                    HarnessClass::Managed => "",
                };
                push_line(
                    &mut snapshot,
                    format!(
                        "  agent {} harness={} provider={} profile={} capacity={} skills={} capabilities={} tools={}{}{}{}{}{}",
                        agent.name, harness, provider, profile, capacity, skills, capabilities, tools, requires, compaction, settings, thread, class
                    ),
                );
            }
        }

        if !self.coerces.is_empty() {
            push_line(&mut snapshot, "coerces");
            for coerce in &self.coerces {
                let params = coerce
                    .params
                    .iter()
                    .map(|param| format!("{} {}", param.name, param.ty.to_snapshot()))
                    .collect::<Vec<_>>()
                    .join(", ");
                push_line(
                    &mut snapshot,
                    format!(
                        "  coerce {}({}) -> {}",
                        coerce.name,
                        params,
                        coerce.output.to_snapshot()
                    ),
                );
            }
        }

        if !self.assertions.is_empty() {
            push_line(&mut snapshot, "assertions");
            for assertion in &self.assertions {
                push_line(
                    &mut snapshot,
                    format!("  assert {}", assertion.expr.expr.to_snapshot()),
                );
                if !assertion.projection_reads.is_empty() {
                    push_line(&mut snapshot, "    reads");
                    for read in &assertion.projection_reads {
                        push_line(&mut snapshot, format!("      {}", read.to_snapshot()));
                    }
                }
            }
        }

        if !self.rules.is_empty() {
            push_line(&mut snapshot, "rules");
            for rule in &self.rules {
                push_line(&mut snapshot, format!("  rule {}", rule.name));
                for when in &rule.whens {
                    match &when.guard {
                        Some(guard) => push_line(
                            &mut snapshot,
                            format!(
                                "    when {} where {}",
                                when.pattern,
                                guard.expr.to_snapshot()
                            ),
                        ),
                        None => push_line(&mut snapshot, format!("    when {}", when.pattern)),
                    }
                }
                if !rule.metadata.fact_reads.is_empty() {
                    push_line(&mut snapshot, "    reads");
                    for read in &rule.metadata.fact_reads {
                        push_line(&mut snapshot, format!("      {}", read));
                    }
                }
                if !rule.metadata.projection_reads.is_empty() {
                    push_line(&mut snapshot, "    projection_reads");
                    for read in &rule.metadata.projection_reads {
                        push_line(&mut snapshot, format!("      {}", read.to_snapshot()));
                    }
                }
                if !rule.metadata.fact_writes.is_empty() {
                    push_line(&mut snapshot, "    writes");
                    for write in &rule.metadata.fact_writes {
                        push_line(&mut snapshot, format!("      {}", write));
                    }
                }
                if !rule.metadata.record_sources.is_empty() {
                    push_line(&mut snapshot, "    record_sources");
                    for source in &rule.metadata.record_sources {
                        push_line(
                            &mut snapshot,
                            format!(
                                "      schema:{} construct={} span={}..{}",
                                source.schema, source.construct, source.span.start, source.span.end
                            ),
                        );
                    }
                }
                if !rule.metadata.fact_consumes.is_empty() {
                    push_line(&mut snapshot, "    consumes");
                    for consumed in &rule.metadata.fact_consumes {
                        push_line(&mut snapshot, format!("      {}", consumed));
                    }
                }
                if !rule.metadata.effects.is_empty() {
                    push_line(&mut snapshot, "    effects");
                    for effect in &rule.metadata.effects {
                        let binding = effect.binding.as_deref().unwrap_or("-");
                        let construct = effect
                            .construct_use
                            .as_ref()
                            .map(|form| {
                                format!(" construct={}->{}", form.keyword, form.target_capability)
                            })
                            .unwrap_or_default();
                        // Turn-access grants are appended only when present, so
                        // grant-free effects keep their existing snapshot shape.
                        let grants = if effect.access_grants.is_empty() {
                            String::new()
                        } else {
                            let rendered = effect
                                .access_grants
                                .iter()
                                .map(|grant| {
                                    let ops = grant
                                        .operations
                                        .iter()
                                        .map(|op| op.operation.as_str())
                                        .collect::<Vec<_>>()
                                        .join(",");
                                    format!("{}[{ops}]", grant.resource)
                                })
                                .collect::<Vec<_>>()
                                .join(";");
                            format!(" grants={rendered}")
                        };
                        // Turn-scoped skill pins (Phase 7) append only when present,
                        // so pin-free effects keep their existing snapshot shape.
                        let homing = effect
                            .on_stream
                            .as_ref()
                            .map(|stream| format!(" on_stream={stream}"))
                            .unwrap_or_default();
                        let skills = if effect.turn_skills.is_empty() {
                            String::new()
                        } else {
                            format!(" skills={}", effect.turn_skills.join(","))
                        };
                        push_line(
                            &mut snapshot,
                            format!(
                                "      {} kind={} binding={}{} key={}{}{}{}",
                                effect.id,
                                effect.kind.as_str(),
                                binding,
                                construct,
                                effect.idempotency_key,
                                grants,
                                skills,
                                homing
                            ),
                        );
                    }
                }
                if !rule.metadata.dependencies.is_empty() {
                    push_line(&mut snapshot, "    dependencies");
                    for dependency in &rule.metadata.dependencies {
                        push_line(
                            &mut snapshot,
                            format!(
                                "      {} --{}--> {}",
                                dependency.upstream,
                                dependency.predicate.as_str(),
                                dependency.downstream
                            ),
                        );
                    }
                }
                if !rule.metadata.case_branches.is_empty() {
                    push_line(&mut snapshot, "    case_branches");
                    for branch in &rule.metadata.case_branches {
                        let guard = branch
                            .guard
                            .as_ref()
                            .map(|guard| guard.expr.to_snapshot())
                            .unwrap_or_else(|| "-".to_owned());
                        push_line(
                            &mut snapshot,
                            format!(
                                "      case {} type={} pattern={} guard={} body_hash={} span={}..{}",
                                branch.scrutinee,
                                branch.scrutinee_type.to_snapshot(),
                                branch.pattern.to_snapshot(),
                                guard,
                                branch.body_hash,
                                branch.pattern_span.start,
                                branch.pattern_span.end
                            ),
                        );
                    }
                }
                if !rule.metadata.terminal_outputs.is_empty() {
                    push_line(&mut snapshot, "    terminal_outputs");
                    for output in &rule.metadata.terminal_outputs {
                        push_line(
                            &mut snapshot,
                            format!(
                                "      {} span={}..{}",
                                output.binding, output.span.start, output.span.end
                            ),
                        );
                        for alternative in &output.alternatives {
                            push_line(
                                &mut snapshot,
                                format!(
                                    "        {} payload={} span={}..{}",
                                    alternative.tag,
                                    alternative.payload_type.to_snapshot(),
                                    alternative.source_span.start,
                                    alternative.source_span.end
                                ),
                            );
                        }
                    }
                }
                if !rule.metadata.terminal_branches.is_empty() {
                    push_line(&mut snapshot, "    terminal_branches");
                    for branch in &rule.metadata.terminal_branches {
                        let tag = branch.tag.as_deref().unwrap_or("_");
                        let binding = branch.binding.as_deref().unwrap_or("-");
                        let guard = branch
                            .guard
                            .as_ref()
                            .map(|guard| guard.expr.to_snapshot())
                            .unwrap_or_else(|| "-".to_owned());
                        push_line(
                            &mut snapshot,
                            format!(
                                "      case {} {} binding={} guard={} body_hash={} span={}..{}",
                                branch.scrutinee,
                                tag,
                                binding,
                                guard,
                                branch.body_hash,
                                branch.pattern_span.start,
                                branch.pattern_span.end
                            ),
                        );
                    }
                }
                push_line(
                    &mut snapshot,
                    format!("    body_hash {}", stable_hash(&rule.body)),
                );
            }
        }

        if !self.rule_dependencies.is_empty() {
            push_line(&mut snapshot, "rule_dependencies");
            for dependency in &self.rule_dependencies {
                push_line(
                    &mut snapshot,
                    format!(
                        "  {} --{}--> {}",
                        dependency.producer, dependency.fact, dependency.consumer
                    ),
                );
            }
        }

        snapshot
    }
}

fn register_standard_library(libraries: &mut BTreeMap<String, LibraryRegistration>, id: &str) {
    libraries
        .entry(id.to_owned())
        .or_insert_with(|| LibraryRegistration {
            id: id.to_owned(),
            version: "0.1.0".to_owned(),
            standard: true,
        });
}

fn register_effect_contract(
    libraries: &mut BTreeMap<String, LibraryRegistration>,
    contracts: &mut BTreeMap<(String, String), EffectContract>,
    kind: IrEffectKind,
    required_capabilities: Vec<String>,
) {
    let contract = effect_contract_for_kind(kind, required_capabilities);
    register_standard_library(libraries, contract.library_id.as_str());
    contracts
        .entry((contract.id.clone(), contract.version.clone()))
        .and_modify(|existing| {
            merge_unique(
                &mut existing.required_capabilities,
                &contract.required_capabilities,
            );
            merge_unique(&mut existing.provider_kinds, &contract.provider_kinds);
            merge_unique(&mut existing.source_forms, &contract.source_forms);
            merge_unique(&mut existing.projected_facts, &contract.projected_facts);
        })
        .or_insert(contract);
}

fn merge_unique(target: &mut Vec<String>, values: &[String]) {
    for value in values {
        if !target.contains(value) {
            target.push(value.clone());
        }
    }
    target.sort();
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn effect_contract_for_kind(
    kind: IrEffectKind,
    required_capabilities: Vec<String>,
) -> EffectContract {
    let mut required_capabilities = required_capabilities;
    required_capabilities.sort();
    required_capabilities.dedup();
    let effect_kind = kind.as_str().to_owned();

    let (
        library_id,
        source_forms,
        input_schema,
        output_schema,
        default_capabilities,
        provider_kinds,
        projected_facts,
        validation,
    ) = match kind {
        IrEffectKind::AgentTell => (
            "std.agent",
            strings(&["tell"]),
            Some("agent.turn.request"),
            Some("AgentTurn"),
            strings(&["agent.turn"]),
            strings(&["agent"]),
            strings(&["effect.output"]),
            TypedOutputValidation::RuntimeBoundary,
        ),
        IrEffectKind::SchemaCoerce => (
            "std.coercion",
            strings(&["coerce", "decide", "prompt"]),
            Some("schema.coerce.input"),
            Some("typed-provider-output"),
            // Capability id == effect kind (spec/std-coercion.md "Static
            // checks" 1: the never-enforced `model.invoke` died with the S2
            // rename), and the provider kind is the kernel's
            // `provider::PROVIDER_SCHEMA_COERCE` ("schema_coercer") string — a
            // schema coercer, not a generic model row.
            strings(&["schema.coerce"]),
            strings(&["schema_coercer"]),
            strings(&["effect.output"]),
            TypedOutputValidation::RuntimeBoundary,
        ),
        IrEffectKind::CapabilityCall => (
            "std.script",
            strings(&["call"]),
            Some("capability.call.input"),
            Some("capability.call.output"),
            Vec::new(),
            strings(&["capability"]),
            strings(&["effect.output"]),
            TypedOutputValidation::RuntimeBoundary,
        ),
        IrEffectKind::EventEmit => (
            "std.ingress",
            strings(&["emit"]),
            Some("event.emit.input"),
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            TypedOutputValidation::None,
        ),
        IrEffectKind::WorkflowInvoke => (
            "std.workflow",
            strings(&["invoke"]),
            Some("workflow.invoke.input"),
            Some("workflow.terminal"),
            Vec::new(),
            Vec::new(),
            strings(&["effect.output"]),
            TypedOutputValidation::RuntimeBoundary,
        ),
        IrEffectKind::TimerWait => (
            "std.time",
            strings(&["timer"]),
            Some("timer.wait.input"),
            Some("TimerElapsed"),
            Vec::new(),
            Vec::new(),
            strings(&["effect.output"]),
            TypedOutputValidation::None,
        ),
        IrEffectKind::ExecCommand => (
            "std.script",
            strings(&["exec"]),
            Some("exec.command.input"),
            Some("exec.command.output"),
            strings(&["exec.run"]),
            strings(&["script", "command"]),
            strings(&["effect.output"]),
            TypedOutputValidation::RuntimeBoundary,
        ),
        // DR-0053 §5. `std.custody` is already the library a `credential`
        // declaration registers; this is its first effect kind.
        IrEffectKind::HttpRequest => (
            "std.custody",
            strings(&["request"]),
            Some("custody.request.input"),
            Some("custody.request.output"),
            strings(&["custody.request"]),
            strings(&["custodian"]),
            strings(&["effect.output"]),
            TypedOutputValidation::RuntimeBoundary,
        ),
        IrEffectKind::MintCredential => (
            "std.custody",
            strings(&["mint"]),
            Some("custody.mint.input"),
            Some("custody.mint.output"),
            strings(&["custody.mint"]),
            strings(&["custodian"]),
            strings(&["effect.output"]),
            TypedOutputValidation::RuntimeBoundary,
        ),
        IrEffectKind::TrackerFile => (
            "std.tracker",
            strings(&["file"]),
            Some("tracker.file.input"),
            None,
            strings(&["tracker.file"]),
            Vec::new(),
            Vec::new(),
            TypedOutputValidation::None,
        ),
        IrEffectKind::TrackerClaim => (
            "std.tracker",
            strings(&["claim"]),
            Some("tracker.claim.input"),
            Some("TrackerClaim"),
            strings(&["tracker.claim"]),
            Vec::new(),
            strings(&["effect.output"]),
            TypedOutputValidation::None,
        ),
        // T3: holder-only renew of a claimed issue. No typed output schema (the
        // renewed/not_held outcome is a completed/failed terminal, mirroring
        // tracker.release), so the manifest contract row folds cleanly against
        // this compiled one.
        IrEffectKind::TrackerRenew => (
            "std.tracker",
            strings(&["renew"]),
            Some("tracker.renew.input"),
            None,
            strings(&["tracker.renew"]),
            Vec::new(),
            Vec::new(),
            TypedOutputValidation::None,
        ),
        IrEffectKind::TrackerRelease => (
            "std.tracker",
            strings(&["release"]),
            Some("tracker.release.input"),
            None,
            strings(&["tracker.release"]),
            Vec::new(),
            Vec::new(),
            TypedOutputValidation::None,
        ),
        IrEffectKind::TrackerFinish => (
            "std.tracker",
            strings(&["finish"]),
            Some("tracker.finish.input"),
            None,
            strings(&["tracker.finish"]),
            Vec::new(),
            Vec::new(),
            TypedOutputValidation::None,
        ),
        IrEffectKind::LeaseAcquire => (
            "std.coord",
            strings(&["acquire"]),
            Some("lease.acquire.input"),
            Some("LeaseAcquireOutcome"),
            Vec::new(),
            Vec::new(),
            strings(&["effect.output"]),
            TypedOutputValidation::None,
        ),
        IrEffectKind::LeaseRenew => (
            "std.coord",
            strings(&["renew"]),
            Some("lease.renew.input"),
            Some("LeaseRenewOutcome"),
            Vec::new(),
            Vec::new(),
            strings(&["effect.output"]),
            TypedOutputValidation::None,
        ),
        IrEffectKind::LedgerAppend => (
            "std.coord",
            strings(&["append"]),
            Some("ledger.append.input"),
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            TypedOutputValidation::None,
        ),
        IrEffectKind::CounterConsume => (
            "std.coord",
            strings(&["consume"]),
            Some("counter.consume.input"),
            Some("CounterConsumeOutcome"),
            Vec::new(),
            Vec::new(),
            strings(&["effect.output"]),
            TypedOutputValidation::None,
        ),
        IrEffectKind::SignalEmit => (
            "std.ingress",
            strings(&["emit", "signal"]),
            Some("signal.emit.input"),
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            TypedOutputValidation::None,
        ),
        // std.files capability ids EQUAL effect kinds (spec/std-files.md, M3
        // id==kind): each contract requires exactly its own kind string, which
        // the store's default-required-capability rule already derives for an
        // empty list — declaring it here makes the registry honest about it.
        IrEffectKind::FileRead => (
            "std.files",
            strings(&["read"]),
            Some("file.read.input"),
            Some("FileReadResult"),
            strings(&["file.read"]),
            Vec::new(),
            strings(&["effect.output"]),
            TypedOutputValidation::RuntimeBoundary,
        ),
        IrEffectKind::FileWrite => (
            "std.files",
            strings(&["write"]),
            Some("file.write.input"),
            Some("FileWriteResult"),
            strings(&["file.write"]),
            Vec::new(),
            strings(&["effect.output"]),
            TypedOutputValidation::RuntimeBoundary,
        ),
        IrEffectKind::FileImport => (
            "std.files",
            strings(&["import"]),
            Some("file.import.input"),
            Some("FileImportResult"),
            strings(&["file.import"]),
            Vec::new(),
            strings(&["effect.output"]),
            TypedOutputValidation::RuntimeBoundary,
        ),
        IrEffectKind::FileExport => (
            "std.files",
            strings(&["export"]),
            Some("file.export.input"),
            Some("FileExportResult"),
            strings(&["file.export"]),
            Vec::new(),
            strings(&["effect.output"]),
            TypedOutputValidation::RuntimeBoundary,
        ),
    };

    merge_unique(&mut required_capabilities, &default_capabilities);

    EffectContract {
        id: effect_kind.clone(),
        library_id: library_id.to_owned(),
        version: "0.1.0".to_owned(),
        effect_kind,
        source_forms,
        input_schema: input_schema.map(str::to_owned),
        output_schema: output_schema.map(str::to_owned),
        required_capabilities,
        provider_kinds,
        projected_facts,
        validation,
    }
}

impl IrEffectKind {
    /// The single canonical `IrEffectKind` → effect-kind string map. Kernel and
    /// CLI delegate here (S0 dedup) so a rename touches exactly one match.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AgentTell => "agent.tell",
            Self::SchemaCoerce => "schema.coerce",
            Self::CapabilityCall => "capability.call",
            Self::EventEmit => "event.emit",
            Self::WorkflowInvoke => "workflow.invoke",
            Self::TimerWait => "timer.wait",
            Self::ExecCommand => "exec.command",
            Self::HttpRequest => "custody.request",
            Self::MintCredential => "custody.mint",
            Self::TrackerFile => "tracker.file",
            Self::TrackerClaim => "tracker.claim",
            Self::TrackerRenew => "tracker.renew",
            Self::TrackerRelease => "tracker.release",
            Self::TrackerFinish => "tracker.finish",
            Self::LeaseAcquire => "lease.acquire",
            Self::LeaseRenew => "lease.renew",
            Self::LedgerAppend => "ledger.append",
            Self::CounterConsume => "counter.consume",
            Self::SignalEmit => "signal.emit",
            Self::FileRead => "file.read",
            Self::FileWrite => "file.write",
            Self::FileImport => "file.import",
            Self::FileExport => "file.export",
        }
    }
}

impl DependencyPredicate {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Succeeds => "succeeds",
            Self::Fails => "fails",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::Completes => "completes",
        }
    }
}

impl IrUseKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Package => "package",
        }
    }
}

impl IrType {
    /// A human-readable label for this type (e.g. `ref<TicketRequest>`), for use in
    /// diagnostics such as workflow-input errors.
    pub fn display_label(&self) -> String {
        self.to_snapshot()
    }

    fn to_snapshot(&self) -> String {
        match self {
            Self::Primitive(primitive) => primitive.as_str().to_owned(),
            Self::LiteralString(value) => format!("literal<{value:?}>"),
            Self::Ref(name) => format!("ref<{name}>"),
            Self::AgentRef(agents) => format!("agentref<{}>", agents.join(" | ")),
            Self::Object(fields) => {
                let fields = fields
                    .iter()
                    .map(|field| format!("{} {}", field.name, field.ty.to_snapshot()))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("object<{{{fields}}}>")
            }
            Self::Optional(inner) => format!("optional<{}>", inner.to_snapshot()),
            Self::Array(inner) => format!("array<{}>", inner.to_snapshot()),
            Self::Map(inner) => format!("map<{}>", inner.to_snapshot()),
            Self::Sealed(inner) => format!("sealed<{}>", inner.to_snapshot()),
            Self::Union(variants) => {
                let variants = variants
                    .iter()
                    .map(Self::to_snapshot)
                    .collect::<Vec<_>>()
                    .join(" | ");
                format!("union<{variants}>")
            }
        }
    }
}

impl IrPrimitiveType {
    /// The primitive's name as source spells it, including the `secret<kind>`
    /// discriminant. Public because the kernel prints primitive names in two
    /// places and a copied table is exactly how a new kind would silently
    /// print as bare `secret` on one path and not the other.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Int => "int",
            Self::Float => "float",
            Self::Bool => "bool",
            Self::Null => "null",
            Self::Duration => "duration",
            Self::Time => "time",
            Self::Image => "image",
            Self::Audio => "audio",
            Self::Pdf => "pdf",
            Self::Video => "video",
            // Static rather than formatted so `as_str` keeps its
            // `&'static str` contract. The table is the closed
            // `CredentialKind` set spelled in source form, and the compiler
            // makes it exhaustive: a kind added to the protocol fails to
            // build here rather than silently printing as bare `secret`.
            Self::Secret(None) => "secret",
            Self::Secret(Some(kind)) => match kind {
                whipplescript_custody::CredentialKind::Bearer => "secret<bearer>",
                whipplescript_custody::CredentialKind::Basic => "secret<basic>",
                whipplescript_custody::CredentialKind::Raw => "secret<raw>",
                whipplescript_custody::CredentialKind::HmacSha256 => "secret<hmac_sha256>",
                whipplescript_custody::CredentialKind::Ed25519 => "secret<ed25519>",
                whipplescript_custody::CredentialKind::AwsSigv4 => "secret<aws_sigv4>",
                whipplescript_custody::CredentialKind::JwtRs256 => "secret<jwt_rs256>",
            },
        }
    }
}

/// Post-lowering check: a turn-access grant whose resource is a declared `file store`
/// may only grant file operations (`read`/`write`/`import`/`export`). Runs after the
/// whole program is lowered so every file-store declaration is visible regardless of
/// source order. Grants whose resource is NOT a declared file store are left alone —
/// they may be package-provided resources whose operation vocabulary lives in the
/// capability registry (validated at the construct-graph layer), so this stays
/// zero-false-positive.
fn validate_turn_access_grant_file_operations(ir: &IrProgram, diagnostics: &mut Vec<Diagnostic>) {
    const FILE_OPERATIONS: [&str; 4] = ["read", "write", "import", "export"];
    let file_stores: BTreeSet<&str> = ir
        .file_stores
        .iter()
        .map(|store| store.name.as_str())
        .collect();
    for rule in &ir.rules {
        for effect in &rule.metadata.effects {
            for grant in &effect.access_grants {
                if !file_stores.contains(grant.resource.as_str()) {
                    continue;
                }
                for op in &grant.operations {
                    if !FILE_OPERATIONS.contains(&op.operation.as_str()) {
                        diagnostics.push(Diagnostic { related: Vec::new(),
                            span: effect.span,
                            message: format!(
                                "rule `{}` grants `{}` on file store `{}`, which is not a file operation",
                                rule.name, op.operation, grant.resource
                            ),
                            suggestion: Some(
                                "file-store grants allow `read`, `write`, `import`, or `export`"
                                    .to_owned(),
                            ),
                        });
                    }
                }
            }
        }
    }
}

/// Post-lowering check: a turn-access grant whose resource is a declared `memory
/// pool` (std.memory, MEM-1) may only grant memory operations
/// (`recall`/`learn`/`curate`). Runs after the whole program is lowered so every
/// pool declaration is visible regardless of source order. Grants whose resource
/// is NOT a declared memory pool are left alone — they may be file stores or
/// package-provided resources whose operation vocabulary lives elsewhere, so this
/// stays zero-false-positive. This closes the deliberate memory-grant-validation
/// deferral (there was no declared-pool list to key it off before MEM-1).
fn validate_turn_access_grant_memory_operations(ir: &IrProgram, diagnostics: &mut Vec<Diagnostic>) {
    const MEMORY_OPERATIONS: [&str; 3] = ["recall", "learn", "curate"];
    let memory_pools: BTreeSet<&str> = ir
        .memory_pools
        .iter()
        .map(|pool| pool.name.as_str())
        .collect();
    for rule in &ir.rules {
        for effect in &rule.metadata.effects {
            for grant in &effect.access_grants {
                if !memory_pools.contains(grant.resource.as_str()) {
                    continue;
                }
                for op in &grant.operations {
                    if !MEMORY_OPERATIONS.contains(&op.operation.as_str()) {
                        diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: effect.span,
                            message: format!(
                                "rule `{}` grants `{}` on memory pool `{}`, which is not a memory operation",
                                rule.name, op.operation, grant.resource
                            ),
                            suggestion: Some(
                                "memory-pool grants allow `recall`, `learn`, or `curate`".to_owned(),
                            ),
                        });
                    }
                }
            }
        }
    }
}

/// Post-lowering check: a turn-access grant on a declared `credential` may only
/// grant operations that credential's KIND can actually perform. Runs after the
/// whole program is lowered so every credential declaration is visible
/// regardless of source order.
///
/// This is S4's argument applied to custody. `CredentialKind::supports` is
/// enforced by the custodian, which refuses the operation at runtime — so
/// before this, `credential k { kind ed25519 }` granted `unwrap` compiled
/// clean and failed in production. An ed25519 key cannot decrypt, and nothing
/// about that depends on runtime state, so the compiler is where it belongs.
///
/// A grant whose resource is not a declared credential is left alone, as its
/// file-store and memory-pool siblings do, so this stays zero-false-positive.
/// An unparseable kind is left alone too: the credential declaration's own
/// check owns that error, and reporting it twice from here would say nothing
/// new.
fn validate_turn_access_grant_credential_kinds(ir: &IrProgram, diagnostics: &mut Vec<Diagnostic>) {
    use whipplescript_custody::{CredentialKind, Operation};

    let kinds: BTreeMap<&str, &str> = ir
        .credentials
        .iter()
        .map(|credential| (credential.name.as_str(), credential.kind.as_str()))
        .collect();
    for rule in &ir.rules {
        for effect in &rule.metadata.effects {
            for grant in &effect.access_grants {
                let Some(name) = grant.resource.strip_prefix("credential ") else {
                    continue;
                };
                let Some(declared) = kinds.get(name) else {
                    continue;
                };
                let Ok(kind) = CredentialKind::parse(declared) else {
                    continue;
                };
                for op in &grant.operations {
                    let Ok(operation) = Operation::parse(&op.operation) else {
                        continue;
                    };
                    if kind.supports(operation) {
                        continue;
                    }
                    let able: Vec<&str> = [
                        CredentialKind::Bearer,
                        CredentialKind::Basic,
                        CredentialKind::Raw,
                        CredentialKind::HmacSha256,
                        CredentialKind::Ed25519,
                        CredentialKind::AwsSigv4,
                        CredentialKind::JwtRs256,
                    ]
                    .into_iter()
                    .filter(|candidate| candidate.supports(operation))
                    .map(|candidate| candidate.as_str())
                    .collect();
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: effect.span,
                        message: format!(
                            "rule `{}` grants `{}` on credential `{name}`, whose kind `{declared}` \
                             cannot perform it",
                            rule.name, op.operation
                        ),
                        suggestion: Some(format!(
                            "`{}` needs a credential of kind {}",
                            op.operation,
                            able.join(" or ")
                        )),
                    });
                }
            }
        }
    }
}

/// std.coord slice 3: a counter without a declared `timezone` anchors its
/// reset-period boundary to UTC — legal, but a daily/weekly/monthly quota
/// silently rolling over at an operator-surprising hour is worth a warning.
/// S4 (file-store default posture): a store is READ-ONLY by default — a
/// `write`/`export` against a store with no `allow write [...]` policy will
/// fail closed at runtime, so surface it as a check error here ("catch before
/// deployment"). Reads/imports need no clause (mounting the root is the read
/// consent); `allow read [...]` narrows them.
fn validate_file_store_write_policy(ir: &IrProgram, diagnostics: &mut Vec<Diagnostic>) {
    let read_only: BTreeSet<&str> = ir
        .file_stores
        .iter()
        .filter(|store| store.write_globs.is_empty())
        .map(|store| store.name.as_str())
        .collect();
    if read_only.is_empty() {
        return;
    }
    fn walk(
        statements: &[body::BodyStmt],
        rule_name: &str,
        read_only: &BTreeSet<&str>,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        for statement in statements {
            match statement {
                body::BodyStmt::Effect(effect) => {
                    let store = match &effect.kind {
                        body::BodyEffectKind::FileWrite { store, .. }
                        | body::BodyEffectKind::FileExport { store, .. } => Some(store),
                        _ => None,
                    };
                    if let Some(store) = store {
                        if read_only.contains(store.as_str()) {
                            diagnostics.push(Diagnostic {
                                related: Vec::new(),
                                span: effect.span,
                                message: format!(
                                    "rule `{rule_name}` writes to store `{store}`, which permits \
                                     no writes — stores are read-only by default"
                                ),
                                suggestion: Some(format!(
                                    "declare `allow write [\"<glob>\", …]` on `file store {store}` \
                                     to permit (and bound) writes"
                                )),
                            });
                        }
                    }
                }
                body::BodyStmt::After(after) => {
                    walk(&after.body, rule_name, read_only, diagnostics)
                }
                body::BodyStmt::Case(case) => {
                    for branch in &case.branches {
                        walk(&branch.body, rule_name, read_only, diagnostics);
                    }
                }
                _ => {}
            }
        }
    }
    for rule in &ir.rules {
        let (ast, _) = body::parse_rule_body(&rule.body, 0);
        walk(&ast.statements, &rule.name, &read_only, diagnostics);
    }
}

/// S6 `emit <signal> from <binding>` (source declarations): expand the
/// projection into concrete emit fields once every declaration has lowered
/// (the signal may be declared after the source). Each of the signal's
/// declared fields not overridden by the block becomes a copy off the `from`
/// binding — the `record … from` semantics. The `from` binding must be the
/// source's `observe` binding: it is the only binding in scope.
fn expand_source_emit_from(ir: &mut IrProgram, diagnostics: &mut Vec<Diagnostic>) {
    let events: BTreeMap<String, Vec<String>> = ir
        .events
        .iter()
        .map(|event| {
            (
                event.name.clone(),
                event
                    .fields
                    .iter()
                    .map(|field| field.name.clone())
                    .collect(),
            )
        })
        .collect();
    for source in &mut ir.sources {
        let Some(from) = source.emit_from.clone() else {
            continue;
        };
        if from != source.observe_binding {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: source.span,
                message: format!(
                    "source `{}` emits `from {from}`, but the only binding in scope is the observe binding `{}`",
                    source.name, source.observe_binding
                ),
                suggestion: Some(format!("write `emit {} from {}`", source.emit_signal, source.observe_binding)),
            });
            continue;
        }
        let Some(signal_fields) = events.get(&source.emit_signal) else {
            // The undeclared-signal diagnostic is reported by the emit checks.
            continue;
        };
        for field in signal_fields {
            if source
                .emit_fields
                .iter()
                .any(|existing| &existing.name == field)
            {
                continue;
            }
            source.emit_fields.push(IrSourceEmitField {
                name: field.clone(),
                value: SourceValue::Path {
                    binding: Ident {
                        name: from.clone(),
                        span: source.span,
                    },
                    segments: vec![Ident {
                        name: field.clone(),
                        span: source.span,
                    }],
                    span: source.span,
                },
                span: source.span,
            });
        }
    }
}

/// Auto-fail R1a — partiality made visible: an effect whose failure has no
/// observing `after` block in its rule will auto-fail the instance at runtime
/// (the rule-level net). That is SAFE, but the "handles only `succeeds`" signal
/// is load-bearing enough to surface prominently at check time — a warning, not
/// a buried lint advisory. `@service` workflows are exempt (they record a
/// durable diagnostic and keep running, so the auto-fail framing would be
/// wrong), timers are exempt (they cannot fail), and the compile-time observer
/// set is deliberately WIDER than the runtime net's: coordination outcome
/// predicates (`held`/`contended`/`ok`/`over`) count as observers here so
/// ordinary coordination code stays quiet, while the runtime net still catches
/// a genuine op failure underneath them.
fn warn_unhandled_effect_failures(ir: &IrProgram, warnings: &mut Vec<Diagnostic>) {
    let service = ir
        .source_tags
        .iter()
        .any(|tag| tag.target_kind == "workflow" && tag.name == "service");
    if service {
        return;
    }
    for rule in &ir.rules {
        for effect in &rule.metadata.effects {
            let Some(binding) = effect.binding.as_deref() else {
                continue;
            };
            if effect.kind == IrEffectKind::TimerWait {
                continue;
            }
            // A `then`-chained effect (synthetic `__then_*` handle) is an
            // explicit opt-in to auto-fail on failure (R2) — never a warning.
            if binding.starts_with(then_expand::THEN_BINDING_PREFIX) {
                continue;
            }
            let observed = rule.body.lines().any(|line| {
                let Some(rest) = line.trim().strip_prefix("after ") else {
                    return false;
                };
                let mut parts = rest.split_whitespace();
                if parts.next() != Some(binding) {
                    return false;
                }
                // `times` only occurs as the two-token predicate `times out`.
                matches!(
                    parts.next().map(|token| token.trim_end_matches('{')),
                    Some(
                        "fails"
                            | "times"
                            | "completes"
                            | "held"
                            | "contended"
                            | "ok"
                            | "over"
                            | "promoted"
                            | "conflicted"
                    )
                )
            });
            if observed {
                continue;
            }
            warnings.push(Diagnostic {
                related: Vec::new(),
                span: effect.span,
                message: format!(
                    "effect `{binding}`'s failure is unhandled in rule `{}`; if it fails or \
                     times out, the instance will auto-fail with a generic reason",
                    rule.name
                ),
                suggestion: Some(format!(
                    "handle it with `after {binding} fails {{ … }}` (typed failure or recovery) \
                     or observe every outcome with `after {binding} completes`"
                )),
            });
        }
    }
}

fn warn_counter_without_timezone(ir: &IrProgram, warnings: &mut Vec<Diagnostic>) {
    for counter in &ir.counters {
        if counter.timezone.is_none() {
            warnings.push(Diagnostic {
                related: Vec::new(),
                span: counter.span,
                message: format!(
                    "counter `{}` declares no `timezone`; its `{}` reset boundary anchors to UTC",
                    counter.name, counter.reset
                ),
                suggestion: Some(
                    "declare `timezone \"<IANA zone>\"` (e.g. `timezone \"America/New_York\"`) to anchor the period locally"
                        .to_owned(),
                ),
            });
        }
    }
}

/// MEM-5 static check 4: a memory-pool grant on a `tell` whose agent runs a
/// NATIVE adapter (codex/claude/command) is inert — only the owned harness
/// exposes the granted memory tools. Warn instead of silently dropping the
/// author's intent (the inert-grant honesty the design eliminates).
fn warn_inert_memory_grant_on_native_adapter(ir: &IrProgram, warnings: &mut Vec<Diagnostic>) {
    let memory_pools: BTreeSet<&str> = ir
        .memory_pools
        .iter()
        .map(|pool| pool.name.as_str())
        .collect();
    if memory_pools.is_empty() {
        return;
    }
    let harness_kind_of: BTreeMap<&str, &str> = ir
        .harnesses
        .iter()
        .map(|harness| (harness.name.as_str(), harness.kind.as_str()))
        .collect();
    let agent_harness_kind: BTreeMap<&str, &str> = ir
        .agents
        .iter()
        .filter_map(|agent| {
            let harness = agent.harness.as_deref()?;
            Some((agent.name.as_str(), *harness_kind_of.get(harness)?))
        })
        .collect();
    for rule in &ir.rules {
        for effect in &rule.metadata.effects {
            let Some(agent) = effect.agent.as_deref() else {
                continue;
            };
            let Some(kind) = agent_harness_kind.get(agent) else {
                continue;
            };
            if !matches!(*kind, "codex" | "claude" | "command") {
                continue;
            }
            for grant in &effect.access_grants {
                if memory_pools.contains(grant.resource.as_str()) {
                    warnings.push(Diagnostic {
                        related: Vec::new(),
                        span: effect.span,
                        message: format!(
                            "rule `{}` grants memory pool `{}` on a tell to `{agent}`, whose \
                             harness kind `{kind}` is a native adapter — memory grants only \
                             take effect on the owned harness, so this grant is inert",
                            rule.name, grant.resource
                        ),
                        suggestion: Some(
                            "target an owned-harness agent, or drop the memory grant".to_owned(),
                        ),
                    });
                }
            }
        }
    }
}

/// Detect recursive pattern application over the pattern-declaration graph and
/// emit `graph.unbounded_pattern_recursion` (severity error) for each expansion
/// cycle, naming the cycle. Returns the set of patterns that participate in a
/// cycle so the caller can suppress the generic "nested apply" message for them.
///
/// A pattern's body that `apply`s another pattern is an edge; a pattern that can
/// reach itself (directly via a self-apply, or transitively) cannot elaborate into
/// a finite first-order program, so v0 rejects it (spec/static-analysis.md). The
/// reachability closure mirrors `models/maude/pattern-recursion.maude`.
fn detect_pattern_recursion(
    patterns: &BTreeMap<String, PatternDecl>,
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeSet<String> {
    // Application edges: pattern name -> the patterns its body applies, with spans.
    let mut edges: BTreeMap<&str, Vec<(&str, SourceSpan)>> = BTreeMap::new();
    for pattern in patterns.values() {
        let mut applied = Vec::new();
        for item in &pattern.items {
            if let Item::Apply(apply) = item {
                applied.push((apply.pattern.name.as_str(), apply.span));
            }
        }
        edges.insert(pattern.name.name.as_str(), applied);
    }

    // A pattern is recursive iff it can reach itself. Find a shortest cycle path
    // back to `start` via breadth-first search, tracking each node's predecessor.
    let find_cycle = |start: &str| -> Option<(Vec<String>, SourceSpan)> {
        let mut queue: VecDeque<&str> = VecDeque::new();
        // predecessor[node] = (came_from, span_of_edge) used to first reach `node`.
        let mut predecessor: BTreeMap<&str, (&str, SourceSpan)> = BTreeMap::new();
        for &(target, span) in edges.get(start).into_iter().flatten() {
            if target == start {
                // Direct self-application.
                return Some((vec![start.to_owned(), start.to_owned()], span));
            }
            if predecessor.insert(target, (start, span)).is_none() {
                queue.push_back(target);
            }
        }
        while let Some(node) = queue.pop_front() {
            for &(target, span) in edges.get(node).into_iter().flatten() {
                if target == start {
                    // Reconstruct start -> ... -> node, then close back to start.
                    let mut path = vec![node.to_owned()];
                    let mut cursor = node;
                    while cursor != start {
                        let (from, _) = predecessor[cursor];
                        path.push(from.to_owned());
                        cursor = from;
                    }
                    path.reverse();
                    path.push(start.to_owned());
                    // Report at the first apply edge of `start` that enters the cycle.
                    let first = &path[1];
                    let entry_span = edges
                        .get(start)
                        .into_iter()
                        .flatten()
                        .find(|(target, _)| target == first)
                        .map(|(_, span)| *span)
                        .unwrap_or(span);
                    return Some((path, entry_span));
                }
                if predecessor.insert(target, (node, span)).is_none() {
                    queue.push_back(target);
                }
            }
        }
        None
    };

    let mut recursive = BTreeSet::new();
    // Iterate patterns in declaration-name order for deterministic diagnostics, and
    // report each cycle once by skipping members already covered by a prior cycle.
    for name in patterns.keys() {
        if recursive.contains(name) {
            continue;
        }
        if let Some((cycle, span)) = find_cycle(name) {
            for member in &cycle {
                recursive.insert(member.clone());
            }
            diagnostics.push(Diagnostic { related: Vec::new(),
                span,
                message: format!(
                    "recursive pattern application is not allowed (graph.unbounded_pattern_recursion): expansion cycle {}",
                    cycle.join(" -> ")
                ),
                suggestion: Some(
                    "break the cycle: pattern expansion must elaborate into a finite program"
                        .to_owned(),
                ),
            });
        }
    }
    recursive
}

/// Reject a *transitive* runtime workflow-invocation cycle (A invokes B invokes A,
/// or longer). RESOLVED 2026-07-01: the invoke-recursion policy is "as permissive
/// as provable convergence at compile time allows"; whipplescript has no
/// convergence proof for runtime `invoke` recursion (termination is data-dependent
/// and there is no decreasing-measure mechanism yet), so — exactly parallel to
/// `detect_pattern_recursion` — any cycle is rejected as
/// `graph.unbounded_workflow_invocation_recursion`. Direct self-invocation (a cycle
/// of length 1) is already rejected per-rule in `validate_workflow_invocations`, so
/// self-edges are excluded here and this catches only length >= 2 cycles. Modeled
/// as invoke-graph non-convergence in `models/maude/subworkflow-convergence.maude`.
fn detect_workflow_invoke_recursion(program: &Program, diagnostics: &mut Vec<Diagnostic>) {
    // Invoke edges: workflow name -> the workflows its rules invoke, with the span
    // of the invoking rule body. Built over the raw AST (all workflows), so it is
    // independent of root selection. Self-edges are excluded (owned by the direct
    // per-rule recursion check).
    let mut edges: BTreeMap<String, Vec<(String, SourceSpan)>> = BTreeMap::new();
    let record_invokes =
        |name: &str, items: &[Item], edges: &mut BTreeMap<String, Vec<(String, SourceSpan)>>| {
            let entry = edges.entry(name.to_owned()).or_default();
            for item in items {
                let Item::Rule(rule) = item else {
                    continue;
                };
                for statement in workflow_invoke_statements(&rule.body.text) {
                    if let Some((target, _)) = invoke_statement_parts(&statement) {
                        if target != name {
                            entry.push((target.to_owned(), rule.body.span));
                        }
                    }
                }
            }
        };
    if let Some(root) = &program.workflow {
        record_invokes(&root.name, &program.items, &mut edges);
    }
    for workflow in &program.workflows {
        record_invokes(&workflow.name.name, &workflow.items, &mut edges);
    }

    // A workflow is in a cycle iff it can reach itself over invoke edges. BFS for a
    // shortest path back to `start` (mirrors `detect_pattern_recursion`).
    let find_cycle = |start: &str| -> Option<(Vec<String>, SourceSpan)> {
        let mut queue: VecDeque<&str> = VecDeque::new();
        let mut predecessor: BTreeMap<&str, (&str, SourceSpan)> = BTreeMap::new();
        for (target, span) in edges.get(start).into_iter().flatten() {
            if predecessor
                .insert(target.as_str(), (start, *span))
                .is_none()
            {
                queue.push_back(target.as_str());
            }
        }
        while let Some(node) = queue.pop_front() {
            for (target, span) in edges.get(node).into_iter().flatten() {
                if target == start {
                    let mut path = vec![node.to_owned()];
                    let mut cursor = node;
                    while cursor != start {
                        let (from, _) = predecessor[cursor];
                        path.push(from.to_owned());
                        cursor = from;
                    }
                    path.reverse();
                    path.push(start.to_owned());
                    let first = &path[1];
                    let entry_span = edges
                        .get(start)
                        .into_iter()
                        .flatten()
                        .find(|(target, _)| target == first)
                        .map(|(_, span)| *span)
                        .unwrap_or(*span);
                    return Some((path, entry_span));
                }
                if predecessor.insert(target.as_str(), (node, *span)).is_none() {
                    queue.push_back(target.as_str());
                }
            }
        }
        None
    };

    let mut flagged: BTreeSet<String> = BTreeSet::new();
    for name in edges.keys() {
        if flagged.contains(name) {
            continue;
        }
        if let Some((cycle, span)) = find_cycle(name) {
            for member in &cycle {
                flagged.insert(member.clone());
            }
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span,
                message: format!(
                    "recursive workflow invocation is not allowed (graph.unbounded_workflow_invocation_recursion): invocation cycle {}",
                    cycle.join(" -> ")
                ),
                suggestion: Some(
                    "break the cycle: a runtime `invoke` cycle has no compile-time convergence proof; route the recurrence through an external event, clock, or durable boundary instead"
                        .to_owned(),
                ),
            });
        }
    }
}

fn detect_private_workflow_invocations(program: &Program, diagnostics: &mut Vec<Diagnostic>) {
    let private_workflows = workflows_tagged(program, "private");
    if private_workflows.is_empty() {
        return;
    }

    let mut record_private_invokes = |caller: &str, items: &[Item]| {
        for item in items {
            let Item::Rule(rule) = item else {
                continue;
            };
            for statement in workflow_invoke_statements(&rule.body.text) {
                let Some((target, _)) = invoke_statement_parts(&statement) else {
                    continue;
                };
                if caller == target || !private_workflows.contains(target) {
                    continue;
                }
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: rule.body.span,
                    message: format!(
                        "rule `{}` invokes private workflow `{target}`",
                        rule.name.name
                    ),
                    suggestion: Some(
                        "remove `@private` from the target workflow or expose a public wrapper workflow"
                            .to_owned(),
                    ),
                });
            }
        }
    };

    if let Some(root) = &program.workflow {
        record_private_invokes(&root.name, &program.items);
    }
    for workflow in &program.workflows {
        record_private_invokes(&workflow.name.name, &workflow.items);
    }
}

/// Every workflow in the bundle carrying `<tag>`, in BOTH declaration forms.
///
/// The two forms store their tags in different places — a header-form workflow
/// (`@service` / `workflow Name` at the top level, with the file's items as its
/// body) on `Program::workflow_tags`, a block-form workflow on
/// `WorkflowDecl::tags` — and a callee-side check that reads only
/// `program.workflows` silently never fires on the header form. That blind spot
/// was live in `detect_private_workflow_invocations`, which is why this is a
/// shared helper rather than a line copied into each caller.
fn workflows_tagged<'a>(program: &'a Program, tag: &str) -> BTreeSet<&'a str> {
    let mut tagged = BTreeSet::new();
    if let Some(root) = &program.workflow {
        if program.workflow_tags.iter().any(|decl| decl.name == tag) {
            tagged.insert(root.name.as_str());
        }
    }
    for workflow in &program.workflows {
        if workflow.tags.iter().any(|decl| decl.name == tag) {
            tagged.insert(workflow.name.name.as_str());
        }
    }
    tagged
}

/// Reject a synchronous `invoke` of a `@service` workflow: the parent awaits a
/// terminal the callee does not promise to reach.
///
/// `spec/execution-contract.md` states the seam — "the parent observes typed
/// terminal output". `@service` is the source-level declaration that a workflow
/// is NOT required to terminate: it is precisely the escape from the liveness
/// check that otherwise demands a rule reaching `complete` or `fail`.
///
/// Note what the tag does NOT mean. It is not a proof of non-termination, and a
/// `@service` workflow with a completing rule reaches a terminal perfectly well
/// at run time — the kernel's `workflow_is_service` governs only the auto-fail
/// net, never the author's own `complete`. So the refusal rests on the missing
/// PROMISE, not on a claim about what the callee will do. A caller that blocks
/// on a terminal has nothing to hold the callee to, and if the terminal does not
/// come, the instance stalls non-terminal with nothing to catch it: the
/// unhandled-failure net observes an effect that reached a FAILURE terminal, and
/// here nothing fails — nothing settles at all.
///
/// This is the rule the agent-tool seam already applies, on the tag alone and
/// for the same reason: `lint_workflow_liveness` rejects a granted `@tool` that
/// is also `@service` with "a `@tool` workflow must terminate", whether or not
/// it happens to carry a completing rule. The argument is about awaiting a
/// callee that declines to promise termination, not about tools, so it holds
/// identically at the `invoke` seam — where, until now, nothing applied it.
/// Non-termination stays a privilege of the ROOT: this refuses being *awaited*,
/// never being tagged.
fn detect_service_workflow_invocations(program: &Program, diagnostics: &mut Vec<Diagnostic>) {
    let service_workflows = workflows_tagged(program, "service");
    if service_workflows.is_empty() {
        return;
    }

    let mut record_service_invokes = |caller: &str, items: &[Item]| {
        for item in items {
            let Item::Rule(rule) = item else {
                continue;
            };
            for statement in workflow_invoke_statements(&rule.body.text) {
                let Some((target, _)) = invoke_statement_parts(&statement) else {
                    continue;
                };
                // Direct self-invocation is refused per-rule already; leaving it
                // here would double-report the same line.
                if caller == target || !service_workflows.contains(target) {
                    continue;
                }
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: rule.body.span,
                    message: format!(
                        "rule `{}` invokes `{target}`, which is tagged `@service` (graph.invoke_awaits_service_workflow): `@service` declares that a workflow need not terminate, and an invocation awaits its terminal output",
                        rule.name.name
                    ),
                    suggestion: Some(
                        "remove `@service` from the target if it does terminate — non-termination is a root-only privilege, not for an awaited sub-workflow; to hand work to a genuinely long-running service, emit a signal or event it observes instead of awaiting it"
                            .to_owned(),
                    ),
                });
            }
        }
    };

    if let Some(root) = &program.workflow {
        record_service_invokes(&root.name, &program.items);
    }
    for workflow in &program.workflows {
        record_service_invokes(&workflow.name.name, &workflow.items);
    }
}

/// Whether `text` names `identifier` at a word boundary.
///
/// Used to ask whether a rule body references an agent at all. A substring test
/// would let `worker` match `worker_pool`; the boundary check keeps the question
/// honest without needing to parse the body, which at this stage is still text.
fn mentions_identifier(text: &str, identifier: &str) -> bool {
    if identifier.is_empty() {
        return false;
    }
    let boundary = |candidate: Option<char>| {
        candidate.is_none_or(|character| !character.is_alphanumeric() && character != '_')
    };
    let mut rest = text;
    let mut consumed = 0usize;
    while let Some(offset) = rest.find(identifier) {
        let start = consumed + offset;
        let end = start + identifier.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        if boundary(before) && boundary(after) {
            return true;
        }
        let step = offset + identifier.len();
        consumed += step;
        rest = &rest[step..];
    }
    false
}

/// The invoke-tool graph must be acyclic (DR-0025).
///
/// An agent's `tools [...]` grant lets the model call that workflow
/// synchronously inside a turn, and the called workflow's own agents may call
/// on in turn. A cycle in that graph is unbounded recursion depth with no
/// compile-time convergence proof — the same condition, for the same reason,
/// that `detect_workflow_invoke_recursion` rejects at the `invoke` seam.
///
/// `models/maude/subworkflow-convergence.maude` has modeled the invariant since
/// DR-0025 (rule `cycle`, over the `invokes` edge) and `docs/guarantees.md`
/// states it, but nothing built the graph: `resolve_same_bundle_tool_grant`
/// checks one granted target in ISOLATION — is it `@tool`, is it locally
/// convergent — and never reads that target's own grants. So a `@tool` workflow
/// whose own agent granted it back, or granted itself, compiled clean.
///
/// SCOPE — same-bundle edges only, deliberately. A granted name that resolves to
/// no workflow in this bundle contributes no edge and no diagnostic here: it may
/// name a package export (whose convergence is checked when the manifest is
/// attested), or nothing at all, and an unresolvable grant is
/// `lint_agent_tool_grants`'s refusal to make, with the package lock in hand.
/// This pass answers only the question the bundle can answer alone.
///
/// AGENT SCOPE mirrors `select_root_workflow`: an item declared at the top level
/// is global — that function splices `program.items` into whichever workflow is
/// selected — so a top-level agent is in scope for EVERY workflow in the bundle,
/// not just for the header-form root.
///
/// Being in scope is not enough to make an EDGE, though, and treating it as
/// enough reports a cycle that cannot happen. An agent that a workflow never
/// tells anything runs no turn there, and a turn is the only thing that can call
/// a granted tool. A shared top-level agent granted `tools [Alpha]`, in a bundle
/// that also declares `Alpha`, therefore produced a phantom `Alpha -> Alpha`
/// even when `Alpha` never touches that agent. So an agent contributes its
/// grants to `W` only when some rule in `W`'s scope names it.
///
/// The name test is deliberately loose — any word-boundary mention in a rule
/// body, not just a `tell` target — because the safe direction here is to keep
/// an edge, not to drop one. Its one real limit is a purely dynamic route
/// (`tell incident.assignee`, where the agent is named by a table row rather
/// than by the rule): the rule body never spells the agent, so no edge forms.
/// Routing a tool-granting agent that way is exotic, and the alternative — every
/// in-scope agent for every workflow — trades that narrow miss for false
/// refusals of ordinary programs.
fn detect_agent_tool_grant_recursion(program: &Program, diagnostics: &mut Vec<Diagnostic>) {
    let mut workflow_names: BTreeSet<&str> = BTreeSet::new();
    if let Some(root) = &program.workflow {
        workflow_names.insert(root.name.as_str());
    }
    for workflow in &program.workflows {
        workflow_names.insert(workflow.name.name.as_str());
    }
    if workflow_names.is_empty() {
        return;
    }

    // The grants of every agent in `items`, each paired with the agent's name so
    // the caller can ask whether the workflow actually uses it.
    let granted_tools = |items: &[Item]| -> Vec<(String, String, SourceSpan)> {
        let mut granted = Vec::new();
        for item in items {
            let Item::Agent(agent) = item else {
                continue;
            };
            for field in &agent.fields {
                if let AgentField::Tools(tools, span) = field {
                    for tool in tools {
                        granted.push((agent.name.name.clone(), tool.name.clone(), *span));
                    }
                }
            }
        }
        granted
    };
    fn rule_bodies(items: &[Item]) -> Vec<&str> {
        items
            .iter()
            .filter_map(|item| match item {
                Item::Rule(rule) => Some(rule.body.text.as_str()),
                _ => None,
            })
            .collect()
    }

    // Global grants first, then the workflow's own block-local agents. A grant
    // that names nothing in this bundle is dropped here, per SCOPE above.
    let global = granted_tools(&program.items);
    let global_bodies = rule_bodies(&program.items);
    let mut edges: BTreeMap<&str, Vec<(&str, SourceSpan)>> = BTreeMap::new();
    for name in &workflow_names {
        let mut outgoing = global.clone();
        // Top-level rules are global for the same reason top-level agents are.
        let mut bodies = global_bodies.clone();
        if let Some(workflow) = program
            .workflows
            .iter()
            .find(|workflow| workflow.name.name == *name)
        {
            outgoing.extend(granted_tools(&workflow.items));
            bodies.extend(rule_bodies(&workflow.items));
        }
        let outgoing = outgoing
            .into_iter()
            .filter(|(agent, _, _)| bodies.iter().any(|body| mentions_identifier(body, agent)))
            .map(|(_, target, span)| (target, span))
            .collect::<Vec<_>>();
        let resolved = outgoing
            .into_iter()
            .filter_map(|(target, span)| {
                workflow_names
                    .get(target.as_str())
                    .map(|resolved| (*resolved, span))
            })
            .collect::<Vec<_>>();
        edges.insert(name, resolved);
    }

    // BFS back to `start`, mirroring `detect_workflow_invoke_recursion`. Unlike
    // that one, a SELF edge is a cycle here and must be reported: a workflow
    // granting itself as a tool is caught by no other check, whereas direct
    // self-`invoke` is already refused per-rule.
    let find_cycle = |start: &str| -> Option<(Vec<String>, SourceSpan)> {
        let mut queue: VecDeque<&str> = VecDeque::new();
        let mut predecessor: BTreeMap<&str, (&str, SourceSpan)> = BTreeMap::new();
        for (target, span) in edges.get(start).into_iter().flatten() {
            if *target == start {
                return Some((vec![start.to_owned(), start.to_owned()], *span));
            }
            if predecessor.insert(target, (start, *span)).is_none() {
                queue.push_back(target);
            }
        }
        while let Some(node) = queue.pop_front() {
            for (target, span) in edges.get(node).into_iter().flatten() {
                if *target == start {
                    let mut path = vec![node.to_owned()];
                    let mut cursor = node;
                    while cursor != start {
                        let (from, _) = predecessor[cursor];
                        path.push(from.to_owned());
                        cursor = from;
                    }
                    path.reverse();
                    path.push(start.to_owned());
                    let entry_span = edges
                        .get(start)
                        .into_iter()
                        .flatten()
                        .find(|(target, _)| *target == path[1])
                        .map(|(_, span)| *span)
                        .unwrap_or(*span);
                    return Some((path, entry_span));
                }
                if predecessor.insert(target, (node, *span)).is_none() {
                    queue.push_back(target);
                }
            }
        }
        None
    };

    let mut flagged: BTreeSet<String> = BTreeSet::new();
    for name in edges.keys() {
        if flagged.contains(*name) {
            continue;
        }
        if let Some((cycle, span)) = find_cycle(name) {
            for member in &cycle {
                flagged.insert(member.clone());
            }
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span,
                message: format!(
                    "recursive agent tool grant is not allowed (graph.unbounded_tool_grant_recursion): invoke-tool cycle {}",
                    cycle.join(" -> ")
                ),
                suggestion: Some(
                    "break the cycle: an agent may call a granted `@tool` workflow synchronously, so a cycle in the grant graph has unbounded recursion depth and no compile-time convergence proof"
                        .to_owned(),
                ),
            });
        }
    }
}

fn expand_pattern_applications(
    mut program: Program,
    diagnostics: &mut Vec<Diagnostic>,
) -> (Program, Vec<IrPatternApplication>) {
    let mut patterns = BTreeMap::new();
    for pattern in &program.patterns {
        if patterns
            .insert(pattern.name.name.clone(), pattern.clone())
            .is_some()
        {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: pattern.name.span,
                message: format!("pattern `{}` is declared more than once", pattern.name.name),
                suggestion: Some("rename one pattern declaration".to_owned()),
            });
        }
    }

    // v0 forbids recursive pattern application (spec/static-analysis.md,
    // graph.unbounded_pattern_recursion): an `apply` that reaches, directly or
    // transitively, a pattern already on the active expansion stack can never
    // elaborate into a finite first-order program. Detect cycles up front so the
    // precise diagnostic is emitted and the generic "nested apply not supported
    // yet" message is suppressed for the recursive case.
    let recursive_patterns = detect_pattern_recursion(&patterns, diagnostics);

    let mut expanded_items = Vec::new();
    let mut applications = Vec::new();
    for item in program.items {
        let Item::Apply(apply) = item else {
            expanded_items.push(item);
            continue;
        };
        let Some(pattern) = patterns.get(&apply.pattern.name) else {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: apply.pattern.span,
                message: format!("pattern `{}` was not found", apply.pattern.name),
                suggestion: Some("declare the pattern before applying it".to_owned()),
            });
            continue;
        };
        if pattern.type_params.len() != apply.type_args.len() {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: apply.span,
                message: format!(
                    "pattern `{}` expects {} type arguments but got {}",
                    pattern.name.name,
                    pattern.type_params.len(),
                    apply.type_args.len()
                ),
                suggestion: Some("match the pattern type parameter list".to_owned()),
            });
            continue;
        }
        let type_substitutions = pattern
            .type_params
            .iter()
            .map(|param| param.name.clone())
            .zip(apply.type_args.iter().cloned())
            .collect::<BTreeMap<_, _>>();
        let value_substitutions = parse_pattern_value_arguments(&apply, diagnostics);
        let local_names = pattern_local_names(pattern, &apply.alias.name);
        let definition_span = pattern.span;
        let application_span = apply.span;
        let mut generated = Vec::new();
        for pattern_item in pattern.items.iter().cloned() {
            // Enforce the pattern-body allow-list before expanding: a pattern
            // is a compile-time reuse fragment, not a workflow, so forbidden
            // constructs are rejected with a clear diagnostic and dropped.
            if let Some(diagnostic) = pattern_body_admission(&pattern_item, &recursive_patterns) {
                diagnostics.push(diagnostic);
                continue;
            }
            if let Some((generated_name, item)) = expand_pattern_item(
                pattern_item,
                &apply.alias.name,
                &type_substitutions,
                &value_substitutions,
                &local_names,
            ) {
                generated.push(generated_name);
                expanded_items.push(item);
            }
        }
        applications.push(IrPatternApplication {
            pattern: pattern.name.name.clone(),
            alias: apply.alias.name,
            type_args: apply.type_args.into_iter().map(lower_type).collect(),
            value_args: value_substitutions
                .into_iter()
                .map(|(name, value)| IrPatternArgument { name, value })
                .collect(),
            generated,
            definition_span,
            application_span,
        });
    }
    program.items = expanded_items;
    (program, applications)
}

fn pattern_local_names(pattern: &PatternDecl, alias: &str) -> BTreeMap<String, String> {
    let mut names = BTreeMap::new();
    for item in &pattern.items {
        match item {
            Item::Harness(harness) => {
                names.insert(
                    harness.name.name.clone(),
                    generated_pattern_name(alias, &harness.name.name),
                );
            }
            Item::Agent(agent) => {
                names.insert(
                    agent.name.name.clone(),
                    generated_pattern_name(alias, &agent.name.name),
                );
            }
            Item::Enum(enum_decl) => {
                names.insert(
                    enum_decl.name.name.clone(),
                    generated_pattern_name(alias, &enum_decl.name.name),
                );
            }
            Item::Class(class_decl) => {
                names.insert(
                    class_decl.name.name.clone(),
                    generated_pattern_name(alias, &class_decl.name.name),
                );
            }
            Item::Coerce(coerce) => {
                names.insert(
                    coerce.name.name.clone(),
                    generated_pattern_name(alias, &coerce.name.name),
                );
            }
            Item::Rule(rule) => {
                names.insert(
                    rule.name.name.clone(),
                    generated_pattern_name(alias, &rule.name.name),
                );
            }
            _ => {}
        }
    }
    names
}

fn generated_pattern_name(alias: &str, name: &str) -> String {
    format!("{alias}_{name}")
}

fn parse_pattern_value_arguments(
    apply: &ApplyDecl,
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeMap<String, String> {
    let mut args = BTreeMap::new();
    for line in apply
        .body
        .text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let mut parts = line.splitn(2, char::is_whitespace);
        let Some(name) = parts.next().filter(|name| is_identifier(name)) else {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: apply.body.span,
                message: format!(
                    "pattern application `{}` has malformed argument `{line}`",
                    apply.alias.name
                ),
                suggestion: Some("write pattern arguments as `name value`".to_owned()),
            });
            continue;
        };
        let Some(value) = parts
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: apply.body.span,
                message: format!(
                    "pattern application `{}` argument `{name}` is missing a value",
                    apply.alias.name
                ),
                suggestion: Some("write pattern arguments as `name value`".to_owned()),
            });
            continue;
        };
        if args.insert(name.to_owned(), value.to_owned()).is_some() {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: apply.body.span,
                message: format!(
                    "pattern application `{}` passes argument `{name}` more than once",
                    apply.alias.name
                ),
                suggestion: Some("remove the duplicate pattern argument".to_owned()),
            });
        }
    }
    args
}

/// The explicit allow-list gate for a `pattern { ... }` body.
///
/// A pattern is a compile-time reuse fragment, not a workflow. Its body MAY
/// declare the building blocks of a workflow -- rules, effects (`coerce`),
/// records (via a rule's `record`), local schemas (`class`/`enum`), tables,
/// agents/harnesses, and coordination resources -- but it MUST NOT contain:
///   * workflow contracts (`input`/`output`/`failure`) -- workflow-level shape,
///   * nested `pattern` declarations,
///   * nested `apply` (pattern applications inside pattern bodies), or
///   * rules that reach a workflow terminal (`complete`/`fail`): a reusable
///     fragment must not hard-code the enclosing workflow's terminal outcome.
///
/// Returns `Some(diagnostic)` for a forbidden construct; `None` when the item is
/// on the allow-list.
fn pattern_body_admission(
    item: &Item,
    recursive_patterns: &BTreeSet<String>,
) -> Option<Diagnostic> {
    match item {
        Item::WorkflowContract(contract) => Some(Diagnostic {
            related: Vec::new(),
            span: contract.span,
            message: "workflow contracts are not allowed in pattern bodies".to_owned(),
            suggestion: Some(
                "declare workflow inputs, outputs, and failures on the workflow".to_owned(),
            ),
        }),
        Item::Pattern(pattern) => Some(Diagnostic {
            related: Vec::new(),
            span: pattern.span,
            message: "nested pattern declarations are not supported in pattern bodies".to_owned(),
            suggestion: Some("declare reusable patterns at source top level".to_owned()),
        }),
        // A recursive nested apply was already rejected with the precise
        // graph.unbounded_pattern_recursion diagnostic by detect_pattern_recursion;
        // don't also emit the generic "not supported yet" message for it.
        Item::Apply(apply) if !recursive_patterns.contains(&apply.pattern.name) => Some(Diagnostic {
            related: Vec::new(),
            span: apply.span,
            message: "pattern applications inside pattern bodies are not supported yet".to_owned(),
            suggestion: Some(
                "apply patterns from workflow bodies only in this implementation slice".to_owned(),
            ),
        }),
        // Objective intent is top-level: a gauge binds a judge to this
        // program's sites and a campaign partitions this program's gauge
        // vector — neither is a reusable template fragment.
        Item::Gauge(gauge) => Some(Diagnostic {
            related: Vec::new(),
            span: gauge.span,
            message: "gauge declarations are not allowed in pattern bodies".to_owned(),
            suggestion: Some("declare gauges at source top level".to_owned()),
        }),
        Item::Campaign(campaign) => Some(Diagnostic {
            related: Vec::new(),
            span: campaign.span,
            message: "campaign declarations are not allowed in pattern bodies".to_owned(),
            suggestion: Some("declare campaigns at source top level".to_owned()),
        }),
        Item::Mark(mark) => Some(Diagnostic {
            related: Vec::new(),
            span: mark.span,
            message: "mark declarations are not allowed in pattern bodies".to_owned(),
            suggestion: Some("declare marks at source top level".to_owned()),
        }),
        Item::Rule(rule) => pattern_rule_terminal_span(rule).map(|span| Diagnostic {
            related: Vec::new(),
            span,
            message: format!(
                "rule `{}` in a pattern body cannot reach a workflow terminal (`complete`/`fail`)",
                rule.name.name
            ),
            suggestion: Some(
                "record a fact in the pattern rule and let a workflow rule decide the terminal outcome"
                    .to_owned(),
            ),
        }),
        _ => None,
    }
}

/// Locate the first workflow-terminal statement (`complete`/`fail`) in a
/// pattern rule body, returning its source span for diagnostics.
fn pattern_rule_terminal_span(rule: &RuleDecl) -> Option<SourceSpan> {
    let mut offset = 0usize;
    for line in rule.body.text.split_inclusive('\n') {
        let trimmed_start = line.trim_start();
        let leading = line.len() - trimmed_start.len();
        let statement = trimmed_start.trim_end();
        if is_pattern_terminal_statement(statement) {
            let start = rule.body.span.start + offset + leading;
            return Some(SourceSpan {
                start,
                end: start + statement.len(),
            });
        }
        offset += line.len();
    }
    None
}

/// A trimmed body line begins a workflow terminal iff it starts with the
/// `complete` or `fail` keyword followed by whitespace, `{`, or end of line.
fn is_pattern_terminal_statement(line: &str) -> bool {
    for keyword in ["complete", "fail"] {
        if let Some(rest) = line.strip_prefix(keyword) {
            if rest.is_empty() || rest.starts_with('{') || rest.starts_with(char::is_whitespace) {
                return true;
            }
        }
    }
    false
}

fn expand_pattern_item(
    item: Item,
    alias: &str,
    type_substitutions: &BTreeMap<String, TypeSyntax>,
    value_substitutions: &BTreeMap<String, String>,
    local_names: &BTreeMap<String, String>,
) -> Option<(String, Item)> {
    match item {
        Item::Include(include) => Some((
            format!("include:{}", include.path.value),
            Item::Include(include),
        )),
        Item::Use(use_decl) => Some((format!("use:{}", use_decl.name.value), Item::Use(use_decl))),
        Item::Tracker(queue) => {
            Some((format!("tracker:{}", queue.name.name), Item::Tracker(queue)))
        }
        Item::Stream(stream) => {
            Some((format!("stream:{}", stream.name.name), Item::Stream(stream)))
        }
        Item::Channel(channel) => Some((
            format!("channel:{}", channel.name.name),
            Item::Channel(channel),
        )),
        Item::Credential(credential) => Some((
            format!("credential:{}", credential.name.name),
            Item::Credential(credential),
        )),
        // Gauges, campaigns, and marks are rejected from pattern bodies by
        // `pattern_body_admission` (objective intent and cut points are
        // top-level); there is deliberately no expansion path for them.
        Item::Gauge(_) | Item::Campaign(_) | Item::Mark(_) => None,
        Item::FileStore(file_store) => Some((
            format!("file-store:{}", file_store.name.name),
            Item::FileStore(file_store),
        )),
        Item::MemoryPool(pool) => Some((
            format!("memory-pool:{}", pool.name.name),
            Item::MemoryPool(pool),
        )),
        Item::Event(event) => Some((format!("event:{}", event.name), Item::Event(event))),
        Item::Source(source) => {
            Some((format!("source:{}", source.name.name), Item::Source(source)))
        }
        Item::Test(test) => Some((format!("test:{}", test.name.value), Item::Test(test))),
        Item::Lease(lease) => Some((format!("lease:{}", lease.name.name), Item::Lease(lease))),
        Item::Ledger(ledger) => {
            Some((format!("ledger:{}", ledger.name.name), Item::Ledger(ledger)))
        }
        Item::Counter(counter) => Some((
            format!("counter:{}", counter.name.name),
            Item::Counter(counter),
        )),
        Item::Action(action) => {
            Some((format!("action:{}", action.name.name), Item::Action(action)))
        }
        Item::Harness(mut harness) => {
            let name = rename_ident(harness.name, alias, local_names);
            let generated = format!("harness:{}", name.name);
            harness.name = name;
            Some((generated, Item::Harness(harness)))
        }
        // Forbidden constructs are rejected up front by `pattern_body_admission`
        // (the explicit allow-list gate), so these arms are unreachable in
        // practice; they stay defensive and simply drop the item.
        Item::WorkflowContract(_) | Item::Pattern(_) | Item::Apply(_) => None,
        Item::Agent(mut agent) => {
            let name = rename_ident(agent.name, alias, local_names);
            let generated = format!("agent:{}", name.name);
            agent.name = name;
            if let Some(harness) = agent.harness {
                agent.harness = Some(Ident {
                    name: local_names
                        .get(&harness.name)
                        .cloned()
                        .unwrap_or(harness.name),
                    span: harness.span,
                });
            }
            Some((generated, Item::Agent(agent)))
        }
        Item::Enum(mut enum_decl) => {
            let name = rename_ident(enum_decl.name, alias, local_names);
            let generated = format!("enum:{}", name.name);
            enum_decl.name = name;
            Some((generated, Item::Enum(enum_decl)))
        }
        Item::Class(mut class_decl) => {
            let name = rename_ident(class_decl.name, alias, local_names);
            let generated = format!("class:{}", name.name);
            class_decl.name = name;
            for field in &mut class_decl.fields {
                field.ty =
                    substitute_pattern_type(field.ty.clone(), type_substitutions, local_names);
            }
            Some((generated, Item::Class(class_decl)))
        }
        Item::Table(mut table) => {
            let name = rename_ident(table.name, alias, local_names);
            let generated = format!("table:{}", name.name);
            table.name = name;
            for row in &mut table.rows {
                row.body.text = substitute_pattern_text(
                    &row.body.text,
                    type_substitutions,
                    value_substitutions,
                    local_names,
                );
            }
            Some((generated, Item::Table(table)))
        }
        Item::Coerce(mut coerce) => {
            let name = rename_ident(coerce.name, alias, local_names);
            let generated = format!("coerce:{}", name.name);
            coerce.name = name;
            for param in &mut coerce.params {
                param.ty =
                    substitute_pattern_type(param.ty.clone(), type_substitutions, local_names);
            }
            coerce.output =
                substitute_pattern_type(coerce.output.clone(), type_substitutions, local_names);
            coerce.body.text = substitute_pattern_text(
                &coerce.body.text,
                type_substitutions,
                value_substitutions,
                local_names,
            );
            Some((generated, Item::Coerce(coerce)))
        }
        Item::Assert(mut assertion) => {
            assertion.expr = substitute_pattern_text(
                &assertion.expr,
                type_substitutions,
                value_substitutions,
                local_names,
            );
            Some((format!("assert:{alias}"), Item::Assert(assertion)))
        }
        Item::Rule(mut rule) => {
            let name = rename_ident(rule.name, alias, local_names);
            let generated = format!("rule:{}", name.name);
            rule.name = name;
            for when in &mut rule.whens {
                when.text = substitute_pattern_text(
                    &when.text,
                    type_substitutions,
                    value_substitutions,
                    local_names,
                );
            }
            rule.body.text = substitute_pattern_text(
                &rule.body.text,
                type_substitutions,
                value_substitutions,
                local_names,
            );
            Some((generated, Item::Rule(rule)))
        }
    }
}

fn rename_ident(ident: Ident, alias: &str, local_names: &BTreeMap<String, String>) -> Ident {
    Ident {
        name: local_names
            .get(&ident.name)
            .cloned()
            .unwrap_or_else(|| generated_pattern_name(alias, &ident.name)),
        span: ident.span,
    }
}

fn substitute_pattern_type(
    ty: TypeSyntax,
    type_substitutions: &BTreeMap<String, TypeSyntax>,
    local_names: &BTreeMap<String, String>,
) -> TypeSyntax {
    match ty {
        TypeSyntax::Ref { name } => {
            if let Some(replacement) = type_substitutions.get(&name.name) {
                return replacement.clone();
            }
            TypeSyntax::Ref {
                name: Ident {
                    name: local_names.get(&name.name).cloned().unwrap_or(name.name),
                    span: name.span,
                },
            }
        }
        TypeSyntax::AgentRef { agents, span } => TypeSyntax::AgentRef {
            agents: agents
                .into_iter()
                .map(|agent| Ident {
                    name: local_names.get(&agent.name).cloned().unwrap_or(agent.name),
                    span: agent.span,
                })
                .collect(),
            span,
        },
        TypeSyntax::Optional { inner, span } => TypeSyntax::Optional {
            inner: Box::new(substitute_pattern_type(
                *inner,
                type_substitutions,
                local_names,
            )),
            span,
        },
        TypeSyntax::Array { inner, span } => TypeSyntax::Array {
            inner: Box::new(substitute_pattern_type(
                *inner,
                type_substitutions,
                local_names,
            )),
            span,
        },
        TypeSyntax::Map { inner, span } => TypeSyntax::Map {
            inner: Box::new(substitute_pattern_type(
                *inner,
                type_substitutions,
                local_names,
            )),
            span,
        },
        TypeSyntax::Union { variants, span } => TypeSyntax::Union {
            variants: variants
                .into_iter()
                .map(|variant| substitute_pattern_type(variant, type_substitutions, local_names))
                .collect(),
            span,
        },
        other => other,
    }
}

/// Substitute a pattern's type parameters, hygienic local names, and value
/// arguments through an item's source text in ONE pass.
///
/// Single-pass is what makes the substitution hygienic. Running one
/// whole-string replacement per map over a shared accumulator — as this did —
/// let each pass rescan text the previous passes had inserted. A type argument
/// was therefore capturable by a pattern-local declaration: `apply Review<Task>`
/// against a pattern declaring its own `Task` had the argument rewritten to the
/// pattern's gensym, so the rule matched the pattern's local class instead of
/// the caller's type. Value-argument keys are unvalidated identifiers taken
/// from the apply body and ran last, so they could rewrite whatever the type
/// pass had just produced. Both failed closed on downstream name resolution,
/// but only after handing the author a diagnostic naming an identifier they
/// never wrote.
///
/// Each identifier token is now resolved exactly once, against the maps in the
/// priority order the multi-pass form implied, and its replacement is emitted
/// without being re-examined. Token boundaries are unchanged: a maximal run of
/// identifier characters is precisely what the old boundary test accepted.
fn substitute_pattern_text(
    text: &str,
    type_substitutions: &BTreeMap<String, TypeSyntax>,
    value_substitutions: &BTreeMap<String, String>,
    local_names: &BTreeMap<String, String>,
) -> String {
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(is_identifier_char) {
        output.push_str(&rest[..start]);
        let after = &rest[start..];
        let end = after
            .find(|ch| !is_identifier_char(ch))
            .unwrap_or(after.len());
        let token = &after[..end];
        match resolve_pattern_token(token, type_substitutions, value_substitutions, local_names) {
            Some(replacement) => output.push_str(&replacement),
            None => output.push_str(token),
        }
        rest = &after[end..];
    }
    output.push_str(rest);
    output
}

/// Resolve one identifier token against the substitution maps, in the priority
/// order the multi-pass form implied: a type parameter first, then a
/// pattern-local declaration, then a value argument. A token naming none of
/// them is not substituted.
fn resolve_pattern_token(
    token: &str,
    type_substitutions: &BTreeMap<String, TypeSyntax>,
    value_substitutions: &BTreeMap<String, String>,
    local_names: &BTreeMap<String, String>,
) -> Option<String> {
    if let Some(ty) = type_substitutions.get(token) {
        return Some(ty.to_source());
    }
    if let Some(local) = local_names.get(token) {
        return Some(local.clone());
    }
    value_substitutions.get(token).cloned()
}

fn is_identifier_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
}

fn collect_projection_reads(expr: &Expr) -> Vec<IrProjectionRead> {
    let mut reads = Vec::new();
    collect_projection_reads_into(expr, &mut reads);
    reads
}

fn collect_projection_reads_into(expr: &Expr, reads: &mut Vec<IrProjectionRead>) {
    match expr {
        Expr::Literal(_) | Expr::Path(_) => {}
        Expr::Index { target, key } => {
            collect_projection_reads_into(target, reads);
            collect_projection_reads_into(key, reads);
        }
        Expr::Array(items) => {
            for item in items {
                collect_projection_reads_into(item, reads);
            }
        }
        Expr::Object(fields) => {
            for field in fields {
                collect_projection_reads_into(&field.value, reads);
            }
        }
        Expr::Unary { expr, .. } => collect_projection_reads_into(expr, reads),
        Expr::Binary { left, right, .. } => {
            collect_projection_reads_into(left, reads);
            collect_projection_reads_into(right, reads);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_projection_reads_into(arg, reads);
            }
        }
        Expr::Query { kind, head, guard } => {
            reads.push(IrProjectionRead {
                kind: *kind,
                head: head.clone(),
                guard: guard.as_ref().map(|guard| guard.to_snapshot()),
            });
            if let Some(guard) = guard {
                collect_projection_reads_into(guard, reads);
            }
        }
    }
}

fn sort_projection_reads(reads: &mut Vec<IrProjectionRead>) {
    reads.sort_by_key(IrProjectionRead::to_snapshot);
    reads.dedup();
}

fn collect_schema_names(program: &Program, diagnostics: &mut Vec<Diagnostic>) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    // Track the first declaration span per name so a duplicate can point back to
    // it as related information ("first declared here").
    let mut first_spans: BTreeMap<String, SourceSpan> = BTreeMap::new();
    for item in &program.items {
        let name = match item {
            Item::Enum(enum_decl) => &enum_decl.name,
            Item::Class(class_decl) => &class_decl.name,
            _ => continue,
        };

        if !names.insert(name.name.clone()) {
            let mut diagnostic = Diagnostic {
                related: Vec::new(),
                span: name.span,
                message: format!("schema `{}` is declared more than once", name.name),
                suggestion: Some("rename one declaration or merge the schemas".to_owned()),
            };
            if let Some(first) = first_spans.get(&name.name) {
                diagnostic = diagnostic.with_related(*first, "first declared here");
            }
            diagnostics.push(diagnostic);
        } else {
            first_spans.insert(name.name.clone(), name.span);
        }
    }

    names
}

fn collect_harness_kinds(
    program: &Program,
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeMap<String, String> {
    let mut kinds: BTreeMap<String, String> = BTreeMap::new();
    for item in &program.items {
        let Item::Harness(harness) = item else {
            continue;
        };
        if kinds
            .insert(harness.name.name.clone(), harness.kind.name.clone())
            .is_some()
        {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: harness.name.span,
                message: format!("harness `{}` is declared more than once", harness.name.name),
                suggestion: Some(
                    "rename one harness declaration or merge the harness settings".to_owned(),
                ),
            });
        }
    }
    kinds
}

fn collect_agent_names(program: &Program, diagnostics: &mut Vec<Diagnostic>) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for item in &program.items {
        let Item::Agent(agent) = item else {
            continue;
        };
        if !names.insert(agent.name.name.clone()) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: agent.name.span,
                message: format!("agent `{}` is declared more than once", agent.name.name),
                suggestion: Some("rename one agent declaration or merge the settings".to_owned()),
            });
        }
    }
    names
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct WorkflowContractNames {
    inputs: BTreeMap<String, TypeSyntax>,
    outputs: BTreeMap<String, TypeSyntax>,
    failures: BTreeMap<String, TypeSyntax>,
}

fn collect_workflow_contract_names(
    program: &Program,
    diagnostics: &mut Vec<Diagnostic>,
) -> WorkflowContractNames {
    let mut names = WorkflowContractNames::default();
    for item in &program.items {
        let Item::WorkflowContract(contract) = item else {
            continue;
        };
        let set = match contract.kind {
            WorkflowContractKind::Input => &mut names.inputs,
            WorkflowContractKind::Output => &mut names.outputs,
            WorkflowContractKind::Failure => &mut names.failures,
        };
        if set
            .insert(contract.name.name.clone(), contract.ty.clone())
            .is_some()
        {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: contract.name.span,
                message: format!(
                    "workflow declares {} `{}` more than once",
                    contract.kind.as_str(),
                    contract.name.name
                ),
                suggestion: Some("remove the duplicate workflow contract".to_owned()),
            });
        }
    }
    names
}

impl SemanticContext {
    fn from_program(
        program: &Program,
        workflow_inputs: BTreeMap<String, WorkflowInputSurface>,
    ) -> Self {
        let mut schemas = SchemaIndex::with_builtins();
        let mut agents = BTreeSet::new();
        let mut agent_capabilities = BTreeMap::new();
        let mut coerce_outputs = BTreeMap::new();
        let mut coerce_params = BTreeMap::new();
        let mut leases = BTreeSet::new();
        let mut ledgers = BTreeSet::new();
        let mut counters = BTreeSet::new();
        let mut channels = BTreeSet::new();
        let mut channel_providers = BTreeMap::new();
        let mut credentials = BTreeMap::new();
        let mut memory_pools = BTreeSet::new();
        let mut trackers = BTreeSet::new();

        for item in &program.items {
            schemas.insert_item(item);
            match item {
                Item::Agent(agent) => {
                    agents.insert(agent.name.name.clone());
                    let capabilities = agent
                        .fields
                        .iter()
                        .find_map(|field| match field {
                            AgentField::Capabilities(capabilities, _) => Some(
                                capabilities
                                    .iter()
                                    .map(|capability| capability.value.clone())
                                    .collect::<BTreeSet<_>>(),
                            ),
                            _ => None,
                        })
                        .unwrap_or_default();
                    agent_capabilities.insert(agent.name.name.clone(), capabilities);
                }
                Item::Coerce(coerce) => {
                    coerce_outputs.insert(coerce.name.name.clone(), coerce.output.clone());
                    coerce_params.insert(coerce.name.name.clone(), coerce.params.clone());
                }
                Item::Lease(lease) => {
                    leases.insert(lease.name.name.clone());
                }
                Item::Ledger(ledger) => {
                    ledgers.insert(ledger.name.name.clone());
                }
                Item::Counter(counter) => {
                    counters.insert(counter.name.name.clone());
                }
                Item::Channel(channel) => {
                    channels.insert(channel.name.name.clone());
                    channel_providers
                        .insert(channel.name.name.clone(), channel.provider.name.clone());
                }
                Item::Credential(credential) => {
                    credentials.insert(
                        credential.name.name.clone(),
                        credential.kind.name.replace('_', "-"),
                    );
                }
                Item::MemoryPool(pool) => {
                    memory_pools.insert(pool.name.name.clone());
                }
                Item::Tracker(queue) => {
                    trackers.insert(queue.name.name.clone());
                }
                _ => {}
            }
        }

        Self {
            workflow: program
                .workflow
                .as_ref()
                .map(|workflow| workflow.name.clone()),
            schemas,
            agents,
            agent_capabilities,
            coerce_outputs,
            coerce_params,
            workflow_inputs,
            leases,
            ledgers,
            counters,
            channels,
            channel_providers,
            credentials,
            memory_pools,
            trackers,
            regions: BTreeMap::new(),
        }
    }
}

fn collect_workflow_input_surfaces(program: &Program) -> BTreeMap<String, WorkflowInputSurface> {
    let mut surfaces = BTreeMap::new();
    let top_level_schemas = schema_index_for_items(&program.items);

    if let Some(workflow) = &program.workflow {
        let inputs = workflow_inputs_for_items(&program.items);
        surfaces.insert(
            workflow.name.clone(),
            WorkflowInputSurface {
                inputs,
                outputs: workflow_outputs_for_items(&program.items),
                failures: workflow_failures_for_items(&program.items),
                schemas: top_level_schemas.clone(),
                milestones: collect_milestone_declarations(&program.items),
            },
        );
    }

    for workflow in &program.workflows {
        let mut schemas = top_level_schemas.clone();
        schemas.merge(schema_index_for_items(&workflow.items));
        surfaces.insert(
            workflow.name.name.clone(),
            WorkflowInputSurface {
                inputs: workflow_inputs_for_items(&workflow.items),
                outputs: workflow_outputs_for_items(&workflow.items),
                failures: workflow_failures_for_items(&workflow.items),
                schemas,
                milestones: collect_milestone_declarations(&workflow.items),
            },
        );
    }

    surfaces
}

fn collect_shared_coordination_usage(program: &Program) -> Vec<IrSharedCoordinationUsage> {
    let global_shared = shared_coordination_declarations(&program.items);
    let mut usage: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    let mut record_workflow = |workflow_name: &str, local_items: &[Item]| {
        let mut shared = global_shared.clone();
        shared.extend(shared_coordination_declarations(local_items));
        if shared.is_empty() {
            return;
        }
        let principal = format!("workflow:local/{workflow_name}");
        for resource in coordination_resources_used_by_items(&program.items)
            .into_iter()
            .chain(coordination_resources_used_by_items(local_items))
        {
            if shared.contains(&resource) {
                usage.entry(resource).or_default().insert(principal.clone());
            }
        }
    };

    if let Some(workflow) = &program.workflow {
        record_workflow(&workflow.name, &[]);
    }
    for workflow in &program.workflows {
        record_workflow(&workflow.name.name, &workflow.items);
    }

    usage
        .into_iter()
        .map(|(resource, principals)| IrSharedCoordinationUsage {
            resource: format!("resource:{resource}"),
            workflow_principals: principals.into_iter().collect(),
        })
        .collect()
}

fn shared_coordination_declarations(items: &[Item]) -> BTreeSet<String> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::Lease(lease) if lease.shared => Some(lease.name.name.clone()),
            Item::Ledger(ledger) if ledger.shared => Some(ledger.name.name.clone()),
            Item::Counter(counter) if counter.shared => Some(counter.name.name.clone()),
            _ => None,
        })
        .collect()
}

fn coordination_resources_used_by_items(items: &[Item]) -> BTreeSet<String> {
    let mut resources = BTreeSet::new();
    for item in items {
        let Item::Rule(rule) = item else {
            continue;
        };
        let (body, _) = body::parse_rule_body(&rule.body.text, rule.body.span.start);
        collect_coordination_resources_from_statements(&body.statements, &mut resources);
    }
    resources
}

fn collect_coordination_resources_from_statements(
    statements: &[body::BodyStmt],
    resources: &mut BTreeSet<String>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => match &effect.kind {
                body::BodyEffectKind::LeaseAcquire { resource, .. } => {
                    resources.insert(resource.clone());
                }
                body::BodyEffectKind::LedgerAppend { ledger, .. } => {
                    resources.insert(ledger.clone());
                }
                body::BodyEffectKind::CounterConsume { counter, .. } => {
                    resources.insert(counter.clone());
                }
                _ => {}
            },
            body::BodyStmt::After(after) => {
                collect_coordination_resources_from_statements(&after.body, resources);
            }
            body::BodyStmt::Region(region) => {
                collect_coordination_resources_from_statements(&region.body, resources);
                collect_coordination_resources_from_statements(&region.lapse_body, resources);
            }
            body::BodyStmt::Case(case_stmt) => {
                for branch in &case_stmt.branches {
                    collect_coordination_resources_from_statements(&branch.body, resources);
                }
            }
            body::BodyStmt::Record(_)
            | body::BodyStmt::Done { .. }
            | body::BodyStmt::Terminal(_)
            | body::BodyStmt::Cancel { .. }
            | body::BodyStmt::Milestone { .. }
            | body::BodyStmt::Redact { .. }
            | body::BodyStmt::Declassify { .. } => {}
        }
    }
}

/// Scans a workflow's rule bodies for `emit milestone "<name>" [of <Class>]`
/// projections (Family C) and returns the name -> payload-class map (empty class
/// string for a bare milestone). The emit statement IS the declaration — the
/// declared milestone set is exactly what the workflow's rules can project, which
/// is what a parent's `after p reaches "<name>"` is validated against.
fn collect_milestone_declarations(items: &[Item]) -> BTreeMap<String, String> {
    let mut milestones = BTreeMap::new();
    for item in items {
        let Item::Rule(rule) = item else {
            continue;
        };
        for (name, class) in milestone_emissions_in_body(&rule.body.text) {
            milestones.entry(name).or_insert(class);
        }
    }
    milestones
}

/// Validates Family C milestone statements in a rule (spec/decision-records/
/// discriminated-families-design.md sections 6.4 / 7.3):
///   - child `emit milestone "<name>" of <Class>` — `<Class>` must be a declared
///     class (the payload the observing parent narrows into scope);
///   - parent `after <p> reaches "<name>"` — `<p>` must be a workflow-invoke
///     binding in this rule, and `<name>` must be a milestone that the invoked
///     child workflow actually declares (the reject-undeclared / terminal-only
///     observation invariant: a parent cannot observe a state the child never
///     projects).
fn validate_milestone_statements(
    rule: &RuleDecl,
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    // Child side: every `emit milestone "<name>" of <Class>` payload class must
    // exist.
    for (name, class) in milestone_emissions_in_body(&rule.body.text) {
        if !class.is_empty() && !semantic.schemas.class_exists(&class) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` emits milestone `{name}` with unknown payload class `{class}`",
                    rule.name.name
                ),
                suggestion: Some(format!("declare `class {class}` before projecting it")),
            });
        }
    }

    // Parent side: every `after <p> reaches "<name>"` must name a milestone the
    // invoked child declares.
    for (binding, milestone) in milestone_reaches_in_body(&rule.body.text) {
        let Some(workflow) = invoke_binding_workflow(rule, &binding) else {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` has `after {binding} reaches \"{milestone}\"` for `{binding}`, which is not a workflow-invoke binding in this rule",
                    rule.name.name
                ),
                suggestion: Some(
                    "`reaches` observes a child workflow milestone; bind the child with `invoke W { ... } as <binding>` first"
                        .to_owned(),
                ),
            });
            continue;
        };
        let declared = semantic
            .workflow_inputs
            .get(&workflow)
            .map(|surface| surface.milestones.contains_key(&milestone))
            .unwrap_or(false);
        if !declared {
            let available = semantic
                .workflow_inputs
                .get(&workflow)
                .map(|surface| {
                    surface
                        .milestones
                        .keys()
                        .map(|name| format!("\"{name}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let suggestion = if available.is_empty() {
                format!("workflow `{workflow}` declares no milestones; add `emit milestone \"{milestone}\" ...` to it")
            } else {
                format!("workflow `{workflow}` declares: {available}")
            };
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` reaches milestone `{milestone}` that workflow `{workflow}` does not declare",
                    rule.name.name
                ),
                suggestion: Some(suggestion),
            });
        }
    }
}

/// Parses `after <binding> reaches "<name>"` headers out of a rule body's text,
/// returning (binding, milestone-name) pairs. Mirrors `milestone_emissions_in_body`.
fn milestone_reaches_in_body(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for raw in body.lines() {
        let trimmed = raw.trim();
        let Some(rest) = trimmed.strip_prefix("after ") else {
            continue;
        };
        let mut words = rest.split_whitespace();
        let Some(binding) = words.next() else {
            continue;
        };
        if words.next() != Some("reaches") {
            continue;
        }
        let Some(quoted) = words.next() else {
            continue;
        };
        if !(quoted.starts_with('"') && quoted.ends_with('"') && quoted.len() >= 2) {
            continue;
        }
        out.push((binding.to_owned(), quoted.trim_matches('"').to_owned()));
    }
    out
}

/// Maps an `invoke <Workflow> { ... } as <binding>` binding to the invoked
/// workflow name within a single rule, so a sibling `after <binding> reaches`
/// can find the child workflow whose milestones it observes.
fn invoke_binding_workflow(rule: &RuleDecl, binding: &str) -> Option<String> {
    for statement in workflow_invoke_statements(&rule.body.text) {
        let (target, _) = invoke_statement_parts(&statement)?;
        if let Some(as_binding) = binding_after_as(&statement) {
            if as_binding == binding {
                return Some(target.to_owned());
            }
        }
    }
    None
}

/// Resolves the payload class of a child milestone for `after <binding> reaches
/// "<milestone>"`: follow `binding` to its invoked workflow, then look up the
/// milestone in that workflow's declared set. Returns the owning workflow with
/// the class, because the class may be declared inside that child and so
/// resolves in the child's index, not this workflow's (`SchemaScopes`).
/// `Some((_, ""))` means the milestone is declared but payload-less; `None`
/// means undeclared (reject) or unresolvable.
fn milestone_payload_class(
    rule: &RuleDecl,
    binding: &str,
    milestone: &str,
    semantic: &SemanticContext,
) -> Option<(String, String)> {
    let workflow = invoke_binding_workflow(rule, binding)?;
    let surface = semantic.workflow_inputs.get(&workflow)?;
    let class = surface.milestones.get(milestone).cloned()?;
    Some((workflow, class))
}

/// Resolves the OUTPUT-contract class of the child workflow a `succeeds`/`completes`
/// invoke binding observes, so `after <binding> succeeds as r` can type `r` and
/// check `r.<field>`. `None` (leave the binding opaque, unchanged) when: the binding
/// is not an invoke; the child declares zero or several outputs (which output the
/// child completes is not statically known); or the sole output is a scalar (no
/// fields).
///
/// The class is resolved in the CHILD's index and returned with its owning
/// workflow. A child that declares its output class workflow-locally — the
/// ordinary, encapsulated spelling — used to fall through this function and leave
/// `r.<field>` unchecked; the class still never becomes nameable in the parent,
/// only resolvable for reads off this binding (`SchemaScopes`).
fn invoke_output_class(
    rule: &RuleDecl,
    binding: &str,
    semantic: &SemanticContext,
) -> Option<(String, String)> {
    let workflow = invoke_binding_workflow(rule, binding)?;
    let surface = semantic.workflow_inputs.get(&workflow)?;
    if surface.outputs.len() != 1 {
        return None;
    }
    match surface.outputs.values().next()? {
        TypeSyntax::Ref { name } if surface.schemas.class_exists(&name.name) => {
            Some((workflow, name.name.clone()))
        }
        _ => None,
    }
}

/// Resolves the FAILURE-contract class of the child workflow a `fails` invoke
/// binding observes, so `after <binding> fails as f` can type `f` to the child's
/// declared failure shape (and check `f.<field>`) instead of the generic DR-0032
/// `TerminalFailed` base. `None` (fall back to the base) when: the binding is not
/// an invoke; the child declares zero or several failures (which failure the child
/// raised is not statically known); or the sole failure is a scalar (no fields).
/// Anything else keeps the base, which every failure structurally satisfies.
///
/// As with `invoke_output_class`, the class is resolved in the CHILD's index and
/// returned with its owning workflow, so a child that declares its failure class
/// workflow-locally is typed rather than silently left on the base.
fn invoke_failure_class(
    rule: &RuleDecl,
    binding: &str,
    semantic: &SemanticContext,
) -> Option<(String, String)> {
    let workflow = invoke_binding_workflow(rule, binding)?;
    let surface = semantic.workflow_inputs.get(&workflow)?;
    if surface.failures.len() != 1 {
        return None;
    }
    match surface.failures.values().next()? {
        TypeSyntax::Ref { name } if surface.schemas.class_exists(&name.name) => {
            Some((workflow, name.name.clone()))
        }
        _ => None,
    }
}

/// Parses `emit milestone "<name>" [of <Class>]` headers out of a rule body's
/// text, returning (name, class) pairs (class is empty for a bare milestone).
/// Text-based to mirror the other body scanners (`workflow_invoke_statements`)
/// and stay independent of flow-vs-rule body provenance.
fn milestone_emissions_in_body(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for raw in body.lines() {
        let trimmed = raw.trim();
        let Some(rest) = trimmed.strip_prefix("emit milestone ") else {
            continue;
        };
        // The name is a quoted string literal; take the text between the first
        // pair of quotes.
        let rest = rest.trim_start();
        if !rest.starts_with('"') {
            continue;
        }
        let Some(close) = rest[1..].find('"') else {
            continue;
        };
        let name = rest[1..=close].to_owned();
        let after_name = rest[close + 2..].trim_start();
        let class = after_name
            .strip_prefix("of ")
            .map(|tail| {
                tail.trim_start()
                    .split(|c: char| c.is_whitespace() || c == '{')
                    .next()
                    .unwrap_or("")
                    .to_owned()
            })
            .unwrap_or_default();
        out.push((name, class));
    }
    out
}

fn schema_index_for_items(items: &[Item]) -> SchemaIndex {
    let mut schemas = SchemaIndex::with_builtins();
    for item in items {
        schemas.insert_item(item);
    }
    schemas
}

fn workflow_inputs_for_items(items: &[Item]) -> BTreeMap<String, TypeSyntax> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::WorkflowContract(contract) if contract.kind == WorkflowContractKind::Input => {
                Some((contract.name.name.clone(), contract.ty.clone()))
            }
            _ => None,
        })
        .collect()
}

fn workflow_outputs_for_items(items: &[Item]) -> BTreeMap<String, TypeSyntax> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::WorkflowContract(contract) if contract.kind == WorkflowContractKind::Output => {
                Some((contract.name.name.clone(), contract.ty.clone()))
            }
            _ => None,
        })
        .collect()
}

fn workflow_failures_for_items(items: &[Item]) -> BTreeMap<String, TypeSyntax> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::WorkflowContract(contract) if contract.kind == WorkflowContractKind::Failure => {
                Some((contract.name.name.clone(), contract.ty.clone()))
            }
            _ => None,
        })
        .collect()
}

impl SchemaIndex {
    fn with_builtins() -> Self {
        let mut index = Self::default();
        index.insert_class(
            "AgentTurn",
            [
                ("id", string_ty()),
                ("summary", string_ty()),
                ("agent", string_ty()),
                ("provider", string_ty()),
                ("status", string_ty()),
                ("run_id", string_ty()),
                ("effect_id", string_ty()),
            ],
        );
        index.insert_class(
            "WorkItem",
            [
                ("id", string_ty()),
                ("title", string_ty()),
                ("body", string_ty()),
                ("queue", string_ty()),
                ("status", string_ty()),
                ("labels", array_ty(string_ty())),
            ],
        );
        // std.vcs observer schemas (DR-0052 grammar pass): the readiness
        // sugar's typed bindings. Observer-origin — the mediator emits
        // them; user rules eliminate, never construct.
        index.insert_class(
            "VcsChange",
            [
                ("branch", string_ty()),
                ("cut", string_ty()),
                ("path", string_ty()),
                ("origin", string_ty()),
                ("by", string_ty()),
                ("intent", string_ty()),
                ("at", string_ty()),
            ],
        );
        index.insert_class(
            "VcsContention",
            [
                ("branch", string_ty()),
                ("with", string_ty()),
                ("stream", string_ty()),
                ("slice", array_ty(string_ty())),
                ("at", string_ty()),
            ],
        );
        index.insert_class(
            "VcsPromotion",
            [
                ("branch", string_ty()),
                ("stream", string_ty()),
                ("cut", string_ty()),
                ("at", string_ty()),
            ],
        );
        index.insert_class(
            "VcsStall",
            [
                ("branch", string_ty()),
                ("stream", string_ty()),
                ("boundary", string_ty()),
                ("paths", array_ty(string_ty())),
                ("at", string_ty()),
            ],
        );
        index.insert_class(
            "Evidence",
            [
                ("title", string_ty()),
                ("path", string_ty()),
                ("summary", string_ty()),
            ],
        );
        index.insert_class(
            "TerminalFailed",
            [
                ("reason", string_ty()),
                ("summary", string_ty()),
                ("effect_id", string_ty()),
                ("run_id", string_ty()),
                // DR-0032: `kind` names the failing effect — the `EffectError` base
                // field that lets a future runtime union dispatch and that
                // telemetry reads. Static narrowing does not require it.
                ("kind", string_ty()),
            ],
        );
        // DR-0032 P3 (per-kind failure extras, DQ-2 static narrowing): each
        // kind's failure schema extends the base with the ruled v1 extras —
        // exec `exit_code`; schema.coerce `error_class` + optional
        // `http_status`; agent.tell `error_class`. The extras are reachable
        // ONLY when the binding's effect kind matches (the `fails`-arm
        // narrowing below), so each addition is additive by construction.
        index.insert_class(
            "TerminalFailedExec",
            [
                ("reason", string_ty()),
                ("summary", string_ty()),
                ("effect_id", string_ty()),
                ("run_id", string_ty()),
                ("kind", string_ty()),
                // Absent when the process could not be spawned (the emitters
                // only set it for a run that actually started) — the docs
                // said so; the type now agrees.
                ("exit_code", optional_ty(int_ty())),
            ],
        );
        index.insert_class(
            "TerminalFailedCoerce",
            [
                ("reason", string_ty()),
                ("summary", string_ty()),
                ("effect_id", string_ty()),
                ("run_id", string_ty()),
                ("kind", string_ty()),
                ("error_class", string_ty()),
                ("http_status", optional_ty(int_ty())),
            ],
        );
        index.insert_class(
            "TerminalFailedTell",
            [
                ("reason", string_ty()),
                ("summary", string_ty()),
                ("effect_id", string_ty()),
                ("run_id", string_ty()),
                ("kind", string_ty()),
                ("error_class", string_ty()),
            ],
        );
        index.insert_class(
            "TerminalTimedOut",
            [
                ("summary", string_ty()),
                ("effect_id", string_ty()),
                ("run_id", string_ty()),
            ],
        );
        index.insert_class(
            "TerminalCancelled",
            [
                ("summary", string_ty()),
                ("effect_id", string_ty()),
                ("run_id", string_ty()),
            ],
        );
        // The `after x completes as o` envelope: the runtime delivers the
        // terminal UNION {tag, status, summary, effect_id, run_id} (plus the
        // dynamically-shaped value/error read via `case o { Completed as v =>
        // … }`). Typing the alias as the effect's SUCCESS schema — the old
        // behavior — approved field reads that were null at runtime on every
        // non-success terminal.
        index.insert_class(
            "TerminalOutcome",
            [
                ("tag", string_ty()),
                ("status", string_ty()),
                ("summary", string_ty()),
                ("effect_id", string_ty()),
                ("run_id", string_ty()),
            ],
        );
        // The generic inbound messaging envelope (spec/messaging.md): a
        // `when message from <channel> as msg` binding sees a `Message`, never a
        // domain type. Structured sub-payloads (sender_claims, interaction,
        // correlation) are JSON-serialized strings here; provider-specific
        // payloads live in bounded evidence / `raw_ref`, not as untyped facts.
        index.insert_class(
            "Message",
            [
                ("message_id", string_ty()),
                ("channel", string_ty()),
                ("provider", string_ty()),
                ("received_at", string_ty()),
                ("sender", string_ty()),
                ("sender_claims", string_ty()),
                ("thread_id", string_ty()),
                ("text", string_ty()),
                ("markdown", string_ty()),
                ("attachments", array_ty(string_ty())),
                ("interaction", string_ty()),
                ("raw_ref", string_ty()),
                ("correlation", string_ty()),
            ],
        );
        // The typed receipt a `send via <channel> { ... } as r` binding sees
        // (std.messaging; the `messaging.send` contract's output schema —
        // spec/std-messaging.md "MessageSendReceipt"). Every provider returns
        // the full shape; correlation fields the provider cannot report
        // (`provider_message_id`, `thread_id`, `destination`) are empty
        // strings, and `accepted_at` is the provider-acknowledged instant.
        // Failure is NOT a receipt: it settles `capability.call.failed` with
        // the DR-0032 EffectError base and routes to `fails as`. `status` is
        // `accepted` in v1 (`delivered` is reserved for providers whose report
        // includes it; none exists yet).
        index.insert_class(
            "MessageSendReceipt",
            [
                ("message_id", string_ty()),
                ("channel", string_ty()),
                ("provider", string_ty()),
                ("status", string_ty()),
                ("provider_message_id", string_ty()),
                ("thread_id", string_ty()),
                ("destination", string_ty()),
                ("accepted_at", string_ty()),
            ],
        );
        index
    }

    fn insert_class<const N: usize>(&mut self, name: &str, fields: [(&str, TypeSyntax); N]) {
        self.classes.insert(
            name.to_owned(),
            fields
                .into_iter()
                .map(|(field, ty)| (field.to_owned(), ty))
                .collect(),
        );
    }

    fn insert_item(&mut self, item: &Item) {
        match item {
            Item::Enum(enum_decl) => {
                self.enums.insert(
                    enum_decl.name.name.clone(),
                    enum_decl
                        .variants
                        .iter()
                        .map(|variant| variant.name.name.clone())
                        .collect(),
                );
                // Data-carrying variants are visible as generated
                // `<Enum>.<Variant>` classes (spec/sum-types.md), so case
                // bindings type-check field access against them.
                for variant in &enum_decl.variants {
                    if variant.fields.is_empty() {
                        continue;
                    }
                    let mut fields = BTreeMap::new();
                    fields.insert(
                        "variant".to_owned(),
                        TypeSyntax::LiteralString {
                            value: variant.name.name.clone(),
                            span: variant.name.span,
                        },
                    );
                    for field in &variant.fields {
                        fields.insert(field.name.name.clone(), field.ty.clone());
                    }
                    self.classes.insert(
                        format!("{}.{}", enum_decl.name.name, variant.name.name),
                        fields,
                    );
                }
            }
            Item::Class(class_decl) => {
                self.classes.insert(
                    class_decl.name.name.clone(),
                    class_decl
                        .fields
                        .iter()
                        .map(|field| (field.name.name.clone(), field.ty.clone()))
                        .collect(),
                );
                self.insert_presence(&class_decl.name.name, &class_decl.fields);
            }
            Item::Event(event) => {
                self.events.insert(event.name.clone());
                // The payload schema is indexed under the dotted signal name,
                // unreachable from user class declarations, so bare `when
                // <signal> as x` bindings type-check field access.
                self.classes.insert(
                    event.name.clone(),
                    event
                        .fields
                        .iter()
                        .map(|field| (field.name.name.clone(), field.ty.clone()))
                        .collect(),
                );
                self.insert_presence(&event.name, &event.fields);
            }
            _ => {}
        }
    }

    /// Record Family B presence conditions for a schema's fields (if any).
    fn insert_presence(&mut self, schema: &str, fields: &[ClassField]) {
        let conditions: BTreeMap<String, (String, String)> = fields
            .iter()
            .filter_map(|field| {
                field
                    .presence_condition
                    .clone()
                    .map(|condition| (field.name.name.clone(), condition))
            })
            .collect();
        if !conditions.is_empty() {
            self.presence.insert(schema.to_owned(), conditions);
        }
    }

    /// The presence condition `(discriminant, literal)` for a schema field, if any.
    fn field_presence(&self, schema: &str, field: &str) -> Option<&(String, String)> {
        self.presence
            .get(schema)
            .and_then(|fields| fields.get(field))
    }

    fn merge(&mut self, other: SchemaIndex) {
        self.classes.extend(other.classes);
        self.enums.extend(other.enums);
        self.presence.extend(other.presence);
    }

    fn class_exists(&self, name: &str) -> bool {
        self.classes.contains_key(name)
    }

    fn resolve_field_path(&self, root_schema: &str, path: &[String]) -> Result<TypeSyntax, String> {
        // Dotted runtime fact names (general `when fact <name>` matches) are
        // untyped — unless a declared `event` (or generated `<Enum>.<Variant>`
        // class) indexes a payload schema under the dotted name, in which
        // case field paths are statically validated against it.
        if root_schema.contains('.') && !self.classes.contains_key(root_schema) {
            return Ok(TypeSyntax::Ref {
                name: Ident {
                    name: root_schema.to_owned(),
                    span: zero_span(),
                },
            });
        }
        let mut schema = root_schema.to_owned();
        let mut current = TypeSyntax::Ref {
            name: Ident {
                name: schema.clone(),
                span: zero_span(),
            },
        };

        for field in path {
            let Some(fields) = self.classes.get(&schema) else {
                return Err(format!("schema `{schema}` has no declared fields"));
            };
            let Some(field_ty) = fields.get(field) else {
                return Err(format!("schema `{schema}` has no field `{field}`"));
            };

            current = field_ty.clone();
            match schema_name_for_path(&current) {
                Some(next_schema) => schema = next_schema,
                None if field != path.last().expect("path is non-empty") => {
                    return Err(format!("field `{field}` is not a schema value"));
                }
                None => {}
            }
        }

        Ok(current)
    }
}

fn zero_span() -> SourceSpan {
    SourceSpan { start: 0, end: 0 }
}

fn string_ty() -> TypeSyntax {
    TypeSyntax::Primitive {
        name: "string".to_owned(),
        span: zero_span(),
    }
}

fn int_ty() -> TypeSyntax {
    TypeSyntax::Primitive {
        name: "int".to_owned(),
        span: zero_span(),
    }
}

fn optional_ty(inner: TypeSyntax) -> TypeSyntax {
    TypeSyntax::Optional {
        inner: Box::new(inner),
        span: zero_span(),
    }
}

fn array_ty(inner: TypeSyntax) -> TypeSyntax {
    TypeSyntax::Array {
        inner: Box::new(inner),
        span: zero_span(),
    }
}

fn schema_name_for_path(ty: &TypeSyntax) -> Option<String> {
    match ty {
        TypeSyntax::Ref { name } => Some(name.name.clone()),
        TypeSyntax::Optional { inner, .. } => schema_name_for_path(inner),
        _ => None,
    }
}

/// The complete standard-package universe: the standard-package campaign's
/// fourteen, plus `std.custody` (DR-0074 §12, which made custody the fifteenth
/// so `seal` could be a construct instance rather than core surgery).
/// `use std.<name>` outside this list is a check error: std resolution is a
/// built-in registry, so an unknown name can never resolve later — a typo'd
/// `use std.coercon` would otherwise silently import nothing (and downstream
/// missing-import bite is advisory only).
pub const STD_PACKAGE_IDS: &[&str] = &[
    "std.agent",
    "std.vcs",
    "std.coercion",
    "std.coord",
    "std.custody",
    "std.files",
    "std.human",
    "std.ingress",
    "std.memory",
    "std.messaging",
    "std.script",
    "std.telemetry",
    "std.time",
    "std.tracker",
    "std.workflow",
];

/// Cross-declaration stream checks (DR-0052 Decision 5, run after all
/// items lower so agent order does not matter): every member names a
/// declared agent, and membership is single-valued — one stream per
/// agent, so the sync topology stays a tree.
fn validate_streams(ir: &IrProgram, diagnostics: &mut Vec<Diagnostic>) {
    let mut memberships: Vec<(&str, &str)> = Vec::new(); // (agent, stream)
    for stream in &ir.streams {
        for (member, span) in stream.members.iter().zip(&stream.member_spans) {
            if !ir.agents.iter().any(|agent| agent.name == *member) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: *span,
                    message: format!(
                        "stream `{}` member `{}` is not a declared agent",
                        stream.name, member
                    ),
                    suggestion: Some(
                        "stream members are agent declarations; declare the agent \
                         or remove it from the stream"
                            .to_owned(),
                    ),
                });
                continue;
            }
            if let Some((_, holder)) = memberships.iter().find(|(agent, _)| agent == member) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: *span,
                    message: format!("agent `{member}` is already a member of stream `{holder}`",),
                    suggestion: Some(
                        "membership is single-valued (the sync topology stays a \
                         tree): an agent homes to exactly one stream"
                            .to_owned(),
                    ),
                });
                continue;
            }
            memberships.push((member, &stream.name));
        }
    }
    // `on stream <name>` on a tell must name a declared stream — the
    // per-turn exception cannot invent topology.
    for rule in &ir.rules {
        for effect in &rule.metadata.effects {
            if let Some(target) = &effect.on_stream {
                if !ir.streams.iter().any(|stream| stream.name == *target) {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: effect.span,
                        message: format!("`on stream {target}` names an undeclared stream"),
                        suggestion: Some(
                            "declare the stream at top level: `stream <name> { members [...] }`"
                                .to_owned(),
                        ),
                    });
                }
            }
            // A literal selection validates against the ONE selection
            // grammar at check time (DR-0052 R4.2 — the grammar lives in
            // whipplescript-core, the same parser the runtime uses;
            // dynamic expressions validate at execution instead).
            if let Some(source) = &effect.selection_source {
                let trimmed = source.trim();
                if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
                    let literal = &trimmed[1..trimmed.len() - 1];
                    if let Err(error) = whipplescript_core::selection::parse(literal) {
                        diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: effect.span,
                            message: format!("the selection does not parse: {error}"),
                            suggestion: Some(
                                "selections compose atoms like `path(<glob>)`, `by(<prefix>)`, \
                                 `intent(<prefix>)`, `cut(<id>)` with `|`, `&`, `~`, and \
                                 `dependents-of(...)`"
                                    .to_owned(),
                            ),
                        });
                    }
                }
            }
            // `with access to vcs { repair for <binding> }` (DR-0052
            // R3): the vcs resource grants exactly one operation, on an
            // invoke only (a tell would hand a MODEL repair authority),
            // and its target must be a fact this rule bound — the grant's
            // extent IS the bound incident fact.
            for grant in &effect.access_grants {
                if grant.resource != "vcs" {
                    continue;
                }
                if effect.kind != IrEffectKind::WorkflowInvoke {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: effect.span,
                        message: "a `vcs` access grant rides an `invoke` only".to_owned(),
                        suggestion: Some(
                            "repair authority is orchestration: grant it to a repair \
                             workflow via `invoke ... with access to vcs { repair for \
                             <binding> }`; agents never receive it"
                                .to_owned(),
                        ),
                    });
                    continue;
                }
                for op in &grant.operations {
                    if op.operation != "repair" {
                        diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: effect.span,
                            message: format!("unknown `vcs` grant operation `{}`", op.operation),
                            suggestion: Some(
                                "the vcs resource grants `repair for <binding>`".to_owned(),
                            ),
                        });
                        continue;
                    }
                    let Some(target) = &op.target else {
                        diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: effect.span,
                            message: "`repair` names no binding".to_owned(),
                            suggestion: Some(
                                "write `repair for <binding>` where the binding is a \
                                 vcs arming fact this rule matched (e.g. `when reconcile \
                                 stalled as r`)"
                                    .to_owned(),
                            ),
                        });
                        continue;
                    };
                    let bound = rule.whens.iter().any(|when| {
                        binding_after_as(when.pattern.as_str()).as_deref() == Some(target)
                    });
                    if !bound {
                        diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: effect.span,
                            message: format!("`repair for {target}` names no binding of this rule"),
                            suggestion: Some(
                                "bind the arming fact first: `when reconcile stalled as \
                                 <binding>` (or the dotted `when fact vcs.* as <binding>` \
                                 form)"
                                    .to_owned(),
                            ),
                        });
                    }
                }
            }
            // `transport ... onto <target>`: the target is a nameable
            // tier — `mainline`, or a declared stream (its line).
            if let Some(target) = &effect.transport_onto {
                if target != "mainline" && !ir.streams.iter().any(|stream| stream.name == *target) {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: effect.span,
                        message: format!(
                            "`onto {target}` names neither `mainline` nor a declared stream"
                        ),
                        suggestion: Some(
                            "transport targets are the nameable tiers: `onto mainline`, or \
                             `onto <stream>` for a declared stream's line"
                                .to_owned(),
                        ),
                    });
                }
            }
        }
    }
}

/// std.messaging v1 provider capability report (spec/std-messaging.md
/// "Capability reports + conditioned checks"). Reports are DATA, never code
/// (M8): these compiled constants are mirrored by the embedded std.messaging
/// manifest's `bindings[].config.report` rows, and the conditioned static
/// checks below admit syntax only when the selected provider's report
/// supports it. Report axes are messaging.md "Provider Capability Report"
/// narrowed for v1: `delivery_receipts` ⊆ {accepted, failed}; `identity` ⊆
/// {anonymous, claimed_actor} (no verified_actor provider exists, so any
/// check demanding verified identity fails closed); `content` ⊆
/// {text, markdown}.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelProviderReport {
    /// The short channel-declaration identifier (`provider <short_name>`).
    pub short_name: &'static str,
    /// The binding-row provider id the short name resolves to.
    pub provider_id: &'static str,
    /// `outbound_only` | `inbound_only` | `bidirectional`.
    pub direction: &'static str,
    /// `anonymous` | `claimed_actor`.
    pub identity: &'static str,
    /// Interaction families the provider can deliver callbacks for.
    pub interactions: &'static [&'static str],
    /// Payload content kinds the provider accepts.
    pub content: &'static [&'static str],
    /// Receipt statuses the provider can report.
    pub delivery_receipts: &'static [&'static str],
}

/// The four v1 std.messaging providers (spec/std-messaging.md "Providers").
pub const CHANNEL_PROVIDER_REPORTS: &[ChannelProviderReport] = &[
    ChannelProviderReport {
        short_name: "fixture",
        provider_id: "fixture",
        direction: "bidirectional",
        identity: "claimed_actor",
        interactions: &["buttons", "reactions"],
        content: &["text", "markdown"],
        delivery_receipts: &["accepted", "failed"],
    },
    ChannelProviderReport {
        short_name: "local",
        provider_id: "std.messaging.local",
        direction: "bidirectional",
        identity: "claimed_actor",
        interactions: &["buttons", "reactions"],
        content: &["text", "markdown"],
        delivery_receipts: &["accepted", "failed"],
    },
    ChannelProviderReport {
        short_name: "desktop",
        provider_id: "std.messaging.desktop",
        direction: "outbound_only",
        identity: "anonymous",
        interactions: &[],
        content: &["text"],
        delivery_receipts: &["accepted", "failed"],
    },
    ChannelProviderReport {
        short_name: "stdio",
        provider_id: "std.messaging.stdio",
        direction: "bidirectional",
        identity: "claimed_actor",
        interactions: &["buttons"],
        content: &["text", "markdown"],
        delivery_receipts: &["accepted", "failed"],
    },
];

/// Resolve a channel's declared `provider <p>` identifier against the v1
/// provider reports: the short name (`local`) or the full binding provider id
/// (`std.messaging.local`) both resolve. `None` = unknown identifier, a check
/// error (spec/std-messaging.md open question 2 resolved: short names resolved
/// against contributed provider kinds, unknown = check error).
pub fn channel_provider_report(provider: &str) -> Option<&'static ChannelProviderReport> {
    CHANNEL_PROVIDER_REPORTS
        .iter()
        .find(|report| report.short_name == provider || report.provider_id == provider)
}

/// The built-in resource gauges: deterministic observables already in the
/// effect ledger, present without declaration (improve design note §3).
/// `std.cache_hit` is the provider prompt-cache hit rate (cache-read tokens /
/// total input-side tokens) — present only when the provider reports cache
/// usage (spec/inference-cache-note.md G2).
pub const BUILTIN_GAUGES: &[&str] = &["std.spend", "std.latency", "std.tokens", "std.cache_hit"];

/// The v1 std.files store providers (spec/std-files.md "Providers"): `local`
/// is the FileStore host-projection seam (native + DO) and the default when a
/// `file store` declares no `provider` clause. Non-filesystem providers
/// (S3/GitHub/Drive) are deferred with cause; an unknown identifier is a
/// check error at the declaration.
pub const FILE_STORE_PROVIDERS: &[&str] = &["local"];

/// Cross-reference validation for the improve surface, run after the item
/// loop so declaration order never matters: judge `coerce` targets must
/// resolve, derived-gauge inputs and campaign gauge references must name a
/// declared gauge or a built-in resource gauge, and a campaign's partition
/// must be disjoint (a gauge cannot be both ascended and sacrificed).
fn validate_improve_declarations(ir: &IrProgram, diagnostics: &mut Vec<Diagnostic>) {
    // A mark rides a committing site: its `after` target must be a rule
    // (flow segments have lowered to `flow.<name>.segN` rules by now).
    for mark in &ir.marks {
        if !ir.rules.iter().any(|rule| rule.name == mark.site) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: mark.span,
                message: format!("mark `{}` rides unknown site `{}`", mark.name, mark.site),
                suggestion: Some(format!(
                    "declared rules: {}",
                    ir.rules
                        .iter()
                        .map(|rule| rule.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            });
        }
    }
    let gauge_names: BTreeSet<&str> = ir.gauges.iter().map(|gauge| gauge.name.as_str()).collect();
    let resolves = |name: &str| gauge_names.contains(name) || BUILTIN_GAUGES.contains(&name);
    let unknown = |name: &str, span: SourceSpan, diagnostics: &mut Vec<Diagnostic>| {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span,
            message: format!("unknown gauge `{name}`"),
            suggestion: Some(format!(
                "declare `gauge {name} {{ ... }}` or use a built-in gauge ({})",
                BUILTIN_GAUGES.join(", ")
            )),
        });
    };
    for gauge in &ir.gauges {
        if gauge.judge_kind == "coerce" {
            match ir
                .coerces
                .iter()
                .find(|coerce| coerce.name == gauge.judge_target)
            {
                None => {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: gauge.span,
                        message: format!(
                            "gauge `{}` judges via undeclared coerce `{}`",
                            gauge.name, gauge.judge_target
                        ),
                        suggestion: Some("declare the coerce this gauge judges with".to_owned()),
                    });
                }
                // Explicit-argument binding (settled 2026-07-14): the
                // judge's data diet is written down, never inferred. The
                // single reserved `record` passes the whole judge-input
                // record to a one-parameter coerce; otherwise each path
                // (`input.…` / `facts.<Class>.<field>`) feeds the
                // parameter at its position, arity-checked here so a
                // drifted signature is a check error, not a silently
                // rebound judge.
                Some(coerce) if !gauge.judge_args.is_empty() => {
                    if gauge.judge_args.len() == 1 && gauge.judge_args[0] == "record" {
                        if coerce.params.len() != 1 {
                            diagnostics.push(Diagnostic {
                                related: Vec::new(),
                                span: gauge.span,
                                message: format!(
                                    "gauge `{}`: the reserved `(record)` form needs a \
                                     single-parameter coerce; `{}` takes {}",
                                    gauge.name,
                                    gauge.judge_target,
                                    coerce.params.len()
                                ),
                                suggestion: Some(
                                    "give the coerce one record-shaped parameter, or bind each \
                                     parameter to an explicit path"
                                        .to_owned(),
                                ),
                            });
                        }
                    } else {
                        for arg in &gauge.judge_args {
                            let head = arg.split('.').next().unwrap_or_default();
                            let valid = match head {
                                "record" => false, // reserved: only alone
                                "input" => true,
                                "facts" => arg.splitn(3, '.').count() == 3,
                                _ => false,
                            };
                            if !valid {
                                diagnostics.push(Diagnostic {
                                    related: Vec::new(),
                                    span: gauge.span,
                                    message: format!(
                                        "gauge `{}`: judge argument `{arg}` is not a record \
                                         path",
                                        gauge.name
                                    ),
                                    suggestion: Some(
                                        "arguments are `input.<path>`, \
                                         `facts.<Class>.<field...>`, or the single reserved \
                                         `record`"
                                            .to_owned(),
                                    ),
                                });
                            }
                        }
                        if gauge.judge_args.len() != coerce.params.len() {
                            diagnostics.push(Diagnostic {
                                related: Vec::new(),
                                span: gauge.span,
                                message: format!(
                                    "gauge `{}`: judge passes {} argument{} but coerce `{}` \
                                     takes {}",
                                    gauge.name,
                                    gauge.judge_args.len(),
                                    if gauge.judge_args.len() == 1 { "" } else { "s" },
                                    gauge.judge_target,
                                    coerce.params.len()
                                ),
                                suggestion: Some(
                                    "bind one path per coerce parameter, in order".to_owned(),
                                ),
                            });
                        }
                    }
                }
                Some(_) => {}
            }
        }
        if !gauge.inputs.is_empty() && gauge.judge_kind != "exec" {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: gauge.span,
                message: format!(
                    "derived gauge `{}` must judge via exec (its judge receives the input score vector)",
                    gauge.name
                ),
                suggestion: Some("use `judge via exec \"<validator>\"`".to_owned()),
            });
        }
        for input in &gauge.inputs {
            if input == &gauge.name {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: gauge.span,
                    message: format!("derived gauge `{}` cannot input itself", gauge.name),
                    suggestion: None,
                });
            } else if !resolves(input) {
                unknown(input, gauge.span, diagnostics);
            }
        }
    }
    for campaign in &ir.campaigns {
        let mut named: Vec<(&str, &'static str)> = Vec::new();
        for name in &campaign.ascend {
            named.push((name, "ascend"));
        }
        for reach in &campaign.reach {
            named.push((&reach.gauge, "reach"));
        }
        for guard in &campaign.guard {
            named.push((&guard.gauge, "guard"));
        }
        for name in &campaign.sacrifice {
            named.push((name, "sacrifice"));
        }
        let mut seen: BTreeMap<&str, &'static str> = BTreeMap::new();
        for (name, role) in named {
            if !resolves(name) {
                unknown(name, campaign.span, diagnostics);
            }
            if let Some(previous) = seen.insert(name, role) {
                let message = if previous == role {
                    format!(
                        "campaign `{}` names gauge `{name}` twice in {role}",
                        campaign.name
                    )
                } else {
                    format!(
                        "campaign `{}` names gauge `{name}` as both {previous} and {role}",
                        campaign.name
                    )
                };
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: campaign.span,
                    message,
                    suggestion: Some("name each gauge once, in at most one clause".to_owned()),
                });
            }
        }
    }
}

/// The harness class (DR-0034). `Managed` = WhippleScript is the agent runtime
/// (owned; hermetic context, full provenance, reproducible). `Delegated` = a foreign
/// runtime WhippleScript invokes, which assembles its own context. The guarantee is
/// two-valued, so the class is too.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessClass {
    Managed,
    Delegated,
}

impl HarnessClass {
    pub fn as_str(self) -> &'static str {
        match self {
            HarnessClass::Managed => "managed",
            HarnessClass::Delegated => "delegated",
        }
    }
}

/// Classify a harness kind (DR-0034 Decision 6). Total over the supported kinds:
/// `owned` and the credential-free `fixture` model client are Managed; every other
/// kind (codex/claude sidecars, the `native-fixture` delegated adapter, `command`)
/// is Delegated. An unrecognized kind — validated registry-side by the CLI
/// (spec/std-agent.md "Open provider registry") — defaults to Delegated, never
/// granting the Managed guarantee to something unknown.
pub fn harness_class(kind: &str) -> HarnessClass {
    match kind {
        "owned" | "fixture" => HarnessClass::Managed,
        _ => HarnessClass::Delegated,
    }
}

fn validate_test_expr_source(
    label: &str,
    source: &str,
    span: SourceSpan,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if source.trim().is_empty() {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span,
            message: format!("{label} is empty"),
            suggestion: Some("provide an expression".to_owned()),
        });
        return;
    }
    if let Err(error) = parse_expression(source) {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span,
            message: format!("{label} is not a valid expression: {error}"),
            suggestion: None,
        });
    }
}

/// The string-literal values of a literal-union (or single-literal) type, or `None`
/// if the type is not a pure string-literal union. Used to validate Family B
/// discriminants.
fn literal_union_values(ty: &TypeSyntax) -> Option<Vec<String>> {
    match ty {
        TypeSyntax::LiteralString { value, .. } => Some(vec![value.clone()]),
        TypeSyntax::Union { variants, .. } => {
            let values = variants
                .iter()
                .filter_map(|variant| match variant {
                    TypeSyntax::LiteralString { value, .. } => Some(value.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            (!values.is_empty() && values.len() == variants.len()).then_some(values)
        }
        _ => None,
    }
}

/// Family B validation (spec/decision-records/discriminated-families-design.md §6.3):
/// every `<field> <T> when <disc> is "<lit>"` must name a same-schema discriminant
/// that is a string-literal union, and `<lit>` must be one of its values.
fn validate_presence_conditions(
    container: &str,
    fields: &[ClassField],
    diagnostics: &mut Vec<Diagnostic>,
) {
    for field in fields {
        let Some((disc, literal)) = &field.presence_condition else {
            continue;
        };
        let Some(disc_field) = fields.iter().find(|candidate| &candidate.name.name == disc) else {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: field.span,
                message: format!(
                    "`{container}` field `{}` is conditioned on unknown discriminant `{disc}`",
                    field.name.name
                ),
                suggestion: Some(
                    "`when <field> is \"...\"` must name a literal-union field of the same schema"
                        .to_owned(),
                ),
            });
            continue;
        };
        match literal_union_values(&disc_field.ty) {
            Some(values) if values.iter().any(|value| value == literal) => {}
            Some(values) => diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: field.span,
                message: format!(
                    "`{container}` field `{}` is conditioned on `{disc} is \"{literal}\"`, which is not a value of `{disc}`",
                    field.name.name
                ),
                suggestion: Some(format!("use one of: {}", values.join(", "))),
            }),
            None => diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: field.span,
                message: format!(
                    "`{container}` field `{}` is conditioned on `{disc}`, which is not a string-literal discriminant",
                    field.name.name
                ),
                suggestion: Some(
                    "the discriminant must be a string-literal union, e.g. `kind \"a\" | \"b\"`"
                        .to_owned(),
                ),
            }),
        }
    }
}

/// The coerce body is a clause list — `prompt` (single or multi-line) and
/// `provider <name>` — not free text. Reject anything else so a typo'd
/// `promt` (which would otherwise silently produce a coercion with NO prompt)
/// or a stray field fails at `check`, matching the agent-block posture.
/// The backend named by a coerce declaration's `provider <name>` clause.
///
/// Mirrors `validate_coerce_body_fields`'s prompt tracking exactly: a `provider`
/// line inside a `"""` prompt is prose the model reads, not a clause, and
/// reading it as one would let a prompt rename the endpoint its own egress is
/// judged against.
fn coerce_declared_provider(body: &str) -> Option<String> {
    let mut in_prompt = false;
    let mut awaiting_opener = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if in_prompt {
            if trimmed.matches('"').count() >= 3 && trimmed.matches("\"\"\"").count() % 2 == 1 {
                in_prompt = false;
            }
            continue;
        }
        if awaiting_opener {
            if trimmed.is_empty() {
                continue;
            }
            awaiting_opener = false;
            if let Some(after_opener) = trimmed.strip_prefix("\"\"\"") {
                if after_opener.matches("\"\"\"").count() % 2 == 0 {
                    in_prompt = true;
                }
                continue;
            }
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "prompt" {
            awaiting_opener = true;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("prompt ") {
            if let Some(after_opener) = rest.strip_prefix("\"\"\"") {
                if after_opener.matches("\"\"\"").count() % 2 == 0 {
                    in_prompt = true;
                }
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("provider ") {
            let mut tokens = rest.split_whitespace();
            if let (Some(name), None) = (tokens.next(), tokens.next()) {
                return Some(name.to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "lib_tests/coerce_provider.rs"]
mod coerce_provider_tests;

fn validate_coerce_body_fields(coerce: &CoerceDecl, diagnostics: &mut Vec<Diagnostic>) {
    let mut in_prompt = false;
    let mut awaiting_opener = false;
    for line in coerce.body.text.lines() {
        let trimmed = line.trim();
        if in_prompt {
            // A line with an odd number of `"""` markers closes the prompt.
            if trimmed.matches("\"\"\"").count() % 2 == 1 {
                in_prompt = false;
            }
            continue;
        }
        if awaiting_opener {
            // Bare `prompt` on its own line: the opener is the next
            // non-empty line.
            if trimmed.is_empty() {
                continue;
            }
            awaiting_opener = false;
            if let Some(after_opener) = trimmed.strip_prefix("\"\"\"") {
                if after_opener.matches("\"\"\"").count() % 2 == 0 {
                    in_prompt = true;
                }
                continue;
            }
            // fall through: not an opener — validate as a clause line
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "prompt" {
            awaiting_opener = true;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("prompt ") {
            let rest = rest.trim_start();
            if let Some(after_opener) = rest.strip_prefix("\"\"\"") {
                // `prompt """…` (optionally annotated): multi-line unless the
                // triple quote closes on the same line.
                if after_opener.matches("\"\"\"").count() % 2 == 0 {
                    in_prompt = true;
                }
            }
            // Single-quoted one-line prompts close on their own line.
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("provider ") {
            if rest.split_whitespace().count() != 1 {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: coerce.name.span,
                    message: format!(
                        "coerce `{}` has a malformed `provider` clause: `{trimmed}`",
                        coerce.name.name
                    ),
                    suggestion: Some("write `provider <name>`".to_owned()),
                });
            }
            continue;
        }
        let field = trimmed.split_whitespace().next().unwrap_or(trimmed);
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: coerce.name.span,
            message: format!(
                "unknown coerce field `{field}` on coerce `{}`",
                coerce.name.name
            ),
            suggestion: Some("supported coerce fields are `prompt` and `provider`".to_owned()),
        });
    }
}

/// Every credential kind as SOURCE spells it — underscored, because the lexer
/// reads one identifier there. Derived from the protocol's closed set rather
/// than typed out, so a kind added to `CredentialKind` appears in every
/// suggestion that lists them instead of in whichever one someone remembered.
pub(crate) fn credential_kind_spellings() -> Vec<String> {
    use whipplescript_custody::CredentialKind::*;
    [Bearer, Basic, Raw, HmacSha256, Ed25519, AwsSigv4, JwtRs256]
        .iter()
        .map(|kind| kind.as_str().replace('-', "_"))
        .collect()
}

fn validate_type_refs(
    ty: &TypeSyntax,
    schema_names: &BTreeSet<String>,
    agent_names: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match ty {
        TypeSyntax::Primitive { .. } | TypeSyntax::LiteralString { .. } => {}
        // The discriminant ranges over a protocol-owned set rather than over
        // this program's schemas, so what there is to resolve is the kind
        // itself. Refused here rather than widened silently to the bare form:
        // `secret<ed25519>` misspelled is a narrowing the author asked for
        // and did not get, which is the over-promise DR-0053 §14 rejects one
        // construct over.
        TypeSyntax::Secret {
            kind: Some(kind), ..
        } => {
            let normalized = kind.name.replace('_', "-");
            if whipplescript_custody::CredentialKind::parse(&normalized).is_err() {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: kind.span,
                    message: format!("`secret` names unknown credential kind `{}`", kind.name),
                    suggestion: Some(format!(
                        "name one of: {}",
                        credential_kind_spellings().join(", ")
                    )),
                });
            }
        }
        TypeSyntax::Secret { kind: None, .. } => {}
        TypeSyntax::Ref { name } => {
            if !schema_names.contains(&name.name) && !is_builtin_schema_ref(&name.name) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: name.span,
                    message: format!("unknown schema reference `{}`", name.name),
                    suggestion: Some(format!(
                        "declare `class {}` or `enum {}` before using it",
                        name.name, name.name
                    )),
                });
            }
        }
        TypeSyntax::AgentRef { agents, .. } => {
            let mut seen = BTreeSet::new();
            for agent in agents {
                if !seen.insert(agent.name.clone()) {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: agent.span,
                        message: format!("AgentRef lists agent `{}` more than once", agent.name),
                        suggestion: Some(
                            "remove the duplicate agent from the AgentRef domain".to_owned(),
                        ),
                    });
                }
                if !agent_names.contains(&agent.name) {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: agent.span,
                        message: format!("AgentRef references unknown agent `{}`", agent.name),
                        suggestion: Some(format!(
                            "declare `agent {}` before using it in AgentRef",
                            agent.name
                        )),
                    });
                }
            }
        }
        TypeSyntax::Optional { inner, .. }
        | TypeSyntax::Array { inner, .. }
        | TypeSyntax::Map { inner, .. }
        | TypeSyntax::Sealed { inner, .. } => {
            validate_type_refs(inner, schema_names, agent_names, diagnostics)
        }
        TypeSyntax::Union { variants, .. } => {
            for variant in variants {
                validate_type_refs(variant, schema_names, agent_names, diagnostics);
            }
        }
    }
}

fn is_builtin_schema_ref(name: &str) -> bool {
    matches!(
        name,
        "AgentTurn"
            | "WorkItem"
            | "Evidence"
            | "VcsChange"
            | "VcsContention"
            | "VcsPromotion"
            | "VcsStall"
            | "TerminalFailed"
            | "TerminalTimedOut"
            | "TerminalCancelled"
            | "TerminalOutcome"
    )
}

/// The terminal-family schemas are `origin = observer` (discriminated-families
/// design §5.4): the kernel projects them when it observes an effect or child
/// terminal, and user rules may only *eliminate* them (`after … fails/times
/// out/cancels as f`), never *construct* them. A rule that `record`s one would
/// forge a terminal outcome the kernel never produced, misleading the
/// `after`/terminal-case reaction machinery. Rejected at check time.
fn is_observer_only_schema(name: &str) -> bool {
    matches!(
        name,
        "TerminalFailed"
            | "TerminalTimedOut"
            | "TerminalCancelled"
            | "TerminalOutcome"
            // std.vcs observer schemas: the mediator emits them; a rule
            // that `record`s one forges a workspace observation.
            | "VcsChange"
            | "VcsContention"
            | "VcsPromotion"
            | "VcsStall"
    )
}

fn validate_canonical_rule_body_syntax(rule: &RuleDecl, diagnostics: &mut Vec<Diagnostic>) {
    for line in rule.body.text.lines().map(str::trim) {
        if line.starts_with("then ") {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` uses unsupported `then` sequencing",
                    rule.name.name
                ),
                suggestion: Some(
                    "use `after <effect> succeeds { ... }` blocks for effect sequencing".to_owned(),
                ),
            });
        }
        if line.starts_with("after ") && line.contains("=>") {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` uses unsupported `after ... =>` sequencing",
                    rule.name.name
                ),
                suggestion: Some("write `after <effect> succeeds { ... }`".to_owned()),
            });
        }
    }
}

/// Reject an effect-bearing cycle in the rule dependency graph
/// (`graph.unbounded_effect_recursion`).
///
/// `spec/static-analysis.md` ("Rule Dependency Graph") classifies the strongly
/// connected components of this graph and calls for exactly one of them to be
/// refused: *effectful internal recursion: rejected unless explicitly proven
/// bounded*. Nothing implemented the classification. `validate_effectful_self_trigger`
/// answers the ONE-rule case — a rule that preserves its own trigger — and a
/// cycle passed between TWO rules escaped it entirely, while the compiler went
/// on to print that same cycle in its own `rule_dependencies` snapshot. Each
/// turn of such a cycle enqueues real external effects, under a fresh
/// idempotency key each time, so exactly-once dedup never brakes it.
///
/// WHAT IS REFUSED, precisely: a component of two or more rules that are
/// mutually reachable over produce/consume edges, at least one of which runs an
/// effect. The other three SCC classes the spec names are left alone — a
/// component with no effects is pure monotonic recursion (allowed), and
/// recursion through an external event or clock is invisible to this graph in
/// the first place, because such a trigger is a `pattern:` read that no
/// `schema:` write can match.
///
/// SELF-EDGES ARE NOT THIS CHECK'S. A one-rule cycle stays with
/// `validate_effectful_self_trigger` and its `consume`-or-advance escape, which
/// is the shape `docs/manual/13-agent-patterns.md` teaches as the retry idiom.
/// Reporting it twice would say nothing new and would break that rule's
/// established diagnostic.
///
/// THE ESCAPE is `@external` on any rule in the component: the tag declares that
/// this rule's facts arrive from outside the workflow, which is the author
/// saying the recurrence is not internal. It is the same tag, with the same
/// meaning, that `lint_workflow_liveness` already honours. There is no
/// bounded-recursion escape yet, exactly as there is none for recursive
/// `apply`: until a statically-decreasing measure exists to prove a bound with,
/// the spec's "unless explicitly proven bounded" has no way to be satisfied and
/// every such cycle is refused.
fn validate_effectful_rule_recursion(ir: &IrProgram, diagnostics: &mut Vec<Diagnostic>) {
    let rules = &ir.rules;
    if rules.len() < 2 {
        return;
    }
    let index_of = rules
        .iter()
        .enumerate()
        .map(|(index, rule)| (rule.name.as_str(), index))
        .collect::<BTreeMap<_, _>>();

    // Adjacency, self-edges dropped: they belong to the per-rule check above.
    let mut reaches = vec![vec![false; rules.len()]; rules.len()];
    for dependency in &ir.rule_dependencies {
        let (Some(&producer), Some(&consumer)) = (
            index_of.get(dependency.producer.as_str()),
            index_of.get(dependency.consumer.as_str()),
        ) else {
            continue;
        };
        if producer != consumer {
            reaches[producer][consumer] = true;
        }
    }
    // Transitive closure. A rule set is small enough that the plain cubic form
    // is both fast enough and the version a reader can check by eye.
    for via in 0..rules.len() {
        for from in 0..rules.len() {
            if !reaches[from][via] {
                continue;
            }
            let through = reaches[via].clone();
            for (to, reachable) in through.into_iter().enumerate() {
                if reachable {
                    reaches[from][to] = true;
                }
            }
        }
    }

    let external = |name: &str| {
        ir.source_tags
            .iter()
            .any(|tag| tag.target_kind == "rule" && tag.name == "external" && tag.target == name)
    };

    let mut reported = vec![false; rules.len()];
    for start in 0..rules.len() {
        if reported[start] {
            continue;
        }
        // The component: every rule mutually reachable with `start`.
        let component = (0..rules.len())
            .filter(|&other| other == start || (reaches[start][other] && reaches[other][start]))
            .collect::<Vec<_>>();
        if component.len() < 2 {
            continue;
        }
        for &member in &component {
            reported[member] = true;
        }
        if component
            .iter()
            .any(|&member| external(&rules[member].name))
        {
            continue;
        }
        let Some(&effectful) = component
            .iter()
            .find(|&&member| !rules[member].metadata.effects.is_empty())
        else {
            continue;
        };

        // Name a concrete round trip rather than an unordered set: BFS from the
        // effectful rule back to itself over the direct edges of the component.
        let cycle = shortest_rule_cycle(ir, rules, &index_of, effectful, &component)
            .unwrap_or_else(|| vec![rules[effectful].name.clone()]);
        // The span of the effect that the cycle re-runs: the most useful line to
        // stand on, and the only span an `IrRule` carries.
        let span = rules[effectful]
            .metadata
            .effects
            .first()
            .map(|effect| effect.span)
            .unwrap_or(SourceSpan { start: 0, end: 0 });
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span,
            message: format!(
                "effectful rule cycle is not allowed (graph.unbounded_effect_recursion): rule cycle {}, and rule `{}` runs effects on every turn of it",
                cycle.join(" -> "),
                rules[effectful].name
            ),
            suggestion: Some(
                "break the cycle: an effect-bearing cycle in the rule dependency graph has no compile-time bound, so each turn enqueues fresh effects forever — consume the triggering fact without recording one the cycle reads back, route the recurrence through an external event or clock, or tag a rule `@external` when its facts genuinely arrive from outside the workflow"
                    .to_owned(),
            ),
        });
    }
}

/// The shortest produce/consume round trip from `start` back to `start`, staying
/// inside `component`, rendered as rule names. Used only to make the diagnostic
/// name a path a reader can follow.
fn shortest_rule_cycle(
    ir: &IrProgram,
    rules: &[IrRule],
    index_of: &BTreeMap<&str, usize>,
    start: usize,
    component: &[usize],
) -> Option<Vec<String>> {
    let mut adjacency: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for dependency in &ir.rule_dependencies {
        let (Some(&producer), Some(&consumer)) = (
            index_of.get(dependency.producer.as_str()),
            index_of.get(dependency.consumer.as_str()),
        ) else {
            continue;
        };
        if producer != consumer && component.contains(&producer) && component.contains(&consumer) {
            adjacency.entry(producer).or_default().insert(consumer);
        }
    }
    let mut queue: VecDeque<usize> = VecDeque::new();
    let mut predecessor: BTreeMap<usize, usize> = BTreeMap::new();
    for &next in adjacency.get(&start).into_iter().flatten() {
        if predecessor.insert(next, start).is_none() {
            queue.push_back(next);
        }
    }
    while let Some(node) = queue.pop_front() {
        for &next in adjacency.get(&node).into_iter().flatten() {
            if next == start {
                let mut path = vec![rules[node].name.clone()];
                let mut cursor = node;
                while cursor != start {
                    cursor = predecessor[&cursor];
                    path.push(rules[cursor].name.clone());
                }
                path.reverse();
                path.push(rules[start].name.clone());
                return Some(path);
            }
            if predecessor.insert(next, node).is_none() {
                queue.push_back(next);
            }
        }
    }
    None
}

/// The fact identifiers one rule reads, as the dependency graph must see them.
///
/// `fact_read_from_when` keys a `when` clause on its FIRST token, so the
/// explicit `when fact <Class> as x` form is recorded as `pattern:fact <Class>
/// as x` — lowercase `fact` is not a class name — while a write is always
/// `schema:<Class>`. The two could therefore never meet, and a rule that
/// triggers through the explicit form contributed no incoming edge at all: a
/// real producer/consumer pair was simply invisible to every analysis built on
/// this graph. `lint_workflow_liveness` already special-cases the same form for
/// the same reason; this is that special case, at the graph.
///
/// Normalising only when the name is capitalised keeps the built-in observer
/// triggers (`when fact agent.turn.completed as ev`) out of it — they name no
/// class, so they can match no write, and passing them through unchanged is
/// both cheaper and truthful.
fn dependency_read_facts(metadata: &IrRuleMetadata) -> Vec<String> {
    metadata
        .fact_reads
        .iter()
        .map(|read| {
            let Some(pattern) = read.strip_prefix("pattern:fact ") else {
                return read.clone();
            };
            match pattern.split_whitespace().next() {
                Some(name) if name.starts_with(char::is_uppercase) => format!("schema:{name}"),
                _ => read.clone(),
            }
        })
        .collect()
}

fn build_rule_dependencies(rules: &[IrRule]) -> Vec<IrRuleDependency> {
    let reads_by_rule = rules
        .iter()
        .map(|rule| dependency_read_facts(&rule.metadata))
        .collect::<Vec<_>>();
    let mut dependencies = Vec::new();
    for producer in rules {
        for produced_fact in &producer.metadata.fact_writes {
            for (consumer, reads) in rules.iter().zip(&reads_by_rule) {
                if reads.contains(produced_fact) {
                    dependencies.push(IrRuleDependency {
                        producer: producer.name.clone(),
                        consumer: consumer.name.clone(),
                        fact: produced_fact.clone(),
                    });
                }
            }
        }
    }
    dependencies.sort_by(|left, right| {
        (&left.producer, &left.consumer, &left.fact).cmp(&(
            &right.producer,
            &right.consumer,
            &right.fact,
        ))
    });
    dependencies
}

/// `send via <channel>` (std.messaging) must name a declared `channel`. The
/// channel name is carried as the construct's `channel` field; an unknown channel
/// would lower to a `messaging.send` effect that no provider can route, so it is
/// rejected at compile time (mirrors `acquire`/`consume` resource-existence checks).
/// `when message from <channel> as msg` (spec/messaging.md) must name a declared
/// channel, mirroring the outbound `send via <channel>` check.
fn validate_message_from_channels(
    rule: &RuleDecl,
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for when in &rule.whens {
        let (pattern, _) = split_when_guard(&when.text);
        let Some(rest) = pattern.trim_start().strip_prefix("message from ") else {
            continue;
        };
        let Some(channel) = rest.split_whitespace().next() else {
            continue;
        };
        if !semantic.channels.iter().any(|c| c.as_str() == channel) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: when.span,
                message: format!("`when message from {channel}` names an unknown channel"),
                suggestion: Some(
                    "declare it with `channel <name> { provider … }`, or correct the channel name"
                        .to_owned(),
                ),
            });
            continue;
        }
        // Capability-report-conditioned check (spec/std-messaging.md "Static
        // checks"): inbound observation requires the channel provider's report
        // `direction` ∈ {inbound_only, bidirectional}. Desktop channels are a
        // check error here — send/receive-capable are distinguishable (the v1
        // acceptance test). Unknown providers already errored at the channel
        // declaration, so they are not re-flagged here.
        if let Some(report) = semantic
            .channel_providers
            .get(channel)
            .and_then(|provider| channel_provider_report(provider))
        {
            if report.direction == "outbound_only" {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: when.span,
                    message: format!(
                        "`when message from {channel}` observes a channel whose provider `{}` is outbound-only (its capability report cannot deliver inbound messages)",
                        report.short_name
                    ),
                    suggestion: Some(
                        "route inbound observation through an inbound-capable provider (`local`, `stdio`, `fixture`)"
                            .to_owned(),
                    ),
                });
            }
        }
    }
}

fn validate_send_channels(
    body_ast: &body::BodyAst,
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    fn walk(
        statements: &[body::BodyStmt],
        semantic: &SemanticContext,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        for statement in statements {
            match statement {
                body::BodyStmt::Effect(effect) => {
                    if let body::BodyEffectKind::ConstructCapabilityCall {
                        keyword, fields, ..
                    } = &effect.kind
                    {
                        if keyword == "send" {
                            if let Some(channel) =
                                fields.iter().find(|field| field.name == "channel")
                            {
                                if !semantic.channels.contains(&channel.source) {
                                    diagnostics.push(Diagnostic {
                                        related: Vec::new(),
                                        span: effect.span,
                                        message: format!(
                                            "`send via {}` names an unknown channel",
                                            channel.source
                                        ),
                                        suggestion: Some(
                                            "declare it with `channel <name> { provider … }`, or correct the channel name"
                                                .to_owned(),
                                        ),
                                    });
                                } else if let Some(report) = semantic
                                    .channel_providers
                                    .get(&channel.source)
                                    .and_then(|provider| channel_provider_report(provider))
                                {
                                    // Capability-report-conditioned check
                                    // (spec/std-messaging.md "Static checks"):
                                    // outbound `send via` requires the provider
                                    // report `direction` ∈ {outbound_only,
                                    // bidirectional}. No v1 provider is
                                    // inbound-only, so this arm has no
                                    // reachable negative today; it exists so a
                                    // future inbound-only provider fails
                                    // closed at check time, not at dispatch.
                                    if report.direction == "inbound_only" {
                                        diagnostics.push(Diagnostic {
                                            related: Vec::new(),
                                            span: effect.span,
                                            message: format!(
                                                "`send via {}` targets a channel whose provider `{}` is inbound-only (its capability report cannot accept outbound sends)",
                                                channel.source, report.short_name
                                            ),
                                            suggestion: Some(
                                                "send through an outbound-capable provider (`local`, `desktop`, `stdio`, `fixture`)"
                                                    .to_owned(),
                                            ),
                                        });
                                    }
                                }
                            }
                        }
                        // MEM-1 check 1: the memory operations must name a
                        // DECLARED pool — the twin of the send-channel check.
                        if matches!(keyword.as_str(), "recall" | "learn" | "curate") {
                            if let Some(pool) = fields.iter().find(|field| field.name == "pool") {
                                if !semantic.memory_pools.contains(&pool.source) {
                                    diagnostics.push(Diagnostic {
                                        related: Vec::new(),
                                        span: effect.span,
                                        message: format!(
                                            "`{keyword}` names unknown memory pool `{}`",
                                            pool.source
                                        ),
                                        suggestion: Some(
                                            "declare it with `memory pool <name> { … }`, or correct the pool name"
                                                .to_owned(),
                                        ),
                                    });
                                }
                            }
                        }
                    }
                }
                body::BodyStmt::After(after) => walk(&after.body, semantic, diagnostics),
                body::BodyStmt::Case(case) => {
                    for branch in &case.branches {
                        walk(&branch.body, semantic, diagnostics);
                    }
                }
                _ => {}
            }
        }
    }
    walk(&body_ast.statements, semantic, diagnostics);
}

/// In-turn agent observations — `agent.turn.streamed` (streamed progress),
/// `agent.turn.tool_requested` (in-turn tool call), and `agent.turn.artifact_captured`
/// (captured artifact/diff) — are recorded as EVIDENCE, never as rule-matchable facts
/// (spec/agent-harness.md). The rule-matchable lifecycle facts are
/// `agent.turn.started/completed/failed/timed_out/cancelled`. A `when` that matches an
/// evidence-only fact can never fire, so it is a compile-time error.
const EVIDENCE_ONLY_TURN_FACTS: [&str; 3] = [
    "agent.turn.streamed",
    "agent.turn.tool_requested",
    "agent.turn.artifact_captured",
];

/// Structural well-formedness of access grants (`with access to <resource> { … }`):
/// a grant must grant at least one operation, and a single effect must not list the
/// same resource twice (merge them). The deeper "required
/// Resource/Operation/Capability ports" validation against the capability registry
/// is a separate construct-graph-layer concern, so this stays registry-independent
/// and zero-false-positive.
fn validate_turn_access_grants(
    rule: &RuleDecl,
    metadata: &IrRuleMetadata,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for effect in &metadata.effects {
        if effect.access_grants.is_empty() {
            continue;
        }
        let mut seen = BTreeSet::new();
        for grant in &effect.access_grants {
            if grant.operations.is_empty() {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: effect.span,
                    message: format!(
                        "rule `{}` has a `with access to {}` grant that grants no operations",
                        rule.name.name, grant.resource
                    ),
                    suggestion: Some(
                        "list at least one operation in the grant block, or drop the grant"
                            .to_owned(),
                    ),
                });
            }
            validate_credential_grant_classes(rule, effect.span, grant, diagnostics);
            if !seen.insert(grant.resource.clone()) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: effect.span,
                    message: format!(
                        "rule `{}` lists access resource `{}` more than once on one effect",
                        rule.name.name, grant.resource
                    ),
                    suggestion: Some(
                        "merge the grant clauses for a resource into a single block".to_owned(),
                    ),
                });
            }
        }
    }
}

/// DR-0053 §14 as extended by DR-0074 §2: each custody operation declares how
/// it may be narrowed, and a grant that narrows it the wrong way is a check
/// error rather than a clause that reads as narrowed while meaning nothing.
///
/// Only `credential` grants are classed here. Every other resource keeps its
/// own vocabulary, and an operation name that happens to collide with a custody
/// one must not be dragged into custody's rules.
fn validate_credential_grant_classes(
    rule: &RuleDecl,
    span: SourceSpan,
    grant: &IrAccessGrant,
    diagnostics: &mut Vec<Diagnostic>,
) {
    use whipplescript_custody::{GrantClass, Operation};

    let Some(credential) = grant.resource.strip_prefix("credential ") else {
        return;
    };
    for op in &grant.operations {
        let Ok(operation) = Operation::parse(&op.operation) else {
            continue;
        };
        let class = operation.grant_class();
        let (bad, detail) = match class {
            GrantClass::Narrowable => (op.globs.is_empty(), "names no glob list"),
            GrantClass::TypeNarrowed => match (&op.target, op.globs.is_empty()) {
                (None, _) => (true, "names no type"),
                (Some(_), false) => (true, "carries a glob list as well as a type"),
                (Some(_), true) => (false, ""),
            },
            GrantClass::NonNarrowable => (
                op.target.is_some() || !op.globs.is_empty(),
                "carries a narrowing clause",
            ),
        };
        if !bad {
            continue;
        }
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span,
            message: format!(
                "rule `{}` grants `{}` on credential `{credential}` but {detail}: this operation takes {}",
                rule.name.name,
                op.operation,
                class.requirement()
            ),
            suggestion: Some(match class {
                GrantClass::Narrowable => format!(
                    "narrow it, as in `{} [\"host/path/*\"]`",
                    op.operation
                ),
                // Failing closed is the point: reading a bare `unwrap` as
                // "every type" would preserve exactly the over-grant DR-0074
                // exists to remove.
                GrantClass::TypeNarrowed => format!(
                    "name the type it may open, as in `{} for PatientRecord`",
                    op.operation
                ),
                GrantClass::NonNarrowable => format!(
                    "name it bare, as in `{}`",
                    op.operation
                ),
            }),
        });
    }
}

fn validate_evidence_fact_not_matched(rule: &RuleDecl, diagnostics: &mut Vec<Diagnostic>) {
    for when in &rule.whens {
        let (pattern, _) = split_when_guard(&when.text);
        let Some(name) = runtime_fact_name_for_pattern(pattern) else {
            continue;
        };
        if EVIDENCE_ONLY_TURN_FACTS.contains(&name.as_str()) {
            diagnostics.push(Diagnostic { related: Vec::new(),
                span: when.span,
                message: format!(
                    "rule `{}` matches evidence-only fact `{name}`: in-turn observations are evidence, not rule-matchable facts",
                    rule.name.name
                ),
                suggestion: Some(
                    "match a lifecycle fact (`agent.turn.completed`/`failed`/`timed_out`/`cancelled`) and read in-turn detail from its evidence".to_owned(),
                ),
            });
        }
    }
}

/// DR-0043 Decision 5: extracts each rule's `during`/`until` region (at most
/// one per rule in v1), REWRITES the rule body to the condition-HOLDS variant
/// (region content spliced inline — every downstream scanner and effect-id
/// derivation sees ordinary text), and returns the pre-rendered region
/// metadata (removed / lapsed variants, region effect scopes) to attach onto
/// the lowered `IrRule`s.
fn extract_rule_regions(
    items: &mut [Item],
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeMap<String, IrRegion> {
    let mut pending = BTreeMap::new();
    for item in items.iter_mut() {
        let Item::Rule(rule) = item else {
            continue;
        };
        let (ast, _) = body::parse_rule_body(&rule.body.text, rule.body.span.start);
        let mut regions = Vec::new();
        collect_region_blocks(&ast.statements, &[], &mut regions);
        if regions.is_empty() {
            continue;
        }
        if regions.len() > 1 {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: regions[1].0.span,
                message: format!(
                    "rule `{}` declares more than one `during`/`until` region",
                    rule.name.name
                ),
                suggestion: Some(
                    "v1 supports one region per rule (including nested regions); split the \
                     rule or merge the conditions"
                        .to_owned(),
                ),
            });
            continue;
        }
        let (region, region_case_arms) = regions[0].clone();
        if count_effect_statements(&region.body) == 0 {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: region.span,
                message: format!(
                    "the `{}` region in rule `{}` contains no progression",
                    if region.until { "until" } else { "during" },
                    rule.name.name
                ),
                suggestion: Some(
                    "a region around purely-atomic actions commits with admission and can \
                     never lapse between steps; it needs at least one effect with a \
                     continuation"
                        .to_owned(),
                ),
            });
            continue;
        }
        // Lapse-arm binding scope: the arm may run at ANY point inside the
        // region, so it may only reference bindings guaranteed at region
        // entry — never a binding the region itself introduces (the optional
        // progress view is the sanctioned window into those).
        let mut region_bindings = BTreeSet::new();
        collect_all_binding_names(&region.body, &mut region_bindings);
        if let Some(view) = &region.lapse_binding {
            region_bindings.remove(view);
        }
        let mut arm_roots = BTreeSet::new();
        collect_statement_roots(&region.lapse_body, &mut arm_roots);
        for root in &arm_roots {
            if region_bindings.contains(root) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: region.span,
                    message: format!(
                        "the `on lapse` arm of rule `{}` references `{root}`, a binding the \
                         region introduces — it may not exist when the arm runs",
                        rule.name.name
                    ),
                    suggestion: Some(
                        "reference only bindings from before the region, or bind the \
                         progress view (`on lapse as got`) and read `got.<binding>` — its \
                         fields are present exactly if that step settled"
                            .to_owned(),
                    ),
                });
            }
        }
        // Variant surgery. All spans are absolute; rebase onto the body text.
        let base = rule.body.span.start;
        let text = rule.body.text.clone();
        let clamp = |offset: usize| offset.saturating_sub(base).min(text.len());
        let (r_start, r_end) = (clamp(region.span.start), clamp(region.span.end));
        let (b_start, b_end) = (clamp(region.body_span.start), clamp(region.body_span.end));
        let (l_start, l_end) = (clamp(region.lapse_span.start), clamp(region.lapse_span.end));
        if !(r_start <= b_start
            && b_start <= b_end
            && b_end <= l_start
            && l_start <= l_end
            && l_end <= r_end)
        {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: region.span,
                message: format!(
                    "internal: region span reconstruction failed for rule `{}`",
                    rule.name.name
                ),
                suggestion: None,
            });
            continue;
        }
        let body_content = &text[b_start..b_end];
        let arm_content = &text[l_start..l_end];
        let variant_holds = format!("{}{}{}", &text[..r_start], body_content, &text[r_end..]);
        let variant_removed = format!("{}{}", &text[..r_start], &text[r_end..]);
        let variant_lapsed = format!("{}{}{}", &text[..r_start], arm_content, &text[r_end..]);
        // Region effect scopes, computed on the HOLDS variant (the canonical
        // kernel body): each region-owned effect binding's LEVEL-1 `after`
        // ancestor is the scope the kernel keys its effect id under.
        let mut effect_bindings = BTreeSet::new();
        collect_effect_binding_names(&region.body, &mut effect_bindings);
        let (holds_ast, _) = body::parse_rule_body(&variant_holds, 0);
        let mut region_effects = Vec::new();
        assign_region_effect_scopes(
            &holds_ast.statements,
            None,
            &effect_bindings,
            &mut region_effects,
        );
        pending.insert(
            rule.name.name.clone(),
            IrRegion {
                until: region.until,
                condition: region.condition.clone(),
                lapse_binding: region.lapse_binding.clone(),
                effects: region_effects,
                body_removed: variant_removed,
                body_lapsed: variant_lapsed,
                arm_content: arm_content.to_owned(),
                arm_case_arms: region_case_arms,
            },
        );
        rule.body.text = variant_holds;
    }
    pending
}

/// Every region in the body, each paired with the `(scrutinee, pattern)` chain of
/// the `case` arms that enclose it. The chain is what lets the lapse arm be
/// read-narrowed at the position the region actually sits in: an arm inside
/// `case e.kind { "deploy" => … }` inherits that arm's Family B allowances, so
/// checking it against the rule-top (empty) allowed set would reject a legal read.
fn collect_region_blocks(
    statements: &[body::BodyStmt],
    case_arms: &[(String, String)],
    out: &mut Vec<(body::RegionBlock, Vec<(String, String)>)>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Region(region) => {
                out.push((region.clone(), case_arms.to_vec()));
                collect_region_blocks(&region.body, case_arms, out);
                collect_region_blocks(&region.lapse_body, case_arms, out);
            }
            body::BodyStmt::After(after) => collect_region_blocks(&after.body, case_arms, out),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    let mut nested = case_arms.to_vec();
                    nested.push((case.scrutinee.clone(), branch.pattern.clone()));
                    collect_region_blocks(&branch.body, &nested, out);
                }
            }
            _ => {}
        }
    }
}

fn count_effect_statements(statements: &[body::BodyStmt]) -> usize {
    let mut count = 0;
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(_) => count += 1,
            body::BodyStmt::After(after) => count += count_effect_statements(&after.body),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    count += count_effect_statements(&branch.body);
                }
            }
            body::BodyStmt::Region(region) => {
                count += count_effect_statements(&region.body);
            }
            _ => {}
        }
    }
    count
}

fn collect_effect_binding_names(statements: &[body::BodyStmt], out: &mut BTreeSet<String>) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                if let Some(binding) = &effect.binding {
                    out.insert(binding.clone());
                }
            }
            body::BodyStmt::After(after) => collect_effect_binding_names(&after.body, out),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_effect_binding_names(&branch.body, out);
                }
            }
            body::BodyStmt::Region(region) => {
                collect_effect_binding_names(&region.body, out);
            }
            _ => {}
        }
    }
}

/// Walks the HOLDS-variant AST assigning each region-owned effect its LEVEL-1
/// `after` scope (the kernel's effect-id key component). `level1` is fixed at
/// the first `after` ancestor and inherited by everything deeper.
fn assign_region_effect_scopes(
    statements: &[body::BodyStmt],
    level1: Option<&(String, String)>,
    region_bindings: &BTreeSet<String>,
    out: &mut Vec<IrRegionEffect>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                if let Some(binding) = &effect.binding {
                    if region_bindings.contains(binding)
                        && !out.iter().any(|known| &known.binding == binding)
                    {
                        out.push(IrRegionEffect {
                            binding: binding.clone(),
                            scope: level1.cloned(),
                        });
                    }
                }
            }
            body::BodyStmt::After(after) => {
                let own = (
                    after.binding.clone(),
                    after.predicate.kernel_str().to_owned(),
                );
                let next = level1.cloned().unwrap_or(own);
                assign_region_effect_scopes(&after.body, Some(&next), region_bindings, out);
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    assign_region_effect_scopes(&branch.body, level1, region_bindings, out);
                }
            }
            body::BodyStmt::Region(region) => {
                assign_region_effect_scopes(&region.body, level1, region_bindings, out);
            }
            _ => {}
        }
    }
}

/// Root identifiers referenced by a statement list's value positions: record
/// fields, terminal fields, done/cancel bindings, effect arguments, and
/// `{{ … }}` prompt interpolations. Used for the lapse-arm scope check.
fn collect_statement_roots(statements: &[body::BodyStmt], out: &mut BTreeSet<String>) {
    fn roots_in_expr(source: &str, out: &mut BTreeSet<String>) {
        let bytes = source.as_bytes();
        let mut i = 0;
        let mut in_string = false;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c == '"' {
                in_string = !in_string;
                i += 1;
                continue;
            }
            if in_string {
                i += 1;
                continue;
            }
            if c.is_ascii_alphabetic() || c == '_' {
                let start = i;
                while i < bytes.len() {
                    let cj = bytes[i] as char;
                    if cj.is_ascii_alphanumeric() || cj == '_' {
                        i += 1;
                    } else {
                        break;
                    }
                }
                let preceded_by_dot = start > 0 && bytes[start - 1] as char == '.';
                if !preceded_by_dot {
                    out.insert(source[start..i].to_owned());
                }
                continue;
            }
            i += 1;
        }
    }
    fn roots_in_fields(fields: &[body::FieldAssign], out: &mut BTreeSet<String>) {
        for field in fields {
            match &field.value {
                body::FieldValue::Expr { source, .. } => roots_in_expr(source, out),
                body::FieldValue::Nested { fields, .. } => roots_in_fields(fields, out),
                body::FieldValue::Shorthand => {
                    out.insert(field.name.clone());
                }
            }
        }
    }
    fn roots_in_prompt(text: &str, out: &mut BTreeSet<String>) {
        let mut rest = text;
        while let Some(open) = rest.find("{{") {
            let tail = &rest[open + 2..];
            let Some(close) = tail.find("}}") else {
                break;
            };
            roots_in_expr(&tail[..close], out);
            rest = &tail[close + 2..];
        }
    }
    for statement in statements {
        match statement {
            body::BodyStmt::Record(record) => roots_in_fields(&record.fields, out),
            body::BodyStmt::Done {
                binding,
                replacement,
                ..
            } => {
                out.insert(binding.clone());
                if let Some(record) = replacement {
                    roots_in_fields(&record.fields, out);
                }
            }
            body::BodyStmt::Cancel { binding, .. } => {
                out.insert(binding.clone());
            }
            body::BodyStmt::Effect(effect) => {
                if let Some(prompt) = &effect.prompt {
                    roots_in_prompt(&prompt.text, out);
                }
                match &effect.kind {
                    body::BodyEffectKind::Coerce { args, .. } => {
                        for arg in args {
                            roots_in_expr(arg, out);
                        }
                    }
                    body::BodyEffectKind::TrackerFinish { item, fields } => {
                        out.insert(item.clone());
                        roots_in_fields(fields, out);
                    }
                    body::BodyEffectKind::TrackerRelease { item } => {
                        out.insert(item.clone());
                    }
                    _ => {}
                }
            }
            body::BodyStmt::Terminal(terminal) => {
                roots_in_fields(&terminal.fields, out);
                if let Some(body::FieldValue::Expr { source, .. }) = &terminal.scalar {
                    roots_in_expr(source, out);
                }
            }
            body::BodyStmt::Milestone { fields, .. } => roots_in_fields(fields, out),
            body::BodyStmt::After(after) => collect_statement_roots(&after.body, out),
            body::BodyStmt::Case(case) => {
                roots_in_expr(&case.scrutinee, out);
                for branch in &case.branches {
                    collect_statement_roots(&branch.body, out);
                }
            }
            body::BodyStmt::Region(region) => {
                collect_statement_roots(&region.body, out);
                collect_statement_roots(&region.lapse_body, out);
            }
            body::BodyStmt::Redact { source, .. } | body::BodyStmt::Declassify { source, .. } => {
                out.insert(source.clone());
            }
        }
    }
}

fn validate_effectful_self_trigger(
    rule: &RuleDecl,
    metadata: &IrRuleMetadata,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if metadata.effects.is_empty() {
        return;
    }

    for written_fact in &metadata.fact_writes {
        if metadata.fact_reads.contains(written_fact)
            && !metadata.fact_consumes.contains(written_fact)
        {
            diagnostics.push(Diagnostic { related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "effectful rule `{}` preserves trigger fact `{written_fact}`",
                    rule.name.name
                ),
                suggestion: Some(
                    "consume or advance the triggering fact, or move the next effect behind an external completion event"
                        .to_owned(),
                ),
            });
        }
    }
}

fn binding_types_for_rule(rule: &RuleDecl) -> BTreeMap<String, String> {
    let mut binding_types = BTreeMap::new();
    for when in &rule.whens {
        if let Some((binding, schema)) = binding_from_when(&when.text) {
            binding_types.insert(binding, schema);
        }
    }
    binding_types
}

fn validate_workflow_terminal_actions(
    rule: &RuleDecl,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    known_roots: &BTreeSet<String>,
    contracts: &WorkflowContractNames,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for line in rule.body.text.lines().map(str::trim) {
        let terminal = line
            .strip_prefix("complete ")
            .map(|rest| ("complete", rest, &contracts.outputs))
            .or_else(|| {
                line.strip_prefix("fail ")
                    .map(|rest| ("fail", rest, &contracts.failures))
            });
        let Some((action, rest, declared)) = terminal else {
            continue;
        };
        // Scalar terminal form: `complete result 0.9` / `fail error "msg"` — a bare
        // value after the name, with no `{ }` block and no `from` projection.
        // Validated against a scalar (primitive) contract; class contracts still
        // require a field block (checked by the block path below).
        if !rest.contains('{') {
            let tokens: Vec<&str> = rest.split_whitespace().collect();
            let is_from = matches!(tokens.as_slice(), [_, "from", ..]) && action == "complete";
            if tokens.len() >= 2 && !is_from {
                let name = tokens[0];
                let value = rest.trim().get(name.len()..).unwrap_or("").trim();
                if !declared.contains_key(name) {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: rule.body.span,
                        message: format!(
                            "rule `{}` {action}s unknown workflow terminal `{name}`",
                            rule.name.name
                        ),
                        suggestion: Some(format!(
                            "declare `{kind} {name} Type` on the workflow first",
                            kind = if action == "complete" {
                                "output"
                            } else {
                                "failure"
                            }
                        )),
                    });
                    continue;
                }
                if let Some(contract_ty) = declared.get(name) {
                    validate_scalar_terminal_payload(
                        rule,
                        action,
                        name,
                        value,
                        contract_ty,
                        semantic,
                        binding_types,
                        known_roots,
                        diagnostics,
                    );
                }
                continue;
            }
        }
        // Header is `<name>` or (for `complete`) `<name> from <binding>` — the
        // bounded-type projection form (DR-0027), whose payload copies the binding.
        let Some(name) = rest.split('{').next().and_then(|header| {
            let mut parts = header.split_whitespace();
            match (parts.next(), parts.next(), parts.next()) {
                (Some(name), None, _) => Some(name),
                (Some(name), Some("from"), Some(binding))
                    if action == "complete" && is_identifier(binding) =>
                {
                    Some(name)
                }
                _ => None,
            }
        }) else {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!("rule `{}` has malformed `{action}` action", rule.name.name),
                suggestion: Some(format!(
                    "{action} a declared workflow terminal with a payload block"
                )),
            });
            continue;
        };
        if !declared.contains_key(name) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` {action}s unknown workflow terminal `{name}`",
                    rule.name.name
                ),
                suggestion: Some(format!(
                    "declare `{kind} {name} Type` on the workflow first",
                    kind = if action == "complete" {
                        "output"
                    } else {
                        "failure"
                    }
                )),
            });
            continue;
        }
        let Some(contract_ty) = declared.get(name) else {
            continue;
        };
        validate_workflow_terminal_payload(
            rule,
            action,
            name,
            contract_ty,
            semantic,
            binding_types,
            known_roots,
            diagnostics,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_workflow_terminal_payload(
    rule: &RuleDecl,
    action: &str,
    terminal_name: &str,
    contract_ty: &TypeSyntax,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    known_roots: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some((_, _, body)) = workflow_terminal_blocks(&rule.body.text).into_iter().find(
        |(candidate_action, candidate_name, _)| {
            candidate_action == action && candidate_name == terminal_name
        },
    ) else {
        return;
    };
    let schema = match contract_ty {
        TypeSyntax::Ref { name } if semantic.schemas.class_exists(&name.name) => &name.name,
        TypeSyntax::Primitive { .. }
        | TypeSyntax::LiteralString { .. }
        | TypeSyntax::Union { .. } => {
            // A scalar (primitive/literal/union) contract takes a bare value, not
            // a field block.
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "workflow terminal `{terminal_name}` has a scalar payload contract but is given a field block"
                ),
                suggestion: Some(format!(
                    "write a bare scalar value: `{action} {terminal_name} <value>`"
                )),
            });
            return;
        }
        _ => {
            diagnostics.push(Diagnostic { related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "workflow terminal `{terminal_name}` uses an unsupported payload contract type"
                ),
                suggestion: Some(
                    "declare the terminal payload as a class (field block) or a scalar type (number/string/bool)"
                        .to_owned(),
                ),
            });
            return;
        }
    };
    for assignment in collect_field_assignments(&body) {
        let (field, value) = match assignment {
            RecordFieldAssignment::Value { field, value } => (field, value),
            RecordFieldAssignment::Shorthand { field } => (field.clone(), field),
        };
        let line = format!("{field} {value}");
        validate_record_field(
            rule,
            &line,
            schema,
            semantic,
            binding_types,
            known_roots,
            diagnostics,
        );
    }
    validate_required_terminal_fields(rule, schema, terminal_name, &body, semantic, diagnostics);
}

/// Validates a bare-scalar terminal payload (`complete result 0.9` /
/// `fail error "reason"`) against a scalar output/failure contract. A class
/// contract is rejected (it needs a field block); a literal value is typechecked
/// against the primitive/enum/union contract, and a binding-expression value has
/// its roots and field path validated.
#[allow(clippy::too_many_arguments)]
fn validate_scalar_terminal_payload(
    rule: &RuleDecl,
    action: &str,
    terminal_name: &str,
    value: &str,
    contract_ty: &TypeSyntax,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    known_roots: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let TypeSyntax::Ref { name } = contract_ty {
        if semantic.schemas.class_exists(&name.name) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "workflow terminal `{terminal_name}` has a class payload contract `{}` but is given a bare scalar value",
                    name.name
                ),
                suggestion: Some(format!("write a field block: `{action} {terminal_name} {{ … }}`")),
            });
            return;
        }
    }
    if value.is_empty() {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!("workflow terminal `{terminal_name}` is missing its scalar value"),
            suggestion: Some(format!("write `{action} {terminal_name} <value>`")),
        });
        return;
    }
    // A literal value is typechecked against the scalar contract; a binding
    // expression has its roots (and any field path) validated.
    validate_literal_assignment(
        rule,
        terminal_name,
        "value",
        contract_ty,
        value,
        semantic,
        diagnostics,
    );
    if let Some(root) = dangling_value_root(value, known_roots) {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!(
                "rule `{}` has unknown binding `{root}` in `{action} {terminal_name}` value",
                rule.name.name
            ),
            suggestion: Some(
                "reference a binding from a `when ... as name` clause, an effect `as` binding, or a `case` pattern"
                    .to_owned(),
            ),
        });
    } else if let Some((root, path)) = expression_path(value) {
        // Local scopes only. A terminal payload line is also walked by the
        // scoped field-path pass in `analyze_rule`, which is where an
        // invoke-derived binding resolves; making this one scope-aware too would
        // report the same read twice.
        check_field_path(
            rule,
            &root,
            &path,
            rule.body.span,
            SchemaScopes::local(&semantic.schemas),
            binding_types,
            diagnostics,
        );
    }
}

fn validate_required_terminal_fields(
    rule: &RuleDecl,
    schema: &str,
    terminal_name: &str,
    body: &str,
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(schema_fields) = semantic.schemas.classes.get(schema) else {
        return;
    };
    let seen = collect_field_assignments(body)
        .into_iter()
        .map(|assignment| match assignment {
            RecordFieldAssignment::Value { field, .. }
            | RecordFieldAssignment::Shorthand { field } => field,
        })
        .collect::<BTreeSet<_>>();
    for (required, ty) in schema_fields {
        if seen.contains(required) || matches!(ty, TypeSyntax::Optional { .. }) {
            continue;
        }
        diagnostics.push(Diagnostic { related: Vec::new(),
            span: rule.body.span,
            message: format!(
                "workflow terminal `{terminal_name}` is missing required field `{schema}.{required}`"
            ),
            suggestion: Some(format!("add `{required}` to the `{terminal_name}` payload")),
        });
    }
}

/// Maximum nesting depth of `after` blocks across `statements` (an `after` inside an
/// `after` is depth 2, …). Other nesting (`case`/`when`/handlers) is descended into so
/// an `after` buried inside them still counts, but only `after` increments the depth —
/// it is `after`-chaining specifically that `lint.deep_after_nesting` advises moving to
/// a `flow`. Computed from the body AST so prompt braces never confuse it.
fn max_after_depth(statements: &[body::BodyStmt]) -> usize {
    use body::BodyStmt;
    statements
        .iter()
        .map(|statement| match statement {
            BodyStmt::After(after) => 1 + max_after_depth(&after.body),
            BodyStmt::Case(case) => case
                .branches
                .iter()
                .map(|branch| max_after_depth(&branch.body))
                .max()
                .unwrap_or(0),
            _ => 0,
        })
        .max()
        .unwrap_or(0)
}

fn analyze_rule(
    rule: &RuleDecl,
    body_ast: &body::BodyAst,
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) -> IrRuleMetadata {
    let mut metadata = IrRuleMetadata {
        fact_reads: rule
            .whens
            .iter()
            .map(|when| fact_read_from_when(&when.text))
            .collect(),
        max_after_depth: max_after_depth(&body_ast.statements),
        ..IrRuleMetadata::default()
    };
    let mut seen_bindings = BTreeSet::new();
    let mut binding_types = BTreeMap::new();
    // Bindings whose schema is declared inside a CHILD workflow (`after <invoke>
    // succeeds/fails/reaches as x`). Their field paths resolve in that child's
    // index, not this one — see `SchemaScopes`.
    let mut foreign_schemas: BTreeMap<String, String> = BTreeMap::new();
    for when in &rule.whens {
        // A pattern that binds (`... as x`) but maps to no known readiness
        // form would otherwise be a silently-dead rule.
        let (pattern_text, _) = split_when_guard(&when.text);
        if binding_after_as(pattern_text).is_some()
            && binding_from_when(&when.text).is_none()
            && !pattern_text.ends_with(" is available")
        {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: when.span,
                message: format!(
                    "rule `{}` has unknown readiness pattern `{pattern_text}`",
                    rule.name.name
                ),
                suggestion: Some(
                    "match a class (`when Class as x`) or a runtime fact (`when fact <name> as x`)"
                        .to_owned(),
                ),
            });
        }
        if let Some((binding, schema)) = binding_from_when(&when.text) {
            validate_binding_name(rule, &binding, when.span, diagnostics);
            if !schema.contains('.') && !semantic.schemas.class_exists(&schema) {
                let suggestion = match closest_name(&schema, semantic.schemas.classes.keys()) {
                    Some(candidate) => {
                        format!("did you mean `{candidate}`? otherwise declare `class {schema}`")
                    }
                    None => format!("declare `class {schema}` before matching it"),
                };
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: when.span,
                    message: format!("rule `{}` matches unknown class `{schema}`", rule.name.name),
                    suggestion: Some(suggestion),
                });
            }
            // The bare dotted form is the typed signal reaction
            // (spec/event-ingress.md): it requires a declared `signal`;
            // undeclared dotted facts keep the untyped `when fact` form.
            if schema.contains('.')
                && !pattern_text.trim_start().starts_with("fact ")
                && !semantic.schemas.events.contains(&schema)
            {
                diagnostics.push(Diagnostic { related: Vec::new(),
                    span: when.span,
                    message: format!(
                        "rule `{}` reacts to undeclared signal `{schema}`",
                        rule.name.name
                    ),
                    suggestion: Some(format!(
                        "declare `signal {schema} {{ ... }}` for a typed reaction, or use `when fact {schema} as ...` for an untyped one"
                    )),
                });
            }
            binding_types.insert(binding, schema);
        }
    }
    let mut effect_payload_types = collect_effect_payload_types(rule, semantic, diagnostics);
    // `exec ... -> Schema as binding` is parsed from the AST (the command text
    // can itself contain `->`/` as `, so a text scan is unsafe), giving its
    // result the same after-binding type flow a named `coerce -> Schema` gets.
    collect_exec_payload_types(&body_ast.statements, semantic, &mut effect_payload_types);
    collect_open_payload_types(&body_ast.statements, semantic, &mut effect_payload_types);
    collect_declassify_payload_types(&body_ast.statements, semantic, &mut effect_payload_types);
    // Inline `decide … as <binding>` carries the synthesized
    // `decide.<rule>.<binding>` class (see `collect_inline_decide_schemas`), so
    // its result is `case`able / field-accessible like a named coerce result.
    collect_decide_payload_types(
        &body_ast.statements,
        &rule.name.name,
        &mut effect_payload_types,
    );
    collect_prompt_payload_types(&body_ast.statements, &mut effect_payload_types);
    // `redact … as <binding>` result carries the synthesized `redact.<rule>.<binding>`
    // projected class (see `collect_redact_schemas`), so access through it resolves
    // against the kept-only fields.
    collect_redact_payload_types(
        &body_ast.statements,
        &rule.name.name,
        &mut effect_payload_types,
    );
    for (binding, payload_type) in &effect_payload_types {
        if let IrType::Ref(schema) = payload_type {
            binding_types.insert(binding.clone(), schema.clone());
        }
    }
    // Effect-kind map for the `fails`-arm static narrowing (DR-0032 P3): the
    // failing effect's kind is always statically known at the read site. Scan
    // raw lines first (every single-line effect form), then the balanced
    // multi-line statements (a `coerce` whose arguments span lines carries its
    // binding on the closing line).
    // Bindings born from the std.vcs completion-valued verbs: the
    // succeeds-refusals below need the construct, not just the generic
    // CapabilityCall kind. Maps binding -> (verb, negative variant).
    let vcs_verb_bindings: BTreeMap<String, (&'static str, &'static str)> = rule
        .body
        .text
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (verb, negative) = if line.starts_with("promote ") {
                ("promote", "Conflicted")
            } else if line.starts_with("undo ") {
                ("undo", "Stranded")
            } else if line.starts_with("transport ") {
                ("transport", "Conflicted")
            } else {
                return None;
            };
            Some((binding_after_as(line)?, (verb, negative)))
        })
        .collect();
    let mut effect_binding_kinds: BTreeMap<String, IrEffectKind> = rule
        .body
        .text
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            // `exec` is not in parse_effect_line (whose other callers feed the
            // rule-metadata effect count); match it here for kind narrowing.
            if line.starts_with("exec ") {
                return Some((binding_after_as(line)?, IrEffectKind::ExecCommand));
            }
            let (kind, binding) = parse_effect_line(line)?;
            Some((binding?, kind))
        })
        .collect();
    for statement in effect_payload_statements(&rule.body.text) {
        if let Some((kind, Some(binding))) = parse_effect_line(statement.trim()) {
            effect_binding_kinds.insert(binding, kind);
        }
    }
    // `after <binding> <predicate> as <alias>`: the alias carries the
    // effect's completed payload type, so case dispatch and field access
    // through it type-check.
    for line in rule.body.text.lines() {
        let Some(rest) = line.trim().strip_prefix("after ") else {
            continue;
        };
        let mut words = rest.split_whitespace();
        let Some(binding) = words.next() else {
            continue;
        };
        let Some(predicate) = words.next() else {
            continue;
        };
        // Coordination ops are completion-valued: an `acquire` COMPLETES with
        // variant Held|Contended (counter `consume` with Ok|Over), so the
        // generic `succeeds` arm would fire on the negative outcome too — a
        // workflow proceeding "as if holding" on Contended. Reject `succeeds`
        // and force the variant vocabulary; `fails` (infra failures) and
        // `completes` (deliberate catch-all) stay legal.
        if predicate == "succeeds" {
            if let Some((verb, negative)) = vcs_verb_bindings.get(binding) {
                // std.vcs verbs are completion-valued: the generic
                // `succeeds` arm would fire on the refusal variant too — a
                // workflow proceeding as if the act landed. Same posture
                // as acquire; outcome-variant predicates are only ever
                // added alongside this refusal (DR-0052 Decision 0).
                let positive = if *verb == "promote" {
                    "promoted"
                } else {
                    "applied"
                };
                let negative_arm = negative.to_lowercase();
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: rule.body.span,
                    message: format!(
                        "rule `{}` observes {verb} `{binding}` with `succeeds`, which also \
                         matches a {negative} outcome (the op completes either way)",
                        rule.name.name
                    ),
                    suggestion: Some(format!(
                        "use `after {binding} {positive}` / `after {binding} {negative_arm}` \
                         for the outcome variants, or `after {binding} completes` for any \
                         settled outcome"
                    )),
                });
            }
        }
        if predicate == "succeeds" {
            match effect_binding_kinds.get(binding) {
                Some(IrEffectKind::LeaseAcquire) => {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: rule.body.span,
                        message: format!(
                            "rule `{}` observes acquire `{binding}` with `succeeds`, which also \
                             matches a Contended outcome (the acquire op completes either way)",
                            rule.name.name
                        ),
                        suggestion: Some(format!(
                            "use `after {binding} held` / `after {binding} contended` for the \
                             outcome variants, or `after {binding} completes` for any settled \
                             outcome"
                        )),
                    });
                }
                Some(IrEffectKind::CounterConsume) => {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: rule.body.span,
                        message: format!(
                            "rule `{}` observes counter consume `{binding}` with `succeeds`, \
                             which also matches an Over outcome (the consume op completes \
                             either way)",
                            rule.name.name
                        ),
                        suggestion: Some(format!(
                            "use `after {binding} ok` / `after {binding} over` for the outcome \
                             variants, or `after {binding} completes` for any settled outcome"
                        )),
                    });
                }
                _ => {}
            }
        }
        // `after p reaches "<name>" as m` (Family C): the milestone name sits
        // between the predicate and `as`, so the alias lands one token later.
        // Type `m` to the child's declared milestone payload class.
        if predicate == "reaches" {
            let Some(quoted) = words.next() else {
                continue;
            };
            let milestone = quoted.trim_matches('"');
            let (Some("as"), Some(alias)) = (words.next(), words.next()) else {
                continue;
            };
            let alias = alias.trim_end_matches('{').trim();
            if alias.is_empty() {
                continue;
            }
            if let Some((workflow, class)) =
                milestone_payload_class(rule, binding, milestone, semantic)
            {
                if !class.is_empty() {
                    binding_types.insert(alias.to_owned(), class);
                    foreign_schemas.insert(alias.to_owned(), workflow);
                }
            }
            continue;
        }
        // `times out` is the only two-token predicate; skip its second word so
        // the `as <alias>` clause lines up.
        if predicate == "times" && words.next() != Some("out") {
            continue;
        }
        let (Some(keyword), Some(alias)) = (words.next(), words.next()) else {
            continue;
        };
        if keyword != "as" {
            continue;
        }
        let alias = alias.trim_end_matches('{').trim();
        if alias.is_empty() {
            continue;
        }
        // Bind the alias to the terminal payload schema that matches the
        // predicate, consistent with the case-tag payload schemas
        // (terminal_payload_schema_for_tag): `times out` -> `TerminalTimedOut`,
        // `cancelled` -> `TerminalCancelled`. Other predicates carry the
        // effect's completed payload schema.
        match predicate {
            "times" => {
                binding_types.insert(alias.to_owned(), "TerminalTimedOut".to_owned());
            }
            "cancelled" => {
                binding_types.insert(alias.to_owned(), "TerminalCancelled".to_owned());
            }
            // `completes` binds the terminal-union ENVELOPE, not the success
            // schema: the runtime delivers {tag, status, summary, …} for ANY
            // settled outcome, and the payload is read via `case o {
            // Completed as v => … }`. The old success-schema typing approved
            // reads that were null on every non-success terminal.
            "completes" => {
                binding_types.insert(alias.to_owned(), "TerminalOutcome".to_owned());
            }
            // DR-0032: the `fails` branch binds the EffectError family — the
            // base `{reason, summary, effect_id, run_id, kind}` plus per-kind
            // extras narrowed STATICALLY by the binding's effect kind (P3 /
            // DQ-2): exec adds `exit_code`; schema.coerce adds `error_class` +
            // optional `http_status`; agent.tell adds `error_class`. Every
            // other kind stays on the plain base.
            //
            // Exception (typed invoke failure): when this is an invoke binding
            // whose child declares a SOLE, shared top-level FAILURE contract class,
            // bind the alias to THAT class so `f.<field>` type-checks against the
            // child's declared failure shape (the runtime merges the child payload
            // under the base). Invoke bindings with a child-local/unresolvable
            // failure class keep the `TerminalFailed` base.
            "fails" => {
                if let Some((workflow, class)) = invoke_failure_class(rule, binding, semantic) {
                    binding_types.insert(alias.to_owned(), class);
                    foreign_schemas.insert(alias.to_owned(), workflow);
                } else {
                    let schema = match effect_binding_kinds.get(binding) {
                        Some(IrEffectKind::ExecCommand) => "TerminalFailedExec",
                        Some(IrEffectKind::SchemaCoerce) => "TerminalFailedCoerce",
                        Some(IrEffectKind::AgentTell) => "TerminalFailedTell",
                        _ => "TerminalFailed",
                    };
                    binding_types.insert(alias.to_owned(), schema.to_owned());
                }
            }
            _ => {
                if let Some(IrType::Ref(schema)) = effect_payload_types.get(binding) {
                    binding_types.insert(alias.to_owned(), schema.clone());
                } else if let Some((workflow, class)) = invoke_output_class(rule, binding, semantic)
                {
                    // Typed invoke result: `after <child> succeeds/completes as r`
                    // binds r to the child workflow's OUTPUT contract class, so
                    // `r.<field>` type-checks. (The runtime already carries the
                    // child's terminal payload into this binding.) The `fails` arm
                    // above keeps the DR-0032 failure base.
                    binding_types.insert(alias.to_owned(), class);
                    foreign_schemas.insert(alias.to_owned(), workflow);
                }
            }
        }
    }
    for when in &rule.whens {
        if let (_, Some(guard)) = split_when_guard(&when.text) {
            validate_expression(rule, guard, semantic, &binding_types, "guard", diagnostics);
            validate_known_field_paths(rule, guard, semantic, &binding_types, diagnostics);
            if let Some(expr) = lower_expression(guard, when.span) {
                metadata
                    .projection_reads
                    .extend(collect_projection_reads(&expr.expr));
            }
        }
        validate_availability_when(rule, &when.text, semantic, &binding_types, diagnostics);
    }
    validate_case_blocks(rule, semantic, &binding_types, diagnostics);
    metadata.case_branches =
        collect_rule_case_metadata(rule, semantic, &binding_types, diagnostics);
    let terminal_metadata = collect_terminal_case_metadata(
        rule,
        semantic,
        &binding_types,
        &effect_payload_types,
        diagnostics,
    );
    // Complete value-position root set: typed bindings plus every binding NAME
    // the body introduces (AST-collected, so multi-line-prompt `tell`/`exec`
    // results and `case` payloads are covered, which `binding_types` omits).
    let mut known_roots: BTreeSet<String> = binding_types.keys().cloned().collect();
    collect_all_binding_names(&body_ast.statements, &mut known_roots);
    validate_record_blocks(rule, semantic, &binding_types, &known_roots, diagnostics);
    validate_effect_payloads(rule, semantic, &binding_types, &known_roots, diagnostics);
    validate_effect_field_roots(rule, &body_ast.statements, &known_roots, diagnostics);
    validate_emit_signal_declarations(
        rule,
        &body_ast.statements,
        &semantic.schemas.events,
        diagnostics,
    );
    validate_http_requests(
        rule,
        &body_ast.statements,
        &semantic.credentials.keys().map(String::as_str).collect(),
        diagnostics,
    );
    validate_workflow_invocations(rule, semantic, &binding_types, &known_roots, diagnostics);
    validate_milestone_statements(rule, semantic, diagnostics);
    let mut block_stack: Vec<BlockFrame> = Vec::new();
    let mut misplaced_effect_bindings = BTreeSet::new();
    seed_ast_only_effect_bindings(&body_ast.statements, &mut seen_bindings, &mut binding_types);
    validate_body_effect_operands(
        rule,
        &body_ast.statements,
        semantic,
        &binding_types,
        diagnostics,
    );
    validate_coordination_discipline(rule, &body_ast.statements, diagnostics);
    // `redact <source> keep [..] as <out>`: the source must resolve to a known
    // schema and every kept field must exist on it (fail-closed).
    validate_redactions(
        rule,
        &body_ast.statements,
        semantic,
        &binding_types,
        diagnostics,
    );
    // DR-0074 §4: no value derived from opened plaintext crosses into a durable
    // record. Runs whether or not an envelope is configured — plaintext in
    // `facts.value_json` is not a policy question.
    {
        let mut open_bindings = BTreeSet::new();
        collect_open_bindings(&body_ast.statements, &mut open_bindings);
        if !open_bindings.is_empty() {
            validate_confinement(
                rule,
                &body_ast.statements,
                &open_bindings,
                &BTreeSet::new(),
                diagnostics,
            );
        }
    }
    // DR-0074 §3 obligation 3: the envelope's `sealed<T>` and the `into <Type>`
    // must agree. Sited here rather than in the collector above because it
    // needs `binding_types` complete — an `open` inside an `after` block reads
    // an envelope off a binding the collector had not yet produced.
    validate_open_type_agreement(
        rule,
        &body_ast.statements,
        semantic,
        &binding_types,
        diagnostics,
    );
    validate_declassify_projection(
        rule,
        &body_ast.statements,
        semantic,
        &binding_types,
        diagnostics,
    );
    // A sealed value reaching a provider as ciphertext is always a mistake;
    // worker-side opening is what the `unwrap for <T>` grant asks for.
    validate_sealed_effect_inputs(
        rule,
        &body_ast.statements,
        semantic,
        &binding_types,
        diagnostics,
    );
    // DR-0074 §10: a sealed value's payload type must match the field it is
    // stored in, or `open`'s three-way agreement rests on a declaration the
    // bytes never satisfied.
    {
        let mut sealed_bindings = BTreeMap::new();
        collect_seal_payload_types(
            &body_ast.statements,
            semantic,
            &binding_types,
            &mut sealed_bindings,
        );
        if !sealed_bindings.is_empty() {
            validate_seal_storage(
                rule,
                &body_ast.statements,
                semantic,
                &sealed_bindings,
                diagnostics,
            );
        }
    }
    // Family B read-narrowing: a presence-conditioned field is readable only inside a
    // matching `case <root>.<disc>` arm (starts with nothing allowed at the rule top).
    validate_conditioned_field_reads(
        rule,
        &body_ast.statements,
        semantic,
        &binding_types,
        &BTreeSet::new(),
        diagnostics,
    );
    let mut anonymous_effects = 0usize;
    let mut record_depth = 0i32;

    for raw_line in rule.body.text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        if record_depth > 0 {
            record_depth += brace_delta(line);
            continue;
        }

        if let Some(binding) = binding_after_multiline_string_end(line) {
            misplaced_effect_bindings.insert(binding.clone());
            diagnostics.push(Diagnostic { related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` places effect binding `{binding}` after a multiline string delimiter",
                    rule.name.name
                ),
                suggestion: Some(format!(
                    "move `as {binding}` onto the effect line, before the multiline string body"
                )),
            });
            continue;
        }
        validate_rule_prompt_content_type_annotation(rule, line, diagnostics);

        if line.starts_with('}') {
            block_stack.pop();
            continue;
        }

        if line.starts_with("case ") || (!line.starts_with("after ") && is_case_branch_start(line))
        {
            validate_known_field_paths_scoped(
                rule,
                line,
                semantic,
                &binding_types,
                &foreign_schemas,
                diagnostics,
            );
            continue;
        }

        let active_afters = after_scopes(&block_stack);
        validate_binding_uses(rule, line, &seen_bindings, &active_afters, diagnostics);
        validate_known_field_paths_scoped(
            rule,
            line,
            semantic,
            &binding_types,
            &foreign_schemas,
            diagnostics,
        );

        if let Some(binding) = parse_consume_line(line) {
            match binding_types.get(&binding) {
                // Collected from the parsed body below; this arm is here for the
                // unknown-binding diagnostic only.
                Some(_) => {}
                None => diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: rule.body.span,
                    message: format!(
                        "rule `{}` consumes unknown fact binding `{binding}`",
                        rule.name.name
                    ),
                    suggestion: Some(
                        "consume a binding introduced by a `when Class as binding` clause"
                            .to_owned(),
                    ),
                }),
            }
            if !line.contains("->") {
                continue;
            }
        }

        if line.starts_with("after ") {
            if let Some(alias) = binding_after_as(line) {
                validate_binding_name(rule, &alias, rule.body.span, diagnostics);
            }
            match parse_after_line(line) {
                Some((binding, predicate)) => {
                    if !seen_bindings.contains(&binding) {
                        let suggestion = if misplaced_effect_bindings.contains(&binding) {
                            format!(
                                "move `as {binding}` onto the effect line before the multiline string"
                            )
                        } else {
                            format!("create an effect with `as {binding}` before the `after` block")
                        };
                        diagnostics.push(Diagnostic { related: Vec::new(),
                            span: rule.body.span,
                            message: format!(
                                "rule `{}` has `after` block for unknown effect binding `{binding}`",
                                rule.name.name
                            ),
                            suggestion: Some(suggestion),
                        });
                    }
                    block_stack.push(BlockFrame::After { binding, predicate });
                }
                None => {
                    diagnostics.push(Diagnostic { related: Vec::new(),
                        span: rule.body.span,
                        message: format!(
                            "rule `{}` has unsupported `after` dependency predicate",
                            rule.name.name
                        ),
                        suggestion: Some(
                            "use `after name succeeds`, `after name fails`, `after name completes`, `after name times out`, or `after name cancelled`"
                                .to_owned(),
                        ),
                    });
                }
            }
            continue;
        }

        if parse_record_start(line).is_some() {
            // Both the write and its diagnostics are taken from the parsed body
            // (`validate_recorded_schemas`); this branch keeps only the brace
            // bookkeeping that tells the scanner how far the record's field
            // block runs.
            record_depth = brace_delta(line).max(1);
            continue;
        }

        if let Some((kind, binding)) = parse_effect_line(line) {
            validate_agent_tell_target(
                rule,
                line,
                &kind,
                semantic,
                &binding_types,
                &known_roots,
                diagnostics,
            );
            anonymous_effects += 1;
            let id = binding
                .clone()
                .unwrap_or_else(|| format!("effect{anonymous_effects}"));
            if let Some(binding) = &binding {
                validate_binding_name(rule, binding, rule.body.span, diagnostics);
                seen_bindings.insert(binding.clone());
                if let Some(schema) = effect_binding_schema(line, &kind, semantic) {
                    binding_types.insert(binding.clone(), schema);
                }
            }
            for (upstream, predicate) in after_scopes(&block_stack) {
                metadata.dependencies.push(IrEffectDependency {
                    upstream,
                    predicate,
                    downstream: id.clone(),
                });
            }
            let idempotency_key = effect_idempotency_key(&rule.name.name, &id, &kind, &binding);
            metadata.effects.push(IrEffectNode {
                id,
                kind,
                binding,
                required_capabilities: parse_required_capabilities(line),
                construct_use: None,
                idempotency_key,
                span: rule.body.span,
                timeout_seconds: None,
                // The line-scanner result is overwritten by collect_effects_from_ast
                // below (which carries the real grants); empty here is fine.
                access_grants: Vec::new(),
                turn_skills: Vec::new(),
                on_stream: None,
                selection_source: None,
                transport_onto: None,
                resource: None,
                agent: None,
                coerce_target: None,
                workflow_target: None,
                endorsed: false,
                declassified: false,
                selected_by: None,
                exec_target: None,
                http_request: None,
                mint_credential: None,
            });
        }
    }

    // One resolution of the rule's item/lease bindings, shared by the effect
    // walk and the payload-reads walk so the two cannot disagree about which
    // queue a `finish` lands in.
    let resolved_bindings = binding_resources(rule, &body_ast.statements, &semantic.trackers);
    let (ast_effects, ast_dependencies) =
        collect_effects_from_ast(&body_ast.statements, &rule.name.name, &resolved_bindings);
    metadata.effects = ast_effects;
    metadata.dependencies = ast_dependencies;

    // `exec ... -> each Schema` produces one `Schema` fact per stream element
    // (spec/json-ingestion.md) — a fact write for liveness and effect-graph
    // analysis, like `record`.
    push_ingest_fact_writes(&body_ast.statements, &mut metadata.fact_writes);
    // Records and consumes come from the parsed body, not from the line scanner
    // above: the scanner cannot see a statement that shares a line with the
    // block that encloses it. See `collect_record_and_consume_facts`.
    collect_record_and_consume_facts(
        &body_ast.statements,
        &binding_types,
        &mut metadata.fact_writes,
        &mut metadata.fact_consumes,
    );
    validate_recorded_schemas(rule, &body_ast.statements, semantic, diagnostics);

    metadata.fact_reads.sort();
    metadata.fact_reads.dedup();
    sort_projection_reads(&mut metadata.projection_reads);
    metadata.fact_writes.sort();
    metadata.fact_writes.dedup();
    metadata.fact_consumes.sort();
    metadata.fact_consumes.dedup();
    metadata.terminal_outputs = terminal_metadata.outputs;
    metadata.terminal_branches = terminal_metadata.branches;
    metadata.envelope_reads_on_payload = terminal_metadata.envelope_reads_on_payload;
    // DR-0044 Q5 / P1: an after-arm `case … where <guard>` guard query observes
    // live fact state at continuation time — the same firing-decision implicit
    // flow as a `when`-guard query (the IFC checker reads `projection_reads` to
    // taint guard-gated egresses). Fold both case families' arm guards into
    // `projection_reads` so the analysis sees them; the `when`-guard queries were
    // added above.
    for branch in &metadata.case_branches {
        if let Some(guard) = &branch.guard {
            metadata
                .projection_reads
                .extend(collect_projection_reads(&guard.expr));
        }
    }
    for branch in &metadata.terminal_branches {
        if let Some(guard) = &branch.guard {
            metadata
                .projection_reads
                .extend(collect_projection_reads(&guard.expr));
        }
    }
    sort_projection_reads(&mut metadata.projection_reads);
    // DR-0043 Decision 7 obligation 2: the lapse arm is not in `rule.body.text`
    // (that is the HOLDS variant), so it is checked here, once, with the binding
    // environment the body loop just built.
    if let Some(region) = semantic.regions.get(&rule.name.name) {
        validate_lapse_arm(
            rule,
            region,
            semantic,
            &binding_types,
            &foreign_schemas,
            &effect_payload_types,
            diagnostics,
        );
    }
    collect_terminal_complete_bindings(&body_ast.statements, &mut metadata.terminal_completes);
    metadata.terminal_completes.sort();
    metadata.terminal_completes.dedup();
    collect_redaction_metadata(
        &body_ast.statements,
        &binding_types,
        &mut metadata.redactions,
    );
    collect_bounded_egresses(
        &body_ast.statements,
        &binding_types,
        &mut metadata.bounded_egresses,
    );
    let mut egress_reads = Vec::new();
    collect_egress_payload_reads(&body_ast.statements, &resolved_bindings, &mut egress_reads);
    for (sink, roots) in egress_reads {
        metadata
            .egress_payload_reads
            .entry(sink)
            .or_default()
            .extend(roots);
    }
    collect_complete_field_reads(&body_ast.statements, &mut metadata.complete_field_reads);
    collect_record_field_reads(&body_ast.statements, &mut metadata.record_field_reads);
    collect_milestone_field_reads(&body_ast.statements, &mut metadata.milestone_field_reads);
    collect_crossing_roots(
        &body_ast.statements,
        &mut metadata.declassified_roots,
        &mut metadata.endorsed_roots,
        &mut metadata.endorsed_claim_items,
    );
    collect_provenance_metadata(
        &body_ast.statements,
        &mut metadata.carried_input_roots,
        &mut metadata.after_aliases,
    );
    collect_egress_case_influence(
        &body_ast.statements,
        &mut Vec::new(),
        &mut metadata.egress_case_influence,
    );
    // Redaction closure over marked roots (redact ∘ marked-crossing): a
    // `redact <marked-output> keep […] as out` projection is still the
    // crossing's carrier — a redaction can only NARROW what the marked
    // coercion released, and the kept fields are additionally held to their
    // per-field schema labels by the redact refinement. Fixpoint so
    // redactions of redactions chain.
    loop {
        let mut changed = false;
        for redaction in &metadata.redactions {
            if metadata.declassified_roots.contains(&redaction.source)
                && metadata
                    .declassified_roots
                    .insert(redaction.binding.clone())
            {
                changed = true;
            }
            if metadata.endorsed_roots.contains(&redaction.source)
                && metadata.endorsed_roots.insert(redaction.binding.clone())
            {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    metadata
}

/// Collect, per egress sink, the binding roots of every enclosing `case`
/// scrutinee (DR-0046 selector influence). The active-scrutinee stack is
/// threaded through nesting; each egress statement records the union of the
/// stack at its position, keyed exactly like `collect_egress_payload_reads`.
fn collect_egress_case_influence(
    statements: &[body::BodyStmt],
    active: &mut Vec<BTreeSet<String>>,
    out: &mut BTreeMap<String, BTreeSet<String>>,
) {
    let record_sink = |sink: String,
                       active: &[BTreeSet<String>],
                       out: &mut BTreeMap<String, BTreeSet<String>>| {
        if active.is_empty() {
            return;
        }
        let entry = out.entry(sink).or_default();
        for roots in active {
            entry.extend(roots.iter().cloned());
        }
    };
    for statement in statements {
        match statement {
            body::BodyStmt::Terminal(terminal) if terminal.kind == body::TerminalKind::Complete => {
                record_sink(terminal.name.clone(), active, out);
            }
            body::BodyStmt::Record(record) => {
                record_sink(format!("fact:{}", record.schema), active, out);
            }
            body::BodyStmt::Done {
                replacement: Some(record),
                ..
            } => {
                record_sink(format!("fact:{}", record.schema), active, out);
            }
            body::BodyStmt::Milestone { name, .. } => {
                record_sink(format!("milestone:{name}"), active, out);
            }
            body::BodyStmt::Effect(effect) => match &effect.kind {
                body::BodyEffectKind::ConstructCapabilityCall {
                    keyword, fields, ..
                } if keyword == "send" => {
                    if let Some(channel) = fields
                        .iter()
                        .find(|field| field.name == "channel")
                        .map(|field| field.source.clone())
                    {
                        record_sink(channel, active, out);
                    }
                }
                body::BodyEffectKind::FileWrite { store, .. } => {
                    record_sink(store.clone(), active, out);
                }
                _ => {}
            },
            body::BodyStmt::After(after) => {
                collect_egress_case_influence(&after.body, active, out);
            }
            body::BodyStmt::Case(case) => {
                let mut roots = BTreeSet::new();
                if let Ok(expr) = parse_expression(&case.scrutinee) {
                    collect_expr_binding_roots(&expr, &mut roots);
                } else {
                    collect_template_binding_roots(&case.scrutinee, &mut roots);
                }
                active.push(roots);
                for branch in &case.branches {
                    collect_egress_case_influence(&branch.body, active, out);
                }
                active.pop();
            }
            _ => {}
        }
    }
}

/// Collect the raw structure input-side provenance narrowing resolves over:
/// for each operation whose OUTPUT carries its INPUT's provenance, the binding
/// roots of that input (template-scan fallback for unparseable sources, same
/// discipline as `send_payload_reads`), plus the `after … succeeds|completes
/// as` alias map.
///
/// Named `coerce_input_roots` until DR-0074, when it stopped being about
/// coerces: `open`'s plaintext carries the provenance of the envelope it opened,
/// and `declassify`'s output carries its source's. All three are the same
/// relation, and a checker that knew only the coerce case could not see that an
/// opened value came from a governed resource at all — so the `grant declassify`
/// consultation at the egress would never fire on it.
fn collect_provenance_metadata(
    statements: &[body::BodyStmt],
    carried_input_roots: &mut BTreeMap<String, BTreeSet<String>>,
    after_aliases: &mut BTreeMap<String, String>,
) {
    for statement in statements {
        match statement {
            // `declassify <source> into <T> as <b>`: the release carries where
            // the value came from. Its AUTHORITY is a separate question, asked
            // by the `grant declassify` consultation this provenance feeds.
            body::BodyStmt::Declassify {
                source, binding, ..
            } => {
                let mut roots = BTreeSet::new();
                if let Ok(expr) = parse_expression(source) {
                    collect_expr_binding_roots(&expr, &mut roots);
                } else {
                    collect_template_binding_roots(source, &mut roots);
                }
                carried_input_roots
                    .entry(binding.clone())
                    .or_default()
                    .extend(roots);
            }
            body::BodyStmt::Effect(effect) => {
                // DR-0074 §3: an `open`'s output is the plaintext of the
                // envelope it was given, so it carries that envelope's
                // provenance exactly.
                if let body::BodyEffectKind::ConstructCapabilityCall {
                    target_capability,
                    fields,
                    ..
                } = &effect.kind
                {
                    if target_capability == CUSTODY_UNWRAP_CAPABILITY {
                        if let (Some(binding), Some(envelope)) = (
                            effect.binding.as_ref(),
                            fields
                                .iter()
                                .find(|field| field.name == OPEN_ENVELOPE_SLOT)
                                .map(|field| field.source.as_str()),
                        ) {
                            let mut roots = BTreeSet::new();
                            if let Ok(expr) = parse_expression(envelope) {
                                collect_expr_binding_roots(&expr, &mut roots);
                            } else {
                                collect_template_binding_roots(envelope, &mut roots);
                            }
                            carried_input_roots
                                .entry(binding.clone())
                                .or_default()
                                .extend(roots);
                        }
                    }
                }
                if let body::BodyEffectKind::Coerce { args, .. } = &effect.kind {
                    if let Some(binding) = &effect.binding {
                        let mut roots = BTreeSet::new();
                        for arg in args {
                            if let Ok(expr) = parse_expression(arg) {
                                collect_expr_binding_roots(&expr, &mut roots);
                            } else {
                                collect_template_binding_roots(arg, &mut roots);
                            }
                        }
                        carried_input_roots
                            .entry(binding.clone())
                            .or_default()
                            .extend(roots);
                    }
                }
            }
            body::BodyStmt::After(after) => {
                if matches!(
                    after.predicate,
                    body::AfterPredicate::Succeeds | body::AfterPredicate::Completes
                ) {
                    if let Some(alias) = &after.alias {
                        after_aliases.insert(alias.clone(), after.binding.clone());
                    }
                }
                collect_provenance_metadata(&after.body, carried_input_roots, after_aliases);
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_provenance_metadata(&branch.body, carried_input_roots, after_aliases);
                }
            }
            _ => {}
        }
    }
}

/// Collect the output roots of marked crossings (`coerce … declassified` /
/// `coerce … endorsed`, DR-0027 I-IFC3): each marked coerce's binding, plus the
/// aliases its `after <binding> succeeds|completes as <alias>` branches bind —
/// the names an egress payload actually references. Two passes so an `after`
/// textually preceding nothing is impossible to miss; aliases of aliases cannot
/// occur (an `after` subject is always an effect binding).
fn collect_crossing_roots(
    statements: &[body::BodyStmt],
    declassified: &mut BTreeSet<String>,
    endorsed: &mut BTreeSet<String>,
    claim_items: &mut BTreeSet<String>,
) {
    fn collect_marked(
        statements: &[body::BodyStmt],
        declassified: &mut BTreeSet<String>,
        endorsed: &mut BTreeSet<String>,
        claim_items: &mut BTreeSet<String>,
    ) {
        for statement in statements {
            match statement {
                // DR-0074 §5: `declassify … into <Type> as <b>` is a marked
                // confidentiality crossing of exactly the kind `coerce …
                // declassified` already is, so its output joins
                // `declassified_roots` and inherits the WHOLE existing
                // discipline — `grant declassify` consultation at the egress,
                // the guarantee report's trusted-surface listing, and
                // NMIF-on-the-selector. Wiring it here rather than adding a
                // second mechanism is what keeps the region's exit audited
                // instead of merely explicit.
                body::BodyStmt::Declassify { binding, .. } => {
                    declassified.insert(binding.clone());
                }
                body::BodyStmt::Effect(effect) => {
                    if let body::BodyEffectKind::Coerce {
                        declassified: is_declassified,
                        endorsed: is_endorsed,
                        ..
                    } = &effect.kind
                    {
                        if let Some(binding) = &effect.binding {
                            if *is_declassified {
                                declassified.insert(binding.clone());
                            }
                            if *is_endorsed {
                                endorsed.insert(binding.clone());
                            }
                        }
                    }
                    // DR-0051 §2: an endorsed claim is a marked crossing of the
                    // same kind, so its output binding joins `endorsed_roots`
                    // and every downstream check — the narrowing, the grant
                    // consultation, NMIF-on-the-selector — applies unchanged.
                    if let body::BodyEffectKind::TrackerClaim {
                        endorsed: is_endorsed,
                        item,
                        ..
                    } = &effect.kind
                    {
                        if *is_endorsed {
                            // The crossed value is the *claimed item*, not the
                            // claim's `as` binding: `claim v as hold` binds a
                            // lease in `hold`, while the decision the program
                            // goes on to read lives in `v`. Marking the lease
                            // would mark a handle nothing reads.
                            endorsed.insert(item.clone());
                            claim_items.insert(item.clone());
                        }
                    }
                }
                body::BodyStmt::After(after) => {
                    collect_marked(&after.body, declassified, endorsed, claim_items)
                }
                body::BodyStmt::Case(case) => {
                    for branch in &case.branches {
                        collect_marked(&branch.body, declassified, endorsed, claim_items);
                    }
                }
                _ => {}
            }
        }
    }
    fn collect_aliases(
        statements: &[body::BodyStmt],
        declassified: &mut BTreeSet<String>,
        endorsed: &mut BTreeSet<String>,
    ) {
        for statement in statements {
            match statement {
                body::BodyStmt::After(after) => {
                    if matches!(
                        after.predicate,
                        body::AfterPredicate::Succeeds | body::AfterPredicate::Completes
                    ) {
                        if let Some(alias) = &after.alias {
                            if declassified.contains(&after.binding) {
                                declassified.insert(alias.clone());
                            }
                            if endorsed.contains(&after.binding) {
                                endorsed.insert(alias.clone());
                            }
                        }
                    }
                    collect_aliases(&after.body, declassified, endorsed);
                }
                body::BodyStmt::Case(case) => {
                    for branch in &case.branches {
                        collect_aliases(&branch.body, declassified, endorsed);
                    }
                }
                _ => {}
            }
        }
    }
    collect_marked(statements, declassified, endorsed, claim_items);
    // Aliases can nest under other afters, so run the alias pass to a fixpoint
    // over the (small) statement tree: one extra pass suffices in practice, but
    // loop until stable so deep nesting cannot order-skip an alias.
    loop {
        let before = (declassified.len(), endorsed.len());
        collect_aliases(statements, declassified, endorsed);
        if (declassified.len(), endorsed.len()) == before {
            break;
        }
    }
}

/// For each `complete <binding> { field: <expr>, … }` egress in a rule body
/// (recursing into nested blocks), the binding roots EACH result field references,
/// as `binding -> field -> {roots}`. A `Shorthand` field (`complete result from src
/// { f }`) resolves to the terminal's `from` binding. Unlike
/// `collect_egress_payload_reads` (which joins a sink's fields), this keeps fields
/// separate so the IFC engine can compute a per-field flow signature (DR-0030 X2
/// v2). Union across branches (a field completed in two arms references the union).
fn collect_complete_field_reads(
    statements: &[body::BodyStmt],
    out: &mut BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Terminal(terminal) if terminal.kind == body::TerminalKind::Complete => {
                let per_field = out.entry(terminal.name.clone()).or_default();
                for field in &terminal.fields {
                    let mut roots = BTreeSet::new();
                    match &field.value {
                        body::FieldValue::Shorthand => {
                            if let Some(root) = &terminal.from {
                                roots.insert(root.clone());
                            }
                        }
                        body::FieldValue::Expr { expr, .. } => {
                            collect_expr_binding_roots(expr, &mut roots)
                        }
                        body::FieldValue::Nested { fields, .. } => collect_payload_field_roots(
                            fields,
                            terminal.from.as_deref(),
                            &mut roots,
                        ),
                    }
                    per_field
                        .entry(field.name.clone())
                        .or_default()
                        .extend(roots);
                }
            }
            body::BodyStmt::After(after) => collect_complete_field_reads(&after.body, out),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_complete_field_reads(&branch.body, out);
                }
            }
            _ => {}
        }
    }
}

/// For each `emit milestone "<name>" { field: <expr>, … }` egress in a rule body
/// (recursing into nested blocks), collect the binding roots EACH milestone field
/// references. This mirrors `collect_complete_field_reads`: the IFC checker uses it
/// to expose and gate a child-to-parent milestone payload with a per-field flow
/// signature (D3′).
fn collect_milestone_field_reads(
    statements: &[body::BodyStmt],
    out: &mut BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Milestone { name, fields, .. } => {
                let per_field = out.entry(name.clone()).or_default();
                for field in fields {
                    let mut roots = BTreeSet::new();
                    match &field.value {
                        body::FieldValue::Shorthand => {}
                        body::FieldValue::Expr { expr, .. } => {
                            collect_expr_binding_roots(expr, &mut roots)
                        }
                        body::FieldValue::Nested { fields, .. } => {
                            collect_payload_field_roots(fields, None, &mut roots)
                        }
                    }
                    per_field
                        .entry(field.name.clone())
                        .or_default()
                        .extend(roots);
                }
            }
            body::BodyStmt::After(after) => collect_milestone_field_reads(&after.body, out),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_milestone_field_reads(&branch.body, out);
                }
            }
            _ => {}
        }
    }
}

/// Collects the `redact <source> keep [..] as <out>` projections of a rule body
/// (recursing into nested blocks) as IFC value-flow metadata, preserving body
/// order so a chained redaction's source resolves against the earlier projection.
/// `binding_types` (the rule's fully-resolved binding -> schema map, including
/// redaction outputs via their synthetic class) supplies each source's schema so
/// the IFC engine can derive the projection's per-field label.
fn collect_redaction_metadata(
    statements: &[body::BodyStmt],
    binding_types: &BTreeMap<String, String>,
    out: &mut Vec<IrRedaction>,
) {
    let mut redacts = Vec::new();
    collect_redact_effects(statements, &mut redacts);
    for (source, keep, binding, _span) in redacts {
        out.push(IrRedaction {
            source: source.to_owned(),
            keep: keep.to_vec(),
            binding: binding.to_owned(),
            source_schema: binding_types.get(source).cloned(),
        });
    }
}

/// Collect the bounded-type projection egresses (`record <T> from <src>`) of a rule
/// body (recursing into nested blocks). A `record T from src` keeps exactly `T`'s
/// declared fields, copied from `src`, so the IFC engine can govern it by the kept
/// fields' per-field labels (sourced from `src`'s schema) — the "bounded-type"
/// auto-redaction reading. Only recorded when the source schema resolves and the
/// target type is declared; otherwise the egress stays conservative.
/// Records a bounded-type projection egress for a PURE `from` projection — a
/// `from <src>` egress every field of which is a shorthand copy of `src.<name>`.
/// The runtime materializes exactly these fields, so the kept set is their names,
/// governed by `src`'s schema per-field labels. `None` source schema, no `from`, or
/// any explicit value field → not a clean projection, so it stays conservative
/// (handled by the whole-read join). `sink` is the engine sink string
/// (`fact:<Schema>` for a record, the completed binding for a `complete`).
fn push_bounded_projection(
    from: Option<&str>,
    fields: &[body::FieldAssign],
    sink: String,
    binding_types: &BTreeMap<String, String>,
    out: &mut Vec<IrBoundedEgress>,
) {
    let Some(source_schema) = from.and_then(|src| binding_types.get(src)) else {
        return;
    };
    if fields.is_empty()
        || !fields
            .iter()
            .all(|field| matches!(field.value, body::FieldValue::Shorthand))
    {
        return;
    }
    out.push(IrBoundedEgress {
        sink,
        source_schema: source_schema.clone(),
        keep: fields.iter().map(|field| field.name.clone()).collect(),
    });
}

fn push_bounded_record(
    record: &body::RecordStmt,
    binding_types: &BTreeMap<String, String>,
    out: &mut Vec<IrBoundedEgress>,
) {
    push_bounded_projection(
        record.from.as_deref(),
        &record.fields,
        format!("fact:{}", record.schema),
        binding_types,
        out,
    );
}

fn collect_bounded_egresses(
    statements: &[body::BodyStmt],
    binding_types: &BTreeMap<String, String>,
    out: &mut Vec<IrBoundedEgress>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Record(record) => push_bounded_record(record, binding_types, out),
            body::BodyStmt::Done {
                replacement: Some(record),
                ..
            } => push_bounded_record(record, binding_types, out),
            // `complete <T> from <src> { … }`: bounded-type projection to the invoker.
            // The engine sink for a complete is the completed binding (its name).
            body::BodyStmt::Terminal(terminal)
                if terminal.kind == body::TerminalKind::Complete && terminal.from.is_some() =>
            {
                push_bounded_projection(
                    terminal.from.as_deref(),
                    &terminal.fields,
                    terminal.name.clone(),
                    binding_types,
                    out,
                );
            }
            body::BodyStmt::After(after) => {
                collect_bounded_egresses(&after.body, binding_types, out)
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_bounded_egresses(&branch.body, binding_types, out);
                }
            }
            _ => {}
        }
    }
}

/// Collect EVERY binding root referenced by an expression, for the information-flow
/// value-flow engine. SOUNDNESS: a missed reference under-approximates a payload's
/// sources — so this over-collects (an over-collected name that is not a relevant
/// binding contributes nothing downstream). It walks every `Expr` variant and, for
/// string literals, extracts `{{ … }}` interpolation roots (those refs live as raw
/// text inside the literal, not as structured nodes). A bare identifier parses as
/// `Literal(Ident)`, a dotted ref as `Path` — both are roots.
fn collect_expr_binding_roots(expr: &Expr, out: &mut BTreeSet<String>) {
    match expr {
        Expr::Literal(ExprLiteral::String(text)) => collect_template_binding_roots(text, out),
        Expr::Literal(ExprLiteral::Ident(name)) => {
            out.insert(name.clone());
        }
        Expr::Literal(ExprLiteral::Number(_) | ExprLiteral::Bool(_) | ExprLiteral::Null) => {}
        Expr::Path(segments) => {
            if let Some(root) = segments.first() {
                out.insert(root.clone());
            }
        }
        Expr::Index { target, key } => {
            collect_expr_binding_roots(target, out);
            collect_expr_binding_roots(key, out);
        }
        Expr::Array(items) => {
            for item in items {
                collect_expr_binding_roots(item, out);
            }
        }
        Expr::Object(fields) => {
            for field in fields {
                collect_expr_binding_roots(&field.value, out);
            }
        }
        Expr::Unary { expr, .. } => collect_expr_binding_roots(expr, out),
        Expr::Binary { left, right, .. } => {
            collect_expr_binding_roots(left, out);
            collect_expr_binding_roots(right, out);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_expr_binding_roots(arg, out);
            }
        }
        Expr::Query { head, guard, .. } => {
            out.insert(head.clone());
            if let Some(guard) = guard {
                collect_expr_binding_roots(guard, out);
            }
        }
    }
}

/// Collect every binding root inside `{{ … }}` interpolations of a string. Unlike
/// `interpolation_roots` (first root per interpolation), value-flow needs EVERY
/// root, so `{{ a.b + c.d }}` yields both `a` and `c`. Each interpolation body is
/// parsed and walked; an unparseable body falls back to a conservative identifier
/// scan (over-collection is sound).
fn collect_template_binding_roots(text: &str, out: &mut BTreeSet<String>) {
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        let after_open = &rest[open + 2..];
        let Some(close) = after_open.find("}}") else {
            break;
        };
        let body = after_open[..close].trim();
        if let Ok(expr) = parse_expression(body) {
            collect_expr_binding_roots(&expr, out);
        } else {
            for token in body.split(|ch: char| !ch.is_alphanumeric() && ch != '_') {
                if token
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| is_ident_start(*byte))
                {
                    out.insert(token.to_owned());
                }
            }
        }
        rest = &after_open[close + 2..];
    }
}

/// Collect the binding roots a payload field list references, threading the
/// enclosing `from <binding>` source so a `Shorthand` field resolves to it.
fn collect_payload_field_roots(
    fields: &[body::FieldAssign],
    from_binding: Option<&str>,
    out: &mut BTreeSet<String>,
) {
    for field in fields {
        match &field.value {
            body::FieldValue::Shorthand => {
                if let Some(root) = from_binding {
                    out.insert(root.to_owned());
                }
            }
            body::FieldValue::Expr { expr, .. } => collect_expr_binding_roots(expr, out),
            body::FieldValue::Nested { fields, .. } => {
                collect_payload_field_roots(fields, from_binding, out)
            }
        }
    }
}

/// For each egress sink in a rule body (recursing into nested blocks), the set of
/// binding roots its payload references, keyed by the sink string the IFC engine
/// uses: a `complete <binding>` by its binding, a `record <Schema>` by
/// `fact:<Schema>`. Surfaced so the engine can recognize a FULLY-REDACTED egress —
/// one whose payload references only redaction outputs (and constants) — and
/// govern it by the projection's per-field label instead of the rule's whole read
/// set. A `record <Schema> from <binding>` references that `from` binding too (its
/// fields are copied). A sink with no recorded entry references nothing resolvable.
fn collect_egress_payload_reads(
    statements: &[body::BodyStmt],
    binding_resources: &BTreeMap<String, String>,
    out: &mut Vec<(String, BTreeSet<String>)>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Terminal(terminal) if terminal.kind == body::TerminalKind::Complete => {
                let mut roots = BTreeSet::new();
                collect_payload_field_roots(&terminal.fields, None, &mut roots);
                // A bare scalar payload's value expression is the whole egress
                // value; its binding roots must join the sink's label (fail-closed
                // — otherwise `complete result secret.value` would under-report).
                if let Some(body::FieldValue::Expr { expr, .. }) = &terminal.scalar {
                    collect_expr_binding_roots(expr, &mut roots);
                }
                out.push((terminal.name.clone(), roots));
            }
            body::BodyStmt::Record(record) => out.push(record_payload_reads(record)),
            // `done <b> -> record <Schema> { … }` is also a record egress.
            body::BodyStmt::Done {
                replacement: Some(record),
                ..
            } => out.push(record_payload_reads(record)),
            body::BodyStmt::Milestone { name, fields, .. } => {
                let mut roots = BTreeSet::new();
                collect_payload_field_roots(fields, None, &mut roots);
                out.push((format!("milestone:{name}"), roots));
            }
            // `send via <channel> { text … }` egresses to the channel; its payload
            // fields (text/markdown/thread_id) are construct-use source text. Keyed by
            // the channel (the engine's send sink, per `resource_for_body`). A
            // `write … to <store>` is likewise an egress to the store: its body
            // AND path expressions are the payload (a path can encode data too),
            // keyed by the store handle.
            body::BodyStmt::Effect(effect) => match &effect.kind {
                body::BodyEffectKind::ConstructCapabilityCall {
                    keyword, fields, ..
                } if keyword == "send" => {
                    if let Some(reads) = send_payload_reads(fields) {
                        out.push(reads);
                    }
                }
                // A `request` egresses its URL, its non-credential header
                // values, and its body. The URL counts: a path or query can
                // carry data as surely as a body can, which is the same
                // reasoning `write … to <store>` applies to its path.
                body::BodyEffectKind::HttpRequest {
                    url,
                    headers,
                    body,
                    signed_with,
                    ..
                } => {
                    let Some(credential) =
                        request_credential_handle(headers, signed_with.as_deref())
                    else {
                        continue;
                    };
                    let mut roots = BTreeSet::new();
                    collect_template_binding_roots(url, &mut roots);
                    for header in headers {
                        // A credential slot carries a HANDLE, never an
                        // expression, so there is nothing to read from it.
                        if let body::RequestHeaderValue::Expr { expr, .. } = &header.value {
                            collect_expr_binding_roots(expr, &mut roots);
                        }
                    }
                    if let Some((source, expr)) = body {
                        collect_expr_binding_roots(expr, &mut roots);
                        collect_template_binding_roots(source, &mut roots);
                    }
                    out.push((credential.to_owned(), roots));
                }
                // What a filed issue carries into the tracker: every field
                // value. `finish item { summary … }` is NOT here — it names an
                // item binding rather than a tracker, so its queue is not known
                // statically. That residual is recorded on the tracker.
                // `finish <item> { summary … }` writes its fields into the
                // same durable row `file issue` does, so what it reads is
                // recorded against the same sink. The queue comes from the
                // binding map, since the statement names an item.
                body::BodyEffectKind::TrackerFinish { item, fields } => {
                    let Some(queue) = binding_resources.get(item) else {
                        continue;
                    };
                    let mut roots = BTreeSet::new();
                    collect_payload_field_roots(fields, None, &mut roots);
                    out.push((queue.clone(), roots));
                }
                body::BodyEffectKind::TrackerFile { queue, fields } => {
                    let mut roots = BTreeSet::new();
                    collect_payload_field_roots(fields, None, &mut roots);
                    out.push((queue.clone(), roots));
                }
                // A mint's exchange egresses its URL, its non-credential
                // header values and its body, exactly as a request does.
                body::BodyEffectKind::MintCredential {
                    parent,
                    url,
                    headers,
                    body,
                    ..
                } => {
                    let mut roots = BTreeSet::new();
                    collect_template_binding_roots(url, &mut roots);
                    for header in headers {
                        if let body::RequestHeaderValue::Expr { expr, .. } = &header.value {
                            collect_expr_binding_roots(expr, &mut roots);
                        }
                    }
                    if let Some((source, expr)) = body {
                        collect_expr_binding_roots(expr, &mut roots);
                        collect_template_binding_roots(source, &mut roots);
                    }
                    out.push((parent.clone(), roots));
                }
                body::BodyEffectKind::FileWrite {
                    store, path, body, ..
                } => {
                    let mut roots = BTreeSet::new();
                    for source in [path, body] {
                        if let Ok(expr) = parse_expression(source) {
                            collect_expr_binding_roots(&expr, &mut roots);
                        } else {
                            collect_template_binding_roots(source, &mut roots);
                        }
                    }
                    out.push((store.clone(), roots));
                }
                _ => {}
            },
            body::BodyStmt::After(after) => {
                collect_egress_payload_reads(&after.body, binding_resources, out)
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_egress_payload_reads(&branch.body, binding_resources, out);
                }
            }
            _ => {}
        }
    }
}

/// The channel sink key and the binding roots a `send` payload references. The
/// payload fields (`text`/`markdown`/`thread_id`) carry expression SOURCE TEXT, so
/// each is parsed and walked (a string literal's `{{ … }}` interpolations count);
/// the `channel` field names the sink. `None` if no channel is present.
fn send_payload_reads(fields: &[body::ConstructUseField]) -> Option<(String, BTreeSet<String>)> {
    let channel = fields
        .iter()
        .find(|field| field.name == "channel")
        .map(|field| field.source.clone())?;
    let mut roots = BTreeSet::new();
    for field in fields.iter().filter(|field| field.name != "channel") {
        if let Ok(expr) = parse_expression(&field.source) {
            collect_expr_binding_roots(&expr, &mut roots);
        } else {
            // Unparseable source: scan its interpolations conservatively.
            collect_template_binding_roots(&field.source, &mut roots);
        }
    }
    Some((channel, roots))
}

/// The `fact:<Schema>` sink key and the binding roots a `record` payload
/// references — its explicit field values plus, for `record <S> from <b>`, the
/// copied-from binding `b`.
/// DR-0051 §4: per-field binding roots for every `record <Schema> { … }` in a
/// rule body, recursing into nested blocks. Mirrors
/// `collect_complete_field_reads`; see `record_field_reads`.
fn collect_record_field_reads(
    statements: &[body::BodyStmt],
    out: &mut BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
) {
    fn record_fields(
        record: &body::RecordStmt,
        out: &mut BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    ) {
        let per_field = out.entry(format!("fact:{}", record.schema)).or_default();
        for field in &record.fields {
            let mut roots = BTreeSet::new();
            match &field.value {
                body::FieldValue::Shorthand => {
                    if let Some(root) = &record.from {
                        roots.insert(root.clone());
                    }
                }
                body::FieldValue::Expr { expr, .. } => collect_expr_binding_roots(expr, &mut roots),
                body::FieldValue::Nested { fields, .. } => {
                    collect_payload_field_roots(fields, record.from.as_deref(), &mut roots)
                }
            }
            per_field
                .entry(field.name.clone())
                .or_default()
                .extend(roots);
        }
    }
    for statement in statements {
        match statement {
            body::BodyStmt::Record(record) => record_fields(record, out),
            body::BodyStmt::Done {
                replacement: Some(record),
                ..
            } => record_fields(record, out),
            body::BodyStmt::After(after) => collect_record_field_reads(&after.body, out),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_record_field_reads(&branch.body, out);
                }
            }
            _ => {}
        }
    }
}

fn record_payload_reads(record: &body::RecordStmt) -> (String, BTreeSet<String>) {
    let mut roots = BTreeSet::new();
    if let Some(from) = &record.from {
        roots.insert(from.clone());
    }
    collect_payload_field_roots(&record.fields, record.from.as_deref(), &mut roots);
    (format!("fact:{}", record.schema), roots)
}

#[derive(Clone, Debug, Default)]
struct TerminalMetadata {
    outputs: Vec<IrTerminalOutput>,
    branches: Vec<IrTerminalCaseBranch>,
    envelope_reads_on_payload: Vec<IrEnvelopeFieldOnPayload>,
}

#[derive(Clone, Debug)]
struct TerminalBranchSource {
    scrutinee: String,
    pattern: String,
    guard: Option<String>,
    body: String,
    pattern_span: SourceSpan,
}

#[derive(Clone, Debug)]
struct RuleCaseBranchSource {
    scrutinee: String,
    scrutinee_type: TypeSyntax,
    pattern: String,
    guard: Option<String>,
    body: String,
    pattern_span: SourceSpan,
}

/// The custody capability an `open` targets (DR-0074 §3). Named once here
/// because three separate checks key on it — the plaintext binding's type, the
/// three-way type agreement, and the confinement analysis.
pub(crate) const CUSTODY_UNWRAP_CAPABILITY: &str = "custody.unwrap";
/// The custody capability a `seal` targets (DR-0074 §12).
pub(crate) const CUSTODY_WRAP_CAPABILITY: &str = "custody.wrap";
/// The value slot of the `seal` construct, as the manifest names it.
pub(crate) const SEAL_VALUE_SLOT: &str = "value";
/// The `into <Type>` slot of the `open` construct, as the manifest names it.
pub(crate) const OPEN_PAYLOAD_TYPE_SLOT: &str = "payload_type";
/// The sealed-envelope slot of the `open` construct.
pub(crate) const OPEN_ENVELOPE_SLOT: &str = "envelope";

fn collect_effect_payload_types(
    rule: &RuleDecl,
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeMap<String, IrType> {
    let mut payloads = BTreeMap::new();
    for statement in effect_payload_statements(&rule.body.text) {
        let line = statement.trim();
        let Some((kind, Some(binding))) = parse_effect_line(line) else {
            continue;
        };
        let payload = terminal_completed_payload_type(line, &kind, semantic);
        // A binding name keys the per-rule payload map, so reusing it for two effects
        // with DIFFERENT result types makes `after <binding> …` ambiguous (§5.5).
        // Same-type reuse (and mutually-exclusive `case` arms, which never both run)
        // is harmless and left alone.
        match payloads.get(&binding) {
            Some(existing) if existing != &payload => {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: rule.body.span,
                    message: format!(
                        "rule `{}` reuses effect binding `{binding}` for effects with conflicting result types",
                        rule.name.name
                    ),
                    suggestion: Some(format!(
                        "give each effect a distinct binding — `as {binding}` is reused with a different result type, so `after {binding} …` is ambiguous"
                    )),
                });
            }
            Some(_) => {}
            None => {
                payloads.insert(binding, payload);
            }
        }
    }

    payloads
}

fn terminal_completed_payload_type(
    line: &str,
    kind: &IrEffectKind,
    semantic: &SemanticContext,
) -> IrType {
    match kind {
        IrEffectKind::SchemaCoerce if line.starts_with("prompt ") => {
            IrType::Primitive(IrPrimitiveType::String)
        }
        IrEffectKind::SchemaCoerce => parse_coerce_call_name(line)
            .and_then(|name| semantic.coerce_outputs.get(name))
            .cloned()
            .map(lower_type)
            .unwrap_or_else(terminal_unknown_payload_type),
        // An agent turn's `Completed` payload is the TURN'S OUTPUT, whose shape
        // is a runtime boundary — not the `AgentTurn` envelope, whose fields
        // reach a rule through the `after … completes as o` alias instead.
        //
        // This arm read `Ref("AgentTurn")` and was unreachable:
        // `effect_payload_statements` admits only `coerce` and `claim` lines,
        // so a `tell` never arrives here. Left correct rather than removed, so
        // that widening the collection later cannot quietly assert the
        // envelope's shape onto the payload.
        IrEffectKind::AgentTell => terminal_unknown_payload_type(),
        IrEffectKind::CapabilityCall
        | IrEffectKind::HttpRequest
        | IrEffectKind::MintCredential
        | IrEffectKind::EventEmit
        | IrEffectKind::WorkflowInvoke
        | IrEffectKind::TimerWait
        | IrEffectKind::ExecCommand
        | IrEffectKind::TrackerFile
        | IrEffectKind::TrackerClaim
        | IrEffectKind::TrackerRenew
        | IrEffectKind::TrackerRelease
        | IrEffectKind::TrackerFinish
        | IrEffectKind::LeaseAcquire
        | IrEffectKind::LeaseRenew
        | IrEffectKind::LedgerAppend
        | IrEffectKind::CounterConsume
        | IrEffectKind::SignalEmit
        | IrEffectKind::FileRead
        | IrEffectKind::FileWrite
        | IrEffectKind::FileImport
        | IrEffectKind::FileExport => terminal_unknown_payload_type(),
    }
}

fn collect_rule_case_metadata(
    rule: &RuleDecl,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<IrRuleCaseBranch> {
    let mut branches = Vec::new();
    for branch in rule_case_branch_sources(rule, semantic, binding_types) {
        let mut branch_scope = binding_types.clone();
        if let Some((binding, schema)) =
            case_branch_payload_binding(&branch.pattern, &branch.scrutinee_type, semantic)
        {
            branch_scope.insert(binding, schema);
        }
        if let Some(guard) = &branch.guard {
            validate_expression(
                rule,
                guard,
                semantic,
                &branch_scope,
                "case guard",
                diagnostics,
            );
            validate_known_field_paths_at_span(
                rule,
                guard,
                branch.pattern_span,
                semantic,
                &branch_scope,
                diagnostics,
            );
        }
        validate_known_field_paths_at_span(
            rule,
            &branch.body,
            branch.pattern_span,
            semantic,
            &branch_scope,
            diagnostics,
        );
        if let Some(pattern) = lower_case_pattern(&branch.pattern, &branch.scrutinee_type, semantic)
        {
            branches.push(IrRuleCaseBranch {
                scrutinee: branch.scrutinee,
                scrutinee_type: lower_type(branch.scrutinee_type),
                pattern,
                guard: branch.guard.as_ref().and_then(|guard| {
                    lower_expression(
                        guard,
                        SourceSpan {
                            start: branch.pattern_span.start,
                            end: branch.pattern_span.end,
                        },
                    )
                }),
                body_hash: stable_hash(&branch.body),
                pattern_span: branch.pattern_span,
            });
        }
    }
    branches.sort_by(|left, right| {
        (left.scrutinee.as_str(), left.pattern_span.start)
            .cmp(&(right.scrutinee.as_str(), right.pattern_span.start))
    });
    branches
}

fn rule_case_branch_sources(
    rule: &RuleDecl,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
) -> Vec<RuleCaseBranchSource> {
    let lines = rule
        .body
        .text
        .lines()
        .scan(0usize, |offset, line| {
            let current = *offset;
            *offset += line.len() + 1;
            Some((line, current))
        })
        .collect::<Vec<_>>();
    let text_lines = lines.iter().map(|(line, _)| *line).collect::<Vec<_>>();
    let mut branches = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let (line, _) = lines[index];
        let trimmed = line.trim();
        let Some(scrutinee) = case_scrutinee(trimmed) else {
            index += 1;
            continue;
        };
        if active_completes_binding_for_case(&text_lines, index, scrutinee) {
            index += 1;
            continue;
        }
        let Some(scrutinee_type) = expression_type(scrutinee, semantic, binding_types) else {
            index += 1;
            continue;
        };
        let mut depth = brace_delta(trimmed).max(1);
        index += 1;
        while index < lines.len() && depth > 0 {
            let (branch_line, branch_line_offset) = lines[index];
            let branch_trimmed = branch_line.trim();
            if depth == 1 {
                if let Some((pattern, guard, body_start)) = terminal_branch_header(branch_trimmed) {
                    let pattern_column = case_pattern_column(branch_line, pattern);
                    let pattern_span = SourceSpan {
                        start: rule_body_text_start(rule) + branch_line_offset + pattern_column,
                        end: rule_body_text_start(rule)
                            + branch_line_offset
                            + pattern_column
                            + pattern.len(),
                    };
                    let mut body_lines = Vec::new();
                    let mut branch_depth = brace_delta(body_start).max(1);
                    index += 1;
                    while index < lines.len() && branch_depth > 0 {
                        let body_line = lines[index].0;
                        let next_depth = branch_depth + brace_delta(body_line);
                        if next_depth >= 1 {
                            body_lines.push(body_line.to_owned());
                        }
                        branch_depth = next_depth;
                        index += 1;
                    }
                    branches.push(RuleCaseBranchSource {
                        scrutinee: scrutinee.to_owned(),
                        scrutinee_type: scrutinee_type.clone(),
                        pattern: pattern.to_owned(),
                        guard,
                        body: body_lines.join("\n"),
                        pattern_span,
                    });
                    continue;
                }
            }
            depth += brace_delta(branch_trimmed);
            index += 1;
        }
    }
    branches
}

fn case_branch_payload_binding(
    pattern: &str,
    scrutinee_type: &TypeSyntax,
    semantic: &SemanticContext,
) -> Option<(String, String)> {
    // Sum types: `Variant as b` binds the payload typed as the generated
    // `<Enum>.<Variant>` class (spec/sum-types.md).
    if let TypeSyntax::Ref { name } = scrutinee_type {
        if semantic.schemas.enums.contains_key(&name.name) {
            let (variant, binding) = sum_case_pattern_parts(pattern);
            let binding = binding?;
            let generated = format!("{}.{variant}", name.name);
            if binding.is_empty() || !semantic.schemas.class_exists(&generated) {
                return None;
            }
            return Some((binding.to_owned(), generated));
        }
    }
    let binding = pattern.strip_prefix("Some ").map(str::trim)?;
    if binding.is_empty() {
        return None;
    }
    let TypeSyntax::Optional { inner, .. } = scrutinee_type else {
        return None;
    };
    let schema = match inner.as_ref() {
        TypeSyntax::Ref { name } if semantic.schemas.class_exists(&name.name) => {
            Some(name.name.clone())
        }
        _ => None,
    }?;
    Some((binding.to_owned(), schema))
}

fn collect_terminal_case_metadata(
    rule: &RuleDecl,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    effect_payload_types: &BTreeMap<String, IrType>,
    diagnostics: &mut Vec<Diagnostic>,
) -> TerminalMetadata {
    let mut metadata = TerminalMetadata::default();
    let mut output_bindings = BTreeSet::new();

    for branch in terminal_case_branch_sources(rule) {
        if output_bindings.insert(branch.scrutinee.clone()) {
            let completed_payload = effect_payload_types
                .get(&branch.scrutinee)
                .cloned()
                .unwrap_or_else(terminal_unknown_payload_type);
            metadata.outputs.push(IrTerminalOutput {
                binding: branch.scrutinee.clone(),
                alternatives: terminal_alternatives(completed_payload, branch.pattern_span),
                span: branch.pattern_span,
            });
        }

        let (tag, binding) = parse_terminal_pattern_parts(&branch.pattern);
        let mut branch_scope = binding_types.clone();
        if let (Some(tag), Some(binding)) = (&tag, &binding) {
            match terminal_payload_schema_for_tag(tag, &branch.scrutinee, effect_payload_types) {
                Some(schema) => {
                    branch_scope.insert(binding.clone(), schema);
                }
                // No schema, so `binding` stays out of scope and every field
                // read on it below resolves to `FieldPathCheck::Unbound` —
                // unchecked, which is right for a runtime-boundary shape.
                // Record the reads that name an ENVELOPE field anyway: the
                // payload does not carry those, and the alias that does is in
                // scope. See `IrEnvelopeFieldOnPayload`.
                None => metadata
                    .envelope_reads_on_payload
                    .extend(envelope_fields_read_on_payload(
                        binding,
                        &branch.scrutinee,
                        &branch.body,
                        branch.guard.as_deref(),
                        branch.pattern_span,
                    )),
            }
        }
        if let Some(guard) = &branch.guard {
            validate_expression(
                rule,
                guard,
                semantic,
                &branch_scope,
                "case guard",
                diagnostics,
            );
            validate_known_field_paths(rule, guard, semantic, &branch_scope, diagnostics);
        }
        validate_known_field_paths(rule, &branch.body, semantic, &branch_scope, diagnostics);
        metadata.branches.push(IrTerminalCaseBranch {
            scrutinee: branch.scrutinee,
            tag,
            binding,
            guard: branch.guard.as_ref().and_then(|guard| {
                lower_expression(
                    guard,
                    SourceSpan {
                        start: branch.pattern_span.start,
                        end: branch.pattern_span.end,
                    },
                )
            }),
            body_hash: stable_hash(&branch.body),
            pattern_span: branch.pattern_span,
        });
    }

    metadata
        .outputs
        .sort_by(|left, right| left.binding.cmp(&right.binding));
    metadata.branches.sort_by(|left, right| {
        (left.scrutinee.as_str(), left.pattern_span.start)
            .cmp(&(right.scrutinee.as_str(), right.pattern_span.start))
    });
    metadata.envelope_reads_on_payload.sort_by(|left, right| {
        (left.span.start, left.binding.as_str(), left.field.as_str()).cmp(&(
            right.span.start,
            right.binding.as_str(),
            right.field.as_str(),
        ))
    });
    metadata
}

/// The terminal envelope's field set — the class `TerminalOutcome` the
/// `after x completes as o` alias binds.
const TERMINAL_ENVELOPE_FIELDS: [&str; 5] = ["tag", "status", "summary", "effect_id", "run_id"];

/// Envelope fields read off `binding`, the untyped `Completed` payload of
/// `scrutinee`. Deduplicated per branch: one finding per field named, however
/// many times the branch reads it.
fn envelope_fields_read_on_payload(
    binding: &str,
    scrutinee: &str,
    body: &str,
    guard: Option<&str>,
    span: SourceSpan,
) -> Vec<IrEnvelopeFieldOnPayload> {
    let mut fields = BTreeSet::new();
    for text in std::iter::once(body).chain(guard) {
        for (root, path) in dotted_paths(text) {
            if root != binding {
                continue;
            }
            // The HEAD of the path is what the payload would have to carry;
            // `v.summary.detail` is the same confusion one level deeper.
            if path
                .first()
                .is_some_and(|field| TERMINAL_ENVELOPE_FIELDS.contains(&field.as_str()))
            {
                fields.insert(path[0].clone());
            }
        }
    }
    fields
        .into_iter()
        .map(|field| IrEnvelopeFieldOnPayload {
            scrutinee: scrutinee.to_owned(),
            binding: binding.to_owned(),
            field,
            span,
        })
        .collect()
}

fn terminal_case_branch_sources(rule: &RuleDecl) -> Vec<TerminalBranchSource> {
    let lines = rule
        .body
        .text
        .lines()
        .scan(0usize, |offset, line| {
            let current = *offset;
            *offset += line.len() + 1;
            Some((line, current))
        })
        .collect::<Vec<_>>();
    let text_lines = lines.iter().map(|(line, _)| *line).collect::<Vec<_>>();
    let mut branches = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let (line, line_offset) = lines[index];
        let trimmed = line.trim();
        let Some(scrutinee) = case_scrutinee(trimmed) else {
            index += 1;
            continue;
        };
        if !active_completes_binding_for_case(&text_lines, index, scrutinee) {
            index += 1;
            continue;
        }
        let mut depth = brace_delta(trimmed).max(1);
        index += 1;
        while index < lines.len() && depth > 0 {
            let (branch_line, branch_line_offset) = lines[index];
            let branch_trimmed = branch_line.trim();
            if depth == 1 {
                if let Some((pattern, guard, body_start)) = terminal_branch_header(branch_trimmed) {
                    let pattern_column = case_pattern_column(branch_line, pattern);
                    let pattern_span = SourceSpan {
                        start: rule_body_text_start(rule) + branch_line_offset + pattern_column,
                        end: rule_body_text_start(rule)
                            + branch_line_offset
                            + pattern_column
                            + pattern.len(),
                    };
                    let mut body_lines = Vec::new();
                    let mut branch_depth = brace_delta(body_start).max(1);
                    index += 1;
                    while index < lines.len() && branch_depth > 0 {
                        let body_line = lines[index].0;
                        let next_depth = branch_depth + brace_delta(body_line);
                        if next_depth >= 1 {
                            body_lines.push(body_line.to_owned());
                        }
                        branch_depth = next_depth;
                        index += 1;
                    }
                    branches.push(TerminalBranchSource {
                        scrutinee: scrutinee.to_owned(),
                        pattern: pattern.to_owned(),
                        guard,
                        body: body_lines.join("\n"),
                        pattern_span,
                    });
                    continue;
                }
            }
            depth += brace_delta(branch_trimmed);
            index += 1;
        }
        let _ = line_offset;
    }
    branches
}

fn rule_body_text_start(rule: &RuleDecl) -> usize {
    rule.body.span.end.saturating_sub(2 + rule.body.text.len())
}

fn terminal_branch_header(line: &str) -> Option<(&str, Option<String>, &str)> {
    let (head, body_start) = line.split_once("=>")?;
    let body_start = body_start.trim();
    if !body_start.starts_with('{') {
        return None;
    }
    let head = head.trim();
    let (pattern, guard) = match head.split_once(" where ") {
        Some((pattern, guard)) => (pattern.trim(), Some(guard.trim().to_owned())),
        None => (head, None),
    };
    Some((pattern, guard, body_start))
}

fn case_pattern_column(line: &str, pattern: &str) -> usize {
    line.find(pattern).unwrap_or_else(|| {
        let indent = line.len().saturating_sub(line.trim_start().len());
        indent + line.trim_start().find(pattern).unwrap_or(0)
    })
}

fn parse_terminal_pattern_parts(pattern: &str) -> (Option<String>, Option<String>) {
    if is_fallback_pattern(pattern) {
        return (None, None);
    }
    let mut parts = pattern.split_whitespace();
    let tag = parts.next().map(str::to_owned);
    // Binding is `Tag as binding` (Stage 1b: the space form `Tag binding` is gone).
    let second = parts.next();
    let binding = match second {
        Some("as") => parts.next().map(str::to_owned),
        Some(_) => return (tag, None),
        None => None,
    };
    if parts.next().is_some() {
        return (tag, None);
    }
    (tag, binding)
}

fn terminal_payload_schema_for_tag(
    tag: &str,
    scrutinee: &str,
    effect_payload_types: &BTreeMap<String, IrType>,
) -> Option<String> {
    match tag {
        "Completed" => match effect_payload_types.get(scrutinee) {
            Some(IrType::Ref(schema)) => Some(schema.clone()),
            _ => None,
        },
        "Failed" => Some("TerminalFailed".to_owned()),
        "TimedOut" => Some("TerminalTimedOut".to_owned()),
        "Cancelled" => Some("TerminalCancelled".to_owned()),
        _ => None,
    }
}

fn terminal_alternatives(
    completed_payload: IrType,
    span: SourceSpan,
) -> Vec<IrTerminalAlternative> {
    [
        ("Completed", completed_payload),
        ("Failed", terminal_failure_payload_type()),
        ("TimedOut", terminal_timeout_payload_type()),
        ("Cancelled", terminal_cancelled_payload_type()),
    ]
    .into_iter()
    .map(|(tag, payload_type)| IrTerminalAlternative {
        tag: tag.to_owned(),
        payload_type,
        source_span: span,
    })
    .collect()
}

fn terminal_failure_payload_type() -> IrType {
    IrType::Object(vec![
        ir_field("reason", IrType::Primitive(IrPrimitiveType::String)),
        ir_field("summary", IrType::Primitive(IrPrimitiveType::String)),
        ir_field("effect_id", IrType::Primitive(IrPrimitiveType::String)),
        ir_field("run_id", IrType::Primitive(IrPrimitiveType::String)),
    ])
}

fn terminal_timeout_payload_type() -> IrType {
    IrType::Object(vec![
        ir_field("summary", IrType::Primitive(IrPrimitiveType::String)),
        ir_field("effect_id", IrType::Primitive(IrPrimitiveType::String)),
        ir_field("run_id", IrType::Primitive(IrPrimitiveType::String)),
    ])
}

fn terminal_cancelled_payload_type() -> IrType {
    IrType::Object(vec![
        ir_field("summary", IrType::Primitive(IrPrimitiveType::String)),
        ir_field("effect_id", IrType::Primitive(IrPrimitiveType::String)),
        ir_field("run_id", IrType::Primitive(IrPrimitiveType::String)),
    ])
}

/// The `Completed` payload of an effect whose result shape is not statically
/// known: an object that claims NO fields.
///
/// It used to claim `{summary, effect_id, run_id}`, and that was a wrong claim
/// rather than a conservative default. Those three belong to the terminal
/// ENVELOPE — the `after x completes as o` alias, typed `TerminalOutcome` — and
/// the runtime's `Completed` payload is `value.value`/`value.output`, the
/// effect's own result, which carries none of them.
///
/// The cost of the old claim was a reader misled, not a program broken: nothing
/// enforces a payload's field set (`whip check` accepts any field name on a
/// dynamically-shaped payload), so the three fields only ever appeared in the
/// IR snapshot. But that snapshot is what an author consults, and it said
/// `summary` was on the payload — which is exactly the mistake
/// `examples/scheduled-escalation.whip` shipped, reading `decided.summary`
/// where it wanted `answer.summary`.
///
/// The failure tags keep their fields: `Failed`, `TimedOut` and `Cancelled` DO
/// carry `summary`/`effect_id`/`run_id` at runtime, because
/// `terminal_payload_for_tag` lifts them into those payloads. Only the
/// `Completed` side was fiction.
fn terminal_unknown_payload_type() -> IrType {
    IrType::Object(Vec::new())
}

fn ir_field(name: &str, ty: IrType) -> IrClassField {
    IrClassField {
        name: name.to_owned(),
        ty,
        is_key: false,
        presence_condition: None,
        span: SourceSpan { start: 0, end: 0 },
    }
}

/// Lower parsed access grants to IR for effects that carry authority-narrowing
/// metadata (`tell` turns and `invoke` start grants).
fn ir_access_grants_for_body(kind: &body::BodyEffectKind) -> Vec<IrAccessGrant> {
    match kind {
        body::BodyEffectKind::Tell { access_grants, .. }
        | body::BodyEffectKind::Invoke { access_grants, .. }
        | body::BodyEffectKind::Exec { access_grants, .. }
        | body::BodyEffectKind::Coerce { access_grants, .. } => access_grants
            .iter()
            .map(|grant| IrAccessGrant {
                resource: grant.resource.clone(),
                operations: grant
                    .operations
                    .iter()
                    .map(|op| IrAccessGrantOp {
                        operation: op.operation.clone(),
                        target: op.target.clone(),
                        globs: op.globs.clone(),
                    })
                    .collect(),
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn ir_effect_kind_for_body(kind: &body::BodyEffectKind) -> IrEffectKind {
    match kind {
        body::BodyEffectKind::Tell { .. } => IrEffectKind::AgentTell,
        body::BodyEffectKind::Coerce { .. }
        | body::BodyEffectKind::Prompt { .. }
        | body::BodyEffectKind::Decide { .. } => IrEffectKind::SchemaCoerce,
        body::BodyEffectKind::Call { .. }
        | body::BodyEffectKind::ConstructCapabilityCall { .. } => IrEffectKind::CapabilityCall,
        body::BodyEffectKind::Invoke { .. } => IrEffectKind::WorkflowInvoke,
        body::BodyEffectKind::Timer { .. } => IrEffectKind::TimerWait,
        body::BodyEffectKind::Exec { .. } => IrEffectKind::ExecCommand,
        body::BodyEffectKind::HttpRequest { .. } => IrEffectKind::HttpRequest,
        body::BodyEffectKind::MintCredential { .. } => IrEffectKind::MintCredential,
        // DR-0053 §11 files a tracker item; it is not a custody OPERATION, so
        // it lowers onto the tracker-file effect kind rather than minting a
        // kind whose only difference is which fields the handler adds.
        body::BodyEffectKind::ObtainCredential { .. } => IrEffectKind::TrackerFile,
        body::BodyEffectKind::TrackerFile { .. } => IrEffectKind::TrackerFile,
        body::BodyEffectKind::TrackerClaim { .. } => IrEffectKind::TrackerClaim,
        body::BodyEffectKind::TrackerRelease { .. } => IrEffectKind::TrackerRelease,
        body::BodyEffectKind::TrackerFinish { .. } => IrEffectKind::TrackerFinish,
        body::BodyEffectKind::LeaseAcquire { .. } => IrEffectKind::LeaseAcquire,
        body::BodyEffectKind::LeaseRenew { .. } => IrEffectKind::LeaseRenew,
        body::BodyEffectKind::LedgerAppend { .. } => IrEffectKind::LedgerAppend,
        body::BodyEffectKind::CounterConsume { .. } => IrEffectKind::CounterConsume,
        body::BodyEffectKind::Notify { .. } => IrEffectKind::SignalEmit,
        body::BodyEffectKind::FileRead { .. } => IrEffectKind::FileRead,
        body::BodyEffectKind::FileWrite { .. } => IrEffectKind::FileWrite,
        body::BodyEffectKind::FileImport { .. } => IrEffectKind::FileImport,
        body::BodyEffectKind::FileExport { .. } => IrEffectKind::FileExport,
    }
}

/// The agent a `tell` addresses, surfaced for information-flow analysis of the
/// turn's egress to the agent's provider. `None` for non-`tell` effects.
fn agent_for_body(kind: &body::BodyEffectKind) -> Option<String> {
    match kind {
        body::BodyEffectKind::Tell { target, .. } => Some(target.clone()),
        _ => None,
    }
}

/// The `coerce` declaration a coerce effect invokes (DR-0062). An inline
/// `decide` names no declaration, so it yields `None` and falls back to the
/// un-named-backend principal.
fn coerce_target_for_body(kind: &body::BodyEffectKind) -> Option<String> {
    match kind {
        body::BodyEffectKind::Coerce { name, .. } => Some(name.clone()),
        _ => None,
    }
}

/// Turn-scoped `with skills [...]` pinned onto an `agent.tell` effect (Phase 7).
fn turn_skills_for_body(kind: &body::BodyEffectKind) -> Vec<String> {
    match kind {
        body::BodyEffectKind::Tell { skills, .. } => skills.clone(),
        _ => Vec::new(),
    }
}

/// `on stream <name>` (std.vcs) carried on an `agent.tell` effect.
fn on_stream_for_body(kind: &body::BodyEffectKind) -> Option<String> {
    match kind {
        body::BodyEffectKind::Tell { on_stream, .. } => on_stream.clone(),
        _ => None,
    }
}

/// The std.vcs selective verbs' statically-checkable pieces (DR-0052
/// R4): the raw selection-slot source, and transport's `onto` target.
fn vcs_selective_for_body(kind: &body::BodyEffectKind) -> (Option<String>, Option<String>) {
    let body::BodyEffectKind::ConstructCapabilityCall {
        keyword, fields, ..
    } = kind
    else {
        return (None, None);
    };
    if keyword != "undo" && keyword != "transport" {
        return (None, None);
    }
    let field = |name: &str| {
        fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.source.clone())
    };
    (field("selection"), field("onto"))
}

/// The workflow an `invoke` targets, surfaced for IFC membrane-door enumeration.
fn workflow_target_for_body(kind: &body::BodyEffectKind) -> Option<String> {
    match kind {
        body::BodyEffectKind::Invoke { workflow, .. } => Some(workflow.clone()),
        _ => None,
    }
}

/// The `exec` surface form (raw command vs manifest capability), surfaced so
/// check-time gates classify exec effects without re-scanning rule-body text.
/// Walk every `request` in a rule body, including inside `after` blocks and
/// `case` arms — an unauthenticated request nested in a branch is still one.
/// DR-0053 §5 as amended. Three refusals, and each closes a way the exchange
/// could quietly not mean what it says.
fn validate_mint_credential(
    rule: &RuleDecl,
    effect: &body::EffectStmt,
    declared_credentials: &BTreeSet<&str>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let body::BodyEffectKind::MintCredential {
        parent, headers, ..
    } = &effect.kind
    else {
        return;
    };
    if !declared_credentials.contains(parent.as_str()) {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: effect.span,
            message: format!(
                "rule `{}` mints from undeclared credential `{parent}`",
                rule.name.name
            ),
            suggestion: Some(format!(
                "declare it: `credential {parent} {{ kind bearer }}`"
            )),
        });
    }
    let presented: BTreeSet<&str> = headers
        .iter()
        .filter_map(|header| match &header.value {
            body::RequestHeaderValue::Credential { handle, .. } => Some(handle.as_str()),
            body::RequestHeaderValue::Expr { .. } => None,
        })
        .collect();
    // An exchange that presents NOTHING spends nothing: a token endpoint would
    // refuse it, and more to the point the mint would not be an exercise of the
    // parent's authority at all.
    if presented.is_empty() {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: effect.span,
            message: format!(
                "rule `{}` mints from `{parent}` without presenting it",
                rule.name.name
            ),
            suggestion: Some(format!(
                "present the parent at a marked slot: `header \"Authorization\" basic {parent}`"
            )),
        });
    }
    // Presenting a DIFFERENT credential is the confusion worth naming: the
    // child inherits `{parent}`'s ceiling by name, so an exchange spending some
    // other credential would produce a child bounded by an authority it was
    // never derived from.
    for handle in presented {
        if handle != parent {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: effect.span,
                message: format!(
                    "rule `{}` mints from `{parent}` but the exchange presents `{handle}`",
                    rule.name.name
                ),
                suggestion: Some(
                    "a mint spends exactly the credential it mints from — the child inherits \
                     that parent's egress ceiling through its name"
                        .to_owned(),
                ),
            });
        }
    }
}

fn validate_http_requests(
    rule: &RuleDecl,
    statements: &[body::BodyStmt],
    declared_credentials: &BTreeSet<&str>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                validate_http_request(rule, effect, declared_credentials, diagnostics);
                validate_obtain_credential(rule, effect, declared_credentials, diagnostics);
                validate_mint_credential(rule, effect, declared_credentials, diagnostics);
            }
            body::BodyStmt::After(after) => {
                validate_http_requests(rule, &after.body, declared_credentials, diagnostics)
            }
            _ => {}
        }
    }
}

/// An `obtain credential` must name a credential the program declares
/// (DR-0053 §11).
///
/// The escalation is *for* a specific authority, and a typo'd handle would file
/// a governance item asking a human for a credential no rule can ever use —
/// the escalation would look answered and change nothing. This is the one
/// static check the verb needs: it presents no material and calls no custody
/// operation, so there is nothing else about it to get wrong at runtime.
fn validate_obtain_credential(
    rule: &RuleDecl,
    effect: &body::EffectStmt,
    declared_credentials: &BTreeSet<&str>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let body::BodyEffectKind::ObtainCredential { credential, .. } = &effect.kind else {
        return;
    };
    if declared_credentials.contains(credential.as_str()) {
        return;
    }
    diagnostics.push(Diagnostic {
        related: Vec::new(),
        span: effect.span,
        message: format!(
            "rule `{}` escalates for undeclared credential `{credential}`",
            rule.name.name
        ),
        suggestion: Some(format!(
            "declare it with `credential {credential} {{ kind bearer }}`; governance supplies \
             the address"
        )),
    });
}

/// A `request` must name a credential it actually presents (DR-0053 §5; the
/// `unmarked` violation in `models/maude/credential-no-eliminator.maude`).
///
/// The custodian refuses at runtime when the slot count it was told disagrees
/// with what it finds; this is the same property decided statically, so a
/// program that could never authenticate fails to build rather than failing on
/// the wire. DR-0042 checks the runtime half at the Worker.
fn validate_http_request(
    rule: &RuleDecl,
    effect: &body::EffectStmt,
    declared_credentials: &BTreeSet<&str>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(request) = http_request_for_body(&effect.kind) else {
        return;
    };
    // Every handle named must be declared. A typo'd handle would otherwise
    // reach the custodian as an unknown credential at egress time.
    for handle in request.credential_handles() {
        if !declared_credentials.contains(handle) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: effect.span,
                message: format!(
                    "rule `{}` presents undeclared credential `{handle}` in a `request`",
                    rule.name.name
                ),
                suggestion: Some(format!(
                    "declare it with `credential {handle} {{ kind bearer }}`"
                )),
            });
        }
    }
    // One `CustodyOp::Request` carries ONE credential's material, so a request
    // naming two is not expressible at the custodian. v1 refuses it here rather
    // than at egress: the sentinel format allows several handles, the operation
    // does not, and the author should learn that from the compiler.
    let distinct: BTreeSet<&str> = request.credential_handles().into_iter().collect();
    if distinct.len() > 1 {
        let mut names: Vec<&str> = distinct.into_iter().collect();
        names.sort_unstable();
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: effect.span,
            message: format!(
                "rule `{}` presents {} credentials in one `request` ({})",
                rule.name.name,
                names.len(),
                names.join(", ")
            ),
            suggestion: Some(
                "a request carries one credential: split it, or present the same handle in \
                 every slot"
                    .to_owned(),
            ),
        });
    }
    // `signed with` canonicalizes the request; it does not put material in a
    // slot. A request that ONLY signs is complete. A request that presents
    // nothing and signs nothing authenticates nothing, and saying so at compile
    // time is cheaper than discovering it against a live endpoint.
    if request.slot_count() == 0 && request.signed_with.is_none() {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: effect.span,
            message: format!(
                "rule `{}` has a `request` that authenticates nothing",
                rule.name.name
            ),
            suggestion: Some(
                "present a credential — `header \"Authorization\" bearer <handle>` — or sign the \
                 request with `signed with <handle>`"
                    .to_owned(),
            ),
        });
    }
}

fn mint_credential_for_body(kind: &body::BodyEffectKind) -> Option<IrMintCredential> {
    let body::BodyEffectKind::MintCredential {
        parent,
        method,
        url,
        headers,
        body,
        token_path,
        public_paths,
    } = kind
    else {
        return None;
    };
    Some(IrMintCredential {
        parent: parent.clone(),
        exchange: IrHttpRequest {
            method: method.clone(),
            url: url.clone(),
            headers: headers
                .iter()
                .map(|header| IrRequestHeader {
                    name: header.name.clone(),
                    value: match &header.value {
                        body::RequestHeaderValue::Credential {
                            presentation,
                            handle,
                        } => IrRequestHeaderValue::Credential {
                            presentation: presentation.as_str().to_owned(),
                            handle: handle.clone(),
                        },
                        body::RequestHeaderValue::Expr { source, .. } => {
                            IrRequestHeaderValue::Expr(source.clone())
                        }
                    },
                })
                .collect(),
            body: body.as_ref().map(|(source, _)| source.clone()),
            // A mint's exchange is never `signed with`: it presents the parent
            // at a marked slot, which is what spending a credential means here.
            signed_with: None,
        },
        token_path: token_path.clone(),
        public_paths: public_paths.clone(),
    })
}

fn http_request_for_body(kind: &body::BodyEffectKind) -> Option<IrHttpRequest> {
    let body::BodyEffectKind::HttpRequest {
        method,
        url,
        headers,
        body,
        signed_with,
    } = kind
    else {
        return None;
    };
    Some(IrHttpRequest {
        method: method.clone(),
        url: url.clone(),
        headers: headers
            .iter()
            .map(|header| IrRequestHeader {
                name: header.name.clone(),
                value: match &header.value {
                    body::RequestHeaderValue::Expr { source, .. } => {
                        IrRequestHeaderValue::Expr(source.clone())
                    }
                    body::RequestHeaderValue::Credential {
                        presentation,
                        handle,
                    } => IrRequestHeaderValue::Credential {
                        presentation: presentation.as_str().to_owned(),
                        handle: handle.clone(),
                    },
                },
            })
            .collect(),
        body: body.as_ref().map(|(source, _)| source.clone()),
        signed_with: signed_with.clone(),
    })
}

fn exec_target_for_body(kind: &body::BodyEffectKind) -> Option<IrExecTarget> {
    match kind {
        body::BodyEffectKind::Exec { target, .. } => Some(match target {
            body::ExecTarget::RawCommand(_) => IrExecTarget::Raw,
            body::ExecTarget::Capability { name, .. } => {
                IrExecTarget::Capability { name: name.clone() }
            }
        }),
        _ => None,
    }
}

/// Whether an effect carries the `endorsed` source marker (I-IFC3) — a `coerce` the
/// author declared an integrity-raising crossing.
fn endorsed_for_body(kind: &body::BodyEffectKind) -> bool {
    matches!(kind, body::BodyEffectKind::Coerce { endorsed: true, .. })
}

/// Whether an effect carries the `declassified` source marker (I-IFC3) — a `coerce`
/// the author declared a confidentiality-lowering crossing.
fn declassified_for_body(kind: &body::BodyEffectKind) -> bool {
    matches!(
        kind,
        body::BodyEffectKind::Coerce {
            declassified: true,
            ..
        }
    )
}

/// The named resource a direct file/channel effect touches, surfaced for
/// information-flow analysis. `None` for effects with no named resource.
fn resource_for_body(
    kind: &body::BodyEffectKind,
    binding_resources: &BTreeMap<String, String>,
) -> Option<String> {
    match kind {
        body::BodyEffectKind::FileRead { store, .. }
        | body::BodyEffectKind::FileWrite { store, .. }
        | body::BodyEffectKind::FileImport { store, .. }
        | body::BodyEffectKind::FileExport { store, .. } => Some(store.clone()),
        // `send via <channel>` carries the channel as a construct field.
        body::BodyEffectKind::ConstructCapabilityCall {
            keyword, fields, ..
        } if keyword == "send" => fields
            .iter()
            .find(|field| field.name == "channel")
            .map(|field| field.source.clone()),
        // `emit signal <name> to <peer>` touches the signal port `signal:<name>` (the
        // emit-port door, DR-0027 E6/H8); surfaced so the IFC checker can carry the
        // emitter's label to the receiver and enumerate the port in the surface.
        body::BodyEffectKind::Notify { event, .. } => Some(format!("signal:{event}")),
        // Coordination is governed as a resource label under E-COORD. The IFC
        // checker decides whether this declaration is partitioned or `shared`.
        body::BodyEffectKind::LeaseAcquire { resource, .. } => Some(format!("resource:{resource}")),
        body::BodyEffectKind::LedgerAppend { ledger, .. } => Some(format!("resource:{ledger}")),
        // DR-0051 §1 gave trackers a READ side — a `when <tracker> has ready
        // issue` trigger keys the bare handle — and never a write side. So an
        // item filed from a rule body reached a durable surface that humans and
        // other agents read, with no sink for the flow checker to weigh it
        // against. Keyed by the bare handle, exactly as the read side and a
        // file store are, so both directions name the same resource.
        body::BodyEffectKind::TrackerFile { queue, .. } => Some(queue.clone()),
        body::BodyEffectKind::CounterConsume { counter, .. } => Some(format!("resource:{counter}")),
        // The four item verbs and `renew` name a BINDING rather than a queue or
        // a lease, so each resolves through the rule's binding map. An
        // unresolvable binding keeps no resource, which is the pre-existing
        // behaviour rather than a guess at which queue was meant.
        body::BodyEffectKind::TrackerClaim { item, .. }
        | body::BodyEffectKind::TrackerRelease { item }
        | body::BodyEffectKind::TrackerFinish { item, .. } => binding_resources.get(item).cloned(),
        // `renew` is one body kind serving two effect kinds: it is a tracker
        // renew when its binding names a claim and a lease renew otherwise, and
        // the binding map already carries whichever it is, because a claim
        // inherits its item's queue.
        body::BodyEffectKind::LeaseRenew {
            acquire_binding, ..
        } => binding_resources.get(acquire_binding).cloned(),
        // An exec ships argv and stdin to a process and reads stdout back. The
        // resource is spelled exactly as `output_tokens_for_root` already
        // spells it, so the two sides of the checker name one thing.
        body::BodyEffectKind::Exec { target, .. } => Some(match target {
            body::ExecTarget::Capability { name, .. } => format!("script:{name}"),
            body::ExecTarget::RawCommand(_) => "exec:raw".to_owned(),
        }),
        // A child workflow is an egress of its payload and a read of its
        // result. `invoke:<name>` is the envelope's own spelling for a workflow
        // endpoint — `is_internal_workflow` already keys it that way.
        body::BodyEffectKind::Invoke { workflow, .. } => Some(format!("invoke:{workflow}")),
        // DR-0053 §5: a `request` leaves the process for an external endpoint
        // under exactly one credential — the checker guarantees the "exactly
        // one". Before this it had no IFC resource at all, so the construct
        // that egresses a URL, headers, and a body to an arbitrary host was
        // invisible to the egress checker.
        //
        // The credential is the sink identity because it is the resource the
        // program DECLARES and the one governance grants by identity
        // (`grant credential … -> credential:<addr>`). It is coarser than the
        // URL — two requests under one credential to different hosts share a
        // sink — and coarse-but-declared is what an envelope can actually
        // grant.
        body::BodyEffectKind::HttpRequest {
            headers,
            signed_with,
            ..
        } => request_credential_handle(headers, signed_with.as_deref()).map(str::to_owned),
        // A mint spends its parent at a token endpoint, which is an egress
        // under that credential like any other. The PARENT is the sink
        // identity — the child does not exist yet, and the checker guarantees
        // the exchange presents exactly the parent.
        body::BodyEffectKind::MintCredential { parent, .. } => Some(parent.clone()),
        _ => None,
    }
}

/// The one credential a `request` authenticates with: the first marked header
/// slot, else `signed with`. `validate_http_request` refuses a request that
/// names none and one that names two, so "first" is "the only one" in any
/// program that compiles.
fn request_credential_handle<'a>(
    headers: &'a [body::RequestHeader],
    signed_with: Option<&'a str>,
) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|header| match &header.value {
            body::RequestHeaderValue::Credential { handle, .. } => Some(handle.as_str()),
            body::RequestHeaderValue::Expr { .. } => None,
        })
        .or(signed_with)
}

fn construct_use_for_body(kind: &body::BodyEffectKind) -> Option<IrConstructUse> {
    match kind {
        body::BodyEffectKind::ConstructCapabilityCall {
            keyword,
            target_capability,
            ..
        } => Some(IrConstructUse {
            keyword: keyword.clone(),
            scope: "rule_body".to_owned(),
            construct_family: "effect_operation".to_owned(),
            lowering_target: "capability_call".to_owned(),
            target_capability: target_capability.clone(),
        }),
        _ => None,
    }
}

fn is_ast_only_effect_kind(kind: &body::BodyEffectKind) -> bool {
    // `send via <channel> { … } as x` closes its `as` on the block line (unlike
    // `recall`, whose `as` is inline), so the line scanner cannot see the binding;
    // seed it from the AST. Other `ConstructCapabilityCall`s (e.g. `recall`) are
    // line-visible and must NOT be treated as AST-only.
    if let body::BodyEffectKind::ConstructCapabilityCall { keyword, .. } = kind {
        return keyword == "send";
    }
    matches!(
        kind,
        body::BodyEffectKind::Prompt { .. }
            | body::BodyEffectKind::Timer { .. }
            | body::BodyEffectKind::Exec { .. }
            // `request … { … } as x` closes its `as` on the block line, the
            // same shape as `send via`, so the line scanner cannot see it.
            | body::BodyEffectKind::HttpRequest { .. }
            // `mint credential from … { … } as x` closes the same way.
            | body::BodyEffectKind::MintCredential { .. }
            | body::BodyEffectKind::Decide { .. }
            | body::BodyEffectKind::TrackerFile { .. }
            | body::BodyEffectKind::ObtainCredential { .. }
            | body::BodyEffectKind::TrackerClaim { .. }
            | body::BodyEffectKind::TrackerRelease { .. }
            | body::BodyEffectKind::TrackerFinish { .. }
            | body::BodyEffectKind::LeaseAcquire { .. }
            | body::BodyEffectKind::LeaseRenew { .. }
            | body::BodyEffectKind::LedgerAppend { .. }
            | body::BodyEffectKind::CounterConsume { .. }
            | body::BodyEffectKind::Notify { .. }
            // `invoke` payload blocks put post-payload modifiers on the closing line
            // in flow-generated rules, so the line scanner may miss `as <binding>`.
            | body::BodyEffectKind::Invoke { .. }
            // `write`/`export` put their `as <binding>` on the block's closing
            // line, so the line-based scanner cannot see it; seed it from the AST
            // so `after <binding>` blocks and sequence checks resolve.
            | body::BodyEffectKind::FileWrite { .. }
            | body::BodyEffectKind::FileExport { .. }
    )
}

/// Bindings introduced by AST-only effect kinds are unknown to the
/// line-based scanner; seed them so sequence checks and `after` blocks see
/// them. Binding types for typed outputs are registered where known.
fn seed_ast_only_effect_bindings(
    statements: &[body::BodyStmt],
    seen_bindings: &mut BTreeSet<String>,
    binding_types: &mut BTreeMap<String, String>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) if is_ast_only_effect_kind(&effect.kind) => {
                if let Some(binding) = &effect.binding {
                    seen_bindings.insert(binding.clone());
                    let _ = binding_types;
                }
            }
            body::BodyStmt::After(after) => {
                seed_ast_only_effect_bindings(&after.body, seen_bindings, binding_types)
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    seed_ast_only_effect_bindings(&branch.body, seen_bindings, binding_types);
                }
            }
            _ => {}
        }
    }
}

/// Derives effect nodes and dependency edges from the body AST, in document
/// order, with ids and idempotency keys identical to the historical
/// line-scanner derivation.
/// Collect the output bindings a rule `complete`s, recursing through the body's
/// nested blocks (after / case / branch / handler). A `complete <binding> {…}` is the
/// workflow's output to its invoker; the IFC checker treats it as an egress sink at
/// the invoker boundary (DR-0030 X2). `fail` terminals are NOT collected —
/// they carry an error to the runtime, not a value to the invoker.
fn collect_terminal_complete_bindings(statements: &[body::BodyStmt], out: &mut Vec<String>) {
    for statement in statements {
        match statement {
            body::BodyStmt::Terminal(terminal) if terminal.kind == body::TerminalKind::Complete => {
                out.push(terminal.name.clone());
            }
            body::BodyStmt::After(after) => collect_terminal_complete_bindings(&after.body, out),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_terminal_complete_bindings(&branch.body, out);
                }
            }
            _ => {}
        }
    }
}

/// Which resource each item/lease binding in a rule refers to.
///
/// The four tracker item verbs and `renew` name a BINDING, not a queue or a
/// lease, so without this they have no IFC resource and their arms in the
/// reader-set match can never fire. Resolving the binding is what gives them
/// one.
///
/// Three sources, and a claim chains through them: a `when <tracker> has ready
/// issue as v` trigger, a `file issue into <q> … as b` in this body, and an
/// `acquire <resource> as b`. A binding from anywhere else stays unresolved and
/// the effect keeps no resource, which is the pre-existing behaviour rather
/// than a guess.
fn binding_resources(
    rule: &RuleDecl,
    statements: &[body::BodyStmt],
    trackers: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut resolved: BTreeMap<String, String> = BTreeMap::new();
    for when in &rule.whens {
        let pattern = when.text.split(" where ").next().unwrap_or(&when.text);
        let words: Vec<&str> = pattern.split_whitespace().collect();
        // `<tracker> has ready issue as <binding>`
        if let ([handle, "has", "ready", "issue"], Some(binding)) =
            (&words[..words.len().min(4)], binding_after_as(pattern))
        {
            if trackers.contains(*handle) {
                resolved.insert(binding.to_owned(), (*handle).to_owned());
            }
        }
    }
    // Two passes so a `claim` naming an item filed later in the same body still
    // resolves; the graph is shallow and this is cheaper than ordering it.
    for _ in 0..2 {
        for_each_body(statements, &mut |stmt| {
            let body::BodyStmt::Effect(effect) = stmt else {
                return;
            };
            let Some(binding) = effect.binding.as_deref() else {
                return;
            };
            let source = match &effect.kind {
                body::BodyEffectKind::TrackerFile { queue, .. } => Some(queue.clone()),
                body::BodyEffectKind::LeaseAcquire { resource, .. } => {
                    Some(format!("resource:{resource}"))
                }
                // A claim carries its item's queue forward, so `renew <claim>`
                // and `finish <claim>` land on the same tracker.
                body::BodyEffectKind::TrackerClaim { item, .. } => resolved.get(item).cloned(),
                _ => None,
            };
            if let Some(source) = source {
                resolved.insert(binding.to_owned(), source);
            }
        });
    }
    resolved
}

fn collect_effects_from_ast(
    statements: &[body::BodyStmt],
    rule_name: &str,
    binding_resources: &BTreeMap<String, String>,
) -> (Vec<IrEffectNode>, Vec<IrEffectDependency>) {
    let mut effects = Vec::new();
    let mut dependencies = Vec::new();
    let mut counter = 0usize;
    let mut after_stack: Vec<(String, DependencyPredicate)> = Vec::new();
    let mut case_stack: Vec<(String, String)> = Vec::new();
    // Renew disambiguation (T3, mirroring the shipped `release` split): a
    // `renew <binding>` whose binding names a same-rule `claim <issue> as
    // <binding>` is a tracker claim-renew (`tracker.renew`); one naming an
    // `acquire ... as <binding>` stays a lease renew (`lease.renew`). Collect
    // the claim `as` bindings up front so the walk can re-classify.
    let claim_bindings = collect_claim_bindings(statements);
    walk_effects(
        statements,
        rule_name,
        &claim_bindings,
        binding_resources,
        &mut counter,
        &mut after_stack,
        &mut case_stack,
        &mut effects,
        &mut dependencies,
    );
    (effects, dependencies)
}

/// The `as` bindings of every `claim <issue> as <binding>` in a rule body — the
/// referent set the renew disambiguation flips `lease.renew` to `tracker.renew`
/// against (the claim result binding, whose output fact carries the issue id).
fn collect_claim_bindings(statements: &[body::BodyStmt]) -> BTreeSet<String> {
    let mut bindings = BTreeSet::new();
    for_each_body(statements, &mut |stmt| {
        if let body::BodyStmt::Effect(effect) = stmt {
            if matches!(effect.kind, body::BodyEffectKind::TrackerClaim { .. }) {
                if let Some(binding) = &effect.binding {
                    bindings.insert(binding.clone());
                }
            }
        }
    });
    bindings
}

#[allow(clippy::too_many_arguments)]
fn walk_effects(
    statements: &[body::BodyStmt],
    rule_name: &str,
    claim_bindings: &BTreeSet<String>,
    binding_resources: &BTreeMap<String, String>,
    counter: &mut usize,
    after_stack: &mut Vec<(String, DependencyPredicate)>,
    case_stack: &mut Vec<(String, String)>,
    effects: &mut Vec<IrEffectNode>,
    dependencies: &mut Vec<IrEffectDependency>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                *counter += 1;
                let id = effect
                    .binding
                    .clone()
                    .unwrap_or_else(|| format!("effect{counter}"));
                // A `renew` naming a claim binding lowers to `tracker.renew`;
                // otherwise it stays the coord `lease.renew` its parser produced.
                let kind = match &effect.kind {
                    body::BodyEffectKind::LeaseRenew {
                        acquire_binding, ..
                    } if claim_bindings.contains(acquire_binding) => IrEffectKind::TrackerRenew,
                    other => ir_effect_kind_for_body(other),
                };
                for (upstream, predicate) in after_stack.iter() {
                    dependencies.push(IrEffectDependency {
                        upstream: upstream.clone(),
                        predicate: predicate.clone(),
                        downstream: id.clone(),
                    });
                }
                let idempotency_key =
                    effect_idempotency_key(rule_name, &id, &kind, &effect.binding);
                let mut required_capabilities = effect.requires.clone();
                match &effect.kind {
                    body::BodyEffectKind::Call { capability, .. } => {
                        required_capabilities.push(capability.clone());
                    }
                    body::BodyEffectKind::ConstructCapabilityCall {
                        target_capability, ..
                    } => {
                        required_capabilities.push(target_capability.clone());
                    }
                    _ => {}
                }
                required_capabilities.sort();
                required_capabilities.dedup();
                let construct_use = construct_use_for_body(&effect.kind);
                let access_grants = ir_access_grants_for_body(&effect.kind);
                let turn_skills = turn_skills_for_body(&effect.kind);
                let on_stream = on_stream_for_body(&effect.kind);
                let (selection_source, transport_onto) = vcs_selective_for_body(&effect.kind);
                let resource = resource_for_body(&effect.kind, binding_resources);
                let agent = agent_for_body(&effect.kind);
                let coerce_target = coerce_target_for_body(&effect.kind);
                let workflow_target = workflow_target_for_body(&effect.kind);
                let endorsed = endorsed_for_body(&effect.kind);
                let declassified = declassified_for_body(&effect.kind);
                let exec_target = exec_target_for_body(&effect.kind);
                let http_request = http_request_for_body(&effect.kind);
                let mint_credential = mint_credential_for_body(&effect.kind);
                effects.push(IrEffectNode {
                    id,
                    kind,
                    binding: effect.binding.clone(),
                    required_capabilities,
                    construct_use,
                    idempotency_key,
                    span: effect.span,
                    timeout_seconds: effect.timeout_seconds,
                    access_grants,
                    turn_skills,
                    on_stream,
                    selection_source,
                    transport_onto,
                    resource,
                    agent,
                    coerce_target,
                    workflow_target,
                    endorsed,
                    declassified,
                    selected_by: case_stack.last().cloned(),
                    exec_target,
                    http_request,
                    mint_credential,
                });
            }
            body::BodyStmt::After(after) => {
                let predicate = match after.predicate {
                    body::AfterPredicate::Succeeds => DependencyPredicate::Succeeds,
                    body::AfterPredicate::Fails => DependencyPredicate::Fails,
                    // `times out` / `cancelled` are distinct non-success terminal
                    // statuses, so the downstream effect releases only on that
                    // specific status (mirroring succeeds/fails), not on any
                    // terminal.
                    body::AfterPredicate::TimedOut => DependencyPredicate::TimedOut,
                    body::AfterPredicate::Cancelled => DependencyPredicate::Cancelled,
                    // Coordination outcomes are completion-valued: the downstream
                    // depends on the op reaching a terminal state; the outcome
                    // variant selects the arm at lowering.
                    body::AfterPredicate::Completes
                    | body::AfterPredicate::Held
                    | body::AfterPredicate::Contended
                    | body::AfterPredicate::Ok
                    | body::AfterPredicate::Over
                    | body::AfterPredicate::Promoted
                    | body::AfterPredicate::Conflicted
                    | body::AfterPredicate::Applied
                    | body::AfterPredicate::Stranded => DependencyPredicate::Completes,
                    // `reaches "<name>"` (Family C) is completion-shaped for the
                    // construct-graph provenance edge; the milestone-specific
                    // gating happens at runtime against the
                    // `workflow.invoke.reached:<name>` fact (text-keyed, see
                    // `fact_matches_after_predicate`), so this IR predicate is
                    // metadata only.
                    body::AfterPredicate::Reaches => DependencyPredicate::Completes,
                };
                after_stack.push((after.binding.clone(), predicate));
                walk_effects(
                    &after.body,
                    rule_name,
                    claim_bindings,
                    binding_resources,
                    counter,
                    after_stack,
                    case_stack,
                    effects,
                    dependencies,
                );
                after_stack.pop();
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    // Record the selector: an effect in this arm is gated by
                    // `case <scrutinee> { <pattern> => … }` (DR §7.4).
                    case_stack.push((case.scrutinee.clone(), branch.pattern.clone()));
                    walk_effects(
                        &branch.body,
                        rule_name,
                        claim_bindings,
                        binding_resources,
                        counter,
                        after_stack,
                        case_stack,
                        effects,
                        dependencies,
                    );
                    case_stack.pop();
                }
            }
            _ => {}
        }
    }
}

fn effect_idempotency_key(
    rule_name: &str,
    effect_id: &str,
    kind: &IrEffectKind,
    binding: &Option<String>,
) -> String {
    stable_hash(&format!(
        "rule={rule_name};effect={effect_id};kind={};binding={}",
        kind.as_str(),
        binding.as_deref().unwrap_or("-")
    ))
}

fn validate_coerce_call(
    rule: &RuleDecl,
    line: &str,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    known_roots: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some((function_name, args)) = parse_coerce_call(line) else {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!("rule `{}` has malformed coerce call", rule.name.name),
            suggestion: Some("write `coerce functionName(arg, ...) as name`".to_owned()),
        });
        return;
    };
    let Some(params) = semantic.coerce_params.get(function_name) else {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!(
                "rule `{}` calls unknown coerce function `{function_name}`",
                rule.name.name
            ),
            suggestion: Some(format!(
                "declare `coerce {function_name}(...) -> Output {{ ... }}` before using it"
            )),
        });
        return;
    };
    if args.len() != params.len() {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!(
                "rule `{}` calls coerce `{function_name}` with {} argument(s), expected {}",
                rule.name.name,
                args.len(),
                params.len()
            ),
            suggestion: Some("pass one argument for each declared coerce parameter".to_owned()),
        });
        return;
    }
    let scope = ExprScope::from_bindings(binding_types);
    for (arg, param) in args.iter().zip(params) {
        // Dangling-root check (mirrors record/terminal value validation): an arg
        // whose root is not a known binding is a typo/unbound reference, which the
        // type-checker below accepts leniently.
        if let Some(root) = dangling_value_root(arg, known_roots) {
            diagnostics.push(Diagnostic { related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` has unknown binding `{root}` in coerce `{function_name}` argument",
                    rule.name.name
                ),
                suggestion: Some(
                    "reference a binding from a `when ... as name` clause, an effect `as` binding, or a `case` pattern"
                        .to_owned(),
                ),
            });
        }
        validate_expr_source_against_type(
            rule,
            &format!("coerce `{function_name}`"),
            &param.name.name,
            &param.ty,
            arg,
            semantic,
            &scope,
            diagnostics,
        );
    }
}

fn validate_effect_payloads(
    rule: &RuleDecl,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    known_roots: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in effect_payload_statements(&rule.body.text) {
        let trimmed = statement.trim();
        if trimmed.starts_with("coerce ") {
            validate_coerce_call(
                rule,
                trimmed,
                semantic,
                binding_types,
                known_roots,
                diagnostics,
            );
        }
    }
}

fn validate_workflow_invocations(
    rule: &RuleDecl,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    known_roots: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in workflow_invoke_statements(&rule.body.text) {
        let Some((target, body)) = invoke_statement_parts(&statement) else {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` has malformed workflow invocation",
                    rule.name.name
                ),
                suggestion: Some("write `invoke Workflow { input value } as binding`".to_owned()),
            });
            continue;
        };
        if semantic.workflow.as_deref() == Some(target) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` recursively invokes workflow `{target}`",
                    rule.name.name
                ),
                suggestion: Some(
                    "split recursive orchestration into an explicit bounded scheduler workflow"
                        .to_owned(),
                ),
            });
            continue;
        }
        let Some(surface) = semantic.workflow_inputs.get(target) else {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` invokes unknown workflow `{target}`",
                    rule.name.name
                ),
                suggestion: Some("invoke a workflow declared in this source bundle".to_owned()),
            });
            continue;
        };

        let mut invocation_semantic = semantic.clone();
        invocation_semantic.schemas.merge(surface.schemas.clone());
        let assignments = collect_field_assignments(body);
        let mut seen = BTreeSet::new();
        for assignment in assignments {
            let (field, value) = match assignment {
                RecordFieldAssignment::Value { field, value } => (field, value),
                RecordFieldAssignment::Shorthand { field } => (field.clone(), field),
            };
            if !seen.insert(field.clone()) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: rule.body.span,
                    message: format!("workflow invocation `{target}` repeats input `{field}`"),
                    suggestion: Some("remove the duplicate invocation input".to_owned()),
                });
                continue;
            }
            let Some(input_ty) = surface.inputs.get(&field) else {
                let known = surface
                    .inputs
                    .keys()
                    .map(|input| format!("`{input}`"))
                    .collect::<Vec<_>>()
                    .join(", ");
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: rule.body.span,
                    message: format!("workflow `{target}` has no input `{field}`"),
                    suggestion: Some(if known.is_empty() {
                        "remove the invocation payload; the target declares no inputs".to_owned()
                    } else {
                        format!("pass one of: {known}")
                    }),
                });
                continue;
            };
            if let Some(root) = dangling_value_root(&value, known_roots) {
                diagnostics.push(Diagnostic { related: Vec::new(),
                    span: rule.body.span,
                    message: format!(
                        "rule `{}` has unknown binding `{root}` in `invoke {target}` input `{field}`",
                        rule.name.name
                    ),
                    suggestion: Some(
                        "reference a binding from a `when ... as name` clause, an effect `as` binding, or a `case` pattern"
                            .to_owned(),
                    ),
                });
            }
            validate_expr_source_against_type(
                rule,
                target,
                &field,
                input_ty,
                &value,
                &invocation_semantic,
                &ExprScope::from_bindings(binding_types),
                diagnostics,
            );
        }
        for input in surface.inputs.keys() {
            if seen.contains(input) {
                continue;
            }
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!("workflow invocation `{target}` is missing input `{input}`"),
                suggestion: Some(format!(
                    "add `{input}` to the `{target}` invocation payload"
                )),
            });
        }
    }
}

fn validate_agent_tell_target(
    rule: &RuleDecl,
    line: &str,
    kind: &IrEffectKind,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    known_roots: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if kind != &IrEffectKind::AgentTell {
        return;
    }
    let Some(target) = parse_tell_target(line) else {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!("rule `{}` has malformed tell target", rule.name.name),
            suggestion: Some("write `tell agentName ...` or `tell task.agentRef ...`".to_owned()),
        });
        return;
    };
    if target.starts_with('"') {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!(
                "rule `{}` uses a string literal as a tell target",
                rule.name.name
            ),
            suggestion: Some("use a declared agent name or an AgentRef field".to_owned()),
        });
        return;
    }
    let required_capabilities = parse_required_capabilities(line);
    if target.contains('.') {
        let Some(ty) = expression_type(target, semantic, binding_types) else {
            // Unknown type can mean a dangling root (the path's binding does not
            // exist) — caught here since the type lookup returns None silently. A
            // known root with a bad path is left to other validation.
            if let Some(root) = dangling_value_root(target, known_roots) {
                diagnostics.push(Diagnostic { related: Vec::new(),
                    span: rule.body.span,
                    message: format!(
                        "rule `{}` has unknown binding `{root}` in tell target `{target}`",
                        rule.name.name
                    ),
                    suggestion: Some(
                        "reference a binding from a `when ... as name` clause or an effect `as` binding"
                            .to_owned(),
                    ),
                });
            }
            return;
        };
        if let TypeSyntax::AgentRef { agents, .. } = ty {
            for agent in agents {
                validate_agent_capabilities(
                    rule,
                    &agent.name,
                    &required_capabilities,
                    semantic,
                    diagnostics,
                );
            }
        } else {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` uses non-AgentRef dynamic tell target `{target}`",
                    rule.name.name
                ),
                suggestion: Some(
                    "declare the field as `AgentRef<...>` before using it as a tell target"
                        .to_owned(),
                ),
            });
        }
        return;
    }
    if !semantic.agents.contains(target) {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!("rule `{}` tells unknown agent `{target}`", rule.name.name),
            suggestion: Some("declare the target agent before telling it".to_owned()),
        });
        return;
    }
    validate_agent_capabilities(rule, target, &required_capabilities, semantic, diagnostics);
}

fn validate_agent_capabilities(
    rule: &RuleDecl,
    agent: &str,
    required_capabilities: &[String],
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if required_capabilities.is_empty() {
        return;
    }
    let declared = semantic
        .agent_capabilities
        .get(agent)
        .cloned()
        .unwrap_or_default();
    for capability in required_capabilities {
        if !declared.contains(capability) {
            diagnostics.push(Diagnostic { related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` tells agent `{agent}` requiring undeclared capability `{capability}`",
                    rule.name.name
                ),
                suggestion: Some(format!(
                    "add `{capability}` to agent `{agent}` capabilities or choose another AgentRef target"
                )),
            });
        }
    }
}

fn validate_availability_when(
    rule: &RuleDecl,
    when: &str,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let (pattern, _) = split_when_guard(when);
    let Some(target) = pattern.strip_suffix(" is available").map(str::trim) else {
        return;
    };
    if target.contains('.') {
        let Some(ty) = expression_type(target, semantic, binding_types) else {
            return;
        };
        if !matches!(ty, TypeSyntax::AgentRef { .. }) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` checks availability for non-AgentRef `{target}`",
                    rule.name.name
                ),
                suggestion: Some(
                    "availability checks must name a declared agent or an AgentRef field"
                        .to_owned(),
                ),
            });
        }
        return;
    }
    if !semantic.agents.contains(target) {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!("rule `{}` checks unknown agent `{target}`", rule.name.name),
            suggestion: Some("declare the target agent before checking availability".to_owned()),
        });
    }
}

#[derive(Clone, Debug, Default)]
struct ExprScope {
    binding_types: BTreeMap<String, String>,
    implicit_schema: Option<String>,
}

impl ExprScope {
    fn from_bindings(binding_types: &BTreeMap<String, String>) -> Self {
        Self {
            binding_types: binding_types.clone(),
            implicit_schema: None,
        }
    }

    fn with_implicit_schema(&self, schema: String) -> Self {
        let mut scope = self.clone();
        scope.implicit_schema = Some(schema);
        scope
    }
}

#[derive(Clone, Debug)]
struct ExprValidationContext {
    subject: String,
    span: SourceSpan,
}

impl ExprValidationContext {
    fn rule(rule: &RuleDecl) -> Self {
        Self {
            subject: format!("rule `{}`", rule.name.name),
            span: rule.body.span,
        }
    }

    fn assertion(span: SourceSpan) -> Self {
        Self {
            subject: "assertion".to_owned(),
            span,
        }
    }
}

fn validate_expression(
    rule: &RuleDecl,
    expr: &str,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    label: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match parse_expression(expr) {
        Ok(expr) => {
            validate_parsed_expression(
                &expr,
                semantic,
                &ExprScope::from_bindings(binding_types),
                &ExprValidationContext::rule(rule),
                label,
                diagnostics,
            );
        }
        Err(message) => diagnostics.push(Diagnostic { related: Vec::new(),
            span: rule.body.span,
            message: format!("rule `{}` has invalid {label} expression: {message}", rule.name.name),
            suggestion: Some("use deterministic field paths, literals, boolean operators, comparisons, membership, count, or exists".to_owned()),
        }),
    }
}

fn validate_parsed_expression(
    expr: &Expr,
    semantic: &SemanticContext,
    scope: &ExprScope,
    context: &ExprValidationContext,
    label: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let presence_proofs = BTreeSet::new();
    validate_expr_node(
        expr,
        semantic,
        scope,
        context,
        &presence_proofs,
        diagnostics,
    );
    let ty = infer_expr_type(expr, semantic, scope, context, diagnostics);
    if ty != ExprType::Bool && ty != ExprType::Unknown {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: context.span,
            message: format!("{} has non-boolean {label} expression", context.subject),
            suggestion: Some(format!("{label} expressions must evaluate to bool")),
        });
    }
}

fn validate_expr_node(
    expr: &Expr,
    semantic: &SemanticContext,
    scope: &ExprScope,
    context: &ExprValidationContext,
    presence_proofs: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match expr {
        Expr::Path(path) => {
            if path.len() < 2 {
                return;
            }
            let root = &path[0];
            let Some(schema) = scope.binding_types.get(root) else {
                if let Some(schema) = &scope.implicit_schema {
                    if let Err(message) =
                        validate_optional_path_access(schema, path, semantic, presence_proofs)
                    {
                        diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: context.span,
                            message: format!(
                                "{} has unsafe optional path `{}`: {message}",
                                context.subject,
                                path.join(".")
                            ),
                            suggestion: Some(
                                "prove the optional value is present before reading through it"
                                    .to_owned(),
                            ),
                        });
                        return;
                    }
                    if let Err(message) = semantic.schemas.resolve_field_path(schema, path) {
                        diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: context.span,
                            message: format!(
                                "{} has invalid expression path `{}`: {message}",
                                context.subject,
                                path.join(".")
                            ),
                            suggestion: Some(
                                "use a field declared on the queried schema".to_owned(),
                            ),
                        });
                    }
                    return;
                }
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!("{} has unknown expression root `{root}`", context.subject),
                    suggestion: Some(
                        "use a binding introduced by a `when ... as name` clause".to_owned(),
                    ),
                });
                return;
            };
            if let Err(message) =
                validate_optional_path_access(schema, &path[1..], semantic, presence_proofs)
            {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} has unsafe optional path `{}`: {message}",
                        context.subject,
                        path.join(".")
                    ),
                    suggestion: Some(
                        "prove the optional value is present before reading through it".to_owned(),
                    ),
                });
                return;
            }
            if let Err(message) = semantic.schemas.resolve_field_path(schema, &path[1..]) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} has invalid expression path `{}`: {message}",
                        context.subject,
                        path.join(".")
                    ),
                    suggestion: Some("use a field declared on the bound schema".to_owned()),
                });
            }
        }
        Expr::Index { target, key } => {
            validate_expr_node(
                target,
                semantic,
                scope,
                context,
                presence_proofs,
                diagnostics,
            );
            validate_expr_node(key, semantic, scope, context, presence_proofs, diagnostics);
            let key_ty = infer_expr_type(key, semantic, scope, context, diagnostics);
            if !matches!(key_ty, ExprType::String | ExprType::Unknown) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!("{} indexes a map with a non-string key", context.subject),
                    suggestion: Some(
                        "use a string literal or string expression as the map key".to_owned(),
                    ),
                });
            }
        }
        Expr::Array(items) => {
            for item in items {
                validate_expr_node(item, semantic, scope, context, presence_proofs, diagnostics);
            }
        }
        Expr::Object(fields) => {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: context.span,
                message: format!(
                    "{} uses an object literal without an expected object or map type",
                    context.subject
                ),
                suggestion: Some(
                    "use object literals only in typed record fields or typed effect arguments"
                        .to_owned(),
                ),
            });
            for field in fields {
                validate_expr_node(
                    &field.value,
                    semantic,
                    scope,
                    context,
                    presence_proofs,
                    diagnostics,
                );
            }
        }
        Expr::Unary { expr, .. } => {
            validate_expr_node(expr, semantic, scope, context, presence_proofs, diagnostics)
        }
        Expr::Binary {
            op: BinaryOp::And,
            left,
            right,
        } => {
            validate_expr_node(left, semantic, scope, context, presence_proofs, diagnostics);
            let mut right_proofs = presence_proofs.clone();
            collect_presence_proofs(left, &mut right_proofs);
            validate_expr_node(right, semantic, scope, context, &right_proofs, diagnostics);
        }
        Expr::Binary { op, left, right } => {
            validate_expr_node(left, semantic, scope, context, presence_proofs, diagnostics);
            validate_expr_node(
                right,
                semantic,
                scope,
                context,
                presence_proofs,
                diagnostics,
            );
            validate_unknown_implicit_idents(
                *op,
                left,
                right,
                semantic,
                scope,
                context,
                diagnostics,
            );
            validate_finite_domain_expr(*op, left, right, semantic, scope, context, diagnostics);
        }
        Expr::Call { name, args } => {
            validate_function_call(name, args, semantic, scope, context, diagnostics);
            for arg in args {
                validate_expr_node(arg, semantic, scope, context, presence_proofs, diagnostics);
            }
        }
        Expr::Query { guard, .. } => {
            validate_query_expr(expr, semantic, scope, context, diagnostics);
            if let Some(guard) = guard {
                let guard_scope = query_guard_scope(expr, semantic, scope);
                validate_expr_node(
                    guard,
                    semantic,
                    &guard_scope,
                    context,
                    presence_proofs,
                    diagnostics,
                );
            }
        }
        Expr::Literal(_) => {}
    }
}

fn validate_unknown_implicit_idents(
    op: BinaryOp,
    left: &Expr,
    right: &Expr,
    semantic: &SemanticContext,
    scope: &ExprScope,
    context: &ExprValidationContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !matches!(
        op,
        BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge
    ) {
        return;
    }
    validate_unknown_implicit_ident(left, right, semantic, scope, context, diagnostics);
    validate_unknown_implicit_ident(right, left, semantic, scope, context, diagnostics);
}

fn validate_unknown_implicit_ident(
    expr: &Expr,
    other: &Expr,
    semantic: &SemanticContext,
    scope: &ExprScope,
    context: &ExprValidationContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Expr::Literal(ExprLiteral::Ident(name)) = expr else {
        return;
    };
    let Some(schema) = &scope.implicit_schema else {
        return;
    };
    let field_exists = semantic
        .schemas
        .classes
        .get(schema)
        .is_some_and(|fields| fields.contains_key(name));
    if field_exists
        || expr_domain(other, semantic, scope).is_some()
        || implicit_ident_field_exists(other, semantic, scope)
    {
        return;
    }
    diagnostics.push(Diagnostic {
        related: Vec::new(),
        span: context.span,
        message: format!(
            "{} fact query `{schema}` has unknown field `{name}`",
            context.subject
        ),
        suggestion: Some(format!(
            "use a field declared on `{schema}` inside the query `where` expression"
        )),
    });
}

fn implicit_ident_field_exists(expr: &Expr, semantic: &SemanticContext, scope: &ExprScope) -> bool {
    let Expr::Literal(ExprLiteral::Ident(name)) = expr else {
        return false;
    };
    let Some(schema) = &scope.implicit_schema else {
        return false;
    };
    semantic
        .schemas
        .classes
        .get(schema)
        .is_some_and(|fields| fields.contains_key(name))
}

fn validate_function_call(
    name: &str,
    args: &[Expr],
    semantic: &SemanticContext,
    scope: &ExprScope,
    context: &ExprValidationContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match name {
        "count" => {
            if args.len() != 1 {
                diagnostics.push(Diagnostic { related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} calls `count` with {} arguments, expected 1",
                        context.subject,
                        args.len()
                    ),
                    suggestion: Some(
                        "call `count` with exactly one array, map, fact query, or effect query argument"
                            .to_owned(),
                    ),
                });
                return;
            }
            let ty = infer_expr_type(&args[0], semantic, scope, context, diagnostics);
            if !is_countable_type(&ty) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} calls `count` with unsupported argument type `{}`",
                        context.subject,
                        expr_type_label(&ty)
                    ),
                    suggestion: Some(
                        "use `count` only with arrays, maps, fact queries, or effect queries"
                            .to_owned(),
                    ),
                });
            }
        }
        "exists" => {
            if args.len() != 1 {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} calls `exists` with {} arguments, expected 1",
                        context.subject,
                        args.len()
                    ),
                    suggestion: Some("call `exists` with exactly one argument".to_owned()),
                });
                return;
            }
            let ty = infer_expr_type(&args[0], semantic, scope, context, diagnostics);
            if !matches!(args[0], Expr::Index { .. }) && !is_exists_type(&ty) {
                diagnostics.push(Diagnostic { related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} calls `exists` with unsupported argument type `{}`",
                        context.subject,
                        expr_type_label(&ty)
                    ),
                    suggestion: Some(
                        "use `exists path` for optional/map presence checks or pass an array, map, fact query, or effect query"
                            .to_owned(),
                    ),
                });
            }
        }
        "empty" => {
            if args.len() != 1 {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} calls `empty` with {} arguments, expected 1",
                        context.subject,
                        args.len()
                    ),
                    suggestion: Some(
                        "call `empty` with exactly one array, map, string, fact query, or effect query argument"
                            .to_owned(),
                    ),
                });
                return;
            }
            let ty = infer_expr_type(&args[0], semantic, scope, context, diagnostics);
            if !is_emptiable_type(&ty) {
                // An optional gets its own message: the inner type is what
                // makes it unsupported (spec: `empty(Optional<T>)` is defined
                // only when `empty(T)` is).
                let optional = matches!(ty, ExprType::Optional(_));
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} calls `empty` with unsupported {}argument type `{}`",
                        context.subject,
                        if optional { "optional " } else { "" },
                        expr_type_label(&ty)
                    ),
                    suggestion: Some(
                        "use `empty` only with arrays, maps, strings, fact queries, effect queries, null, or supported optional values"
                            .to_owned(),
                    ),
                });
            }
        }
        _ => {}
    }
}

fn validate_query_expr(
    expr: &Expr,
    semantic: &SemanticContext,
    scope: &ExprScope,
    context: &ExprValidationContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Expr::Query { kind, head, guard } = expr else {
        return;
    };
    if *kind == QueryKind::Fact {
        let Some(schema) = query_head_schema(head, semantic) else {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: context.span,
                message: format!(
                    "{} queries unknown fact schema `{}`",
                    context.subject,
                    head.trim()
                ),
                suggestion: Some("use a declared class name in fact queries".to_owned()),
            });
            return;
        };
        if let Some(guard) = guard {
            let guard_scope = scope.with_implicit_schema(schema);
            let ty = infer_expr_type(guard, semantic, &guard_scope, context, diagnostics);
            if !matches!(ty, ExprType::Bool | ExprType::Unknown) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} fact query `{}` has non-boolean `where` expression",
                        context.subject,
                        head.trim()
                    ),
                    suggestion: Some("query `where` expressions must evaluate to bool".to_owned()),
                });
            }
        }
    }
}

fn validate_optional_path_access(
    root_schema: &str,
    path: &[String],
    semantic: &SemanticContext,
    presence_proofs: &BTreeSet<String>,
) -> Result<(), String> {
    let mut schema = root_schema.to_owned();
    let mut prefix = Vec::new();
    for (index, field) in path.iter().enumerate() {
        let Some(fields) = semantic.schemas.classes.get(&schema) else {
            return Ok(());
        };
        let Some(field_ty) = fields.get(field) else {
            return Ok(());
        };
        prefix.push(field.clone());
        if let TypeSyntax::Optional { inner, .. } = field_ty {
            if index + 1 < path.len() && !presence_proofs.contains(&prefix.join(".")) {
                return Err(format!(
                    "`{}` must be proven present before accessing `{}`",
                    prefix.join("."),
                    path[index + 1..].join(".")
                ));
            }
            if let Some(next_schema) = schema_name_for_path(inner) {
                schema = next_schema;
            }
            continue;
        }
        if let Some(next_schema) = schema_name_for_path(field_ty) {
            schema = next_schema;
        }
    }
    Ok(())
}

fn collect_presence_proofs(expr: &Expr, proofs: &mut BTreeSet<String>) {
    match expr {
        Expr::Binary {
            op: BinaryOp::Ne,
            left,
            right,
        } => {
            if matches!(**right, Expr::Literal(ExprLiteral::Null)) {
                if let Some(path) = expr_path_key(left) {
                    proofs.insert(path);
                }
            }
            if matches!(**left, Expr::Literal(ExprLiteral::Null)) {
                if let Some(path) = expr_path_key(right) {
                    proofs.insert(path);
                }
            }
        }
        Expr::Unary {
            op: UnaryOp::Not,
            expr,
        } => {
            if let Expr::Binary {
                op: BinaryOp::Eq,
                left,
                right,
            } = expr.as_ref()
            {
                if matches!(**right, Expr::Literal(ExprLiteral::Null)) {
                    if let Some(path) = expr_path_key(left) {
                        proofs.insert(path);
                    }
                }
                if matches!(**left, Expr::Literal(ExprLiteral::Null)) {
                    if let Some(path) = expr_path_key(right) {
                        proofs.insert(path);
                    }
                }
            }
        }
        Expr::Call { name, args } if name == "exists" && args.len() == 1 => {
            if let Some(path) = expr_path_key(&args[0]) {
                proofs.insert(path);
            }
        }
        Expr::Binary {
            op: BinaryOp::And,
            left,
            right,
        } => {
            collect_presence_proofs(left, proofs);
            collect_presence_proofs(right, proofs);
        }
        _ => {}
    }
}

fn expr_path_key(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Literal(ExprLiteral::Ident(name)) => Some(name.clone()),
        Expr::Path(path) if path.len() >= 2 => Some(path[1..].join(".")),
        Expr::Index { target, key } => {
            let target = expr_path_key(target)?;
            let key = match key.as_ref() {
                Expr::Literal(ExprLiteral::String(value) | ExprLiteral::Ident(value)) => value,
                _ => return None,
            };
            Some(format!("{target}[{key:?}]"))
        }
        _ => None,
    }
}

fn query_guard_scope(expr: &Expr, semantic: &SemanticContext, scope: &ExprScope) -> ExprScope {
    let Expr::Query {
        kind: QueryKind::Fact,
        head,
        ..
    } = expr
    else {
        return scope.clone();
    };
    query_head_schema(head, semantic)
        .map(|schema| scope.with_implicit_schema(schema))
        .unwrap_or_else(|| scope.clone())
}

fn query_head_schema(head: &str, semantic: &SemanticContext) -> Option<String> {
    let mut parts = head.split_whitespace();
    let schema = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    semantic
        .schemas
        .class_exists(schema)
        .then(|| schema.to_owned())
}

fn implicit_field_type(
    name: &str,
    semantic: &SemanticContext,
    scope: &ExprScope,
) -> Option<TypeSyntax> {
    let schema = scope.implicit_schema.as_ref()?;
    semantic
        .schemas
        .resolve_field_path(schema, &[name.to_owned()])
        .ok()
}

fn infer_expr_type(
    expr: &Expr,
    semantic: &SemanticContext,
    scope: &ExprScope,
    context: &ExprValidationContext,
    diagnostics: &mut Vec<Diagnostic>,
) -> ExprType {
    match expr {
        Expr::Literal(ExprLiteral::Ident(name)) => implicit_field_type(name, semantic, scope)
            .map(|ty| expr_type_from_type_syntax(&ty, semantic))
            .unwrap_or_else(|| expr_literal_type(&ExprLiteral::Ident(name.clone()))),
        Expr::Literal(literal) => expr_literal_type(literal),
        Expr::Path(path) => expr_path_type(path, semantic, scope).unwrap_or(ExprType::Unknown),
        Expr::Index { target, key } => {
            let target_ty = infer_expr_type(target, semantic, scope, context, diagnostics);
            let key_ty = infer_expr_type(key, semantic, scope, context, diagnostics);
            if !matches!(key_ty, ExprType::String | ExprType::Unknown) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!("{} indexes a map with a non-string key", context.subject),
                    suggestion: Some(
                        "use a string literal or string expression as the map key".to_owned(),
                    ),
                });
            }
            match target_ty {
                ExprType::Map(inner) => *inner,
                ExprType::Unknown => ExprType::Unknown,
                _ => {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: context.span,
                        message: format!("{} indexes a non-map expression", context.subject),
                        suggestion: Some("use indexing only on map values".to_owned()),
                    });
                    ExprType::Unknown
                }
            }
        }
        Expr::Array(items) => infer_array_type(items, semantic, scope, context, diagnostics),
        Expr::Object(fields) => {
            for field in fields {
                infer_expr_type(&field.value, semantic, scope, context, diagnostics);
            }
            ExprType::Object
        }
        Expr::Unary {
            op: UnaryOp::Not,
            expr,
        } => {
            let inner = infer_expr_type(expr, semantic, scope, context, diagnostics);
            if !matches!(inner, ExprType::Bool | ExprType::Unknown) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} applies `!` to a non-boolean expression",
                        context.subject
                    ),
                    suggestion: Some("use `!` only with boolean expressions".to_owned()),
                });
            }
            ExprType::Bool
        }
        Expr::Binary { op, left, right } => {
            infer_binary_type(*op, left, right, semantic, scope, context, diagnostics)
        }
        Expr::Call { name, args } => match name.as_str() {
            "count" => ExprType::Int,
            "exists" => ExprType::Bool,
            "empty" => ExprType::Bool,
            _ => {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} calls unsupported expression function `{name}`",
                        context.subject
                    ),
                    suggestion: Some("use `count`, `exists`, or `empty`".to_owned()),
                });
                for arg in args {
                    infer_expr_type(arg, semantic, scope, context, diagnostics);
                }
                ExprType::Unknown
            }
        },
        Expr::Query { guard, .. } => {
            if let Some(guard) = guard {
                let guard_scope = query_guard_scope(expr, semantic, scope);
                infer_expr_type(guard, semantic, &guard_scope, context, diagnostics);
            }
            ExprType::Collection
        }
    }
}

fn infer_binary_type(
    op: BinaryOp,
    left: &Expr,
    right: &Expr,
    semantic: &SemanticContext,
    scope: &ExprScope,
    context: &ExprValidationContext,
    diagnostics: &mut Vec<Diagnostic>,
) -> ExprType {
    let left_ty = infer_expr_type(left, semantic, scope, context, diagnostics);
    let right_ty = infer_expr_type(right, semantic, scope, context, diagnostics);
    match op {
        BinaryOp::And | BinaryOp::Or => {
            for ty in [&left_ty, &right_ty] {
                if !matches!(ty, ExprType::Bool | ExprType::Unknown) {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: context.span,
                        message: format!(
                            "{} uses boolean operator with non-boolean operand",
                            context.subject
                        ),
                        suggestion: Some(
                            "use `&&` and `||` only with boolean expressions".to_owned(),
                        ),
                    });
                    break;
                }
            }
            ExprType::Bool
        }
        BinaryOp::Eq | BinaryOp::Ne => {
            if !types_comparable(&left_ty, &right_ty) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!("{} compares incompatible expression types", context.subject),
                    suggestion: Some(
                        "compare values with compatible scalar or finite-domain types".to_owned(),
                    ),
                });
            }
            ExprType::Bool
        }
        BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
            if !is_orderable_pair(&left_ty, &right_ty) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!("{} orders non-orderable expression values", context.subject),
                    suggestion: Some(
                        "use ordering only with int, float, duration, or time values".to_owned(),
                    ),
                });
            }
            ExprType::Bool
        }
        BinaryOp::In | BinaryOp::NotIn => {
            match &right_ty {
                ExprType::Array(item_ty) => {
                    if !types_comparable(&left_ty, item_ty) {
                        diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: context.span,
                            message: format!(
                                "{} uses membership with incompatible item type",
                                context.subject
                            ),
                            suggestion: Some(
                                "make the left value compatible with the array item type"
                                    .to_owned(),
                            ),
                        });
                    }
                }
                ExprType::Map(_) => {
                    if !is_string_like_key_type(&left_ty) {
                        diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: context.span,
                            message: format!(
                                "{} uses map membership with a non-string key",
                                context.subject
                            ),
                            suggestion: Some(
                                "use a string value on the left side of map membership".to_owned(),
                            ),
                        });
                    }
                }
                ExprType::Unknown => {}
                _ => diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} uses membership against a non-array/non-map expression",
                        context.subject
                    ),
                    suggestion: Some(
                        "use `in` with an array literal, array value, or map value".to_owned(),
                    ),
                }),
            }
            ExprType::Bool
        }
        BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div => {
            for ty in [&left_ty, &right_ty] {
                if !matches!(ty, ExprType::Int | ExprType::Float | ExprType::Unknown) {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: context.span,
                        message: format!(
                            "{} uses arithmetic with a non-numeric operand",
                            context.subject
                        ),
                        suggestion: Some("use `+ - * /` only with int or float values".to_owned()),
                    });
                    break;
                }
            }
            if matches!(left_ty, ExprType::Float) || matches!(right_ty, ExprType::Float) {
                ExprType::Float
            } else if matches!(left_ty, ExprType::Int) && matches!(right_ty, ExprType::Int) {
                ExprType::Int
            } else {
                ExprType::Unknown
            }
        }
    }
}

fn infer_array_type(
    items: &[Expr],
    semantic: &SemanticContext,
    scope: &ExprScope,
    context: &ExprValidationContext,
    diagnostics: &mut Vec<Diagnostic>,
) -> ExprType {
    let mut item_ty: Option<ExprType> = None;
    for item in items {
        let ty = infer_expr_type(item, semantic, scope, context, diagnostics);
        if matches!(ty, ExprType::Unknown) {
            continue;
        }
        match &item_ty {
            None => item_ty = Some(ty),
            Some(existing) if types_comparable(existing, &ty) => {}
            Some(_) => {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!("{} has mixed-type array literal", context.subject),
                    suggestion: Some("use array literals whose elements share one type".to_owned()),
                });
                return ExprType::Array(Box::new(ExprType::Unknown));
            }
        }
    }
    ExprType::Array(Box::new(item_ty.unwrap_or(ExprType::Unknown)))
}

fn expr_path_type(
    path: &[String],
    semantic: &SemanticContext,
    scope: &ExprScope,
) -> Option<ExprType> {
    if path.len() < 2 {
        return None;
    }
    if let Some(schema) = scope.binding_types.get(&path[0]) {
        if schema.contains('.') {
            // Untyped runtime fact binding (general `when fact <name>`).
            return Some(ExprType::Unknown);
        }
        return semantic
            .schemas
            .resolve_field_path(schema, &path[1..])
            .ok()
            .map(|ty| expr_type_from_type_syntax(&ty, semantic));
    }
    let schema = scope.implicit_schema.as_ref()?;
    if schema.contains('.') {
        return Some(ExprType::Unknown);
    }
    semantic
        .schemas
        .resolve_field_path(schema, path)
        .ok()
        .map(|ty| expr_type_from_type_syntax(&ty, semantic))
}

fn expr_type_from_type_syntax(ty: &TypeSyntax, semantic: &SemanticContext) -> ExprType {
    match ty {
        TypeSyntax::Primitive { name, .. } => match name.as_str() {
            "bool" => ExprType::Bool,
            "int" => ExprType::Int,
            "float" => ExprType::Float,
            "string" => ExprType::String,
            "duration" => ExprType::Duration,
            "time" => ExprType::Time,
            _ => ExprType::Unknown,
        },
        TypeSyntax::Secret { kind, .. } => ExprType::Secret(kind.as_ref().and_then(|kind| {
            // An unknown kind is reported by `validate_secret_kinds`; here it
            // widens to the bare form rather than cascading a second error on
            // every use of the binding.
            whipplescript_custody::CredentialKind::parse(&kind.name.replace('_', "-")).ok()
        })),
        TypeSyntax::LiteralString { value, .. } => ExprType::Finite {
            label: "literal".to_owned(),
            values: vec![value.clone()],
        },
        TypeSyntax::AgentRef { agents, .. } => ExprType::Finite {
            label: "AgentRef".to_owned(),
            values: agents.iter().map(|agent| agent.name.clone()).collect(),
        },
        TypeSyntax::Ref { name } => semantic
            .schemas
            .enums
            .get(&name.name)
            .map(|variants| ExprType::Finite {
                label: format!("enum `{}`", name.name),
                values: variants.iter().cloned().collect(),
            })
            .unwrap_or(ExprType::Object),
        TypeSyntax::Optional { inner, .. } => {
            ExprType::Optional(Box::new(expr_type_from_type_syntax(inner, semantic)))
        }
        TypeSyntax::Array { inner, .. } => {
            ExprType::Array(Box::new(expr_type_from_type_syntax(inner, semantic)))
        }
        TypeSyntax::Sealed { inner, .. } => {
            ExprType::Sealed(Box::new(expr_type_from_type_syntax(inner, semantic)))
        }
        TypeSyntax::Map { inner, .. } => {
            ExprType::Map(Box::new(expr_type_from_type_syntax(inner, semantic)))
        }
        TypeSyntax::Union { variants, .. } => {
            let values = variants
                .iter()
                .filter_map(|variant| match variant {
                    TypeSyntax::LiteralString { value, .. } => Some(value.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if values.len() == variants.len() && !values.is_empty() {
                ExprType::Finite {
                    label: "literal union".to_owned(),
                    values,
                }
            } else {
                ExprType::Unknown
            }
        }
    }
}

fn expr_literal_type(literal: &ExprLiteral) -> ExprType {
    match literal {
        ExprLiteral::String(_) | ExprLiteral::Ident(_) => ExprType::String,
        ExprLiteral::Number(value) if value.contains('.') => ExprType::Float,
        ExprLiteral::Number(_) => ExprType::Int,
        ExprLiteral::Bool(_) => ExprType::Bool,
        ExprLiteral::Null => ExprType::Null,
    }
}

fn types_comparable(left: &ExprType, right: &ExprType) -> bool {
    if matches!(left, ExprType::Unknown) || matches!(right, ExprType::Unknown) {
        return true;
    }
    if matches!(left, ExprType::Null) || matches!(right, ExprType::Null) {
        return true;
    }
    if is_numeric_type(left) && is_numeric_type(right) {
        return true;
    }
    match (left, right) {
        (ExprType::Optional(left), right) | (right, ExprType::Optional(left)) => {
            types_comparable(left, right)
        }
        (ExprType::Finite { .. }, ExprType::String)
        | (ExprType::String, ExprType::Finite { .. })
        | (ExprType::Finite { .. }, ExprType::Finite { .. }) => true,
        _ => left == right,
    }
}

fn is_numeric_type(ty: &ExprType) -> bool {
    matches!(ty, ExprType::Int | ExprType::Float)
}

fn is_string_like_key_type(ty: &ExprType) -> bool {
    match ty {
        ExprType::String | ExprType::Unknown | ExprType::Finite { .. } => true,
        ExprType::Optional(inner) => is_string_like_key_type(inner),
        _ => false,
    }
}

fn is_orderable_pair(left: &ExprType, right: &ExprType) -> bool {
    if matches!(left, ExprType::Unknown) || matches!(right, ExprType::Unknown) {
        return true;
    }
    (is_numeric_type(left) && is_numeric_type(right))
        || matches!(
            (left, right),
            (ExprType::Duration, ExprType::Duration)
                | (ExprType::Time, ExprType::Time)
                // A quoted ISO-8601 string in a time-typed comparison is a
                // time literal (spec/scheduled-time.md).
                | (ExprType::Time, ExprType::String)
                | (ExprType::String, ExprType::Time)
        )
}

fn is_countable_type(ty: &ExprType) -> bool {
    matches!(
        ty,
        ExprType::Array(_) | ExprType::Map(_) | ExprType::Collection | ExprType::Unknown
    )
}

fn is_exists_type(ty: &ExprType) -> bool {
    matches!(
        ty,
        ExprType::Array(_)
            | ExprType::Map(_)
            | ExprType::Collection
            | ExprType::Optional(_)
            | ExprType::Unknown
    )
}

/// Spec "Count And Empty": `empty` is a structural emptiness test for arrays,
/// maps, strings, fact/effect queries, and null; `empty(Optional<T>)` is
/// defined only when `empty(T)` is (so `empty(string?)` works, `empty(int?)`
/// does not). It never coerces scalars, objects, enum variants, or agent refs.
fn is_emptiable_type(ty: &ExprType) -> bool {
    match ty {
        ExprType::Array(_)
        | ExprType::Map(_)
        | ExprType::String
        | ExprType::Collection
        | ExprType::Null
        | ExprType::Unknown => true,
        ExprType::Optional(inner) => is_emptiable_type(inner),
        _ => false,
    }
}

fn expr_type_label(ty: &ExprType) -> String {
    match ty {
        ExprType::Bool => "bool".to_owned(),
        ExprType::Int => "int".to_owned(),
        ExprType::Float => "float".to_owned(),
        ExprType::String => "string".to_owned(),
        ExprType::Finite { label, values } => format!("{label}<{}>", values.join(" | ")),
        ExprType::Duration => "duration".to_owned(),
        ExprType::Time => "time".to_owned(),
        ExprType::Secret(None) => "secret".to_owned(),
        ExprType::Secret(Some(kind)) => format!("secret<{}>", kind.as_str().replace('-', "_")),
        ExprType::Null => "null".to_owned(),
        ExprType::Object => "object".to_owned(),
        ExprType::Array(inner) => format!("{}[]", expr_type_label(inner)),
        ExprType::Map(inner) => format!("map<{}>", expr_type_label(inner)),
        ExprType::Sealed(inner) => format!("sealed<{}>", expr_type_label(inner)),
        ExprType::Optional(inner) => format!("{}?", expr_type_label(inner)),
        ExprType::Collection => "query".to_owned(),
        ExprType::Unknown => "unknown".to_owned(),
    }
}

fn validate_finite_domain_expr(
    op: BinaryOp,
    left: &Expr,
    right: &Expr,
    semantic: &SemanticContext,
    scope: &ExprScope,
    context: &ExprValidationContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !matches!(
        op,
        BinaryOp::Eq | BinaryOp::Ne | BinaryOp::In | BinaryOp::NotIn
    ) {
        return;
    }
    let Some((domain, literals)) = finite_domain_comparison(left, right, semantic, scope)
        .or_else(|| finite_domain_comparison(right, left, semantic, scope))
    else {
        validate_finite_domain_relation(op, left, right, semantic, scope, context, diagnostics);
        return;
    };
    for literal in literals.into_iter().flatten() {
        if !domain.iter().any(|value| value == &literal) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: context.span,
                message: format!(
                    "{} compares finite-domain value to unknown `{literal}`",
                    context.subject
                ),
                suggestion: Some(format!("use one of: {}", domain.join(", "))),
            });
        }
    }
    validate_finite_domain_relation(op, left, right, semantic, scope, context, diagnostics);
}

fn validate_finite_domain_relation(
    op: BinaryOp,
    left: &Expr,
    right: &Expr,
    semantic: &SemanticContext,
    scope: &ExprScope,
    context: &ExprValidationContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match op {
        BinaryOp::Eq => {
            let Some(left_domain) = expr_domain(left, semantic, scope) else {
                return;
            };
            let Some(right_domain) = expr_domain(right, semantic, scope) else {
                return;
            };
            if left_domain
                .iter()
                .all(|value| !right_domain.iter().any(|right| right == value))
            {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} has statically unsatisfiable finite-domain equality",
                        context.subject
                    ),
                    suggestion: Some(format!(
                        "compare domains with at least one shared value; left: {}, right: {}",
                        left_domain.join(", "),
                        right_domain.join(", ")
                    )),
                });
            }
        }
        BinaryOp::In => {
            let Some(domain) = expr_domain(left, semantic, scope) else {
                return;
            };
            let Some(literals) = literal_array_values(right) else {
                return;
            };
            if literals
                .iter()
                .all(|literal| !domain.iter().any(|value| value == literal))
            {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} has statically unsatisfiable finite-domain membership",
                        context.subject
                    ),
                    suggestion: Some(format!("use one of: {}", domain.join(", "))),
                });
            }
        }
        BinaryOp::NotIn => {
            let Some(domain) = expr_domain(left, semantic, scope) else {
                return;
            };
            let Some(literals) = literal_array_values(right) else {
                return;
            };
            if !domain.is_empty()
                && domain
                    .iter()
                    .all(|value| literals.iter().any(|literal| literal == value))
            {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: context.span,
                    message: format!(
                        "{} has statically unsatisfiable finite-domain exclusion",
                        context.subject
                    ),
                    suggestion: Some(
                        "leave at least one domain value outside the exclusion set".to_owned(),
                    ),
                });
            }
        }
        _ => {}
    }
}

fn finite_domain_comparison(
    domain_expr: &Expr,
    literal_expr: &Expr,
    semantic: &SemanticContext,
    scope: &ExprScope,
) -> Option<(Vec<String>, Vec<Option<String>>)> {
    let domain = expr_domain(domain_expr, semantic, scope)?;
    let literals = match literal_expr {
        Expr::Literal(literal) => vec![expr_literal_name(literal)],
        Expr::Array(items) => items
            .iter()
            .filter_map(|item| match item {
                Expr::Literal(literal) => Some(expr_literal_name(literal)),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    Some((domain, literals))
}

fn expr_domain(expr: &Expr, semantic: &SemanticContext, scope: &ExprScope) -> Option<Vec<String>> {
    let ty = match expr {
        Expr::Path(path) => {
            let root = path.first()?;
            if let Some(schema) = scope.binding_types.get(root) {
                semantic
                    .schemas
                    .resolve_field_path(schema, path.get(1..)?)
                    .ok()?
            } else {
                let schema = scope.implicit_schema.as_ref()?;
                semantic.schemas.resolve_field_path(schema, path).ok()?
            }
        }
        Expr::Literal(ExprLiteral::Ident(name)) => implicit_field_type(name, semantic, scope)?,
        _ => return None,
    };
    finite_expr_domain(&ty, semantic)
}

fn finite_expr_domain(ty: &TypeSyntax, semantic: &SemanticContext) -> Option<Vec<String>> {
    match ty {
        TypeSyntax::Ref { name } => semantic
            .schemas
            .enums
            .get(&name.name)
            .map(|variants| variants.iter().cloned().collect()),
        TypeSyntax::Union { variants, .. } => {
            let values = variants
                .iter()
                .filter_map(|variant| match variant {
                    TypeSyntax::LiteralString { value, .. } => Some(value.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            (!values.is_empty()).then_some(values)
        }
        TypeSyntax::AgentRef { agents, .. } => {
            Some(agents.iter().map(|agent| agent.name.clone()).collect())
        }
        _ => None,
    }
}

fn expr_literal_name(literal: &ExprLiteral) -> Option<String> {
    match literal {
        ExprLiteral::String(value) | ExprLiteral::Ident(value) => Some(value.clone()),
        _ => None,
    }
}

fn literal_array_values(expr: &Expr) -> Option<Vec<String>> {
    let Expr::Array(items) = expr else {
        return None;
    };
    items
        .iter()
        .map(|item| match item {
            Expr::Literal(literal) => expr_literal_name(literal),
            _ => None,
        })
        .collect()
}

fn parse_tell_target(line: &str) -> Option<&str> {
    line.strip_prefix("tell ")?
        .split_whitespace()
        .next()
        .filter(|target| !target.is_empty())
}

fn parse_required_capabilities(line: &str) -> Vec<String> {
    let Some(rest) = line.split_once(" requires ") else {
        return Vec::new();
    };
    let Some(list) = rest.1.trim_start().strip_prefix('[') else {
        return Vec::new();
    };
    let Some((items, _)) = list.split_once(']') else {
        return Vec::new();
    };
    let mut capabilities = items
        .split(',')
        .filter_map(|item| {
            let value = item.trim().trim_matches('"');
            (!value.is_empty()).then(|| value.to_owned())
        })
        .collect::<Vec<_>>();
    capabilities.sort();
    capabilities.dedup();
    capabilities
}

fn validate_case_blocks(
    rule: &RuleDecl,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let lines = rule
        .body
        .text
        .lines()
        .scan(0usize, |offset, line| {
            let current = *offset;
            *offset += line.len() + 1;
            Some((line, current))
        })
        .collect::<Vec<_>>();
    let text_lines = lines.iter().map(|(line, _)| *line).collect::<Vec<_>>();
    let mut index = 0usize;
    while index < lines.len() {
        let trimmed = lines[index].0.trim();
        let Some(scrutinee) = case_scrutinee(trimmed) else {
            index += 1;
            continue;
        };
        let scrutinee_ty = expression_type(scrutinee, semantic, binding_types);
        let terminal_case = scrutinee_ty.is_none()
            && active_completes_binding_for_case(&text_lines, index, scrutinee);
        if scrutinee_ty.is_none() && !terminal_case {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` has case scrutinee `{scrutinee}` that is not a typed path",
                    rule.name.name
                ),
                suggestion: Some("match on a bound field such as `task.provider`".to_owned()),
            });
        }
        let mut depth = brace_delta(trimmed).max(1);
        let mut case_index = index + 1;
        let mut branches = Vec::new();
        while case_index < lines.len() && depth > 0 {
            let (raw_line, line_offset) = lines[case_index];
            let line = raw_line.trim();
            if depth == 1 {
                if let Some(branch) = parse_case_branch_head(line) {
                    let pattern_column = case_pattern_column(raw_line, branch.pattern);
                    let branch = SpanCaseBranchHead {
                        pattern: branch.pattern,
                        guard: branch.guard,
                        pattern_span: SourceSpan {
                            start: rule_body_text_start(rule) + line_offset + pattern_column,
                            end: rule_body_text_start(rule)
                                + line_offset
                                + pattern_column
                                + branch.pattern.len(),
                        },
                    };
                    branches.push(branch);
                    if terminal_case {
                        validate_terminal_case_pattern(
                            rule,
                            branch.pattern,
                            branch.pattern_span,
                            diagnostics,
                        );
                    } else {
                        validate_case_pattern(
                            rule,
                            branch.pattern,
                            scrutinee_ty.as_ref(),
                            branch.pattern_span,
                            semantic,
                            diagnostics,
                        );
                    }
                    // Terminal-case guards are validated by
                    // `collect_terminal_case_metadata`, which is the only path
                    // with `effect_payload_types` and so the only one that can
                    // bind the tag-refined payload (`Completed as result where
                    // result.x ...`) into the guard scope. Validating them here
                    // too would reject that binding as an unknown root.
                    if let Some(guard) = branch.guard.filter(|_| !terminal_case) {
                        let mut branch_scope = binding_types.clone();
                        if let Some(scrutinee_ty) = scrutinee_ty.as_ref() {
                            if let Some((binding, schema)) =
                                case_branch_payload_binding(branch.pattern, scrutinee_ty, semantic)
                            {
                                branch_scope.insert(binding, schema);
                            }
                        }
                        validate_expression(
                            rule,
                            guard,
                            semantic,
                            &branch_scope,
                            "case guard",
                            diagnostics,
                        );
                        validate_known_field_paths_at_span(
                            rule,
                            guard,
                            branch.pattern_span,
                            semantic,
                            &branch_scope,
                            diagnostics,
                        );
                    }
                }
            }
            depth += brace_delta(line);
            case_index += 1;
        }
        if terminal_case {
            validate_terminal_case_coverage(rule, &branches, diagnostics);
        } else {
            validate_case_coverage(
                rule,
                scrutinee_ty.as_ref(),
                &branches,
                semantic,
                diagnostics,
            );
        }
        index += 1;
    }
}

fn active_completes_binding_for_case(lines: &[&str], case_index: usize, scrutinee: &str) -> bool {
    let mut scopes: Vec<(String, DependencyPredicate, i32)> = Vec::new();
    for line in lines.iter().take(case_index) {
        let trimmed = line.trim();
        if let Some((binding, predicate)) = parse_after_line(trimmed) {
            scopes.push((binding, predicate, brace_delta(trimmed).max(1)));
        } else {
            let delta = brace_delta(trimmed);
            for (_, _, depth) in &mut scopes {
                *depth += delta;
            }
            scopes.retain(|(_, _, depth)| *depth > 0);
        }
    }
    scopes.iter().any(|(binding, predicate, _)| {
        binding == scrutinee && predicate == &DependencyPredicate::Completes
    })
}

fn brace_delta(line: &str) -> i32 {
    line.chars().fold(0, |depth, ch| match ch {
        '{' => depth + 1,
        '}' => depth - 1,
        _ => depth,
    })
}

fn case_scrutinee(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("case ")?;
    let expr = rest.strip_suffix('{').unwrap_or(rest).trim();
    (!expr.is_empty()).then_some(expr)
}

fn is_case_branch_start(line: &str) -> bool {
    line.contains("=>")
}

#[derive(Clone, Copy)]
struct CaseBranchHead<'a> {
    pattern: &'a str,
    guard: Option<&'a str>,
}

#[derive(Clone, Copy)]
struct SpanCaseBranchHead<'a> {
    pattern: &'a str,
    guard: Option<&'a str>,
    pattern_span: SourceSpan,
}

fn parse_case_branch_head(line: &str) -> Option<CaseBranchHead<'_>> {
    let (pattern, _) = line.split_once("=>")?;
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return None;
    }
    match pattern.split_once(" where ") {
        Some((pattern, guard)) => Some(CaseBranchHead {
            pattern: pattern.trim(),
            guard: Some(guard.trim()),
        }),
        None => Some(CaseBranchHead {
            pattern,
            guard: None,
        }),
    }
}

fn expression_type(
    expr: &str,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
) -> Option<TypeSyntax> {
    // A bare enum-typed binding is a valid scrutinee: `case o` dispatches a
    // sum-type payload (spec/sum-types.md). Class-typed bare bindings stay
    // untyped here so the "match on a bound field" guidance still fires.
    let is_bare_ident = !expr.is_empty()
        && expr.chars().all(|ch| ch.is_alphanumeric() || ch == '_')
        && expr.chars().next().is_some_and(char::is_alphabetic);
    if is_bare_ident {
        let schema = binding_types.get(expr)?;
        if semantic.schemas.enums.contains_key(schema) {
            return Some(TypeSyntax::Ref {
                name: Ident {
                    name: schema.clone(),
                    span: zero_span(),
                },
            });
        }
        return None;
    }
    let (root, path) = expression_path(expr)?;
    let schema = binding_types.get(&root)?;
    semantic.schemas.resolve_field_path(schema, &path).ok()
}

fn validate_case_pattern(
    rule: &RuleDecl,
    pattern: &str,
    scrutinee_ty: Option<&TypeSyntax>,
    span: SourceSpan,
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if matches!(pattern, "_" | "default") {
        return;
    }
    if pattern == "None" {
        if !matches!(scrutinee_ty, Some(TypeSyntax::Optional { .. })) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span,
                message: format!(
                    "rule `{}` uses `None` for a non-optional case",
                    rule.name.name
                ),
                suggestion: Some("use `None` only when matching an optional field".to_owned()),
            });
        }
        return;
    }
    if pattern.starts_with("Some ") {
        if !matches!(scrutinee_ty, Some(TypeSyntax::Optional { .. })) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span,
                message: format!(
                    "rule `{}` uses `Some` for a non-optional case",
                    rule.name.name
                ),
                suggestion: Some("use `Some name` only when matching an optional field".to_owned()),
            });
        }
        return;
    }
    let Some(scrutinee_ty) = scrutinee_ty else {
        return;
    };
    match scrutinee_ty {
        TypeSyntax::Ref { name } => {
            let Some(variants) = semantic.schemas.enums.get(&name.name) else {
                return;
            };
            let (variant, binding) = sum_case_pattern_parts(pattern);
            if !variants.contains(variant) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span,
                    message: format!("enum `{}` has no variant `{variant}`", name.name),
                    suggestion: Some(format!(
                        "use one of: {}",
                        variants.iter().cloned().collect::<Vec<_>>().join(", ")
                    )),
                });
                return;
            }
            // `as` binds a data-carrying variant's payload (spec/sum-types.md);
            // a bare variant has no payload to bind.
            if binding.is_some()
                && !semantic
                    .schemas
                    .class_exists(&format!("{}.{variant}", name.name))
            {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span,
                    message: format!(
                        "variant `{variant}` of enum `{}` carries no payload to bind",
                        name.name
                    ),
                    suggestion: Some(format!("write `{variant} => {{ ... }}` without `as`")),
                });
            }
        }
        TypeSyntax::Union { variants, .. } => {
            let Some(literal) = parse_literal_expr(pattern) else {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span,
                    message: format!(
                        "rule `{}` has unsupported case pattern `{pattern}`",
                        rule.name.name
                    ),
                    suggestion: Some("use a literal branch value or `_`".to_owned()),
                });
                return;
            };
            validate_union_case_pattern(rule, variants, &literal, span, diagnostics);
        }
        TypeSyntax::AgentRef { agents, .. } => {
            let Some(literal) = parse_literal_expr(pattern) else {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span,
                    message: format!(
                        "rule `{}` has unsupported AgentRef case pattern `{pattern}`",
                        rule.name.name
                    ),
                    suggestion: Some(
                        "use a declared agent name, a string literal, or `_`".to_owned(),
                    ),
                });
                return;
            };
            validate_agent_ref_case_pattern(rule, agents, &literal, span, diagnostics);
        }
        TypeSyntax::Optional { inner, .. } => {
            validate_case_pattern(rule, pattern, Some(inner), span, semantic, diagnostics);
        }
        // `case` over a `bool` field: only the two literals `true`/`false` (plus
        // the `_`/`default` fallbacks already handled above) are valid patterns.
        TypeSyntax::Primitive { name, .. } if name == "bool" => {
            if !matches!(pattern, "true" | "false") {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span,
                    message: format!(
                        "rule `{}` has case pattern `{pattern}` that is not a `bool` value",
                        rule.name.name
                    ),
                    suggestion: Some("match `true`, `false`, or `_`".to_owned()),
                });
            }
        }
        _ => {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span,
                message: format!(
                    "rule `{}` cannot pattern-match this scrutinee type",
                    rule.name.name
                ),
                suggestion: Some(
                    "match an enum, literal union, optional, or tagged output union".to_owned(),
                ),
            });
        }
    }
}

fn terminal_case_tags() -> [&'static str; 4] {
    ["Completed", "Failed", "TimedOut", "Cancelled"]
}

fn validate_terminal_case_pattern(
    rule: &RuleDecl,
    pattern: &str,
    span: SourceSpan,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if is_fallback_pattern(pattern) {
        return;
    }
    let mut parts = pattern.split_whitespace();
    let Some(tag) = parts.next() else {
        return;
    };
    // Binding is `Tag as binding` (Stage 1b: the legacy space form `Tag binding` is
    // no longer accepted — it aligns terminal cases with enum-variant `as` binding).
    let second = parts.next();
    let binding = match second {
        Some("as") => parts.next(),
        other => other,
    };
    let uses_as = matches!(second, Some("as"));
    if parts.next().is_some() || binding.is_none() || !uses_as {
        diagnostics.push(Diagnostic { related: Vec::new(),
            span,
            message: format!(
                "rule `{}` has malformed terminal-output case pattern `{pattern}`",
                rule.name.name
            ),
            suggestion: Some("write `Completed as result`, `Failed as failure`, `TimedOut as timeout`, or `Cancelled as cancel` (the `as` is required)".to_owned()),
        });
        return;
    }
    let tags = terminal_case_tags();
    if !tags.contains(&tag) {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span,
            message: format!(
                "rule `{}` terminal-output case pattern cannot be `{tag}`",
                rule.name.name
            ),
            suggestion: Some(format!("use one of: {}", tags.join(", "))),
        });
    }
}

fn validate_terminal_case_coverage(
    rule: &RuleDecl,
    branches: &[SpanCaseBranchHead<'_>],
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_unreachable_after_fallback(rule, branches, diagnostics);
    if branches.is_empty()
        || branches
            .iter()
            .any(|branch| is_fallback_pattern(branch.pattern))
    {
        validate_duplicate_terminal_case_patterns(rule, branches, diagnostics);
        return;
    }
    validate_duplicate_terminal_case_patterns(rule, branches, diagnostics);
    let covered = branches
        .iter()
        .filter(|branch| branch.guard.is_none())
        .filter_map(|branch| normalized_terminal_case_pattern(branch.pattern))
        .collect::<BTreeSet<_>>();
    let missing = terminal_case_tags()
        .iter()
        .filter(|tag| !covered.contains(**tag))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!(
                "rule `{}` has non-exhaustive terminal-output case; missing {}",
                rule.name.name,
                missing.join(", ")
            ),
            suggestion: Some(
                "add terminal branches for every value or add `_ => { ... }`".to_owned(),
            ),
        });
    }
}

fn validate_duplicate_terminal_case_patterns(
    rule: &RuleDecl,
    branches: &[SpanCaseBranchHead<'_>],
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut seen = BTreeSet::new();
    for branch in branches.iter().filter(|branch| branch.guard.is_none()) {
        let Some(pattern) = normalized_terminal_case_pattern(branch.pattern) else {
            continue;
        };
        if !seen.insert(pattern.to_owned()) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: branch.pattern_span,
                message: format!(
                    "rule `{}` has duplicate unguarded terminal-output case pattern `{pattern}`",
                    rule.name.name
                ),
                suggestion: Some(
                    "remove the duplicate branch or add mutually exclusive `where` guards"
                        .to_owned(),
                ),
            });
        }
    }
}

fn validate_case_coverage(
    rule: &RuleDecl,
    scrutinee_ty: Option<&TypeSyntax>,
    branches: &[SpanCaseBranchHead<'_>],
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_unreachable_after_fallback(rule, branches, diagnostics);
    if branches.is_empty()
        || branches
            .iter()
            .any(|branch| is_fallback_pattern(branch.pattern))
    {
        validate_duplicate_case_patterns(rule, branches, diagnostics);
        return;
    }
    validate_duplicate_case_patterns(rule, branches, diagnostics);

    let Some(domain) = finite_case_domain(scrutinee_ty, semantic) else {
        return;
    };
    let covered = branches
        .iter()
        .filter(|branch| branch.guard.is_none())
        .filter_map(|branch| normalized_case_pattern(branch.pattern))
        .collect::<BTreeSet<_>>();
    let missing = domain
        .iter()
        .filter(|value| !covered.contains(value.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!(
                "rule `{}` has non-exhaustive case; missing {}",
                rule.name.name,
                missing.join(", ")
            ),
            suggestion: Some("add branches for every value or add `_ => { ... }`".to_owned()),
        });
    }
}

fn validate_duplicate_case_patterns(
    rule: &RuleDecl,
    branches: &[SpanCaseBranchHead<'_>],
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut seen = BTreeSet::new();
    for branch in branches.iter().filter(|branch| branch.guard.is_none()) {
        let Some(pattern) = normalized_case_pattern(branch.pattern) else {
            continue;
        };
        if !seen.insert(pattern.to_owned()) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: branch.pattern_span,
                message: format!(
                    "rule `{}` has duplicate unguarded case pattern `{pattern}`",
                    rule.name.name
                ),
                suggestion: Some(
                    "remove the duplicate branch or add mutually exclusive `where` guards"
                        .to_owned(),
                ),
            });
        }
    }
}

/// Flags case branches that can never be reached because an earlier *unguarded*
/// wildcard (`_`/`default`) already matches everything. Shared by rule cases and
/// terminal-output cases. Mirrors case-family.maude inv c (redundant-postwild): any
/// arm after the wildcard is redundant. A *guarded* fallback (`_ where g`) does not
/// shadow, since its guard can fail at runtime.
fn validate_unreachable_after_fallback(
    rule: &RuleDecl,
    branches: &[SpanCaseBranchHead<'_>],
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut ordered: Vec<&SpanCaseBranchHead<'_>> = branches.iter().collect();
    ordered.sort_by_key(|branch| branch.pattern_span.start);
    let mut fallback_span: Option<SourceSpan> = None;
    for branch in ordered {
        if let Some(prior) = fallback_span {
            diagnostics.push(
                Diagnostic {
                    related: Vec::new(),
                    span: branch.pattern_span,
                    message: format!(
                        "rule `{}` has an unreachable case branch after the `_` wildcard",
                        rule.name.name
                    ),
                    suggestion: Some(
                        "move this branch before the wildcard, or remove it".to_owned(),
                    ),
                }
                .with_related(
                    prior,
                    "this unguarded wildcard already matches every remaining value",
                ),
            );
        } else if branch.guard.is_none() && is_fallback_pattern(branch.pattern) {
            fallback_span = Some(branch.pattern_span);
        }
    }
}

fn finite_case_domain(
    scrutinee_ty: Option<&TypeSyntax>,
    semantic: &SemanticContext,
) -> Option<Vec<String>> {
    match scrutinee_ty? {
        TypeSyntax::Ref { name } => semantic
            .schemas
            .enums
            .get(&name.name)
            .map(|variants| variants.iter().cloned().collect()),
        TypeSyntax::Union { variants, .. } => {
            let values = variants
                .iter()
                .filter_map(|variant| match variant {
                    TypeSyntax::LiteralString { value, .. } => Some(value.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            (!values.is_empty()).then_some(values)
        }
        TypeSyntax::Optional { .. } => Some(vec!["Some".to_owned(), "None".to_owned()]),
        TypeSyntax::AgentRef { agents, .. } => {
            Some(agents.iter().map(|agent| agent.name.clone()).collect())
        }
        // `bool` is a finite two-value domain: an exhaustive `case` over it must
        // cover both `true` and `false` (or carry a `_`).
        TypeSyntax::Primitive { name, .. } if name == "bool" => {
            Some(vec!["true".to_owned(), "false".to_owned()])
        }
        _ => None,
    }
}

/// Splits a sum-type case pattern `Variant as binding` into variant and
/// binding (spec/sum-types.md); a plain pattern returns no binding.
fn sum_case_pattern_parts(pattern: &str) -> (&str, Option<&str>) {
    match pattern.split_once(" as ") {
        Some((variant, binding)) => (variant.trim(), Some(binding.trim())),
        None => (pattern.trim(), None),
    }
}

fn normalized_case_pattern(pattern: &str) -> Option<&str> {
    if is_fallback_pattern(pattern) {
        return None;
    }
    if pattern.starts_with("Some ") {
        return Some("Some");
    }
    if pattern == "None" {
        return Some("None");
    }
    // Coverage counts the variant, not its payload binding.
    let (pattern, _) = sum_case_pattern_parts(pattern);
    // `bool` literals parse to the value-less `LiteralExpr::Bool`; return them
    // verbatim so they count toward `true`/`false` coverage.
    if matches!(pattern, "true" | "false") {
        return Some(pattern);
    }
    parse_literal_expr(pattern).and_then(|literal| match literal {
        LiteralExpr::String(value) | LiteralExpr::Ident(value) => Some(value),
        _ => None,
    })
}

fn normalized_terminal_case_pattern(pattern: &str) -> Option<&str> {
    if is_fallback_pattern(pattern) {
        return None;
    }
    pattern.split_whitespace().next()
}

fn is_fallback_pattern(pattern: &str) -> bool {
    matches!(pattern, "_" | "default")
}

fn validate_union_case_pattern(
    rule: &RuleDecl,
    variants: &[TypeSyntax],
    literal: &LiteralExpr<'_>,
    span: SourceSpan,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let allowed = variants
        .iter()
        .filter_map(|variant| match variant {
            TypeSyntax::LiteralString { value, .. } => Some(value.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if allowed.is_empty() {
        return;
    }
    let LiteralExpr::String(value) = literal else {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span,
            message: format!(
                "rule `{}` case pattern must be one of its literal variants",
                rule.name.name
            ),
            suggestion: Some(format!("use one of: {}", allowed.join(", "))),
        });
        return;
    };
    if !allowed.contains(value) {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span,
            message: format!("rule `{}` case pattern cannot be `{value}`", rule.name.name),
            suggestion: Some(format!("use one of: {}", allowed.join(", "))),
        });
    }
}

fn validate_agent_ref_case_pattern(
    rule: &RuleDecl,
    agents: &[Ident],
    literal: &LiteralExpr<'_>,
    span: SourceSpan,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let allowed = agents
        .iter()
        .map(|agent| agent.name.as_str())
        .collect::<Vec<_>>();
    let (LiteralExpr::String(value) | LiteralExpr::Ident(value)) = literal else {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span,
            message: format!("rule `{}` has non-agent case pattern", rule.name.name),
            suggestion: Some(format!("use one of: {}", allowed.join(", "))),
        });
        return;
    };
    if !allowed.contains(value) {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span,
            message: format!("AgentRef has no agent `{value}`"),
            suggestion: Some(format!("use one of: {}", allowed.join(", "))),
        });
    }
}

fn validate_binding_uses(
    rule: &RuleDecl,
    line: &str,
    seen_bindings: &BTreeSet<String>,
    scope_stack: &[(String, DependencyPredicate)],
    diagnostics: &mut Vec<Diagnostic>,
) {
    for root in interpolation_roots(line) {
        if !seen_bindings.contains(&root) {
            continue;
        }
        if scope_stack.iter().any(|(binding, _)| binding == &root) {
            continue;
        }

        diagnostics.push(Diagnostic { related: Vec::new(),
            span: rule.body.span,
            message: format!(
                "rule `{}` uses effect output `{root}` outside a matching `after {root} ...` block",
                rule.name.name
            ),
            suggestion: Some(format!(
                "move this use into `after {root} succeeds {{ ... }}` or another matching terminal branch"
            )),
        });
    }
}

fn after_scopes(block_stack: &[BlockFrame]) -> Vec<(String, DependencyPredicate)> {
    block_stack
        .iter()
        .map(|frame| match frame {
            BlockFrame::After { binding, predicate } => (binding.clone(), predicate.clone()),
        })
        .collect()
}

/// The single lowering table for readiness sugar: maps a `when` pattern to
/// the runtime fact name it matches. The general form is
/// `when fact <name> as x`; the English phrases are documented abbreviations
/// of it.
pub fn runtime_fact_name_for_pattern(pattern: &str) -> Option<String> {
    let pattern = pattern.trim();
    if let Some(rest) = pattern.strip_prefix("fact ") {
        let name = rest.split_whitespace().next()?;
        return Some(name.to_owned());
    }
    // Inbound messaging (spec/messaging.md): `message from <channel>` matches the
    // channel-specific `message.<channel>` fact ingested by `whip message`.
    if let Some(rest) = pattern.strip_prefix("message from ") {
        if let Some(channel) = rest.split_whitespace().next() {
            return Some(format!("message.{channel}"));
        }
    }
    // std.vcs readiness sugar (DR-0052 grammar pass): each phrase is a
    // defined lowering onto a generated-only `vcs.*` fact; the leading
    // word of the stream forms is the stream guard's subject.
    if pattern == "line changed" || pattern == "line changed by others" {
        return Some("vcs.cut.recorded".to_owned());
    }
    if pattern == "reconcile stalled" {
        return Some("vcs.reconcile.stalled".to_owned());
    }
    {
        let words: Vec<&str> = pattern.split_whitespace().collect();
        match words.as_slice() {
            [_, "has", "contention"] => {
                return Some("vcs.contention.predicted".to_owned());
            }
            [_, "promoted"] => {
                return Some("vcs.stream.promoted".to_owned());
            }
            [_, "is", "quiescent"] => {
                return Some("vcs.stream.quiescent".to_owned());
            }
            _ => {}
        }
    }
    let mut words = pattern.split_whitespace();
    let first = words.next()?;
    if words.next() == Some("completed") && words.next() == Some("turn") {
        let _ = first;
        return Some("agent.turn.completed".to_owned());
    }
    {
        let mut words = pattern.split_whitespace();
        let _tracker = words.next();
        if words.next() == Some("has")
            && words.next() == Some("ready")
            && words.next() == Some("issue")
        {
            return Some("tracker.issue.ready".to_owned());
        }
    }
    if first.chars().next().is_some_and(char::is_uppercase) {
        return Some(first.to_owned());
    }
    None
}

/// The schema used to type-check fields on the pattern's binding. Dotted
/// runtime fact names are untyped (no class declares them); the sugar forms
/// map to their builtin schemas.
fn binding_from_when(when: &str) -> Option<(String, String)> {
    let (pattern, _) = split_when_guard(when);
    let binding = binding_after_as(pattern)?;
    let first = pattern.split_whitespace().next()?;
    let completed_turn = {
        let mut words = pattern.split_whitespace();
        words.next();
        words.next() == Some("completed") && words.next() == Some("turn")
    };
    let has_ready_issue = {
        let mut words = pattern.split_whitespace();
        words.next();
        words.next() == Some("has")
            && words.next() == Some("ready")
            && words.next() == Some("issue")
    };
    let schema = if let Some(rest) = pattern.strip_prefix("fact ") {
        rest.split_whitespace().next()?.to_owned()
    } else if first.chars().next().is_some_and(char::is_uppercase) {
        first.to_owned()
    } else if first.contains('.') {
        // Bare dotted reaction `when deploy.finished as d` — typed against a
        // declared `event` (validated at the call site,
        // spec/event-ingress.md).
        first.to_owned()
    } else if completed_turn {
        "AgentTurn".to_owned()
    } else if has_ready_issue {
        "WorkItem".to_owned()
    } else if pattern.starts_with("message from ") {
        // Inbound messaging (spec/messaging.md): `when message from <channel> as
        // msg` binds the generic `Message` envelope, never a domain type.
        "Message".to_owned()
    } else {
        let schema = vcs_sugar_schema(pattern.split(" as ").next().unwrap_or(pattern).trim())?;
        // std.vcs readiness sugar (DR-0052): each phrase binds its
        // builtin observer schema, like `completed turn` -> AgentTurn.
        schema.to_owned()
    };

    Some((binding, schema))
}

/// The builtin observer schema each std.vcs sugar phrase binds.
fn vcs_sugar_schema(phrase: &str) -> Option<&'static str> {
    if phrase == "line changed" || phrase == "line changed by others" {
        return Some("VcsChange");
    }
    if phrase == "reconcile stalled" {
        return Some("VcsStall");
    }
    let words: Vec<&str> = phrase.split_whitespace().collect();
    match words.as_slice() {
        [_, "has", "contention"] => Some("VcsContention"),
        [_, "promoted"] => Some("VcsPromotion"),
        _ => None,
    }
}

pub(crate) fn split_when_guard(when: &str) -> (&str, Option<&str>) {
    match when.split_once(" where ") {
        Some((pattern, guard)) => (pattern.trim(), Some(guard.trim())),
        None => (when.trim(), None),
    }
}

fn effect_binding_schema(
    line: &str,
    kind: &IrEffectKind,
    semantic: &SemanticContext,
) -> Option<String> {
    match kind {
        IrEffectKind::SchemaCoerce => parse_coerce_call_name(line).and_then(|name| {
            semantic
                .coerce_outputs
                .get(name)
                .and_then(schema_name_for_path)
        }),
        IrEffectKind::AgentTell
        | IrEffectKind::CapabilityCall
        | IrEffectKind::HttpRequest
        | IrEffectKind::MintCredential
        | IrEffectKind::EventEmit
        | IrEffectKind::WorkflowInvoke
        | IrEffectKind::TimerWait
        | IrEffectKind::ExecCommand
        | IrEffectKind::TrackerFile
        | IrEffectKind::TrackerClaim
        | IrEffectKind::TrackerRenew
        | IrEffectKind::TrackerRelease
        | IrEffectKind::TrackerFinish
        | IrEffectKind::LeaseAcquire
        | IrEffectKind::LeaseRenew
        | IrEffectKind::LedgerAppend
        | IrEffectKind::CounterConsume
        | IrEffectKind::SignalEmit
        | IrEffectKind::FileRead
        | IrEffectKind::FileWrite
        | IrEffectKind::FileImport
        | IrEffectKind::FileExport => None,
    }
}

fn parse_coerce_call_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("coerce ")?;
    rest.split_once('(').map(|(name, _)| name.trim())
}

fn parse_coerce_call(line: &str) -> Option<(&str, Vec<&str>)> {
    let rest = line.strip_prefix("coerce ")?;
    let call = rest.split(" as ").next().unwrap_or(rest).trim();
    let (name, tail) = call.split_once('(')?;
    let (args, _) = tail.rsplit_once(')')?;
    Some((name.trim(), split_expression_args(args)))
}

fn split_expression_args(args: &str) -> Vec<&str> {
    let mut values = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut previous = '\0';
    for (index, ch) in args.char_indices() {
        if ch == '"' && previous != '\\' {
            in_string = !in_string;
        } else if !in_string {
            match ch {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                ',' if depth == 0 => {
                    let value = args[start..index].trim();
                    if !value.is_empty() {
                        values.push(value);
                    }
                    start = index + ch.len_utf8();
                }
                _ => {}
            }
        }
        previous = ch;
    }
    let value = args[start..].trim();
    if !value.is_empty() {
        values.push(value);
    }
    values
}

fn effect_payload_statements(body: &str) -> Vec<String> {
    collect_body_statements(body, effect_payload_statement_balance)
}

fn workflow_invoke_statements(body: &str) -> Vec<String> {
    collect_body_statements(body, workflow_invoke_statement_balance)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StatementBalance {
    None,
    Parens,
    Braces,
}

fn collect_body_statements(
    body: &str,
    statement_balance: fn(&str) -> Option<StatementBalance>,
) -> Vec<String> {
    let lines = body.lines().collect::<Vec<_>>();
    let mut statements = Vec::new();
    let mut index = 0usize;
    let mut record_depth = 0i32;
    let mut multiline_string = false;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        if trimmed.is_empty() {
            index += 1;
            continue;
        }
        if multiline_string {
            if trimmed.contains("\"\"\"") {
                multiline_string = false;
            }
            index += 1;
            continue;
        }
        if record_depth > 0 {
            record_depth += brace_delta(trimmed);
            index += 1;
            continue;
        }
        if parse_record_start(trimmed).is_some() {
            record_depth = brace_delta(trimmed).max(1);
            index += 1;
            continue;
        }
        if trimmed.contains("\"\"\"") {
            multiline_string = trimmed.matches("\"\"\"").count() % 2 == 1;
            index += 1;
            continue;
        }
        if let Some(balance) = statement_balance(trimmed) {
            match balance {
                StatementBalance::None => statements.push(trimmed.to_owned()),
                StatementBalance::Parens => {
                    let (statement, next_index) =
                        statement_until_balanced(&lines, index, trimmed, paren_delta);
                    statements.push(statement);
                    index = next_index + 1;
                    continue;
                }
                StatementBalance::Braces => {
                    let (statement, next_index) =
                        statement_until_balanced(&lines, index, trimmed, brace_delta);
                    statements.push(statement);
                    index = next_index + 1;
                    continue;
                }
            }
        }
        index += 1;
    }
    statements
}

fn effect_payload_statement_balance(trimmed: &str) -> Option<StatementBalance> {
    if trimmed.starts_with("coerce ") {
        Some(StatementBalance::Parens)
    } else if trimmed.starts_with("claim ") {
        Some(StatementBalance::None)
    } else {
        None
    }
}

fn workflow_invoke_statement_balance(trimmed: &str) -> Option<StatementBalance> {
    trimmed
        .starts_with("invoke ")
        .then_some(StatementBalance::Braces)
}

fn invoke_statement_parts(statement: &str) -> Option<(&str, &str)> {
    let rest = statement.trim().strip_prefix("invoke ")?;
    let target = rest
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches('{');
    if target.is_empty() {
        return None;
    }
    let open = statement.find('{')?;
    let mut depth = 0i32;
    let mut close = None;
    for (offset, ch) in statement[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close?;
    (close > open).then_some((target, statement[open + 1..close].trim()))
}

fn statement_until_balanced(
    lines: &[&str],
    index: usize,
    trimmed: &str,
    delta: fn(&str) -> i32,
) -> (String, usize) {
    let mut statement = trimmed.to_owned();
    let mut depth = delta(trimmed);
    let mut cursor = index;
    while depth > 0 && cursor + 1 < lines.len() {
        cursor += 1;
        let next = lines[cursor].trim();
        statement.push(' ');
        statement.push_str(next);
        depth += delta(next);
    }
    (statement, cursor)
}

fn paren_delta(line: &str) -> i32 {
    line.chars().fold(0, |depth, ch| match ch {
        '(' => depth + 1,
        ')' => depth - 1,
        _ => depth,
    })
}

/// The hygienic class name synthesized for an inline `decide -> { … } as
/// <binding>`. Dots are illegal in user class names (like the `flow.<name>.seg*`
/// rule convention), so `decide.<rule>.<binding>` can never collide with a
/// declared schema. The lowering pass, the type checker, and the runtime fixture
/// all derive the same name, so the anonymous result shape flows exactly like a
/// named `coerce -> Schema`: `after <binding> succeeds as r` resolves `r`'s
/// fields for `case` dispatch and field access.
pub fn inline_decide_schema_name(rule: &str, binding: &str) -> String {
    format!("decide.{rule}.{binding}")
}

/// A single-identifier `decide` field type is either a primitive keyword
/// (`bool`, `string`, …) or a reference to a declared class/enum. The `decide`
/// grammar only admits single identifiers, so no compound parsing is needed.
fn decide_field_type_syntax(ty: &str, span: SourceSpan) -> TypeSyntax {
    // `secret` stopped being a primitive name when it gained its discriminant
    // (DR-0053 §15). The `decide` grammar admits only single identifiers, so
    // the parameterised form is unspellable here and the bare one is what it
    // always was — without this arm it would fall through to `Ref` and report
    // an unknown schema instead of the unsatisfiable coerce schema that says
    // a model cannot produce a secret.
    if ty == "secret" {
        return TypeSyntax::Secret { kind: None, span };
    }
    if is_primitive_type(ty) {
        TypeSyntax::Primitive {
            name: ty.to_owned(),
            span,
        }
    } else {
        TypeSyntax::Ref {
            name: Ident {
                name: ty.to_owned(),
                span,
            },
        }
    }
}

/// Collects every inline `decide … as <binding>` in a rule body — recursing
/// through nested after/case/branch/handler blocks — yielding
/// `(binding, result_fields, span)` for synthesis and type registration.
#[allow(clippy::type_complexity)]
fn collect_decide_effects<'a>(
    statements: &'a [body::BodyStmt],
    out: &mut Vec<(&'a str, &'a [(String, String)], SourceSpan)>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                if let body::BodyEffectKind::Decide { result_fields } = &effect.kind {
                    if let Some(binding) = &effect.binding {
                        out.push((binding.as_str(), result_fields.as_slice(), effect.span));
                    }
                }
            }
            body::BodyStmt::After(after) => collect_decide_effects(&after.body, out),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_decide_effects(&branch.body, out);
                }
            }
            _ => {}
        }
    }
}

/// Registers each inline `decide … as <binding>` result as `Ref(decide.<rule>.<binding>)`
/// so the after-binding type flow resolves the anonymous shape's fields, exactly
/// like a named `coerce -> Schema`. The synthesized class is injected into both
/// the semantic schema index and the IR by [`collect_inline_decide_schemas`].
fn collect_decide_payload_types(
    statements: &[body::BodyStmt],
    rule_name: &str,
    payloads: &mut BTreeMap<String, IrType>,
) {
    let mut decides = Vec::new();
    collect_decide_effects(statements, &mut decides);
    for (binding, _fields, _span) in decides {
        payloads.insert(
            binding.to_owned(),
            IrType::Ref(inline_decide_schema_name(rule_name, binding)),
        );
    }
}

fn collect_prompt_payload_types(
    statements: &[body::BodyStmt],
    payloads: &mut BTreeMap<String, IrType>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                if matches!(&effect.kind, body::BodyEffectKind::Prompt { .. }) {
                    if let Some(binding) = &effect.binding {
                        payloads
                            .insert(binding.clone(), IrType::Primitive(IrPrimitiveType::String));
                    }
                }
            }
            body::BodyStmt::After(after) => collect_prompt_payload_types(&after.body, payloads),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_prompt_payload_types(&branch.body, payloads);
                }
            }
            _ => {}
        }
    }
}

/// Synthesizes a hygienic `decide.<rule>.<binding>` class for every inline
/// `decide -> { … } as <binding>`, injecting it into both the semantic schema
/// index (so field access / `case` type-check) and the IR (so the runtime
/// fixture can generate the anonymous shape). Mirrors the generated
/// `<Enum>.<Variant>` class synthesis for data-carrying sum-type variants.
fn collect_inline_decide_schemas(
    rules: &[(&RuleDecl, body::BodyAst)],
    semantic: &mut SemanticContext,
    ir: &mut IrProgram,
) {
    for (rule, body_ast) in rules {
        let mut decides = Vec::new();
        collect_decide_effects(&body_ast.statements, &mut decides);
        for (binding, fields, span) in decides {
            let name = inline_decide_schema_name(&rule.name.name, binding);
            // Build the field shape once as `TypeSyntax` (the schema-index form),
            // then lower it for the IR so both representations stay in lockstep.
            let mut syntax_fields: BTreeMap<String, TypeSyntax> = BTreeMap::new();
            let mut ir_fields = Vec::new();
            for (field_name, field_ty) in fields {
                let ty = decide_field_type_syntax(field_ty, span);
                ir_fields.push(IrClassField {
                    name: field_name.clone(),
                    ty: lower_type(ty.clone()),
                    is_key: false,
                    presence_condition: None,
                    span,
                });
                syntax_fields.insert(field_name.clone(), ty);
            }
            semantic.schemas.classes.insert(name.clone(), syntax_fields);
            ir.schemas.push(IrSchema::Class(IrClass {
                name,
                fields: ir_fields,
                span,
            }));
        }
    }
}

/// The hygienic synthetic class name for a `redact … as <binding>` projection:
/// `redact.<rule>.<binding>`, holding only the kept fields of the source schema.
pub fn redact_schema_name(rule: &str, binding: &str) -> String {
    format!("redact.{rule}.{binding}")
}

/// Collects every `redact <source> keep [..] as <binding>` in a rule body —
/// recursing through nested after/case/branch/handler blocks — for projected-type
/// synthesis, type registration, and IFC value-flow.
#[allow(clippy::type_complexity)]
fn collect_redact_effects<'a>(
    statements: &'a [body::BodyStmt],
    out: &mut Vec<(&'a str, &'a [String], &'a str, SourceSpan)>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Redact {
                source,
                keep,
                binding,
                span,
            } => out.push((source.as_str(), keep.as_slice(), binding.as_str(), *span)),
            body::BodyStmt::After(after) => collect_redact_effects(&after.body, out),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_redact_effects(&branch.body, out);
                }
            }
            _ => {}
        }
    }
}

/// Resolves binding -> schema name for a rule's redact SOURCES: `when Class as x`
/// matches, plus coerce/decide/exec result bindings. Used only to find the schema
/// a `redact` projects from, so the synthetic projected class copies the kept
/// fields' types. (`after`-alias sources are a documented follow-up; an
/// unresolved source surfaces as an empty projection + a `validate_redactions`
/// diagnostic.) Diagnostics from the reused collector are discarded — the real
/// pass re-emits them.
fn rule_binding_schemas(
    rule: &RuleDecl,
    body_ast: &body::BodyAst,
    semantic: &SemanticContext,
) -> BTreeMap<String, String> {
    let mut schemas = binding_types_for_rule(rule);
    let mut payloads = collect_effect_payload_types(rule, semantic, &mut Vec::new());
    collect_exec_payload_types(&body_ast.statements, semantic, &mut payloads);
    collect_decide_payload_types(&body_ast.statements, &rule.name.name, &mut payloads);
    collect_redact_payload_types(&body_ast.statements, &rule.name.name, &mut payloads);
    // `after <binding> <predicate> as <alias>` aliases the effect's completed
    // payload schema, so a `coerce … as c` then `after c succeeds as cust` then
    // `redact cust …` resolves (the primary read-then-redact flow). Only
    // payload-carrying predicates are mapped here; terminal predicates
    // (`times out`/`fails`) bind synthetic terminal schemas not usefully redacted.
    for line in rule.body.text.lines() {
        let Some(rest) = line.trim().strip_prefix("after ") else {
            continue;
        };
        let mut words = rest.split_whitespace();
        let Some(binding) = words.next() else {
            continue;
        };
        let Some(predicate) = words.next() else {
            continue;
        };
        if predicate == "times" && words.next() != Some("out") {
            continue;
        }
        let (Some("as"), Some(alias)) = (words.next(), words.next()) else {
            continue;
        };
        let alias = alias.trim_end_matches('{').trim();
        if alias.is_empty() {
            continue;
        }
        if let Some(IrType::Ref(schema)) = payloads.get(binding) {
            schemas.insert(alias.to_owned(), schema.clone());
        }
    }
    for (binding, ty) in payloads {
        if let IrType::Ref(schema) = ty {
            schemas.insert(binding, schema);
        }
    }
    schemas
}

/// Synthesizes a hygienic `redact.<rule>.<binding>` class for every
/// `redact <source> keep [..] as <binding>`, holding ONLY the kept fields of the
/// source schema (with their source types). This is what makes a redaction sound:
/// the projected binding cannot expose a dropped field (accessing one is a
/// type error, since it is absent from the synthetic class), so the lowered IFC
/// label the checker assigns the projection is honoured by the type system too.
/// Mirrors [`collect_inline_decide_schemas`]; run before the rule loop so
/// `analyze_rule` sees the class. A redact chained off an earlier redact's output
/// resolves via the local map built as the pass proceeds.
fn collect_redact_schemas(
    rules: &[(&RuleDecl, body::BodyAst)],
    semantic: &mut SemanticContext,
    ir: &mut IrProgram,
) {
    for (rule, body_ast) in rules {
        let mut redacts = Vec::new();
        collect_redact_effects(&body_ast.statements, &mut redacts);
        if redacts.is_empty() {
            continue;
        }
        let binding_schemas = rule_binding_schemas(rule, body_ast, semantic);
        let mut local: BTreeMap<String, String> = BTreeMap::new();
        for (source, keep, binding, span) in redacts {
            let name = redact_schema_name(&rule.name.name, binding);
            let source_schema = binding_schemas
                .get(source)
                .cloned()
                .or_else(|| local.get(source).cloned());
            // Clone the kept fields' types out of the source schema first, so the
            // immutable borrow ends before we insert the new class.
            let projected: Vec<(String, TypeSyntax)> = source_schema
                .as_ref()
                .and_then(|schema| semantic.schemas.classes.get(schema))
                .map(|src_fields| {
                    keep.iter()
                        .filter_map(|field| {
                            src_fields.get(field).map(|ty| (field.clone(), ty.clone()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut syntax_fields: BTreeMap<String, TypeSyntax> = BTreeMap::new();
            let mut ir_fields = Vec::new();
            for (field_name, ty) in &projected {
                syntax_fields.insert(field_name.clone(), ty.clone());
                ir_fields.push(IrClassField {
                    name: field_name.clone(),
                    ty: lower_type(ty.clone()),
                    is_key: false,
                    presence_condition: None,
                    span,
                });
            }
            semantic.schemas.classes.insert(name.clone(), syntax_fields);
            ir.schemas.push(IrSchema::Class(IrClass {
                name: name.clone(),
                fields: ir_fields,
                span,
            }));
            local.insert(binding.to_owned(), name);
        }
    }
}

/// Registers each `redact … as <binding>` result as `Ref(redact.<rule>.<binding>)`
/// so field access / `case` through the projection resolves against the kept-only
/// synthetic class (a dropped field is an unknown-field error). Mirrors
/// [`collect_decide_payload_types`].
fn collect_redact_payload_types(
    statements: &[body::BodyStmt],
    rule_name: &str,
    payloads: &mut BTreeMap<String, IrType>,
) {
    let mut redacts = Vec::new();
    collect_redact_effects(statements, &mut redacts);
    for (_source, _keep, binding, _span) in redacts {
        payloads.insert(
            binding.to_owned(),
            IrType::Ref(redact_schema_name(rule_name, binding)),
        );
    }
}

/// Validates each `redact <source> keep [..] as <out>`: the source must resolve to
/// a known schema, and every kept field must exist on it. Fail-closed — an
/// unresolvable source or unknown kept field is a hard error, so a redaction can
/// never silently project nothing (which would carry no data and mask a mistake).
fn validate_redactions(
    rule: &RuleDecl,
    statements: &[body::BodyStmt],
    semantic: &SemanticContext,
    binding_schemas: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut redacts = Vec::new();
    collect_redact_effects(statements, &mut redacts);
    let mut local: BTreeMap<String, String> = BTreeMap::new();
    for (source, keep, binding, span) in redacts {
        let source_schema = binding_schemas
            .get(source)
            .cloned()
            .or_else(|| local.get(source).cloned());
        local.insert(
            binding.to_owned(),
            redact_schema_name(&rule.name.name, binding),
        );
        let Some(schema) = source_schema else {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span,
                message: format!(
                    "rule `{}` redacts `{source}`, which has no known schema",
                    rule.name.name
                ),
                suggestion: Some(
                    "redact a binding with a known record type — a matched `when Class as x`, or a \
                     coerce/decide/exec result"
                        .to_owned(),
                ),
            });
            continue;
        };
        let Some(src_fields) = semantic.schemas.classes.get(&schema) else {
            continue;
        };
        for field in keep {
            if !src_fields.contains_key(field) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span,
                    message: format!(
                        "rule `{}` redacts `{source}` keeping unknown field `{field}` of `{schema}`",
                        rule.name.name
                    ),
                    suggestion: Some(format!("keep a field declared on `{schema}`")),
                });
            }
        }
    }
}

/// Registers the typed result of the single `exec "..." -> Schema as binding`
/// form so `after <binding> succeeds as r` resolves `r`'s fields — the same
/// after-binding type flow a named `coerce -> Schema` already gets. The
/// streaming `-> each Schema` form records one fact per element (not a single
/// bound value), so it is skipped here.
fn collect_exec_payload_types(
    statements: &[body::BodyStmt],
    semantic: &SemanticContext,
    payloads: &mut BTreeMap<String, IrType>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                if let body::BodyEffectKind::Exec {
                    parse_target: Some(parse),
                    ..
                } = &effect.kind
                {
                    if !parse.each {
                        if let Some(binding) = &effect.binding {
                            if semantic.schemas.class_exists(&parse.schema) {
                                payloads.insert(binding.clone(), IrType::Ref(parse.schema.clone()));
                            }
                        }
                    }
                }
            }
            body::BodyStmt::After(after) => {
                collect_exec_payload_types(&after.body, semantic, payloads)
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_exec_payload_types(&branch.body, semantic, payloads);
                }
            }
            _ => {}
        }
    }
}

/// DR-0074 §4, the load-bearing rule: **any value crossing from interpreter
/// memory into a durable record must be sealed or declassified first.**
///
/// Inside an `open`'s `after` block — the confinement region of §3 — the
/// plaintext binding and everything derived from it (§6) may be compared,
/// projected, iterated and interpolated freely, because none of that writes
/// anything down. What is refused is the crossing.
///
/// **Why this lives in the parser and not the IFC checker.** §4 says the rule
/// "mostly falls out of the existing lattice", and under a governed envelope it
/// does. But an envelope is optional under the gradual model, so a check that
/// lived only in the kernel would not run at all in ungoverned dev mode — and
/// plaintext reaching `facts.value_json` is not a policy question. Same
/// boundary Slice 1 settled for the grant classes: zero-setup floor here,
/// governed ceiling there.
///
/// **The crossings are derived from durability, not from a construct list.**
/// Three statement shapes write durably: a `record`, a terminal payload, and
/// ANY effect (§4: "Reaching anything outside whip means creating an effect,
/// and every effect records its input durably"). Enumerating effect *kinds*
/// would reopen the split-route hole; instead every effect is a crossing and
/// `collect_effect_binding_roots` is exhaustive over the kinds.
fn validate_confinement(
    rule: &RuleDecl,
    statements: &[body::BodyStmt],
    open_bindings: &BTreeSet<String>,
    confined: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    // Confinement ACCUMULATES down a block: a `redact` of plaintext produces a
    // further confined binding that later statements must not cross with, so
    // the set grows as the block is walked rather than being fixed on entry.
    let mut confined = confined.clone();
    let confined = &mut confined;
    for statement in statements {
        match statement {
            body::BodyStmt::Record(record) => {
                let mut roots = BTreeSet::new();
                collect_payload_field_roots(&record.fields, record.from.as_deref(), &mut roots);
                refuse_confined_crossing(
                    rule,
                    &roots,
                    confined,
                    record.span,
                    &format!("records `{}`", record.schema),
                    diagnostics,
                );
            }
            body::BodyStmt::Terminal(terminal) => {
                let mut roots = BTreeSet::new();
                collect_payload_field_roots(&terminal.fields, terminal.from.as_deref(), &mut roots);
                refuse_confined_crossing(
                    rule,
                    &roots,
                    confined,
                    terminal.span,
                    &format!("completes `{}`", terminal.name),
                    diagnostics,
                );
            }
            body::BodyStmt::Milestone {
                name, fields, span, ..
            } => {
                let mut roots = BTreeSet::new();
                collect_payload_field_roots(fields, None, &mut roots);
                refuse_confined_crossing(
                    rule,
                    &roots,
                    confined,
                    *span,
                    &format!("emits milestone `{name}`"),
                    diagnostics,
                );
            }
            body::BodyStmt::Effect(effect) => {
                let mut roots = BTreeSet::new();
                collect_effect_binding_roots(&effect.kind, &mut roots);
                if let Some(prompt) = &effect.prompt {
                    collect_template_binding_roots(&prompt.text, &mut roots);
                }
                refuse_confined_crossing(
                    rule,
                    &roots,
                    confined,
                    effect.span,
                    "creates an effect, whose input is durable,",
                    diagnostics,
                );
            }
            // A `redact` is a synchronous pure projection that never becomes an
            // effect, so it writes nothing down — but its RESULT still derives
            // from confined plaintext, so the confinement travels with it (§6).
            // It narrows a value; it does not release one.
            body::BodyStmt::Redact {
                source, binding, ..
            } => {
                if confined.contains(source.split('.').next().unwrap_or(source)) {
                    confined.insert(binding.clone());
                }
            }
            // `declassify` is §5's EXIT. Its result is deliberately NOT
            // confined: that is the whole point of a granted, audited crossing,
            // and a region with no exit satisfies §4 trivially. The bound on
            // what escapes is the target type, and the authority to do it at all
            // is governance's `grant declassify`, checked in the kernel.
            body::BodyStmt::Declassify { .. } => {}
            body::BodyStmt::After(after) => {
                let mut inner = confined.clone();
                // Entering the `after` block of an `open` is what opens a
                // region: its success alias IS the plaintext.
                if open_bindings.contains(&after.binding)
                    && matches!(
                        after.predicate,
                        body::AfterPredicate::Succeeds | body::AfterPredicate::Completes
                    )
                {
                    if let Some(alias) = &after.alias {
                        inner.insert(alias.clone());
                    }
                }
                validate_confinement(rule, &after.body, open_bindings, &inner, diagnostics);
            }
            body::BodyStmt::Case(case) => {
                // The scrutinee is a READ, not a crossing: §4 says in-region
                // plaintext may be compared freely. A branch alias binds part
                // of it, so the confinement follows into the arm.
                let mut roots = BTreeSet::new();
                if let Ok(expr) = parse_expression(&case.scrutinee) {
                    collect_expr_binding_roots(&expr, &mut roots);
                } else {
                    collect_template_binding_roots(&case.scrutinee, &mut roots);
                }
                let scrutinee_confined = roots.iter().any(|root| confined.contains(root));
                for branch in &case.branches {
                    let mut inner = confined.clone();
                    if scrutinee_confined {
                        if let Some(alias) = &branch.binding {
                            inner.insert(alias.clone());
                        }
                    }
                    validate_confinement(rule, &branch.body, open_bindings, &inner, diagnostics);
                }
            }
            body::BodyStmt::Region(region) => {
                validate_confinement(rule, &region.body, open_bindings, confined, diagnostics);
                validate_confinement(
                    rule,
                    &region.lapse_body,
                    open_bindings,
                    confined,
                    diagnostics,
                );
            }
            body::BodyStmt::Done { .. } | body::BodyStmt::Cancel { .. } => {}
        }
    }
}

/// The §4 refusal. Names the crossing, and offers the exits — including
/// `confine`, which the record's *Consequences* adds as a fourth resolution
/// beside `separate`, `cleared`, and `downgrade`: keep the work inside the
/// region and let only a sealed or declassified value out of it.
fn refuse_confined_crossing(
    rule: &RuleDecl,
    roots: &BTreeSet<String>,
    confined: &BTreeSet<String>,
    span: SourceSpan,
    what: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let leaked: Vec<&String> = roots
        .iter()
        .filter(|root| confined.contains(*root))
        .collect();
    let Some(first) = leaked.first() else {
        return;
    };
    diagnostics.push(Diagnostic {
        related: Vec::new(),
        span,
        message: format!(
            "rule `{}` {what} using `{first}`, which holds plaintext opened inside a \
             confinement region (DR-0074 §4: a value crossing into a durable record must be \
             sealed or declassified first)",
            rule.name.name
        ),
        suggestion: Some(
            "confine the work to the region and let only a converted value out: `seal` it \
             back to a `sealed<T>` and record that, or `declassify` it into a bounded type. \
             A value derived from opened plaintext is itself confined (§6)"
                .to_owned(),
        ),
    });
}

/// The bindings of every `open` in a rule body, at any depth — the effects
/// whose `after` block is a confinement region.
fn collect_open_bindings(statements: &[body::BodyStmt], out: &mut BTreeSet<String>) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                if let body::BodyEffectKind::ConstructCapabilityCall {
                    target_capability, ..
                } = &effect.kind
                {
                    if target_capability == CUSTODY_UNWRAP_CAPABILITY {
                        if let Some(binding) = &effect.binding {
                            out.insert(binding.clone());
                        }
                    }
                }
            }
            body::BodyStmt::After(after) => collect_open_bindings(&after.body, out),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_open_bindings(&branch.body, out);
                }
            }
            body::BodyStmt::Region(region) => {
                collect_open_bindings(&region.body, out);
                collect_open_bindings(&region.lapse_body, out);
            }
            _ => {}
        }
    }
}

/// Every binding root an EFFECT references, whatever its kind.
///
/// §4's rule is about the RECORD, not the construct: "Reaching anything outside
/// whip means creating an effect, and every effect records its input durably."
/// So the confinement check needs one question answered uniformly for all
/// twenty-three effect kinds — which bindings does this effect carry into its
/// durable outbox row?
///
/// The match is deliberately EXHAUSTIVE with no `_` arm. A new effect kind is
/// a new durable crossing, and the split-route hole §4 describes is exactly
/// what a wildcard arm would reopen: one route checked, another reaching the
/// same table unchecked. Adding a variant must fail to compile here.
fn collect_effect_binding_roots(kind: &body::BodyEffectKind, out: &mut BTreeSet<String>) {
    let mut sources = Vec::new();
    collect_effect_expression_sources(kind, &mut sources);
    for text in &sources {
        if let Ok(expr) = parse_expression(text) {
            collect_expr_binding_roots(&expr, out);
        } else {
            collect_template_binding_roots(text, out);
        }
    }
}

/// Every expression SOURCE an effect carries into its durable input, whatever
/// its kind — the one exhaustive walk over the twenty-three effect kinds.
///
/// [`collect_effect_binding_roots`] is derived from this rather than repeating
/// the match, because two exhaustive walks over the same enum is the shape that
/// produced DR-0075: they agree on the day they are written and drift after.
/// One owner, two questions asked of it — which bindings does this effect carry
/// (the §4 crossing rule), and what does each of them resolve to (the sealed
/// input check).
///
/// Exhaustive with no `_` arm, deliberately: a new effect kind is a new durable
/// input, and adding one must fail to compile here.
fn collect_effect_expression_sources(kind: &body::BodyEffectKind, out: &mut Vec<String>) {
    let source = |text: &str, out: &mut Vec<String>| out.push(text.to_owned());
    let fields = |fields: &[body::FieldAssign], out: &mut Vec<String>| {
        for field in fields {
            if let body::FieldValue::Expr { source, .. } = &field.value {
                out.push(source.clone());
            }
        }
    };
    match kind {
        // A turn carries its prompt (collected by the caller from
        // `EffectStmt::prompt`) and its target; the target is an agent name,
        // not a binding.
        body::BodyEffectKind::Tell { on_stream, .. } => {
            if let Some(stream) = on_stream {
                source(stream, out);
            }
        }
        body::BodyEffectKind::Coerce { args, .. } => {
            for arg in args {
                source(arg, out);
            }
        }
        // The prompt text is the input; the caller adds it for every effect.
        body::BodyEffectKind::Prompt { .. } | body::BodyEffectKind::Decide { .. } => {}
        body::BodyEffectKind::Call { argument, .. } => {
            if let Some(argument) = argument {
                source(argument, out);
            }
        }
        body::BodyEffectKind::ConstructCapabilityCall { fields, .. } => {
            for field in fields {
                source(&field.source, out);
            }
        }
        body::BodyEffectKind::Invoke { payload, .. } => fields(payload, out),
        body::BodyEffectKind::Timer { until, .. } => {
            if let Some(until) = until {
                source(until, out);
            }
        }
        body::BodyEffectKind::HttpRequest {
            url, headers, body, ..
        } => {
            source(url, out);
            for header in headers {
                // A credential header is a MARKED SLOT the custodian fills
                // (DR-0053 §5); it carries a handle, never a binding.
                if let body::RequestHeaderValue::Expr { source: text, .. } = &header.value {
                    out.push(text.clone());
                }
            }
            if let Some((text, _)) = body {
                out.push(text.clone());
            }
        }
        // A mint's exchange reaches the same durable outbox row a request's
        // does, and carries the same shapes.
        body::BodyEffectKind::MintCredential {
            url, headers, body, ..
        } => {
            source(url, out);
            for header in headers {
                // A credential header is a MARKED SLOT the custodian fills
                // (DR-0053 §5); it carries a handle, never a binding.
                if let body::RequestHeaderValue::Expr { source: text, .. } = &header.value {
                    out.push(text.clone());
                }
            }
            if let Some((text, _)) = body {
                out.push(text.clone());
            }
        }
        body::BodyEffectKind::Exec { target, .. } => match target {
            body::ExecTarget::RawCommand(command) => source(command, out),
            body::ExecTarget::Capability { stdin_binding, .. } => {
                out.push(stdin_binding.clone());
            }
        },
        body::BodyEffectKind::TrackerFile { fields: f, .. } => fields(f, out),
        // An escalation's title and body reach the same durable tracker row a
        // `file issue` does. The credential is a declared HANDLE, not a
        // binding, and carries nothing of the run into the record.
        body::BodyEffectKind::ObtainCredential { fields: f, .. } => fields(f, out),
        body::BodyEffectKind::TrackerClaim { item, .. }
        | body::BodyEffectKind::TrackerRelease { item } => source(item, out),
        body::BodyEffectKind::TrackerFinish { item, fields: f } => {
            source(item, out);
            fields(f, out);
        }
        body::BodyEffectKind::LeaseAcquire { key_expr, .. } => source(key_expr, out),
        body::BodyEffectKind::LeaseRenew {
            acquire_binding, ..
        } => {
            out.push(acquire_binding.clone());
        }
        body::BodyEffectKind::LedgerAppend { fields: f, .. } => fields(f, out),
        body::BodyEffectKind::CounterConsume {
            key_expr,
            amount_expr,
            ..
        } => {
            source(key_expr, out);
            source(amount_expr, out);
        }
        body::BodyEffectKind::Notify {
            target_expr,
            from,
            fields: f,
            ..
        } => {
            source(target_expr, out);
            if let Some(from) = from {
                out.push(from.clone());
            }
            fields(f, out);
        }
        body::BodyEffectKind::FileRead { path, .. } => source(path, out),
        body::BodyEffectKind::FileWrite { path, body, .. } => {
            source(path, out);
            source(body, out);
        }
        body::BodyEffectKind::FileImport { path, .. } => source(path, out),
        body::BodyEffectKind::FileExport {
            path, predicate, ..
        } => {
            source(path, out);
            if let Some(predicate) = predicate {
                source(predicate, out);
            }
        }
    }
}

/// DR-0074 §10: a `seal` produces a `sealed<T>` value, where `T` is the
/// declared type of what was sealed. Without this the envelope has nowhere to
/// go — a `sealed<PatientRecord>` field refuses the binding — so `seal` could
/// be written but its result could never be stored, which is the whole point
/// of sealing.
///
/// The payload type is read from the sealed EXPRESSION rather than from an
/// ascription, because the surface has no type slot: Slice 1 dropped it so the
/// binding could be spelled `as`. An expression whose type does not resolve
/// leaves the binding untyped rather than guessing.
fn collect_seal_payload_types(
    statements: &[body::BodyStmt],
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    payloads: &mut BTreeMap<String, String>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                let body::BodyEffectKind::ConstructCapabilityCall {
                    target_capability,
                    fields,
                    ..
                } = &effect.kind
                else {
                    continue;
                };
                if target_capability != CUSTODY_WRAP_CAPABILITY {
                    continue;
                }
                let (Some(binding), Some(value)) = (
                    effect.binding.as_ref(),
                    fields
                        .iter()
                        .find(|field| field.name == SEAL_VALUE_SLOT)
                        .map(|field| field.source.trim()),
                ) else {
                    continue;
                };
                let root = value.split('.').next().unwrap_or(value);
                let Some(root_schema) = binding_types.get(root) else {
                    continue;
                };
                let path: Vec<String> = value.split('.').skip(1).map(str::to_owned).collect();
                // Compared as SOURCE TEXT so a sealed primitive is tracked
                // too: `sealed<string>` is as legal as `sealed<PatientRecord>`,
                // and a collector that only understood class references would
                // silently skip exactly the cases with no other check.
                let Ok(resolved) = semantic.schemas.resolve_field_path(root_schema, &path) else {
                    continue;
                };
                payloads.insert(binding.clone(), resolved.to_source());
            }
            body::BodyStmt::After(after) => {
                // The success alias IS the envelope, so it carries the same
                // payload type as the `seal` binding it came from.
                if let (Some(alias), Some(sealed_as)) =
                    (after.alias.as_ref(), payloads.get(&after.binding).cloned())
                {
                    payloads.insert(alias.clone(), sealed_as);
                }
                collect_seal_payload_types(&after.body, semantic, binding_types, payloads)
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_seal_payload_types(&branch.body, semantic, binding_types, payloads);
                }
            }
            body::BodyStmt::Region(region) => {
                collect_seal_payload_types(&region.body, semantic, binding_types, payloads);
                collect_seal_payload_types(&region.lapse_body, semantic, binding_types, payloads);
            }
            _ => {}
        }
    }
}

/// A `seal`'s envelope may only be stored in a `sealed<T>` field whose `T` is
/// the type that was actually sealed.
///
/// Without this a `seal claim.id` (a string) lands happily in a
/// `sealed<PatientRecord>` field, and the mismatch surfaces only at `open` —
/// where DR-0074 §3's obligation-3 check trusts the FIELD's declared type and
/// therefore asks the custodian for a grant on a type the bytes were never
/// sealed as. The three-way agreement §2 depends on is only as good as the
/// weakest of the three.
fn validate_seal_storage(
    rule: &RuleDecl,
    statements: &[body::BodyStmt],
    semantic: &SemanticContext,
    sealed_bindings: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Record(record) => {
                for field in &record.fields {
                    let body::FieldValue::Expr { source, .. } = &field.value else {
                        continue;
                    };
                    let Some(sealed_as) = sealed_bindings.get(source.trim()) else {
                        continue;
                    };
                    let Ok(TypeSyntax::Sealed { inner, .. }) = semantic
                        .schemas
                        .resolve_field_path(&record.schema, std::slice::from_ref(&field.name))
                    else {
                        continue;
                    };
                    let expected = inner.to_source();
                    if expected == *sealed_as {
                        continue;
                    }
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: field.span,
                        message: format!(
                            "rule `{}` stores `{}` in `{}.{}`, which expects \
                             `sealed<{}>` — it was sealed as `sealed<{sealed_as}>`",
                            rule.name.name,
                            source.trim(),
                            record.schema,
                            field.name,
                            expected
                        ),
                        suggestion: Some(
                            "seal the value the field's payload type names; `open` later trusts \
                             that declaration to choose the unwrap grant (DR-0074 §2)"
                                .to_owned(),
                        ),
                    });
                }
            }
            body::BodyStmt::After(after) => {
                validate_seal_storage(rule, &after.body, semantic, sealed_bindings, diagnostics)
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    validate_seal_storage(
                        rule,
                        &branch.body,
                        semantic,
                        sealed_bindings,
                        diagnostics,
                    );
                }
            }
            body::BodyStmt::Region(region) => {
                validate_seal_storage(rule, &region.body, semantic, sealed_bindings, diagnostics);
                validate_seal_storage(
                    rule,
                    &region.lapse_body,
                    semantic,
                    sealed_bindings,
                    diagnostics,
                );
            }
            _ => {}
        }
    }
}

/// `declassify <source> into <Type> as <binding>` types `binding` at `<Type>`.
/// Unlike `redact`, which synthesizes a projected class from a kept-field list,
/// the target here is a class the program already declares — so there is
/// nothing to synthesize and the release's shape is reviewable in the source.
fn collect_declassify_payload_types(
    statements: &[body::BodyStmt],
    semantic: &SemanticContext,
    payloads: &mut BTreeMap<String, IrType>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Declassify {
                target_type,
                binding,
                ..
            } if semantic.schemas.class_exists(target_type) => {
                payloads.insert(binding.clone(), IrType::Ref(target_type.clone()));
            }
            body::BodyStmt::After(after) => {
                collect_declassify_payload_types(&after.body, semantic, payloads)
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_declassify_payload_types(&branch.body, semantic, payloads);
                }
            }
            body::BodyStmt::Region(region) => {
                collect_declassify_payload_types(&region.body, semantic, payloads);
                collect_declassify_payload_types(&region.lapse_body, semantic, payloads);
            }
            _ => {}
        }
    }
}

/// The target type of a `declassify` is the BOUND on the release, so it has to
/// be a real projection of the source rather than an assertion about it.
///
/// DR-0074 §5 and `docs/providers.md` both make this the whole control: a
/// `Receipt` of `{approved bool, amount Money}` is a genuine bound, while one
/// carrying a free-text field the model wrote "is an open channel with extra
/// steps". A target naming a field the source does not have is neither — it is
/// a release whose shape nothing checks, which is the decorative-mechanism
/// failure DR-0053 §14's grant classes exist to avoid.
fn validate_declassify_projection(
    rule: &RuleDecl,
    statements: &[body::BodyStmt],
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Declassify {
                source,
                target_type,
                span,
                ..
            } => {
                if !semantic.schemas.class_exists(target_type) {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: *span,
                        message: format!(
                            "rule `{}` declassifies into `{target_type}`, which is not a \
                             declared class",
                            rule.name.name
                        ),
                        suggestion: Some(
                            "declare the bounded type the release is narrowed to".to_owned(),
                        ),
                    });
                    continue;
                }
                let root = source.split('.').next().unwrap_or(source);
                let Some(source_schema) = binding_types.get(root) else {
                    continue;
                };
                let mut rest = source.split('.').skip(1).map(str::to_owned).peekable();
                let path: Vec<String> = rest.by_ref().collect();
                let Ok(resolved) = semantic.schemas.resolve_field_path(source_schema, &path) else {
                    continue;
                };
                let TypeSyntax::Ref { name: from } = resolved else {
                    continue;
                };
                let Some(target_fields) = semantic.schemas.classes.get(target_type) else {
                    continue;
                };
                for field in target_fields.keys() {
                    if semantic
                        .schemas
                        .resolve_field_path(&from.name, std::slice::from_ref(field))
                        .is_err()
                    {
                        diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: *span,
                            message: format!(
                                "rule `{}` declassifies `{source}` into `{target_type}`, which \
                                 declares `{field}` — a field `{}` does not have",
                                rule.name.name, from.name
                            ),
                            suggestion: Some(format!(
                                "`declassify` projects onto the target type's fields, so every \
                                 field of `{target_type}` must exist on `{}`; the target type is \
                                 the bound on what is released",
                                from.name
                            )),
                        });
                    }
                }
            }
            body::BodyStmt::After(after) => validate_declassify_projection(
                rule,
                &after.body,
                semantic,
                binding_types,
                diagnostics,
            ),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    validate_declassify_projection(
                        rule,
                        &branch.body,
                        semantic,
                        binding_types,
                        diagnostics,
                    );
                }
            }
            body::BodyStmt::Region(region) => {
                validate_declassify_projection(
                    rule,
                    &region.body,
                    semantic,
                    binding_types,
                    diagnostics,
                );
                validate_declassify_projection(
                    rule,
                    &region.lapse_body,
                    semantic,
                    binding_types,
                    diagnostics,
                );
            }
            _ => {}
        }
    }
}

/// DR-0074 §3, obligation 3: the `into <Type>` must match the envelope's own
/// `sealed<T>`. **All three agreeing is what makes the grant meaningful** — the
/// envelope's type, the `into` type, and the grant's type. This validator owns
/// the first pair, which is the only one answerable without a policy: the grant
/// side is checked against the turn's own scoping here too, and against the
/// signed envelope in the kernel, where governance lives.
///
/// A mismatch is not a cast. `open <sealed<A>> into B` asks the custodian for a
/// grant on B while handing it an A, so it would either fail at runtime or —
/// worse, if a grant on B existed — open bytes under an authorisation that was
/// never about them.
fn validate_open_type_agreement(
    rule: &RuleDecl,
    statements: &[body::BodyStmt],
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                let body::BodyEffectKind::ConstructCapabilityCall {
                    target_capability,
                    fields,
                    ..
                } = &effect.kind
                else {
                    continue;
                };
                if target_capability != CUSTODY_UNWRAP_CAPABILITY {
                    continue;
                }
                let slot = |name: &str| {
                    fields
                        .iter()
                        .find(|field| field.name == name)
                        .map(|field| field.source.trim())
                };
                let (Some(envelope), Some(declared)) =
                    (slot(OPEN_ENVELOPE_SLOT), slot(OPEN_PAYLOAD_TYPE_SLOT))
                else {
                    continue;
                };
                // Only a resolvable dotted read carries a declared type. A
                // literal or a computed expression has no `sealed<T>` to
                // compare against, and inventing an answer for it would report
                // a mismatch the source does not contain.
                let mut parts = envelope.split('.');
                let (Some(root), rest) =
                    (parts.next(), parts.map(str::to_owned).collect::<Vec<_>>())
                else {
                    continue;
                };
                let Some(root_schema) = binding_types.get(root) else {
                    continue;
                };
                let Ok(resolved) = semantic.schemas.resolve_field_path(root_schema, &rest) else {
                    continue;
                };
                let TypeSyntax::Sealed { inner, .. } = resolved else {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: effect.span,
                        message: format!(
                            "rule `{}` opens `{envelope}`, which is not a sealed value",
                            rule.name.name
                        ),
                        suggestion: Some(
                            "`open` takes a `sealed<T>`; seal the value first, or read the field \
                             that holds the envelope"
                                .to_owned(),
                        ),
                    });
                    continue;
                };
                let TypeSyntax::Ref { name: sealed_type } = *inner else {
                    continue;
                };
                if sealed_type.name == declared {
                    continue;
                }
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: effect.span,
                    message: format!(
                        "rule `{}` opens `{envelope}` into `{declared}`, but it is sealed as \
                         `sealed<{}>`",
                        rule.name.name, sealed_type.name
                    ),
                    suggestion: Some(format!(
                        "open it into `{}`; `into` names the type the envelope already holds, \
                         and it is what the unwrap grant is narrowed by (DR-0074 §2)",
                        sealed_type.name
                    )),
                });
            }
            body::BodyStmt::After(after) => validate_open_type_agreement(
                rule,
                &after.body,
                semantic,
                binding_types,
                diagnostics,
            ),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    validate_open_type_agreement(
                        rule,
                        &branch.body,
                        semantic,
                        binding_types,
                        diagnostics,
                    );
                }
            }
            _ => {}
        }
    }
}

/// DR-0074 §3: an `open` binds its plaintext at the type named by `into
/// <Type>`, so `after <opening> succeeds as patient` types `patient` as that
/// class and `patient.<field>` resolves like any other typed binding.
///
/// Keyed on the construct's TARGET CAPABILITY rather than on the `open`
/// keyword. The keyword belongs to a package manifest and could be spelled
/// differently by another one; `custody.unwrap` is the operation this typing
/// rule is actually about, and the generated grammar table carries it, so the
/// manifest stays the single source of both the parse and this.
fn collect_open_payload_types(
    statements: &[body::BodyStmt],
    semantic: &SemanticContext,
    payloads: &mut BTreeMap<String, IrType>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                if let body::BodyEffectKind::ConstructCapabilityCall {
                    target_capability,
                    fields,
                    ..
                } = &effect.kind
                {
                    if target_capability != CUSTODY_UNWRAP_CAPABILITY {
                        continue;
                    }
                    let (Some(binding), Some(payload_type)) = (
                        effect.binding.as_ref(),
                        fields
                            .iter()
                            .find(|field| field.name == OPEN_PAYLOAD_TYPE_SLOT)
                            .map(|field| field.source.trim()),
                    ) else {
                        continue;
                    };
                    // An unknown class is the type-reference check's diagnostic,
                    // not this collector's; leaving the binding untyped here
                    // would turn one error into a second, confusing one about a
                    // field on a schema that does not exist.
                    if semantic.schemas.class_exists(payload_type) {
                        payloads.insert(binding.clone(), IrType::Ref(payload_type.to_owned()));
                    }
                }
            }
            body::BodyStmt::After(after) => {
                collect_open_payload_types(&after.body, semantic, payloads)
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    collect_open_payload_types(&branch.body, semantic, payloads);
                }
            }
            _ => {}
        }
    }
}

/// Collects the schemas an `exec ... -> each` stream records as facts.
/// The facts a rule body RECORDS and CONSUMES, walked over the parsed body.
///
/// `metadata.effects` moved to an AST walk (`collect_effects_from_ast`) and left
/// records and consumes behind on the line scanner in `analyze_rule`, which
/// requires `record` or `done` to begin a TRIMMED line. So a statement written
/// inside its enclosing block on one line —
/// `after t completes { done j -> record Finished { id j.id } }` — contributed
/// neither a write nor a consume, while the identical program across three lines
/// contributed both. The scanner sees the `after`, opens a block frame and moves
/// to the next line; the rest of that line is never read.
///
/// That is not a formatting nicety, because the write set is load-bearing three
/// times over. `record` is a governed information-flow sink (`fact:<Schema>`),
/// and an inline record of confidential data passed the flow checker with ZERO
/// violations while the multi-line form was denied — a fail-OPEN hole, opened by
/// a line break. The write set is also what `build_rule_dependencies` turns into
/// edges, so an inline record is invisible to `graph.unbounded_effect_recursion`
/// and to the self-trigger check. And its absence raises a false
/// "nothing produces `<X>`" against a rule that reads what it records.
fn collect_record_and_consume_facts(
    statements: &[body::BodyStmt],
    binding_types: &BTreeMap<String, String>,
    fact_writes: &mut Vec<String>,
    fact_consumes: &mut Vec<String>,
) {
    let recurse = |statements: &[body::BodyStmt],
                   fact_writes: &mut Vec<String>,
                   fact_consumes: &mut Vec<String>| {
        collect_record_and_consume_facts(statements, binding_types, fact_writes, fact_consumes);
    };
    for statement in statements {
        match statement {
            body::BodyStmt::Record(record) => {
                fact_writes.push(format!("schema:{}", record.schema));
            }
            body::BodyStmt::Done {
                binding,
                replacement,
                ..
            } => {
                // An unknown binding is the line scanner's diagnostic to make;
                // silence here means "not a fact consume", not "unreported".
                if let Some(schema) = binding_types.get(binding) {
                    fact_consumes.push(format!("schema:{schema}"));
                }
                if let Some(record) = replacement {
                    fact_writes.push(format!("schema:{}", record.schema));
                }
            }
            body::BodyStmt::After(after) => recurse(&after.body, fact_writes, fact_consumes),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    recurse(&branch.body, fact_writes, fact_consumes);
                }
            }
            body::BodyStmt::Region(region) => {
                recurse(&region.body, fact_writes, fact_consumes);
                recurse(&region.lapse_body, fact_writes, fact_consumes);
            }
            _ => {}
        }
    }
}

/// Every `record <Schema>` in a rule body names a class the program declares and
/// does not name a kernel-owned terminal schema.
///
/// Walked over the parsed body for the reason `collect_record_and_consume_facts`
/// is: the line scanner in `analyze_rule` cannot see a record that shares a line
/// with the block enclosing it, so `after t completes { record NoSuchClass { … } }`
/// compiled clean while the same record on its own line was refused. A refusal a
/// line break escapes is not a refusal.
///
/// The span is the record statement's own, which is better than the whole-body
/// span the scanner could offer.
fn validate_recorded_schemas(
    rule: &RuleDecl,
    statements: &[body::BodyStmt],
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        let recorded = match statement {
            body::BodyStmt::Record(record) => Some(record),
            body::BodyStmt::Done {
                replacement: Some(record),
                ..
            } => Some(record),
            _ => None,
        };
        if let Some(record) = recorded {
            let schema = &record.schema;
            if is_observer_only_schema(schema) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: record.span,
                    message: format!(
                        "rule `{}` cannot record kernel-owned terminal schema `{schema}`",
                        rule.name.name
                    ),
                    suggestion: Some(
                        "the terminal family (`TerminalFailed`/`TerminalTimedOut`/`TerminalCancelled`) is produced only by the kernel; to fail this workflow use `fail <failure> { ... }`, and to react to an effect terminal use `after <effect> fails/times out/cancels as f`"
                            .to_owned(),
                    ),
                });
            } else if !semantic.schemas.class_exists(schema) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: record.span,
                    message: format!("rule `{}` records unknown class `{schema}`", rule.name.name),
                    suggestion: Some(format!("declare `class {schema}` before recording it")),
                });
            }
        }
        match statement {
            body::BodyStmt::After(after) => {
                validate_recorded_schemas(rule, &after.body, semantic, diagnostics);
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    validate_recorded_schemas(rule, &branch.body, semantic, diagnostics);
                }
            }
            body::BodyStmt::Region(region) => {
                validate_recorded_schemas(rule, &region.body, semantic, diagnostics);
                validate_recorded_schemas(rule, &region.lapse_body, semantic, diagnostics);
            }
            _ => {}
        }
    }
}

fn push_ingest_fact_writes(statements: &[body::BodyStmt], fact_writes: &mut Vec<String>) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                match &effect.kind {
                    body::BodyEffectKind::Exec {
                        parse_target: Some(parse),
                        ..
                    } if parse.each => {
                        fact_writes.push(format!("schema:{}", parse.schema));
                    }
                    // `import <fmt> <Schema>` admits one `<Schema>` fact per row
                    // (spec/std-library/files.md), so a `when <Schema>` rule has a
                    // producer for liveness/effect-graph analysis.
                    body::BodyEffectKind::FileImport { schema, .. } => {
                        fact_writes.push(format!("schema:{schema}"));
                    }
                    _ => {}
                }
            }
            body::BodyStmt::After(after) => push_ingest_fact_writes(&after.body, fact_writes),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    push_ingest_fact_writes(&branch.body, fact_writes);
                }
            }
            // A region body is a container like the other two, and was missed
            // for the same reason a container is always missed: nothing makes a
            // walk enumerate them.
            body::BodyStmt::Region(region) => {
                push_ingest_fact_writes(&region.body, fact_writes);
                push_ingest_fact_writes(&region.lapse_body, fact_writes);
            }
            _ => {}
        }
    }
}

/// Body-effect operand checks that need schema knowledge:
/// - `timer until <operand>`: a non-literal operand must be a dotted path
///   resolving to a `time`-typed field (spec/scheduled-time.md). Literals were
///   format-validated by the body parser, so anything that still looks like an
///   instant here is a valid literal and passes.
/// - `exec ... -> Schema` / `-> each Schema`: the parse target must name a
///   declared class (spec/json-ingestion.md).
///
/// The coordination safety model (spec/coordination.md): at most one held
/// lease per progression (hard default), exhaustive outcome handling, and
/// the linear must-release discipline (instance terminals auto-release, so
/// a path that ends in `complete`/`fail` is safe without an explicit
/// `release`).
fn validate_coordination_discipline(
    rule: &RuleDecl,
    statements: &[body::BodyStmt],
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut acquires = Vec::new();
    let mut consumes = Vec::new();
    let mut claims = Vec::new();
    collect_coordination_effects(statements, &mut acquires, &mut consumes, &mut claims);

    // std.vcs completion-valued verbs (DR-0052): promote, undo, and
    // transport are exhaustive exactly like acquire — an unwritten
    // refusal arm is a workflow with no policy at the refusal.
    let mut vcs_verbs: Vec<(&'static str, [&'static str; 2], String, SourceSpan)> = Vec::new();
    for_each_body(statements, &mut |stmt| {
        if let body::BodyStmt::Effect(effect) = stmt {
            if let body::BodyEffectKind::ConstructCapabilityCall { keyword, .. } = &effect.kind {
                let arms: Option<(&'static str, [&'static str; 2])> = match keyword.as_str() {
                    "promote" => Some(("promote", ["promoted", "conflicted"])),
                    "undo" => Some(("undo", ["applied", "stranded"])),
                    "transport" => Some(("transport", ["applied", "conflicted"])),
                    _ => None,
                };
                if let (Some((verb, required)), Some(binding)) = (arms, &effect.binding) {
                    vcs_verbs.push((verb, required, binding.clone(), effect.span));
                }
            }
        }
    });
    for (verb, required_arms, binding, span) in &vcs_verbs {
        let mut predicates = BTreeSet::new();
        collect_after_predicates(statements, binding, &mut predicates);
        for required in required_arms {
            if !predicates.contains(*required) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: *span,
                    message: format!(
                        "rule `{}` does not handle the `{required}` outcome of {verb} `{binding}`",
                        rule.name.name
                    ),
                    suggestion: Some(format!(
                        "{verb} outcomes are exhaustive: add `after {binding} {required} {{ ... }}`"
                    )),
                });
            }
        }
    }

    // A `renew <binding>` names ONE OF TWO legitimate referents (T3, mirroring
    // the `release` disambiguation below):
    //   (1) an `acquire ... as <binding>` LEASE binding acquired in this rule —
    //       lowers to `lease.renew` (std.coord); resolves the acquire's recorded
    //       resource/key at runtime;
    //   (2) a `claim <issue> as <binding>` CLAIM binding claimed in this rule —
    //       lowers to `tracker.renew` (std.tracker); resolves the claimed issue
    //       id from the claim's output fact.
    // A `renew <binding>` naming NEITHER renews nothing, so catch the typo at
    // `whip check`. (Scoped to `renew`, which is new.)
    let claim_bindings = collect_claim_bindings(statements);
    let renewable: BTreeSet<&str> = acquires
        .iter()
        .map(|(b, _, _)| b.as_str())
        .chain(claim_bindings.iter().map(String::as_str))
        .collect();
    for_each_body(statements, &mut |stmt| {
        if let body::BodyStmt::Effect(effect) = stmt {
            if let body::BodyEffectKind::LeaseRenew {
                acquire_binding, ..
            } = &effect.kind
            {
                if !renewable.contains(acquire_binding.as_str()) {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: effect.span,
                        message: format!(
                            "rule `{}` renews unbound coordination binding `{}`",
                            rule.name.name, acquire_binding
                        ),
                        suggestion: Some(format!(
                            "`renew {acquire_binding}` must name a lease acquired here (`acquire ... as {acquire_binding}`) or an issue claimed here (`claim ... as {acquire_binding}`)"
                        )),
                    });
                }
            }
        }
    });

    // A `release <x>` names ONE OF THREE legitimate referents (spec/coordination.md,
    // verified against the corpus + the rule-body matrix test):
    //   (1) an `acquire ... as <x>` LEASE binding acquired in this rule;
    //   (2) a `claim <x> as ...` — the *item* being claimed (the `TrackerClaim.item`,
    //       NOT the claim's `as` binding);
    //   (3) a `when <queue> has ready <x> as <x>` WORK-ITEM binding, released
    //       without a same-rule claim.
    // A naive `acquire ∪ claim-binding` model false-positives forms (2) and (3);
    // admit exactly these three and flag a `release <x>` that matches none as a
    // genuinely-unbound release. Scoped per-rule like the `renew` check above.
    let work_items: Vec<String> = rule
        .whens
        .iter()
        .filter_map(|when| when_has_ready_binding(&when.text))
        .collect();
    let releasable: BTreeSet<&str> = acquires
        .iter()
        .map(|(b, _, _)| b.as_str())
        .chain(claims.iter().map(|(item, _)| item.as_str()))
        .chain(work_items.iter().map(String::as_str))
        .collect();
    for_each_body(statements, &mut |stmt| {
        if let body::BodyStmt::Effect(effect) = stmt {
            if let body::BodyEffectKind::TrackerRelease { item } = &effect.kind {
                if !releasable.contains(item.as_str()) {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: effect.span,
                        message: format!(
                            "rule `{}` releases unbound coordination item `{}`",
                            rule.name.name, item
                        ),
                        suggestion: Some(format!(
                            "`release {item}` must name a lease acquired here (`acquire ... as {item}`), an item claimed here (`claim {item} as ...`), or a work item bound by a `when <queue> has ready ... as {item}` reaction"
                        )),
                    });
                }
            }
        }
    });

    if acquires.len() > 1 {
        diagnostics.push(Diagnostic { related: Vec::new(),
            span: acquires[1].2,
            message: format!(
                "rule `{}` acquires more than one lease in a single progression",
                rule.name.name
            ),
            suggestion: Some(
                "the hard default is at most one held lease per progression (it breaks hold-and-wait); restructure into separate rules"
                    .to_owned(),
            ),
        });
    }
    for (binding, until_ttl, span) in &acquires {
        if *until_ttl {
            continue;
        }
        let mut predicates = BTreeSet::new();
        collect_after_predicates(statements, binding, &mut predicates);
        for required in ["held", "contended"] {
            if !predicates.contains(required) {
                diagnostics.push(Diagnostic { related: Vec::new(),
                    span: *span,
                    message: format!(
                        "rule `{}` does not handle the `{required}` outcome of lease `{binding}`",
                        rule.name.name
                    ),
                    suggestion: Some(format!(
                        "coordination outcomes are exhaustive: add `after {binding} {required} {{ ... }}`"
                    )),
                });
            }
        }
        if let Some(held_body) = find_after_body(statements, binding, body::AfterPredicate::Held) {
            if !releases_or_terminates(held_body, binding) {
                diagnostics.push(Diagnostic { related: Vec::new(),
                    span: *span,
                    message: format!(
                        "rule `{}` can hold lease `{binding}` forever: the `held` branch neither releases it nor reaches a workflow terminal",
                        rule.name.name
                    ),
                    suggestion: Some(format!(
                        "add `release {binding}` on every non-terminal path, or use `acquire ... until ttl` for fire-and-forget"
                    )),
                });
            }
        }
    }
    for (binding, span) in &consumes {
        let mut predicates = BTreeSet::new();
        collect_after_predicates(statements, binding, &mut predicates);
        for required in ["ok", "over"] {
            if !predicates.contains(required) {
                diagnostics.push(Diagnostic { related: Vec::new(),
                    span: *span,
                    message: format!(
                        "rule `{}` does not handle the `{required}` outcome of counter consume `{binding}`",
                        rule.name.name
                    ),
                    suggestion: Some(format!(
                        "coordination outcomes are exhaustive: add `after {binding} {required} {{ ... }}`"
                    )),
                });
            }
        }
    }
}

fn collect_coordination_effects(
    statements: &[body::BodyStmt],
    acquires: &mut Vec<(String, bool, SourceSpan)>,
    consumes: &mut Vec<(String, SourceSpan)>,
    claims: &mut Vec<(String, SourceSpan)>,
) {
    for_each_body(statements, &mut |stmt| {
        if let body::BodyStmt::Effect(effect) = stmt {
            match &effect.kind {
                body::BodyEffectKind::LeaseAcquire { until_ttl, .. } => {
                    if let Some(binding) = &effect.binding {
                        acquires.push((binding.clone(), *until_ttl, effect.span));
                    }
                }
                body::BodyEffectKind::CounterConsume { .. } => {
                    if let Some(binding) = &effect.binding {
                        consumes.push((binding.clone(), effect.span));
                    }
                }
                // A `claim <item> as <lease>` makes `<item>` releasable: the
                // releasable referent is the *item* being claimed (the
                // `TrackerClaim.item`), not the claim's `as` binding.
                body::BodyEffectKind::TrackerClaim { item, .. } => {
                    claims.push((item.clone(), effect.span));
                }
                _ => {}
            }
        }
    });
}

/// The work-item binding of a `when <queue> has ready <item> as <binding>`
/// reaction: the `as <binding>` names a claimable/releasable work item pulled
/// off the queue (spec/coordination.md). Returns `None` for every other `when`
/// pattern (plain fact binds are not releasable). Guards (`where ...`) are
/// stripped first so the pattern words line up.
fn when_has_ready_binding(when: &str) -> Option<String> {
    let (pattern, _) = split_when_guard(when);
    let mut words = pattern.split_whitespace();
    let _queue = words.next()?;
    if words.next() == Some("has") && words.next() == Some("ready") {
        return binding_after_as(pattern);
    }
    None
}

fn collect_after_predicates(
    statements: &[body::BodyStmt],
    binding: &str,
    predicates: &mut BTreeSet<&'static str>,
) {
    for_each_body(statements, &mut |stmt| {
        if let body::BodyStmt::After(after) = stmt {
            if after.binding == binding {
                predicates.insert(after.predicate.as_str());
            }
        }
    });
}

fn find_after_body<'a>(
    statements: &'a [body::BodyStmt],
    binding: &str,
    predicate: body::AfterPredicate,
) -> Option<&'a [body::BodyStmt]> {
    for statement in statements {
        match statement {
            body::BodyStmt::After(after) => {
                if after.binding == binding && after.predicate == predicate {
                    return Some(&after.body);
                }
                if let Some(found) = find_after_body(&after.body, binding, predicate) {
                    return Some(found);
                }
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    if let Some(found) = find_after_body(&branch.body, binding, predicate) {
                        return Some(found);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// Linear must-release, prototype form: a statement list is safe if some
/// statement guarantees release — an explicit `release <binding>`, a
/// workflow terminal (instance-terminal auto-release), a nested after-block
/// that is safe, or a branching construct ALL of whose branches are safe.
fn releases_or_terminates(statements: &[body::BodyStmt], binding: &str) -> bool {
    statements.iter().any(|statement| match statement {
        body::BodyStmt::Effect(effect) => matches!(
            &effect.kind,
            body::BodyEffectKind::TrackerRelease { item } if item == binding
        ),
        body::BodyStmt::Terminal(_) => true,
        body::BodyStmt::After(after) => releases_or_terminates(&after.body, binding),
        body::BodyStmt::Case(case) => {
            !case.branches.is_empty()
                && case
                    .branches
                    .iter()
                    .all(|branch| releases_or_terminates(&branch.body, binding))
        }
        _ => false,
    })
}

fn for_each_body(statements: &[body::BodyStmt], visit: &mut impl FnMut(&body::BodyStmt)) {
    for statement in statements {
        visit(statement);
        match statement {
            body::BodyStmt::After(after) => for_each_body(&after.body, visit),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    for_each_body(&branch.body, visit);
                }
            }
            _ => {}
        }
    }
}

/// Family B: the `(root, field)` pairs a `case <root>.<disc> { "<lit>" => ... }` arm
/// makes readable — the fields conditioned on `<disc> is "<lit>"`. Empty unless the
/// scrutinee is a single-level `<root>.<disc>` path bound to a schema and the arm
/// pattern is the matching string literal.
fn family_b_arm_allowed(
    scrutinee: &str,
    pattern: &str,
    binding_types: &BTreeMap<String, String>,
    semantic: &SemanticContext,
) -> BTreeSet<(String, String)> {
    let mut allowed = BTreeSet::new();
    let Some((root, disc)) = scrutinee.split_once('.') else {
        return allowed;
    };
    if disc.contains('.') {
        return allowed;
    }
    let trimmed = pattern.trim();
    if trimmed == "_" || trimmed == "default" {
        return allowed;
    }
    let literal = trimmed.trim_matches('"');
    if literal.is_empty() {
        return allowed;
    }
    let Some(schema) = binding_types.get(root) else {
        return allowed;
    };
    if let Some(conditions) = semantic.schemas.presence.get(schema) {
        for (field, (cond_disc, cond_literal)) in conditions {
            if cond_disc == disc && cond_literal == literal {
                allowed.insert((root.to_owned(), field.clone()));
            }
        }
    }
    allowed
}

/// Reject ONE read of `<root>.<field>` when that field is Family B
/// presence-conditioned and `allowed` (the conditioned fields this scope's `case`
/// arm makes present) does not carry it. The single place the diagnostic is
/// worded, so a written read, a `from` shorthand copy, and an implicit `from`
/// copy all report identically.
#[allow(clippy::too_many_arguments)]
fn check_conditioned_read(
    rule: &RuleDecl,
    root: &str,
    field: &str,
    span: SourceSpan,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    allowed: &BTreeSet<(String, String)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(schema) = binding_types.get(root) else {
        return;
    };
    let Some((disc, _literal)) = semantic.schemas.field_presence(schema, field) else {
        return;
    };
    if allowed.contains(&(root.to_owned(), field.to_owned())) {
        return;
    }
    diagnostics.push(Diagnostic {
        related: Vec::new(),
        span,
        message: format!(
            "rule `{}` reads conditional field `{root}.{field}` outside a matching `case {root}.{disc}` arm",
            rule.name.name
        ),
        suggestion: Some(format!(
            "read `{root}.{field}` inside `case {root}.{disc} {{ \"...\" => ... }}` — it is present only for a specific `{disc}`"
        )),
    });
}

/// Reject reads of a Family B presence-conditioned field in `text` that are not
/// permitted by `allowed` (the conditioned fields this scope's `case` arm makes
/// present). `text` is any source fragment that may contain dotted field paths.
fn check_conditioned_reads_in_text(
    rule: &RuleDecl,
    text: &str,
    span: SourceSpan,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    allowed: &BTreeSet<(String, String)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (root, path) in dotted_paths(text) {
        let Some(first) = path.first() else {
            continue;
        };
        check_conditioned_read(
            rule,
            &root,
            first,
            span,
            semantic,
            binding_types,
            allowed,
            diagnostics,
        );
    }
}

/// The dotted paths inside a free-text fragment's `{{ … }}` interpolations, which
/// are the only place a prompt or a command string reads a binding. Prose outside
/// the braces is NOT a read — scanning it whole would turn an `e.g.` in an English
/// sentence into a read of a binding named `e`.
fn interpolation_paths(text: &str) -> Vec<(String, Vec<String>)> {
    let mut paths = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        let after_open = &rest[open + 2..];
        let Some(close) = after_open.find("}}") else {
            break;
        };
        paths.extend(dotted_paths(&after_open[..close]));
        rest = &after_open[close + 2..];
    }
    paths
}

/// Reject conditioned reads in a FREE-TEXT operand — a prompt body, an `exec`
/// command line. Only `{{ … }}` interpolations are scanned (see
/// `interpolation_paths`); the surrounding prose is not source.
fn check_conditioned_reads_in_interpolations(
    rule: &RuleDecl,
    text: &str,
    span: SourceSpan,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    allowed: &BTreeSet<(String, String)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (root, path) in interpolation_paths(text) {
        let Some(first) = path.first() else {
            continue;
        };
        check_conditioned_read(
            rule,
            &root,
            first,
            span,
            semantic,
            binding_types,
            allowed,
            diagnostics,
        );
    }
}

/// `from_binding` is the enclosing statement's `from <binding>` source (`None`
/// when the statement has none). A bare `Shorthand` field copies the same-named
/// field OFF that source, so it is a read of `<from_binding>.<field>` and narrows
/// exactly like a written-out `<from_binding>.<field>` expression. A nested block
/// keeps the same source (nesting introduces no new `from`).
fn check_conditioned_reads_in_fields(
    rule: &RuleDecl,
    fields: &[body::FieldAssign],
    from_binding: Option<&str>,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    allowed: &BTreeSet<(String, String)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for field in fields {
        match &field.value {
            body::FieldValue::Expr { source, .. } => check_conditioned_reads_in_text(
                rule,
                source,
                field.span,
                semantic,
                binding_types,
                allowed,
                diagnostics,
            ),
            body::FieldValue::Nested { fields, .. } => check_conditioned_reads_in_fields(
                rule,
                fields,
                from_binding,
                semantic,
                binding_types,
                allowed,
                diagnostics,
            ),
            body::FieldValue::Shorthand => {
                if let Some(root) = from_binding {
                    check_conditioned_read(
                        rule,
                        root,
                        &field.name,
                        field.span,
                        semantic,
                        binding_types,
                        allowed,
                        diagnostics,
                    );
                }
            }
        }
    }
}

/// The copies a `from <binding>` block makes that nobody wrote down. A `from`
/// projection copies EVERY same-named field of the target shape off the source
/// binding, the written block only overriding (`parse_record_fields_with_from` in
/// the kernel is the runtime authority) — so omitting a field name copies it just
/// the same, and a presence-conditioned one is read whether or not it is spelled.
/// `target_fields` is the destination's declared field set, which bounds the copy;
/// fields the block assigns explicitly are not copied and are checked as their own
/// expressions.
#[allow(clippy::too_many_arguments)]
fn check_conditioned_implicit_copies(
    rule: &RuleDecl,
    from_binding: Option<&str>,
    target_fields: Option<&BTreeMap<String, TypeSyntax>>,
    fields: &[body::FieldAssign],
    span: SourceSpan,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    allowed: &BTreeSet<(String, String)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let (Some(root), Some(target_fields)) = (from_binding, target_fields) else {
        return;
    };
    let written: BTreeSet<&str> = fields.iter().map(|field| field.name.as_str()).collect();
    for name in target_fields.keys() {
        if written.contains(name.as_str()) {
            continue;
        }
        check_conditioned_read(
            rule,
            root,
            name,
            span,
            semantic,
            binding_types,
            allowed,
            diagnostics,
        );
    }
}

/// A `record <Class> [from <binding>] { … }` in either of its two statement
/// positions (a plain `record`, or the `done … -> record` replacement).
fn check_conditioned_record_reads(
    rule: &RuleDecl,
    record: &body::RecordStmt,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    allowed: &BTreeSet<(String, String)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    check_conditioned_reads_in_fields(
        rule,
        &record.fields,
        record.from.as_deref(),
        semantic,
        binding_types,
        allowed,
        diagnostics,
    );
    check_conditioned_implicit_copies(
        rule,
        record.from.as_deref(),
        semantic.schemas.classes.get(&record.schema),
        &record.fields,
        record.span,
        semantic,
        binding_types,
        allowed,
        diagnostics,
    );
}

/// Every read position of one effect statement. An effect is an EGRESS as much as a
/// terminal is — a prompt, a command line, an invoke payload, a coordination key all
/// carry the field's value out of the rule — so a presence-conditioned field is
/// narrowed here exactly as it is in a record or terminal value.
///
/// The `kind` match is wildcard-free on purpose: a new `BodyEffectKind` must state
/// which of its operands are reads rather than inherit silence from a `_` arm. Three
/// operand shapes:
///
///   * EXPRESSION text (`dotted_paths`) — an operand written as an expression:
///     coerce arguments, coordination keys, a timer's `until` path, file paths and
///     bodies, an export predicate, a signal's target instance.
///   * FREE text (`interpolation_paths`, `{{ … }}` only) — a model prompt or an
///     `exec` command line, where the surrounding prose is not source.
///   * FIELD BLOCKS (`check_conditioned_reads_in_fields`) — an invoke payload, a
///     tracker file/finish payload, a ledger row, a signal's override block, which
///     narrow through the same walk record and terminal payloads use.
///
/// Named identifiers are not reads: an agent, capability, workflow, queue, ledger,
/// counter, lease, file store, format, mode, or schema NAME references a declaration,
/// and a bare binding operand (`claim <item>`, `release <item>`, `renew <lease>`,
/// `call … for <binding>`, `exec <capability> with <binding>`) reads the whole
/// binding rather than a conditioned field of it.
fn check_conditioned_effect_reads(
    rule: &RuleDecl,
    effect: &body::EffectStmt,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    allowed: &BTreeSet<(String, String)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let span = effect.span;
    let expression = |text: &str, diagnostics: &mut Vec<Diagnostic>| {
        check_conditioned_reads_in_text(
            rule,
            text,
            span,
            semantic,
            binding_types,
            allowed,
            diagnostics,
        );
    };

    // Every effect kind may carry a prompt (`tell`/`prompt`/`decide`/`coerce`
    // bodies), and a prompt is free text: only its interpolations are reads.
    if let Some(prompt) = &effect.prompt {
        check_conditioned_reads_in_interpolations(
            rule,
            &prompt.text,
            span,
            semantic,
            binding_types,
            allowed,
            diagnostics,
        );
    }

    match &effect.kind {
        body::BodyEffectKind::Coerce { args, .. } => {
            for arg in args {
                expression(arg, diagnostics);
            }
        }
        body::BodyEffectKind::ConstructCapabilityCall { fields, .. } => {
            for field in fields {
                expression(&field.source, diagnostics);
            }
        }
        body::BodyEffectKind::MintCredential { headers, body, .. }
        | body::BodyEffectKind::HttpRequest { headers, body, .. } => {
            // A credential slot is a handle, not an expression — it never
            // reaches the expression checker, which is the point: there is no
            // expression that yields material.
            for header in headers {
                if let body::RequestHeaderValue::Expr { source, .. } = &header.value {
                    expression(source, diagnostics);
                }
            }
            if let Some((source, _)) = body {
                expression(source, diagnostics);
            }
        }
        body::BodyEffectKind::Invoke { payload, .. } => check_conditioned_reads_in_fields(
            rule,
            payload,
            // An invoke payload block takes no `from` projection.
            None,
            semantic,
            binding_types,
            allowed,
            diagnostics,
        ),
        body::BodyEffectKind::Timer { until, .. } => {
            if let Some(until) = until {
                expression(until, diagnostics);
            }
        }
        body::BodyEffectKind::Exec {
            target,
            access_grants: _,
            parse_target: _,
        } => match target {
            // A raw command is a string literal: prose plus interpolations.
            body::ExecTarget::RawCommand(command) => {
                check_conditioned_reads_in_interpolations(
                    rule,
                    command,
                    span,
                    semantic,
                    binding_types,
                    allowed,
                    diagnostics,
                );
            }
            // `with <binding>` pipes the whole binding to stdin.
            body::ExecTarget::Capability { .. } => {}
        },
        body::BodyEffectKind::TrackerFile { fields, .. }
        | body::BodyEffectKind::ObtainCredential { fields, .. }
        | body::BodyEffectKind::TrackerFinish { fields, .. }
        | body::BodyEffectKind::LedgerAppend { fields, .. } => check_conditioned_reads_in_fields(
            rule,
            fields,
            None,
            semantic,
            binding_types,
            allowed,
            diagnostics,
        ),
        body::BodyEffectKind::LeaseAcquire { key_expr, .. } => expression(key_expr, diagnostics),
        body::BodyEffectKind::CounterConsume {
            key_expr,
            amount_expr,
            ..
        } => {
            expression(key_expr, diagnostics);
            expression(amount_expr, diagnostics);
        }
        // `emit signal <name> to <target> from <binding> { overrides }` is both an
        // operand position (the target instance) and the third COPY position (the
        // `record … from` precedent, S6): the block overrides, the projection copies
        // every same-named field the signal declares.
        body::BodyEffectKind::Notify {
            target_expr,
            event,
            from,
            fields,
        } => {
            expression(target_expr, diagnostics);
            check_conditioned_reads_in_fields(
                rule,
                fields,
                from.as_deref(),
                semantic,
                binding_types,
                allowed,
                diagnostics,
            );
            check_conditioned_implicit_copies(
                rule,
                from.as_deref(),
                semantic.schemas.classes.get(event),
                fields,
                span,
                semantic,
                binding_types,
                allowed,
                diagnostics,
            );
        }
        body::BodyEffectKind::FileRead { path, .. }
        | body::BodyEffectKind::FileImport { path, .. } => expression(path, diagnostics),
        body::BodyEffectKind::FileWrite { path, body, .. } => {
            expression(path, diagnostics);
            expression(body, diagnostics);
        }
        body::BodyEffectKind::FileExport {
            path, predicate, ..
        } => {
            expression(path, diagnostics);
            if let Some(predicate) = predicate {
                expression(predicate, diagnostics);
            }
        }
        // Prompt-only or name-only kinds: every operand is a declaration name, a
        // bare binding, or the prompt already scanned above.
        body::BodyEffectKind::Tell { .. }
        | body::BodyEffectKind::Prompt { .. }
        | body::BodyEffectKind::Decide { .. }
        | body::BodyEffectKind::Call { .. }
        | body::BodyEffectKind::TrackerClaim { .. }
        | body::BodyEffectKind::TrackerRelease { .. }
        | body::BodyEffectKind::LeaseRenew { .. } => {}
    }
}

/// The declared field set of the workflow output contract a `complete <name> from
/// <binding>` projects onto — the bound on what that projection copies. `None`
/// when the contract is scalar, inline-typed to something other than a class, or
/// not resolvable in this workflow's scope (nothing is claimed about the copy).
fn terminal_output_fields<'a>(
    terminal: &body::TerminalStmt,
    semantic: &'a SemanticContext,
) -> Option<&'a BTreeMap<String, TypeSyntax>> {
    if terminal.kind != body::TerminalKind::Complete {
        return None;
    }
    let workflow = semantic.workflow.as_ref()?;
    let surface = semantic.workflow_inputs.get(workflow)?;
    match surface.outputs.get(&terminal.name)? {
        TypeSyntax::Ref { name } => semantic.schemas.classes.get(&name.name),
        _ => None,
    }
}

/// Family B read-narrowing (discriminated-families-design.md §5.6/§5.7): walk the
/// rule body and reject a read of a presence-conditioned field that is not inside a
/// matching `case <root>.<disc>` arm. Each `case` arm extends `allowed` with the
/// fields its discriminant=literal makes present. Coverage is every read position a
/// rule body has: record/terminal/done/milestone values, branch conditions, case
/// guards, and effect operands (`check_conditioned_effect_reads` — prompts, command
/// lines, payloads, coordination keys). Every `from`-carrying statement passes its
/// source binding down, so both spellings of a copy — the written `Shorthand` field
/// and the field the projection copies implicitly — narrow like the
/// `<binding>.<field>` read each one is.
fn validate_conditioned_field_reads(
    rule: &RuleDecl,
    statements: &[body::BodyStmt],
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    allowed: &BTreeSet<(String, String)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Record(record) => {
                check_conditioned_record_reads(
                    rule,
                    record,
                    semantic,
                    binding_types,
                    allowed,
                    diagnostics,
                );
            }
            body::BodyStmt::Terminal(terminal) => {
                check_conditioned_reads_in_fields(
                    rule,
                    &terminal.fields,
                    terminal.from.as_deref(),
                    semantic,
                    binding_types,
                    allowed,
                    diagnostics,
                );
                check_conditioned_implicit_copies(
                    rule,
                    terminal.from.as_deref(),
                    terminal_output_fields(terminal, semantic),
                    &terminal.fields,
                    terminal.span,
                    semantic,
                    binding_types,
                    allowed,
                    diagnostics,
                );
                // A bare scalar payload value is also an egress read.
                if let Some(body::FieldValue::Expr { source, .. }) = &terminal.scalar {
                    check_conditioned_reads_in_text(
                        rule,
                        source,
                        terminal.span,
                        semantic,
                        binding_types,
                        allowed,
                        diagnostics,
                    );
                }
            }
            body::BodyStmt::Done {
                replacement: Some(record),
                ..
            } => check_conditioned_record_reads(
                rule,
                record,
                semantic,
                binding_types,
                allowed,
                diagnostics,
            ),
            body::BodyStmt::Milestone { fields, .. } => check_conditioned_reads_in_fields(
                rule,
                fields,
                // `emit milestone` carries no `from` projection.
                None,
                semantic,
                binding_types,
                allowed,
                diagnostics,
            ),
            body::BodyStmt::Effect(effect) => check_conditioned_effect_reads(
                rule,
                effect,
                semantic,
                binding_types,
                allowed,
                diagnostics,
            ),
            body::BodyStmt::Done { .. }
            | body::BodyStmt::Cancel { .. }
            | body::BodyStmt::Redact { .. }
            | body::BodyStmt::Declassify { .. } => {}
            body::BodyStmt::After(after) => validate_conditioned_field_reads(
                rule,
                &after.body,
                semantic,
                binding_types,
                allowed,
                diagnostics,
            ),
            body::BodyStmt::Region(region) => {
                validate_conditioned_field_reads(
                    rule,
                    &region.body,
                    semantic,
                    binding_types,
                    allowed,
                    diagnostics,
                );
                validate_conditioned_field_reads(
                    rule,
                    &region.lapse_body,
                    semantic,
                    binding_types,
                    allowed,
                    diagnostics,
                );
            }
            body::BodyStmt::Case(case) => {
                for arm in &case.branches {
                    let mut arm_allowed = allowed.clone();
                    arm_allowed.extend(family_b_arm_allowed(
                        &case.scrutinee,
                        &arm.pattern,
                        binding_types,
                        semantic,
                    ));
                    if let Some(guard) = &arm.guard {
                        check_conditioned_reads_in_text(
                            rule,
                            guard,
                            arm.span,
                            semantic,
                            binding_types,
                            &arm_allowed,
                            diagnostics,
                        );
                    }
                    validate_conditioned_field_reads(
                        rule,
                        &arm.body,
                        semantic,
                        binding_types,
                        &arm_allowed,
                        diagnostics,
                    );
                }
            }
        }
    }
}

fn validate_body_effect_operands(
    rule: &RuleDecl,
    statements: &[body::BodyStmt],
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                match &effect.kind {
                    body::BodyEffectKind::LeaseAcquire { resource, .. }
                        if !semantic.leases.contains(resource) =>
                    {
                        diagnostics.push(Diagnostic { related: Vec::new(),
                            span: effect.span,
                            message: format!(
                                "rule `{}` acquires undeclared lease `{resource}`",
                                rule.name.name
                            ),
                            suggestion: Some(format!(
                                "declare `lease {resource} {{ key <Type>  slots <N>  ttl <duration> }}`"
                            )),
                        });
                    }
                    body::BodyEffectKind::LedgerAppend { ledger, schema, .. } => {
                        if !semantic.ledgers.contains(ledger) {
                            diagnostics.push(Diagnostic { related: Vec::new(),
                                span: effect.span,
                                message: format!(
                                    "rule `{}` appends to undeclared ledger `{ledger}`",
                                    rule.name.name
                                ),
                                suggestion: Some(format!(
                                    "declare `ledger {ledger} {{ entry <Type>  partition by <field>  retain <duration> }}`"
                                )),
                            });
                        }
                        if !semantic.schemas.class_exists(schema) {
                            diagnostics.push(Diagnostic {
                                related: Vec::new(),
                                span: effect.span,
                                message: format!(
                                    "rule `{}` appends unknown entry class `{schema}`",
                                    rule.name.name
                                ),
                                suggestion: Some(format!("declare `class {schema}` first")),
                            });
                        }
                    }
                    body::BodyEffectKind::CounterConsume { counter, .. }
                        if !semantic.counters.contains(counter) =>
                    {
                        diagnostics.push(Diagnostic { related: Vec::new(),
                            span: effect.span,
                            message: format!(
                                "rule `{}` consumes undeclared counter `{counter}`",
                                rule.name.name
                            ),
                            suggestion: Some(format!(
                                "declare `counter {counter} {{ key <Type>  cap <N>  reset <period> }}`"
                            )),
                        });
                    }
                    _ => {}
                }
                // `exec <name> with <binding>` requires a typed record binding
                // (spec/std-script.md "Static checks" item 4): the binding is
                // serialized to the script's stdin as a typed record, so an
                // unknown or untyped binding cannot cross.
                if let body::BodyEffectKind::Exec {
                    target:
                        body::ExecTarget::Capability {
                            name,
                            stdin_binding,
                        },
                    ..
                } = &effect.kind
                {
                    match binding_types.get(stdin_binding) {
                        None => {
                            diagnostics.push(Diagnostic {
                                related: Vec::new(),
                                span: effect.span,
                                message: format!(
                                    "rule `{}` uses unknown binding `{stdin_binding}` in `exec {name} with {stdin_binding}` — `with` requires a typed record binding",
                                    rule.name.name
                                ),
                                suggestion: Some(format!(
                                    "bind a typed record first (e.g. `when <Class> as {stdin_binding}` or `coerce ... -> <Class> as {stdin_binding}`) and pass that binding to `with`"
                                )),
                            });
                        }
                        // A dotted binding without an indexed payload class is an
                        // untyped runtime fact (`when fact <name> as x`) — no
                        // static record shape crosses to stdin. Non-dotted
                        // unknown classes are already reported at their binding
                        // site (`matches unknown class` / unknown parse schema).
                        Some(schema)
                            if schema.contains('.') && !semantic.schemas.class_exists(schema) =>
                        {
                            diagnostics.push(Diagnostic {
                                related: Vec::new(),
                                span: effect.span,
                                message: format!(
                                    "rule `{}` passes untyped fact binding `{stdin_binding}` to `exec {name} with` — `with` requires a typed record binding",
                                    rule.name.name
                                ),
                                suggestion: Some(format!(
                                    "declare `signal {schema} {{ ... }}` for a typed reaction, or bind a declared class and pass that to `with`"
                                )),
                            });
                        }
                        Some(_) => {}
                    }
                }
                if let body::BodyEffectKind::Exec {
                    parse_target: Some(parse),
                    ..
                } = &effect.kind
                {
                    if !semantic.schemas.class_exists(&parse.schema) {
                        let suggestion =
                            match closest_name(&parse.schema, semantic.schemas.classes.keys()) {
                                Some(candidate) => format!(
                                    "did you mean `{candidate}`? otherwise declare `class {}`",
                                    parse.schema
                                ),
                                None => format!(
                                    "declare `class {}` before parsing into it",
                                    parse.schema
                                ),
                            };
                        diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: effect.span,
                            message: format!(
                                "rule `{}` parses exec output into unknown schema `{}`",
                                rule.name.name, parse.schema
                            ),
                            suggestion: Some(suggestion),
                        });
                    }
                }
                let body::BodyEffectKind::Timer {
                    until: Some(until), ..
                } = &effect.kind
                else {
                    continue;
                };
                if body::is_iso8601_instant(until) {
                    continue;
                }
                let mut segments = until.split('.');
                let root = segments.next().unwrap_or_default();
                let path = segments.map(str::to_owned).collect::<Vec<_>>();
                let Some(schema) = binding_types.get(root) else {
                    diagnostics.push(Diagnostic { related: Vec::new(),
                        span: effect.span,
                        message: format!(
                            "rule `{}` uses unknown binding `{root}` in `timer until {until}`",
                            rule.name.name
                        ),
                        suggestion: Some(
                            "bind a fact in `when` and reference a `time` field on it, or use an ISO-8601 literal"
                                .to_owned(),
                        ),
                    });
                    continue;
                };
                // Dotted runtime fact bindings are untyped; their fields
                // cannot be statically checked.
                if schema.contains('.') {
                    continue;
                }
                let resolved = if path.is_empty() {
                    Err(format!(
                        "`{root}` is a `{schema}` record, not a `time` value"
                    ))
                } else {
                    semantic.schemas.resolve_field_path(schema, &path)
                };
                match resolved {
                    Ok(TypeSyntax::Primitive { ref name, .. }) if name == "time" => {}
                    Ok(_) => {
                        diagnostics.push(Diagnostic { related: Vec::new(),
                            span: effect.span,
                            message: format!(
                                "rule `{}` uses non-time operand `{until}` in `timer until`",
                                rule.name.name
                            ),
                            suggestion: Some(format!(
                                "declare the field as `time` on `{schema}` or use an ISO-8601 literal"
                            )),
                        });
                    }
                    Err(message) => {
                        diagnostics.push(Diagnostic { related: Vec::new(),
                            span: effect.span,
                            message: format!(
                                "rule `{}` has invalid `timer until` operand `{until}`: {message}",
                                rule.name.name
                            ),
                            suggestion: Some(
                                "reference a `time`-typed field on a bound fact, or use an ISO-8601 literal"
                                    .to_owned(),
                            ),
                        });
                    }
                }
            }
            body::BodyStmt::After(after) => {
                validate_body_effect_operands(
                    rule,
                    &after.body,
                    semantic,
                    binding_types,
                    diagnostics,
                );
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    validate_body_effect_operands(
                        rule,
                        &branch.body,
                        semantic,
                        binding_types,
                        diagnostics,
                    );
                }
            }
            _ => {}
        }
    }
}

/// The reserved namespace the synthesized progress-view classes live under. A `.`
/// cannot appear in a declared class name, so these can never collide with an
/// author's class — the same guarantee the `<Enum>.<Variant>` sum-type lowering
/// relies on.
const PROGRESS_VIEW_NAMESPACE: &str = "region";

/// DR-0043 Decision 7 obligation 2 — type the lapse arm.
///
/// The `on lapse` arm is spliced out of the canonical (condition-HOLDS) rule body,
/// so *nothing* validated it: not the progress view, and not ordinary bindings
/// either — `fail error { reason task.bogus }` in an arm was accepted in full.
/// This walks the arm text with the rule's binding environment extended by the
/// progress view, against a schema index extended with two synthesized classes:
///
///   `region.<rule>.Progress`  one optional field per step (the step's own settled
///                             payload) plus `steps`
///   `region.<rule>.Steps`     one `string` field per step (its status)
///
/// The DR's four rules then fall out of the ordinary path resolver: a field that is
/// neither a step nor `steps` has no field on Progress; an unknown step has no field
/// on Steps; a path *through* a status hits "is not a schema value"; and a deeper
/// path under a step resolves against that step's own schema because
/// `schema_name_for_path` sees through the optional.
///
/// The same splice hid the arm from Family B read-narrowing, so the arm is walked
/// with that pass too: an arm is an egress position like any other, and the region
/// it belongs to may itself sit inside a `case` arm whose allowances the arm keeps.
fn validate_lapse_arm(
    rule: &RuleDecl,
    region: &IrRegion,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    foreign_schemas: &BTreeMap<String, String>,
    effect_payload_types: &BTreeMap<String, IrType>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut schemas = semantic.schemas.clone();
    let mut arm_bindings = binding_types.clone();

    if let Some(view) = &region.lapse_binding {
        let progress = format!("{PROGRESS_VIEW_NAMESPACE}.{}.Progress", rule.name.name);
        let steps = format!("{PROGRESS_VIEW_NAMESPACE}.{}.Steps", rule.name.name);

        let mut progress_fields = BTreeMap::new();
        let mut steps_fields = BTreeMap::new();
        // Derive the step set from `region.effects` — the same list the kernel
        // walks when it pins the view (rule_pass.rs), including the `__then_`
        // strip, so the checker's field set and the runtime's key set cannot
        // drift apart.
        for effect in &region.effects {
            let step = effect
                .binding
                .strip_prefix(then_expand::THEN_BINDING_PREFIX)
                .unwrap_or(&effect.binding)
                .to_owned();
            // A step's status is always a string; its settled value is optional
            // because the arm can run before that step settled — or at all.
            steps_fields.insert(step.clone(), string_ty());
            let settled = match effect_payload_types.get(&effect.binding) {
                Some(IrType::Ref(name)) if semantic.schemas.class_exists(name) => TypeSyntax::Ref {
                    name: Ident {
                        name: name.clone(),
                        span: zero_span(),
                    },
                },
                // No resolvable payload schema: the step reads as a settled scalar,
                // so a bare read is fine and a deeper path correctly errors.
                _ => string_ty(),
            };
            progress_fields.insert(step, optional_ty(settled));
        }
        progress_fields.insert(
            "steps".to_owned(),
            TypeSyntax::Ref {
                name: Ident {
                    name: steps.clone(),
                    span: zero_span(),
                },
            },
        );

        schemas.classes.insert(steps, steps_fields);
        schemas.classes.insert(progress.clone(), progress_fields);
        arm_bindings.insert(view.clone(), progress);
    }

    for line in region.arm_content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        validate_known_field_paths_in_index(
            rule,
            line,
            rule.body.span,
            // The synthesized view classes are local to this check; an ambient
            // binding the arm inherits may still be invoke-derived and resolve in
            // a child's index.
            SchemaScopes {
                local: &schemas,
                foreign: foreign_schemas,
                workflows: &semantic.workflow_inputs,
            },
            &arm_bindings,
            diagnostics,
        );
    }

    // Family B read-narrowing. The arm is an egress like any other body position —
    // `coerce fa(e.region)` in an arm carries the conditioned value out of the
    // instance — and the splice is the only reason the rule-body pass never saw it.
    // The allowed set starts from the `case` arms the region sits inside, so an arm
    // under `case e.kind { "deploy" => … }` keeps that arm's allowances.
    let (arm_ast, _) = body::parse_rule_body(&region.arm_content, 0);
    let mut allowed = BTreeSet::new();
    for (scrutinee, pattern) in &region.arm_case_arms {
        allowed.extend(family_b_arm_allowed(
            scrutinee,
            pattern,
            &arm_bindings,
            semantic,
        ));
    }
    let mut arm_diagnostics = Vec::new();
    validate_conditioned_field_reads(
        rule,
        &arm_ast.statements,
        semantic,
        &arm_bindings,
        &allowed,
        &mut arm_diagnostics,
    );
    // `arm_content` is cut from the then-expanded body text, so offsets into it are
    // not source positions. Every arm diagnostic is reported at the body span, the
    // same span the field-path walk above uses.
    for mut diagnostic in arm_diagnostics {
        diagnostic.span = rule.body.span;
        diagnostics.push(diagnostic);
    }
}

/// No binding in this scope carries a foreign (child-workflow) schema.
static NO_FOREIGN_SCHEMAS: BTreeMap<String, String> = BTreeMap::new();
static NO_WORKFLOW_SURFACES: BTreeMap<String, WorkflowInputSurface> = BTreeMap::new();

/// Which schema index a binding's field paths resolve in.
///
/// A parent that observes a child workflow's result, failure, or milestone
/// payload holds a value whose class may be declared *inside that child*. The
/// class is not nameable in the parent — and must not become nameable, or a
/// child's private types would leak into the parent's declaration space — but
/// its fields are exactly the contract the parent was handed, so the parent's
/// reads resolve in the child's own index. That is structural typing across the
/// workflow boundary, not an import.
///
/// A binding with no `foreign` entry resolves locally, which is every ordinary
/// binding.
#[derive(Clone, Copy)]
struct SchemaScopes<'a> {
    local: &'a SchemaIndex,
    /// Binding -> the child workflow whose index types it.
    foreign: &'a BTreeMap<String, String>,
    workflows: &'a BTreeMap<String, WorkflowInputSurface>,
}

impl<'a> SchemaScopes<'a> {
    fn local(local: &'a SchemaIndex) -> Self {
        Self {
            local,
            foreign: &NO_FOREIGN_SCHEMAS,
            workflows: &NO_WORKFLOW_SURFACES,
        }
    }

    fn index_for(&self, binding: &str) -> &'a SchemaIndex {
        self.foreign
            .get(binding)
            .and_then(|workflow| self.workflows.get(workflow))
            .map_or(self.local, |surface| &surface.schemas)
    }
}

fn validate_known_field_paths(
    rule: &RuleDecl,
    line: &str,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_known_field_paths_at_span(
        rule,
        line,
        rule.body.span,
        semantic,
        binding_types,
        diagnostics,
    );
}

/// `validate_known_field_paths` for a scope that can hold invoke-derived
/// bindings, whose payload classes may live in the child workflow's index.
fn validate_known_field_paths_scoped(
    rule: &RuleDecl,
    line: &str,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    foreign: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_known_field_paths_in_index(
        rule,
        line,
        rule.body.span,
        SchemaScopes {
            local: &semantic.schemas,
            foreign,
            workflows: &semantic.workflow_inputs,
        },
        binding_types,
        diagnostics,
    );
}

fn validate_known_field_paths_at_span(
    rule: &RuleDecl,
    line: &str,
    span: SourceSpan,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_known_field_paths_in_index(
        rule,
        line,
        span,
        SchemaScopes::local(&semantic.schemas),
        binding_types,
        diagnostics,
    );
}

/// `validate_known_field_paths_at_span` against explicit schema scopes rather
/// than the program's index alone. The lapse arm resolves its progress view
/// against an index extended with that region's synthesized view classes, which
/// exist only for the duration of the check; an invoke-derived binding resolves
/// against the child workflow that produced it.
/// What resolving one `<root>.<path>` read established. Callers that only want
/// the diagnostic ignore this; the record-field walk acts on it, because a read
/// it cannot resolve suppresses the literal and expected-value checks that
/// follow it.
#[derive(Clone, Copy, Eq, PartialEq)]
enum FieldPathCheck {
    /// `root` is not a typed binding here. Nothing was checked or reported —
    /// the caller decides whether that means a dangling reference.
    Unbound,
    /// `root` is typed, but its schema is absent from the index consulted. A
    /// child workflow's private class reads this way in a scope that was not
    /// given the child's index. Nothing was checked or reported.
    ///
    /// Distinct from `Resolved` for one caller only: `validate_record_field`
    /// stops the field here rather than running the literal and expected-value
    /// checks against a schema it cannot see. That is observable in a narrow
    /// shape — `expression_path` accepts any expression holding exactly ONE
    /// dotted path, so a brace- or bracket-valued field carrying one reaches
    /// `validate_expected_assignment`, which acts on it. For a bare path both of
    /// those validators return immediately and the distinction does not show.
    SchemaNotIndexed,
    /// The path was resolved. A diagnostic was pushed if it did not.
    Resolved,
}

/// Resolve one `<root>.<path>` read against the index that types `root`, and
/// report an unresolvable one.
///
/// This is the single implementation. It used to exist three times — here, in
/// `validate_scalar_terminal_payload`, and in `validate_record_field` — with the
/// same message and suggestion but three different control flows, so a change to
/// one (scope awareness, say) silently left the other two behind.
fn check_field_path(
    rule: &RuleDecl,
    root: &str,
    path: &[String],
    span: SourceSpan,
    scopes: SchemaScopes,
    binding_types: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) -> FieldPathCheck {
    let Some(schema) = binding_types.get(root) else {
        return FieldPathCheck::Unbound;
    };
    let schemas = scopes.index_for(root);
    if !schemas.class_exists(schema) {
        return FieldPathCheck::SchemaNotIndexed;
    }
    if let Err(message) = schemas.resolve_field_path(schema, path) {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span,
            message: format!(
                "rule `{}` has invalid field path `{root}.{}`: {message}",
                rule.name.name,
                path.join(".")
            ),
            suggestion: Some(
                "use a field declared on the bound schema or add it to the class declaration"
                    .to_owned(),
            ),
        });
    }
    FieldPathCheck::Resolved
}

fn validate_known_field_paths_in_index(
    rule: &RuleDecl,
    line: &str,
    span: SourceSpan,
    scopes: SchemaScopes,
    binding_types: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (root, path) in dotted_paths(line) {
        check_field_path(rule, &root, &path, span, scopes, binding_types, diagnostics);
    }
}

/// Every `sealed<T>` a type REACHES, as `(field path, payload type)`.
///
/// The empty path means the type is itself sealed. Recurses through class
/// references, and through `Optional`/`Array`/`Map` because a sealed value
/// inside a collection still renders as ciphertext. Cycle-guarded on class
/// name: a self-referential schema would otherwise not terminate.
fn collect_reachable_sealed(
    schemas: &SchemaIndex,
    ty: &TypeSyntax,
    prefix: String,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<(String, String)>,
) {
    match ty {
        TypeSyntax::Sealed { inner, .. } => out.push((prefix, inner.to_source())),
        TypeSyntax::Optional { inner, .. }
        | TypeSyntax::Array { inner, .. }
        | TypeSyntax::Map { inner, .. } => {
            collect_reachable_sealed(schemas, inner, prefix, seen, out)
        }
        TypeSyntax::Ref { name } => {
            if !seen.insert(name.name.clone()) {
                return;
            }
            if let Some(fields) = schemas.classes.get(&name.name) {
                for (field, field_ty) in fields {
                    let next = if prefix.is_empty() {
                        field.clone()
                    } else {
                        format!("{prefix}.{field}")
                    };
                    collect_reachable_sealed(schemas, field_ty, next, seen, out);
                }
            }
            seen.remove(&name.name);
        }
        _ => {}
    }
}

/// A `sealed<T>` reaching an effect's input must be accompanied by an
/// `unwrap for T` grant on that same effect.
///
/// **The trap this closes.** A sealed value interpolated into a prompt renders
/// as its ENVELOPE — `{credential, context, nonce_b64, ciphertext_b64}` — so the
/// provider receives base64 ciphertext and answers about nothing. It compiles,
/// it runs, and the failure is a plausible-looking model reply. There is no
/// sentinel machinery for payloads the way DR-0053 §5 provides one for
/// credentials: `IrType::Sealed` appears in the lowering only as a shape
/// descriptor.
///
/// So an effect carrying a sealed input is making one of two statements. With a
/// matching grant it is asking for worker-side opening — the effect's durable
/// row already records `unwrap` narrowed to the type, which is the whole
/// authorization half. Without one it is asking the provider to read
/// ciphertext, which is a mistake in every case, and is refused here rather
/// than in production.
fn validate_sealed_effect_inputs(
    rule: &RuleDecl,
    statements: &[body::BodyStmt],
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                // Every expression this effect carries into its durable input,
                // plus its prompt: the prompt is where a sealed value most
                // naturally lands, and it is not part of the effect kind.
                // `open` is the one effect whose sealed input is the point.
                // Its authorization is the `with <credential>` slot and the
                // envelope-side unwrap grant, not a turn access grant, and
                // DR-0074 §3's obligation-3 check already relates its type.
                if let body::BodyEffectKind::ConstructCapabilityCall {
                    target_capability, ..
                } = &effect.kind
                {
                    if target_capability == CUSTODY_UNWRAP_CAPABILITY {
                        continue;
                    }
                }
                let mut sources: Vec<String> = Vec::new();
                collect_effect_expression_sources(&effect.kind, &mut sources);
                if let Some(prompt) = &effect.prompt {
                    sources.push(prompt.text.clone());
                }
                let granted: BTreeSet<&str> = effect
                    .kind
                    .access_grants()
                    .iter()
                    .flat_map(|grant| grant.operations.iter())
                    .filter(|op| op.operation == "unwrap")
                    .filter_map(|op| op.target.as_deref())
                    .collect();
                // Both shapes a sealed value can arrive in: named directly
                // (`claim.body`) and reached through a value passed whole
                // (`claim`, whose `body` field is sealed). `dotted_paths`
                // yields only paths with at least one field, so the second
                // shape was invisible — which is the gap this closes.
                let mut found: BTreeSet<(String, String)> = BTreeSet::new();
                for source in &sources {
                    let mut roots = BTreeSet::new();
                    if let Ok(expr) = parse_expression(source) {
                        collect_expr_binding_roots(&expr, &mut roots);
                    } else {
                        collect_template_binding_roots(source, &mut roots);
                    }
                    let targets = dotted_paths(source)
                        .into_iter()
                        .chain(roots.into_iter().map(|root| (root, Vec::new())));
                    for (root, path) in targets {
                        let Some(root_schema) = binding_types.get(&root) else {
                            continue;
                        };
                        let Ok(resolved) = semantic.schemas.resolve_field_path(root_schema, &path)
                        else {
                            continue;
                        };
                        let full = if path.is_empty() {
                            root.clone()
                        } else {
                            format!("{root}.{}", path.join("."))
                        };
                        // Every sealed field this value REACHES, not only the
                        // case where the value is itself sealed. A record
                        // carrying an envelope renders the same ciphertext into
                        // the request, and the runtime walker already recurses
                        // into objects and arrays to find one — so a checker
                        // that looked only at the top level disagreed with the
                        // resolution it is supposed to be gating.
                        let mut seen = BTreeSet::new();
                        let mut reachable = Vec::new();
                        collect_reachable_sealed(
                            &semantic.schemas,
                            &resolved,
                            String::new(),
                            &mut seen,
                            &mut reachable,
                        );
                        for (field_path, payload) in reachable {
                            if granted.contains(payload.as_str()) {
                                continue;
                            }
                            let at = if field_path.is_empty() {
                                full.clone()
                            } else {
                                format!("{full}.{field_path}")
                            };
                            // Keyed by WHERE the sealed value is, so naming a
                            // record and its sealed field in one prompt reports
                            // the field once rather than twice.
                            found.insert((at, payload));
                        }
                    }
                }
                for (at, payload) in found {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: effect.span,
                        message: format!(
                            "rule `{}` passes `{at}` to an effect, which is \
                             `sealed<{payload}>`, and the effect has no `unwrap for {payload}` \
                             grant — the provider would receive ciphertext",
                            rule.name.name
                        ),
                        suggestion: Some(format!(
                            "grant the turn worker-side opening: `with access to credential \
                             <cred> {{ unwrap for {payload} }}`, or send a value the provider \
                             can read — `redact` drops a sealed field"
                        )),
                    });
                }
            }
            body::BodyStmt::After(after) => validate_sealed_effect_inputs(
                rule,
                &after.body,
                semantic,
                binding_types,
                diagnostics,
            ),
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    validate_sealed_effect_inputs(
                        rule,
                        &branch.body,
                        semantic,
                        binding_types,
                        diagnostics,
                    );
                }
            }
            body::BodyStmt::Region(region) => {
                validate_sealed_effect_inputs(
                    rule,
                    &region.body,
                    semantic,
                    binding_types,
                    diagnostics,
                );
                validate_sealed_effect_inputs(
                    rule,
                    &region.lapse_body,
                    semantic,
                    binding_types,
                    diagnostics,
                );
            }
            _ => {}
        }
    }
}

fn dotted_paths(line: &str) -> Vec<(String, Vec<String>)> {
    let bytes = line.as_bytes();
    let mut paths = Vec::new();
    let mut index = 0;

    while index < bytes.len() {
        if !is_ident_start(bytes[index]) {
            index += 1;
            continue;
        }

        let root_start = index;
        index += 1;
        while index < bytes.len() && is_ident_continue(bytes[index]) {
            index += 1;
        }
        let root = &line[root_start..index];
        let mut fields = Vec::new();

        while bytes.get(index) == Some(&b'.')
            && bytes
                .get(index + 1)
                .is_some_and(|byte| is_ident_start(*byte))
        {
            index += 1;
            let field_start = index;
            index += 1;
            while index < bytes.len() && is_ident_continue(bytes[index]) {
                index += 1;
            }
            fields.push(line[field_start..index].to_owned());
        }

        if !fields.is_empty() {
            paths.push((root.to_owned(), fields));
        }
    }

    paths
}

fn interpolation_roots(line: &str) -> Vec<String> {
    let mut roots = Vec::new();
    let mut rest = line;

    while let Some(open) = rest.find("{{") {
        let after_open = &rest[open + 2..];
        let Some(close) = after_open.find("}}") else {
            break;
        };
        let expr = after_open[..close].trim();
        if let Some(root) = expr
            .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
            .find(|part| !part.is_empty())
        {
            roots.push(root.to_owned());
        }
        rest = &after_open[close + 2..];
    }

    roots
}

// `claim` stays bindable: `claim item as claim` is an established idiom and
// the trailing binding position is unambiguous.
const RESERVED_BINDING_KEYWORDS: &[&str] = &[
    "after", "call", "case", "coerce", "complete", "consume", "done", "emit", "fail", "invoke",
    "record", "tell", "when", "where",
];

fn validate_binding_name(
    rule: &RuleDecl,
    binding: &str,
    span: SourceSpan,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if RESERVED_BINDING_KEYWORDS.contains(&binding) {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span,
            message: format!(
                "rule `{}` binds reserved keyword `{binding}`",
                rule.name.name
            ),
            suggestion: Some(format!(
                "`{binding}` is a rule body keyword; choose another binding name"
            )),
        });
    }
}

fn closest_name<'a>(target: &str, candidates: impl Iterator<Item = &'a String>) -> Option<String> {
    let target_lower = target.to_lowercase();
    candidates
        .map(|candidate| {
            let distance = edit_distance(&target_lower, &candidate.to_lowercase());
            (distance, candidate)
        })
        .filter(|(distance, candidate)| {
            *distance <= 2 && *distance < target.len().min(candidate.len())
        })
        .min_by_key(|(distance, candidate)| (*distance, candidate.as_str().to_owned()))
        .map(|(_, candidate)| candidate.clone())
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0usize; b.len() + 1];
    for (i, a_char) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, b_char) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(a_char != b_char);
            current[j + 1] = substitution.min(previous[j + 1] + 1).min(current[j] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

fn fact_read_from_when(when: &str) -> String {
    let (pattern, _) = split_when_guard(when);
    let first = pattern.split_whitespace().next().unwrap_or("<empty>");
    if first.chars().next().is_some_and(char::is_uppercase) {
        format!("schema:{first}")
    } else {
        format!("pattern:{pattern}")
    }
}

fn parse_record_start(line: &str) -> Option<(String, Option<String>)> {
    let rest = line.strip_prefix("record ").or_else(|| {
        line.strip_prefix("done ")
            .and_then(|rest| rest.split_once("->"))
            .map(|(_, record)| record.trim())
            .and_then(|record| record.strip_prefix("record "))
    })?;
    let before_brace = rest.split('{').next().unwrap_or(rest).trim();
    let mut parts = before_brace.split_whitespace();
    let schema = parts.next()?.to_owned();
    let from_binding = match (parts.next(), parts.next(), parts.next()) {
        (None, None, None) => None,
        (Some("from"), Some(binding), None) => Some(binding.to_owned()),
        _ => return None,
    };
    Some((schema, from_binding))
}

fn validate_record_field(
    rule: &RuleDecl,
    line: &str,
    record_schema: &str,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    known_roots: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some((field, expr)) = record_field_assignment(line) else {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!(
                "rule `{}` has malformed field assignment in `record {record_schema}`",
                rule.name.name
            ),
            suggestion: Some("write record fields as `field value`".to_owned()),
        });
        return;
    };

    let Some(fields) = semantic.schemas.classes.get(record_schema) else {
        return;
    };
    let Some(field_ty) = fields.get(field) else {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!("class `{record_schema}` has no field `{field}`"),
            suggestion: Some(format!(
                "add `{field}` to `class {record_schema}` or record an existing field"
            )),
        });
        return;
    };

    if let Some((root, path)) = expression_path(expr) {
        // Local scopes only, for the same reason as the terminal payload above.
        match check_field_path(
            rule,
            &root,
            &path,
            rule.body.span,
            SchemaScopes::local(&semantic.schemas),
            binding_types,
            diagnostics,
        ) {
            // A read this scope cannot resolve says nothing about the literal
            // and expected-value checks below either, so it stops the field
            // here rather than letting them judge a schema they cannot see.
            FieldPathCheck::SchemaNotIndexed => return,
            FieldPathCheck::Resolved => {}
            // A field access whose root is neither a bound name nor a special
            // root is a dangling reference: the binding does not exist.
            FieldPathCheck::Unbound => {
                if let Some(root) = dangling_value_root(expr, known_roots) {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: rule.body.span,
                        message: format!(
                            "rule `{}` has unknown binding `{root}` in `record {record_schema}` field `{field}`",
                            rule.name.name
                        ),
                        suggestion: Some(
                            "reference a binding from a `when ... as name` clause, an effect `as` binding, or a `case` pattern"
                                .to_owned(),
                        ),
                    });
                }
            }
        }
    }

    validate_literal_assignment(
        rule,
        record_schema,
        field,
        field_ty,
        expr,
        semantic,
        diagnostics,
    );
    validate_expected_assignment(
        rule,
        record_schema,
        field,
        field_ty,
        expr,
        semantic,
        binding_types,
        diagnostics,
    );
}

fn record_field_assignment(line: &str) -> Option<(&str, &str)> {
    let field_end = line.find(char::is_whitespace)?;
    let field = &line[..field_end];
    let expr = line[field_end..].trim();
    (!field.is_empty() && !expr.is_empty()).then_some((field, expr))
}

/// Roots valid in value positions without being author bindings: the
/// external-event payload and the coerce prompt context. An explicit allowlist
/// so genuine typos are still caught.
const SPECIAL_VALUE_ROOTS: &[&str] = &["external", "ctx"];

/// Collects every binding NAME a rule body introduces, from the parsed AST so it
/// is robust to multi-line prompts and nesting (the line-based effect collectors
/// only track `coerce`/`claim`, so `tell`/`exec`/etc. bindings are invisible to
/// `binding_types`). Used to reject dangling roots in value positions without
/// false-flagging valid effect results, `after` aliases, or case bindings.
fn collect_all_binding_names(statements: &[body::BodyStmt], out: &mut BTreeSet<String>) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                if let Some(binding) = &effect.binding {
                    out.insert(binding.clone());
                }
            }
            body::BodyStmt::Region(region) => {
                if let Some(view) = &region.lapse_binding {
                    out.insert(view.clone());
                }
                collect_all_binding_names(&region.body, out);
                collect_all_binding_names(&region.lapse_body, out);
            }
            body::BodyStmt::After(after) => {
                if let Some(alias) = &after.alias {
                    out.insert(alias.clone());
                }
                collect_all_binding_names(&after.body, out);
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    if let Some(binding) = &branch.binding {
                        out.insert(binding.clone());
                    }
                    collect_all_binding_names(&branch.body, out);
                }
            }
            // `redact … as <out>` and `declassify … as <out>` both introduce
            // the projected binding `out`.
            body::BodyStmt::Redact { binding, .. } | body::BodyStmt::Declassify { binding, .. } => {
                out.insert(binding.clone());
            }
            body::BodyStmt::Record(_)
            | body::BodyStmt::Done { .. }
            | body::BodyStmt::Terminal(_)
            | body::BodyStmt::Milestone { .. }
            | body::BodyStmt::Cancel { .. } => {}
        }
    }
}

/// A `source`'s `emit <signal>` must name a declared `signal` — the ingestion
/// mirror of the rule-side "reacts to undeclared signal" check on `when <signal>`.
/// Only dotted names are typed signal declarations (a bare name is a class/fact,
/// consistent with the reaction check). Without this a source silently admits a
/// signal fact no rule can react to (rules may only react to declared signals),
/// so ingested data is dropped with no diagnostic — this lifts the guarantee to
/// static `whip check`, symmetric with the clock/file/http source runtime that
/// admits `emit_signal`.
fn validate_source_emit_signal_declared(
    source: &SourceDecl,
    declared_signals: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let signal = &source.emit.signal;
    if signal.contains('.') && !declared_signals.contains(signal) {
        let suggestion = match closest_name(signal, declared_signals.iter()) {
            Some(candidate) => {
                format!("did you mean `{candidate}`? otherwise declare `signal {signal} {{ ... }}`")
            }
            None => format!("declare `signal {signal} {{ ... }}` so rules can react to it"),
        };
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: source.emit.signal_span,
            message: format!(
                "source `{}` emits undeclared signal `{}`",
                source.name.name, signal
            ),
            suggestion: Some(suggestion),
        });
    }

    // The emit fields map the source's observation record onto the signal
    // payload by name. Each `<field> <observe>.<obsfield>` must read a real
    // observation field for this source's kind, else it silently maps null at
    // runtime. The observation schemas below MUST mirror the records built in
    // the CLI source resolvers (`resolve_due_{clock,file,http}_sources`): add a
    // field there → add it here. Unknown providers have no known schema, so
    // their emit fields are not checked (avoids false positives).
    let observation_fields: Option<&[&str]> = match source.provider.name.as_str() {
        "clock" => Some(&[
            "scheduled_at",
            "observed_at",
            "occurrence_id",
            "missed_count",
            "schedule_name",
        ]),
        // `file` observes lines in `path` mode and (path, content-hash)
        // occurrences in `watch` mode (spec/std-ingress.md I2a; content
        // READING stays std.files).
        "file" if source.watch.is_some() => Some(&["path", "content_hash", "watch"]),
        "file" => Some(&["line", "line_index", "path"]),
        "http" => Some(&["item", "item_index", "url"]),
        _ => None,
    };
    // `dedup` reads the same observation record the emit mapping reads: an
    // unknown field would make the admission key silently null at runtime.
    if let (Some(fields), Some(SourceValue::Path { segments, .. })) =
        (observation_fields, &source.dedup)
    {
        if let [field] = segments.as_slice() {
            if !fields.contains(&field.name.as_str()) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: field.span,
                    message: format!(
                        "source `{}` `dedup` reads `{}.{}`, but a `{}` source's observation has no field `{}`",
                        source.name.name,
                        source.observe_binding.name,
                        field.name,
                        source.provider.name,
                        field.name
                    ),
                    suggestion: Some(format!(
                        "available observation fields: {}",
                        fields.join(", ")
                    )),
                });
            }
        }
    }
    if let Some(fields) = observation_fields {
        let observe = &source.observe_binding.name;
        for emit_field in &source.emit.fields {
            let SourceValue::Path {
                binding,
                segments,
                span,
            } = &emit_field.value
            else {
                continue;
            };
            if &binding.name != observe {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: *span,
                    message: format!(
                        "source `{}` emit reads unknown binding `{}`",
                        source.name.name, binding.name
                    ),
                    suggestion: Some(format!(
                        "the source's observation binding is `{observe}` (declared by `observe as {observe}`)"
                    )),
                });
                continue;
            }
            if let Some(obs_field) = segments.first() {
                if !fields.contains(&obs_field.name.as_str()) {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: obs_field.span,
                        message: format!(
                            "source `{}` emit reads `{}.{}`, but a `{}` source's observation has no field `{}`",
                            source.name.name, observe, obs_field.name, source.provider.name, obs_field.name
                        ),
                        suggestion: Some(format!(
                            "available observation fields: {}",
                            fields.join(", ")
                        )),
                    });
                }
            }
        }
    }
}

/// `emit signal <name> to <target>` requires `<name>` to be a declared `signal`
/// — the declaration is the typed payload contract at the emit site, symmetric
/// with the reaction-side "reacts to undeclared signal" check on `when <signal>`
/// (spec/event-ingress.md, "Directed injection"). Without this, an emit of an
/// undeclared signal only fails at runtime when the effect input is built
/// (`whipplescript_kernel::rule_lowering`, "emit signal of undeclared signal");
/// this lifts the same guarantee to static `whip check`. Recurses into
/// `after`/`case`/`branch`/`handler` bodies so a nested emit is covered too.
fn validate_emit_signal_declarations(
    rule: &RuleDecl,
    statements: &[body::BodyStmt],
    declared_signals: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => {
                if let body::BodyEffectKind::Notify { event, .. } = &effect.kind {
                    if !declared_signals.contains(event) {
                        diagnostics.push(Diagnostic {
                            related: Vec::new(),
                            span: effect.span,
                            message: format!(
                                "rule `{}` emits undeclared signal `{event}`",
                                rule.name.name
                            ),
                            suggestion: Some(format!(
                                "declare `signal {event} {{ ... }}` so the emitted payload is typed and admissible, \
                                 or check the signal name"
                            )),
                        });
                    }
                }
            }
            body::BodyStmt::After(after) => {
                validate_emit_signal_declarations(rule, &after.body, declared_signals, diagnostics)
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    validate_emit_signal_declarations(
                        rule,
                        &branch.body,
                        declared_signals,
                        diagnostics,
                    );
                }
            }
            _ => {}
        }
    }
}

/// Flags dangling roots in the field payloads of body-AST effects that the
/// line-based validators don't reach: `emit`/`notify` (`Notify`), `file item
/// into` (`TrackerFile`), and ledger `append` (`LedgerAppend`). Uses the parsed
/// AST and the same root check as the record/coerce/tell/invoke validators.
fn validate_effect_field_roots(
    rule: &RuleDecl,
    statements: &[body::BodyStmt],
    known_roots: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        match statement {
            body::BodyStmt::Effect(effect) => match &effect.kind {
                body::BodyEffectKind::Notify {
                    target_expr,
                    event,
                    from,
                    fields,
                } => {
                    if let Some(from) = from {
                        check_operand_root(
                            rule,
                            &format!("emit `{event}` from"),
                            from,
                            known_roots,
                            diagnostics,
                        );
                    }
                    check_operand_root(
                        rule,
                        &format!("emit `{event}` target"),
                        target_expr,
                        known_roots,
                        diagnostics,
                    );
                    check_field_value_roots(
                        rule,
                        &format!("emit `{event}`"),
                        fields,
                        known_roots,
                        diagnostics,
                    );
                }
                body::BodyEffectKind::TrackerFile { queue, fields } => {
                    check_field_value_roots(
                        rule,
                        &format!("file into `{queue}`"),
                        fields,
                        known_roots,
                        diagnostics,
                    );
                }
                body::BodyEffectKind::ObtainCredential {
                    credential, fields, ..
                } => {
                    check_field_value_roots(
                        rule,
                        &format!("obtain credential `{credential}`"),
                        fields,
                        known_roots,
                        diagnostics,
                    );
                }
                body::BodyEffectKind::TrackerFinish { item, fields } => {
                    check_operand_root(rule, "finish item", item, known_roots, diagnostics);
                    check_field_value_roots(rule, "finish", fields, known_roots, diagnostics);
                }
                body::BodyEffectKind::LedgerAppend { ledger, fields, .. } => {
                    check_field_value_roots(
                        rule,
                        &format!("append to `{ledger}`"),
                        fields,
                        known_roots,
                        diagnostics,
                    );
                }
                body::BodyEffectKind::LeaseAcquire {
                    resource, key_expr, ..
                } => {
                    check_operand_root(
                        rule,
                        &format!("acquire `{resource}` key"),
                        key_expr,
                        known_roots,
                        diagnostics,
                    );
                }
                body::BodyEffectKind::CounterConsume {
                    counter,
                    key_expr,
                    amount_expr,
                } => {
                    check_operand_root(
                        rule,
                        &format!("consume `{counter}` key"),
                        key_expr,
                        known_roots,
                        diagnostics,
                    );
                    check_operand_root(
                        rule,
                        &format!("consume `{counter}` amount"),
                        amount_expr,
                        known_roots,
                        diagnostics,
                    );
                }
                _ => {}
            },
            body::BodyStmt::After(after) => {
                validate_effect_field_roots(rule, &after.body, known_roots, diagnostics)
            }
            body::BodyStmt::Case(case) => {
                for branch in &case.branches {
                    validate_effect_field_roots(rule, &branch.body, known_roots, diagnostics);
                }
            }
            _ => {}
        }
    }
}

/// The single source of truth for value-position root validation: returns the
/// dangling root of a single-path value expression — a `root.field…` access whose
/// root is neither a known binding nor a recognized special root — or `None`.
/// Bare atoms (agents, enum variants, literals) have no path and are ignored; the
/// `"`-guard skips values whose "path" was mis-extracted from inside a string
/// literal. Used by every value-position validator (record/terminal/coerce/tell/
/// invoke/effect payloads/operands).
fn dangling_value_root(value: &str, known_roots: &BTreeSet<String>) -> Option<String> {
    let (root, path) = expression_path(value)?;
    if !path.is_empty()
        && !value.contains('"')
        && !known_roots.contains(&root)
        && !SPECIAL_VALUE_ROOTS.contains(&root.as_str())
    {
        Some(root)
    } else {
        None
    }
}

/// Flags a dangling root in a single effect-operand expression (e.g. an
/// `emit ... to <target>` target, a lease/counter `for <key>` key). Same check
/// as the field/record validators.
fn check_operand_root(
    rule: &RuleDecl,
    context: &str,
    operand: &str,
    known_roots: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let Some(root) = dangling_value_root(operand, known_roots) {
        diagnostics.push(Diagnostic { related: Vec::new(),
            span: rule.body.span,
            message: format!(
                "rule `{}` has unknown binding `{root}` in {context} `{operand}`",
                rule.name.name
            ),
            suggestion: Some(
                "reference a binding from a `when ... as name` clause, an effect `as` binding, or a `case` pattern"
                    .to_owned(),
            ),
        });
    }
}

fn check_field_value_roots(
    rule: &RuleDecl,
    context: &str,
    fields: &[body::FieldAssign],
    known_roots: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for field in fields {
        match &field.value {
            body::FieldValue::Expr { source, .. } => {
                if let Some(root) = dangling_value_root(source, known_roots) {
                    diagnostics.push(Diagnostic { related: Vec::new(),
                        span: rule.body.span,
                        message: format!(
                            "rule `{}` has unknown binding `{root}` in {context} field `{}`",
                            rule.name.name, field.name
                        ),
                        suggestion: Some(
                            "reference a binding from a `when ... as name` clause, an effect `as` binding, or a `case` pattern"
                                .to_owned(),
                        ),
                    });
                }
            }
            body::FieldValue::Nested { fields, .. } => {
                check_field_value_roots(rule, context, fields, known_roots, diagnostics)
            }
            body::FieldValue::Shorthand => {}
        }
    }
}

/// The complete set of value-position binding roots for a rule: `when` bindings
/// plus every binding the body introduces, collected from the parsed AST.
fn known_roots_for_rule(rule: &RuleDecl, body_ast: &body::BodyAst) -> BTreeSet<String> {
    let mut roots: BTreeSet<String> = binding_types_for_rule(rule).into_keys().collect();
    collect_all_binding_names(&body_ast.statements, &mut roots);
    roots
}

fn validate_record_blocks(
    rule: &RuleDecl,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    known_roots: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (schema, from_binding, body) in record_blocks(&rule.body.text) {
        // A token where a field NAME was expected is a value the author wrote
        // that nothing consumes. The splitter skips it silently, so
        // `record Out { title  "hello" }` compiled clean and recorded the
        // shorthand's value instead of the literal — a different value than the
        // source says, with no diagnostic anywhere.
        for stray in body::stray_value_tokens(&body) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "rule `{}` has a value with no field name in `record {schema}`: `{stray}`",
                    rule.name.name
                ),
                suggestion: Some(format!(
                    "give it a field name (`<field> {stray}`), or remove it"
                )),
            });
        }
        for assignment in collect_field_assignments(&body) {
            let (field, value) = match assignment {
                RecordFieldAssignment::Value { field, value } => (field, value),
                RecordFieldAssignment::Shorthand { field } => {
                    let value = from_binding
                        .as_ref()
                        .map(|binding| format!("{binding}.{field}"))
                        .unwrap_or_else(|| field.clone());
                    (field, value)
                }
            };
            let line = format!("{field} {value}");
            validate_record_field(
                rule,
                &line,
                &schema,
                semantic,
                binding_types,
                known_roots,
                diagnostics,
            );
        }
    }
}

fn record_blocks(body: &str) -> Vec<(String, Option<String>, String)> {
    let mut blocks = Vec::new();
    let lines = body.lines().collect::<Vec<_>>();
    let mut index = 0usize;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        let Some((schema, from_binding)) = parse_record_start(trimmed) else {
            index += 1;
            continue;
        };
        // Single-line record `record X { f y }`: opens and closes on one line
        // (brace_delta 0), so the multi-line loop below never collects its fields,
        // leaving them unvalidated. Extract the inner content directly.
        if brace_delta(trimmed) == 0 && trimmed.contains('{') {
            if let (Some(open), Some(close)) = (trimmed.find('{'), trimmed.rfind('}')) {
                if close > open {
                    blocks.push((
                        schema,
                        from_binding,
                        trimmed[open + 1..close].trim().to_owned(),
                    ));
                }
            }
            index += 1;
            continue;
        }
        let mut depth = brace_delta(trimmed);
        let mut record_lines = Vec::new();
        index += 1;
        while index < lines.len() && depth > 0 {
            let line = lines[index];
            let before = depth;
            depth += brace_delta(line);
            if !(before == 1 && depth == 0 && line.trim() == "}") {
                record_lines.push(line.to_owned());
            }
            index += 1;
        }
        blocks.push((schema, from_binding, record_lines.join("\n")));
    }
    blocks
}

fn workflow_terminal_blocks(body: &str) -> Vec<(String, String, String)> {
    let mut blocks = Vec::new();
    let lines = body.lines().collect::<Vec<_>>();
    let mut index = 0usize;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        let terminal = trimmed
            .strip_prefix("complete ")
            .map(|rest| ("complete", rest))
            .or_else(|| trimmed.strip_prefix("fail ").map(|rest| ("fail", rest)));
        let Some((action, rest)) = terminal else {
            index += 1;
            continue;
        };
        let Some(name) = rest.split('{').next().and_then(|header| {
            let mut parts = header.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some(name), None) => Some(name.to_owned()),
                _ => None,
            }
        }) else {
            index += 1;
            continue;
        };
        let mut depth = brace_delta(trimmed);
        let mut terminal_lines = Vec::new();
        if depth == 0 && trimmed.contains('{') {
            // Single-line block: `complete <name> { <fields> }` opens and closes
            // on this line, so its inner content never reaches the multi-line loop
            // below. Capture the content between the braces as the block body.
            if let (Some(open), Some(close)) = (trimmed.find('{'), trimmed.rfind('}')) {
                if close > open {
                    let inner = trimmed[open + 1..close].trim();
                    if !inner.is_empty() {
                        terminal_lines.push(inner.to_owned());
                    }
                }
            }
            index += 1;
        } else {
            index += 1;
            while index < lines.len() && depth > 0 {
                let line = lines[index];
                let before = depth;
                depth += brace_delta(line);
                if !(before == 1 && depth == 0 && line.trim() == "}") {
                    terminal_lines.push(line.to_owned());
                }
                index += 1;
            }
        }
        blocks.push((action.to_owned(), name, terminal_lines.join("\n")));
    }
    blocks
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RecordFieldAssignment {
    Value { field: String, value: String },
    Shorthand { field: String },
}

fn collect_field_assignments(body: &str) -> Vec<RecordFieldAssignment> {
    // Token-level splitting (R5): structure comes from tokens, never line
    // breaks, so a single-line multi-field payload
    // (`complete result { first "a" second "b" }`) collects every field —
    // the same splitter the kernel and table rows already use.
    body::split_field_assignments(body)
        .into_iter()
        .map(|assignment| match assignment.value {
            Some(value) => RecordFieldAssignment::Value {
                field: assignment.name,
                value,
            },
            None => RecordFieldAssignment::Shorthand {
                field: assignment.name,
            },
        })
        .collect()
}

fn expression_path(expr: &str) -> Option<(String, Vec<String>)> {
    let mut paths = dotted_paths(expr);
    if paths.len() != 1 {
        return None;
    }
    Some(paths.remove(0))
}

fn validate_literal_assignment(
    rule: &RuleDecl,
    record_schema: &str,
    field: &str,
    field_ty: &TypeSyntax,
    expr: &str,
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(literal) = parse_literal_expr(expr) else {
        return;
    };

    match field_ty {
        TypeSyntax::Primitive { name, .. } => {
            validate_primitive_literal(rule, record_schema, field, name, &literal, diagnostics)
        }
        TypeSyntax::LiteralString { value, .. } => {
            if literal != LiteralExpr::String(value.as_str()) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: rule.body.span,
                    message: format!(
                        "field `{record_schema}.{field}` expects literal string `{value}`"
                    ),
                    suggestion: Some(format!("record `{field} {value:?}`")),
                });
            }
        }
        TypeSyntax::Ref { name } => {
            validate_enum_literal(
                rule,
                record_schema,
                field,
                &name.name,
                &literal,
                semantic,
                diagnostics,
            );
        }
        TypeSyntax::Union { variants, .. } => {
            validate_union_literal(rule, record_schema, field, variants, &literal, diagnostics);
        }
        TypeSyntax::AgentRef { agents, .. } => {
            validate_agent_ref_literal(rule, record_schema, field, agents, &literal, diagnostics);
        }
        TypeSyntax::Optional { inner, .. } => {
            if literal != LiteralExpr::Null {
                validate_literal_assignment(
                    rule,
                    record_schema,
                    field,
                    inner,
                    expr,
                    semantic,
                    diagnostics,
                );
            }
        }
        // DR-0074 §1: a sealed value has no literal form. It arises only from
        // `seal`, so a literal in this position is always wrong, and saying so
        // is more useful than the mismatch it would otherwise surface later.
        //
        // A bare IDENTIFIER is exempt, and the exemption is load-bearing rather
        // than a loosening: `LiteralExpr::Ident` is how a binding reference
        // parses in a field position, so refusing it here made the only value
        // that CAN legally land in a sealed field — a `seal`'s own output —
        // unstorable. The binding's type is checked by the ordinary assignment
        // path; this arm is about literals.
        TypeSyntax::Sealed { .. } => {
            if !matches!(literal, LiteralExpr::Ident(_)) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: rule.body.span,
                    message: format!(
                        "field `{record_schema}.{field}` expects `{}`, which has no literal form",
                        field_ty.to_source()
                    ),
                    suggestion: Some(format!(
                        "seal a value first: `seal <value> with <credential> as v`, then use \
                         `v` — a `{}` arises only from `seal`",
                        field_ty.to_source()
                    )),
                });
            }
        }
        // DR-0053 §5: a secret has no literal form either — a credential is
        // never a value in source. Reached directly now that `secret` is its
        // own type-syntax variant rather than a primitive name.
        TypeSyntax::Secret { .. } => {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "field `{record_schema}.{field}` is `{}`: secrets have no literal form",
                    field_ty.to_source()
                ),
                suggestion: Some(
                    "reference a declared credential; material lives with the custodian, never \
                     in source"
                        .to_owned(),
                ),
            });
        }
        TypeSyntax::Array { .. } | TypeSyntax::Map { .. } => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_expected_assignment(
    rule: &RuleDecl,
    record_schema: &str,
    field: &str,
    field_ty: &TypeSyntax,
    expr: &str,
    semantic: &SemanticContext,
    binding_types: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !(expr.trim_start().starts_with('{') || expr.trim_start().starts_with('[')) {
        return;
    }
    validate_expr_source_against_type(
        rule,
        record_schema,
        field,
        field_ty,
        expr,
        semantic,
        &ExprScope::from_bindings(binding_types),
        diagnostics,
    );
}

#[allow(clippy::too_many_arguments)]
fn validate_expr_source_against_type(
    rule: &RuleDecl,
    record_schema: &str,
    field: &str,
    expected_ty: &TypeSyntax,
    expr: &str,
    semantic: &SemanticContext,
    scope: &ExprScope,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match expected_ty {
        TypeSyntax::Map { inner, .. } => {
            let parsed = match parse_expression(expr) {
                Ok(Expr::Object(fields)) => fields,
                Ok(_) => {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: rule.body.span,
                        message: format!("field `{record_schema}.{field}` expects a map literal"),
                        suggestion: Some(format!("record `{field} {{ key value }}`")),
                    });
                    return;
                }
                Err(message) => {
                    diagnostics.push(Diagnostic {
                        related: Vec::new(),
                        span: rule.body.span,
                        message: format!(
                            "field `{record_schema}.{field}` expects a map literal: {message}"
                        ),
                        suggestion: Some(format!("record `{field} {{ key value }}`")),
                    });
                    return;
                }
            };
            for map_field in &parsed {
                validate_expr_against_type(
                    rule,
                    record_schema,
                    field,
                    inner,
                    &map_field.value,
                    semantic,
                    scope,
                    diagnostics,
                );
            }
        }
        TypeSyntax::Array { inner, .. } => match parse_expression(expr) {
            Ok(Expr::Array(items)) => {
                for item in items {
                    validate_expr_against_type(
                        rule,
                        record_schema,
                        field,
                        inner,
                        &item,
                        semantic,
                        scope,
                        diagnostics,
                    );
                }
            }
            Ok(expr) => validate_inferred_assignment_type(
                rule,
                record_schema,
                field,
                expected_ty,
                &expr,
                semantic,
                scope,
                diagnostics,
            ),
            Err(message) => {
                push_invalid_assignment_expr(rule, record_schema, field, message, diagnostics)
            }
        },
        TypeSyntax::Optional { inner, .. } => {
            if expr.trim() != "null" {
                validate_expr_source_against_type(
                    rule,
                    record_schema,
                    field,
                    inner,
                    expr,
                    semantic,
                    scope,
                    diagnostics,
                );
            }
        }
        TypeSyntax::Ref { name } if semantic.schemas.class_exists(&name.name) => {
            let parsed = match parse_expression(expr) {
                Ok(Expr::Object(fields)) => fields,
                Ok(expr) => {
                    validate_inferred_assignment_type(
                        rule,
                        record_schema,
                        field,
                        expected_ty,
                        &expr,
                        semantic,
                        scope,
                        diagnostics,
                    );
                    return;
                }
                Err(message) => {
                    push_invalid_assignment_expr(rule, record_schema, field, message, diagnostics);
                    return;
                }
            };
            validate_object_literal_fields(
                rule,
                record_schema,
                field,
                &name.name,
                &parsed,
                semantic,
                scope,
                diagnostics,
            );
        }
        _ => match parse_expression(expr) {
            Ok(expr) => validate_inferred_assignment_type(
                rule,
                record_schema,
                field,
                expected_ty,
                &expr,
                semantic,
                scope,
                diagnostics,
            ),
            Err(message) => {
                push_invalid_assignment_expr(rule, record_schema, field, message, diagnostics)
            }
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_expr_against_type(
    rule: &RuleDecl,
    record_schema: &str,
    field: &str,
    expected_ty: &TypeSyntax,
    expr: &Expr,
    semantic: &SemanticContext,
    scope: &ExprScope,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match expr {
        Expr::Array(items) if matches!(expected_ty, TypeSyntax::Array { .. }) => {
            if let TypeSyntax::Array { inner, .. } = expected_ty {
                for item in items {
                    validate_expr_against_type(
                        rule,
                        record_schema,
                        field,
                        inner,
                        item,
                        semantic,
                        scope,
                        diagnostics,
                    );
                }
            }
        }
        Expr::Object(fields) => match expected_ty {
            TypeSyntax::Map { inner, .. } => {
                for field in fields {
                    validate_expr_against_type(
                        rule,
                        record_schema,
                        field.key.as_str(),
                        inner,
                        &field.value,
                        semantic,
                        scope,
                        diagnostics,
                    );
                }
            }
            TypeSyntax::Ref { name } if semantic.schemas.class_exists(&name.name) => {
                validate_object_literal_fields(
                    rule,
                    record_schema,
                    field,
                    &name.name,
                    fields,
                    semantic,
                    scope,
                    diagnostics,
                );
            }
            _ => validate_inferred_assignment_type(
                rule,
                record_schema,
                field,
                expected_ty,
                expr,
                semantic,
                scope,
                diagnostics,
            ),
        },
        _ => validate_inferred_assignment_type(
            rule,
            record_schema,
            field,
            expected_ty,
            expr,
            semantic,
            scope,
            diagnostics,
        ),
    }
}

fn push_invalid_assignment_expr(
    rule: &RuleDecl,
    record_schema: &str,
    field: &str,
    message: String,
    diagnostics: &mut Vec<Diagnostic>,
) {
    diagnostics.push(Diagnostic {
        related: Vec::new(),
        span: rule.body.span,
        message: format!(
            "rule `{}` has invalid expression for field `{record_schema}.{field}`: {message}",
            rule.name.name
        ),
        suggestion: Some(
            "use array literals or expected-schema object literals for collection fields"
                .to_owned(),
        ),
    });
}

#[allow(clippy::too_many_arguments)]
fn validate_object_literal_fields(
    rule: &RuleDecl,
    record_schema: &str,
    field: &str,
    object_schema: &str,
    object_fields: &[ExprObjectField],
    semantic: &SemanticContext,
    scope: &ExprScope,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(schema_fields) = semantic.schemas.classes.get(object_schema) else {
        return;
    };
    let mut seen = BTreeSet::new();
    for object_field in object_fields {
        if !seen.insert(object_field.key.clone()) {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "field `{record_schema}.{field}` repeats object field `{}`",
                    object_field.key
                ),
                suggestion: Some("remove the duplicate object field".to_owned()),
            });
            continue;
        }
        let Some(field_ty) = schema_fields.get(&object_field.key) else {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "class `{object_schema}` has no field `{}`",
                    object_field.key
                ),
                suggestion: Some(format!(
                    "add `{}` to `class {object_schema}` or use an existing field",
                    object_field.key
                )),
            });
            continue;
        };
        validate_expr_against_type(
            rule,
            object_schema,
            &object_field.key,
            field_ty,
            &object_field.value,
            semantic,
            scope,
            diagnostics,
        );
    }
    for (required, ty) in schema_fields {
        if seen.contains(required) || matches!(ty, TypeSyntax::Optional { .. }) {
            continue;
        }
        diagnostics.push(Diagnostic { related: Vec::new(),
            span: rule.body.span,
            message: format!(
                "field `{record_schema}.{field}` is missing required object field `{object_schema}.{required}`"
            ),
            suggestion: Some(format!("add `{required}` to the `{field}` object literal")),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_inferred_assignment_type(
    rule: &RuleDecl,
    record_schema: &str,
    field: &str,
    expected_ty: &TypeSyntax,
    expr: &Expr,
    semantic: &SemanticContext,
    scope: &ExprScope,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let literal = expr_literal_as_literal_expr(expr);
    if let Some(literal) = literal {
        validate_literal_against_type(
            rule,
            record_schema,
            field,
            expected_ty,
            &literal,
            semantic,
            diagnostics,
        );
        return;
    }

    let context = ExprValidationContext::rule(rule);
    let mut local_diagnostics = Vec::new();
    let actual_ty = infer_expr_type(expr, semantic, scope, &context, &mut local_diagnostics);
    diagnostics.extend(local_diagnostics);
    let expected_expr_ty = expr_type_from_type_syntax(expected_ty, semantic);
    if !types_comparable(&actual_ty, &expected_expr_ty) {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!(
                "field `{record_schema}.{field}` receives incompatible expression type"
            ),
            suggestion: Some(format!(
                "record a value compatible with `{}`",
                expected_ty.to_source()
            )),
        });
    }
}

fn validate_literal_against_type(
    rule: &RuleDecl,
    record_schema: &str,
    field: &str,
    field_ty: &TypeSyntax,
    literal: &LiteralExpr<'_>,
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match field_ty {
        TypeSyntax::Primitive { name, .. } => {
            validate_primitive_literal(rule, record_schema, field, name, literal, diagnostics)
        }
        TypeSyntax::LiteralString { value, .. } => {
            if literal != &LiteralExpr::String(value.as_str()) {
                diagnostics.push(Diagnostic {
                    related: Vec::new(),
                    span: rule.body.span,
                    message: format!(
                        "field `{record_schema}.{field}` expects literal string `{value}`"
                    ),
                    suggestion: Some(format!("record `{field} {value:?}`")),
                });
            }
        }
        TypeSyntax::Ref { name } => {
            validate_enum_literal(
                rule,
                record_schema,
                field,
                &name.name,
                literal,
                semantic,
                diagnostics,
            );
        }
        TypeSyntax::Union { variants, .. } => {
            validate_union_literal(rule, record_schema, field, variants, literal, diagnostics);
        }
        TypeSyntax::AgentRef { agents, .. } => {
            validate_agent_ref_literal(rule, record_schema, field, agents, literal, diagnostics);
        }
        TypeSyntax::Optional { inner, .. } => {
            if literal != &LiteralExpr::Null {
                validate_literal_against_type(
                    rule,
                    record_schema,
                    field,
                    inner,
                    literal,
                    semantic,
                    diagnostics,
                );
            }
        }
        // DR-0074 §1: a sealed value has no literal form. It arises only from
        // `seal`, so a literal in this position is always wrong, and saying so
        // is more useful than the mismatch it would otherwise surface later.
        TypeSyntax::Sealed { .. } => {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "field `{record_schema}.{field}` expects `{}`, which has no literal form",
                    field_ty.to_source()
                ),
                suggestion: Some(format!(
                    "seal a value first: `seal <value> as {} with <credential> -> v`, then use `v`",
                    field_ty.to_source()
                )),
            });
        }
        // DR-0053 §5: a secret has no literal form either — a credential is
        // never a value in source. Reached directly now that `secret` is its
        // own type-syntax variant rather than a primitive name.
        TypeSyntax::Secret { .. } => {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!(
                    "field `{record_schema}.{field}` is `{}`: secrets have no literal form",
                    field_ty.to_source()
                ),
                suggestion: Some(
                    "reference a declared credential; material lives with the custodian, never \
                     in source"
                        .to_owned(),
                ),
            });
        }
        TypeSyntax::Array { .. } | TypeSyntax::Map { .. } => {}
    }
}

fn expr_literal_as_literal_expr(expr: &Expr) -> Option<LiteralExpr<'_>> {
    match expr {
        Expr::Literal(ExprLiteral::String(value)) => Some(LiteralExpr::String(value)),
        Expr::Literal(ExprLiteral::Number(value)) => Some(LiteralExpr::Number(value)),
        Expr::Literal(ExprLiteral::Bool(_)) => Some(LiteralExpr::Bool),
        Expr::Literal(ExprLiteral::Null) => Some(LiteralExpr::Null),
        Expr::Literal(ExprLiteral::Ident(value)) => Some(LiteralExpr::Ident(value)),
        _ => None,
    }
}

fn validate_agent_ref_literal(
    rule: &RuleDecl,
    record_schema: &str,
    field: &str,
    agents: &[Ident],
    literal: &LiteralExpr<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let allowed = agents
        .iter()
        .map(|agent| agent.name.as_str())
        .collect::<Vec<_>>();
    if let LiteralExpr::String(value) = literal {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!(
                "field `{record_schema}.{field}` expects an AgentRef value, not string `{value}`"
            ),
            suggestion: Some(format!(
                "use an unquoted declared agent name: {}",
                allowed.join(", ")
            )),
        });
        return;
    }
    let LiteralExpr::Ident(value) = literal else {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!("field `{record_schema}.{field}` expects an AgentRef value"),
            suggestion: Some(format!("use one of: {}", allowed.join(", "))),
        });
        return;
    };
    if !allowed.contains(value) {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!("field `{record_schema}.{field}` cannot reference agent `{value}`"),
            suggestion: Some(format!("use one of: {}", allowed.join(", "))),
        });
    }
}

fn parse_literal_expr(expr: &str) -> Option<LiteralExpr<'_>> {
    let expr = expr.trim().trim_end_matches(',');
    if let Some(value) = expr
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        return Some(LiteralExpr::String(value));
    }
    if expr.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
        && expr.chars().any(|ch| ch.is_ascii_digit())
    {
        return Some(LiteralExpr::Number(expr));
    }
    match expr {
        "true" => Some(LiteralExpr::Bool),
        "false" => Some(LiteralExpr::Bool),
        "null" => Some(LiteralExpr::Null),
        value if value.chars().all(|ch| ch.is_alphanumeric() || ch == '_') => {
            Some(LiteralExpr::Ident(value))
        }
        _ => None,
    }
}

struct ExprParser<'a> {
    source: &'a str,
    tokens: Vec<ExprToken>,
    pos: usize,
    depth: usize,
}

/// Recursion-depth ceiling for the guard-expression grammar. Every level of
/// `(`/`[`/`{` nesting and every prefix `!`/`not` descends through
/// `parse_unary`, so bounding it there stops a deeply-nested expression in a
/// workflow file from overflowing the stack and aborting the process — a
/// normal `Err` diagnostic is returned instead. Far above any real expression.
const MAX_EXPR_DEPTH: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExprToken {
    kind: ExprTokenKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ExprTokenKind {
    Ident(String),
    String(String),
    Number(String),
    Symbol(char),
    Op(&'static str),
}

impl<'a> ExprParser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            tokens: lex_expr(source),
            pos: 0,
            depth: 0,
        }
    }

    fn parse(mut self) -> Result<Expr, String> {
        let expr = self.parse_or()?;
        if self.peek().is_some() {
            return Err(format!(
                "unexpected token in expression `{}`",
                self.source.trim()
            ));
        }
        Ok(expr)
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut expr = self.parse_and()?;
        while self.consume_op("||") || self.consume_ident("or") {
            let right = self.parse_and()?;
            expr = Expr::Binary {
                op: BinaryOp::Or,
                left: Box::new(expr),
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut expr = self.parse_comparison()?;
        while self.consume_op("&&") || self.consume_ident("and") {
            let right = self.parse_comparison()?;
            expr = Expr::Binary {
                op: BinaryOp::And,
                left: Box::new(expr),
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_comparison(&mut self) -> Result<Expr, String> {
        let mut expr = self.parse_additive()?;
        loop {
            let op = if self.consume_op("==") {
                Some(BinaryOp::Eq)
            } else if self.consume_op("!=") {
                Some(BinaryOp::Ne)
            } else if self.consume_op("<=") {
                Some(BinaryOp::Le)
            } else if self.consume_op(">=") {
                Some(BinaryOp::Ge)
            } else if self.consume_symbol('<') {
                Some(BinaryOp::Lt)
            } else if self.consume_symbol('>') {
                Some(BinaryOp::Gt)
            } else if self.consume_ident("not") {
                if !self.consume_ident("in") {
                    return Err("expected `in` after `not`".to_owned());
                }
                Some(BinaryOp::NotIn)
            } else if self.consume_ident("in") {
                Some(BinaryOp::In)
            } else {
                None
            };
            let Some(op) = op else {
                return Ok(expr);
            };
            let right = self.parse_additive()?;
            expr = Expr::Binary {
                op,
                left: Box::new(expr),
                right: Box::new(right),
            };
        }
    }

    fn parse_additive(&mut self) -> Result<Expr, String> {
        let mut expr = self.parse_multiplicative()?;
        loop {
            let op = if self.consume_symbol('+') {
                Some(BinaryOp::Add)
            } else if self.consume_symbol('-') {
                Some(BinaryOp::Sub)
            } else {
                None
            };
            let Some(op) = op else {
                return Ok(expr);
            };
            let right = self.parse_multiplicative()?;
            expr = Expr::Binary {
                op,
                left: Box::new(expr),
                right: Box::new(right),
            };
        }
    }

    fn parse_multiplicative(&mut self) -> Result<Expr, String> {
        let mut expr = self.parse_unary()?;
        loop {
            let op = if self.consume_symbol('*') {
                Some(BinaryOp::Mul)
            } else if self.consume_symbol('/') {
                Some(BinaryOp::Div)
            } else {
                None
            };
            let Some(op) = op else {
                return Ok(expr);
            };
            let right = self.parse_unary()?;
            expr = Expr::Binary {
                op,
                left: Box::new(expr),
                right: Box::new(right),
            };
        }
    }

    fn parse_unary(&mut self) -> Result<Expr, String> {
        // Depth guard (every nesting level descends through here): return a
        // diagnostic rather than recurse the native stack to a crash.
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            self.depth -= 1;
            return Err(format!(
                "expression in `{}` is nested too deeply (limit {MAX_EXPR_DEPTH})",
                self.source.trim()
            ));
        }
        let result = self.parse_unary_inner();
        self.depth -= 1;
        result
    }

    fn parse_unary_inner(&mut self) -> Result<Expr, String> {
        if self.consume_symbol('!') {
            return Ok(Expr::Unary {
                op: UnaryOp::Not,
                expr: Box::new(self.parse_unary()?),
            });
        }
        // Prefix `not` binds looser than comparisons so `not x in y`
        // reads as `not (x in y)`; binary `not in` is handled by
        // parse_comparison before this prefix form is reached.
        if self.consume_ident("not") {
            return Ok(Expr::Unary {
                op: UnaryOp::Not,
                expr: Box::new(self.parse_comparison()?),
            });
        }
        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Result<Expr, String> {
        let mut expr = self.parse_primary()?;
        loop {
            if self.consume_symbol('[') {
                let key = self.parse_or()?;
                self.expect_symbol(']')?;
                expr = Expr::Index {
                    target: Box::new(expr),
                    key: Box::new(key),
                };
                continue;
            }
            return Ok(expr);
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        if self.consume_symbol('(') {
            let expr = self.parse_or()?;
            self.expect_symbol(')')?;
            return Ok(expr);
        }
        if self.consume_symbol('[') {
            let mut items = Vec::new();
            if self.consume_symbol(']') {
                return Ok(Expr::Array(items));
            }
            loop {
                items.push(self.parse_or()?);
                if self.consume_symbol(']') {
                    break;
                }
                self.expect_symbol(',')?;
            }
            return Ok(Expr::Array(items));
        }
        if self.consume_symbol('{') {
            let mut fields = Vec::new();
            if self.consume_symbol('}') {
                return Ok(Expr::Object(fields));
            }
            loop {
                let key = match self.advance().map(|token| token.kind.clone()) {
                    Some(ExprTokenKind::Ident(value) | ExprTokenKind::String(value)) => value,
                    _ => return Err("expected object field name".to_owned()),
                };
                let value = self.parse_or()?;
                fields.push(ExprObjectField { key, value });
                if self.consume_symbol('}') {
                    break;
                }
                let _ = self.consume_symbol(',');
            }
            return Ok(Expr::Object(fields));
        }
        match self.advance().map(|token| token.kind.clone()) {
            Some(ExprTokenKind::String(value)) => Ok(Expr::Literal(ExprLiteral::String(value))),
            Some(ExprTokenKind::Number(value)) => Ok(Expr::Literal(ExprLiteral::Number(value))),
            Some(ExprTokenKind::Ident(value)) if value == "true" => {
                Ok(Expr::Literal(ExprLiteral::Bool(true)))
            }
            Some(ExprTokenKind::Ident(value)) if value == "false" => {
                Ok(Expr::Literal(ExprLiteral::Bool(false)))
            }
            Some(ExprTokenKind::Ident(value)) if value == "null" => {
                Ok(Expr::Literal(ExprLiteral::Null))
            }
            Some(ExprTokenKind::Ident(value)) if value == "exists" && !self.at_symbol('(') => {
                let arg = match self.parse_postfix()? {
                    Expr::Literal(ExprLiteral::Ident(path)) => Expr::Path(vec![path]),
                    expr => expr,
                };
                Ok(Expr::Call {
                    name: value,
                    args: vec![arg],
                })
            }
            Some(ExprTokenKind::Ident(value))
                if matches!(value.as_str(), "count" | "exists" | "empty")
                    && self.at_symbol('(') =>
            {
                self.expect_symbol('(')?;
                if let Some(query) = self.try_parse_query()? {
                    self.expect_symbol(')')?;
                    Ok(Expr::Call {
                        name: value,
                        args: vec![query],
                    })
                } else {
                    let mut args = Vec::new();
                    if self.consume_symbol(')') {
                        return Ok(Expr::Call { name: value, args });
                    }
                    loop {
                        args.push(self.parse_or()?);
                        if self.consume_symbol(')') {
                            break;
                        }
                        self.expect_symbol(',')?;
                    }
                    Ok(Expr::Call { name: value, args })
                }
            }
            Some(ExprTokenKind::Ident(value)) => {
                let mut path = vec![value];
                while self.consume_symbol('.') {
                    let Some(ExprTokenKind::Ident(field)) =
                        self.advance().map(|token| token.kind.clone())
                    else {
                        return Err("expected field name after `.`".to_owned());
                    };
                    path.push(field);
                }
                if path.len() == 1 {
                    Ok(Expr::Literal(ExprLiteral::Ident(path.remove(0))))
                } else {
                    Ok(Expr::Path(path))
                }
            }
            _ => Err(format!("expected expression in `{}`", self.source.trim())),
        }
    }

    fn try_parse_query(&mut self) -> Result<Option<Expr>, String> {
        let checkpoint = self.pos;
        let kind = if self.consume_ident("effect") {
            QueryKind::Effect
        } else if matches!(
            self.peek().map(|token| &token.kind),
            Some(ExprTokenKind::Ident(value)) if value.chars().next().is_some_and(char::is_uppercase)
        ) {
            QueryKind::Fact
        } else {
            return Ok(None);
        };
        let mut head = Vec::new();
        while let Some(token) = self.peek() {
            if self.at_symbol(')') || self.at_ident("where") {
                break;
            }
            head.push(self.token_text(token));
            self.pos += 1;
        }
        if head.is_empty() {
            self.pos = checkpoint;
            return Ok(None);
        }
        let guard = if self.consume_ident("where") {
            Some(Box::new(self.parse_or()?))
        } else {
            None
        };
        Ok(Some(Expr::Query {
            kind,
            head: join_query_head(&head),
            guard,
        }))
    }

    fn token_text(&self, token: &ExprToken) -> String {
        match &token.kind {
            ExprTokenKind::Ident(value) | ExprTokenKind::Number(value) => value.clone(),
            ExprTokenKind::String(value) => format!("{value:?}"),
            ExprTokenKind::Symbol(value) => value.to_string(),
            ExprTokenKind::Op(value) => value.to_string(),
        }
    }

    fn peek(&self) -> Option<&ExprToken> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<&ExprToken> {
        let token = self.tokens.get(self.pos)?;
        self.pos += 1;
        Some(token)
    }

    fn at_symbol(&self, symbol: char) -> bool {
        matches!(
            self.peek().map(|token| &token.kind),
            Some(ExprTokenKind::Symbol(value)) if *value == symbol
        )
    }

    fn consume_symbol(&mut self, symbol: char) -> bool {
        if self.at_symbol(symbol) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_symbol(&mut self, symbol: char) -> Result<(), String> {
        if self.consume_symbol(symbol) {
            Ok(())
        } else {
            Err(format!("expected `{symbol}`"))
        }
    }

    fn at_ident(&self, ident: &str) -> bool {
        matches!(
            self.peek().map(|token| &token.kind),
            Some(ExprTokenKind::Ident(value)) if value == ident
        )
    }

    fn consume_ident(&mut self, ident: &str) -> bool {
        if self.at_ident(ident) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn consume_op(&mut self, op: &'static str) -> bool {
        if matches!(
            self.peek().map(|token| &token.kind),
            Some(ExprTokenKind::Op(value)) if *value == op
        ) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
}

fn join_query_head(tokens: &[String]) -> String {
    let mut head = String::new();
    for token in tokens {
        if token == "." {
            head.push('.');
        } else if head.ends_with('.') || head.is_empty() {
            head.push_str(token);
        } else {
            head.push(' ');
            head.push_str(token);
        }
    }
    head
}

fn lex_expr(source: &str) -> Vec<ExprToken> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if is_ident_start(byte) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_ident_continue(bytes[index]) {
                index += 1;
            }
            tokens.push(ExprToken {
                kind: ExprTokenKind::Ident(source[start..index].to_owned()),
            });
            continue;
        }
        if byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.') {
                index += 1;
            }
            tokens.push(ExprToken {
                kind: ExprTokenKind::Number(source[start..index].to_owned()),
            });
            continue;
        }
        if byte == b'"' {
            let start = index + 1;
            index += 1;
            while index < bytes.len() && bytes[index] != b'"' {
                index += 1;
            }
            let value = source[start..index.min(bytes.len())].to_owned();
            index = (index + 1).min(bytes.len());
            tokens.push(ExprToken {
                kind: ExprTokenKind::String(value),
            });
            continue;
        }
        let rest = &source[index..];
        if rest.starts_with("&&") {
            tokens.push(ExprToken {
                kind: ExprTokenKind::Op("&&"),
            });
            index += 2;
        } else if rest.starts_with("||") {
            tokens.push(ExprToken {
                kind: ExprTokenKind::Op("||"),
            });
            index += 2;
        } else if rest.starts_with("==") {
            tokens.push(ExprToken {
                kind: ExprTokenKind::Op("=="),
            });
            index += 2;
        } else if rest.starts_with("!=") {
            tokens.push(ExprToken {
                kind: ExprTokenKind::Op("!="),
            });
            index += 2;
        } else if rest.starts_with("<=") {
            tokens.push(ExprToken {
                kind: ExprTokenKind::Op("<="),
            });
            index += 2;
        } else if rest.starts_with(">=") {
            tokens.push(ExprToken {
                kind: ExprTokenKind::Op(">="),
            });
            index += 2;
        } else {
            tokens.push(ExprToken {
                kind: ExprTokenKind::Symbol(byte as char),
            });
            index += 1;
        }
    }
    tokens
}

fn validate_primitive_literal(
    rule: &RuleDecl,
    record_schema: &str,
    field: &str,
    primitive: &str,
    literal: &LiteralExpr<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let valid = matches!(
        (primitive, literal),
        ("string", LiteralExpr::String(_))
            | ("string", LiteralExpr::Ident(_))
            | ("int", LiteralExpr::Number(_))
            | ("float", LiteralExpr::Number(_))
            | ("bool", LiteralExpr::Bool)
            | ("null", LiteralExpr::Null)
            | ("duration", LiteralExpr::String(_))
            | ("time", LiteralExpr::String(_))
    );
    if !valid {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!("field `{record_schema}.{field}` expects `{primitive}`"),
            suggestion: Some(format!("record a value compatible with `{primitive}`")),
        });
        return;
    }
    match (primitive, literal) {
        ("duration", LiteralExpr::String(value)) if parse_duration_seconds(value).is_none() => {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!("field `{record_schema}.{field}` has invalid duration literal"),
                suggestion: Some("use an ISO-8601 duration such as `\"PT30M\"`".to_owned()),
            });
        }
        ("time", LiteralExpr::String(value)) if parse_time_epoch_seconds(value).is_none() => {
            diagnostics.push(Diagnostic {
                related: Vec::new(),
                span: rule.body.span,
                message: format!("field `{record_schema}.{field}` has invalid time literal"),
                suggestion: Some(
                    "use an RFC3339 timestamp such as `\"2026-05-29T10:00:00Z\"`".to_owned(),
                ),
            });
        }
        _ => {}
    }
}

fn validate_enum_literal(
    rule: &RuleDecl,
    record_schema: &str,
    field: &str,
    schema: &str,
    literal: &LiteralExpr<'_>,
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(variants) = semantic.schemas.enums.get(schema) else {
        return;
    };
    let LiteralExpr::Ident(variant) = literal else {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!("field `{record_schema}.{field}` expects enum `{schema}`"),
            suggestion: Some(format!(
                "use one of: {}",
                variants.iter().cloned().collect::<Vec<_>>().join(", ")
            )),
        });
        return;
    };
    if !variants.contains(*variant) {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!("enum `{schema}` has no variant `{variant}`"),
            suggestion: Some(format!(
                "use one of: {}",
                variants.iter().cloned().collect::<Vec<_>>().join(", ")
            )),
        });
    }
}

fn validate_union_literal(
    rule: &RuleDecl,
    record_schema: &str,
    field: &str,
    variants: &[TypeSyntax],
    literal: &LiteralExpr<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let allowed = variants
        .iter()
        .filter_map(|variant| match variant {
            TypeSyntax::LiteralString { value, .. } => Some(value.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if allowed.is_empty() {
        return;
    }
    let LiteralExpr::String(value) = literal else {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!("field `{record_schema}.{field}` expects one of its literal variants"),
            suggestion: Some(format!("use one of: {}", allowed.join(", "))),
        });
        return;
    };
    if !allowed.contains(value) {
        diagnostics.push(Diagnostic {
            related: Vec::new(),
            span: rule.body.span,
            message: format!("field `{record_schema}.{field}` cannot be `{value}`"),
            suggestion: Some(format!("use one of: {}", allowed.join(", "))),
        });
    }
}

fn parse_effect_line(line: &str) -> Option<(IrEffectKind, Option<String>)> {
    let kind = if line.starts_with("tell ") {
        IrEffectKind::AgentTell
    } else if line.starts_with("coerce ") || line.starts_with("prompt ") {
        IrEffectKind::SchemaCoerce
    } else if line.starts_with("claim ") {
        IrEffectKind::TrackerClaim
    } else if line.starts_with("call ") || body::starts_with_package_effect_verb(line) {
        IrEffectKind::CapabilityCall
    } else if line.starts_with("emit ") {
        IrEffectKind::EventEmit
    } else if line.starts_with("invoke ") {
        IrEffectKind::WorkflowInvoke
    } else if line.starts_with("read ") {
        IrEffectKind::FileRead
    } else if line.starts_with("write ") {
        IrEffectKind::FileWrite
    } else if line.starts_with("import ") {
        IrEffectKind::FileImport
    } else if line.starts_with("export ") {
        IrEffectKind::FileExport
    } else if line.starts_with("acquire ") {
        IrEffectKind::LeaseAcquire
    } else if line.starts_with("renew ") {
        IrEffectKind::LeaseRenew
    } else if line.starts_with("append ") {
        IrEffectKind::LedgerAppend
    } else if line.starts_with("consume ") && line.contains(" for ") {
        // The counter verb (`consume <counter> for <key> …`); the bare
        // `consume <binding>` alias was removed, and `done` never reaches
        // this fn as an effect line.
        IrEffectKind::CounterConsume
    } else {
        return None;
    };

    Some((kind, binding_after_as(line)))
}

fn parse_consume_line(line: &str) -> Option<String> {
    // `done <binding>` consumes the matched fact. The bare `consume` alias for
    // `done` was removed; `consume <counter> for ...` is the distinct counter
    // verb (multi-word, so it never satisfies the identifier check below).
    let binding = line
        .trim()
        .trim_end_matches(';')
        .strip_prefix("done ")?
        .split("->")
        .next()
        .unwrap_or_default()
        .trim();
    let mut chars = binding.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    chars
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        .then(|| binding.to_owned())
}

fn binding_after_multiline_string_end(line: &str) -> Option<String> {
    line.strip_prefix("\"\"\"")
        .and_then(|rest| rest.trim().strip_prefix("as "))
        .and_then(|rest| rest.split_whitespace().next())
        .map(|binding| binding.trim_matches(|ch: char| !ch.is_alphanumeric() && ch != '_'))
        .filter(|binding| !binding.is_empty())
        .map(str::to_owned)
}

fn validate_rule_prompt_content_type_annotation(
    rule: &RuleDecl,
    line: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !(line.starts_with("tell ") || line.starts_with("coerce ")) {
        return;
    }
    let Some(annotation) = malformed_prompt_content_type_annotation(line) else {
        return;
    };
    diagnostics.push(Diagnostic {
        related: Vec::new(),
        span: rule.body.span,
        message: format!(
            "rule `{}` has malformed multiline prompt content type `{annotation}`",
            rule.name.name
        ),
        suggestion: Some(
            "write a supported token such as `\"\"\"markdown` or put prompt text on the next line"
                .to_owned(),
        ),
    });
}

fn validate_coerce_prompt_content_type_annotations(
    coerce: &CoerceDecl,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for line in coerce.body.text.lines().map(str::trim) {
        if !line.starts_with("prompt ") {
            continue;
        }
        let Some(annotation) = malformed_prompt_content_type_annotation(line) else {
            continue;
        };
        diagnostics.push(Diagnostic { related: Vec::new(),
            span: coerce.body.span,
            message: format!(
                "coerce `{}` has malformed multiline prompt content type `{annotation}`",
                coerce.name.name
            ),
            suggestion: Some(
                "write a supported token such as `\"\"\"markdown` or put prompt text on the next line"
                    .to_owned(),
            ),
        });
    }
}

fn malformed_prompt_content_type_annotation(line: &str) -> Option<String> {
    let (_, tail) = line.split_once("\"\"\"")?;
    let candidate = tail.trim();
    if candidate.is_empty() || candidate.contains("\"\"\"") {
        return None;
    }
    let mut parts = candidate.split_whitespace();
    let first = parts.next()?;
    let has_extra_text = parts.next().is_some();
    let first_is_supported = is_supported_prompt_content_type(first);
    let first_is_annotation_shaped = first_is_supported || first.contains('/');
    if has_extra_text && first_is_annotation_shaped {
        return Some(candidate.to_owned());
    }
    if first.contains('/') && !first_is_supported {
        return Some(first.to_owned());
    }
    None
}

fn is_supported_prompt_content_type(candidate: &str) -> bool {
    if !is_prompt_content_type_token(candidate) {
        return false;
    }
    let normalized = candidate.to_ascii_lowercase();
    normalized.contains('/')
        || matches!(
            normalized.as_str(),
            "markdown" | "json" | "text" | "plain" | "html" | "xml" | "yaml" | "yml"
        )
}

fn is_prompt_content_type_token(candidate: &str) -> bool {
    let mut chars = candidate.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '+' | '-' | '_'))
}

pub(crate) fn binding_after_as(line: &str) -> Option<String> {
    let mut tokens = line.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "as" {
            return tokens
                .next()
                .map(|binding| binding.trim_matches(|ch: char| !ch.is_alphanumeric() && ch != '_'))
                .filter(|binding| !binding.is_empty())
                .map(str::to_owned);
        }
    }
    None
}

fn parse_after_line(line: &str) -> Option<(String, DependencyPredicate)> {
    let rest = line.strip_prefix("after ")?;
    if rest.contains("=>") {
        return None;
    }
    let before_body = rest.split('{').next().unwrap_or(rest).trim();
    let mut parts = before_body.split_whitespace();
    let binding = parts.next()?.to_owned();
    let predicate = match parts.next()? {
        "succeeds" => DependencyPredicate::Succeeds,
        "fails" => DependencyPredicate::Fails,
        // `times out` / `cancelled` react only to that specific non-success
        // terminal status (spec/expression-kernel.md), mirroring succeeds/fails.
        "cancelled" => DependencyPredicate::Cancelled,
        "times" => {
            if parts.next()? != "out" {
                return None;
            }
            DependencyPredicate::TimedOut
        }
        // Coordination outcomes (spec/coordination.md) are completion-valued;
        // the arm dispatch happens on the outcome variant at lowering.
        "completes" | "held" | "contended" | "ok" | "over" | "promoted" | "conflicted"
        | "applied" | "stranded" => DependencyPredicate::Completes,
        // `after p reaches "<name>" [as m]` (Family C): consume the quoted
        // milestone name (which may contain whitespace — token-splitting used
        // to reject multi-word names); the IR predicate is completion-shaped
        // (runtime gating keys on the milestone-specific `reached` fact).
        "reaches" => {
            let rest = before_body.trim().strip_prefix(&binding)?.trim_start();
            let after_kw = rest.strip_prefix("reaches")?.trim_start();
            let quoted = after_kw.strip_prefix('"')?;
            let close = quoted.find('"')?;
            let tail = &quoted[close + 1..];
            let mut tail_parts = tail.split_whitespace();
            match (tail_parts.next(), tail_parts.next(), tail_parts.next()) {
                (None, None, None) => {}
                (Some("as"), Some(alias), None) if is_identifier(alias) => {}
                _ => return None,
            }
            return Some((binding, DependencyPredicate::Completes));
        }
        _ => return None,
    };
    match (parts.next(), parts.next(), parts.next()) {
        (None, None, None) => {}
        (Some("as"), Some(alias), None) if is_identifier(alias) => {}
        _ => return None,
    }
    Some((binding, predicate))
}

pub(crate) fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

pub(crate) fn push_line(snapshot: &mut String, line: impl AsRef<str>) {
    snapshot.push_str(line.as_ref());
    snapshot.push('\n');
}

pub(crate) fn stable_hash(value: &str) -> String {
    // SHA-256 truncated to 128 bits (the FNV-collision hardening swap):
    // source_hash/ir_hash are program-version identity — colliding them
    // aliases two program revisions. Report-schema digest patterns and the
    // Python validator mirrors must stay in lockstep with this width.
    use sha2::Digest;
    let digest = sha2::Sha256::digest(value.as_bytes());
    let mut hex = String::with_capacity(32);
    for byte in &digest[..16] {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

pub fn parse_duration_seconds(value: &str) -> Option<f64> {
    let value = value.strip_prefix('P')?;
    let mut rest = value;
    let mut seconds = 0.0;
    let mut consumed = false;
    let mut in_time = false;

    while !rest.is_empty() {
        if let Some(next) = rest.strip_prefix('T') {
            if in_time {
                return None;
            }
            in_time = true;
            rest = next;
            continue;
        }

        let number_len = rest
            .char_indices()
            .take_while(|(_, ch)| ch.is_ascii_digit() || *ch == '.')
            .map(|(index, ch)| index + ch.len_utf8())
            .last()?;
        let number = rest[..number_len].parse::<f64>().ok()?;
        if !number.is_finite() {
            return None;
        }
        let unit = rest[number_len..].chars().next()?;
        rest = &rest[number_len + unit.len_utf8()..];
        let multiplier = match (in_time, unit) {
            (false, 'D') => 86_400.0,
            (true, 'H') => 3_600.0,
            (true, 'M') => 60.0,
            (true, 'S') => 1.0,
            _ => return None,
        };
        seconds += number * multiplier;
        consumed = true;
    }

    consumed.then_some(seconds)
}

pub fn parse_time_epoch_seconds(value: &str) -> Option<f64> {
    if value.len() < 20 {
        return None;
    }
    let year = parse_fixed_i32(value, 0, 4)?;
    require_byte(value, 4, b'-')?;
    let month = parse_fixed_u32(value, 5, 2)?;
    require_byte(value, 7, b'-')?;
    let day = parse_fixed_u32(value, 8, 2)?;
    require_byte(value, 10, b'T')?;
    let hour = parse_fixed_u32(value, 11, 2)?;
    require_byte(value, 13, b':')?;
    let minute = parse_fixed_u32(value, 14, 2)?;
    require_byte(value, 16, b':')?;
    let second = parse_fixed_u32(value, 17, 2)?;
    let mut offset_start = 19;
    let mut fractional_second = 0.0;
    if value.as_bytes().get(offset_start).copied() == Some(b'.') {
        let fraction_start = offset_start + 1;
        let fraction_len = value[fraction_start..]
            .char_indices()
            .take_while(|(_, ch)| ch.is_ascii_digit())
            .map(|(index, ch)| index + ch.len_utf8())
            .last()?;
        let fraction = &value[fraction_start..fraction_start + fraction_len];
        let scale = 10_f64.powi(i32::try_from(fraction.len()).ok()?);
        fractional_second = fraction.parse::<f64>().ok()? / scale;
        offset_start = fraction_start + fraction_len;
    }
    if !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    let offset_seconds = match value.as_bytes().get(offset_start).copied()? {
        b'Z' if value.len() == offset_start + 1 => 0,
        b'+' | b'-' if value.len() == offset_start + 6 => {
            let sign = if value.as_bytes()[offset_start] == b'+' {
                1
            } else {
                -1
            };
            let offset_hour = parse_fixed_i32(value, offset_start + 1, 2)?;
            require_byte(value, offset_start + 3, b':')?;
            let offset_minute = parse_fixed_i32(value, offset_start + 4, 2)?;
            if offset_hour > 23 || offset_minute > 59 {
                return None;
            }
            sign * (offset_hour * 3_600 + offset_minute * 60)
        }
        _ => return None,
    };

    let days = days_from_civil(year, month, day);
    let local_seconds = days * 86_400 + i64::from(hour * 3_600 + minute * 60 + second.min(59));
    Some((local_seconds - i64::from(offset_seconds)) as f64 + fractional_second)
}

fn parse_fixed_i32(value: &str, start: usize, len: usize) -> Option<i32> {
    value.get(start..start + len)?.parse::<i32>().ok()
}

fn parse_fixed_u32(value: &str, start: usize, len: usize) -> Option<u32> {
    value.get(start..start + len)?.parse::<u32>().ok()
}

fn require_byte(value: &str, index: usize, expected: u8) -> Option<()> {
    (value.as_bytes().get(index).copied()? == expected).then_some(())
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = month as i32;
    let day = day as i32;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    i64::from(era * 146_097 + day_of_era - 719_468)
}

/// Flat-prepend body emitter used where the output feeds IR construction (e.g.
/// a table's synthetic rule body, whose `body_hash` is part of program identity).
/// Kept byte-for-byte stable so the lowered IR / snapshots do not move; the
/// idempotent re-indenter for human formatting is [`format_block_body`].
fn push_block_body(body: &str, formatted: &mut String) {
    if body.is_empty() {
        return;
    }
    for line in body.lines() {
        if line.trim().is_empty() {
            formatted.push('\n');
        } else {
            push_line(formatted, format!("  {}", line.trim_end()));
        }
    }
}

/// Net bracket-depth change for one line, ignoring brackets inside strings.
/// Returns `(delta, opens_unclosed_triple)`: a `true` second element means the
/// line starts a `"""..."""` that does not close on the same line, so following
/// lines are string content. ASCII markers only — UTF-8 string bytes can't
/// false-match.
fn scan_braces(line: &str) -> (i32, bool) {
    let bytes = line.as_bytes();
    let mut index = 0;
    let mut delta = 0i32;
    let mut in_string = false;
    while index < bytes.len() {
        if in_string {
            match bytes[index] {
                b'\\' => index += 1,
                b'"' => in_string = false,
                _ => {}
            }
            index += 1;
            continue;
        }
        if line[index..].starts_with("\"\"\"") {
            match line[index + 3..].find("\"\"\"") {
                Some(offset) => index += 3 + offset + 3,
                None => return (delta, true),
            }
            continue;
        }
        match bytes[index] {
            b'"' => in_string = true,
            b'{' | b'[' | b'(' => delta += 1,
            b'}' | b']' | b')' => delta -= 1,
            _ => {}
        }
        index += 1;
    }
    (delta, false)
}

impl TypeSyntax {
    fn to_source(&self) -> String {
        match self {
            Self::Primitive { name, .. } => name.clone(),
            Self::LiteralString { value, .. } => format!("{value:?}"),
            Self::Ref { name } => name.name.clone(),
            Self::AgentRef { agents, .. } => {
                let agents = agents
                    .iter()
                    .map(|agent| agent.name.as_str())
                    .collect::<Vec<_>>()
                    .join(" | ");
                format!("AgentRef<{agents}>")
            }
            Self::Optional { inner, .. } => format!("{}?", inner.to_source()),
            Self::Array { inner, .. } => format!("{}[]", inner.to_source()),
            Self::Map { inner, .. } => format!("map<{}>", inner.to_source()),
            Self::Sealed { inner, .. } => format!("sealed<{}>", inner.to_source()),
            Self::Secret { kind: None, .. } => "secret".to_owned(),
            Self::Secret {
                kind: Some(kind), ..
            } => format!("secret<{}>", kind.name),
            Self::Union { variants, .. } => variants
                .iter()
                .map(Self::to_source)
                .collect::<Vec<_>>()
                .join(" | "),
        }
    }
}

#[cfg(test)]
#[path = "lib_tests/tests.rs"]
mod tests;
