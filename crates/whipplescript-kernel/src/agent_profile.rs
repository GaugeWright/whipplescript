//! The `std.agent` profile-preset table and capability-report data
//! (spec/std-agent.md "Profile presets" + "Capability reports", slices 4-5).
//!
//! One table, fully explicit expansions: the owned-harness boolean tool-policy
//! vector, the native tool-policy translation hints per provider class, and
//! the capability list each preset grants. The owned harness, the Codex and
//! Claude adapters, and the sidecar payload all consume COMPUTED policy from
//! these rows — no adapter hard-matches preset names, and the sidecar carries
//! no compiled-in defaults (policy-free transport).
//!
//! Pre-S6 staging (spec/std-agent.md slice 4): the table lands here as
//! compiled data; the `std.agent` embedded manifest's `profiles` section
//! mirrors it (slice 7), drift-tested from the CLI.

/// The owned-harness tool-policy vector one preset expands to (the boolean
/// vector `HarnessProfilePolicy` consumes; cli/harness_tools.rs).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnedToolPolicyRow {
    pub read_files: bool,
    pub write_files: bool,
    pub bash: bool,
    pub tracker_file: bool,
    pub tracker_claim: bool,
    pub tracker_finish: bool,
    pub tracker_release: bool,
    pub workflow_invoke: bool,
}

/// One profile-preset row (DR-0009 "Profiles And Capabilities" pinned list,
/// as explicit package data).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentProfilePreset {
    pub name: &'static str,
    /// The canonical 7 are `canonical: true`; `permissive` ships as an
    /// operator/dev-only NON-canonical row (spec/std-agent.md "Open
    /// naming-boundary questions" 1), never valid hosted.
    pub canonical: bool,
    /// The owned-harness expansion.
    pub owned: OwnedToolPolicyRow,
    /// Claude translation hint: the base allowed-tool set the adapter starts
    /// from. `None` = the preset has no Claude translation — the adapter
    /// fails closed (`unsupported_profile`), it never invents one.
    pub claude_allowed_tools: Option<&'static [&'static str]>,
    /// Whether the Codex adapter maps this preset at all (sandbox/approval
    /// still derive from the requested capabilities). `false` fails closed
    /// (`profile_denied`).
    pub codex_mapped: bool,
    /// The capability grants the preset can truthfully expand to. An adapter
    /// grants a requested capability only if it appears here.
    pub capabilities: &'static [&'static str],
}

impl AgentProfilePreset {
    pub fn grants_capability(&self, capability: &str) -> bool {
        self.capabilities.contains(&capability)
    }
}

const READ_ONLY: OwnedToolPolicyRow = OwnedToolPolicyRow {
    read_files: true,
    write_files: false,
    bash: false,
    tracker_file: false,
    tracker_claim: false,
    tracker_finish: false,
    tracker_release: false,
    workflow_invoke: true,
};

const NO_WORKSPACE: OwnedToolPolicyRow = OwnedToolPolicyRow {
    read_files: false,
    write_files: false,
    bash: false,
    tracker_file: false,
    tracker_claim: false,
    tracker_finish: false,
    tracker_release: false,
    workflow_invoke: true,
};

const FULL: OwnedToolPolicyRow = OwnedToolPolicyRow {
    read_files: true,
    write_files: true,
    bash: true,
    tracker_file: true,
    tracker_claim: true,
    tracker_finish: true,
    tracker_release: true,
    workflow_invoke: true,
};

/// The preset table: the canonical 7 (DR-0009) plus the non-canonical
/// `permissive` operator/dev row. Every expansion is explicit — closing the
/// two shipped dishonesty holes: `issue-triager` was canonical but unmapped
/// (silently permissive), and unknown presets fell through to `permissive()`
/// (now fail-closed at every consumer).
pub const AGENT_PROFILE_PRESETS: &[AgentProfilePreset] = &[
    AgentProfilePreset {
        name: "repo-reader",
        canonical: true,
        owned: READ_ONLY,
        claude_allowed_tools: Some(&["Read", "Glob", "Grep"]),
        codex_mapped: true,
        capabilities: &["repo.read"],
    },
    AgentProfilePreset {
        name: "repo-writer",
        canonical: true,
        owned: FULL,
        claude_allowed_tools: Some(&["Read", "Glob", "Grep", "Edit", "Write"]),
        codex_mapped: true,
        capabilities: &["repo.read", "repo.write", "command.run"],
    },
    AgentProfilePreset {
        name: "internet-research",
        canonical: true,
        owned: NO_WORKSPACE,
        claude_allowed_tools: None,
        codex_mapped: false,
        capabilities: &[],
    },
    AgentProfilePreset {
        // Canonical but previously unmapped in the owned harness (absent from
        // the hard-matched names), so it silently fell to permissive — the
        // explicit expansion: read the repo, work the tracker, no writes.
        name: "issue-triager",
        canonical: true,
        owned: OwnedToolPolicyRow {
            read_files: true,
            write_files: false,
            bash: false,
            tracker_file: true,
            tracker_claim: true,
            tracker_finish: true,
            tracker_release: true,
            workflow_invoke: true,
        },
        claude_allowed_tools: None,
        codex_mapped: false,
        capabilities: &["repo.read"],
    },
    AgentProfilePreset {
        name: "release-operator",
        canonical: true,
        owned: FULL,
        claude_allowed_tools: None,
        codex_mapped: false,
        capabilities: &["repo.read", "repo.write", "command.run"],
    },
    AgentProfilePreset {
        name: "no-repo",
        canonical: true,
        owned: NO_WORKSPACE,
        claude_allowed_tools: None,
        codex_mapped: false,
        capabilities: &[],
    },
    AgentProfilePreset {
        name: "permissive",
        canonical: false,
        owned: FULL,
        claude_allowed_tools: None,
        codex_mapped: false,
        capabilities: &["repo.read", "repo.write", "command.run"],
    },
];

/// Look up a preset row by name. `None` = not a preset — every consumer
/// fails closed (the permissive fallback is dead; spec/std-agent.md slice 4).
pub fn agent_profile_preset(name: &str) -> Option<&'static AgentProfilePreset> {
    AGENT_PROFILE_PRESETS
        .iter()
        .find(|preset| preset.name == name)
}

/// The minimal capability-report schema (spec/std-agent.md "Capability
/// reports", slice 5; DR-0015 "What Is Standardized" as amended to v1).
pub const AGENT_FEATURE_REPORT_SCHEMA: &str = "whipplescript.agent_feature_report.v0";

/// The DR-0015 feature-class taxonomy, verbatim (single source:
/// whipplescript-core, shared with the parser's `requires` membership check).
/// A report may only carry classes from this list (unknown class = validation
/// error).
pub const AGENT_FEATURE_CLASS_TAXONOMY: &[&str] = whipplescript_core::AGENT_FEATURE_CLASS_TAXONOMY;

/// DR-0004 + DR-0017 support vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureSupport {
    Native,
    Emulated,
    RequestOnly,
    Unsupported,
    Unknown,
}

impl FeatureSupport {
    pub fn as_str(self) -> &'static str {
        match self {
            FeatureSupport::Native => "native",
            FeatureSupport::Emulated => "emulated",
            FeatureSupport::RequestOnly => "request_only",
            FeatureSupport::Unsupported => "unsupported",
            FeatureSupport::Unknown => "unknown",
        }
    }

    /// Whether a `requires [<class>]` declaration is truthfully satisfied by
    /// an entry with this support level (DR-0015: a required class the report
    /// cannot state as supported is an error).
    pub fn satisfies_requirement(self) -> bool {
        matches!(self, FeatureSupport::Native | FeatureSupport::Emulated)
    }
}

/// Probed-vs-compiled honesty (DR-0015): v1 ships compiled claims; `whip
/// doctor --providers` may upgrade entries to `probed` from deterministic
/// local probes (deferred with cause in spec/std-agent.md).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureReportSource {
    Compiled,
    Probed,
}

impl FeatureReportSource {
    pub fn as_str(self) -> &'static str {
        match self {
            FeatureReportSource::Compiled => "compiled",
            FeatureReportSource::Probed => "probed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeatureReportEntry {
    pub class: &'static str,
    pub support: FeatureSupport,
    pub source: FeatureReportSource,
    /// Required when support is not `unsupported`/`unknown`.
    pub native_name: Option<&'static str>,
    pub dispatch: Option<&'static str>,
}

/// One provider kind's compiled feature report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentFeatureReport {
    pub provider_kind: &'static str,
    pub entries: &'static [FeatureReportEntry],
}

impl AgentFeatureReport {
    pub fn entry(&self, class: &str) -> Option<&'static FeatureReportEntry> {
        self.entries.iter().find(|entry| entry.class == class)
    }
}

const fn native(class: &'static str) -> FeatureReportEntry {
    FeatureReportEntry {
        class,
        support: FeatureSupport::Native,
        source: FeatureReportSource::Compiled,
        // The owned harness IS the runtime: the "native" mechanism is whip's
        // own brokered surface, named by the class itself.
        native_name: Some(class),
        dispatch: Some("brokered"),
    }
}

const fn unsupported(class: &'static str) -> FeatureReportEntry {
    FeatureReportEntry {
        class,
        support: FeatureSupport::Unsupported,
        source: FeatureReportSource::Compiled,
        native_name: None,
        dispatch: None,
    }
}

/// The owned harness's report: all-`native` — truthful because whip brokers
/// every tool and owns the turn loop (spec/std-agent.md "Taxonomy position of
/// `owned`"; slice 5 gate).
const OWNED_REPORT: &[FeatureReportEntry] = &[
    native("context.compact"),
    native("context.auto_compact"),
    native("session.resume"),
    native("session.fork"),
    native("session.clone"),
    native("session.export"),
    native("turn.cancel"),
    native("turn.steer"),
    native("turn.follow_up"),
    native("subagent.spawn"),
    native("subagent.observe"),
    native("subagent.steer"),
    native("skill.attach"),
    native("plugin.load"),
    native("hook.lifecycle"),
    native("native.command.dispatch"),
    native("permission.policy"),
    native("model.select"),
    native("reasoning.select"),
    native("goal.track"),
    native("command.list"),
    native("feature.report"),
];

/// The fixture reference provider: deterministic by construction. Its stub
/// honors a cooperative cancel request (catalog depth `cooperative_request`),
/// so `turn.cancel` is `request_only`; everything else is honestly
/// unsupported.
const FIXTURE_REPORT: &[FeatureReportEntry] = &[
    unsupported("context.compact"),
    unsupported("context.auto_compact"),
    unsupported("session.resume"),
    unsupported("session.fork"),
    unsupported("session.clone"),
    unsupported("session.export"),
    FeatureReportEntry {
        class: "turn.cancel",
        support: FeatureSupport::RequestOnly,
        source: FeatureReportSource::Compiled,
        native_name: Some("fixture.cancel"),
        dispatch: Some("in_process"),
    },
    unsupported("turn.steer"),
    unsupported("turn.follow_up"),
    unsupported("subagent.spawn"),
    unsupported("subagent.observe"),
    unsupported("subagent.steer"),
    unsupported("skill.attach"),
    unsupported("plugin.load"),
    unsupported("hook.lifecycle"),
    unsupported("native.command.dispatch"),
    unsupported("permission.policy"),
    unsupported("model.select"),
    unsupported("reasoning.select"),
    unsupported("goal.track"),
    unsupported("command.list"),
    unsupported("feature.report"),
];

/// The generic subprocess adapter: no feature dispatch at all (catalog
/// cancellation depth `none`); every class is honestly unsupported.
const COMMAND_REPORT: &[FeatureReportEntry] = &[
    unsupported("context.compact"),
    unsupported("context.auto_compact"),
    unsupported("session.resume"),
    unsupported("session.fork"),
    unsupported("session.clone"),
    unsupported("session.export"),
    unsupported("turn.cancel"),
    unsupported("turn.steer"),
    unsupported("turn.follow_up"),
    unsupported("subagent.spawn"),
    unsupported("subagent.observe"),
    unsupported("subagent.steer"),
    unsupported("skill.attach"),
    unsupported("plugin.load"),
    unsupported("hook.lifecycle"),
    unsupported("native.command.dispatch"),
    unsupported("permission.policy"),
    unsupported("model.select"),
    unsupported("reasoning.select"),
    unsupported("goal.track"),
    unsupported("command.list"),
    unsupported("feature.report"),
];

/// The Codex App Server adapter's compiled report (std.agent.codex, slice 7):
/// live-validated interrupt (catalog depth `native_stop`) and config-file
/// model selection; nothing else is dispatched by the adapter.
// Un-gated after the codex adapter moved to whipplescript-provider-codex
// (DR-0024): this is static feature-report VOCABULARY (what codex supports), not
// adapter code, so the kernel keeps advertising it regardless of which provider
// crates a given host builds. Making AGENT_FEATURE_REPORTS externally extensible
// (so external crates contribute their own report) is a tracked follow-on.
const CODEX_REPORT: &[FeatureReportEntry] = &[
    unsupported("context.compact"),
    unsupported("context.auto_compact"),
    unsupported("session.resume"),
    unsupported("session.fork"),
    unsupported("session.clone"),
    unsupported("session.export"),
    FeatureReportEntry {
        class: "turn.cancel",
        support: FeatureSupport::Native,
        source: FeatureReportSource::Compiled,
        native_name: Some("turn/interrupt"),
        dispatch: Some("rpc_command"),
    },
    unsupported("turn.steer"),
    unsupported("turn.follow_up"),
    unsupported("subagent.spawn"),
    unsupported("subagent.observe"),
    unsupported("subagent.steer"),
    unsupported("skill.attach"),
    unsupported("plugin.load"),
    unsupported("hook.lifecycle"),
    unsupported("native.command.dispatch"),
    unsupported("permission.policy"),
    FeatureReportEntry {
        class: "model.select",
        support: FeatureSupport::Native,
        source: FeatureReportSource::Compiled,
        native_name: Some("model"),
        dispatch: Some("config_file"),
    },
    unsupported("reasoning.select"),
    unsupported("goal.track"),
    unsupported("command.list"),
    unsupported("feature.report"),
];

/// The Claude Agent SDK adapter's compiled report (std.agent.claude, slice 7).
/// `turn.cancel` is `unknown` per DR-0017 "Cancellation should remain
/// conservative" — the report half of the slice-2 honesty fix: never state
/// support for cancellation that has not been live-validated. Tool policy and
/// model selection ARE live-wired SDK options.
// Un-gated after the claude adapter moved to whipplescript-provider-claude
// (DR-0024): static feature-report vocabulary, like CODEX_REPORT above.
const CLAUDE_REPORT: &[FeatureReportEntry] = &[
    unsupported("context.compact"),
    unsupported("context.auto_compact"),
    unsupported("session.resume"),
    unsupported("session.fork"),
    unsupported("session.clone"),
    unsupported("session.export"),
    FeatureReportEntry {
        class: "turn.cancel",
        support: FeatureSupport::Unknown,
        source: FeatureReportSource::Compiled,
        native_name: None,
        dispatch: None,
    },
    unsupported("turn.steer"),
    unsupported("turn.follow_up"),
    unsupported("subagent.spawn"),
    unsupported("subagent.observe"),
    unsupported("subagent.steer"),
    unsupported("skill.attach"),
    unsupported("plugin.load"),
    unsupported("hook.lifecycle"),
    unsupported("native.command.dispatch"),
    FeatureReportEntry {
        class: "permission.policy",
        support: FeatureSupport::Native,
        source: FeatureReportSource::Compiled,
        native_name: Some("allowedTools/disallowedTools/permissionMode"),
        dispatch: Some("sdk_option"),
    },
    FeatureReportEntry {
        class: "model.select",
        support: FeatureSupport::Native,
        source: FeatureReportSource::Compiled,
        native_name: Some("model"),
        dispatch: Some("sdk_option"),
    },
    unsupported("reasoning.select"),
    unsupported("goal.track"),
    unsupported("command.list"),
    unsupported("feature.report"),
];

/// The compiled reports, one per provider kind this binary knows: std.agent's
/// own providers always; codex/claude iff their adapter feature is compiled
/// (manifest presence and adapter presence agree by construction, slice 7).
pub const AGENT_FEATURE_REPORTS: &[AgentFeatureReport] = &[
    AgentFeatureReport {
        provider_kind: "owned",
        entries: OWNED_REPORT,
    },
    AgentFeatureReport {
        provider_kind: "fixture",
        entries: FIXTURE_REPORT,
    },
    AgentFeatureReport {
        provider_kind: "native-fixture",
        entries: FIXTURE_REPORT,
    },
    AgentFeatureReport {
        provider_kind: "command",
        entries: COMMAND_REPORT,
    },
    AgentFeatureReport {
        provider_kind: "codex",
        entries: CODEX_REPORT,
    },
    AgentFeatureReport {
        provider_kind: "claude",
        entries: CLAUDE_REPORT,
    },
];

/// Look up the compiled report for a provider kind.
pub fn agent_feature_report(provider_kind: &str) -> Option<&'static AgentFeatureReport> {
    AGENT_FEATURE_REPORTS
        .iter()
        .find(|report| report.provider_kind == provider_kind)
}

/// Whether `class` is a DR-0015 taxonomy member.
pub fn is_agent_feature_class(class: &str) -> bool {
    AGENT_FEATURE_CLASS_TAXONOMY.contains(&class)
}

/// Schema validation for one report (spec/std-agent.md "Static checks" 4):
/// classes must be taxonomy members, exactly the full taxonomy once each
/// (the v1 minimal report is the class list verbatim), and a stated support
/// level must carry its native_name/dispatch pair.
pub fn validate_agent_feature_report(report: &AgentFeatureReport) -> Vec<String> {
    let mut problems = Vec::new();
    for entry in report.entries {
        if !is_agent_feature_class(entry.class) {
            problems.push(format!(
                "report `{}` states unknown feature class `{}` (not in the DR-0015 taxonomy)",
                report.provider_kind, entry.class
            ));
        }
        let stated = !matches!(
            entry.support,
            FeatureSupport::Unsupported | FeatureSupport::Unknown
        );
        if stated && (entry.native_name.is_none() || entry.dispatch.is_none()) {
            problems.push(format!(
                "report `{}` class `{}` states support `{}` without native_name + dispatch",
                report.provider_kind,
                entry.class,
                entry.support.as_str()
            ));
        }
        if !stated && (entry.native_name.is_some() || entry.dispatch.is_some()) {
            problems.push(format!(
                "report `{}` class `{}` carries native_name/dispatch for `{}` support",
                report.provider_kind,
                entry.class,
                entry.support.as_str()
            ));
        }
    }
    for class in AGENT_FEATURE_CLASS_TAXONOMY {
        let count = report
            .entries
            .iter()
            .filter(|entry| entry.class == *class)
            .count();
        if count != 1 {
            problems.push(format!(
                "report `{}` must state class `{class}` exactly once (found {count})",
                report.provider_kind
            ));
        }
    }
    problems
}

/// The canonical preset names (DR-0009 pinned list) for diagnostics.
pub fn canonical_preset_names() -> Vec<&'static str> {
    AGENT_PROFILE_PRESETS
        .iter()
        .filter(|preset| preset.canonical)
        .map(|preset| preset.name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DR-0009 canonical 7 are all present, exactly once each, and
    /// `permissive` is the only non-canonical row.
    #[test]
    fn table_carries_the_canonical_seven_plus_permissive() {
        let canonical = canonical_preset_names();
        assert_eq!(
            canonical,
            vec![
                "repo-reader",
                "repo-writer",
                "internet-research",
                "issue-triager",
                "release-operator",
                "no-repo",
            ]
        );
        let non_canonical: Vec<_> = AGENT_PROFILE_PRESETS
            .iter()
            .filter(|preset| !preset.canonical)
            .map(|preset| preset.name)
            .collect();
        assert_eq!(non_canonical, vec!["permissive"]);
        for preset in AGENT_PROFILE_PRESETS {
            assert_eq!(
                AGENT_PROFILE_PRESETS
                    .iter()
                    .filter(|other| other.name == preset.name)
                    .count(),
                1,
                "preset `{}` must appear exactly once",
                preset.name
            );
        }
    }

    /// `issue-triager` is mapped (the shipped hole this table closes): repo
    /// read + tracker work, no writes, no bash.
    #[test]
    fn issue_triager_expansion_is_explicit() {
        let preset = agent_profile_preset("issue-triager").expect("mapped");
        assert!(preset.owned.read_files);
        assert!(!preset.owned.write_files);
        assert!(!preset.owned.bash);
        assert!(preset.owned.tracker_file && preset.owned.tracker_claim);
        assert!(preset.owned.tracker_finish && preset.owned.tracker_release);
    }

    /// Unknown names resolve to nothing — the consumer-side fail-closed hook.
    #[test]
    fn unknown_preset_is_not_in_the_table() {
        assert!(agent_profile_preset("docs-reader").is_none());
        assert!(agent_profile_preset("").is_none());
    }

    /// Slice 5 gate: every compiled report passes schema validation.
    #[test]
    fn compiled_feature_reports_validate() {
        for report in AGENT_FEATURE_REPORTS {
            let problems = validate_agent_feature_report(report);
            assert!(
                problems.is_empty(),
                "report `{}` invalid: {problems:?}",
                report.provider_kind
            );
        }
    }

    /// Slice 5 gate: the owned report is all-`native` (whip brokers every
    /// tool; spec/std-agent.md "Taxonomy position of `owned`").
    #[test]
    fn owned_report_is_all_native() {
        let report = agent_feature_report("owned").expect("owned report");
        assert_eq!(report.entries.len(), AGENT_FEATURE_CLASS_TAXONOMY.len());
        for entry in report.entries {
            assert_eq!(
                entry.support,
                FeatureSupport::Native,
                "owned class `{}` must be native",
                entry.class
            );
            assert_eq!(entry.source, FeatureReportSource::Compiled);
        }
    }

    /// Slice 5 gate: the fixture report is deterministic — compiled-source,
    /// cooperative-request cancel (matching the catalog depth), everything
    /// else unsupported.
    #[test]
    fn fixture_report_is_deterministic() {
        let report = agent_feature_report("fixture").expect("fixture report");
        for entry in report.entries {
            assert_eq!(entry.source, FeatureReportSource::Compiled);
            let expected = if entry.class == "turn.cancel" {
                FeatureSupport::RequestOnly
            } else {
                FeatureSupport::Unsupported
            };
            assert_eq!(
                entry.support, expected,
                "fixture class `{}` drifted",
                entry.class
            );
        }
        // `native-fixture` shares the deterministic reference report.
        assert_eq!(
            agent_feature_report("native-fixture")
                .expect("report")
                .entries,
            report.entries
        );
    }

    /// DR-0017 conformance (the report half of slice 2): the Claude report
    /// states `turn.cancel: unknown` — never a validated support level.
    #[test]
    fn claude_report_states_turn_cancel_unknown() {
        let report = agent_feature_report("claude").expect("claude report");
        let entry = report.entry("turn.cancel").expect("turn.cancel entry");
        assert_eq!(entry.support, FeatureSupport::Unknown);
        assert_eq!(entry.source, FeatureReportSource::Compiled);
        assert!(entry.native_name.is_none() && entry.dispatch.is_none());
    }

    /// A capability an adapter may grant must be in the preset's list.
    #[test]
    fn capability_grants_are_table_driven() {
        assert!(agent_profile_preset("repo-writer")
            .expect("row")
            .grants_capability("repo.write"));
        assert!(!agent_profile_preset("repo-reader")
            .expect("row")
            .grants_capability("repo.write"));
    }
}
