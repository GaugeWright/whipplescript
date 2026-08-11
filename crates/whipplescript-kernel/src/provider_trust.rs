//! Model trust tiers: provider custody classes and evidence rungs (DR-0062).
//!
//! DR-0027 made the model endpoint a principal in the confidentiality lattice,
//! which answers *may this model read it*. It does not answer where the bytes
//! durably land, for how long, or who can compel them later — a zero-retention
//! endpoint, one that logs for abuse monitoring, and one whose terms permit
//! training are three different risk objects with identical read clearance.
//!
//! Two facts about an endpoint carry that difference, deliberately not one
//! ladder (DR-0062 §3). The **evidence rung** accrues by operator effort, as the
//! MCP ladder does. The **custody class** is a recorded procurement fact, because
//! no amount of configuration turns a public API into an on-prem deployment.
//!
//! This module is the store-free, network-free core: the two orderings, the
//! derivation of both from evidence, and the admissibility function. It is the
//! executable mirror of `models/maude/model-trust-admissibility.maude` — the
//! bites that model proves by reachability search are the `denies_*` tests at
//! the bottom of this file. Keep the two in step: a change here wants a change
//! there.
//!
//! The load-bearing discipline, inherited from DR-0053 §4: **both facts are
//! DERIVED FROM EVIDENCE, never asserted.** There is deliberately no path from
//! what a registry row *claims* into [`derive`] — [`ProviderEvidence`] has no
//! field for it. That absence is the theorem.

use std::fmt;

/// Who holds the transcript after a call. The order is over *who holds it*, not
/// how well — which is what makes it a total order, and what answers the
/// objection that a badly-run on-prem box beats a contracted zero-retention API.
/// [`CustodyClass::OperatorHeld`]'s substance is that no third party has custody
/// at all; whether the operator then leaks it to themselves is a different door
/// (`file_store` labels, the telemetry export, the session-event stream).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CustodyClass {
    /// `c0` — nobody has said anything. Assume the worst.
    Unknown,
    /// `c1` — the vendor retains and may embed the transcript in weights.
    /// Distinct from [`CustodyClass::Retained`] because training is
    /// qualitatively different from storage: the data becomes irrecoverably
    /// embedded rather than merely kept, and no deletion request reaches it.
    Trains,
    /// `c2` — the vendor retains under stated terms (logs, abuse window).
    Retained,
    /// `c3` — contractual zero-retention; no durable third-party copy.
    ZeroRetention,
    /// `c4` — no third party holds it at all. The one class carrying a property
    /// whip can check for itself, and even then only weakly.
    OperatorHeld,
}

impl CustodyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Trains => "trains",
            Self::Retained => "retained",
            Self::ZeroRetention => "zero-retention",
            Self::OperatorHeld => "operator-held",
        }
    }

    /// Names are primary, numeric aliases accepted — the spelling discipline
    /// DR-0053 already uses for credential rungs, where `hardware` and `r2` both
    /// parse. The names read in two grammatical positions: a demand in the
    /// envelope (`require custody zero-retention for Operator`) and a report in
    /// `whip provider status`.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unknown" | "c0" => Some(Self::Unknown),
            "trains" | "c1" => Some(Self::Trains),
            "retained" | "c2" => Some(Self::Retained),
            "zero-retention" | "c3" => Some(Self::ZeroRetention),
            "operator-held" | "c4" => Some(Self::OperatorHeld),
            _ => None,
        }
    }

    /// The accepted spellings, for diagnostics that have to list them.
    pub const NAMES: &'static str = "unknown | trains | retained | zero-retention | operator-held";
}

impl fmt::Display for CustodyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How much a human has staked on the endpoint's identity. Three rungs, not
/// four: there is no analogue of MCP's per-tool role file.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProviderRung {
    /// An endpoint someone configured. Zero setup; every use tagged degraded,
    /// never silent.
    Unattested,
    /// Endpoint URL + model id + config digest frozen. Drift now fails instead
    /// of succeeding quietly.
    Pinned,
    /// A filed custody claim carrying signer, date and expiry. The act that
    /// converts testimony into admissible evidence.
    Attested,
}

impl ProviderRung {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unattested => "unattested",
            Self::Pinned => "pinned",
            Self::Attested => "attested",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unattested" | "r0" => Some(Self::Unattested),
            "pinned" | "r1" => Some(Self::Pinned),
            "attested" | "r2" => Some(Self::Attested),
            _ => None,
        }
    }
}

impl fmt::Display for ProviderRung {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A signed custody claim about an endpoint. `c1`–`c3` are testimony — whip
/// cannot verify a retention claim, ever — so the claim carries who staked their
/// name on it and whether its term is still running.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FiledClaim {
    pub class: CustodyClass,
    /// Who signed. Carried for the audit trail and `whip provider status`; the
    /// admissibility decision does not read it.
    pub signer: String,
    /// Whether the claim's term is still current. A lapsed claim yields no
    /// derived custody, so the endpoint DEMOTES rather than coasting on an
    /// expired contract (DR-0062 §7).
    pub current: bool,
}

/// What the registry has to show for one endpoint.
///
/// Note what is absent: there is no field for what a registry row *claims* its
/// custody is. Configuration is not evidence, and giving it no way in is how
/// that is enforced rather than merely documented.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProviderEvidence {
    /// The digest frozen by `whip provider pin`.
    pub pinned_digest: Option<String>,
    /// What the endpoint resolves to now. A mismatch is drift.
    pub live_digest: Option<String>,
    /// A signed custody claim, if one has been filed.
    pub filed_claim: Option<FiledClaim>,
    /// Whether whip supervises the endpoint. The one self-checkable property,
    /// and even then only weakly — private address plus pinning, not proof.
    pub operator_run: bool,
}

/// What the evidence actually supports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivedTrust {
    pub rung: ProviderRung,
    pub custody: CustodyClass,
    /// The floor is tagged, not silent: an endpoint resting at `unattested`
    /// reports the weakness rather than reading as unknown or assumed-good.
    pub degraded: bool,
}

/// Read the rung and custody class off evidence.
///
/// The rules are the Maude module's, in the same order:
///
/// - the floor needs no evidence and none can be missing — a configured
///   endpoint IS `unattested`/`unknown`, tagged degraded;
/// - FRESHNESS: a pin counts only against the digest it was taken against, so
///   endpoint drift stops it counting (the stale-TPM-quote shape of DR-0053);
/// - PIN AS PRECONDITION: a filed claim becomes admissible evidence only against
///   a pinned endpoint, and only while its term is current;
/// - `operator-held` needs the pin but no filed testimony, because it is the one
///   class with a property whip can check itself.
pub fn derive(evidence: &ProviderEvidence) -> DerivedTrust {
    let pinned = match (&evidence.pinned_digest, &evidence.live_digest) {
        (Some(pinned), Some(live)) => pinned == live,
        _ => false,
    };
    if !pinned {
        // Nothing above the floor can be derived without a pin: a claim about an
        // endpoint is meaningless if the endpoint can change underneath it.
        return DerivedTrust {
            rung: ProviderRung::Unattested,
            custody: CustodyClass::Unknown,
            degraded: true,
        };
    }

    let attested = evidence
        .filed_claim
        .as_ref()
        .is_some_and(|claim| claim.current);
    let from_claim = if attested {
        evidence
            .filed_claim
            .as_ref()
            .map_or(CustodyClass::Unknown, |claim| claim.class)
    } else {
        CustodyClass::Unknown
    };
    let from_operator = if evidence.operator_run {
        CustodyClass::OperatorHeld
    } else {
        CustodyClass::Unknown
    };

    DerivedTrust {
        rung: if attested {
            ProviderRung::Attested
        } else {
            ProviderRung::Pinned
        },
        // Both derivations coexist in the model's soup and admission may use
        // either, so the effective class is the stronger of the two.
        custody: from_claim.max(from_operator),
        degraded: false,
    }
}

/// One endpoint's registry row, as plain strings.
///
/// The kernel does not depend on the store crate, so the row crosses as text and
/// is interpreted here — which keeps one tested place deciding what a stored
/// claim means, instead of that logic living in whichever caller loaded it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RegistryEvidence<'a> {
    pub pinned_digest: Option<&'a str>,
    pub claim_class: Option<&'a str>,
    pub claim_signer: Option<&'a str>,
    /// RFC 3339. Judged against `now` — see [`claim_is_current`].
    pub claim_expires_at: Option<&'a str>,
    pub operator_run: bool,
}

/// Is a filed claim's term still running?
///
/// **Fail-closed on anything it cannot read.** An expiry that does not parse is
/// treated as lapsed rather than perpetual: a corrupt or hand-edited term must
/// not become the strongest possible claim, which is exactly what "if we cannot
/// parse it, ignore it" would produce.
pub fn claim_is_current(expires_at: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    match chrono::DateTime::parse_from_rfc3339(expires_at) {
        Ok(expiry) => expiry.with_timezone(&chrono::Utc) > now,
        Err(_) => false,
    }
}

/// Assemble what [`derive`] needs from a registry row plus the endpoint's
/// **current** digest.
///
/// `live_digest` is passed in rather than stored, and that is the whole point of
/// freshness: a digest read back from the same row it is compared against would
/// always match, and drift would be undetectable.
///
/// Fail-closed twice more: a claim whose class is not a spelling this build
/// knows, or which is missing its signer or term, yields **no claim at all**
/// rather than a partially-trusted one.
pub fn evidence_from_registry(
    row: RegistryEvidence<'_>,
    live_digest: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> ProviderEvidence {
    let filed_claim = match (row.claim_class, row.claim_signer, row.claim_expires_at) {
        (Some(class), Some(signer), Some(expires_at)) => {
            CustodyClass::parse(class).map(|class| FiledClaim {
                class,
                signer: signer.to_owned(),
                current: claim_is_current(expires_at, now),
            })
        }
        _ => None,
    };
    ProviderEvidence {
        pinned_digest: row.pinned_digest.map(str::to_owned),
        live_digest: live_digest.map(str::to_owned),
        filed_claim,
        operator_run: row.operator_run,
    }
}

/// The endpoint identity a pin freezes: a stable hash of the provider's
/// resolved configuration (backend, model id, base URL — whatever the
/// `effect_providers` row carries).
///
/// Canonicalized before hashing so that a re-serialization with different key
/// order does not read as drift. Unparseable config hashes its raw bytes rather
/// than being treated as absent: a config whip cannot parse is still a config
/// that can CHANGE, and a pin over it must still notice.
pub fn endpoint_digest(config_json: &str) -> String {
    let canonical = serde_json::from_str::<serde_json::Value>(config_json)
        .map(|value| value.to_string())
        .unwrap_or_else(|_| config_json.to_owned());
    crate::rule_lowering::stable_hash_hex(&canonical)
}

/// Why a delegation edge was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DelegationDenial {
    /// The endpoint is not pinned, so nothing above the floor could be derived.
    /// Reported ahead of [`DelegationDenial::UnderClass`] because it is the
    /// actionable root cause: an unpinned endpoint is always `unknown` too, and
    /// telling the operator to raise the class would send them the wrong way.
    BelowRung { rung: ProviderRung },
    /// The endpoint's custody class does not reach what the envelope demands.
    UnderClass {
        derived: CustodyClass,
        demanded: CustodyClass,
    },
}

impl DelegationDenial {
    /// The operator-facing sentence. Names the endpoint, what it has, what was
    /// demanded, and the one action that fixes it.
    pub fn message(&self, provider: &str, role: &str) -> String {
        match self {
            Self::BelowRung { rung } => format!(
                "delegating `provider:{provider}` for `{role}` needs a pinned endpoint, \
                 but `{provider}` is `{rung}` — a custody claim about an endpoint is \
                 meaningless if the endpoint can change underneath it \
                 (run `whip provider pin {provider}`)"
            ),
            Self::UnderClass { derived, demanded } => format!(
                "delegating `provider:{provider}` for `{role}` needs custody `{demanded}`, \
                 but the evidence for `{provider}` supports only `{derived}` — either file \
                 a claim that reaches `{demanded}`, or lower the demand for `{role}` in the \
                 signed envelope"
            ),
        }
    }
}

/// Is a delegation edge granting `provider` read-authority for a role
/// admissible, given what the envelope demands of that role?
///
/// `demand` is `None` when the envelope declares no custody requirement for the
/// role, and that is **unconstrained** — the same `None`-means-no-floor reading
/// `mcp_min_rung` already has. This is what keeps zero setup working: an
/// unattested endpoint still runs, it is simply public-only until someone
/// declares a demand, exactly as an MCP rung-0 server still works under
/// per-tool-name grants.
pub fn delegation_admissible(
    derived: &DerivedTrust,
    demand: Option<CustodyClass>,
) -> Result<(), DelegationDenial> {
    let Some(demanded) = demand else {
        return Ok(());
    };
    if derived.rung < ProviderRung::Pinned {
        return Err(DelegationDenial::BelowRung { rung: derived.rung });
    }
    if derived.custody < demanded {
        return Err(DelegationDenial::UnderClass {
            derived: derived.custody,
            demanded,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(class: CustodyClass, current: bool) -> Option<FiledClaim> {
        Some(FiledClaim {
            class,
            signer: "ops@acme.com".to_owned(),
            current,
        })
    }

    fn pinned_fresh() -> ProviderEvidence {
        ProviderEvidence {
            pinned_digest: Some("dA".to_owned()),
            live_digest: Some("dA".to_owned()),
            ..ProviderEvidence::default()
        }
    }

    #[test]
    fn parses_names_and_numeric_aliases() {
        assert_eq!(CustodyClass::parse("c3"), Some(CustodyClass::ZeroRetention));
        assert_eq!(
            CustodyClass::parse("zero-retention"),
            Some(CustodyClass::ZeroRetention)
        );
        assert_eq!(ProviderRung::parse("r1"), Some(ProviderRung::Pinned));
        assert_eq!(CustodyClass::parse("zero_retention"), None);
    }

    #[test]
    fn custody_order_is_who_holds_the_transcript() {
        assert!(CustodyClass::OperatorHeld > CustodyClass::ZeroRetention);
        assert!(CustodyClass::ZeroRetention > CustodyClass::Retained);
        assert!(CustodyClass::Retained > CustodyClass::Trains);
        assert!(CustodyClass::Trains > CustodyClass::Unknown);
    }

    // --- coverage: the model's Solution searches -------------------------

    #[test]
    fn floor_is_reached_and_tagged() {
        let derived = derive(&ProviderEvidence::default());
        assert_eq!(derived.rung, ProviderRung::Unattested);
        assert_eq!(derived.custody, CustodyClass::Unknown);
        assert!(derived.degraded, "the floor must be tagged, not silent");
    }

    #[test]
    fn fresh_pin_and_current_claim_reach_the_class() {
        let derived = derive(&ProviderEvidence {
            filed_claim: claim(CustodyClass::OperatorHeld, true),
            ..pinned_fresh()
        });
        assert_eq!(derived.rung, ProviderRung::Attested);
        assert_eq!(derived.custody, CustodyClass::OperatorHeld);
        assert!(!derived.degraded);
        assert!(delegation_admissible(&derived, Some(CustodyClass::ZeroRetention)).is_ok());
    }

    #[test]
    fn operator_run_reaches_the_top_class_without_testimony() {
        // c4 is the asymmetry: a property whip can check needs no signer.
        let derived = derive(&ProviderEvidence {
            operator_run: true,
            ..pinned_fresh()
        });
        assert_eq!(derived.custody, CustodyClass::OperatorHeld);
        assert_eq!(
            derived.rung,
            ProviderRung::Pinned,
            "no claim was filed, so the rung stays pinned"
        );
        assert!(delegation_admissible(&derived, Some(CustodyClass::OperatorHeld)).is_ok());
    }

    #[test]
    fn higher_class_clears_a_lower_demand() {
        let derived = derive(&ProviderEvidence {
            filed_claim: claim(CustodyClass::ZeroRetention, true),
            ..pinned_fresh()
        });
        assert!(delegation_admissible(&derived, Some(CustodyClass::Retained)).is_ok());
    }

    #[test]
    fn an_undeclared_demand_is_unconstrained() {
        // The progressive-rigor door: zero setup keeps working, public-only.
        let derived = derive(&ProviderEvidence::default());
        assert!(delegation_admissible(&derived, None).is_ok());
    }

    // --- bite: the model's No-solution searches --------------------------

    #[test]
    fn denies_configuration_as_evidence() {
        // There is no way to express "the registry row says c4" — the struct has
        // no field for it. This test pins the consequence: an endpoint with a
        // fresh pin and nothing filed supports nothing above the floor.
        let derived = derive(&pinned_fresh());
        assert_eq!(derived.custody, CustodyClass::Unknown);
        assert_eq!(
            delegation_admissible(&derived, Some(CustodyClass::ZeroRetention)),
            Err(DelegationDenial::UnderClass {
                derived: CustodyClass::Unknown,
                demanded: CustodyClass::ZeroRetention,
            })
        );
    }

    #[test]
    fn denies_a_claim_against_a_drifted_endpoint() {
        // The discriminating case for pin-as-precondition (DR-0062 §5): the
        // claim is real, signed, current, and worthless, because it is testimony
        // about a deployment this endpoint no longer is.
        let derived = derive(&ProviderEvidence {
            pinned_digest: Some("dA".to_owned()),
            live_digest: Some("dB".to_owned()),
            filed_claim: claim(CustodyClass::OperatorHeld, true),
            // Even the self-checkable class does not survive drift: whip can
            // only vouch for an endpoint it can still identify.
            operator_run: true,
        });
        assert_eq!(derived.rung, ProviderRung::Unattested);
        assert_eq!(
            delegation_admissible(&derived, Some(CustodyClass::ZeroRetention)),
            Err(DelegationDenial::BelowRung {
                rung: ProviderRung::Unattested
            })
        );
    }

    #[test]
    fn denies_an_unpinned_claim() {
        let derived = derive(&ProviderEvidence {
            filed_claim: claim(CustodyClass::OperatorHeld, true),
            ..ProviderEvidence::default()
        });
        assert_eq!(derived.custody, CustodyClass::Unknown);
        assert!(delegation_admissible(&derived, Some(CustodyClass::Retained)).is_err());
    }

    #[test]
    fn denies_a_lapsed_claim() {
        // Contracts lapse; an attestation that outlives its term must demote.
        let derived = derive(&ProviderEvidence {
            filed_claim: claim(CustodyClass::OperatorHeld, false),
            ..pinned_fresh()
        });
        assert_eq!(derived.rung, ProviderRung::Pinned);
        assert_eq!(derived.custody, CustodyClass::Unknown);
        assert!(delegation_admissible(&derived, Some(CustodyClass::ZeroRetention)).is_err());
    }

    #[test]
    fn denies_an_under_class_endpoint() {
        let derived = derive(&ProviderEvidence {
            filed_claim: claim(CustodyClass::Retained, true),
            ..pinned_fresh()
        });
        assert_eq!(
            delegation_admissible(&derived, Some(CustodyClass::ZeroRetention)),
            Err(DelegationDenial::UnderClass {
                derived: CustodyClass::Retained,
                demanded: CustodyClass::ZeroRetention,
            })
        );
    }

    #[test]
    fn below_rung_is_reported_ahead_of_under_class() {
        // An unpinned endpoint is under-class too; naming the class would send
        // the operator to file a claim that still would not count.
        let derived = derive(&ProviderEvidence::default());
        let denial = delegation_admissible(&derived, Some(CustodyClass::OperatorHeld))
            .expect_err("unpinned must be refused");
        assert!(matches!(denial, DelegationDenial::BelowRung { .. }));
        assert!(denial
            .message("acme", "Operator")
            .contains("whip provider pin"));
    }

    // Evidence does not leak across endpoints by construction: `derive` reads a
    // single `ProviderEvidence`, so there is no shared soup for one endpoint's
    // attestation to satisfy another's. The Maude model has to search for that;
    // here it is a type.

    // --- the registry bridge -------------------------------------------

    fn at(stamp: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(stamp)
            .expect("test stamp")
            .with_timezone(&chrono::Utc)
    }

    fn filed_row() -> RegistryEvidence<'static> {
        RegistryEvidence {
            pinned_digest: Some("sha256:dA"),
            claim_class: Some("zero-retention"),
            claim_signer: Some("ops@acme.com"),
            claim_expires_at: Some("2027-01-01T00:00:00Z"),
            operator_run: false,
        }
    }

    #[test]
    fn registry_row_becomes_evidence_and_derives() {
        let evidence =
            evidence_from_registry(filed_row(), Some("sha256:dA"), at("2026-08-07T00:00:00Z"));
        let derived = derive(&evidence);
        assert_eq!(derived.rung, ProviderRung::Attested);
        assert_eq!(derived.custody, CustodyClass::ZeroRetention);
    }

    #[test]
    fn an_expired_term_demotes_the_endpoint() {
        // Read a day after the term ran out: the row is unchanged, the class is
        // gone. Demotion is automatic, not a diary entry.
        let evidence =
            evidence_from_registry(filed_row(), Some("sha256:dA"), at("2027-01-02T00:00:00Z"));
        let derived = derive(&evidence);
        assert_eq!(derived.custody, CustodyClass::Unknown);
        assert!(delegation_admissible(&derived, Some(CustodyClass::ZeroRetention)).is_err());
    }

    #[test]
    fn drift_is_detected_against_the_live_digest() {
        // The endpoint now resolves elsewhere; the stored pin is unchanged.
        let evidence =
            evidence_from_registry(filed_row(), Some("sha256:dB"), at("2026-08-07T00:00:00Z"));
        assert_eq!(derive(&evidence).rung, ProviderRung::Unattested);
    }

    #[test]
    fn unreadable_evidence_fails_closed() {
        // An expiry that does not parse is LAPSED, never perpetual.
        assert!(!claim_is_current("whenever", at("2026-08-07T00:00:00Z")));
        // A class this build does not know yields no claim, not a trusted one.
        let unknown = RegistryEvidence {
            claim_class: Some("totally-private"),
            ..filed_row()
        };
        let evidence =
            evidence_from_registry(unknown, Some("sha256:dA"), at("2026-08-07T00:00:00Z"));
        assert!(evidence.filed_claim.is_none());
        assert_eq!(derive(&evidence).custody, CustodyClass::Unknown);
        // A claim missing its signer is not half-trusted either.
        let unsigned = RegistryEvidence {
            claim_signer: None,
            ..filed_row()
        };
        let evidence =
            evidence_from_registry(unsigned, Some("sha256:dA"), at("2026-08-07T00:00:00Z"));
        assert!(evidence.filed_claim.is_none());
    }
}
