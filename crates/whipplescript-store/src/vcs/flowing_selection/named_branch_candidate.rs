//! A checked, complete handoff prefix from one named branch to trunk.
//!
//! This prepares a candidate only. The ref admission path still refuses
//! handed units until transitive policy and holder accounting are proved.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

impl<B: Branches + FlowingSources + FlowingAdmissions, C: ContentBlobs> WorkspaceVcs<B, C> {
    /// Construct a trunk candidate from a named branch's complete selected
    /// handoff prefix. Every source twig must have read the exact predecessor
    /// realized on this branch; an unproved dependency scope refuses rather
    /// than assuming disjoint writes are independent.
    pub fn prepare_named_branch_candidate(
        &mut self,
        revision: &NativeRevision,
        expected_trunk_cut_id: Option<&str>,
        candidate_cut_id: &str,
        actor: &str,
        recorded_at: &str,
    ) -> StoreResult<NativeCandidateOutcome> {
        use NativeCandidateOutcome as R;
        if revision.contribution_id.trim().is_empty()
            || revision.units.is_empty()
            || candidate_cut_id.trim().is_empty()
            || actor.trim().is_empty()
        {
            return Ok(R::CandidateMismatch);
        }
        let Some(source) = self.branches.get_branch(&revision.source_branch_id)? else {
            return Ok(R::SourceMismatch);
        };
        let Some(fence) = self.branches.flowing_source(&revision.source_branch_id)? else {
            return Ok(R::SourceMismatch);
        };
        if source.status != BranchStatus::Active
            || source.name.is_none()
            || source.parent_branch_id.as_deref() != Some(crate::branches::MAINLINE_BRANCH_ID)
            || fence.kind != crate::branches::flowing_fence::FlowingSourceKind::Branch
            || fence.incarnation_id != revision.source_incarnation_id
            || !fence.admission_enabled
            || fence.held
            || fence.revision.is_some()
        {
            return Ok(R::SourceMismatch);
        }
        let Some(trunk) = self
            .branches
            .get_branch(crate::branches::MAINLINE_BRANCH_ID)?
        else {
            return Ok(R::StaleBase);
        };
        if trunk.status != BranchStatus::Active
            || trunk.head_cut_id.as_deref() != expected_trunk_cut_id
            || source.branch_point_cut_id.as_deref() != expected_trunk_cut_id
            || source.branch_point_manifest_hash != trunk.head_manifest_hash
        {
            return Ok(R::StaleBase);
        }
        if let Some(base_id) = expected_trunk_cut_id {
            let Some(base) = self.branches.get_cut(base_id)? else {
                return Ok(R::StaleBase);
            };
            if base.branch_id != crate::branches::MAINLINE_BRANCH_ID
                || Some(base.manifest_hash.as_str()) != trunk.head_manifest_hash.as_deref()
                || self.load_manifest_opt_raw(&base.manifest_hash)?.is_none()
            {
                return Ok(R::StaleBase);
            }
        }
        let FlowingBranchLineageOutcome::Verified(lineage) =
            self.inspect_flowing_branch_lineage(&revision.source_branch_id)?
        else {
            return Ok(R::SourceMismatch);
        };
        let Some(prefix) = lineage.prefix_through(&revision.source_cut_id) else {
            return Ok(R::IncompletePrefix);
        };
        if prefix.selected_manifest_hash() != revision.source_manifest_hash
            || prefix.selected_handoffs().len() != revision.units.len()
        {
            return Ok(R::IncompletePrefix);
        }
        // One mixed target cut carries several ordered receipts. The simple
        // candidate constructor below advances its predecessor once per cut,
        // so it must wait for a batch-aware realized-basis proof.
        if prefix
            .selected_handoffs()
            .windows(2)
            .any(|pair| pair[0].target_after_cut_id == pair[1].target_after_cut_id)
        {
            return Ok(R::IncompletePrefix);
        }
        let mut prior = Vec::new();
        let mut predecessor_cut_id = expected_trunk_cut_id.map(str::to_owned);
        let mut predecessor_manifest_hash = trunk.head_manifest_hash.clone();
        let mut substantive_units = BTreeSet::new();
        let mut last_substantive_owner = BTreeMap::new();
        let mut atoms = Vec::new();
        let mut basis_evidence = Vec::new();
        for (receipt, selected) in prefix.selected_handoffs().iter().zip(&revision.units) {
            if receipt.unit_id != selected.unit_id
                || receipt.source_cut_id != selected.source_cut_id
                || receipt.source_basis_digest != selected.basis_digest
                || receipt.target_before_cut_id != predecessor_cut_id
            {
                return Ok(R::IncompletePrefix);
            }
            if self
                .branches
                .admitted_unit_operation(&selected.unit_id)?
                .is_some()
            {
                return Ok(R::UnitAlreadyAdmitted {
                    unit_id: selected.unit_id.clone(),
                });
            }
            let Some(unit) = self.branches.contribution_declaration(&selected.unit_id)? else {
                return Ok(R::IncompletePrefix);
            };
            let Some(basis) = self.branches.contribution_basis(&selected.unit_id)? else {
                return Ok(R::IncompletePrefix);
            };
            let Some(source_twig) = self.branches.get_branch(&unit.source_branch_id)? else {
                return Ok(R::SourceMismatch);
            };
            if unit.source_branch_id != receipt.source_branch_id
                || unit.source_cut_id != selected.source_cut_id
                || unit.pin_id != selected.pin_id
                || unit.principal != selected.principal
                || unit.intent != selected.intent
                || unit.source_manifest_hash != receipt.source_manifest_hash
                || basis.basis_digest != selected.basis_digest
                || source_twig.parent_branch_id.as_deref()
                    != Some(revision.source_branch_id.as_str())
                || source_twig.branch_point_cut_id != predecessor_cut_id
                || source_twig.branch_point_manifest_hash != predecessor_manifest_hash
            {
                return Ok(R::IncompletePrefix);
            }
            let read = native_read_basis_digest(
                predecessor_cut_id.as_deref(),
                predecessor_manifest_hash.as_deref(),
            );
            let deps = native_dependency_basis_digest(&prior);
            if unit.read_basis_digest != read || unit.dependency_basis_digest != deps {
                return Ok(R::UnprovenBasis {
                    unit_id: unit.unit_id,
                });
            }
            match self.net_source_paths(&basis)? {
                Ok(_) => {}
                Err(FlowingTargetEffectsOutcome::MissingContent { content_id }) => {
                    return Ok(R::MissingContent { content_id });
                }
                Err(_) => return Ok(R::IncompletePrefix),
            }
            for atom in basis.atoms {
                if atom.before != atom.after {
                    substantive_units.insert(selected.unit_id.clone());
                    last_substantive_owner.insert(atom.path.clone(), selected.unit_id.clone());
                }
                atoms.push((selected.unit_id.clone(), atom));
            }
            basis_evidence.push((selected.unit_id.clone(), read, deps));
            prior.push((selected.unit_id.clone(), selected.basis_digest.clone()));
            predecessor_cut_id = Some(receipt.target_after_cut_id.clone());
            predecessor_manifest_hash = Some(receipt.target_after_manifest_hash.clone());
        }
        let selected_manifest = self.load_manifest(Some(prefix.selected_manifest_hash()))?;
        let base_manifest = self.load_manifest(trunk.head_manifest_hash.as_deref())?;
        let applied_units: BTreeSet<String> = last_substantive_owner
            .into_iter()
            .filter(|(path, _)| base_manifest.get(path) != selected_manifest.get(path))
            .map(|(_, owner)| owner)
            .collect();
        let outcomes: Vec<FlowingSelectedUnit> = revision
            .units
            .iter()
            .map(|unit| FlowingSelectedUnit {
                unit_id: unit.unit_id.clone(),
                basis_digest: unit.basis_digest.clone(),
                principal: unit.principal.clone(),
                intent: unit.intent.clone(),
                outcome: if applied_units.contains(&unit.unit_id) {
                    FlowingUnitOutcome::Applied
                } else if substantive_units.contains(&unit.unit_id) {
                    FlowingUnitOutcome::Neutralized
                } else {
                    FlowingUnitOutcome::Equivalent
                },
            })
            .collect();
        let Some(raw) = self.load_manifest_opt_raw(prefix.selected_manifest_hash())? else {
            return Ok(R::SourceMismatch);
        };
        let mut retained_ids = match raw {
            RawManifest::Tree(_) => {
                crate::manifest_tree::reachable_ids(&self.content, prefix.selected_manifest_hash())?
            }
            RawManifest::Flat(manifest) => manifest.into_values().collect(),
        };
        retained_ids.insert(prefix.selected_manifest_hash().to_owned());
        for (_, atom) in &atoms {
            retained_ids.extend(atom.before.iter().cloned());
            retained_ids.extend(atom.after.iter().cloned());
        }
        for id in retained_ids {
            if !self.content.cached_read_available(&id)? {
                return Ok(R::MissingContent { content_id: id });
            }
        }
        let no_op = if let Some(base) = trunk.head_manifest_hash.as_deref() {
            base == prefix.selected_manifest_hash()
        } else {
            selected_manifest.is_empty()
        };
        if no_op {
            if expected_trunk_cut_id != Some(candidate_cut_id) {
                return Ok(R::CandidateMismatch);
            }
        } else {
            let origin = format!("transport:{}", revision.source_branch_id);
            let matches = |cut: &CutRow| {
                cut.branch_id == crate::branches::MAINLINE_BRANCH_ID
                    && cut.parent_cut_id.as_deref() == expected_trunk_cut_id
                    && cut.manifest_hash == prefix.selected_manifest_hash()
                    && cut.change_id == candidate_cut_id
                    && cut.origin.as_deref() == Some(origin.as_str())
                    && cut.actor.as_deref() == Some(actor)
                    && cut.intent.as_deref() == Some(revision.contribution_id.as_str())
                    && cut.recorded_at == recorded_at
            };
            if let Some(existing) = self.branches.get_cut(candidate_cut_id)? {
                if !matches(&existing) {
                    return Ok(R::CandidateMismatch);
                }
            } else {
                self.branches.record_cut(CutRecord {
                    cut_id: candidate_cut_id,
                    change_id: candidate_cut_id,
                    branch_id: crate::branches::MAINLINE_BRANCH_ID,
                    manifest_hash: prefix.selected_manifest_hash(),
                    parent_cut_id: expected_trunk_cut_id,
                    origin: Some(&origin),
                    actor: Some(actor),
                    intent: Some(&revision.contribution_id),
                    recorded_at,
                })?;
            }
            if !self
                .branches
                .get_cut(candidate_cut_id)?
                .as_ref()
                .is_some_and(matches)
            {
                return Ok(R::CandidateMismatch);
            }
        }
        let witness = serde_json::to_vec(&(
            "native-named-branch-prefix-v1",
            revision,
            expected_trunk_cut_id,
            prefix.selected_handoffs(),
            &atoms,
            &basis_evidence,
            &outcomes,
            candidate_cut_id,
            prefix.selected_manifest_hash(),
        ))?;
        let source_atoms_digest = format!("sha256:{}", crate::chunking::content_hash_hex(&witness));
        let candidate_witness = FlowingCandidateWitness {
            contribution_id: revision.contribution_id.clone(),
            revision_sequence: revision.sequence,
            source_branch_id: revision.source_branch_id.clone(),
            source_incarnation_id: revision.source_incarnation_id.clone(),
            source_cut_id: revision.source_cut_id.clone(),
            source_manifest_hash: revision.source_manifest_hash.clone(),
            expected_trunk_cut_id: expected_trunk_cut_id.map(str::to_owned),
            candidate_cut_id: candidate_cut_id.to_owned(),
            candidate_manifest_hash: prefix.selected_manifest_hash().to_owned(),
            source_atoms_digest: source_atoms_digest.clone(),
            units: outcomes.clone(),
        };
        let candidate_witness_digest =
            self.branches.record_candidate_witness(&candidate_witness)?;
        Ok(R::Prepared(NativeCandidate {
            contribution_id: revision.contribution_id.clone(),
            revision_sequence: revision.sequence,
            source_cut_id: revision.source_cut_id.clone(),
            expected_trunk_cut_id: expected_trunk_cut_id.map(str::to_owned),
            candidate_cut_id: candidate_cut_id.to_owned(),
            candidate_manifest_hash: prefix.selected_manifest_hash().to_owned(),
            source_atoms_digest,
            candidate_witness_digest,
            units: outcomes,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branches::flowing_admission::{
        FlowingCancelOutcome, FlowingCancelRequest, ReleaseFlowingAttemptOutcome,
        RetainFlowingAttemptOutcome,
    };
    use crate::branches::flowing_fence::{
        FlowingFence, FlowingSourceKind, OpenFlowingSource, OpenFlowingSourceOutcome,
    };
    use crate::branches::flowing_sources::{
        BindContributionBasisOutcome, DeclareContribution, DeclareContributionOutcome,
        HandoffContributionOutcome, PinPrivateCut, PinPrivateCutOutcome, ReleasePrivateCut,
        ReleasePrivateCutOutcome,
    };
    use crate::branches::{BranchStore, CutRecord, MAINLINE_BRANCH_ID};
    use crate::content::ContentStore;
    use crate::source_review::{ReviewError, ReviewStore};
    use crate::source_review_native::{NativeCandidateRequest, NativeUnitRef, NativeUpload};

    fn handed_branch(
        read_basis: Option<&str>,
    ) -> (WorkspaceVcs<BranchStore, ContentStore>, NativeRevision) {
        let mut vcs = WorkspaceVcs::from_parts(
            BranchStore::open_in_memory().unwrap(),
            ContentStore::open(":memory:").unwrap(),
        );
        vcs.init("t0").unwrap();
        vcs.create_branch("branch", Some("feature"), MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        for (id, incarnation, kind) in [
            ("branch", "branch-inc", FlowingSourceKind::Branch),
            ("twig", "twig-inc", FlowingSourceKind::Twig),
        ] {
            if id == "twig" {
                vcs.create_branch("twig", None, "branch", "t1").unwrap();
            }
            assert!(matches!(
                vcs.branches
                    .open_flowing_source(&OpenFlowingSource {
                        source_branch_id: id.into(),
                        incarnation_id: incarnation.into(),
                        kind,
                        owner: "coordinator".into(),
                        opened_at: "t1".into(),
                    })
                    .unwrap(),
                OpenFlowingSourceOutcome::Opened(_)
            ));
        }
        vcs.write("twig", "a.txt", Some("A"), "twig-a", "t2")
            .unwrap();
        let twig_cut = vcs.branches.get_cut("twig-a").unwrap().unwrap();
        assert_eq!(
            vcs.branches
                .pin_private_cut(PinPrivateCut {
                    pin_id: "pin-a",
                    twig_branch_id: "twig",
                    cut_id: "twig-a",
                    manifest_hash: &twig_cut.manifest_hash,
                    principal: "s:author",
                    retained_at: "t3",
                })
                .unwrap(),
            PinPrivateCutOutcome::Pinned
        );
        let read = native_read_basis_digest(None, None);
        let deps = native_dependency_basis_digest(&[]);
        assert_eq!(
            vcs.branches
                .declare_contribution(DeclareContribution {
                    unit_id: "unit-a",
                    pin_id: "pin-a",
                    principal: "s:author",
                    intent: "customer change",
                    read_basis_digest: read_basis.unwrap_or(&read),
                    dependency_basis_digest: &deps,
                    scope_digest: "scope-a",
                    declared_at: "t3",
                })
                .unwrap(),
            DeclareContributionOutcome::Declared
        );
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes("pin-a", &selection::parse("path(a.txt)").unwrap())
            .unwrap()
        else {
            panic!("selected unit")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-a", &selection, "t4")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
        let basis = vcs.branches.contribution_basis("unit-a").unwrap().unwrap();
        let manifest = vcs
            .store_manifest(&BTreeMap::from([(
                "a.txt".to_owned(),
                basis.atoms[0].after.clone().unwrap(),
            )]))
            .unwrap();
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "target-a",
                change_id: "target-a",
                branch_id: "branch",
                manifest_hash: &manifest,
                parent_cut_id: None,
                origin: Some("transport:twig"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t5",
            })
            .unwrap();
        let FlowingTargetEffectsOutcome::Verified(target) = vcs
            .verify_private_target_effects("unit-a", "target-a")
            .unwrap()
        else {
            panic!("exact handoff target")
        };
        assert!(matches!(
            vcs.handoff_private_selection("handoff-a", &target, "mediator", "t6")
                .unwrap(),
            HandoffContributionOutcome::Transferred(_)
        ));
        let revision = NativeRevision {
            contribution_id: "review-a".into(),
            sequence: 1,
            upload_id: "upload-a".into(),
            actor: "s:author".into(),
            source_branch_id: "branch".into(),
            source_incarnation_id: "branch-inc".into(),
            source_cut_id: "target-a".into(),
            source_manifest_hash: manifest,
            units: vec![NativeUnitRef {
                unit_id: "unit-a".into(),
                source_cut_id: "twig-a".into(),
                pin_id: "pin-a".into(),
                basis_digest: basis.basis_digest,
                principal: "s:author".into(),
                intent: "customer change".into(),
            }],
        };
        (vcs, revision)
    }

    fn append_handed_tail(vcs: &mut WorkspaceVcs<BranchStore, ContentStore>) {
        vcs.create_branch("twig-b", None, "branch", "t7").unwrap();
        assert!(matches!(
            vcs.branches
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig-b".into(),
                    incarnation_id: "twig-b-inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator".into(),
                    opened_at: "t7".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        vcs.write("twig-b", "b.txt", Some("B"), "twig-b-cut", "t8")
            .unwrap();
        let twig_cut = vcs.branches.get_cut("twig-b-cut").unwrap().unwrap();
        assert_eq!(
            vcs.branches
                .pin_private_cut(PinPrivateCut {
                    pin_id: "pin-b",
                    twig_branch_id: "twig-b",
                    cut_id: "twig-b-cut",
                    manifest_hash: &twig_cut.manifest_hash,
                    principal: "s:other",
                    retained_at: "t9",
                })
                .unwrap(),
            PinPrivateCutOutcome::Pinned
        );
        let predecessor = vcs.branches.get_cut("target-a").unwrap().unwrap();
        let first_basis = vcs.branches.contribution_basis("unit-a").unwrap().unwrap();
        let read = native_read_basis_digest(Some("target-a"), Some(&predecessor.manifest_hash));
        let deps = native_dependency_basis_digest(&[("unit-a".into(), first_basis.basis_digest)]);
        assert_eq!(
            vcs.branches
                .declare_contribution(DeclareContribution {
                    unit_id: "unit-b",
                    pin_id: "pin-b",
                    principal: "s:other",
                    intent: "later work",
                    read_basis_digest: &read,
                    dependency_basis_digest: &deps,
                    scope_digest: "scope-b",
                    declared_at: "t9",
                })
                .unwrap(),
            DeclareContributionOutcome::Declared
        );
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes("pin-b", &selection::parse("path(b.txt)").unwrap())
            .unwrap()
        else {
            panic!("later source unit")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-b", &selection, "t10")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
        let FlowingTargetEffectsOutcome::Verified(target) = vcs
            .prepare_private_handoff_target("unit-b", "target-b", "mediator", "t11")
            .unwrap()
        else {
            panic!("later handoff target")
        };
        assert!(matches!(
            vcs.handoff_private_selection("handoff-b", &target, "mediator", "t12")
                .unwrap(),
            HandoffContributionOutcome::Transferred(_)
        ));
    }

    #[test]
    fn named_branch_candidate_requires_the_exact_handoff_and_read_basis() {
        let (mut vcs, revision) = handed_branch(None);
        let NativeCandidateOutcome::Prepared(candidate) = vcs
            .prepare_named_branch_candidate(&revision, None, "candidate-a", "mediator", "t7")
            .unwrap()
        else {
            panic!("complete verified prefix")
        };
        assert_eq!(candidate.units.len(), 1);
        assert_eq!(candidate.units[0].outcome, FlowingUnitOutcome::Applied);
        assert_eq!(
            candidate.candidate_manifest_hash,
            revision.source_manifest_hash
        );
        assert_eq!(
            vcs.branches
                .release_private_cut(ReleasePrivateCut {
                    pin_id: "pin-a",
                    released_by: "mediator",
                    reason: "handoff complete",
                    released_at: "t8",
                })
                .unwrap(),
            ReleasePrivateCutOutcome::Released
        );
        assert!(matches!(
            vcs.branches
                .retain_flowing_attempt("attempt-a", &candidate.candidate_witness_digest, "t9")
                .unwrap(),
            RetainFlowingAttemptOutcome::Retained(_)
        ));
        assert!(matches!(
            vcs.branches
                .cancel_flowing_attempt(&FlowingCancelRequest {
                    cancel_op_id: "cancel-a".into(),
                    admission_op_id: "attempt-a".into(),
                    source_branch_id: "branch".into(),
                    source_incarnation_id: "branch-inc".into(),
                    expected_owner_epoch: 0,
                    coordinator: "coordinator".into(),
                    recorded_at: "t10".into(),
                })
                .unwrap(),
            FlowingCancelOutcome::Cancelled(_)
        ));
        assert_eq!(
            vcs.branches
                .release_terminal_flowing_attempt("attempt-a", "t11")
                .unwrap(),
            ReleaseFlowingAttemptOutcome::Released
        );
        assert!(vcs.branches.pinned_cuts("t11").unwrap().contains("twig-a"));

        let mut omitted = revision.clone();
        omitted.units[0].basis_digest = "wrong".into();
        assert_eq!(
            vcs.prepare_named_branch_candidate(&omitted, None, "candidate-b", "mediator", "t8")
                .unwrap(),
            NativeCandidateOutcome::IncompletePrefix
        );

        let (mut stale, revision) = handed_branch(Some("stale-read-basis"));
        assert_eq!(
            stale
                .prepare_named_branch_candidate(&revision, None, "candidate-a", "mediator", "t7")
                .unwrap(),
            NativeCandidateOutcome::UnprovenBasis {
                unit_id: "unit-a".into()
            }
        );
        assert!(stale.branches.get_cut("candidate-a").unwrap().is_none());
    }

    #[test]
    fn named_branch_candidate_refuses_unreceipted_or_stale_lineage() {
        let (mut vcs, revision) = handed_branch(None);
        vcs.write("branch", "other.txt", Some("other"), "local-cut", "t7")
            .unwrap();
        assert_eq!(
            vcs.prepare_named_branch_candidate(&revision, None, "candidate-a", "mediator", "t8")
                .unwrap(),
            NativeCandidateOutcome::SourceMismatch
        );
        assert!(vcs.branches.get_cut("candidate-a").unwrap().is_none());

        let (mut vcs, revision) = handed_branch(None);
        vcs.write(
            MAINLINE_BRANCH_ID,
            "other.txt",
            Some("other"),
            "trunk-cut",
            "t7",
        )
        .unwrap();
        assert_eq!(
            vcs.prepare_named_branch_candidate(&revision, None, "candidate-a", "mediator", "t8")
                .unwrap(),
            NativeCandidateOutcome::StaleBase
        );
        assert!(vcs.branches.get_cut("candidate-a").unwrap().is_none());
    }

    #[test]
    fn named_branch_review_upload_snapshots_the_complete_handoff_prefix() {
        let (mut vcs, expected) = handed_branch(None);
        append_handed_tail(&mut vcs);
        let mut reviews = ReviewStore::open(":memory:").unwrap();
        reviews
            .create_native_contribution(
                "review-a",
                "coordinator",
                "shared branch work",
                MAINLINE_BRANCH_ID,
                &[],
            )
            .unwrap();
        let request = NativeUpload {
            contribution_id: "review-a",
            upload_id: "upload-a",
            actor: "coordinator",
            source_branch_id: "branch",
            source_cut_id: "target-a",
            unit_ids: &["unit-a"],
        };
        let revision = reviews.upload_named_branch_revision(&vcs, request).unwrap();
        assert_eq!(revision.source_cut_id, expected.source_cut_id);
        assert_eq!(revision.source_manifest_hash, expected.source_manifest_hash);
        assert_eq!(revision.units, expected.units);
        assert_eq!(
            vcs.branches
                .get_branch("branch")
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some("target-b")
        );
        assert_eq!(
            reviews.upload_named_branch_revision(&vcs, request).unwrap(),
            revision
        );
        assert!(matches!(
            reviews.upload_named_branch_revision(&vcs, NativeUpload {
                upload_id: "incomplete",
                unit_ids: &["wrong"],
                ..request
            }),
            Err(ReviewError::Invalid(message))
                if message == "selected units must be the complete ordered handoff prefix"
        ));
        let prepared = reviews
            .prepare_native_candidate(
                &mut vcs,
                NativeCandidateRequest {
                    contribution_id: "review-a",
                    sequence: revision.sequence,
                    expected_trunk_cut_id: None,
                    candidate_cut_id: "candidate-a",
                    actor: "coordinator",
                    recorded_at: "t9",
                },
            )
            .unwrap();
        assert!(matches!(prepared, NativeCandidateOutcome::Prepared(_)));
    }

    #[test]
    fn named_branch_review_upload_refuses_invalid_identity_and_source() {
        let (mut vcs, _) = handed_branch(None);
        let mut reviews = ReviewStore::open(":memory:").unwrap();
        reviews
            .create_native_contribution(
                "review-a",
                "coordinator",
                "shared branch work",
                MAINLINE_BRANCH_ID,
                &[],
            )
            .unwrap();
        let request = NativeUpload {
            contribution_id: "review-a",
            upload_id: "upload-a",
            actor: "coordinator",
            source_branch_id: "branch",
            source_cut_id: "target-a",
            unit_ids: &["unit-a"],
        };
        assert!(matches!(
            reviews.upload_named_branch_revision(&vcs, NativeUpload { upload_id: "", ..request }),
            Err(ReviewError::Invalid(message))
                if message == "upload id, actor and selected units are required"
        ));
        assert!(matches!(
            reviews.upload_named_branch_revision(&vcs, NativeUpload { actor: "other", ..request }),
            Err(ReviewError::Invalid(message))
                if message == "named branch upload needs its author's native trunk contribution"
        ));
        assert!(matches!(
            reviews.upload_named_branch_revision(&vcs, NativeUpload { source_branch_id: "missing", ..request }),
            Err(ReviewError::Missing(message)) if message == "source branch missing"
        ));
        vcs.create_branch("unflowing", Some("unflowing"), MAINLINE_BRANCH_ID, "t7")
            .unwrap();
        assert!(matches!(
            reviews.upload_named_branch_revision(&vcs, NativeUpload { source_branch_id: "unflowing", ..request }),
            Err(ReviewError::Missing(message)) if message == "flowing source unflowing"
        ));
        reviews
            .create_native_contribution(
                "other-owner",
                "other",
                "another branch review",
                MAINLINE_BRANCH_ID,
                &[],
            )
            .unwrap();
        assert!(matches!(
            reviews.upload_named_branch_revision(&vcs, NativeUpload {
                contribution_id: "other-owner",
                actor: "other",
                ..request
            }),
            Err(ReviewError::Invalid(message))
                if message == "source needs an eligible named branch owned by the uploader"
        ));
        assert!(matches!(
            reviews.upload_named_branch_revision(&vcs, NativeUpload { source_cut_id: "twig-a", ..request }),
            Err(ReviewError::Invalid(message))
                if message == "selected cut is not a handoff receipt boundary"
        ));
        let revision = reviews.upload_named_branch_revision(&vcs, request).unwrap();
        assert!(matches!(
            reviews.upload_named_branch_revision(&vcs, NativeUpload { source_cut_id: "twig-a", ..request }),
            Err(ReviewError::Conflict(message))
                if message == "upload id already names another revision"
        ));
        assert_eq!(
            reviews
                .native_revision("review-a", revision.sequence)
                .unwrap(),
            revision
        );
        vcs.write(
            "branch",
            "unreceipted.txt",
            Some("new"),
            "unreceipted",
            "t8",
        )
        .unwrap();
        assert!(matches!(
            reviews.upload_named_branch_revision(&vcs, NativeUpload { upload_id: "upload-b", ..request }),
            Err(ReviewError::Invalid(message))
                if message == "source branch handoff lineage is incomplete"
        ));
    }
}
