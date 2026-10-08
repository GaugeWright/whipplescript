//! A checked, complete handoff prefix from one named branch to trunk.
//!
//! This prepares a candidate only. The ref admission path accepts an exact
//! one-hop handoff only after the candidate, source policy, holder receipt and
//! gate certificate are independently recaptured under ref exclusion.

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
        if actor.trim().is_empty() {
            return Ok(NativeCandidateOutcome::CandidateMismatch);
        }
        match self.derive_named_branch_candidate(
            revision,
            expected_trunk_cut_id,
            candidate_cut_id,
        )? {
            NativeCandidateOutcome::Prepared(candidate) => {
                self.record_derived_native_candidate(revision, candidate, actor, recorded_at)
            }
            refused => Ok(refused),
        }
    }

    pub(super) fn derive_named_branch_candidate(
        &self,
        revision: &NativeRevision,
        expected_trunk_cut_id: Option<&str>,
        candidate_cut_id: &str,
    ) -> StoreResult<NativeCandidateOutcome> {
        use NativeCandidateOutcome as R;
        if revision.contribution_id.trim().is_empty()
            || revision.units.is_empty()
            || candidate_cut_id.trim().is_empty()
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
        let mut prior = Vec::new();
        let mut predecessor_cut_id = expected_trunk_cut_id.map(str::to_owned);
        let mut predecessor_manifest_hash = trunk.head_manifest_hash.clone();
        let mut substantive_units = BTreeSet::new();
        let mut last_substantive_owner = BTreeMap::new();
        let mut atoms = Vec::new();
        let mut basis_evidence = Vec::new();
        let handoffs = prefix.selected_handoffs();
        let mut start = 0;
        while start < handoffs.len() {
            let cut_id = &handoffs[start].target_after_cut_id;
            let mut end = start + 1;
            while end < handoffs.len() && handoffs[end].target_after_cut_id == *cut_id {
                end += 1;
            }
            let group = &handoffs[start..end];
            if group.iter().any(|receipt| {
                receipt.target_before_cut_id != predecessor_cut_id
                    || receipt.target_after_manifest_hash != group[0].target_after_manifest_hash
            }) {
                return Ok(R::IncompletePrefix);
            }
            let batch = self.branches.target_handoff_batch(cut_id)?;
            if let Some(batch) = &batch {
                if batch.units != group {
                    return Ok(R::IncompletePrefix);
                }
                let Some(derived) = self.branches.flowing_derived_cut(&batch.derivation_id)? else {
                    return Ok(R::IncompletePrefix);
                };
                match self.verify_batch_source_order_with_prior(
                    &derived.witness,
                    &prior,
                    &handoffs[..start],
                    Some(group),
                )? {
                    FlowingBatchSourceOrderOutcome::Verified => {}
                    FlowingBatchSourceOrderOutcome::UnprovenBasis { unit_id } => {
                        return Ok(R::UnprovenBasis { unit_id });
                    }
                    FlowingBatchSourceOrderOutcome::MissingContent { content_id } => {
                        return Ok(R::MissingContent { content_id });
                    }
                    _ => return Ok(R::IncompletePrefix),
                }
            } else if group.len() != 1 {
                return Ok(R::IncompletePrefix);
            }
            for (receipt, selected) in group.iter().zip(&revision.units[start..end]) {
                if receipt.unit_id != selected.unit_id
                    || receipt.source_cut_id != selected.source_cut_id
                    || receipt.source_basis_digest != selected.basis_digest
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
                    || (batch.is_none()
                        && (source_twig.branch_point_cut_id != predecessor_cut_id
                            || source_twig.branch_point_manifest_hash != predecessor_manifest_hash))
                {
                    return Ok(R::IncompletePrefix);
                }
                let read = if batch.is_some() {
                    unit.read_basis_digest.clone()
                } else {
                    native_read_basis_digest(
                        predecessor_cut_id.as_deref(),
                        predecessor_manifest_hash.as_deref(),
                    )
                };
                let deps = if batch.is_some() {
                    unit.dependency_basis_digest.clone()
                } else {
                    native_dependency_basis_digest(&prior)
                };
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
            }
            predecessor_cut_id = Some(cut_id.clone());
            predecessor_manifest_hash = Some(group[0].target_after_manifest_hash.clone());
            start = end;
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
        if no_op != (expected_trunk_cut_id == Some(candidate_cut_id)) {
            return Ok(R::CandidateMismatch);
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
        let candidate_witness_digest = candidate_witness.digest()?;
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

#[cfg(feature = "native")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::branches::flowing_admission::{
        test_issuer, FlowingAdmissionOutcome, FlowingAdmissionRequest, FlowingAdmissions,
        FlowingCancelOutcome, FlowingCancelRequest, FlowingGateCertificate, FlowingGateCheck,
        FlowingGateVerdict, ReleaseFlowingAttemptOutcome, RetainFlowingAttemptOutcome,
    };
    use crate::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceTransition, FlowingSourceKind,
        OpenFlowingSource, OpenFlowingSourceOutcome,
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

    fn signed_branch_request(
        vcs: &mut WorkspaceVcs<BranchStore, ContentStore>,
        witness: &crate::branches::flowing_admission::FlowingCandidateWitness,
        op_id: &str,
        epoch: i64,
    ) -> FlowingAdmissionRequest {
        use crate::branches::flowing_coverage::{tests, FlowingCoveragePremises};

        let premises: FlowingCoveragePremises = tests::premises();
        vcs.branches
            .record_flowing_coverage_premises(&premises)
            .unwrap();
        let lineage = crate::branches::flowing_lineage::capture(&vcs.branches, witness)
            .unwrap()
            .unwrap();
        let holders = crate::branches::flowing_holders::capture(&vcs.branches, witness)
            .unwrap()
            .unwrap();
        assert_eq!(holders.len(), 1);
        assert_eq!(holders[0].handoff_op_id.as_deref(), Some("handoff-a"));
        let certificate = FlowingGateCertificate {
            candidate_witness_digest: witness.digest().unwrap(),
            expected_trunk_cut_id: witness.expected_trunk_cut_id.clone(),
            candidate_cut_id: witness.candidate_cut_id.clone(),
            candidate_manifest_hash: witness.candidate_manifest_hash.clone(),
            lineage_fences: lineage,
            unit_holders: holders,
            source_eligibility_epoch: epoch,
            source_owner_epoch: 0,
            coordinator: "coordinator".into(),
            policy_digest: "sha256:branch-policy".into(),
            rules_digest: "sha256:branch-rules".into(),
            graph_coverage_digest: "sha256:branch-graph".into(),
            coverage: Some(tests::basis_for(
                &premises,
                &witness.candidate_manifest_hash,
            )),
            required_checks: vec!["full-workspace-bar".into()],
            checks: vec![FlowingGateCheck {
                check_id: "full-workspace-bar".into(),
                input_digest: "sha256:branch-input".into(),
                evidence_digest: "sha256:branch-evidence".into(),
                verdict: FlowingGateVerdict::Passed,
            }],
        };
        let handle = certificate.handle().unwrap();
        let db = vcs.branches.test_connection();
        db.execute(
            "INSERT INTO flowing_gate_certificates (handle, certificate_json) VALUES (?1, ?2)",
            rusqlite::params![&handle, serde_json::to_string(&certificate).unwrap()],
        )
        .unwrap();
        vcs.branches
            .configure_flowing_gate_issuer(&test_issuer::trusted(test_issuer::ISSUER, 1, 7))
            .unwrap();
        vcs.branches
            .record_flowing_gate_signature(&test_issuer::sign(&handle, test_issuer::ISSUER, 1, 7))
            .unwrap();
        FlowingAdmissionRequest {
            op_id: op_id.into(),
            certificate_handle: handle,
            candidate_witness_digest: witness.digest().unwrap(),
            contribution_id: witness.contribution_id.clone(),
            revision_sequence: witness.revision_sequence,
            source_branch_id: witness.source_branch_id.clone(),
            source_incarnation_id: witness.source_incarnation_id.clone(),
            source_cut_id: witness.source_cut_id.clone(),
            source_manifest_hash: witness.source_manifest_hash.clone(),
            expected_eligibility_epoch: epoch,
            expected_owner_epoch: 0,
            coordinator: "coordinator".into(),
            expected_trunk_cut_id: witness.expected_trunk_cut_id.clone(),
            candidate_cut_id: witness.candidate_cut_id.clone(),
            candidate_manifest_hash: witness.candidate_manifest_hash.clone(),
            units: witness.units.clone(),
            recorded_at: "t-admit".into(),
        }
    }

    #[test]
    fn one_hop_named_branch_requires_fresh_holder_and_hold_fences_at_trunk_cas() {
        let (mut vcs, revision) = handed_branch(None);
        let NativeCandidateOutcome::Prepared(candidate) = vcs
            .prepare_named_branch_candidate(&revision, None, "candidate-a", "coordinator", "t7")
            .unwrap()
        else {
            panic!("complete named-branch candidate")
        };
        let witness = vcs
            .branches
            .candidate_witness(&candidate.candidate_witness_digest)
            .unwrap()
            .unwrap();
        let request = signed_branch_request(&mut vcs, &witness, "admit-a", 0);
        assert!(matches!(
            vcs.branches
                .retain_flowing_attempt("admit-a", &candidate.candidate_witness_digest, "t8")
                .unwrap(),
            RetainFlowingAttemptOutcome::Retained(_)
        ));
        vcs.verify_retained_native_candidate(
            &revision,
            &candidate.candidate_witness_digest,
            "admit-a",
        )
        .unwrap();
        let original = vcs
            .branches
            .contribution_handoff("unit-a")
            .unwrap()
            .unwrap();
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE flowing_handoffs SET source_basis_digest = 'wrong' WHERE unit_id = 'unit-a'",
                [],
            )
            .unwrap();
        assert_eq!(
            vcs.branches.admit_flowing_prefix(&request).unwrap(),
            FlowingAdmissionOutcome::Refused(
                crate::branches::flowing_admission::FlowingAdmissionRefusal::HolderUnavailable
            )
        );
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE flowing_handoffs SET source_basis_digest = ?1 WHERE unit_id = 'unit-a'",
                [&original.source_basis_digest],
            )
            .unwrap();
        let transition = |op_id: &str, epoch, action| FlowingFenceTransition {
            op_id: op_id.into(),
            source_branch_id: "branch".into(),
            incarnation_id: "branch-inc".into(),
            expected_eligibility_epoch: epoch,
            expected_owner_epoch: 0,
            actor: "coordinator".into(),
            action,
            recorded_at: "t9".into(),
        };
        vcs.branches
            .transition_flowing_source(&transition("hold-a", 0, FlowingFenceAction::Hold))
            .unwrap();
        let mut held_request = request.clone();
        held_request.expected_eligibility_epoch = 1;
        assert_eq!(
            vcs.branches.admit_flowing_prefix(&held_request).unwrap(),
            FlowingAdmissionOutcome::Refused(
                crate::branches::flowing_admission::FlowingAdmissionRefusal::Held
            )
        );
        vcs.branches
            .transition_flowing_source(&transition("release-a", 1, FlowingFenceAction::ReleaseHold))
            .unwrap();
        assert_eq!(
            vcs.branches.admit_flowing_prefix(&request).unwrap(),
            FlowingAdmissionOutcome::Refused(
                crate::branches::flowing_admission::FlowingAdmissionRefusal::StaleEligibilityEpoch {
                    current: 2,
                }
            )
        );
        let fresh = signed_branch_request(&mut vcs, &witness, "admit-a", 2);
        assert!(matches!(
            vcs.branches.admit_flowing_prefix(&fresh).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
        assert_eq!(
            vcs.branches
                .admitted_unit_operation("unit-a")
                .unwrap()
                .as_deref(),
            Some("admit-a")
        );
        assert_eq!(
            vcs.branches
                .get_branch(MAINLINE_BRANCH_ID)
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some("candidate-a")
        );
    }

    #[test]
    fn named_branch_batch_uses_the_prior_branch_roster_as_its_dependency_basis() {
        use crate::branches::flowing_sources::{
            HandoffBatchContributionOutcome, RecordFlowingDerivedCutOutcome,
        };
        let (mut vcs, mut revision) = handed_branch(None);
        vcs.create_branch("twig-batch", None, "branch", "t8")
            .unwrap();
        assert!(matches!(
            vcs.branches
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig-batch".into(),
                    incarnation_id: "twig-batch-inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator".into(),
                    opened_at: "t8".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        let mut prior_cut_id = Some("target-a".to_owned());
        let mut prior_manifest = Some(revision.source_manifest_hash.clone());
        let mut predecessors = vec![("unit-a".to_owned(), revision.units[0].basis_digest.clone())];
        for (unit_id, pin_id, cut_id, body) in [
            ("unit-b", "pin-b", "twig-b", "B"),
            ("unit-c", "pin-c", "twig-c", "C"),
        ] {
            vcs.write("twig-batch", "b.txt", Some(body), cut_id, "t9")
                .unwrap();
            let cut = vcs.branches.get_cut(cut_id).unwrap().unwrap();
            assert_eq!(
                vcs.branches
                    .pin_private_cut(PinPrivateCut {
                        pin_id,
                        twig_branch_id: "twig-batch",
                        cut_id,
                        manifest_hash: &cut.manifest_hash,
                        principal: "s:author",
                        retained_at: "t10",
                    })
                    .unwrap(),
                PinPrivateCutOutcome::Pinned
            );
            let read = native_read_basis_digest(prior_cut_id.as_deref(), prior_manifest.as_deref());
            let deps = native_dependency_basis_digest(&predecessors);
            assert_eq!(
                vcs.branches
                    .declare_contribution(DeclareContribution {
                        unit_id,
                        pin_id,
                        principal: "s:author",
                        intent: "later mixed work",
                        read_basis_digest: &read,
                        dependency_basis_digest: &deps,
                        scope_digest: "batch-scope",
                        declared_at: "t10",
                    })
                    .unwrap(),
                DeclareContributionOutcome::Declared
            );
            let FlowingSelectionOutcome::Selected(selection) = vcs
                .select_private_changes(
                    pin_id,
                    &selection::parse(&format!("change({cut_id})")).unwrap(),
                )
                .unwrap()
            else {
                panic!("selected batch unit")
            };
            assert_eq!(
                vcs.bind_private_selection(unit_id, &selection, "t11")
                    .unwrap(),
                BindContributionBasisOutcome::Bound
            );
            predecessors.push((unit_id.into(), selection.digest().into()));
            prior_cut_id = Some(cut_id.into());
            prior_manifest = Some(cut.manifest_hash);
            revision.units.push(NativeUnitRef {
                unit_id: unit_id.into(),
                source_cut_id: cut_id.into(),
                pin_id: pin_id.into(),
                basis_digest: selection.digest().into(),
                principal: "s:author".into(),
                intent: "later mixed work".into(),
            });
        }
        let manifest = prior_manifest.unwrap();
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "target-batch",
                change_id: "target-batch",
                branch_id: "branch",
                manifest_hash: &manifest,
                parent_cut_id: Some("target-a"),
                origin: Some("transport-batch:derive-batch"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t12",
            })
            .unwrap();
        let FlowingBatchTargetEffectsOutcome::Verified(witness) = vcs
            .verify_private_batch_target_effects(&["unit-b", "unit-c"], "target-batch")
            .unwrap()
        else {
            panic!("derived target batch")
        };
        assert_eq!(
            vcs.verify_private_batch_source_order(&witness).unwrap(),
            FlowingBatchSourceOrderOutcome::Verified
        );
        let RecordFlowingDerivedCutOutcome::Recorded(derived) = vcs
            .record_private_batch_derivation("derive-batch", &witness, "mediator", "t12")
            .unwrap()
        else {
            panic!("retained batch derivation")
        };
        assert!(matches!(
            vcs.handoff_private_batch_derivation(
                "derive-batch",
                &derived.witness_digest,
                "mediator",
                "t13"
            )
            .unwrap(),
            HandoffBatchContributionOutcome::Transferred(_)
        ));
        for pin_id in ["pin-b", "pin-c"] {
            assert_eq!(
                vcs.branches
                    .release_private_cut(ReleasePrivateCut {
                        pin_id,
                        released_by: "mediator",
                        reason: "handed to branch",
                        released_at: "t13",
                    })
                    .unwrap(),
                ReleasePrivateCutOutcome::Released
            );
        }
        revision.source_cut_id = "target-batch".into();
        revision.source_manifest_hash = manifest;
        let NativeCandidateOutcome::Prepared(candidate) = vcs
            .prepare_named_branch_candidate(&revision, None, "candidate-batch", "mediator", "t14")
            .unwrap()
        else {
            panic!("batch must retain the earlier branch unit")
        };
        assert_eq!(candidate.units.len(), 3);
        assert_eq!(candidate.units[0].outcome, FlowingUnitOutcome::Applied);
        assert_eq!(candidate.units[1].outcome, FlowingUnitOutcome::Neutralized);
        assert_eq!(candidate.units[2].outcome, FlowingUnitOutcome::Applied);
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE flowing_contributions SET dependency_basis_digest = 'wrong' WHERE unit_id = 'unit-b'",
                [],
            )
            .unwrap();
        assert_eq!(
            vcs.prepare_named_branch_candidate(
                &revision,
                None,
                "candidate-stale",
                "mediator",
                "t14"
            )
            .unwrap(),
            NativeCandidateOutcome::UnprovenBasis {
                unit_id: "unit-b".into()
            }
        );
    }

    #[test]
    fn retained_named_candidate_verification_keeps_handoff_and_tail_exact() {
        let (mut vcs, revision) = handed_branch(None);
        let NativeCandidateOutcome::Prepared(candidate) = vcs
            .prepare_named_branch_candidate(&revision, None, "candidate-a", "mediator", "t7")
            .unwrap()
        else {
            panic!("candidate")
        };
        assert_eq!(
            vcs.branches
                .release_private_cut(ReleasePrivateCut {
                    pin_id: "pin-a",
                    released_by: "mediator",
                    reason: "handed",
                    released_at: "t8",
                })
                .unwrap(),
            ReleasePrivateCutOutcome::Released
        );
        vcs.retain_review_attempt("verify-attempt", &candidate.candidate_witness_digest, "t9")
            .unwrap();
        let before = vcs.branches.test_connection().total_changes();
        let verified = vcs
            .verify_retained_native_candidate(
                &revision,
                &candidate.candidate_witness_digest,
                "verify-attempt",
            )
            .unwrap();
        assert_eq!(vcs.branches.test_connection().total_changes(), before);
        append_handed_tail(&mut vcs);
        assert_eq!(
            vcs.verify_retained_native_candidate(
                &revision,
                &candidate.candidate_witness_digest,
                "verify-attempt"
            )
            .unwrap(),
            verified
        );
        let mut changed = revision.clone();
        changed.units[0].intent = "substituted intent".into();
        assert!(vcs
            .verify_retained_native_candidate(
                &changed,
                &candidate.candidate_witness_digest,
                "verify-attempt"
            )
            .is_err());
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
        let witness = vcs
            .branches
            .candidate_witness(&candidate.candidate_witness_digest)
            .unwrap()
            .unwrap();
        let fences = crate::branches::flowing_lineage::capture(&vcs.branches, &witness)
            .unwrap()
            .unwrap();
        // This is the actual content-verified handoff, including a released
        // origin pin. The receiving named branch supplies current policy;
        // the transferred twig needs no separate eligibility grant.
        assert_eq!(fences.len(), 1);
        assert_eq!(fences[0].source_branch_id, "branch");
        assert_eq!(fences[0].incarnation_id, "branch-inc");
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
