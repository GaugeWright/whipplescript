use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{
    decide, initial_state, member_point_is_ancestor, missing_member_field, missing_open_field,
    missing_transition_field, validate_member_opening_receipt, validate_source_opening_receipt,
    FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceReceipt,
    FlowingFenceRefusal, FlowingFenceState, FlowingFenceTransition, FlowingMemberOpeningReceipt,
    FlowingMemberOpeningRequest, FlowingSourceKind, FlowingSourceOpeningReceipt,
    OpenFlowingMemberOutcome, OpenFlowingMemberRefusal, OpenFlowingSource,
    OpenFlowingSourceOutcome,
};
use crate::branches::{BranchStatus, BranchStore, CreateBranch, MAINLINE_BRANCH_ID};
use crate::StoreResult;

type FenceOutcome = FlowingFenceOutcome;

pub(crate) fn read_state(
    connection: &Connection,
    source: &str,
) -> StoreResult<Option<FlowingFenceState>> {
    connection
        .query_row(
            "SELECT state_json FROM flowing_source_fences WHERE source_branch_id = ?1",
            [source],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|json| serde_json::from_str(&json).map_err(Into::into))
        .transpose()
}

pub(crate) fn close_pending(connection: &Connection, source: &str) -> StoreResult<bool> {
    Ok(read_close_request(connection, source)?.is_some())
}

fn read_receipt(connection: &Connection, op_id: &str) -> StoreResult<Option<FlowingFenceReceipt>> {
    connection
        .query_row(
            "SELECT request_json, state_json FROM flowing_source_fence_ops WHERE op_id = ?1",
            [op_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .map(|(request, state)| {
            Ok(FlowingFenceReceipt {
                request: serde_json::from_str(&request)?,
                state: serde_json::from_str(&state)?,
            })
        })
        .transpose()
}

fn read_member_opening(
    connection: &Connection,
    branch_id: &str,
) -> StoreResult<Option<FlowingMemberOpeningReceipt>> {
    let receipt: Option<FlowingMemberOpeningReceipt> = connection
        .query_row(
            "SELECT request_json, branch_json, state_json FROM flowing_member_openings WHERE branch_id = ?1",
            [branch_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
        )
        .optional()?
        .map(|(request, branch, source)| -> StoreResult<_> {
            Ok(FlowingMemberOpeningReceipt {
                request: serde_json::from_str(&request)?,
                branch: serde_json::from_str(&branch)?,
                source: serde_json::from_str(&source)?,
            })
        })
        .transpose()?;
    if let Some(receipt) = &receipt {
        validate_member_opening_receipt(branch_id, receipt)?;
    }
    Ok(receipt)
}

fn read_source_opening(
    connection: &Connection,
    source_branch_id: &str,
) -> StoreResult<Option<FlowingSourceOpeningReceipt>> {
    let receipt: Option<FlowingSourceOpeningReceipt> = connection
        .query_row(
            "SELECT request_json, state_json FROM flowing_source_openings WHERE source_branch_id = ?1",
            [source_branch_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .map(|(request, state)| -> StoreResult<_> {
            Ok(FlowingSourceOpeningReceipt {
                request: serde_json::from_str(&request)?,
                state: serde_json::from_str(&state)?,
            })
        })
        .transpose()?;
    if let Some(receipt) = &receipt {
        validate_source_opening_receipt(source_branch_id, receipt)?;
    }
    Ok(receipt)
}

pub(crate) fn read_close_request(
    connection: &Connection,
    source: &str,
) -> StoreResult<Option<FlowingFenceReceipt>> {
    let marker: Option<(String, String)> = connection
        .query_row(
            "SELECT op_id, incarnation_id FROM flowing_source_close_requests \
             WHERE source_branch_id = ?1",
            [source],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((op_id, incarnation_id)) = marker else {
        return Ok(None);
    };
    let receipt = read_receipt(connection, &op_id)?.ok_or_else(|| {
        crate::StoreError::Conflict("flowing close request lost its ref receipt".into())
    })?;
    if receipt.request.action != FlowingFenceAction::RequestClose
        || receipt.request.op_id != op_id
        || receipt.request.source_branch_id != source
        || receipt.request.incarnation_id != incarnation_id
        || receipt.state.source_branch_id != source
        || receipt.state.incarnation_id != incarnation_id
    {
        return Err(crate::StoreError::Conflict(
            "flowing close request differs from its ref receipt".into(),
        ));
    }
    Ok(Some(receipt))
}

impl FlowingFence for BranchStore {
    fn open_flowing_member(
        &mut self,
        branch: CreateBranch<'_>,
        source: &OpenFlowingSource,
    ) -> StoreResult<OpenFlowingMemberOutcome> {
        use OpenFlowingMemberOutcome as Outcome;
        use OpenFlowingMemberRefusal as Refusal;

        if let Some(field) = missing_member_field(&branch, source) {
            return Ok(Outcome::Refused(Refusal::Invalid { field }));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let opening_request = FlowingMemberOpeningRequest::new(&branch, source);
        if let Some(receipt) = read_member_opening(&tx, branch.branch_id)? {
            if receipt.request != opening_request {
                // MUTATION-SUCCESS-EXPR: Ok(Outcome::Existing { branch: receipt.branch, source: receipt.source })
                return Ok(Outcome::Refused(Refusal::IdentityMismatch));
            }
            let current_branch = BranchStore::row_by_id(&tx, branch.branch_id)?;
            let current_source = read_state(&tx, branch.branch_id)?;
            if current_branch.is_none()
                || current_source
                    .as_ref()
                    .is_none_or(|state| state.incarnation_id != receipt.source.incarnation_id)
            {
                return Err(crate::StoreError::Conflict(
                    "flowing member opening lost current authority".into(),
                ));
            }
            return Ok(Outcome::Existing {
                branch: receipt.branch,
                source: receipt.source,
            });
        }
        if let Some(_existing) = BranchStore::row_by_id(&tx, branch.branch_id)? {
            if read_state(&tx, branch.branch_id)?.is_none() {
                // MUTATION-SUCCESS-EXPR: Ok(Outcome::Opened { branch: _existing, source: initial_state(source) })
                return Ok(Outcome::Refused(Refusal::ExistingBranchWithoutSource));
            }
            // A legacy two-step opening cannot acquire a receipt retroactively.
            // MUTATION-SUCCESS-EXPR: Ok(Outcome::Opened { branch: _existing, source: initial_state(source) })
            return Ok(Outcome::Refused(Refusal::IdentityMismatch));
        }
        if let Some(key) = branch.idempotency_key {
            let used: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM branches WHERE idempotency_key = ?1)",
                [key],
                |row| row.get(0),
            )?;
            if used {
                return Ok(Outcome::Refused(Refusal::IdentityMismatch));
            }
        }
        let Some(parent) = BranchStore::row_by_id(&tx, branch.parent_branch_id)? else {
            // MUTATION-SUCCESS-EXPR: Ok(Outcome::Opened { branch: BranchStore::row_by_id(&tx, MAINLINE_BRANCH_ID)?.expect("mainline"), source: initial_state(source) })
            return Ok(Outcome::Refused(Refusal::ParentMissing));
        };
        if parent.status != BranchStatus::Active {
            return Ok(Outcome::Refused(Refusal::ParentNotActive));
        }
        let Some(parent_source) = read_state(&tx, branch.parent_branch_id)? else {
            // MUTATION-SUCCESS-EXPR: Ok(Outcome::Opened { branch: parent, source: initial_state(source) })
            return Ok(Outcome::Refused(Refusal::ParentNotFlowing));
        };
        if parent_source.kind != FlowingSourceKind::Branch
            || parent.parent_branch_id.as_deref() != Some(MAINLINE_BRANCH_ID)
        {
            return Ok(Outcome::Refused(Refusal::ParentNotFlowing));
        }
        if !parent_source.admission_enabled {
            return Ok(Outcome::Refused(Refusal::ParentAdmissionDisabled));
        }
        if let Some((cut_id, manifest_hash)) = branch.at_cut {
            if !member_point_is_ancestor(
                parent.head_cut_id.as_deref(),
                cut_id,
                manifest_hash,
                |id| BranchStore::cut_by_id(&tx, id),
            )? {
                return Ok(Outcome::Refused(Refusal::Invalid { field: "at_cut" }));
            }
        }
        let (point_cut, point_manifest) = match branch.at_cut {
            Some((cut, manifest)) => (Some(cut.to_owned()), Some(manifest.to_owned())),
            None => (parent.head_cut_id, parent.head_manifest_hash),
        };
        tx.execute(
            "INSERT INTO branches \
             (branch_id, name, parent_branch_id, branch_point_cut_id, \
              branch_point_manifest_hash, head_cut_id, head_manifest_hash, \
              status, created_at, updated_at, idempotency_key) \
             VALUES (?1, NULL, ?2, ?3, ?4, ?3, ?4, 'active', ?5, ?5, ?6)",
            params![
                branch.branch_id,
                branch.parent_branch_id,
                point_cut,
                point_manifest,
                branch.created_at,
                branch.idempotency_key,
            ],
        )?;
        let state = initial_state(source);
        tx.execute(
            "INSERT INTO flowing_source_fences (source_branch_id, state_json) VALUES (?1, ?2)",
            params![branch.branch_id, serde_json::to_string(&state)?],
        )?;
        tx.execute(
            "INSERT INTO flowing_source_openings (source_branch_id, request_json, state_json) VALUES (?1, ?2, ?3)",
            params![branch.branch_id, serde_json::to_string(source)?, serde_json::to_string(&state)?],
        )?;
        let created = BranchStore::row_by_id(&tx, branch.branch_id)?
            .expect("created member row exists in transaction");
        tx.execute(
            "INSERT INTO flowing_member_openings (branch_id, request_json, branch_json, state_json) VALUES (?1, ?2, ?3, ?4)",
            params![branch.branch_id, serde_json::to_string(&opening_request)?, serde_json::to_string(&created)?, serde_json::to_string(&state)?],
        )?;
        tx.commit()?;
        Ok(Outcome::Opened {
            branch: created,
            source: state,
        })
    }

    fn open_flowing_source(
        &mut self,
        request: &OpenFlowingSource,
    ) -> StoreResult<OpenFlowingSourceOutcome> {
        if let Some(field) = missing_open_field(request) {
            return Ok(OpenFlowingSourceOutcome::Invalid { field });
        }
        if request.source_branch_id == MAINLINE_BRANCH_ID {
            return Ok(OpenFlowingSourceOutcome::Invalid {
                field: "source_branch_id",
            });
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(receipt) = read_source_opening(&tx, &request.source_branch_id)? {
            if receipt.request != *request {
                // MUTATION-SUCCESS-EXPR: Ok(OpenFlowingSourceOutcome::Existing(receipt.state))
                return Ok(OpenFlowingSourceOutcome::IdentityMismatch);
            }
            let current = read_state(&tx, &request.source_branch_id)?;
            if BranchStore::row_by_id(&tx, &request.source_branch_id)?.is_none()
                || current
                    .as_ref()
                    .is_none_or(|state| state.incarnation_id != receipt.state.incarnation_id)
            {
                return Err(crate::StoreError::Conflict(
                    "flowing source opening lost current authority".into(),
                ));
            }
            return Ok(OpenFlowingSourceOutcome::Existing(receipt.state));
        }
        if let Some(existing) = read_state(&tx, &request.source_branch_id)? {
            return Ok(
                if existing.incarnation_id == request.incarnation_id
                    && existing.kind == request.kind
                    && existing.owner == request.owner
                    && existing.opened_at == request.opened_at
                {
                    OpenFlowingSourceOutcome::Existing(existing)
                } else {
                    OpenFlowingSourceOutcome::IdentityMismatch
                },
            );
        }
        let Some(branch) = BranchStore::row_by_id(&tx, &request.source_branch_id)? else {
            return Ok(OpenFlowingSourceOutcome::BranchMissing);
        };
        if branch.status != BranchStatus::Active {
            return Ok(OpenFlowingSourceOutcome::BranchNotActive);
        }
        if (request.kind == FlowingSourceKind::Branch) != branch.name.is_some() {
            return Ok(OpenFlowingSourceOutcome::InvalidKindName);
        }
        if request.kind == FlowingSourceKind::Branch
            && branch.parent_branch_id.as_deref() != Some(MAINLINE_BRANCH_ID)
        {
            return Ok(OpenFlowingSourceOutcome::InvalidKindParent);
        }
        if request.kind == FlowingSourceKind::Twig
            && branch.parent_branch_id.as_deref() != Some(MAINLINE_BRANCH_ID)
        {
            let parent = match branch.parent_branch_id.as_deref() {
                Some(id)
                    if BranchStore::row_by_id(&tx, id)?
                        .is_some_and(|row| row.status == BranchStatus::Active) =>
                {
                    read_state(&tx, id)?
                }
                None => None,
                Some(_) => None,
            };
            if !parent.is_some_and(|state| {
                state.kind == FlowingSourceKind::Branch && state.admission_enabled
            }) {
                return Ok(OpenFlowingSourceOutcome::InvalidKindParent);
            }
        }
        if branch.head_cut_id != branch.branch_point_cut_id
            || branch.head_manifest_hash != branch.branch_point_manifest_hash
            || branch.updated_at != branch.created_at
        {
            return Ok(OpenFlowingSourceOutcome::BranchAlreadyMoved);
        }
        let has_children: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM branches WHERE parent_branch_id = ?1)",
            [&request.source_branch_id],
            |row| row.get(0),
        )?;
        if has_children {
            return Ok(OpenFlowingSourceOutcome::BranchAlreadyHasChildren);
        }
        let state = FlowingFenceState {
            source_branch_id: request.source_branch_id.clone(),
            incarnation_id: request.incarnation_id.clone(),
            kind: request.kind.clone(),
            owner: request.owner.clone(),
            owner_epoch: 0,
            eligibility_epoch: 0,
            held: false,
            revision: None,
            admission_enabled: true,
            opened_at: request.opened_at.clone(),
        };
        tx.execute(
            "INSERT INTO flowing_source_fences (source_branch_id, state_json) VALUES (?1, ?2)",
            params![request.source_branch_id, serde_json::to_string(&state)?],
        )?;
        tx.execute(
            "INSERT INTO flowing_source_openings (source_branch_id, request_json, state_json) VALUES (?1, ?2, ?3)",
            params![request.source_branch_id, serde_json::to_string(request)?, serde_json::to_string(&state)?],
        )?;
        tx.commit()?;
        Ok(OpenFlowingSourceOutcome::Opened(state))
    }

    fn flowing_source(&self, source_branch_id: &str) -> StoreResult<Option<FlowingFenceState>> {
        read_state(&self.connection, source_branch_id)
    }

    fn flowing_source_opening(
        &self,
        source_branch_id: &str,
    ) -> StoreResult<Option<FlowingSourceOpeningReceipt>> {
        read_source_opening(&self.connection, source_branch_id)
    }

    fn flowing_member_opening(
        &self,
        branch_id: &str,
    ) -> StoreResult<Option<FlowingMemberOpeningReceipt>> {
        read_member_opening(&self.connection, branch_id)
    }

    fn flowing_close_request(
        &self,
        source_branch_id: &str,
    ) -> StoreResult<Option<FlowingFenceReceipt>> {
        read_close_request(&self.connection, source_branch_id)
    }

    fn transition_flowing_source(
        &mut self,
        request: &FlowingFenceTransition,
    ) -> StoreResult<FlowingFenceOutcome> {
        if let Some(field) = missing_transition_field(request) {
            return Ok(FlowingFenceOutcome::Refused(FlowingFenceRefusal::Invalid {
                field,
            }));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_receipt(&tx, &request.op_id)? {
            if existing.request == *request {
                return Ok(FlowingFenceOutcome::Existing(existing));
            }
            // MUTATION-SUCCESS-EXPR: Ok(FlowingFenceOutcome::Existing(existing))
            return Ok(FenceOutcome::Refused(FlowingFenceRefusal::IdentityMismatch));
        }
        let Some(state) = read_state(&tx, &request.source_branch_id)? else {
            // MUTATION-SUCCESS-EXPR: Ok(FlowingFenceOutcome::Applied(FlowingFenceReceipt { request: request.clone(), state: FlowingFenceState { source_branch_id: String::new(), incarnation_id: String::new(), kind: FlowingSourceKind::Twig, owner: String::new(), owner_epoch: 0, eligibility_epoch: 0, held: false, revision: None, admission_enabled: false, opened_at: String::new() } }))
            return Ok(FlowingFenceOutcome::Refused(FlowingFenceRefusal::Missing));
        };
        let Some(branch) = BranchStore::row_by_id(&tx, &request.source_branch_id)? else {
            // MUTATION-SUCCESS-EXPR: Ok(FlowingFenceOutcome::Applied(FlowingFenceReceipt { request: request.clone(), state }))
            return Ok(FlowingFenceOutcome::Refused(FlowingFenceRefusal::Missing));
        };
        if branch.status != BranchStatus::Active {
            // MUTATION-SUCCESS-EXPR: Ok(FlowingFenceOutcome::Applied(FlowingFenceReceipt { request: request.clone(), state }))
            return Ok(FenceOutcome::Refused(FlowingFenceRefusal::BranchNotActive));
        }
        let after = match decide(&state, request, branch.head_cut_id.as_deref()) {
            Ok(after) => after,
            Err(refusal) => return Ok(FlowingFenceOutcome::Refused(refusal)),
        };
        if request.action == FlowingFenceAction::RequestClose {
            if state.kind == FlowingSourceKind::Twig
                && branch.parent_branch_id.as_deref() != Some(MAINLINE_BRANCH_ID)
            {
                return Ok(FenceOutcome::Refused(FlowingFenceRefusal::NotDirectSource));
            }
            if close_pending(&tx, &request.source_branch_id)? {
                return Ok(FenceOutcome::Refused(
                    FlowingFenceRefusal::CloseAlreadyPending,
                ));
            }
            tx.execute(
                "INSERT INTO flowing_source_close_requests \
                 (source_branch_id, op_id, incarnation_id, recorded_at) VALUES (?1, ?2, ?3, ?4)",
                params![
                    request.source_branch_id,
                    request.op_id,
                    request.incarnation_id,
                    request.recorded_at
                ],
            )?;
        }
        let state_json = serde_json::to_string(&after)?;
        tx.execute(
            "UPDATE flowing_source_fences SET state_json = ?2 WHERE source_branch_id = ?1",
            params![request.source_branch_id, state_json],
        )?;
        tx.execute(
            "INSERT INTO flowing_source_fence_ops (op_id, request_json, state_json) \
             VALUES (?1, ?2, ?3)",
            params![request.op_id, serde_json::to_string(request)?, state_json,],
        )?;
        tx.commit()?;
        Ok(FlowingFenceOutcome::Applied(FlowingFenceReceipt {
            request: request.clone(),
            state: after,
        }))
    }

    fn flowing_fence_receipt(&self, op_id: &str) -> StoreResult<Option<FlowingFenceReceipt>> {
        read_receipt(&self.connection, op_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branches::flowing_close_roster::FlowingCloseRosterReader;
    use crate::branches::flowing_fence::{FlowingFenceAction, FlowingRevision};
    use crate::branches::{
        AdvanceOutcome, Branches, CreateBranch, CreateBranchOutcome, CutRecord, CutRow,
        RetargetOutcome,
    };
    use crate::StoreError;

    fn source() -> BranchStore {
        let mut store = BranchStore::open_in_memory().unwrap();
        store.ensure_mainline("t0").unwrap();
        assert!(matches!(
            store
                .create_branch(CreateBranch {
                    branch_id: "branch",
                    name: Some("feature"),
                    parent_branch_id: MAINLINE_BRANCH_ID,
                    at_cut: None,
                    created_at: "t1",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::Created(_)
        ));
        store
    }

    fn request(
        store: &BranchStore,
        op_id: &str,
        action: FlowingFenceAction,
    ) -> FlowingFenceTransition {
        let state = store.flowing_source("branch").unwrap().unwrap();
        FlowingFenceTransition {
            op_id: op_id.into(),
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            expected_eligibility_epoch: state.eligibility_epoch,
            expected_owner_epoch: state.owner_epoch,
            actor: "mediator".into(),
            action,
            recorded_at: op_id.into(),
        }
    }

    fn member_request<'a>(id: &'a str, parent: &'a str, key: Option<&'a str>) -> CreateBranch<'a> {
        CreateBranch {
            branch_id: id,
            name: None,
            parent_branch_id: parent,
            at_cut: None,
            created_at: "t3",
            idempotency_key: key,
        }
    }

    fn member_opening(id: &str) -> OpenFlowingSource {
        OpenFlowingSource {
            source_branch_id: id.into(),
            incarnation_id: format!("{id}-inc"),
            kind: FlowingSourceKind::Twig,
            owner: "mediator".into(),
            opened_at: "t3".into(),
        }
    }

    #[test]
    fn atomic_member_refusals_leave_no_partial_membership() {
        use OpenFlowingMemberOutcome::Refused;
        use OpenFlowingMemberRefusal as Why;

        let mut store = source();
        assert_eq!(
            store
                .open_flowing_member(
                    CreateBranch {
                        name: Some("named"),
                        ..member_request("invalid", "branch", None)
                    },
                    &member_opening("invalid"),
                )
                .unwrap(),
            Refused(Why::Invalid { field: "name" })
        );
        assert_eq!(
            store
                .open_flowing_member(
                    member_request("missing", "absent", None),
                    &member_opening("missing")
                )
                .unwrap(),
            Refused(Why::ParentMissing)
        );
        assert_eq!(
            store
                .open_flowing_member(
                    member_request("legacy", "branch", None),
                    &member_opening("legacy")
                )
                .unwrap(),
            Refused(Why::ParentNotFlowing)
        );
        store
            .create_branch(CreateBranch {
                branch_id: "inactive",
                name: Some("inactive"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        store.discard_branch("inactive", "t2").unwrap();
        assert_eq!(
            store
                .open_flowing_member(
                    member_request("closed", "inactive", None),
                    &member_opening("closed")
                )
                .unwrap(),
            Refused(Why::ParentNotActive)
        );
        store
            .create_branch(member_request("twig-parent", MAINLINE_BRANCH_ID, None))
            .unwrap();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "twig-parent".into(),
                incarnation_id: "twig-parent-inc".into(),
                kind: FlowingSourceKind::Twig,
                owner: "mediator".into(),
                opened_at: "t3".into(),
            })
            .unwrap();
        assert_eq!(
            store
                .open_flowing_member(
                    member_request("nested", "twig-parent", None),
                    &member_opening("nested")
                )
                .unwrap(),
            Refused(Why::ParentNotFlowing)
        );
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "mediator".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        assert_eq!(
            store
                .open_flowing_member(
                    CreateBranch {
                        at_cut: Some(("missing-cut", "missing-manifest")),
                        ..member_request("bad-cut", "branch", None)
                    },
                    &member_opening("bad-cut"),
                )
                .unwrap(),
            Refused(Why::Invalid { field: "at_cut" })
        );
        store
            .create_branch(member_request("preexisting", "branch", None))
            .unwrap();
        assert_eq!(
            store
                .open_flowing_member(
                    member_request("preexisting", "branch", None),
                    &member_opening("preexisting")
                )
                .unwrap(),
            Refused(Why::ExistingBranchWithoutSource)
        );
        assert!(matches!(
            store
                .open_flowing_source(&member_opening("preexisting"))
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        assert_eq!(
            store
                .open_flowing_member(
                    member_request("preexisting", "branch", None),
                    &member_opening("preexisting")
                )
                .unwrap(),
            Refused(Why::IdentityMismatch)
        );
        store
            .create_branch(member_request(
                "used-key",
                MAINLINE_BRANCH_ID,
                Some("collision"),
            ))
            .unwrap();
        assert_eq!(
            store
                .open_flowing_member(
                    member_request("new", "branch", Some("collision")),
                    &member_opening("new")
                )
                .unwrap(),
            Refused(Why::IdentityMismatch)
        );
        assert!(matches!(
            store
                .open_flowing_member(
                    member_request("member", "branch", None),
                    &member_opening("member")
                )
                .unwrap(),
            OpenFlowingMemberOutcome::Opened { .. }
        ));
        assert_eq!(
            store
                .open_flowing_member(
                    member_request("member", "branch", None),
                    &OpenFlowingSource {
                        owner: "different".into(),
                        ..member_opening("member")
                    },
                )
                .unwrap(),
            Refused(Why::IdentityMismatch)
        );
        let disable = request(&store, "disable", FlowingFenceAction::DisableAdmission);
        store.transition_flowing_source(&disable).unwrap();
        assert_eq!(
            store
                .open_flowing_member(
                    member_request("late", "branch", None),
                    &member_opening("late")
                )
                .unwrap(),
            Refused(Why::ParentAdmissionDisabled)
        );
        for id in [
            "invalid", "missing", "legacy", "closed", "nested", "bad-cut", "new", "late",
        ] {
            assert!(store.get_branch(id).unwrap().is_none(), "{id}");
            assert!(store.flowing_source(id).unwrap().is_none(), "{id}");
        }
    }

    #[test]
    fn disabled_flowing_branch_refuses_new_members_and_retargets() {
        let mut store = source();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "mediator".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        let original = CreateBranch {
            branch_id: "member",
            name: None,
            parent_branch_id: "branch",
            at_cut: None,
            created_at: "t3",
            idempotency_key: Some("original-member"),
        };
        assert!(matches!(
            store.create_branch(original.clone()).unwrap(),
            CreateBranchOutcome::Created(_)
        ));
        assert_eq!(
            store
                .create_branch(CreateBranch {
                    branch_id: "nested-name",
                    name: Some("nested"),
                    parent_branch_id: "branch",
                    at_cut: None,
                    created_at: "t3",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::ParentFlowingTopology
        );
        assert_eq!(
            store
                .create_branch(CreateBranch {
                    branch_id: "nested-child",
                    name: None,
                    parent_branch_id: "member",
                    at_cut: None,
                    created_at: "t3",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::ParentFlowingTopology
        );
        store
            .create_branch(CreateBranch {
                branch_id: "outsider",
                name: None,
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t3",
                idempotency_key: None,
            })
            .unwrap();
        assert_eq!(
            store.retarget_branch("outsider", "branch", "t3").unwrap(),
            RetargetOutcome::ParentFlowingSource
        );
        assert_eq!(
            store.retarget_branch("outsider", "member", "t3").unwrap(),
            RetargetOutcome::ParentFlowingSource
        );
        let disable = request(&store, "disable", FlowingFenceAction::DisableAdmission);
        assert!(matches!(
            store.transition_flowing_source(&disable).unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        assert_eq!(
            store
                .create_branch(CreateBranch {
                    branch_id: "late-member",
                    name: None,
                    parent_branch_id: "branch",
                    at_cut: None,
                    created_at: "t4",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::ParentAdmissionDisabled
        );
        assert_eq!(
            store
                .create_branch(CreateBranch {
                    branch_id: "late-grandchild",
                    name: None,
                    parent_branch_id: "member",
                    at_cut: None,
                    created_at: "t4",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::ParentAdmissionDisabled
        );
        assert!(matches!(
            store.create_branch(original).unwrap(),
            CreateBranchOutcome::Existing(_)
        ));
        assert_eq!(
            store.retarget_branch("outsider", "branch", "t4").unwrap(),
            RetargetOutcome::ParentFlowingSource
        );
        assert_eq!(
            store
                .get_branch("outsider")
                .unwrap()
                .unwrap()
                .parent_branch_id
                .as_deref(),
            Some(MAINLINE_BRANCH_ID)
        );
        assert!(store.get_branch("late-member").unwrap().is_none());
    }

    #[test]
    fn unopened_flowing_member_cannot_acquire_private_work() {
        let mut store = source();
        assert!(matches!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "branch".into(),
                    incarnation_id: "inc-1".into(),
                    kind: FlowingSourceKind::Branch,
                    owner: "mediator".into(),
                    opened_at: "t2".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        assert!(matches!(
            store
                .create_branch(CreateBranch {
                    branch_id: "member",
                    name: None,
                    parent_branch_id: "branch",
                    at_cut: None,
                    created_at: "t3",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::Created(_)
        ));
        assert!(matches!(
            store.advance_head("member", None, "unopened", "manifest", "t3"),
            Err(StoreError::Conflict(message)) if message == "flowing member has no source fence"
        ));
        assert!(matches!(
            store.commit_write_with_evidence(
                CutRecord {
                    cut_id: "unopened",
                    change_id: "unopened",
                    branch_id: "member",
                    manifest_hash: "manifest",
                    parent_cut_id: None,
                    origin: None,
                    actor: None,
                    intent: None,
                    recorded_at: "t3",
                },
                None,
            ),
            Err(StoreError::Conflict(message)) if message == "flowing member has no source fence"
        ));
        assert!(store.get_cut("unopened").unwrap().is_none());
        assert!(matches!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "member".into(),
                    incarnation_id: "member-inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "mediator".into(),
                    opened_at: "t3".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        let member = store.flowing_source("member").unwrap().unwrap();
        let member_close = FlowingFenceTransition {
            op_id: "member-close".into(),
            source_branch_id: "member".into(),
            incarnation_id: "member-inc".into(),
            expected_eligibility_epoch: member.eligibility_epoch,
            expected_owner_epoch: member.owner_epoch,
            actor: "mediator".into(),
            action: FlowingFenceAction::RequestClose,
            recorded_at: "t3".into(),
        };
        assert_eq!(
            store.transition_flowing_source(&member_close).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::NotDirectSource)
        );
        assert!(store.flowing_close_request("member").unwrap().is_none());
    }

    #[test]
    fn member_open_rolls_back_branch_when_fence_insert_fails() {
        let mut store = source();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "mediator".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        store
            .test_connection()
            .execute_batch(
                "CREATE TRIGGER reject_member_fence BEFORE INSERT ON flowing_source_fences \
                 WHEN NEW.source_branch_id = 'member' BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        let member = CreateBranch {
            branch_id: "member",
            name: None,
            parent_branch_id: "branch",
            at_cut: None,
            created_at: "t3",
            idempotency_key: Some("member-key"),
        };
        let opening = OpenFlowingSource {
            source_branch_id: "member".into(),
            incarnation_id: "member-inc".into(),
            kind: FlowingSourceKind::Twig,
            owner: "mediator".into(),
            opened_at: "t3".into(),
        };
        assert!(store.open_flowing_member(member.clone(), &opening).is_err());
        assert!(store.get_branch("member").unwrap().is_none());
        assert!(store.flowing_source("member").unwrap().is_none());
        store
            .test_connection()
            .execute_batch("DROP TRIGGER reject_member_fence")
            .unwrap();
        assert!(matches!(
            store.open_flowing_member(member, &opening).unwrap(),
            OpenFlowingMemberOutcome::Opened { .. }
        ));
        store
            .test_connection()
            .execute_batch(
                "CREATE TRIGGER reject_member_receipt BEFORE INSERT ON flowing_member_openings \
             WHEN NEW.branch_id = 'member2' BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        let second = member_request("member2", "branch", Some("member-key-2"));
        let second_opening = member_opening("member2");
        assert!(store
            .open_flowing_member(second.clone(), &second_opening)
            .is_err());
        assert!(store.get_branch("member2").unwrap().is_none());
        assert!(store.flowing_source("member2").unwrap().is_none());
        store
            .test_connection()
            .execute_batch("DROP TRIGGER reject_member_receipt")
            .unwrap();
        assert!(matches!(
            store.open_flowing_member(second, &second_opening).unwrap(),
            OpenFlowingMemberOutcome::Opened { .. }
        ));
        store
            .test_connection()
            .execute(
                "DELETE FROM flowing_source_openings WHERE source_branch_id = 'member2'",
                [],
            )
            .unwrap();
        assert!(matches!(
            crate::branches::flowing_open_host::read_member_opening_evidence(&store, "member2"),
            Err(StoreError::Conflict(message)) if message == "flowing opening host evidence refuses: member source opening receipt is missing"
        ));
        let mut retained = store.flowing_member_opening("member").unwrap().unwrap();
        retained.branch.name = Some("forged".into());
        store
            .test_connection()
            .execute(
                "UPDATE flowing_member_openings SET branch_json = ?1 WHERE branch_id = 'member'",
                [serde_json::to_string(&retained.branch).unwrap()],
            )
            .unwrap();
        assert!(matches!(
            store.flowing_member_opening("member"),
            Err(StoreError::Conflict(message)) if message == "flowing member opening receipt is inconsistent"
        ));
    }

    #[test]
    fn close_request_fences_new_members_but_retains_existing_members_and_cas_window() {
        let mut store = source();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "mediator".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        assert!(matches!(
            store
                .create_branch(CreateBranch {
                    branch_id: "early-member",
                    name: None,
                    parent_branch_id: "branch",
                    at_cut: None,
                    created_at: "t3",
                    idempotency_key: Some("early-member-op"),
                })
                .unwrap(),
            CreateBranchOutcome::Created(_)
        ));
        let close = request(&store, "request-close", FlowingFenceAction::RequestClose);
        let before = store.flowing_source("branch").unwrap().unwrap();
        assert!(matches!(
            store.transition_flowing_source(&close).unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        assert_eq!(store.flowing_source("branch").unwrap().unwrap(), before);
        assert_eq!(
            store.transition_flowing_source(&close).unwrap(),
            FlowingFenceOutcome::Existing(store.flowing_close_request("branch").unwrap().unwrap())
        );
        assert_eq!(
            store
                .transition_flowing_source(&request(
                    &store,
                    "another-close",
                    FlowingFenceAction::RequestClose,
                ))
                .unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::CloseAlreadyPending)
        );
        assert_eq!(
            store
                .create_branch(CreateBranch {
                    branch_id: "late-member",
                    name: None,
                    parent_branch_id: "branch",
                    at_cut: None,
                    created_at: "t4",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::ParentAdmissionDisabled
        );
        assert!(matches!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "early-member".into(),
                    incarnation_id: "early-inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "mediator".into(),
                    opened_at: "t4".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        let roster = store.flowing_close_roster("branch").unwrap().unwrap();
        assert_eq!(roster.close_request.unwrap().request, close);
        assert_eq!(roster.members.len(), 1);
        assert_eq!(roster.members[0].branch_id, "early-member");
        let disable = request(&store, "disable", FlowingFenceAction::DisableAdmission);
        assert!(matches!(
            store.transition_flowing_source(&disable).unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        let after = store.flowing_source("branch").unwrap().unwrap();
        assert!(!after.admission_enabled);
        assert_eq!(after.eligibility_epoch, before.eligibility_epoch + 1);

        let mut wrong_incarnation = after.clone();
        wrong_incarnation.incarnation_id = "foreign-incarnation".into();
        store
            .test_connection()
            .execute(
                "UPDATE flowing_source_fences SET state_json = ?1 WHERE source_branch_id = 'branch'",
                [serde_json::to_string(&wrong_incarnation).unwrap()],
            )
            .unwrap();
        assert!(matches!(
            store.flowing_close_roster("branch"),
            Err(StoreError::Conflict(message))
                if message == "flowing close request belongs to another incarnation"
        ));
        store
            .test_connection()
            .execute(
                "UPDATE flowing_source_fences SET state_json = ?1 WHERE source_branch_id = 'branch'",
                [serde_json::to_string(&after).unwrap()],
            )
            .unwrap();
        store
            .test_connection()
            .execute(
                "UPDATE flowing_source_close_requests SET incarnation_id = 'foreign-incarnation' \
                 WHERE source_branch_id = 'branch'",
                [],
            )
            .unwrap();
        assert!(matches!(
            store.flowing_close_request("branch"),
            Err(StoreError::Conflict(message))
                if message == "flowing close request differs from its ref receipt"
        ));
        store
            .test_connection()
            .execute(
                "UPDATE flowing_source_close_requests SET incarnation_id = 'inc-1' \
                 WHERE source_branch_id = 'branch'",
                [],
            )
            .unwrap();
        store
            .test_connection()
            .execute(
                "DELETE FROM flowing_source_fence_ops WHERE op_id = 'request-close'",
                [],
            )
            .unwrap();
        assert!(matches!(
            store.flowing_close_request("branch"),
            Err(StoreError::Conflict(message))
                if message == "flowing close request lost its ref receipt"
        ));
    }

    #[test]
    fn corrupt_flowing_parent_ancestry_cannot_admit_a_member() {
        for (corruption, expected) in [
            (
                "UPDATE branches SET parent_branch_id = 'member' WHERE branch_id = 'branch'",
                "cyclic branch ancestry",
            ),
            (
                "DELETE FROM branches WHERE branch_id = 'branch'",
                "missing branch ancestor",
            ),
        ] {
            let mut store = source();
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "branch".into(),
                    incarnation_id: "inc-1".into(),
                    kind: FlowingSourceKind::Branch,
                    owner: "mediator".into(),
                    opened_at: "t2".into(),
                })
                .unwrap();
            store
                .create_branch(CreateBranch {
                    branch_id: "member",
                    name: None,
                    parent_branch_id: "branch",
                    at_cut: None,
                    created_at: "t3",
                    idempotency_key: None,
                })
                .unwrap();
            store.connection.execute(corruption, []).unwrap();
            let error = store
                .create_branch(CreateBranch {
                    branch_id: "late-member",
                    name: None,
                    parent_branch_id: "member",
                    at_cut: None,
                    created_at: "t4",
                    idempotency_key: None,
                })
                .unwrap_err();
            assert!(format!("{error:?}").contains(expected));
            assert!(store.get_branch("late-member").unwrap().is_none());
        }
    }

    #[test]
    fn head_move_guard_requires_a_recorded_cut_and_exact_revision() {
        let mut state = FlowingFenceState {
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            kind: FlowingSourceKind::Branch,
            owner: "coordinator".into(),
            owner_epoch: 0,
            eligibility_epoch: 0,
            held: false,
            revision: None,
            admission_enabled: true,
            opened_at: "t0".into(),
        };
        let mut cut = CutRow {
            cut_id: "cut-1".into(),
            change_id: "change-1".into(),
            branch_id: "branch".into(),
            manifest_hash: "manifest-1".into(),
            parent_cut_id: None,
            origin: Some("write:file".into()),
            actor: Some("human:author".into()),
            intent: None,
            recorded_at: "t1".into(),
        };
        let guard = crate::branches::flowing_fence::require_head_move;
        assert!(matches!(
            guard(&state, None, "cut-1", "manifest-1", None),
            Err(StoreError::Conflict(message)) if message.contains("needs a recorded cut")
        ));
        assert!(matches!(
            guard(&state, None, "cut-1", "wrong-manifest", Some(&cut)),
            Err(StoreError::Conflict(message)) if message.contains("cut differs from the proposed head")
        ));
        assert!(guard(&state, None, "cut-1", "manifest-1", Some(&cut)).is_ok());

        cut.parent_cut_id = Some("unrelated-cut".into());
        assert!(matches!(
            guard(&state, None, "cut-1", "manifest-1", Some(&cut)),
            Err(StoreError::Conflict(message)) if message.contains("rewrite needs a revision fence")
        ));
        state.revision = Some(FlowingRevision {
            begin_op_id: "begin-1".into(),
            before_cut_id: None,
            after_cut_id: "planned-cut".into(),
        });
        assert!(matches!(
            guard(&state, None, "cut-1", "manifest-1", Some(&cut)),
            Err(StoreError::Conflict(message)) if message.contains("differs from its pending revision")
        ));
        state.revision.as_mut().unwrap().after_cut_id = "cut-1".into();
        assert!(guard(&state, None, "cut-1", "manifest-1", Some(&cut)).is_ok());
        state.admission_enabled = false;
        assert!(matches!(
            guard(&state, None, "cut-1", "manifest-1", Some(&cut)),
            Err(StoreError::Conflict(message)) if message.contains("no longer accepts head moves")
        ));
    }

    #[test]
    fn legacy_terminal_move_cannot_discard_a_flowing_source() {
        let mut store = source();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        assert!(matches!(
            store.discard_branch("branch", "t3"),
            Err(StoreError::Conflict(message)) if message.contains("controlled lifecycle move")
        ));
        assert_eq!(
            store.get_branch("branch").unwrap().unwrap().status,
            crate::branches::BranchStatus::Active
        );
    }

    #[test]
    fn source_fence_holds_revision_takeover_and_close_with_exact_retries() {
        let mut store = source();
        let opening = OpenFlowingSource {
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            kind: FlowingSourceKind::Branch,
            owner: "coordinator-a".into(),
            opened_at: "t2".into(),
        };
        let OpenFlowingSourceOutcome::Opened(first) = store.open_flowing_source(&opening).unwrap()
        else {
            panic!("fresh source must open")
        };
        assert_eq!(first.eligibility_epoch, 0);
        assert_eq!(
            store.open_flowing_source(&opening).unwrap(),
            OpenFlowingSourceOutcome::Existing(first.clone())
        );
        for (branch_id, parent_branch_id) in [
            ("member-twig", "branch"),
            ("direct-twig", MAINLINE_BRANCH_ID),
        ] {
            store
                .create_branch(CreateBranch {
                    branch_id,
                    name: None,
                    parent_branch_id,
                    at_cut: None,
                    created_at: "t2",
                    idempotency_key: None,
                })
                .unwrap();
            assert!(matches!(
                store
                    .open_flowing_source(&OpenFlowingSource {
                        source_branch_id: branch_id.into(),
                        incarnation_id: format!("{branch_id}-inc"),
                        kind: FlowingSourceKind::Twig,
                        owner: "coordinator-a".into(),
                        opened_at: "t2".into(),
                    })
                    .unwrap(),
                OpenFlowingSourceOutcome::Opened(_)
            ));
        }
        assert_eq!(
            store
                .create_branch(CreateBranch {
                    branch_id: "nested-twig",
                    name: None,
                    parent_branch_id: "member-twig",
                    at_cut: None,
                    created_at: "t2",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::ParentFlowingTopology
        );
        assert!(store.get_branch("nested-twig").unwrap().is_none());

        let hold = request(&store, "hold-1", FlowingFenceAction::Hold);
        let FlowingFenceOutcome::Applied(held) = store.transition_flowing_source(&hold).unwrap()
        else {
            panic!("Hold must commit")
        };
        assert!(held.state.held);
        assert_eq!(held.state.eligibility_epoch, 1);
        let host = crate::branches::flowing_fence_host::read_fence_evidence(&store, "hold-1")
            .unwrap()
            .unwrap();
        assert!(host.resulting_held);
        assert_eq!(host.resulting_eligibility_epoch, 1);
        assert_eq!(
            store.transition_flowing_source(&hold).unwrap(),
            FlowingFenceOutcome::Existing(held.clone())
        );
        let mut reused = hold.clone();
        reused.action = FlowingFenceAction::ReleaseHold;
        assert_eq!(
            store.transition_flowing_source(&reused).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::IdentityMismatch)
        );
        let stale = FlowingFenceTransition {
            op_id: "stale".into(),
            ..hold.clone()
        };
        assert_eq!(
            store.transition_flowing_source(&stale).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::StaleEligibilityEpoch { current: 1 })
        );
        let release = request(&store, "release-1", FlowingFenceAction::ReleaseHold);
        let FlowingFenceOutcome::Applied(released) =
            store.transition_flowing_source(&release).unwrap()
        else {
            panic!("release must commit")
        };
        assert!(!released.state.held);
        assert_eq!(released.state.eligibility_epoch, 2);

        let begin = request(
            &store,
            "begin-1",
            FlowingFenceAction::BeginRevision {
                before_cut_id: None,
                after_cut_id: "branch-cut-1".into(),
            },
        );
        let FlowingFenceOutcome::Applied(pending) =
            store.transition_flowing_source(&begin).unwrap()
        else {
            panic!("revision fence must commit before the head moves")
        };
        assert_eq!(
            pending.state.revision.as_ref().unwrap().begin_op_id,
            "begin-1"
        );
        let finish = request(
            &store,
            "finish-1",
            FlowingFenceAction::FinishRevision {
                begin_op_id: "begin-1".into(),
            },
        );
        assert_eq!(
            store.transition_flowing_source(&finish).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::HeadMismatch { current: None })
        );
        store
            .record_cut(CutRecord {
                cut_id: "branch-cut-1",
                change_id: "branch-cut-1",
                branch_id: "branch",
                manifest_hash: "manifest-1",
                parent_cut_id: None,
                origin: Some("revision"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t3",
            })
            .unwrap();
        assert!(matches!(
            store
                .advance_head("branch", None, "branch-cut-1", "manifest-1", "t3")
                .unwrap(),
            AdvanceOutcome::Advanced(_)
        ));
        let FlowingFenceOutcome::Applied(finished) =
            store.transition_flowing_source(&finish).unwrap()
        else {
            panic!("the exact moved head closes the pending revision")
        };
        assert!(finished.state.revision.is_none());
        assert_eq!(finished.state.eligibility_epoch, 4);

        let obsolete = request(&store, "obsolete", FlowingFenceAction::Hold);
        let invalidate = request(
            &store,
            "revoke-1",
            FlowingFenceAction::InvalidateEligibility {
                reason: "grant revoked".into(),
            },
        );
        let FlowingFenceOutcome::Applied(invalidated) =
            store.transition_flowing_source(&invalidate).unwrap()
        else {
            panic!("revocation must fence prior candidates")
        };
        assert_eq!(invalidated.state.eligibility_epoch, 5);
        assert_eq!(
            store.transition_flowing_source(&obsolete).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::StaleEligibilityEpoch { current: 5 })
        );

        let begin_aborted = request(
            &store,
            "begin-aborted",
            FlowingFenceAction::BeginRevision {
                before_cut_id: Some("branch-cut-1".into()),
                after_cut_id: "branch-cut-2".into(),
            },
        );
        assert!(matches!(
            store.transition_flowing_source(&begin_aborted).unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        let abort = request(
            &store,
            "abort-1",
            FlowingFenceAction::AbortRevision {
                begin_op_id: "begin-aborted".into(),
            },
        );
        let FlowingFenceOutcome::Applied(aborted) =
            store.transition_flowing_source(&abort).unwrap()
        else {
            panic!("unmoved head may abort the revision")
        };
        assert!(aborted.state.revision.is_none());
        assert_eq!(aborted.state.eligibility_epoch, 7);

        let takeover = request(
            &store,
            "takeover-1",
            FlowingFenceAction::Takeover {
                new_owner: "coordinator-b".into(),
            },
        );
        let FlowingFenceOutcome::Applied(taken) =
            store.transition_flowing_source(&takeover).unwrap()
        else {
            panic!("takeover must commit")
        };
        assert_eq!(taken.state.owner, "coordinator-b");
        assert_eq!(taken.state.owner_epoch, 1);
        assert_eq!(taken.state.eligibility_epoch, 8);
        assert_eq!(
            store.open_flowing_source(&opening).unwrap(),
            OpenFlowingSourceOutcome::Existing(first.clone())
        );
        let disable = request(&store, "close-1", FlowingFenceAction::DisableAdmission);
        let FlowingFenceOutcome::Applied(closed) =
            store.transition_flowing_source(&disable).unwrap()
        else {
            panic!("admission must disable at the ref authority")
        };
        assert!(!closed.state.admission_enabled);
        assert_eq!(
            store.open_flowing_source(&opening).unwrap(),
            OpenFlowingSourceOutcome::Existing(first)
        );
        let later = request(
            &store,
            "late-revision",
            FlowingFenceAction::BeginRevision {
                before_cut_id: Some("branch-cut-1".into()),
                after_cut_id: "branch-cut-2".into(),
            },
        );
        assert_eq!(
            store.transition_flowing_source(&later).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::AdmissionDisabled)
        );
        assert_eq!(store.flowing_fence_receipt("hold-1").unwrap(), Some(held));
        assert!(store.flowing_fence_receipt("stale").unwrap().is_none());
        for op_id in [
            "hold-1",
            "release-1",
            "begin-1",
            "finish-1",
            "revoke-1",
            "begin-aborted",
            "abort-1",
            "takeover-1",
            "close-1",
        ] {
            let evidence = crate::branches::flowing_fence_host::read_fence_evidence(&store, op_id)
                .unwrap()
                .unwrap();
            assert_eq!(evidence.operation_id, op_id);
            let bytes = serde_json::to_vec(&evidence).unwrap();
            assert_eq!(
                crate::branches::flowing_fence_host::FlowingHostFenceEvidenceV1::decode(&bytes)
                    .unwrap(),
                evidence
            );
        }
    }

    #[test]
    fn failed_operation_insert_rolls_back_the_fence_change() {
        let mut store = source();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator-a".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_fence_op BEFORE INSERT ON flowing_source_fence_ops \
                 BEGIN SELECT RAISE(ABORT, 'injected refusal'); END;",
            )
            .unwrap();
        let hold = request(&store, "hold-fails", FlowingFenceAction::Hold);
        assert!(store.transition_flowing_source(&hold).is_err());
        let state = store.flowing_source("branch").unwrap().unwrap();
        assert!(!state.held);
        assert_eq!(state.eligibility_epoch, 0);
        assert!(store.flowing_fence_receipt("hold-fails").unwrap().is_none());
        let close = request(&store, "close-fails", FlowingFenceAction::RequestClose);
        assert!(store.transition_flowing_source(&close).is_err());
        assert!(store.flowing_close_request("branch").unwrap().is_none());
        assert!(matches!(
            store
                .create_branch(CreateBranch {
                    branch_id: "member-after-failed-close",
                    name: None,
                    parent_branch_id: "branch",
                    at_cut: None,
                    created_at: "t4",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::Created(_)
        ));
    }

    #[test]
    fn invalid_request_and_inactive_branch_cannot_change_fence_state() {
        let mut store = source();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator-a".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        let mut invalid = request(&store, "bad-actor", FlowingFenceAction::Hold);
        invalid.actor.clear();
        assert_eq!(
            store.transition_flowing_source(&invalid).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::Invalid { field: "actor" })
        );
        let mut no_state = request(&store, "no-state", FlowingFenceAction::Hold);
        no_state.source_branch_id = "never-opened".into();
        assert_eq!(
            store.transition_flowing_source(&no_state).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::Missing)
        );
        // Simulate an older writer bypassing the new terminal guard.
        store
            .connection
            .execute(
                "UPDATE branches SET status = 'discarded' WHERE branch_id = 'branch'",
                [],
            )
            .unwrap();
        let hold = request(&store, "closed-branch", FlowingFenceAction::Hold);
        assert_eq!(
            store.transition_flowing_source(&hold).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::BranchNotActive)
        );
        assert_eq!(
            store
                .flowing_source("branch")
                .unwrap()
                .unwrap()
                .eligibility_epoch,
            0
        );
        store
            .connection
            .execute("DELETE FROM branches WHERE branch_id = 'branch'", [])
            .unwrap();
        assert_eq!(
            store.transition_flowing_source(&hold).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::Missing)
        );
    }

    #[test]
    fn inactive_parent_cannot_open_a_member_twig() {
        let mut store = source();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "branch-inc".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "twig",
                name: None,
                parent_branch_id: "branch",
                at_cut: None,
                created_at: "t3",
                idempotency_key: None,
            })
            .unwrap();
        // Simulate an older writer bypassing the new terminal guard.
        store
            .connection
            .execute(
                "UPDATE branches SET status = 'discarded' WHERE branch_id = 'branch'",
                [],
            )
            .unwrap();
        assert_eq!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig".into(),
                    incarnation_id: "twig-inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator".into(),
                    opened_at: "t4".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::InvalidKindParent
        );
        assert!(store.flowing_source("twig").unwrap().is_none());
    }

    #[test]
    fn opening_cannot_reinterpret_existing_writes_or_member_twigs() {
        let opening = OpenFlowingSource {
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            kind: FlowingSourceKind::Branch,
            owner: "coordinator-a".into(),
            opened_at: "t2".into(),
        };
        let mut written = source();
        written
            .advance_head("branch", None, "old-cut", "old-manifest", "t2")
            .unwrap();
        assert_eq!(
            written.open_flowing_source(&opening).unwrap(),
            OpenFlowingSourceOutcome::BranchAlreadyMoved
        );

        let mut parent = source();
        parent
            .create_branch(CreateBranch {
                branch_id: "member-twig",
                name: None,
                parent_branch_id: "branch",
                at_cut: None,
                created_at: "t2",
                idempotency_key: None,
            })
            .unwrap();
        assert_eq!(
            parent.open_flowing_source(&opening).unwrap(),
            OpenFlowingSourceOutcome::BranchAlreadyHasChildren
        );
        assert_eq!(
            parent
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "member-twig".into(),
                    incarnation_id: "twig-inc".into(),
                    kind: FlowingSourceKind::Branch,
                    owner: "coordinator-a".into(),
                    opened_at: "t3".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::InvalidKindName
        );
        assert_eq!(
            parent
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "member-twig".into(),
                    incarnation_id: "twig-inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator-a".into(),
                    opened_at: "t3".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::InvalidKindParent
        );
    }
}
