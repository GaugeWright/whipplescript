use super::flowing_sources::exact_atomic;
use super::DoBranches;
use crate::do_store::{as_text, opt_text, sql_err, text, DoSql};
use whipplescript_store::branches::flowing_fence::{
    decide, initial_state, member_point_is_ancestor, missing_member_field, missing_open_field,
    missing_transition_field, validate_member_opening_receipt, validate_source_opening_receipt,
    FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceReceipt,
    FlowingFenceRefusal, FlowingFenceState, FlowingFenceTransition, FlowingMemberOpeningReceipt,
    FlowingMemberOpeningRequest, FlowingSourceKind, FlowingSourceOpeningReceipt,
    OpenFlowingMemberOutcome, OpenFlowingMemberRefusal, OpenFlowingSource,
    OpenFlowingSourceOutcome,
};
use whipplescript_store::branches::{BranchStatus, Branches, CreateBranch, MAINLINE_BRANCH_ID};
use whipplescript_store::StoreResult;

type FenceOutcome = FlowingFenceOutcome;

pub(super) fn read_state<S: DoSql>(
    sql: &S,
    source: &str,
) -> StoreResult<Option<FlowingFenceState>> {
    sql.query(
        "SELECT state_json FROM flowing_source_fences WHERE source_branch_id = ?1",
        &[text(source)],
    )
    .map_err(sql_err)?
    .first()
    .map(|row| serde_json::from_str(&as_text(&row[0])).map_err(Into::into))
    .transpose()
}

pub(super) fn close_pending<S: DoSql>(sql: &S, source: &str) -> StoreResult<bool> {
    Ok(read_close_request(sql, source)?.is_some())
}

fn read_receipt<S: DoSql>(sql: &S, op_id: &str) -> StoreResult<Option<FlowingFenceReceipt>> {
    sql.query(
        "SELECT request_json, state_json FROM flowing_source_fence_ops WHERE op_id = ?1",
        &[text(op_id)],
    )
    .map_err(sql_err)?
    .first()
    .map(|row| -> StoreResult<_> {
        Ok(FlowingFenceReceipt {
            request: serde_json::from_str(&as_text(&row[0]))?,
            state: serde_json::from_str(&as_text(&row[1]))?,
        })
    })
    .transpose()
}

fn read_member_opening<S: DoSql>(
    sql: &S,
    branch_id: &str,
) -> StoreResult<Option<FlowingMemberOpeningReceipt>> {
    let receipt: Option<FlowingMemberOpeningReceipt> = sql.query(
        "SELECT request_json, branch_json, state_json FROM flowing_member_openings WHERE branch_id = ?1",
        &[text(branch_id)],
    )
    .map_err(sql_err)?
    .first()
    .map(|row| -> StoreResult<_> {
        Ok(FlowingMemberOpeningReceipt {
            request: serde_json::from_str(&as_text(&row[0]))?,
            branch: serde_json::from_str(&as_text(&row[1]))?,
            source: serde_json::from_str(&as_text(&row[2]))?,
        })
    })
    .transpose()?;
    if let Some(receipt) = &receipt {
        validate_member_opening_receipt(branch_id, receipt)?;
    }
    Ok(receipt)
}

fn read_source_opening<S: DoSql>(
    sql: &S,
    source_branch_id: &str,
) -> StoreResult<Option<FlowingSourceOpeningReceipt>> {
    let receipt: Option<FlowingSourceOpeningReceipt> = sql.query(
        "SELECT request_json, state_json FROM flowing_source_openings WHERE source_branch_id = ?1",
        &[text(source_branch_id)],
    )
    .map_err(sql_err)?
    .first()
    .map(|row| -> StoreResult<_> {
        Ok(FlowingSourceOpeningReceipt {
            request: serde_json::from_str(&as_text(&row[0]))?,
            state: serde_json::from_str(&as_text(&row[1]))?,
        })
    })
    .transpose()?;
    if let Some(receipt) = &receipt {
        validate_source_opening_receipt(source_branch_id, receipt)?;
    }
    Ok(receipt)
}

pub(super) fn read_close_request<S: DoSql>(
    sql: &S,
    source: &str,
) -> StoreResult<Option<FlowingFenceReceipt>> {
    let rows = sql
        .query(
            "SELECT op_id, incarnation_id FROM flowing_source_close_requests \
             WHERE source_branch_id = ?1",
            &[text(source)],
        )
        .map_err(sql_err)?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let op_id = as_text(&row[0]);
    let incarnation_id = as_text(&row[1]);
    let receipt = read_receipt(sql, &op_id)?.ok_or_else(|| {
        whipplescript_store::StoreError::Conflict(
            "flowing close request lost its ref receipt".into(),
        )
    })?;
    if receipt.request.action != FlowingFenceAction::RequestClose
        || receipt.request.op_id != op_id
        || receipt.request.source_branch_id != source
        || receipt.request.incarnation_id != incarnation_id
        || receipt.state.source_branch_id != source
        || receipt.state.incarnation_id != incarnation_id
    {
        return Err(whipplescript_store::StoreError::Conflict(
            "flowing close request differs from its ref receipt".into(),
        ));
    }
    Ok(Some(receipt))
}

impl<S: DoSql> FlowingFence for DoBranches<S> {
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
        let opening_request = FlowingMemberOpeningRequest::new(&branch, source);
        exact_atomic(&self.sql, "flowing member open", || {
            if let Some(receipt) = read_member_opening(&self.sql, branch.branch_id)? {
                if receipt.request != opening_request {
                    // MUTATION-SUCCESS-EXPR: Ok(Outcome::Existing { branch: receipt.branch, source: receipt.source })
                    return Ok(Outcome::Refused(Refusal::IdentityMismatch));
                }
                let current_branch = self.row_by_id(branch.branch_id)?;
                let current_source = read_state(&self.sql, branch.branch_id)?;
                if current_branch.is_none()
                    || current_source
                        .as_ref()
                        .is_none_or(|state| state.incarnation_id != receipt.source.incarnation_id)
                {
                    return Err(whipplescript_store::StoreError::Conflict(
                        "flowing member opening lost current authority".into(),
                    ));
                }
                return Ok(Outcome::Existing {
                    branch: receipt.branch,
                    source: receipt.source,
                });
            }
            if let Some(_existing) = self.row_by_id(branch.branch_id)? {
                if read_state(&self.sql, branch.branch_id)?.is_none() {
                    // MUTATION-SUCCESS-EXPR: Ok(Outcome::Opened { branch: _existing, source: initial_state(source) })
                    return Ok(Outcome::Refused(Refusal::ExistingBranchWithoutSource));
                }
                // MUTATION-SUCCESS-EXPR: Ok(Outcome::Opened { branch: _existing, source: initial_state(source) })
                return Ok(Outcome::Refused(Refusal::IdentityMismatch));
            }
            if let Some(key) = branch.idempotency_key {
                let used = self
                    .sql
                    .query(
                        "SELECT branch_id FROM branches WHERE idempotency_key = ?1 LIMIT 1",
                        &[text(key)],
                    )
                    .map_err(sql_err)?;
                if !used.is_empty() {
                    return Ok(Outcome::Refused(Refusal::IdentityMismatch));
                }
            }
            let Some(parent) = self.row_by_id(branch.parent_branch_id)? else {
                // MUTATION-SUCCESS-EXPR: Ok(Outcome::Opened { branch: self.row_by_id(MAINLINE_BRANCH_ID)?.expect("mainline"), source: initial_state(source) })
                return Ok(Outcome::Refused(Refusal::ParentMissing));
            };
            if parent.status != BranchStatus::Active {
                return Ok(Outcome::Refused(Refusal::ParentNotActive));
            }
            let Some(parent_source) = read_state(&self.sql, branch.parent_branch_id)? else {
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
                    |id| self.get_cut(id),
                )? {
                    return Ok(Outcome::Refused(Refusal::Invalid { field: "at_cut" }));
                }
            }
            let (point_cut, point_manifest) = match branch.at_cut {
                Some((cut, manifest)) => (Some(cut.to_owned()), Some(manifest.to_owned())),
                None => (parent.head_cut_id, parent.head_manifest_hash),
            };
            self.sql
                .execute(
                    "INSERT INTO branches \
                     (branch_id, name, parent_branch_id, branch_point_cut_id, \
                      branch_point_manifest_hash, head_cut_id, head_manifest_hash, \
                      status, created_at, updated_at, idempotency_key) \
                     VALUES (?1, NULL, ?2, ?3, ?4, ?3, ?4, 'active', ?5, ?5, ?6)",
                    &[
                        text(branch.branch_id),
                        text(branch.parent_branch_id),
                        opt_text(point_cut.as_deref()),
                        opt_text(point_manifest.as_deref()),
                        text(branch.created_at),
                        opt_text(branch.idempotency_key),
                    ],
                )
                .map_err(sql_err)?;
            let state = initial_state(source);
            self.sql
                .execute(
                    "INSERT INTO flowing_source_fences (source_branch_id, state_json) VALUES (?1, ?2)",
                    &[
                        text(branch.branch_id),
                        text(&serde_json::to_string(&state)?),
                    ],
                )
                .map_err(sql_err)?;
            self.sql.execute(
                "INSERT INTO flowing_source_openings (source_branch_id, request_json, state_json) VALUES (?1, ?2, ?3)",
                &[text(branch.branch_id), text(&serde_json::to_string(source)?), text(&serde_json::to_string(&state)?)],
            ).map_err(sql_err)?;
            let created = self
                .row_by_id(branch.branch_id)?
                .expect("created member row exists in transaction");
            self.sql.execute(
                "INSERT INTO flowing_member_openings (branch_id, request_json, branch_json, state_json) VALUES (?1, ?2, ?3, ?4)",
                &[text(branch.branch_id), text(&serde_json::to_string(&opening_request)?), text(&serde_json::to_string(&created)?), text(&serde_json::to_string(&state)?)],
            ).map_err(sql_err)?;
            Ok(Outcome::Opened {
                branch: created,
                source: state,
            })
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
        exact_atomic(&self.sql, "flowing source open", || {
            if let Some(receipt) = read_source_opening(&self.sql, &request.source_branch_id)? {
                if receipt.request != *request {
                    // MUTATION-SUCCESS-EXPR: Ok(OpenFlowingSourceOutcome::Existing(receipt.state))
                    return Ok(OpenFlowingSourceOutcome::IdentityMismatch);
                }
                let current = read_state(&self.sql, &request.source_branch_id)?;
                if self.row_by_id(&request.source_branch_id)?.is_none()
                    || current
                        .as_ref()
                        .is_none_or(|state| state.incarnation_id != receipt.state.incarnation_id)
                {
                    return Err(whipplescript_store::StoreError::Conflict(
                        "flowing source opening lost current authority".into(),
                    ));
                }
                return Ok(OpenFlowingSourceOutcome::Existing(receipt.state));
            }
            if let Some(existing) = read_state(&self.sql, &request.source_branch_id)? {
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
            let Some(branch) = self.row_by_id(&request.source_branch_id)? else {
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
                        if self
                            .row_by_id(id)?
                            .is_some_and(|row| row.status == BranchStatus::Active) =>
                    {
                        read_state(&self.sql, id)?
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
            let children = self
                .sql
                .query(
                    "SELECT 1 FROM branches WHERE parent_branch_id = ?1 LIMIT 1",
                    &[text(&request.source_branch_id)],
                )
                .map_err(sql_err)?;
            if !children.is_empty() {
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
            self.sql
                .execute(
                    "INSERT INTO flowing_source_fences (source_branch_id, state_json) \
                     VALUES (?1, ?2)",
                    &[
                        text(&request.source_branch_id),
                        text(&serde_json::to_string(&state)?),
                    ],
                )
                .map_err(sql_err)?;
            self.sql.execute(
                "INSERT INTO flowing_source_openings (source_branch_id, request_json, state_json) VALUES (?1, ?2, ?3)",
                &[text(&request.source_branch_id), text(&serde_json::to_string(request)?), text(&serde_json::to_string(&state)?)],
            ).map_err(sql_err)?;
            Ok(OpenFlowingSourceOutcome::Opened(state))
        })
    }

    fn flowing_source(&self, source_branch_id: &str) -> StoreResult<Option<FlowingFenceState>> {
        read_state(&self.sql, source_branch_id)
    }

    fn flowing_source_opening(
        &self,
        source_branch_id: &str,
    ) -> StoreResult<Option<FlowingSourceOpeningReceipt>> {
        read_source_opening(&self.sql, source_branch_id)
    }

    fn flowing_member_opening(
        &self,
        branch_id: &str,
    ) -> StoreResult<Option<FlowingMemberOpeningReceipt>> {
        read_member_opening(&self.sql, branch_id)
    }

    fn flowing_close_request(
        &self,
        source_branch_id: &str,
    ) -> StoreResult<Option<FlowingFenceReceipt>> {
        read_close_request(&self.sql, source_branch_id)
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
        exact_atomic(&self.sql, "flowing source transition", || {
            if let Some(existing) = read_receipt(&self.sql, &request.op_id)? {
                if existing.request == *request {
                    return Ok(FlowingFenceOutcome::Existing(existing));
                }
                // MUTATION-SUCCESS-EXPR: Ok(FlowingFenceOutcome::Existing(existing))
                return Ok(FenceOutcome::Refused(FlowingFenceRefusal::IdentityMismatch));
            }
            let Some(state) = read_state(&self.sql, &request.source_branch_id)? else {
                // MUTATION-SUCCESS-EXPR: Ok(FlowingFenceOutcome::Applied(FlowingFenceReceipt { request: request.clone(), state: FlowingFenceState { source_branch_id: String::new(), incarnation_id: String::new(), kind: FlowingSourceKind::Twig, owner: String::new(), owner_epoch: 0, eligibility_epoch: 0, held: false, revision: None, admission_enabled: false, opened_at: String::new() } }))
                return Ok(FlowingFenceOutcome::Refused(FlowingFenceRefusal::Missing));
            };
            let Some(branch) = self.row_by_id(&request.source_branch_id)? else {
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
                if close_pending(&self.sql, &request.source_branch_id)? {
                    return Ok(FenceOutcome::Refused(
                        FlowingFenceRefusal::CloseAlreadyPending,
                    ));
                }
                self.sql.execute(
                    "INSERT INTO flowing_source_close_requests \
                     (source_branch_id, op_id, incarnation_id, recorded_at) VALUES (?1, ?2, ?3, ?4)",
                    &[
                        text(&request.source_branch_id),
                        text(&request.op_id),
                        text(&request.incarnation_id),
                        text(&request.recorded_at),
                    ],
                ).map_err(sql_err)?;
            }
            let state_json = serde_json::to_string(&after)?;
            self.sql
                .execute(
                    "UPDATE flowing_source_fences SET state_json = ?2 \
                     WHERE source_branch_id = ?1",
                    &[text(&request.source_branch_id), text(&state_json)],
                )
                .map_err(sql_err)?;
            self.sql
                .execute(
                    "INSERT INTO flowing_source_fence_ops (op_id, request_json, state_json) \
                     VALUES (?1, ?2, ?3)",
                    &[
                        text(&request.op_id),
                        text(&serde_json::to_string(request)?),
                        text(&state_json),
                    ],
                )
                .map_err(sql_err)?;
            Ok(FlowingFenceOutcome::Applied(FlowingFenceReceipt {
                request: request.clone(),
                state: after,
            }))
        })
    }

    fn flowing_fence_receipt(&self, op_id: &str) -> StoreResult<Option<FlowingFenceReceipt>> {
        read_receipt(&self.sql, op_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::do_store::test_support::RusqliteDoSql;
    use std::rc::Rc;
    use whipplescript_store::branches::flowing_close_roster::FlowingCloseRosterReader;
    use whipplescript_store::branches::flowing_fence::FlowingFenceAction;
    use whipplescript_store::branches::flowing_open_host::{
        read_member_opening_evidence, read_source_opening_evidence,
        FlowingHostMemberOpeningEvidenceV1, FlowingHostSourceOpeningEvidenceV1,
    };
    use whipplescript_store::branches::{
        AdvanceOutcome, BranchStore, Branches, CreateBranch, CreateBranchOutcome, CutRecord,
        OpBranchState, RetargetOutcome,
    };
    use whipplescript_store::StoreError;

    fn exercise_atomic_member<B: Branches + FlowingFence>(mut store: B) {
        store.ensure_mainline("t0").unwrap();
        store
            .record_cut(CutRecord {
                cut_id: "parent-pin",
                change_id: "parent-pin",
                branch_id: MAINLINE_BRANCH_ID,
                manifest_hash: "manifest-pin",
                parent_cut_id: None,
                origin: Some("fixture"),
                actor: Some("coordinator"),
                intent: None,
                recorded_at: "t0",
            })
            .unwrap();
        assert!(matches!(
            store
                .advance_head(MAINLINE_BRANCH_ID, None, "parent-pin", "manifest-pin", "t0")
                .unwrap(),
            AdvanceOutcome::Advanced(_)
        ));
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
        assert!(matches!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "branch".into(),
                    incarnation_id: "branch-inc".into(),
                    kind: FlowingSourceKind::Branch,
                    owner: "coordinator".into(),
                    opened_at: "t1".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        store
            .record_cut(CutRecord {
                cut_id: "foreign-pin",
                change_id: "foreign-pin",
                branch_id: MAINLINE_BRANCH_ID,
                manifest_hash: "foreign-manifest",
                parent_cut_id: None,
                origin: Some("fixture"),
                actor: Some("coordinator"),
                intent: None,
                recorded_at: "t2",
            })
            .unwrap();
        assert_eq!(
            store
                .open_flowing_member(
                    CreateBranch {
                        branch_id: "foreign",
                        name: None,
                        parent_branch_id: "branch",
                        at_cut: Some(("foreign-pin", "foreign-manifest")),
                        created_at: "t2",
                        idempotency_key: None,
                    },
                    &OpenFlowingSource {
                        source_branch_id: "foreign".into(),
                        incarnation_id: "foreign-inc".into(),
                        kind: FlowingSourceKind::Twig,
                        owner: "coordinator".into(),
                        opened_at: "t2".into(),
                    },
                )
                .unwrap(),
            OpenFlowingMemberOutcome::Refused(OpenFlowingMemberRefusal::Invalid {
                field: "at_cut"
            })
        );
        assert!(store.get_branch("foreign").unwrap().is_none());
        let member = CreateBranch {
            branch_id: "member",
            name: None,
            parent_branch_id: "branch",
            at_cut: Some(("parent-pin", "manifest-pin")),
            created_at: "t2",
            idempotency_key: Some("member-key"),
        };
        let opening = OpenFlowingSource {
            source_branch_id: "member".into(),
            incarnation_id: "member-inc".into(),
            kind: FlowingSourceKind::Twig,
            owner: "coordinator".into(),
            opened_at: "t2".into(),
        };
        let OpenFlowingMemberOutcome::Opened { branch, source } =
            store.open_flowing_member(member.clone(), &opening).unwrap()
        else {
            panic!("member must open atomically");
        };
        assert_eq!(store.get_branch("member").unwrap(), Some(branch.clone()));
        assert_eq!(branch.branch_point_cut_id.as_deref(), Some("parent-pin"));
        assert_eq!(
            store.flowing_source("member").unwrap(),
            Some(source.clone())
        );
        assert_eq!(
            store.open_flowing_member(member.clone(), &opening).unwrap(),
            OpenFlowingMemberOutcome::Existing {
                branch: branch.clone(),
                source: source.clone()
            }
        );
        assert_eq!(
            store.open_flowing_source(&opening).unwrap(),
            OpenFlowingSourceOutcome::Existing(source.clone())
        );
        assert_eq!(
            store
                .open_flowing_member(
                    member.clone(),
                    &OpenFlowingSource {
                        owner: "different".into(),
                        ..opening.clone()
                    },
                )
                .unwrap(),
            OpenFlowingMemberOutcome::Refused(OpenFlowingMemberRefusal::IdentityMismatch)
        );
        assert!(matches!(
            store
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "takeover-member".into(),
                    source_branch_id: "member".into(),
                    incarnation_id: "member-inc".into(),
                    expected_eligibility_epoch: source.eligibility_epoch,
                    expected_owner_epoch: source.owner_epoch,
                    actor: "coordinator".into(),
                    action: FlowingFenceAction::Takeover {
                        new_owner: "successor".into()
                    },
                    recorded_at: "t3".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        assert_eq!(
            store.flowing_source("member").unwrap().unwrap().owner,
            "successor"
        );
        assert_eq!(
            store.open_flowing_source(&opening).unwrap(),
            OpenFlowingSourceOutcome::Existing(source.clone())
        );
        assert_eq!(
            store.open_flowing_member(member.clone(), &opening).unwrap(),
            OpenFlowingMemberOutcome::Existing {
                branch: branch.clone(),
                source: source.clone()
            }
        );
        let parent = store.flowing_source("branch").unwrap().unwrap();
        assert!(matches!(
            store
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "close".into(),
                    source_branch_id: "branch".into(),
                    incarnation_id: "branch-inc".into(),
                    expected_eligibility_epoch: parent.eligibility_epoch,
                    expected_owner_epoch: parent.owner_epoch,
                    actor: "coordinator".into(),
                    action: FlowingFenceAction::DisableAdmission,
                    recorded_at: "t3".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        assert_eq!(
            store
                .open_flowing_member(
                    CreateBranch {
                        branch_id: "late",
                        idempotency_key: Some("late-key"),
                        ..member.clone()
                    },
                    &OpenFlowingSource {
                        source_branch_id: "late".into(),
                        incarnation_id: "late-inc".into(),
                        ..opening.clone()
                    },
                )
                .unwrap(),
            OpenFlowingMemberOutcome::Refused(OpenFlowingMemberRefusal::ParentAdmissionDisabled)
        );
        assert!(store.get_branch("late").unwrap().is_none());
        assert!(store.flowing_source("late").unwrap().is_none());
        let retained_member = store.flowing_member_opening("member").unwrap().unwrap();
        assert_eq!(
            retained_member.request,
            FlowingMemberOpeningRequest::new(&member, &opening)
        );
        assert_eq!(retained_member.branch, branch);
        assert_eq!(retained_member.source, source);
        let retained_source = store.flowing_source_opening("member").unwrap().unwrap();
        assert_eq!(retained_source.request, opening);
        assert_eq!(retained_source.state, source);
        let source_evidence = read_source_opening_evidence(&store, "member")
            .unwrap()
            .unwrap();
        let source_wire = serde_json::to_vec(&source_evidence).unwrap();
        assert_eq!(
            FlowingHostSourceOpeningEvidenceV1::decode(&source_wire).unwrap(),
            source_evidence
        );
        let member_evidence = read_member_opening_evidence(&store, "member")
            .unwrap()
            .unwrap();
        let member_wire = serde_json::to_vec(&member_evidence).unwrap();
        assert_eq!(
            FlowingHostMemberOpeningEvidenceV1::decode(&member_wire).unwrap(),
            member_evidence
        );
        assert_eq!(member_evidence.parent_branch_id, "branch");
        assert_eq!(
            member_evidence.branch_point_cut_id.as_deref(),
            Some("parent-pin")
        );
        assert!(!String::from_utf8(member_wire)
            .unwrap()
            .contains("member-key"));
        assert_eq!(
            store.open_flowing_member(member, &opening).unwrap(),
            OpenFlowingMemberOutcome::Existing { branch, source }
        );
    }

    #[test]
    fn atomic_flowing_member_open_has_native_hosted_parity() {
        exercise_atomic_member(BranchStore::open(":memory:").unwrap());
        exercise_atomic_member(DoBranches::new(RusqliteDoSql::with_runtime_schema()).unwrap());
    }

    fn exercise_source_opening_retry<B: Branches + FlowingFence>(mut store: B) {
        store.ensure_mainline("t0").unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "branch",
                name: Some("feature"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        let opening = OpenFlowingSource {
            source_branch_id: "branch".into(),
            incarnation_id: "inc".into(),
            kind: FlowingSourceKind::Branch,
            owner: "coordinator".into(),
            opened_at: "t2".into(),
        };
        let OpenFlowingSourceOutcome::Opened(original) =
            store.open_flowing_source(&opening).unwrap()
        else {
            panic!("new source must open");
        };
        store
            .create_branch(CreateBranch {
                branch_id: "direct-twig",
                name: None,
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t2",
                idempotency_key: None,
            })
            .unwrap();
        assert!(matches!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "direct-twig".into(),
                    incarnation_id: "direct-inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator".into(),
                    opened_at: "t2".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        assert!(read_source_opening_evidence(&store, "direct-twig")
            .unwrap()
            .is_some());
        assert!(read_member_opening_evidence(&store, "direct-twig")
            .unwrap()
            .is_none());
        assert!(matches!(
            store
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "takeover".into(),
                    source_branch_id: "branch".into(),
                    incarnation_id: "inc".into(),
                    expected_eligibility_epoch: 0,
                    expected_owner_epoch: 0,
                    actor: "coordinator".into(),
                    action: FlowingFenceAction::Takeover {
                        new_owner: "successor".into()
                    },
                    recorded_at: "t3".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        assert_eq!(
            store.flowing_source("branch").unwrap().unwrap().owner,
            "successor"
        );
        assert_eq!(
            store.open_flowing_source(&opening).unwrap(),
            OpenFlowingSourceOutcome::Existing(original.clone())
        );
        let retained = store.flowing_source_opening("branch").unwrap().unwrap();
        assert_eq!(retained.request, opening);
        assert_eq!(retained.state, original);
        let evidence = read_source_opening_evidence(&store, "branch")
            .unwrap()
            .unwrap();
        assert_eq!(
            FlowingHostSourceOpeningEvidenceV1::decode(&serde_json::to_vec(&evidence).unwrap())
                .unwrap(),
            evidence
        );
        assert!(store.flowing_member_opening("branch").unwrap().is_none());
        assert_eq!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    owner: "successor".into(),
                    ..opening
                })
                .unwrap(),
            OpenFlowingSourceOutcome::IdentityMismatch
        );
    }

    #[test]
    fn source_opening_retry_after_takeover_has_native_hosted_parity() {
        exercise_source_opening_retry(BranchStore::open(":memory:").unwrap());
        exercise_source_opening_retry(
            DoBranches::new(RusqliteDoSql::with_runtime_schema()).unwrap(),
        );
    }

    #[test]
    fn hosted_member_open_replay_requires_current_source_authority() {
        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut store = DoBranches::new(Rc::clone(&sql)).unwrap();
        store.ensure_mainline("t0").unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "branch",
                name: Some("feature"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "branch-inc".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator".into(),
                opened_at: "t1".into(),
            })
            .unwrap();
        let member = member_request("member", "branch", None);
        let opening = member_opening("member");
        assert!(matches!(
            store.open_flowing_member(member.clone(), &opening).unwrap(),
            OpenFlowingMemberOutcome::Opened { .. }
        ));

        // Simulate damaged authority while retaining the immutable opening receipt.
        sql.execute(
            "DELETE FROM flowing_source_fences WHERE source_branch_id = 'member'",
            &[],
        )
        .unwrap();
        assert!(matches!(
            store.open_flowing_member(member, &opening),
            Err(StoreError::Conflict(message))
                if message == "flowing member opening lost current authority"
        ));
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
            owner: "coordinator".into(),
            opened_at: "t3".into(),
        }
    }

    fn exercise_atomic_member_refusals<B: Branches + FlowingFence>(mut store: B) {
        use OpenFlowingMemberOutcome::Refused;
        use OpenFlowingMemberRefusal as Why;

        store.ensure_mainline("t0").unwrap();
        assert_eq!(
            store
                .open_flowing_member(
                    member_request("missing-child", "missing", None),
                    &member_opening("missing-child")
                )
                .unwrap(),
            Refused(Why::ParentMissing)
        );
        for name in ["legacy", "inactive"] {
            store
                .create_branch(CreateBranch {
                    branch_id: name,
                    name: Some(name),
                    parent_branch_id: MAINLINE_BRANCH_ID,
                    at_cut: None,
                    created_at: "t1",
                    idempotency_key: None,
                })
                .unwrap();
        }
        assert_eq!(
            store
                .open_flowing_member(
                    member_request("legacy-child", "legacy", None),
                    &member_opening("legacy-child")
                )
                .unwrap(),
            Refused(Why::ParentNotFlowing)
        );
        store.discard_branch("inactive", "t2").unwrap();
        assert_eq!(
            store
                .open_flowing_member(
                    member_request("inactive-child", "inactive", None),
                    &member_opening("inactive-child")
                )
                .unwrap(),
            Refused(Why::ParentNotActive)
        );
        store
            .create_branch(CreateBranch {
                branch_id: "twig-parent",
                name: None,
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "twig-parent".into(),
                incarnation_id: "twig-parent-inc".into(),
                kind: FlowingSourceKind::Twig,
                owner: "coordinator".into(),
                opened_at: "t2".into(),
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
                source_branch_id: "legacy".into(),
                incarnation_id: "legacy-inc".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        assert_eq!(
            store
                .open_flowing_member(
                    CreateBranch {
                        at_cut: Some(("missing-cut", "missing-manifest")),
                        ..member_request("bad-cut", "legacy", None)
                    },
                    &member_opening("bad-cut"),
                )
                .unwrap(),
            Refused(Why::Invalid { field: "at_cut" })
        );
        assert_eq!(
            store
                .open_flowing_member(
                    CreateBranch {
                        name: Some("named"),
                        ..member_request("invalid", "legacy", None)
                    },
                    &member_opening("invalid"),
                )
                .unwrap(),
            Refused(Why::Invalid { field: "name" })
        );
        store
            .create_branch(member_request("preexisting", "legacy", None))
            .unwrap();
        assert_eq!(
            store
                .open_flowing_member(
                    member_request("preexisting", "legacy", None),
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
                    member_request("preexisting", "legacy", None),
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
                    member_request("new", "legacy", Some("collision")),
                    &member_opening("new")
                )
                .unwrap(),
            Refused(Why::IdentityMismatch)
        );
        let parent = store.flowing_source("legacy").unwrap().unwrap();
        store
            .transition_flowing_source(&FlowingFenceTransition {
                op_id: "disable".into(),
                source_branch_id: "legacy".into(),
                incarnation_id: "legacy-inc".into(),
                expected_eligibility_epoch: parent.eligibility_epoch,
                expected_owner_epoch: parent.owner_epoch,
                actor: "coordinator".into(),
                action: FlowingFenceAction::DisableAdmission,
                recorded_at: "t4".into(),
            })
            .unwrap();
        assert_eq!(
            store
                .open_flowing_member(
                    member_request("late", "legacy", None),
                    &member_opening("late")
                )
                .unwrap(),
            Refused(Why::ParentAdmissionDisabled)
        );
        assert!(store.get_branch("late").unwrap().is_none());
    }

    #[test]
    fn atomic_flowing_member_refusals_have_native_hosted_parity() {
        exercise_atomic_member_refusals(BranchStore::open(":memory:").unwrap());
        exercise_atomic_member_refusals(
            DoBranches::new(RusqliteDoSql::with_runtime_schema()).unwrap(),
        );
    }

    fn exercise<B: Branches + FlowingFence>(mut store: B) -> Vec<FlowingFenceOutcome> {
        store.ensure_mainline("t0").unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "branch",
                name: Some("feature"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        let opening = OpenFlowingSource {
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            kind: FlowingSourceKind::Branch,
            owner: "coordinator-a".into(),
            opened_at: "t2".into(),
        };
        assert!(matches!(
            store.open_flowing_source(&opening).unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        store
            .create_branch(CreateBranch {
                branch_id: "twig",
                name: None,
                parent_branch_id: "branch",
                at_cut: None,
                created_at: "t2",
                idempotency_key: None,
            })
            .unwrap();
        assert!(matches!(
            store.advance_head("twig", None, "unopened", "manifest", "t2"),
            Err(StoreError::Conflict(message))
                if message == "flowing member has no source fence"
        ));
        assert!(matches!(
            store.commit_write_with_evidence(
                CutRecord {
                    cut_id: "unopened",
                    change_id: "unopened",
                    branch_id: "twig",
                    manifest_hash: "manifest",
                    parent_cut_id: None,
                    origin: None,
                    actor: None,
                    intent: None,
                    recorded_at: "t2",
                },
                None,
            ),
            Err(StoreError::Conflict(message))
                if message == "flowing member has no source fence"
        ));
        assert!(store.get_cut("unopened").unwrap().is_none());
        assert!(matches!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig".into(),
                    incarnation_id: "twig-inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator-a".into(),
                    opened_at: "t2".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        let member = store.flowing_source("twig").unwrap().unwrap();
        let member_close = FlowingFenceTransition {
            op_id: "member-close".into(),
            source_branch_id: "twig".into(),
            incarnation_id: "twig-inc".into(),
            expected_eligibility_epoch: member.eligibility_epoch,
            expected_owner_epoch: member.owner_epoch,
            actor: "coordinator-a".into(),
            action: FlowingFenceAction::RequestClose,
            recorded_at: "t2".into(),
        };
        assert_eq!(
            store.transition_flowing_source(&member_close).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::NotDirectSource)
        );
        assert!(store.flowing_close_request("twig").unwrap().is_none());
        assert_eq!(
            store
                .create_branch(CreateBranch {
                    branch_id: "named-member",
                    name: Some("nested"),
                    parent_branch_id: "branch",
                    at_cut: None,
                    created_at: "t2",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::ParentFlowingTopology
        );
        assert_eq!(
            store
                .create_branch(CreateBranch {
                    branch_id: "nested-member",
                    name: None,
                    parent_branch_id: "twig",
                    at_cut: None,
                    created_at: "t2",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::ParentFlowingTopology
        );
        let mut outcomes = Vec::new();
        for (op_id, action) in [
            ("hold", FlowingFenceAction::Hold),
            ("release", FlowingFenceAction::ReleaseHold),
            (
                "begin",
                FlowingFenceAction::BeginRevision {
                    before_cut_id: None,
                    after_cut_id: "c1".into(),
                },
            ),
        ] {
            let state = store.flowing_source("branch").unwrap().unwrap();
            let request = FlowingFenceTransition {
                op_id: op_id.into(),
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                expected_eligibility_epoch: state.eligibility_epoch,
                expected_owner_epoch: state.owner_epoch,
                actor: "mediator".into(),
                action,
                recorded_at: op_id.into(),
            };
            let applied = store.transition_flowing_source(&request).unwrap();
            assert!(matches!(applied, FlowingFenceOutcome::Applied(_)));
            let host = whipplescript_store::branches::flowing_fence_host::read_fence_evidence(
                &store, op_id,
            )
            .unwrap()
            .unwrap();
            assert_eq!(host.operation_id, op_id);
            assert_eq!(
                host.resulting_held,
                store.flowing_source("branch").unwrap().unwrap().held
            );
            assert!(matches!(
                store.transition_flowing_source(&request).unwrap(),
                FlowingFenceOutcome::Existing(_)
            ));
            let mut reused = request.clone();
            reused.action = FlowingFenceAction::DisableAdmission;
            assert_eq!(
                store.transition_flowing_source(&reused).unwrap(),
                FlowingFenceOutcome::Refused(FlowingFenceRefusal::IdentityMismatch)
            );
            outcomes.push(applied);
        }
        let state = store.flowing_source("branch").unwrap().unwrap();
        let finish = FlowingFenceTransition {
            op_id: "finish".into(),
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            expected_eligibility_epoch: state.eligibility_epoch,
            expected_owner_epoch: state.owner_epoch,
            actor: "mediator".into(),
            action: FlowingFenceAction::FinishRevision {
                begin_op_id: "begin".into(),
            },
            recorded_at: "finish".into(),
        };
        outcomes.push(store.transition_flowing_source(&finish).unwrap());
        store
            .record_cut(CutRecord {
                cut_id: "c1",
                change_id: "c1",
                branch_id: "branch",
                manifest_hash: "manifest-1",
                parent_cut_id: None,
                origin: Some("revision"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t3",
            })
            .unwrap();
        store
            .advance_head("branch", None, "c1", "manifest-1", "t3")
            .unwrap();
        outcomes.push(store.transition_flowing_source(&finish).unwrap());
        let state = store.flowing_source("branch").unwrap().unwrap();
        assert!(state.revision.is_none());
        assert_eq!(state.eligibility_epoch, 4);
        assert!(matches!(
            store
                .create_branch(CreateBranch {
                    branch_id: "outsider",
                    name: None,
                    parent_branch_id: MAINLINE_BRANCH_ID,
                    at_cut: None,
                    created_at: "t4",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::Created(_)
        ));
        assert_eq!(
            store.retarget_branch("outsider", "branch", "t4").unwrap(),
            RetargetOutcome::ParentFlowingSource
        );
        assert_eq!(
            store.retarget_branch("outsider", "twig", "t4").unwrap(),
            RetargetOutcome::ParentFlowingSource
        );
        let disable = FlowingFenceTransition {
            op_id: "disable".into(),
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            expected_eligibility_epoch: state.eligibility_epoch,
            expected_owner_epoch: state.owner_epoch,
            actor: "mediator".into(),
            action: FlowingFenceAction::DisableAdmission,
            recorded_at: "t5".into(),
        };
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
                    created_at: "t6",
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
                    parent_branch_id: "twig",
                    at_cut: None,
                    created_at: "t6",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::ParentAdmissionDisabled
        );
        assert!(matches!(
            store
                .create_branch(CreateBranch {
                    branch_id: "twig",
                    name: None,
                    parent_branch_id: "branch",
                    at_cut: None,
                    created_at: "t2",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::Existing(_)
        ));
        assert_eq!(
            store.retarget_branch("outsider", "branch", "t6").unwrap(),
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
        outcomes
    }

    #[test]
    fn hosted_fence_matches_native_for_hold_revision_and_exact_retries() {
        let native = exercise(BranchStore::open(":memory:").unwrap());
        let hosted =
            exercise(DoBranches::new(Rc::new(RusqliteDoSql::with_runtime_schema())).unwrap());
        assert_eq!(hosted, native);
        assert_eq!(
            hosted[3],
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::HeadMismatch { current: None })
        );
    }

    #[test]
    fn hosted_close_request_keeps_existing_member_and_fences_late_members() {
        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut store = DoBranches::new(Rc::clone(&sql)).unwrap();
        store.ensure_mainline("t0").unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "branch",
                name: Some("feature"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
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
                branch_id: "early-member",
                name: None,
                parent_branch_id: "branch",
                at_cut: None,
                created_at: "t3",
                idempotency_key: Some("early-member-op"),
            })
            .unwrap();
        let before = store.flowing_source("branch").unwrap().unwrap();
        let close = FlowingFenceTransition {
            op_id: "close".into(),
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            expected_eligibility_epoch: before.eligibility_epoch,
            expected_owner_epoch: before.owner_epoch,
            actor: "mediator".into(),
            action: FlowingFenceAction::RequestClose,
            recorded_at: "t4".into(),
        };
        assert!(matches!(
            store.transition_flowing_source(&close).unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        assert_eq!(
            store.transition_flowing_source(&close).unwrap(),
            FlowingFenceOutcome::Existing(store.flowing_close_request("branch").unwrap().unwrap())
        );
        let mut competing = close.clone();
        competing.op_id = "another-close".into();
        assert_eq!(
            store.transition_flowing_source(&competing).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::CloseAlreadyPending)
        );
        assert_eq!(store.flowing_source("branch").unwrap().unwrap(), before);
        assert_eq!(
            store
                .create_branch(CreateBranch {
                    branch_id: "late-member",
                    name: None,
                    parent_branch_id: "branch",
                    at_cut: None,
                    created_at: "t5",
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
                    opened_at: "t5".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        let roster = store.flowing_close_roster("branch").unwrap().unwrap();
        assert_eq!(roster.close_request.unwrap().request, close);
        assert_eq!(roster.members.len(), 1);
        assert_eq!(roster.members[0].branch_id, "early-member");

        let original_fence = store.flowing_source("branch").unwrap().unwrap();
        let mut wrong_incarnation = original_fence.clone();
        wrong_incarnation.incarnation_id = "foreign-incarnation".into();
        sql.execute(
            "UPDATE flowing_source_fences SET state_json = ?1 WHERE source_branch_id = 'branch'",
            &[text(&serde_json::to_string(&wrong_incarnation).unwrap())],
        )
        .unwrap();
        assert!(matches!(
            store.flowing_close_roster("branch"),
            Err(whipplescript_store::StoreError::Conflict(message))
                if message == "flowing close request belongs to another incarnation"
        ));
        sql.execute(
            "UPDATE flowing_source_fences SET state_json = ?1 WHERE source_branch_id = 'branch'",
            &[text(&serde_json::to_string(&original_fence).unwrap())],
        )
        .unwrap();
        sql.execute(
            "UPDATE flowing_source_close_requests SET incarnation_id = 'foreign-incarnation' \
             WHERE source_branch_id = 'branch'",
            &[],
        )
        .unwrap();
        assert!(matches!(
            store.flowing_close_request("branch"),
            Err(whipplescript_store::StoreError::Conflict(message))
                if message == "flowing close request differs from its ref receipt"
        ));
        sql.execute(
            "UPDATE flowing_source_close_requests SET incarnation_id = 'inc-1' \
             WHERE source_branch_id = 'branch'",
            &[],
        )
        .unwrap();
        sql.execute(
            "DELETE FROM flowing_source_fence_ops WHERE op_id = 'close'",
            &[],
        )
        .unwrap();
        assert!(matches!(
            store.flowing_close_request("branch"),
            Err(whipplescript_store::StoreError::Conflict(message))
                if message == "flowing close request lost its ref receipt"
        ));
    }

    #[test]
    fn hosted_corrupt_flowing_parent_ancestry_cannot_admit_a_member() {
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
            let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
            let mut store = DoBranches::new(Rc::clone(&sql)).unwrap();
            store.ensure_mainline("t0").unwrap();
            store
                .create_branch(CreateBranch {
                    branch_id: "branch",
                    name: Some("feature"),
                    parent_branch_id: MAINLINE_BRANCH_ID,
                    at_cut: None,
                    created_at: "t1",
                    idempotency_key: None,
                })
                .unwrap();
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
            sql.execute(corruption, &[]).unwrap();
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

    fn open_after_parent_discard() -> OpenFlowingSourceOutcome {
        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut store = DoBranches::new(Rc::clone(&sql)).unwrap();
        store.ensure_mainline("t0").unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "branch",
                name: Some("feature"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        assert!(matches!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "branch".into(),
                    incarnation_id: "branch-inc".into(),
                    kind: FlowingSourceKind::Branch,
                    owner: "coordinator".into(),
                    opened_at: "t2".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
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
        sql.execute(
            "UPDATE branches SET status = 'discarded' WHERE branch_id = 'branch'",
            &[],
        )
        .unwrap();
        let result = store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "twig".into(),
                incarnation_id: "twig-inc".into(),
                kind: FlowingSourceKind::Twig,
                owner: "coordinator".into(),
                opened_at: "t5".into(),
            })
            .unwrap();
        assert!(store.flowing_source("twig").unwrap().is_none());
        result
    }

    #[test]
    fn hosted_inactive_parent_cannot_open_a_member_twig() {
        assert_eq!(
            open_after_parent_discard(),
            OpenFlowingSourceOutcome::InvalidKindParent
        );
    }

    fn cut<'a>(id: &'a str, parent: Option<&'a str>, manifest: &'a str) -> CutRecord<'a> {
        CutRecord {
            cut_id: id,
            change_id: id,
            branch_id: "branch",
            manifest_hash: manifest,
            parent_cut_id: parent,
            origin: Some("write:note.txt"),
            actor: Some("human:fixture"),
            intent: Some("fixture"),
            recorded_at: "t3",
        }
    }

    fn exercise_source_mutation_boundary<B: Branches + FlowingFence>(mut store: B) {
        store.ensure_mainline("t0").unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "branch",
                name: Some("feature"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator".into(),
                opened_at: "t2".into(),
            })
            .unwrap();

        assert!(store
            .advance_head("branch", None, "unrecorded", "m1", "t3")
            .is_err());
        assert!(store
            .get_branch("branch")
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
        store.record_cut(cut("a", None, "m1")).unwrap();
        assert!(matches!(
            store.advance_head("branch", None, "a", "m1", "t3").unwrap(),
            AdvanceOutcome::Advanced(_)
        ));
        assert!(matches!(
            store.commit_write(cut("b", Some("a"), "m2")).unwrap(),
            AdvanceOutcome::Advanced(_)
        ));
        assert_eq!(
            store
                .flowing_source("branch")
                .unwrap()
                .unwrap()
                .eligibility_epoch,
            0
        );

        store.record_cut(cut("next", Some("b"), "m-next")).unwrap();
        assert!(store
            .advance_head("branch", Some("b"), "next", "substituted", "t4")
            .is_err());

        store.record_cut(cut("rewrite", None, "m3")).unwrap();
        assert!(store
            .advance_head("branch", Some("b"), "rewrite", "m3", "t4")
            .is_err());
        assert_eq!(
            store
                .get_branch("branch")
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some("b")
        );
        let state = store.flowing_source("branch").unwrap().unwrap();
        let begin = FlowingFenceTransition {
            op_id: "begin-rewrite".into(),
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            expected_eligibility_epoch: state.eligibility_epoch,
            expected_owner_epoch: state.owner_epoch,
            actor: "coordinator".into(),
            action: FlowingFenceAction::BeginRevision {
                before_cut_id: Some("b".into()),
                after_cut_id: "rewrite".into(),
            },
            recorded_at: "t4".into(),
        };
        assert!(matches!(
            store.transition_flowing_source(&begin).unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        store.record_cut(cut("other", Some("b"), "m4")).unwrap();
        assert!(store
            .advance_head("branch", Some("b"), "other", "m4", "t4")
            .is_err());
        assert!(store
            .commit_write(cut("pending-write", Some("b"), "m-pending"))
            .is_err());
        assert!(store.get_cut("pending-write").unwrap().is_none());
        assert!(store.get_op("op-pending-write").unwrap().is_none());
        assert!(matches!(
            store
                .advance_head("branch", Some("b"), "rewrite", "m3", "t4")
                .unwrap(),
            AdvanceOutcome::Advanced(_)
        ));

        store
            .create_branch(CreateBranch {
                branch_id: "other-parent",
                name: Some("other"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t5",
                idempotency_key: None,
            })
            .unwrap();
        assert!(store
            .retarget_branch("branch", "other-parent", "t5")
            .is_err());
        assert!(store
            .rebase_branch("branch", Some("rewrite"), "p", "mp", "r", "mr", "t5")
            .is_err());
        let before = store.get_branch("branch").unwrap().unwrap();
        assert!(store
            .restore_branch_state("branch", Some("rewrite"), &OpBranchState::of(&before), "t5")
            .is_err());
        assert!(store.discard_branch("branch", "t5").is_err());
        assert!(store.adopt_branch("branch", "merge", "t5").is_err());
        assert_eq!(store.get_branch("branch").unwrap(), Some(before));

        let state = store.flowing_source("branch").unwrap().unwrap();
        let finish = FlowingFenceTransition {
            op_id: "finish-rewrite".into(),
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            expected_eligibility_epoch: state.eligibility_epoch,
            expected_owner_epoch: state.owner_epoch,
            actor: "coordinator".into(),
            action: FlowingFenceAction::FinishRevision {
                begin_op_id: "begin-rewrite".into(),
            },
            recorded_at: "t6".into(),
        };
        assert!(matches!(
            store.transition_flowing_source(&finish).unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        assert_eq!(
            store
                .flowing_source("branch")
                .unwrap()
                .unwrap()
                .eligibility_epoch,
            2
        );
        assert!(store.discard_branch("branch", "t7").is_err());
    }

    #[test]
    fn flowing_source_head_and_shape_mutations_have_native_hosted_parity() {
        exercise_source_mutation_boundary(BranchStore::open(":memory:").unwrap());
        exercise_source_mutation_boundary(
            DoBranches::new(Rc::new(RusqliteDoSql::with_runtime_schema())).unwrap(),
        );
    }

    #[test]
    fn hosted_failed_receipt_insert_rolls_back_state() {
        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut store = DoBranches::new(Rc::clone(&sql)).unwrap();
        store.ensure_mainline("t0").unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "branch",
                name: Some("feature"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator-a".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        sql.execute(
            "CREATE TRIGGER fail_fence_op BEFORE INSERT ON flowing_source_fence_ops \
             BEGIN SELECT RAISE(ABORT, 'injected refusal'); END",
            &[],
        )
        .unwrap();
        let hold = FlowingFenceTransition {
            op_id: "hold-fails".into(),
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            expected_eligibility_epoch: 0,
            expected_owner_epoch: 0,
            actor: "mediator".into(),
            action: FlowingFenceAction::Hold,
            recorded_at: "t3".into(),
        };
        assert!(store.transition_flowing_source(&hold).is_err());
        let state = store.flowing_source("branch").unwrap().unwrap();
        assert!(!state.held);
        assert_eq!(state.eligibility_epoch, 0);
        assert!(store.flowing_fence_receipt("hold-fails").unwrap().is_none());
        let mut close = hold;
        close.op_id = "close-fails".into();
        close.action = FlowingFenceAction::RequestClose;
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
    fn hosted_member_open_rolls_back_branch_when_fence_insert_fails() {
        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut store = DoBranches::new(Rc::clone(&sql)).unwrap();
        store.ensure_mainline("t0").unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "branch",
                name: Some("feature"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        sql.execute(
            "CREATE TRIGGER reject_member_fence BEFORE INSERT ON flowing_source_fences \
             WHEN NEW.source_branch_id = 'member' BEGIN SELECT RAISE(ABORT, 'injected'); END",
            &[],
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
            owner: "coordinator".into(),
            opened_at: "t3".into(),
        };
        assert!(store.open_flowing_member(member.clone(), &opening).is_err());
        assert!(store.get_branch("member").unwrap().is_none());
        assert!(store.flowing_source("member").unwrap().is_none());
        sql.execute("DROP TRIGGER reject_member_fence", &[])
            .unwrap();
        assert!(matches!(
            store.open_flowing_member(member, &opening).unwrap(),
            OpenFlowingMemberOutcome::Opened { .. }
        ));
        sql.execute(
            "CREATE TRIGGER reject_member_receipt BEFORE INSERT ON flowing_member_openings \
             WHEN NEW.branch_id = 'member2' BEGIN SELECT RAISE(ABORT, 'injected'); END",
            &[],
        )
        .unwrap();
        let second = member_request("member2", "branch", Some("member-key-2"));
        let second_opening = member_opening("member2");
        assert!(store
            .open_flowing_member(second.clone(), &second_opening)
            .is_err());
        assert!(store.get_branch("member2").unwrap().is_none());
        assert!(store.flowing_source("member2").unwrap().is_none());
        sql.execute("DROP TRIGGER reject_member_receipt", &[])
            .unwrap();
        assert!(matches!(
            store.open_flowing_member(second, &second_opening).unwrap(),
            OpenFlowingMemberOutcome::Opened { .. }
        ));
        sql.execute(
            "DELETE FROM flowing_source_openings WHERE source_branch_id = 'member2'",
            &[],
        )
        .unwrap();
        assert!(matches!(
            read_member_opening_evidence(&store, "member2"),
            Err(StoreError::Conflict(message)) if message == "flowing opening host evidence refuses: member source opening receipt is missing"
        ));
        let mut retained = store.flowing_member_opening("member").unwrap().unwrap();
        retained.branch.name = Some("forged".into());
        sql.execute(
            "UPDATE flowing_member_openings SET branch_json = ?1 WHERE branch_id = 'member'",
            &[text(&serde_json::to_string(&retained.branch).unwrap())],
        )
        .unwrap();
        assert!(matches!(
            store.flowing_member_opening("member"),
            Err(StoreError::Conflict(message)) if message == "flowing member opening receipt is inconsistent"
        ));
    }

    #[test]
    fn hosted_source_open_rolls_back_fence_when_opening_receipt_insert_fails() {
        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut store = DoBranches::new(Rc::clone(&sql)).unwrap();
        store.ensure_mainline("t0").unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "branch",
                name: Some("feature"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        sql.execute(
            "CREATE TRIGGER reject_source_opening BEFORE INSERT ON flowing_source_openings \
             WHEN NEW.source_branch_id = 'branch' BEGIN SELECT RAISE(ABORT, 'injected'); END",
            &[],
        )
        .unwrap();
        let opening = OpenFlowingSource {
            source_branch_id: "branch".into(),
            incarnation_id: "inc".into(),
            kind: FlowingSourceKind::Branch,
            owner: "coordinator".into(),
            opened_at: "t2".into(),
        };
        assert!(store.open_flowing_source(&opening).is_err());
        assert!(store.flowing_source("branch").unwrap().is_none());
        sql.execute("DROP TRIGGER reject_source_opening", &[])
            .unwrap();
        assert!(matches!(
            store.open_flowing_source(&opening).unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        sql.execute(
            "DELETE FROM flowing_source_fences WHERE source_branch_id = 'branch'",
            &[],
        )
        .unwrap();
        assert!(matches!(
            store.open_flowing_source(&opening),
            Err(StoreError::Conflict(message)) if message == "flowing source opening lost current authority"
        ));
        let mut retained = store.flowing_source_opening("branch").unwrap().unwrap();
        retained.state.held = true;
        sql.execute(
            "UPDATE flowing_source_openings SET state_json = ?1 WHERE source_branch_id = 'branch'",
            &[text(&serde_json::to_string(&retained.state).unwrap())],
        )
        .unwrap();
        assert!(matches!(
            store.flowing_source_opening("branch"),
            Err(StoreError::Conflict(message)) if message == "flowing source opening receipt is inconsistent"
        ));
    }

    #[test]
    fn hosted_invalid_request_and_inactive_branch_cannot_change_fence_state() {
        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut store = DoBranches::new(Rc::clone(&sql)).unwrap();
        store.ensure_mainline("t0").unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "branch",
                name: Some("feature"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator-a".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        let request = FlowingFenceTransition {
            op_id: "hold".into(),
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            expected_eligibility_epoch: 0,
            expected_owner_epoch: 0,
            actor: "mediator".into(),
            action: FlowingFenceAction::Hold,
            recorded_at: "t3".into(),
        };
        let mut invalid = request.clone();
        invalid.actor.clear();
        assert_eq!(
            store.transition_flowing_source(&invalid).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::Invalid { field: "actor" })
        );
        let mut no_state = request.clone();
        no_state.source_branch_id = "never-opened".into();
        no_state.op_id = "no-state".into();
        assert_eq!(
            store.transition_flowing_source(&no_state).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::Missing)
        );
        sql.execute(
            "UPDATE branches SET status = 'discarded' WHERE branch_id = 'branch'",
            &[],
        )
        .unwrap();
        assert_eq!(
            store.transition_flowing_source(&request).unwrap(),
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
        sql.execute("DELETE FROM branches WHERE branch_id = 'branch'", &[])
            .unwrap();
        assert_eq!(
            store.transition_flowing_source(&request).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::Missing)
        );
    }

    #[test]
    fn hosted_open_refuses_a_preexisting_member_twig() {
        let mut store = DoBranches::new(Rc::new(RusqliteDoSql::with_runtime_schema())).unwrap();
        store.ensure_mainline("t0").unwrap();
        for (branch_id, parent_branch_id) in
            [("branch", MAINLINE_BRANCH_ID), ("member-twig", "branch")]
        {
            store
                .create_branch(CreateBranch {
                    branch_id,
                    name: (branch_id == "branch").then_some("feature"),
                    parent_branch_id,
                    at_cut: None,
                    created_at: "t1",
                    idempotency_key: None,
                })
                .unwrap();
        }
        assert_eq!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "branch".into(),
                    incarnation_id: "inc-1".into(),
                    kind: FlowingSourceKind::Branch,
                    owner: "coordinator-a".into(),
                    opened_at: "t2".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::BranchAlreadyHasChildren
        );
    }
}
