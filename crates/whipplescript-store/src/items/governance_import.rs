use super::*;
use crate::norm::NormVerifier;
use crate::norm_governance_import::{
    validate_import, GovernanceImportRequest, GovernanceImportResult,
};
impl WorkItemStore {
    /// Retry lookup, current basis/map checks and all norm event/alias inserts
    /// are owned by this same immediate publication transaction.
    pub fn import_governance(
        &mut self,
        request: &GovernanceImportRequest,
        verifier: &dyn NormVerifier,
    ) -> StoreResult<GovernanceImportResult> {
        let tx = self.discovery_transaction()?;
        let checkpoint = load_norm_checkpoint(&tx)?.ok_or_else(|| {
            StoreError::Conflict("governance import requires a pinned norm ledger".into())
        })?;
        let history = load_norm_events(&tx)?;
        let prepared = validate_import(&history, &checkpoint, request, verifier)?;
        for event in &prepared.events {
            insert_norm_event(&tx, event, None)?;
        }
        tx.commit()?;
        Ok(prepared.result)
    }
    /// One coherent raw capture for opaque incremental preparation; no per-act
    /// snapshot or mutable projection is exposed.
    pub fn governance_preparation_capture(
        &self,
    ) -> StoreResult<(crate::norm::NormCheckpoint, Vec<TrackerEvent>)> {
        let transaction = if self.connection.is_autocommit() {
            Some(self.connection.unchecked_transaction()?)
        } else {
            None
        };
        let checkpoint = load_norm_checkpoint(&self.connection)?.ok_or_else(|| {
            StoreError::Conflict("governance preparation requires a pinned norm ledger".into())
        })?;
        let history = load_norm_events(&self.connection)?;
        if let Some(transaction) = transaction {
            transaction.commit()?;
        }
        Ok((checkpoint, history))
    }
    pub fn governance_reference(
        &self,
        scope: &str,
        number: &str,
        verifier: &dyn NormVerifier,
    ) -> StoreResult<Option<String>> {
        let transaction = if self.connection.is_autocommit() {
            Some(self.connection.unchecked_transaction()?)
        } else {
            None
        };
        let checkpoint = load_norm_checkpoint(&self.connection)?.ok_or_else(|| {
            StoreError::Conflict("governance reference requires a pinned norm ledger".into())
        })?;
        let result = crate::norm_governance_import::resolve_governance_reference(
            &load_norm_events(&self.connection)?,
            &checkpoint,
            verifier,
            scope,
            number,
        )?;
        if let Some(transaction) = transaction {
            transaction.commit()?;
        }
        Ok(result)
    }
}
