use super::*;
use whipplescript_store::norm::NormVerifier;
use whipplescript_store::norm_governance_import::{
    validate_import, GovernanceImportRequest, GovernanceImportResult,
};
impl<Sql: DoSql> DoSqliteStore<Sql> {
    /// No await/yield is possible between these owning reads and the one
    /// SQLite statement. The statement includes every norm row and alias trigger.
    pub fn import_governance(
        &mut self,
        request: &GovernanceImportRequest,
        verifier: &dyn NormVerifier,
    ) -> StoreResult<GovernanceImportResult> {
        let checkpoint = self.norm_checkpoint()?.ok_or_else(|| {
            StoreError::Conflict("governance import requires a pinned norm ledger".into())
        })?;
        let history = self.norm_events()?;
        let prepared = validate_import(&history, &checkpoint, request, verifier)?;
        if !prepared.events.is_empty() {
            self.sql
                .execute(
                    whipplescript_store::norm::NORM_INSERT_SQL,
                    &[
                        text(&serde_json::to_string(&prepared.events)?),
                        SqlValue::Null,
                    ],
                )
                .map_err(sql_err)?;
        }
        Ok(prepared.result)
    }
    pub fn governance_reference(
        &self,
        scope: &str,
        number: &str,
        verifier: &dyn NormVerifier,
    ) -> StoreResult<Option<String>> {
        let checkpoint = self.norm_checkpoint()?.ok_or_else(|| {
            StoreError::Conflict("governance reference requires a pinned norm ledger".into())
        })?;
        whipplescript_store::norm_governance_import::resolve_governance_reference(
            &self.norm_events()?,
            &checkpoint,
            verifier,
            scope,
            number,
        )
    }
}
