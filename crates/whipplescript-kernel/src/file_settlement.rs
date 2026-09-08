//! Settle synchronous file effects without a terminal-to-fact crash gap.
use super::*;

impl<S: RuntimeStore> RuntimeKernel<S> {
    /// File handlers expose their terminal and continuation fact together.
    pub(crate) fn settle_file_run(
        &mut self,
        completion: EffectCompletion<'_>,
        fact_name: &str,
        fact_value: &str,
        fact_event_key: &str,
    ) -> StoreResult<StoredEvent> {
        let status = match completion.status {
            "completed" => EffectStatus::Completed,
            "failed" => EffectStatus::Failed,
            _ => {
                return Err(StoreError::Conflict(
                    "file settlement terminal status".into(),
                ))
            }
        };
        let diagnostic = (status == EffectStatus::Failed)
            .then(|| self.terminal_diagnostic_from_completion(&completion, status.clone()))
            .flatten();
        let fact_id = idempotency_key(&[
            completion.instance_id,
            "fact",
            fact_name,
            completion.effect_id,
        ]);
        let event = self.store.settle_file_effect(
            completion,
            diagnostic,
            whipplescript_store::file_settlement::FileSettlementFact {
                fact_id: &fact_id,
                event_key: fact_event_key,
                name: fact_name,
                value_json: fact_value,
            },
        )?;
        self.emit(TraceEvent::EffectTerminal {
            run_id: completion.run_id.into(),
            effect_id: completion.effect_id.into(),
            status,
        });
        Ok(event)
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    #[test]
    fn file_settlement_refuses_non_file_terminal_states_before_storage() {
        let mut store = whipplescript_store::SqliteStore::open_in_memory()
            .expect("settlement fixture operation");
        let fixture = whipplescript_store::file_settlement::conformance::setup(
            &mut store,
            "file.write",
            "completed",
        );
        let mut kernel = RuntimeKernel::new(store);
        let before = kernel
            .store()
            .list_events(&fixture.instance)
            .expect("settlement fixture operation");
        for status in ["cancelled", "timed_out", "uncertain"] {
            let error = kernel
                .settle_file_run(
                    EffectCompletion {
                        status,
                        ..fixture.completion()
                    },
                    &fixture.name,
                    &fixture.value,
                    "settle-fact-event",
                )
                .expect_err("invalid settlement must refuse");
            assert!(
                matches!(error, StoreError::Conflict(ref message) if message == "file settlement terminal status")
            );
            assert_eq!(
                kernel
                    .store()
                    .list_events(&fixture.instance)
                    .expect("settlement fixture operation"),
                before
            );
        }
        kernel
            .settle_file_run(
                fixture.completion(),
                &fixture.name,
                &fixture.value,
                "settle-fact-event",
            )
            .expect("settlement fixture operation");
        assert_eq!(
            kernel
                .store()
                .list_facts(&fixture.instance)
                .expect("settlement fixture operation")
                .len(),
            1
        );
    }
}
