//! The Rust-to-transaction callback contract, independent of the JS ABI.
//! Keeping refusal propagation here lets the native suite exercise the branch
//! that must throw through the Worker's synchronous transaction boundary.

#[cfg(any(test, target_arch = "wasm32"))]
use whipplescript_store::{StoreError, StoreResult};

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn invoke_body(
    body: &mut dyn FnMut() -> StoreResult<()>,
    failure: &mut Option<StoreError>,
) -> Result<(), &'static str> {
    if let Err(error) = body() {
        *failure = Some(error);
        // MUTATION-SUCCESS-EXPR: Ok(())
        return Err("host action transaction aborted");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_action_transaction_callback_propagates_failure_without_disclosing_it() {
        let mut failure = None;
        assert_eq!(
            invoke_body(
                &mut || Err(StoreError::Conflict("private failure detail".into())),
                &mut failure,
            ),
            Err("host action transaction aborted")
        );
        assert!(
            matches!(failure, Some(StoreError::Conflict(detail)) if detail == "private failure detail")
        );
    }

    #[test]
    fn host_action_transaction_callback_runs_a_successful_body_once() {
        let mut failure = None;
        let mut calls = 0;
        assert_eq!(
            invoke_body(
                &mut || {
                    calls += 1;
                    Ok(())
                },
                &mut failure
            ),
            Ok(())
        );
        assert_eq!(calls, 1);
        assert!(failure.is_none());
    }
}
