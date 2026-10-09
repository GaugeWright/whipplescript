//! Preparation uses the invoking host's installed custody and full-ledger
//! authority. Source documents cannot supply keys, grants or a destination pin.
use super::*;
use whipplescript_store::norm_governance_import::{
    prepare_from_capture, GovernancePreparationOptions, GovernanceSource,
};

pub(super) fn prepare(
    args: &Arguments<'_>,
    store: &WorkItemStore,
    verifier: &dyn NormVerifier,
    signer: &NormCustodyKey<'_>,
) -> Result<Value, String> {
    let raw = std::fs::read(args.required("--source")?)
        .map_err(|e| format!("cannot read complete governance source: {e}"))?;
    let source = GovernanceSource::from_bytes(
        args.required("--scope")?.into(),
        args.required("--revision")?.into(),
        "decisions/log.hjson".into(),
        &raw,
    )
    .map_err(debug_error)?;
    let (checkpoint, history) = store
        .governance_preparation_capture()
        .map_err(debug_error)?;
    let preparation =
        whipplescript_store::norm::NormPreparation::new(&history, &checkpoint, verifier)
            .map_err(debug_error)?;
    let exact = |name: &str| -> Result<_, String> {
        let entries: Vec<_> = preparation
            .view()
            .charter
            .vocabularies
            .iter()
            .filter(|v| v.definition.name == name && v.definition.version == "1")
            .collect();
        if entries.len() != 1 {
            return Err(format!(
                "governance preparation requires one exact installed {name}@1 declaration"
            ));
        }
        Vocabulary::new(entries[0].definition.clone())
            .map(|v| v.reference().clone())
            .map_err(|e| e.to_string())
    };
    let options = GovernancePreparationOptions {
        import_id: args.required("--import-id")?.into(),
        source,
        actor: signer.actor().clone(),
        created_at: args
            .flags
            .get("--at")
            .map(|v| (*v).into())
            .unwrap_or_else(super::super::now_stamp),
        nonce_prefix: match args.flags.get("--nonce") {
            Some(v) => (*v).into(),
            None => super::super::credential_proxy_token()?,
        },
        decision_vocabulary: exact("decision")?,
        assertion_vocabulary: exact("assertion")?,
        adopt_numbers: if args.flags.contains_key("--adopt") {
            serde_json::from_str(&args.file("--adopt")?).map_err(|e| e.to_string())?
        } else {
            Vec::new()
        },
    };
    let request = prepare_from_capture(preparation, options, &mut |statement| {
        Ok(SignedNormEvent {
            statement: statement.clone(),
            signature: signer
                .sign(statement)
                .map_err(whipplescript_store::StoreError::Conflict)?,
            successor_signature: None,
        })
    })
    .map_err(debug_error)?;
    serde_json::to_value(request).map_err(|e| e.to_string())
}
