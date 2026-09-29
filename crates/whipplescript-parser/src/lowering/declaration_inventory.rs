//! Compiler-owned inventory for declaration construct forms.
//!
//! The expected occurrence is taken from the selected, pattern-expanded AST,
//! before its item is lowered. After lowering, the matching IR collection
//! must have gained exactly that item's payload. This does not resolve a
//! package registration or claim that platform-core syntax is covered.

use super::*;

pub(crate) fn from_effective_item(
    item: &Item,
    occurrence: usize,
) -> Option<IrDeclarationConstruct> {
    let (keyword, name, family, lowering) = match item {
        Item::Tracker(item) => (
            "tracker",
            item.name.name.as_str(),
            "declaration_block",
            "metadata_only",
        ),
        Item::FileStore(item) => (
            "file store",
            item.name.name.as_str(),
            "declaration_block",
            "metadata_only",
        ),
        Item::Lease(item) => (
            "lease",
            item.name.name.as_str(),
            "declaration_block",
            "metadata_only",
        ),
        Item::Ledger(item) => (
            "ledger",
            item.name.name.as_str(),
            "declaration_block",
            "metadata_only",
        ),
        Item::Counter(item) => (
            "counter",
            item.name.name.as_str(),
            "declaration_block",
            "metadata_only",
        ),
        Item::Event(item) => (
            "signal",
            item.name.as_str(),
            "declaration_block",
            "metadata_only",
        ),
        Item::Source(item) => (
            "source",
            item.name.name.as_str(),
            "source_declaration",
            if item.clock.is_some() {
                "clock_source"
            } else {
                "signal_source"
            },
        ),
        _ => return None,
    };
    Some(IrDeclarationConstruct {
        occurrence,
        keyword: keyword.into(),
        name: name.into(),
        scope: "top_level".into(),
        family: family.into(),
        lowering: lowering.into(),
        span: item.span(),
    })
}

pub(crate) fn lowered_count(declaration: &IrDeclarationConstruct, ir: &IrProgram) -> usize {
    match declaration.keyword.as_str() {
        "tracker" => ir.trackers.len(),
        "file store" => ir.file_stores.len(),
        "lease" => ir.leases.len(),
        "ledger" => ir.ledgers.len(),
        "counter" => ir.counters.len(),
        "signal" => ir.events.len(),
        "source" => ir.sources.len(),
        _ => 0,
    }
}

pub(crate) fn verify_lowered_once(
    declaration: &IrDeclarationConstruct,
    before: usize,
    ir: &IrProgram,
) -> Result<(), Box<Diagnostic>> {
    let matched = match declaration.keyword.as_str() {
        "tracker" => {
            ir.trackers.len() == before + 1
                && ir.trackers.get(before).is_some_and(|item| {
                    item.name == declaration.name && item.span == declaration.span
                })
        }
        "file store" => {
            ir.file_stores.len() == before + 1
                && ir
                    .file_stores
                    .get(before)
                    .is_some_and(|item| item.name == declaration.name)
        }
        "lease" => {
            ir.leases.len() == before + 1
                && ir.leases.get(before).is_some_and(|item| {
                    item.name == declaration.name && item.span == declaration.span
                })
        }
        "ledger" => {
            ir.ledgers.len() == before + 1
                && ir.ledgers.get(before).is_some_and(|item| {
                    item.name == declaration.name && item.span == declaration.span
                })
        }
        "counter" => {
            ir.counters.len() == before + 1
                && ir.counters.get(before).is_some_and(|item| {
                    item.name == declaration.name && item.span == declaration.span
                })
        }
        "signal" => {
            ir.events.len() == before + 1
                && ir.events.get(before).is_some_and(|item| {
                    item.name == declaration.name && item.span == declaration.span
                })
        }
        "source" => {
            ir.sources.len() == before + 1
                && ir.sources.get(before).is_some_and(|item| {
                    item.name == declaration.name
                        && item.span == declaration.span
                        && item.is_clock == (declaration.lowering == "clock_source")
                })
        }
        _ => false,
    };
    if matched {
        Ok(())
    } else {
        Err(Box::new(Diagnostic {
            code: diagnostic_code!("lowering.internal"),
            severity: Severity::Error,
            related: Vec::new(),
            fixits: Vec::new(),
            span: declaration.span,
            message: format!(
                "declaration construct `{}` was not lowered exactly once",
                declaration.name
            ),
            suggestion: suggest("report this compiler inventory failure".to_owned()),
        }))
    }
}

pub(crate) fn retain_or_refuse(
    declaration: IrDeclarationConstruct,
    before: usize,
    ir: &mut IrProgram,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match verify_lowered_once(&declaration, before, ir) {
        Ok(()) => ir
            .declaration_constructs
            .as_mut()
            .expect("new compiler IR has a declaration inventory")
            .push(declaration),
        Err(diagnostic) => diagnostics.push(*diagnostic),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_declaration_constructs_survive_lowering_with_distinct_occurrences() {
        for (source, names, source_lowering) in [
            (
                include_str!("../../../../examples/gastown-lite.whip"),
                &["lease", "ledger", "tracker"][..],
                None,
            ),
            (
                include_str!("../../../../examples/circuit-breaker.whip"),
                &["counter"][..],
                None,
            ),
            (
                include_str!("../../../../examples/file-store-demo.whip"),
                &["file store"][..],
                None,
            ),
            (
                include_str!("../../../../examples/clock-source.whip"),
                &["signal", "source"][..],
                Some("clock_source"),
            ),
            (
                include_str!("../../../../examples/ingress-file-source.whip"),
                &["signal", "source"][..],
                Some("signal_source"),
            ),
        ] {
            let compiled = compile_program(source);
            assert!(
                compiled.diagnostics.is_empty(),
                "{:?}",
                compiled.diagnostics
            );
            let ir = compiled.ir.expect("checked IR");
            assert_eq!(
                ir.declaration_constructs
                    .as_ref()
                    .expect("checked inventory")
                    .iter()
                    .map(|item| item.keyword.as_str())
                    .collect::<Vec<_>>(),
                names
            );
            assert!(ir
                .declaration_constructs
                .as_ref()
                .expect("checked inventory")
                .windows(2)
                .all(|pair| pair[0].occurrence < pair[1].occurrence));
            if let Some(expected) = source_lowering {
                let observed = ir
                    .declaration_constructs
                    .as_ref()
                    .unwrap()
                    .iter()
                    .find(|item| item.keyword == "source")
                    .unwrap();
                assert_eq!(observed.lowering, expected);
            }
        }
    }

    #[test]
    fn omitted_or_changed_lowered_payload_refuses_inventory_match() {
        let compiled = compile_program(include_str!("../../../../examples/clock-source.whip"));
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        let mut ir = compiled.ir.expect("checked IR");
        let source = ir
            .declaration_constructs
            .as_ref()
            .expect("checked inventory")
            .iter()
            .find(|item| item.keyword == "source")
            .unwrap()
            .clone();
        assert!(verify_lowered_once(&source, 0, &ir).is_ok());
        ir.sources[0].is_clock = false;
        assert!(verify_lowered_once(&source, 0, &ir).is_err());
        ir.sources.clear();
        let error = verify_lowered_once(&source, 0, &ir).unwrap_err();
        assert_eq!(error.code, diagnostic_code!("lowering.internal"));
        assert!(error.message.contains("not lowered exactly once"));

        ir.declaration_constructs = Some(Vec::new());
        let mut diagnostics = Vec::new();
        retain_or_refuse(source, 0, &mut ir, &mut diagnostics);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, diagnostic_code!("lowering.internal"));
        assert!(ir.declaration_constructs.unwrap().is_empty());
    }

    #[test]
    fn repeated_pattern_declarations_have_distinct_effective_occurrences() {
        let source = r#"use std.tracker
workflow Repeated
pattern Queue {
  tracker backlog
}
apply Queue as first {}
apply Queue as second {}
"#;
        let compiled = compile_program(source);
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        let ir = compiled.ir.expect("checked IR");
        let declarations = ir.declaration_constructs.expect("checked inventory");
        assert_eq!(declarations.len(), 2);
        assert_eq!(declarations[0].span, declarations[1].span);
        assert_ne!(declarations[0].occurrence, declarations[1].occurrence);
    }

    #[test]
    fn older_ir_without_inventory_remains_unknown_but_checked_empty_is_explicit() {
        let compiled = compile_program(include_str!("../../../../examples/minimal-noop.whip"));
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        let ir = compiled.ir.expect("checked IR");
        assert_eq!(ir.declaration_constructs, Some(Vec::new()));
        let mut legacy = serde_json::to_value(ir).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("declaration_constructs");
        let legacy: IrProgram = serde_json::from_value(legacy).unwrap();
        assert_eq!(legacy.declaration_constructs, None);
    }
}
