//! The single source-to-rule elaboration for table seeders. The generated
//! body stays byte-stable; row origins never pretend to be generated offsets.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TableOrigin {
    pub name: Ident,
    pub records: Vec<IrRecordSource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ElaboratedTable {
    pub rule: RuleDecl,
    pub origin: TableOrigin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedRule {
    pub rule: RuleDecl,
    pub table: Option<TableOrigin>,
}

pub(crate) fn prepare_rules(
    program: &Program,
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<PreparedRule> {
    program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Rule(rule) => Some(PreparedRule {
                rule: rule.clone(),
                table: None,
            }),
            Item::Table(table) => {
                elaborate(table.clone(), semantic, diagnostics).map(|table| PreparedRule {
                    rule: table.rule,
                    table: Some(table.origin),
                })
            }
            _ => None,
        })
        .collect()
}

pub(super) fn elaborate(
    table: TableDecl,
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<ElaboratedTable> {
    if !semantic.schemas.class_exists(&table.schema.name) {
        diagnostics.push(Diagnostic {
            code: diagnostic_code!("type.unknown_schema"),
            severity: Severity::Error,
            related: Vec::new(),
            fixits: Vec::new(),
            span: table.schema.span,
            message: format!(
                "table `{}` targets unknown class `{}`",
                table.name.name, table.schema.name
            ),
            suggestion: suggest(crate::suggest_otherwise(
                &table.schema.name,
                semantic.schemas.classes.keys(),
                "declare the class before seeding rows for it",
            )),
        });
        return None;
    }

    if table.rows.is_empty() {
        diagnostics.push(Diagnostic {
            code: diagnostic_code!("construct.missing_requirement"),
            severity: Severity::Error,
            related: Vec::new(),
            fixits: Vec::new(),
            span: table.span,
            message: format!("table `{}` has no rows", table.name.name),
            suggestion: suggest("add at least one `{ ... }` row".to_owned()),
        });
        return None;
    }

    let mut body = String::new();
    for row in &table.rows {
        push_line(&mut body, format!("record {} {{", table.schema.name));
        push_block_body(&row.body.text, &mut body);
        push_line(&mut body, "}");
        body.push('\n');
    }
    if body.ends_with('\n') {
        body.pop();
    }

    let rule = RuleDecl {
        name: Ident {
            name: format!("table_{}", table.name.name),
            span: table.name.span,
        },
        // A synthesized table seeder records once from `started`; nothing about
        // it is a maintained derivation.
        kind: RuleKind::Rule,
        tags: Vec::new(),
        description: None,
        whens: vec![WhenClause {
            // Synthesized from the table declaration; not in the file.
            text: SourceText::generated("started".to_owned()),
            span: table.name.span,
        }],
        // Synthesized from the table's rows; the text is not in the file.
        body: BlockSource::generated(body, table.span),
        span: table.span,
    };

    let record_sources = table
        .rows
        .iter()
        .map(|row| IrRecordSource {
            schema: table.schema.name.clone(),
            construct: "table_row".to_owned(),
            span: row.span,
        })
        .collect::<Vec<_>>();

    Some(ElaboratedTable {
        rule,
        origin: TableOrigin {
            name: table.name,
            records: record_sources,
        },
    })
}
