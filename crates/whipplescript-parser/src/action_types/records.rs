//! Record construction uses the same lexical values and directional contracts
//! as calls/returns. Projection does not grant a value fact identity.
use super::*;
use body::{FieldAssign, FieldValue, RecordStmt};

fn may_equal(ty: &IrType, required: &str) -> bool {
    match ty {
        IrType::LiteralString(value) => value == required,
        IrType::Union(variants) => variants.iter().any(|ty| may_equal(ty, required)),
        IrType::Optional(inner) => may_equal(inner, required),
        IrType::Primitive(IrPrimitiveType::Null) => false,
        _ => true,
    }
}

pub(super) fn required_field(
    schema: &str,
    field: &str,
    expected: &TypeSyntax,
    actual: &[IrClassField],
    semantic: &SemanticContext,
) -> bool {
    if matches!(expected, TypeSyntax::Optional { .. }) {
        return false;
    }
    semantic
        .schemas
        .field_presence(schema, field)
        .is_none_or(|(disc, required)| {
            actual.iter().find(|f| &f.name == disc).is_some_and(|f| {
                // A malformed discriminator already has its own field
                // error; do not speculate about dependent missing fields.
                semantic.schemas.classes[schema]
                    .get(disc)
                    .is_some_and(|ty| assignable(&f.ty, &lower_type(ty.clone()), semantic))
                    && may_equal(&f.ty, required)
            })
        })
}

fn member(name: String, ty: IrType, span: SourceSpan) -> IrClassField {
    IrClassField {
        name,
        ty,
        span,
        is_key: false,
        presence_condition: None,
    }
}

fn projection_sources(ty: &IrType, semantic: &SemanticContext) -> Option<Vec<String>> {
    match ty {
        IrType::Ref(name) if semantic.schemas.classes.contains_key(name) => {
            Some(vec![name.clone()])
        }
        IrType::Union(variants) if !variants.is_empty() => Some(
            variants
                .iter()
                .map(|ty| projection_sources(ty, semantic))
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        ),
        _ => None,
    }
}

fn expected_enums(ty: &IrType, semantic: &SemanticContext) -> Vec<String> {
    match ty {
        IrType::Ref(name) if semantic.schemas.enums.contains_key(name) => vec![name.clone()],
        IrType::Optional(inner) => expected_enums(inner, semantic),
        IrType::Union(variants) => variants
            .iter()
            .flat_map(|ty| expected_enums(ty, semantic))
            .collect(),
        _ => Vec::new(),
    }
}

impl Checker<'_> {
    fn field_error(
        &mut self,
        code: DiagnosticCode,
        span: SourceSpan,
        message: String,
        declaration: SourceSpan,
    ) {
        self.diagnostics.push(
            Diagnostic::error(code, span, message)
                .with_related(declaration, "field contract declared here"),
        );
    }

    fn field_assignment(
        &mut self,
        name: &str,
        actual: &IrType,
        expected: &TypeSyntax,
        span: SourceSpan,
    ) {
        if !record_assignable(actual, &lower_type(expected.clone()), self.semantic) {
            self.field_error(
                diagnostic_code!("type.mismatch"),
                span,
                format!(
                    "field `{name}` expects {}, got {}",
                    type_label(&lower_type(expected.clone())),
                    type_label(actual)
                ),
                expected.span(),
            );
        }
    }

    pub(super) fn record_payload(&mut self, record: &RecordStmt, environment: &Environment) {
        if is_observer_only_schema(&record.schema)
            && self.semantic.schemas.decl_span(&record.schema).is_none()
        {
            return;
        }
        let Some(schema) = self.semantic.schemas.classes.get(&record.schema).cloned() else {
            // The schema-ownership validator reports this once, in its phase.
            return;
        };
        let before = self.diagnostics.len();
        let sources = if let Some(from) = &record.from {
            let sources = environment
                .get(from)
                .and_then(Option::as_ref)
                .and_then(|ty| projection_sources(ty, self.semantic));
            let Some(sources) = sources else {
                self.diagnostics.push(Diagnostic::error(diagnostic_code!("type.mismatch"), record.span,
                    format!("projection into `{}` requires a present class value for source `{from}`", record.schema))
                    .with_related(self.semantic.schemas.decl_span(&record.schema).unwrap_or(record.span), "destination record declared here"));
                return;
            };
            sources.into_iter().map(Some).collect::<Vec<_>>()
        } else {
            vec![None]
        };
        let explicit = self.record_fields(
            &record.schema,
            &record.fields,
            record.from.as_deref(),
            None,
            environment,
        );
        let written: BTreeSet<_> = record
            .fields
            .iter()
            .map(|field| field.name.clone())
            .collect();
        for source in sources {
            let mut actual = explicit.clone();
            let mut omittable = BTreeSet::new();
            let mut attempted = written.clone();
            if let (Some(source), Some(from)) = (&source, &record.from) {
                let fields = self.semantic.schemas.classes[source].clone();
                for (field, source_ty) in &fields {
                    let Some(expected) = schema.get(field) else {
                        continue;
                    };
                    if written.contains(field.as_str()) {
                        continue;
                    }
                    attempted.insert(field.clone());
                    let ty = environment.member_type(
                        &IrType::Ref(source.clone()),
                        std::slice::from_ref(from),
                        std::slice::from_ref(field),
                        self.semantic,
                    );
                    match ty {
                        Ok(ty) => {
                            self.field_assignment(
                                &format!(
                                    "{}.{} (copied from {from}.{field})",
                                    record.schema, field
                                ),
                                &ty,
                                expected,
                                record.span,
                            );
                            actual.push(member(field.clone(), ty, record.span));
                            if matches!(source_ty, TypeSyntax::Optional { .. }) {
                                omittable.insert(field.clone());
                            }
                        }
                        Err(failure) => {
                            let before_read = self.diagnostics.len();
                            self.path_error(
                                failure,
                                &[from.clone(), field.clone()],
                                environment,
                                record.span,
                            );
                            if self.diagnostics.len() == before_read {
                                self.field_error(diagnostic_code!("type.mismatch"), record.span,
                                    format!("cannot determine the type of implicit copy `{from}.{field}` into `{}`", record.schema), expected.span());
                            }
                        }
                    }
                }
            }
            self.missing_fields(&record.schema, &actual, &attempted, &omittable, record.span);
        }
        // One source union can repeat the same obligation; report it once at
        // this construction, without hiding distinct alternatives' type errors.
        let errors = self.diagnostics.drain(before..).collect::<Vec<_>>();
        let mut unique = Vec::new();
        for error in errors {
            if !unique.contains(&error) {
                unique.push(error);
            }
        }
        self.diagnostics.extend(unique);
    }

    fn missing_fields(
        &mut self,
        schema: &str,
        actual: &[IrClassField],
        attempted: &BTreeSet<String>,
        omittable: &BTreeSet<String>,
        span: SourceSpan,
    ) {
        for (field, ty) in self.semantic.schemas.classes[schema].clone() {
            if required_field(schema, &field, &ty, actual, self.semantic)
                && (!attempted.contains(field.as_str()) || omittable.contains(&field))
            {
                self.field_error(
                    diagnostic_code!("type.missing_required_field"),
                    span,
                    format!("record `{schema}` does not guarantee required field `{field}`"),
                    ty.span(),
                );
            }
        }
    }

    fn record_fields(
        &mut self,
        schema: &str,
        fields: &[FieldAssign],
        from: Option<&str>,
        tag: Option<&str>,
        environment: &Environment,
    ) -> Vec<IrClassField> {
        let declared = self.semantic.schemas.classes[schema].clone();
        let mut actual = Vec::new();
        let mut seen = BTreeMap::new();
        if let Some(tag) = tag {
            actual.push(member(
                "variant".into(),
                IrType::LiteralString(tag.into()),
                self.semantic
                    .schemas
                    .decl_span(schema)
                    .expect("generated variant"),
            ));
        }
        for field in fields {
            if tag.is_some() && field.name == "variant" {
                self.field_error(
                    diagnostic_code!("construct.reserved_name"),
                    field.span,
                    "a variant constructor cannot override its synthesized `variant` tag".into(),
                    declared["variant"].span(),
                );
                continue;
            }
            if let Some(first) = seen.get(&field.name) {
                self.diagnostics.push(
                    Diagnostic::error(
                        diagnostic_code!("type.duplicate_field"),
                        field.span,
                        format!(
                            "record `{schema}` supplies field `{}` more than once",
                            field.name
                        ),
                    )
                    .with_related(*first, "first assignment is here"),
                );
                continue;
            }
            seen.insert(field.name.clone(), field.span);
            let Some(expected) = declared.get(&field.name) else {
                self.diagnostics.push(
                    Diagnostic::error(
                        diagnostic_code!("type.unknown_field"),
                        field.span,
                        format!("record `{schema}` has no field `{}`", field.name),
                    )
                    .with_related(
                        self.semantic
                            .schemas
                            .decl_span(schema)
                            .unwrap_or(field.span),
                        "record declared here",
                    ),
                );
                continue;
            };
            let before = self.diagnostics.len();
            let ty = match &field.value {
                FieldValue::Nested {
                    schema: variant,
                    fields,
                } => self.variant_value(variant, fields, expected, environment, field.span),
                _ => {
                    let expr = match field
                        .record_expression(from, &|name| environment.get(name).is_some())
                    {
                        Ok(expr) => expr,
                        Err(message) => {
                            self.field_error(
                                diagnostic_code!("type.mismatch"),
                                field.span,
                                message,
                                expected.span(),
                            );
                            continue;
                        }
                    };
                    if !object_contexts(&expr, Some(&lower_type(expected.clone())), self.semantic) {
                        self.field_error(diagnostic_code!("type.mismatch"), field.span,
                            format!("field `{schema}.{}` constructs an object without its expected class or map shape", field.name), expected.span());
                        None
                    } else {
                        self.infer_node(&expr, field.span, environment)
                    }
                }
            };
            if let Some(ty) = ty {
                self.field_assignment(
                    &format!("{schema}.{}", field.name),
                    &ty,
                    expected,
                    field.span,
                );
                actual.push(member(field.name.clone(), ty, field.span));
            } else if self.diagnostics.len() == before {
                self.field_error(
                    diagnostic_code!("type.mismatch"),
                    field.span,
                    format!(
                        "cannot determine the value type for field `{schema}.{}`",
                        field.name
                    ),
                    expected.span(),
                );
            }
        }
        actual
    }

    fn variant_value(
        &mut self,
        variant: &str,
        fields: &[FieldAssign],
        expected: &TypeSyntax,
        environment: &Environment,
        span: SourceSpan,
    ) -> Option<IrType> {
        let candidates = expected_enums(&lower_type(expected.clone()), self.semantic);
        let candidates = candidates
            .into_iter()
            .filter(|name| {
                self.semantic.schemas.enums[name]
                    .iter()
                    .any(|value| value == variant)
            })
            .collect::<Vec<_>>();
        let start = self.diagnostics.len();
        let mut best: Option<Vec<Diagnostic>> = None;
        for name in candidates {
            let schema = format!("{name}.{variant}");
            if !self.semantic.schemas.classes.contains_key(&schema) {
                self.field_error(
                    diagnostic_code!("type.mismatch"),
                    span,
                    format!("variant `{name}.{variant}` has no payload; use its bare name"),
                    expected.span(),
                );
            } else {
                let actual = self.record_fields(&schema, fields, None, Some(variant), environment);
                let mut written = fields
                    .iter()
                    .map(|f| f.name.clone())
                    .collect::<BTreeSet<_>>();
                written.insert("variant".into());
                self.missing_fields(&schema, &actual, &written, &BTreeSet::new(), span);
                if self.diagnostics.len() == start {
                    return Some(IrType::Ref(name));
                }
            }
            let errors = self.diagnostics.drain(start..).collect::<Vec<_>>();
            if best.as_ref().is_none_or(|old| errors.len() < old.len()) {
                best = Some(errors);
            }
        }
        if let Some(errors) = best {
            self.diagnostics.extend(errors);
        } else {
            self.field_error(
                diagnostic_code!("type.mismatch"),
                span,
                format!(
                    "constructor `{variant}` is not a payload variant of expected type {}",
                    type_label(&lower_type(expected.clone()))
                ),
                expected.span(),
            );
        }
        None
    }
}
