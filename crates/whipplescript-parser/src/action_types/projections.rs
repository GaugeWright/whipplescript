//! Pure field projection shares the lexical type and presence proof of a read.
use super::*;
use environment::ReadFailure;

pub(super) enum Failure {
    Source,
    Repeated(String),
    Field(String, ReadFailure),
}

fn record(ty: &IrType, semantic: &SemanticContext) -> bool {
    match ty {
        IrType::Ref(name) => semantic.schemas.classes.contains_key(name),
        IrType::Object(_) => true,
        IrType::Union(variants) => {
            !variants.is_empty() && variants.iter().all(|ty| record(ty, semantic))
        }
        _ => false,
    }
}

impl Checker<'_> {
    pub(super) fn redact_type(
        &self,
        source: &str,
        keep: &[String],
        environment: &Environment,
        span: SourceSpan,
    ) -> Result<IrType, Failure> {
        let ty = environment.get(source).and_then(Option::as_ref);
        if !ty.is_some_and(|ty| record(ty, self.semantic)) {
            return Err(Failure::Source);
        }
        let mut seen: BTreeSet<&String> = BTreeSet::new();
        let mut fields = Vec::new();
        for field in keep {
            if !seen.insert(field) {
                return Err(Failure::Repeated(field.clone()));
            }
            let ty = environment
                .read_path(&[source.into(), field.clone()], self.semantic)
                .map_err(|failure| Failure::Field(field.clone(), failure))?;
            fields.push(IrClassField {
                name: field.clone(),
                ty,
                span,
                is_key: false,
                presence_condition: None,
            });
        }
        Ok(IrType::Object(fields))
    }

    pub(super) fn check_redact(
        &mut self,
        source: &str,
        keep: &[String],
        environment: &Environment,
        span: SourceSpan,
    ) {
        let message = match self.redact_type(source, keep, environment, span) {
            Ok(_) => return,
            Err(Failure::Source) => {
                format!("redact source `{source}` must be a present record value")
            }
            Err(Failure::Repeated(field)) => format!("redact keep list repeats field `{field}`"),
            Err(Failure::Field(field, failure)) => {
                let before = self.diagnostics.len();
                self.path_error(
                    failure,
                    &[source.to_owned(), field.clone()],
                    environment,
                    span,
                );
                if self.diagnostics.len() != before {
                    return;
                }
                format!("cannot keep unavailable field `{field}` from `{source}`")
            }
        };
        self.diagnostics.push(Diagnostic::error(
            diagnostic_code!("type.mismatch"),
            span,
            message,
        ));
    }
}

#[cfg(test)]
mod tests;
