//! Collection reads prove key compatibility and retain possible absence.
use super::*;

pub(super) fn literal_index(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::Literal(ExprLiteral::Number(value)) => value.parse().ok(),
        _ => None,
    }
}
fn optional(ty: IrType) -> IrType {
    if is_null(&ty) || matches!(ty, IrType::Optional(_)) {
        ty
    } else {
        IrType::Optional(Box::new(ty))
    }
}
fn result(target: &IrType, key: &IrType, semantic: &SemanticContext) -> Result<IrType, String> {
    let mut pending = vec![target];
    let mut members = Vec::new();
    while let Some(target) = pending.pop() {
        match target {
            IrType::Optional(inner) => pending.push(inner),
            IrType::Union(variants) => pending.extend(variants.iter().rev()),
            ty if is_null(ty) => {}
            IrType::Array(inner) | IrType::Map(inner) => {
                let (family, expected) = if matches!(target, IrType::Array(_)) {
                    ("array", IrPrimitiveType::Int)
                } else {
                    ("map", IrPrimitiveType::String)
                };
                if !assignable(key, &primitive(expected.clone()), semantic) {
                    let message = format!(
                        "{family} index requires {}, got {}",
                        type_label(&primitive(expected)),
                        type_label(key)
                    );
                    // MUTATION-SUCCESS-EXPR: Ok(optional((**inner).clone()))
                    return Err(message);
                }
                members.push((**inner).clone());
            }
            _ => {
                let message = format!(
                    "cannot index {}; expected an array or map",
                    type_label(target)
                );
                // MUTATION-SUCCESS-EXPR: Ok(primitive(IrPrimitiveType::Null))
                return Err(message);
            }
        }
    }
    if members.is_empty() {
        // MUTATION-SUCCESS-EXPR: Ok(primitive(IrPrimitiveType::Null))
        return Err("indexed target has no array or map value type".into());
    }
    let ty = if members.len() == 1 {
        members.remove(0)
    } else {
        IrType::Union(members)
    };
    Ok(optional(ty))
}
impl Checker<'_> {
    pub(super) fn indexed(
        &mut self,
        target: &Expr,
        key: &Expr,
        span: SourceSpan,
        environment: &Environment,
    ) -> Option<IrType> {
        // Resolve the whole constructed array first. A selected element does
        // not erase evaluation/type obligations on its strict siblings.
        let target_type = self.infer_node(target, span, environment)?;
        let key_type = self.infer_node(key, span, environment)?;
        let inferred = match result(&target_type, &key_type, self.semantic) {
            Ok(ty) => ty,
            Err(message) => {
                self.diagnostics.push(Diagnostic::error(
                    diagnostic_code!("type.mismatch"),
                    span,
                    message,
                ));
                return None;
            }
        };
        if let (Expr::Array(items), Some(index)) = (target, literal_index(key)) {
            return match usize::try_from(index)
                .ok()
                .and_then(|index| items.get(index))
            {
                Some(item) => self.infer_node(item, span, environment),
                None => Some(primitive(IrPrimitiveType::Null)),
            };
        }
        Some(inferred)
    }
}

#[cfg(test)]
mod tests;
