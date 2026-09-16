//! Absence is one alternative of a successful value, never pending or failure.
use super::*;

pub(super) fn pattern_is_null(pattern: &str, ty: Option<&IrType>) -> bool {
    matches!(
        parse_expression(pattern),
        Ok(Expr::Literal(ExprLiteral::Null))
    ) || ty.is_some_and(|ty| optional_presence(ty, pattern) == Some(PresencePattern::Absent))
}

// Partition only the outer value. A nullable array element says nothing about
// whether the array itself exists; sealed values retain their full contract.
fn partition(ty: &IrType, absent: &mut bool, present: &mut Vec<IrType>) {
    match ty {
        ty if is_null(ty) => *absent = true,
        IrType::Optional(inner) => {
            *absent = true;
            partition(inner, absent, present);
        }
        IrType::Union(variants) => {
            for variant in variants {
                partition(variant, absent, present);
            }
        }
        _ => present.push(ty.clone()),
    }
}

pub(super) fn select(ty: &IrType, keep_null: bool, keep_present: bool) -> IrType {
    if keep_null && keep_present {
        return ty.clone();
    }
    let mut absent = false;
    let mut present = Vec::new();
    partition(ty, &mut absent, &mut present);
    if !keep_present {
        present.clear();
    }
    if keep_null && absent {
        present.push(primitive(IrPrimitiveType::Null));
    }
    if present.len() == 1 {
        present.remove(0)
    } else {
        IrType::Union(present)
    }
}

pub(super) fn guard(ty: &IrType, expr: &Expr, path: &[String]) -> IrType {
    let possible = |absent| {
        guard_truth(expr, &|left, right| {
            let null = |expr: &Expr| matches!(expr, Expr::Literal(ExprLiteral::Null));
            if (value_path(left).as_deref() == Some(path) && null(right))
                || (value_path(right).as_deref() == Some(path) && null(left))
            {
                Some(absent)
            } else {
                None
            }
        }) != Some(false)
    };
    select(ty, possible(true), possible(false))
}
