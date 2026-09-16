//! Symbolic subject expressions. Shared subtrees keep helper summaries compact;
//! substitution never promotes a record type or a provenance reference.
use super::*;
use std::rc::Rc;

pub(super) type Value = Rc<Shape>;
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Scalar {
    Null,
    String(String),
    Other,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Shape {
    Parameter {
        index: usize,
        ty: IrType,
        span: SourceSpan,
    },
    Fact {
        schema: String,
        span: SourceSpan,
    },
    Data {
        scalar: Scalar,
        span: SourceSpan,
        reason: &'static str,
    },
    Object {
        fields: BTreeMap<String, Value>,
        span: SourceSpan,
    },
    Array {
        items: Vec<Value>,
        span: SourceSpan,
    },
    Select {
        target: Value,
        key: Value,
        span: SourceSpan,
    },
    Narrow {
        value: Value,
        pattern: String,
        span: SourceSpan,
    },
    Alternatives(Vec<Value>),
    Unknown {
        span: SourceSpan,
        reason: &'static str,
    },
    Never,
}
pub(super) fn data(span: SourceSpan, reason: &'static str) -> Value {
    Rc::new(Shape::Data {
        scalar: Scalar::Other,
        span,
        reason,
    })
}
pub(super) fn absent(span: SourceSpan) -> Value {
    Rc::new(Shape::Data {
        scalar: Scalar::Null,
        span,
        reason: "this value can be absent",
    })
}
pub(super) fn string(value: &str, span: SourceSpan) -> Value {
    Rc::new(Shape::Data {
        scalar: Scalar::String(value.into()),
        span,
        reason: "a string is an ordinary value",
    })
}
pub(super) fn alternatives(values: impl IntoIterator<Item = Value>) -> Value {
    let mut out = Vec::new();
    let mut pending: Vec<_> = values.into_iter().collect();
    while let Some(value) = pending.pop() {
        match value.as_ref() {
            Shape::Never => {}
            Shape::Alternatives(items) => pending.extend(items.iter().cloned()),
            _ => {
                if !out.contains(&value) {
                    out.push(value);
                }
            }
        }
    }
    out.reverse();
    match out.len() {
        0 => Rc::new(Shape::Never),
        1 => out.pop().expect("one alternative"),
        _ => Rc::new(Shape::Alternatives(out)),
    }
}
pub(super) fn select(target: Value, key: Value, span: SourceSpan) -> Value {
    let literal = match key.as_ref() {
        Shape::Data {
            scalar: Scalar::String(key),
            ..
        } => Some(key),
        _ => None,
    };
    match target.as_ref() {
        Shape::Never => target,
        Shape::Alternatives(items) => alternatives(
            items
                .iter()
                .map(|item| select(item.clone(), key.clone(), span)),
        ),
        Shape::Fact { .. } => data(
            span,
            "a field of a matched fact is data, not the matched fact",
        ),
        Shape::Object { fields, .. } => {
            if let Some(key) = literal {
                return fields.get(key).cloned().unwrap_or_else(|| absent(span));
            }
            if parameters(&key).is_empty() {
                return alternatives(
                    fields
                        .values()
                        .cloned()
                        .chain(std::iter::once(absent(span))),
                );
            }
            Rc::new(Shape::Select { target, key, span })
        }
        Shape::Data {
            scalar: Scalar::Null | Scalar::String(_),
            ..
        } => absent(span),
        Shape::Data { .. } => data(
            span,
            "selecting ordinary data does not create a fact identity",
        ),
        Shape::Array { .. } => Rc::new(Shape::Unknown {
            span,
            reason: "array indexing has no managed fact-subject contract",
        }),
        Shape::Unknown { .. } => target,
        _ => Rc::new(Shape::Select { target, key, span }),
    }
}
pub(super) fn narrow(value: Value, pattern: &str, span: SourceSpan) -> Value {
    match value.as_ref() {
        Shape::Never => value,
        Shape::Alternatives(items) => {
            alternatives(items.iter().map(|item| narrow(item.clone(), pattern, span)))
        }
        _ if matches!(pattern, "_" | "default") => value,
        Shape::Data {
            scalar: Scalar::Null,
            ..
        } => {
            if pattern == "None" {
                value
            } else {
                Rc::new(Shape::Never)
            }
        }
        _ if pattern == "None" => absent(span),
        Shape::Fact { schema, .. } if pattern != "Some" && schema != pattern => {
            Rc::new(Shape::Never)
        }
        Shape::Parameter { .. } | Shape::Select { .. } | Shape::Narrow { .. } => {
            Rc::new(Shape::Narrow {
                value,
                pattern: pattern.into(),
                span,
            })
        }
        _ => value,
    }
}
fn children(value: &Value) -> Vec<Value> {
    match value.as_ref() {
        Shape::Object { fields, .. } => fields.values().cloned().collect(),
        Shape::Array { items, .. } | Shape::Alternatives(items) => items.clone(),
        Shape::Select { target, key, .. } => vec![target.clone(), key.clone()],
        Shape::Narrow { value, .. } => vec![value.clone()],
        _ => Vec::new(),
    }
}
fn key(value: &Value) -> usize {
    Rc::as_ptr(value) as usize
}
pub(super) fn parameters(value: &Value) -> BTreeSet<usize> {
    let mut found = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut pending = vec![value.clone()];
    while let Some(value) = pending.pop() {
        if !seen.insert(key(&value)) {
            continue;
        }
        if let Shape::Parameter { index, .. } = value.as_ref() {
            found.insert(*index);
        }
        pending.extend(children(&value));
    }
    found
}
/// Rebuild a shared DAG once, with an explicit stack for long finite helpers.
pub(super) fn substitute(value: &Value, arguments: &[Value]) -> Value {
    let mut memo = BTreeMap::<usize, Value>::new();
    let mut pending = vec![(value.clone(), false)];
    while let Some((value, ready)) = pending.pop() {
        if memo.contains_key(&key(&value)) {
            continue;
        }
        if !ready {
            pending.push((value.clone(), true));
            pending.extend(children(&value).into_iter().map(|child| (child, false)));
            continue;
        }
        let get = |value: &Value| memo[&key(value)].clone();
        let replaced = match value.as_ref() {
            Shape::Parameter { index, .. } => arguments[*index].clone(),
            Shape::Object { fields, span } => Rc::new(Shape::Object {
                fields: fields
                    .iter()
                    .map(|(name, value)| (name.clone(), get(value)))
                    .collect(),
                span: *span,
            }),
            Shape::Array { items, span } => Rc::new(Shape::Array {
                items: items.iter().map(get).collect(),
                span: *span,
            }),
            Shape::Select { target, key, span } => select(get(target), get(key), *span),
            Shape::Narrow {
                value,
                pattern,
                span,
            } => narrow(get(value), pattern, *span),
            Shape::Alternatives(items) => alternatives(items.iter().map(get)),
            _ => value.clone(),
        };
        memo.insert(key(&value), replaced);
    }
    memo[&key(value)].clone()
}
pub(super) fn possible_fact(value: &Value, semantic: &SemanticContext) -> bool {
    fn ty(value: &Value, semantic: &SemanticContext) -> Option<IrType> {
        match value.as_ref() {
            Shape::Parameter { ty, .. } => Some(ty.clone()),
            Shape::Narrow { pattern, value, .. } if pattern == "Some" => match ty(value, semantic)?
            {
                IrType::Optional(inner) => Some(*inner),
                other => Some(other),
            },
            Shape::Narrow { pattern, .. } if semantic.schemas.class_exists(pattern) => {
                Some(IrType::Ref(pattern.clone()))
            }
            Shape::Select { target, key, .. } => match key.as_ref() {
                Shape::Data {
                    scalar: Scalar::String(name),
                    ..
                } => action_types::field_type(
                    &ty(target, semantic)?,
                    std::slice::from_ref(name),
                    semantic,
                ),
                _ => match ty(target, semantic)? {
                    IrType::Map(inner) => Some(*inner),
                    _ => None,
                },
            },
            _ => None,
        }
    }
    fn permits(ty: &IrType, semantic: &SemanticContext) -> bool {
        match ty {
            IrType::Ref(name) => semantic.schemas.class_exists(name),
            IrType::Optional(inner) => permits(inner, semantic),
            IrType::Union(items) => items.iter().any(|item| permits(item, semantic)),
            _ => false,
        }
    }
    ty(value, semantic).is_none_or(|ty| permits(&ty, semantic))
}
