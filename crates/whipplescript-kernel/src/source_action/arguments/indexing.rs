//! Ready collection selection. The strict join owns waits and failure causes.
use super::*;

fn lookup<'a>(
    target: &'a Value,
    key: &Value,
) -> Result<(Option<&'a Value>, Option<String>), &'static str> {
    let (value, pointer) = match (target, key) {
        (Value::Object(object), Value::String(key)) => {
            (object.get(key), format!("/{}", subjects::token(key)))
        }
        (Value::Array(items), Value::Number(number)) if number.is_i64() || number.is_u64() => {
            let index = number
                .as_u64()
                .and_then(|index| usize::try_from(index).ok());
            (
                index.and_then(|index| items.get(index)),
                index.map_or(String::new(), |index| format!("/{index}")),
            )
        }
        (Value::Null, Value::String(_)) => (None, String::new()),
        (Value::Null, Value::Number(number)) if number.is_i64() || number.is_u64() => {
            (None, String::new())
        }
        (Value::Object(_), _) => {
            // MUTATION-SUCCESS-EXPR: Ok((None, None))
            return Err("map index requires a string key");
        }
        (Value::Array(_), _) => {
            // MUTATION-SUCCESS-EXPR: Ok((None, None))
            return Err("array index requires an integer key");
        }
        (Value::Null, _) => {
            // MUTATION-SUCCESS-EXPR: Ok((None, None))
            return Err("index key requires an integer or string");
        }
        _ => {
            // MUTATION-SUCCESS-EXPR: Ok((None, None))
            return Err("index target requires an array or map");
        }
    };
    Ok((value, value.map(|_| pointer)))
}

pub(super) fn evaluate(target: Evaluation, key: Evaluation) -> Evaluation {
    let selected = match (&target.state, &key.state) {
        (State::Ready(value), State::Ready(key)) => lookup(value, key)
            .ok()
            .and_then(|(_, pointer)| pointer)
            .map(|pointer| subjects::selected(&target.subjects, &pointer))
            .unwrap_or_default(),
        _ => FactSubjects::new(),
    };
    let mut result = strict(vec![target, key], |values| {
        match lookup(&values[0], &values[1]) {
            Ok((value, _)) => value.cloned().map_or(EvalValue::Missing, EvalValue::Json),
            Err(message) => EvalValue::error(message),
        }
    });
    if matches!(result.state, State::Ready(_)) {
        result.subjects = selected;
    }
    result
}
#[cfg(test)]
mod tests;
