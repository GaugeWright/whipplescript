//! Exact subvalue subjects. Source provenance alone never creates an entry.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactSubject {
    pub fact_id: String,
    pub admission_event: String,
}

pub type FactSubjects = BTreeMap<String, FactSubject>;

pub(super) fn token(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

pub(crate) fn nested(subjects: &FactSubjects, key: &str) -> FactSubjects {
    let prefix = format!("/{}", token(key));
    subjects
        .iter()
        .map(|(path, subject)| (format!("{prefix}{path}"), subject.clone()))
        .collect()
}

pub(super) fn selected(subjects: &FactSubjects, path: &str) -> FactSubjects {
    let prefix = format!("{path}/");
    subjects
        .iter()
        .filter_map(|(candidate, subject)| {
            if candidate == path {
                Some((String::new(), subject.clone()))
            } else if candidate.starts_with(&prefix) {
                Some((candidate[path.len()..].to_owned(), subject.clone()))
            } else {
                None
            }
        })
        .collect()
}

fn exists(value: &Value, pointer: &str) -> bool {
    if pointer.is_empty() {
        return true;
    }
    let Some(path) = pointer.strip_prefix('/') else {
        return false;
    };
    let mut value = value;
    for raw in path.split('/') {
        let key = raw.replace("~1", "/").replace("~0", "~");
        if token(&key) != raw {
            return false;
        }
        let next = match value {
            Value::Object(fields) => fields.get(&key),
            Value::Array(items) => key
                .parse::<usize>()
                .ok()
                .filter(|index| index.to_string() == key)
                .and_then(|index| items.get(index)),
            _ => None,
        };
        let Some(next) = next else {
            return false;
        };
        value = next;
    }
    true
}

pub(crate) fn validate(argument: &Argument) -> Result<(), String> {
    for (path, subject) in &argument.subjects {
        if !exists(&argument.value, path) {
            return Err("action fact subject does not name a canonical existing subvalue".into());
        }
        if subject.fact_id.is_empty() || subject.admission_event.is_empty() {
            return Err("action fact subject has an incomplete admission identity".into());
        }
        if !argument.sources.contains(&ValueSource::Fact {
            fact_id: subject.fact_id.clone(),
            admission_event: subject.admission_event.clone(),
        }) {
            return Err("action fact subject is absent from its fact source references".into());
        }
    }
    Ok(())
}
