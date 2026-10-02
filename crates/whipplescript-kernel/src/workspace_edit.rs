//! Pure workspace edit semantics shared by native and hosted tools.
//! Admission, reading and write-on-success remain the host's responsibility.
use serde_json::Value;

/// Apply an ordered edit array, preserving a leading BOM and refusing edits
/// that rewrite an earlier edit's output. Errors produce no output to write.
pub fn apply_edits(
    mut content: String,
    path: &str,
    edits: &[Value],
) -> Result<(String, usize), String> {
    // Match without a leading UTF-8 BOM and restore it on output.
    const BOM: &str = "\u{feff}";
    let had_bom = content.starts_with(BOM);
    if had_bom {
        content = content[BOM.len()..].to_string();
    }
    // Regions already rewritten, in current-content coordinates (with the edit
    // index that produced them). A later edit whose match intersects one is
    // editing an earlier edit's output — almost always a model mistake.
    let mut replaced: Vec<(usize, std::ops::Range<usize>)> = Vec::new();
    let mut applied = 0usize;
    for (index, edit) in edits.iter().enumerate() {
        let old = text_argument(edit, "oldText")?;
        let new = text_argument(edit, "newText")?;
        if old.is_empty() {
            return Err(format!("edit {index}: oldText must not be empty"));
        }
        let mut matches = content.match_indices(old);
        let Some((start, _)) = matches.next() else {
            return Err(format!("edit {index}: oldText not found in `{path}`"));
        };
        let matches = 1 + matches.count();
        if matches > 1 {
            return Err(format!(
                "edit {index}: oldText matches {matches} times in `{path}`; make it unique"
            ));
        }
        let end = start + old.len();
        for (earlier, region) in &replaced {
            if start < region.end && region.start < end {
                return Err(format!(
                    "edit {earlier} and edit {index} overlap in `{path}`; merge them \
                         into one edit or target disjoint regions"
                ));
            }
        }
        content.replace_range(start..end, new);
        // Shift the recorded regions that sit after the splice point.
        let delta = new.len() as isize - old.len() as isize;
        for (_, region) in replaced.iter_mut() {
            if region.start >= end {
                region.start = (region.start as isize + delta) as usize;
                region.end = (region.end as isize + delta) as usize;
            }
        }
        replaced.push((index, start..start + new.len()));
        applied += 1;
    }
    let output = if had_bom {
        format!("{BOM}{content}")
    } else {
        content
    };
    Ok((output, applied))
}

fn text_argument<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing required string argument `{name}`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ws331_edit_validation_keeps_canonical_refusals() {
        for (edits, expected) in [
            (json!([{}]), "missing required string argument `oldText`"),
            (
                json!([{"oldText":"x"}]),
                "missing required string argument `newText`",
            ),
            (
                json!([{"oldText":"", "newText":"y"}]),
                "edit 0: oldText must not be empty",
            ),
            (
                json!([{"oldText":"z", "newText":"y"}]),
                "edit 0: oldText not found in `e.txt`",
            ),
            (
                json!([{"oldText":"x", "newText":"y"}]),
                "edit 0: oldText matches 2 times in `e.txt`; make it unique",
            ),
        ] {
            assert_eq!(
                apply_edits("x x".into(), "e.txt", edits.as_array().unwrap()).unwrap_err(),
                expected
            );
        }
        let overlapping = json!([
            {"oldText":"alpha beta", "newText":"alpha beta"},
            {"oldText":"beta gamma", "newText":"BETA gamma"}
        ]);
        assert_eq!(
            apply_edits("alpha beta gamma".into(), "e.txt", overlapping.as_array().unwrap()).unwrap_err(),
            "edit 0 and edit 1 overlap in `e.txt`; merge them into one edit or target disjoint regions"
        );
        assert_eq!(
            apply_edits("\u{feff}unchanged".into(), "e.txt", &[]).unwrap(),
            ("\u{feff}unchanged".into(), 0)
        );
    }
}
