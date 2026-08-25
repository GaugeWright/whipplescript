//! Review-grade diff over content-addressed manifests (untie-substrate
//! readiness tracker Phase 2: an against-target diff surface consumable
//! by an external UI — presentation quality, not just manifest delta).
//!
//! Pure and host-agnostic: two manifests + the content seam in,
//! structured per-path entries with line-level hunks out. Line diffs run
//! Myers' greedy O((N+M)D) algorithm on line boundaries with configurable
//! context; a side whose payload is unavailable (erased under the honesty
//! downgrade, or a hash the store no longer carries) degrades to an
//! honest hash-only entry — never a fabricated body.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::content::ContentBlobs;
use crate::StoreResult;

/// How one path changed between the two sides.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    Added,
    Removed,
    Modified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineTag {
    Context,
    Removed,
    Added,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiffLine {
    pub tag: LineTag,
    pub text: String,
}

/// One hunk: 1-based line starts and lengths on each side (unified-diff
/// `@@` semantics), with tagged lines including context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiffHunk {
    pub base_start: usize,
    pub base_len: usize,
    pub target_start: usize,
    pub target_len: usize,
    pub lines: Vec<DiffLine>,
}

/// One path's change: content hashes on both sides, plus hunks when both
/// payloads were readable. `payload_unavailable` marks the honest
/// degradation (an erased or missing blob): hashes and kind stand, hunks
/// are absent rather than invented.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiffEntry {
    pub path: String,
    pub kind: DiffKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hunks: Vec<DiffHunk>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub payload_unavailable: bool,
}

impl DiffEntry {
    /// Render this entry as unified-diff text (the human/UI fallback
    /// presentation; structured hunks are the primary surface).
    pub fn to_unified(&self) -> String {
        let mut out = String::new();
        let (from, to) = match self.kind {
            DiffKind::Added => ("/dev/null".to_owned(), format!("b/{}", self.path)),
            DiffKind::Removed => (format!("a/{}", self.path), "/dev/null".to_owned()),
            DiffKind::Modified => (format!("a/{}", self.path), format!("b/{}", self.path)),
        };
        out.push_str(&format!("--- {from}\n+++ {to}\n"));
        if self.payload_unavailable {
            out.push_str("(payload unavailable: hashes only)\n");
            return out;
        }
        for hunk in &self.hunks {
            out.push_str(&format!(
                "@@ -{},{} +{},{} @@\n",
                hunk.base_start, hunk.base_len, hunk.target_start, hunk.target_len
            ));
            for line in &hunk.lines {
                let sigil = match line.tag {
                    LineTag::Context => ' ',
                    LineTag::Removed => '-',
                    LineTag::Added => '+',
                };
                out.push(sigil);
                out.push_str(&line.text);
                out.push('\n');
            }
        }
        out
    }
}

/// Diff two manifests (base → target) through the content seam.
/// `context` = context lines per hunk (unified-diff convention: 3).
pub fn diff_manifests(
    base: &BTreeMap<String, String>,
    target: &BTreeMap<String, String>,
    content: &dyn ContentBlobs,
    context: usize,
) -> StoreResult<Vec<DiffEntry>> {
    let mut entries = Vec::new();
    let mut paths: Vec<&String> = base.keys().chain(target.keys()).collect();
    paths.sort();
    paths.dedup();
    for path in paths {
        let base_hash = base.get(path);
        let target_hash = target.get(path);
        let (kind, base_body, target_body) = match (base_hash, target_hash) {
            (None, None) => continue,
            (Some(b), Some(t)) if b == t => continue,
            (None, Some(t)) => (DiffKind::Added, None, content.get(t)?),
            (Some(b), None) => (DiffKind::Removed, content.get(b)?, None),
            (Some(b), Some(t)) => (DiffKind::Modified, content.get(b)?, content.get(t)?),
        };
        // A side that SHOULD have a payload but doesn't is the honest
        // degradation; a side absent from the manifest is simply empty.
        let payload_unavailable = (base_hash.is_some() && base_body.is_none())
            || (target_hash.is_some() && target_body.is_none());
        let hunks = if payload_unavailable {
            Vec::new()
        } else {
            hunks_between(
                base_body.as_deref().unwrap_or(""),
                target_body.as_deref().unwrap_or(""),
                context,
            )
        };
        entries.push(DiffEntry {
            path: path.clone(),
            kind,
            base_hash: base_hash.cloned(),
            target_hash: target_hash.cloned(),
            hunks,
            payload_unavailable,
        });
    }
    Ok(entries)
}

/// Line-level hunks between two bodies.
pub fn hunks_between(base: &str, target: &str, context: usize) -> Vec<DiffHunk> {
    let base_lines: Vec<&str> = base.lines().collect();
    let target_lines: Vec<&str> = target.lines().collect();
    let script = myers_diff(&base_lines, &target_lines);
    build_hunks(&script, context)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Edit<'a> {
    Keep(&'a str),
    Remove(&'a str),
    Add(&'a str),
}

/// Myers' greedy shortest-edit-script diff, O((N+M)D): the forward pass
/// keeps a per-round snapshot of the furthest-x frontier (`trace`), and
/// the backtrack walks rounds in reverse — `trace[d]` holds round d-1's
/// frontier, exactly what round d's endpoints extended from.
///
/// Each snapshot is only the LIVE BAND, `k` in `[-d, d]`, not the whole
/// `2(N+M)+1` frontier: round d can have reached no further diagonal, and the
/// backtrack reads no further than one diagonal either side of its own. Storing
/// the whole vector made the trace O(D·(N+M)) — for two wholly different large
/// files, tens of gigabytes copied — where the band is O(D²).
fn myers_diff<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<Edit<'a>> {
    let n = a.len() as isize;
    let m = b.len() as isize;
    let max = n + m;
    if max == 0 {
        return Vec::new();
    }
    // An empty side admits exactly one edit script — every line of the other
    // side, in order — so the general search has nothing to decide. Taking it
    // anyway costs O(m²): the frontier walks d out to m, banding a fresh
    // `2d+1` snapshot every round. This is the common case rather than a
    // corner one — an added or removed file diffs against an empty side, and a
    // whole-branch diff reports every path that way.
    if a.is_empty() {
        return b.iter().map(|line| Edit::Add(line)).collect();
    }
    if b.is_empty() {
        return a.iter().map(|line| Edit::Remove(line)).collect();
    }
    let offset = max;
    let width = (2 * max + 1) as usize;
    let mut v = vec![0isize; width];
    let mut trace: Vec<Vec<isize>> = Vec::new();
    'outer: for d in 0..=max {
        trace.push(v[(offset - d) as usize..=(offset + d) as usize].to_vec());
        let mut k = -d;
        while k <= d {
            let idx = (k + offset) as usize;
            let mut x = if k == -d || (k != d && v[idx - 1] < v[idx + 1]) {
                v[idx + 1]
            } else {
                v[idx - 1] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[idx] = x;
            if x >= n && y >= m {
                break 'outer;
            }
            k += 2;
        }
    }
    // Backtrack from (n, m) through each round's frontier.
    let mut edits = Vec::new();
    let mut x = n;
    let mut y = m;
    for d in (1..trace.len()).rev() {
        let d_i = d as isize;
        // The band is centred on k = 0 with radius d, so a diagonal's slot is
        // `k + d` rather than `k + offset`.
        let band = &trace[d];
        let k = x - y;
        let idx = (k + d_i) as usize;
        let prev_k = if k == -d_i || (k != d_i && band[idx - 1] < band[idx + 1]) {
            k + 1
        } else {
            k - 1
        };
        let prev_idx = (prev_k + d_i) as usize;
        let prev_x = band[prev_idx];
        let prev_y = prev_x - prev_k;
        // The snake (shared lines) this round rode after its edit step.
        while x > prev_x && y > prev_y {
            x -= 1;
            y -= 1;
            edits.push(Edit::Keep(a[x as usize]));
        }
        // The edit step itself: a down-move from k+1 inserts, a
        // right-move from k-1 removes.
        if prev_k == k + 1 {
            edits.push(Edit::Add(b[prev_y as usize]));
        } else {
            edits.push(Edit::Remove(a[prev_x as usize]));
        }
        x = prev_x;
        y = prev_y;
    }
    // Round 0's leading diagonal.
    while x > 0 && y > 0 {
        x -= 1;
        y -= 1;
        edits.push(Edit::Keep(a[x as usize]));
    }
    debug_assert!(x == 0 && y == 0, "backtrack must land at the origin");
    edits.reverse();
    edits
}

/// Group an edit script into hunks with `context` lines of surround.
fn build_hunks(script: &[Edit<'_>], context: usize) -> Vec<DiffHunk> {
    // Positions of non-keep edits in the script.
    let change_positions: Vec<usize> = script
        .iter()
        .enumerate()
        .filter(|(_, edit)| !matches!(edit, Edit::Keep(_)))
        .map(|(index, _)| index)
        .collect();
    if change_positions.is_empty() {
        return Vec::new();
    }
    // Merge changes whose context windows touch into ranges.
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for &position in &change_positions {
        let start = position.saturating_sub(context);
        let end = (position + context + 1).min(script.len());
        match ranges.last_mut() {
            Some((_, last_end)) if start <= *last_end => *last_end = end,
            _ => ranges.push((start, end)),
        }
    }
    // Walk the script once, tracking 1-based line cursors on both sides.
    let mut hunks = Vec::new();
    let mut base_line = 1usize;
    let mut target_line = 1usize;
    let mut cursor = 0usize;
    for (start, end) in ranges {
        while cursor < start {
            match script[cursor] {
                Edit::Keep(_) => {
                    base_line += 1;
                    target_line += 1;
                }
                Edit::Remove(_) => base_line += 1,
                Edit::Add(_) => target_line += 1,
            }
            cursor += 1;
        }
        let base_start = base_line;
        let target_start = target_line;
        let mut lines = Vec::new();
        while cursor < end {
            let (tag, text) = match script[cursor] {
                Edit::Keep(text) => {
                    base_line += 1;
                    target_line += 1;
                    (LineTag::Context, text)
                }
                Edit::Remove(text) => {
                    base_line += 1;
                    (LineTag::Removed, text)
                }
                Edit::Add(text) => {
                    target_line += 1;
                    (LineTag::Added, text)
                }
            };
            lines.push(DiffLine {
                tag,
                text: text.to_owned(),
            });
            cursor += 1;
        }
        hunks.push(DiffHunk {
            base_start,
            base_len: base_line - base_start,
            target_start,
            target_len: target_line - target_start,
            lines,
        });
    }
    hunks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(hunk: &DiffHunk) -> String {
        hunk.lines
            .iter()
            .map(|line| match line.tag {
                LineTag::Context => ' ',
                LineTag::Removed => '-',
                LineTag::Added => '+',
            })
            .collect()
    }

    #[test]
    fn modified_line_produces_one_hunk_with_context() {
        let base = "a\nb\nc\nd\ne\nf\ng\n";
        let target = "a\nb\nc\nD\ne\nf\ng\n";
        let hunks = hunks_between(base, target, 2);
        assert_eq!(hunks.len(), 1);
        let hunk = &hunks[0];
        assert_eq!(hunk.base_start, 2);
        assert_eq!(hunk.target_start, 2);
        assert_eq!(hunk.base_len, 5);
        assert_eq!(hunk.target_len, 5);
        assert_eq!(tags(hunk), "  -+  ");
    }

    #[test]
    fn distant_changes_produce_separate_hunks() {
        let base = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n";
        let target = "1\nTWO\n3\n4\n5\n6\n7\n8\n9\n10\nELEVEN\n12\n";
        let hunks = hunks_between(base, target, 1);
        assert_eq!(hunks.len(), 2);
        assert_eq!(hunks[0].base_start, 1);
        assert_eq!(tags(&hunks[0]), " -+ ");
        assert_eq!(hunks[1].base_start, 10);
        assert_eq!(tags(&hunks[1]), " -+ ");
    }

    #[test]
    fn pure_insertion_and_deletion_and_empty_sides() {
        let hunks = hunks_between("", "new\n", 3);
        assert_eq!(hunks.len(), 1);
        assert_eq!(tags(&hunks[0]), "+");
        assert_eq!(hunks[0].base_len, 0);
        assert_eq!(hunks[0].target_len, 1);
        let hunks = hunks_between("old\n", "", 3);
        assert_eq!(tags(&hunks[0]), "-");
        assert!(hunks_between("same\n", "same\n", 3).is_empty());
        assert!(hunks_between("", "", 3).is_empty());
    }

    /// The edit script is minimal-ish and, crucially, CORRECT: applying
    /// it to the base reproduces the target for a batch of shapes.
    #[test]
    fn edit_script_reconstructs_the_target() {
        let cases = [
            ("a\nb\nc\n", "a\nx\nc\n"),
            ("a\nb\nc\nd\n", "b\nc\nd\ne\n"),
            ("x\ny\nz\n", "a\nb\nc\n"),
            ("common\n", "common\nadded\n"),
            ("a\nb\na\nb\na\n", "b\na\nb\na\nb\n"),
            ("1\n2\n3\n4\n5\n", "1\n3\n5\n"),
            ("1\n3\n5\n", "1\n2\n3\n4\n5\n"),
        ];
        for (base, target) in cases {
            let base_lines: Vec<&str> = base.lines().collect();
            let target_lines: Vec<&str> = target.lines().collect();
            let script = myers_diff(&base_lines, &target_lines);
            let mut rebuilt_base = Vec::new();
            let mut rebuilt_target = Vec::new();
            for edit in &script {
                match edit {
                    Edit::Keep(text) => {
                        rebuilt_base.push(*text);
                        rebuilt_target.push(*text);
                    }
                    Edit::Remove(text) => rebuilt_base.push(*text),
                    Edit::Add(text) => rebuilt_target.push(*text),
                }
            }
            assert_eq!(rebuilt_base, base_lines, "base for {base:?} -> {target:?}");
            assert_eq!(
                rebuilt_target, target_lines,
                "target for {base:?} -> {target:?}"
            );
        }
    }

    /// The same correctness property over generated pairs, which is what keeps
    /// the banded trace honest: a mis-indexed backtrack yields a script that is
    /// plausible line by line and still rebuilds the wrong sides, and the fixed
    /// cases above are too shallow to reach the deeper rounds.
    #[test]
    fn generated_pairs_also_reconstruct_both_sides() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for case in 0..200 {
            let alphabet = 2 + (case % 5);
            let base_len = (next() % 40) as usize;
            let target_len = (next() % 40) as usize;
            let base: Vec<String> = (0..base_len)
                .map(|_| format!("line_{}", next() % alphabet))
                .collect();
            let target: Vec<String> = (0..target_len)
                .map(|_| format!("line_{}", next() % alphabet))
                .collect();
            let base_lines: Vec<&str> = base.iter().map(String::as_str).collect();
            let target_lines: Vec<&str> = target.iter().map(String::as_str).collect();
            let script = myers_diff(&base_lines, &target_lines);

            let mut rebuilt_base = Vec::new();
            let mut rebuilt_target = Vec::new();
            for edit in &script {
                match edit {
                    Edit::Keep(text) => {
                        rebuilt_base.push(*text);
                        rebuilt_target.push(*text);
                    }
                    Edit::Remove(text) => rebuilt_base.push(*text),
                    Edit::Add(text) => rebuilt_target.push(*text),
                }
            }
            assert_eq!(rebuilt_base, base_lines, "base for case {case}");
            assert_eq!(rebuilt_target, target_lines, "target for case {case}");
        }
    }

    #[cfg(feature = "native")]
    #[test]
    fn manifest_diff_reports_kinds_and_honest_unavailability() {
        let dir = std::env::temp_dir().join(format!(
            "whipplescript-diff-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        let content = crate::content::ContentStore::open(dir.join("content.sqlite"))
            .expect("open content store");
        let old_hash = content.put("line one\nline two\n").expect("put");
        let new_hash = content.put("line one\nline 2\n").expect("put");
        let added_hash = content.put("brand new\n").expect("put");
        let mut base = BTreeMap::new();
        base.insert("mod.md".to_owned(), old_hash.clone());
        base.insert("gone.md".to_owned(), old_hash.clone());
        base.insert("lost.md".to_owned(), "hash-that-does-not-exist".to_owned());
        let mut target = BTreeMap::new();
        target.insert("mod.md".to_owned(), new_hash);
        target.insert("new.md".to_owned(), added_hash);
        let entries = diff_manifests(&base, &target, &content, 3).expect("diff");
        let by_path: BTreeMap<&str, &DiffEntry> = entries
            .iter()
            .map(|entry| (entry.path.as_str(), entry))
            .collect();
        assert_eq!(by_path["gone.md"].kind, DiffKind::Removed);
        assert_eq!(by_path["new.md"].kind, DiffKind::Added);
        assert_eq!(by_path["mod.md"].kind, DiffKind::Modified);
        assert_eq!(by_path["mod.md"].hunks.len(), 1);
        // The missing-payload side degrades honestly: hashes, no hunks.
        assert!(by_path["lost.md"].payload_unavailable);
        assert!(by_path["lost.md"].hunks.is_empty());
        // Unified rendering round-trips the shape.
        let unified = by_path["mod.md"].to_unified();
        assert!(unified.contains("--- a/mod.md"));
        assert!(unified.contains("-line two"));
        assert!(unified.contains("+line 2"));
    }
}
