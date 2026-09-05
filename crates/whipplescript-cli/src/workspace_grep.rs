//! The workspace `grep` tool's matching semantics, in one place.
//!
//! This tool is implemented on both sides of a crate boundary —
//! `host_runtime` in the library, `harness_tools` in the binary — and the two
//! copies did not agree. The library's read only `pattern` and `path`, so a
//! caller passing `ignoreCase`, `context` or `limit` (all three declared by the
//! very schema that implementation advertises) got a case-sensitive,
//! contextless search under a different cap, and nothing said so. A schema is a
//! contract; silently ignoring three of its five properties is the tool
//! answering a question it was not asked.
//!
//! The crate boundary is why there were two copies rather than one, so the
//! shared half lives here, below both.

/// How many characters of a matching line are echoed before truncation.
const GREP_MAX_LINE_CHARS: usize = 500;

/// A compiled pattern, or a literal fallback.
///
/// An invalid regex is deliberately NOT an error: users paste literal code
/// fragments (`foo(`, `a[0]`) as patterns and expect a lenient literal search,
/// so a compile failure degrades to substring matching.
pub enum GrepMatcher {
    Regex(regex::Regex),
    Literal { needle: String, ignore_case: bool },
}

impl GrepMatcher {
    #[must_use]
    pub fn new(pattern: &str, ignore_case: bool) -> Self {
        match regex::RegexBuilder::new(pattern)
            .case_insensitive(ignore_case)
            .build()
        {
            Ok(regex) => Self::Regex(regex),
            Err(_) => Self::Literal {
                needle: if ignore_case {
                    pattern.to_lowercase()
                } else {
                    pattern.to_owned()
                },
                ignore_case,
            },
        }
    }

    #[must_use]
    pub fn is_match(&self, line: &str) -> bool {
        match self {
            Self::Regex(regex) => regex.is_match(line),
            Self::Literal {
                needle,
                ignore_case,
            } => {
                if *ignore_case {
                    line.to_lowercase().contains(needle)
                } else {
                    line.contains(needle)
                }
            }
        }
    }
}

#[must_use]
pub fn cap_grep_line(line: &str) -> String {
    match line.char_indices().nth(GREP_MAX_LINE_CHARS) {
        Some((byte_index, _)) => format!("{}... [truncated]", &line[..byte_index]),
        None => line.to_string(),
    }
}

/// One file's grep hits, honouring `context` and `limit`.
///
/// `matches_found` is threaded rather than returned so a caller can stop
/// walking the tree once the limit is reached.
pub fn grep_file_into(
    relative: &str,
    content: &str,
    matcher: &GrepMatcher,
    context: usize,
    limit: usize,
    matches_found: &mut usize,
    hits: &mut Vec<String>,
) {
    if context == 0 {
        // No window to merge, so matches stream straight out: no per-file line
        // vector, match vector, or ordered set.
        for (index, line) in content.lines().enumerate() {
            if *matches_found >= limit {
                break;
            }
            if !matcher.is_match(line) {
                continue;
            }
            *matches_found += 1;
            hits.push(format!("{relative}:{}:{}", index + 1, cap_grep_line(line)));
        }
        return;
    }
    let lines: Vec<&str> = content.lines().collect();
    // Match pass first so a context line that is itself a match keeps the match
    // (`:`) format even past the match limit.
    let matched: Vec<bool> = lines.iter().map(|line| matcher.is_match(line)).collect();
    // The match limit counts matches; context lines ride along free. Overlapping
    // context windows are merged, so each line is emitted once.
    let mut emit: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for (index, &hit) in matched.iter().enumerate() {
        if !hit {
            continue;
        }
        if *matches_found >= limit {
            break;
        }
        *matches_found += 1;
        let from = index.saturating_sub(context);
        let to = (index + context).min(lines.len().saturating_sub(1));
        emit.extend(from..=to);
    }
    for index in emit {
        let line = cap_grep_line(lines[index]);
        if matched[index] {
            hits.push(format!("{relative}:{}:{line}", index + 1));
        } else {
            hits.push(format!("{relative}-{}-{line}", index + 1));
        }
    }
}
