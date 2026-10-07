//! Cache-efficiency lint for prompt templates (WS-291).
//!
//! Every provider's prompt cache rewards the same thing: a byte-identical
//! prefix across calls (`spec/inference-cache-note.md`). A prompt template
//! that interpolates a value which changes on every call — a run or effect
//! id, a timestamp, a random draw — ends the cacheable prefix at that
//! interpolation, so every byte of fixed text written after it is re-processed
//! at the full input rate on every call. Moving the volatile value to the end
//! of the prompt keeps the meaning and makes the fixed text a stable prefix.
//!
//! This is a WARNING, never a refusal: the program is correct, only more
//! expensive than it needs to be. It offers no fix-it, because reordering a
//! prompt changes what the model reads, and that is the author's call.
//!
//! What counts as volatile is decided by name, since the type of an
//! interpolated path is not known at this point of lowering and a lint that
//! guesses wrong in the quiet direction costs nothing. The threshold below is
//! a guess, not a measurement: no live cache-metric run exists yet, and the
//! note says to revisit it once one does.
//!
//! WhippleScript source has no surface that reaches an agent's SYSTEM prompt
//! today — a managed agent's system prompt is assembled from skill bundles and
//! project instructions, neither of which is interpolated — so every prompt
//! this pass sees is a user turn. When an authored system-prompt surface
//! lands, a volatile value anywhere in it should be warned on, since the
//! system block is the prefix every turn shares.

use super::*;

/// Fixed text, in non-whitespace characters, that must follow a volatile
/// interpolation before the ordering is worth a warning. Below this the
/// prompt's cacheable remainder is too small to matter. Provisional: revisit
/// once live cache measurements exist (`spec/inference-cache-note.md`).
pub(crate) const VOLATILE_PROMPT_TAIL_MIN_CHARS: usize = 160;

/// Field or parameter names whose value differs on every call by construction.
const VOLATILE_NAMES: &[&str] = &[
    "run_id",
    "effect_id",
    "instance_id",
    "idempotency_key",
    "request_id",
    "trace_id",
    "span_id",
    "nonce",
    "uuid",
    "random",
    "now",
    "timestamp",
];

/// Call spellings that draw a fresh value each time they are evaluated.
const VOLATILE_CALLS: &[&str] = &["now(", "random(", "uuid(", "timestamp("];

/// Whether the interior of one `{{ … }}` interpolation reads a volatile value.
fn interpolation_is_volatile(interior: &str) -> bool {
    let compact: String = interior.chars().filter(|c| !c.is_whitespace()).collect();
    if VOLATILE_CALLS.iter().any(|call| compact.contains(call)) {
        return true;
    }
    // Each `a.b.c` chain (or bare name — a coerce parameter is one) is judged
    // by its leaf, the name of the value actually interpolated.
    interior
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .filter_map(|chain| chain.rsplit('.').next())
        .any(|leaf| VOLATILE_NAMES.contains(&leaf) || leaf.ends_with("_at"))
}

/// The first volatile interpolation in `text` that is followed by at least
/// [`VOLATILE_PROMPT_TAIL_MIN_CHARS`] of fixed text, as the interpolation's
/// interior (trimmed) and the size of that fixed tail.
pub(crate) fn volatile_prompt_prefix(text: &str) -> Option<(String, usize)> {
    let ranges = interpolation_ranges(text);
    let first = ranges
        .iter()
        .position(|range| interpolation_is_volatile(&text[range.clone()]))?;
    // Fixed text after the volatile interpolation: every byte outside the
    // later interpolations' fences, counted without whitespace so a
    // reindented prompt is judged the same.
    let mut tail = 0usize;
    let mut at = ranges[first].end + 2;
    for range in &ranges[first + 1..] {
        let open = range.start - 2;
        tail += text[at..open]
            .chars()
            .filter(|c| !c.is_whitespace())
            .count();
        at = range.end + 2;
    }
    tail += text[at.min(text.len())..]
        .chars()
        .filter(|c| !c.is_whitespace())
        .count();
    (tail >= VOLATILE_PROMPT_TAIL_MIN_CHARS)
        .then(|| (text[ranges[first].clone()].trim().to_owned(), tail))
}

fn volatile_prefix_warning(owner: &str, span: SourceSpan, text: &str) -> Option<Diagnostic> {
    let (interpolation, tail) = volatile_prompt_prefix(text)?;
    Some(Diagnostic {
        code: diagnostic_code!("effect.volatile_prompt_prefix"),
        severity: Severity::Warning,
        related: Vec::new(),
        fixits: Vec::new(),
        span,
        message: format!(
            "{owner} interpolates `{{{{ {interpolation} }}}}`, which changes on every call, ahead of {tail} characters of fixed text; the provider's prompt cache cannot reuse anything after it"
        ),
        suggestion: suggest(format!(
            "move `{{{{ {interpolation} }}}}` to the end of the prompt, after the fixed text, so the text before it is a stable prefix the cache can reuse"
        )),
    })
}

/// Warn on every prompt template — a `tell`, `prompt`, `decide` or other
/// effect's prompt, and a `coerce` declaration's body — that places a volatile
/// interpolation ahead of a substantial run of fixed text.
pub(crate) fn warn_volatile_prompt_prefixes(
    ir: &IrProgram,
    rule_bodies: &[BlockSource],
    warnings: &mut Vec<Diagnostic>,
) {
    for coerce in &ir.coerces {
        if let Some(warning) = volatile_prefix_warning(
            &format!("coerce `{}`'s prompt", coerce.name),
            coerce.span,
            &coerce.body,
        ) {
            warnings.push(warning);
        }
    }

    fn walk(statements: &[body::BodyStmt], warnings: &mut Vec<Diagnostic>) {
        for statement in statements {
            match statement {
                body::BodyStmt::Effect(effect) => {
                    if let Some(prompt) = &effect.prompt {
                        if let Some(warning) =
                            volatile_prefix_warning("this prompt", effect.span, &prompt.text)
                        {
                            warnings.push(warning);
                        }
                    }
                }
                body::BodyStmt::After(after) => walk(&after.body, warnings),
                body::BodyStmt::Case(case) => {
                    for branch in &case.branches {
                        walk(&branch.body, warnings);
                    }
                }
                body::BodyStmt::Region(region) => {
                    walk(&region.body, warnings);
                    walk(&region.lapse_body, warnings);
                }
                _ => {}
            }
        }
    }

    // The same positional pairing `validate_file_store_write_policy` relies
    // on: a rule's recorded block gives its body a real source base, so the
    // warning lands on the effect's own line.
    let aligned = rule_bodies.len() == ir.rules.len();
    for (index, rule) in ir.rules.iter().enumerate() {
        let base = aligned
            .then(|| rule_bodies.get(index))
            .flatten()
            .map(BlockSource::body_base)
            .unwrap_or(body::BodyBase::Generated(zero_span()));
        let (ast, _) = body::parse_rule_body(&rule.body, base);
        walk(&ast.statements, warnings);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(n: usize) -> String {
        "x".repeat(n)
    }

    #[test]
    fn a_volatile_value_ahead_of_fixed_text_is_found() {
        let text = format!("Run {{{{ f.run_id }}}}. {}", fixed(200));
        let (interpolation, tail) = volatile_prompt_prefix(&text).expect("warned");
        assert_eq!(interpolation, "f.run_id");
        assert!(tail >= 200);
    }

    #[test]
    fn a_volatile_value_at_the_end_is_not_a_finding() {
        let text = format!("{} Run {{{{ f.run_id }}}}.", fixed(400));
        assert_eq!(volatile_prompt_prefix(&text), None);
    }

    #[test]
    fn a_short_fixed_tail_is_below_the_threshold() {
        let text = format!("Run {{{{ f.run_id }}}}. {}", fixed(20));
        assert_eq!(volatile_prompt_prefix(&text), None);
    }

    #[test]
    fn stable_interpolations_are_not_volatile() {
        let text = format!(
            "Review {{{{ ticket.title }}}}. {} {{{{ ctx.output_format }}}}",
            fixed(400)
        );
        assert_eq!(volatile_prompt_prefix(&text), None);
    }

    #[test]
    fn timestamps_calls_and_bare_parameters_are_volatile() {
        for interior in [
            "t.fired_at",
            "now()",
            "random ( )",
            "request_id",
            "x.timestamp",
        ] {
            let text = format!("At {{{{ {interior} }}}}: {}", fixed(200));
            assert!(volatile_prompt_prefix(&text).is_some(), "{interior}");
        }
    }

    #[test]
    fn the_tail_ignores_whitespace_and_later_interpolations() {
        // 150 fixed characters, padded with whitespace and split by a stable
        // interpolation whose interior must not count as fixed text.
        let text = format!(
            "{{{{ f.effect_id }}}}\n\n    {}   {{{{ a_very_long_stable_binding_name.with_a_field }}}}   {}",
            fixed(75),
            fixed(75)
        );
        assert_eq!(volatile_prompt_prefix(&text), None);
        let text = format!(
            "{{{{ f.effect_id }}}} {} {{{{ t.title }}}} {}",
            fixed(80),
            fixed(80)
        );
        assert_eq!(
            volatile_prompt_prefix(&text),
            Some(("f.effect_id".to_owned(), 160))
        );
    }
}
