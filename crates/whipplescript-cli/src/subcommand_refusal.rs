//! Refusing a malformed `whip <command> <subcommand>` by saying what was wrong.
//!
//! A command with subcommands states its grammar as one usage line,
//! `usage: whip issue <new ...|list ...|show <id>|...>`. Its refusals used to
//! print all of that line and nothing else: forty alternatives for
//! `whip issue`, from which the reader had to find the one that applied and
//! then guess what was wrong with it. A refusal now names the problem and
//! prints the usage of the one subcommand involved, read out of the same line,
//! so there is no second statement of the grammar to drift from the first.

use std::process::ExitCode;

use whipplescript_parser::suggest_then_keyword;

/// `whip issue claim: missing <id>`, then the usage of `claim` alone.
pub(crate) fn refuse(usage: &str, subcommand: &str, problem: &str) -> ExitCode {
    eprintln!("{}", refusal_text(usage, subcommand, problem));
    ExitCode::from(2)
}

/// A subcommand the command does not have: say so, offer the nearest, and list
/// the rest by name. `synonyms` maps the words other trackers use to the ones
/// this command spells differently.
pub(crate) fn unknown(usage: &str, subcommand: &str, synonyms: &[(&str, &[&str])]) -> ExitCode {
    eprintln!("{}", unknown_text(usage, subcommand, synonyms));
    ExitCode::from(2)
}

/// `missing <b> and <c>`: the placeholders from the first absent one on.
pub(crate) fn missing(placeholders: &[&str], present: usize) -> String {
    format!(
        "missing {}",
        and_list(&placeholders[present.min(placeholders.len())..])
    )
}

/// An argument no form of the subcommand accepts.
pub(crate) fn unexpected(arg: &str) -> String {
    if arg.starts_with('-') && arg.len() > 1 {
        format!("unknown option `{arg}`")
    } else {
        format!("unexpected argument `{arg}`")
    }
}

/// `missing --tracker`, or `--tracker needs a value` when it was given bare.
pub(crate) fn missing_option(args: &[String], option: &str) -> String {
    if args.iter().any(|arg| arg == option) {
        format!("{option} needs a value")
    } else {
        format!("missing {option}")
    }
}

fn refusal_text(usage: &str, subcommand: &str, problem: &str) -> String {
    let (command, forms) = forms(usage);
    let own = forms
        .iter()
        .filter(|form| first_word(form) == subcommand)
        .collect::<Vec<_>>();
    let mut text = format!("{command} {subcommand}: {problem}");
    if own.is_empty() {
        text.push_str(&format!("\n{usage}"));
    }
    for (index, form) in own.iter().enumerate() {
        let lead = if index == 0 { "usage:" } else { "      " };
        text.push_str(&format!("\n{lead} {command} {form}"));
    }
    text
}

fn unknown_text(usage: &str, subcommand: &str, synonyms: &[(&str, &[&str])]) -> String {
    let (command, forms) = forms(usage);
    let mut names: Vec<&str> = Vec::new();
    for form in &forms {
        let name = first_word(form);
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let mut text = if subcommand.is_empty() {
        format!("{command}: missing a subcommand")
    } else {
        format!("{command}: unknown subcommand `{subcommand}`")
    };
    // A word another tracker uses names its meaning here exactly; a near
    // spelling is the language's own closed-vocabulary policy, so a slip gets
    // the same answer here as in a program.
    let hint = match synonyms.iter().find(|(word, _)| *word == subcommand) {
        Some((_, meant)) => format!(
            "did you mean {}?",
            or_list(
                &meant
                    .iter()
                    .map(|name| format!("`{name}`"))
                    .collect::<Vec<_>>()
            )
        ),
        None => suggest_then_keyword(subcommand, &names, "")
            .trim()
            .to_owned(),
    };
    if !hint.is_empty() {
        text.push_str(&format!("\n{hint}"));
    }
    text.push_str(&format!(
        "\nsubcommands: {}\nrun `{command} --help` for how each is used",
        names.join(" ")
    ));
    text
}

/// `("whip issue", ["new --tracker TR ...", "list [...]", ...])` from a
/// `usage: whip issue <...|...>` line. Alternatives split on a `|` outside any
/// bracket, since `[--to A|--clear]` and `<path|->` are choices within one.
fn forms(usage: &str) -> (&str, Vec<&str>) {
    let line = usage.strip_prefix("usage: ").unwrap_or(usage);
    let Some((command, grammar)) = line.split_once(" <") else {
        return (line, Vec::new());
    };
    let grammar = grammar.strip_suffix('>').unwrap_or(grammar);
    let mut forms = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (index, ch) in grammar.char_indices() {
        match ch {
            '[' | '(' | '<' => depth += 1,
            ']' | ')' | '>' => depth = depth.saturating_sub(1),
            '|' if depth == 0 => {
                forms.push(grammar[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    forms.push(grammar[start..].trim());
    (command, forms)
}

fn first_word(form: &str) -> &str {
    form.split_whitespace().next().unwrap_or_default()
}

fn and_list(items: &[&str]) -> String {
    joined(
        &items
            .iter()
            .map(|item| (*item).to_owned())
            .collect::<Vec<_>>(),
        "and",
    )
}

fn or_list(items: &[String]) -> String {
    joined(items, "or")
}

fn joined(items: &[String], conjunction: &str) -> String {
    match items.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} {conjunction} {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USAGE: &str = "usage: whip issue <\
new --tracker TR --title T|\
assign <id> [--to A|--clear]|\
import <path|->|import --from DIR|\
finish <id> [--summary S]|\
rebuild>";

    #[test]
    fn forms_split_only_between_alternatives() {
        let (command, forms) = forms(USAGE);
        assert_eq!(command, "whip issue");
        assert_eq!(
            forms,
            [
                "new --tracker TR --title T",
                "assign <id> [--to A|--clear]",
                "import <path|->",
                "import --from DIR",
                "finish <id> [--summary S]",
                "rebuild",
            ]
        );
    }

    #[test]
    fn a_refusal_names_the_problem_and_only_its_own_usage() {
        assert_eq!(
            refusal_text(USAGE, "assign", "needs --to <actor> or --clear"),
            "whip issue assign: needs --to <actor> or --clear\n\
             usage: whip issue assign <id> [--to A|--clear]"
        );
        assert_eq!(
            refusal_text(USAGE, "import", "missing <path>"),
            "whip issue import: missing <path>\n\
             usage: whip issue import <path|->\n       whip issue import --from DIR"
        );
    }

    #[test]
    fn a_subcommand_the_usage_does_not_name_falls_back_to_all_of_it() {
        assert_eq!(
            refusal_text(USAGE, "add", "missing --title"),
            format!("whip issue add: missing --title\n{USAGE}")
        );
    }

    #[test]
    fn an_unknown_subcommand_is_named_with_the_nearest_and_the_rest() {
        let text = unknown_text(USAGE, "finsh", &[]);
        assert_eq!(
            text,
            "whip issue: unknown subcommand `finsh`\n\
             did you mean `finish`?\n\
             subcommands: new assign import finish rebuild\n\
             run `whip issue --help` for how each is used"
        );
    }

    #[test]
    fn another_trackers_word_is_translated() {
        let text = unknown_text(USAGE, "close", &[("close", &["finish", "cancel"])]);
        assert!(
            text.contains("\ndid you mean `finish` or `cancel`?\n"),
            "{text}"
        );
    }

    #[test]
    fn a_word_nowhere_near_offers_no_guess() {
        let text = unknown_text(USAGE, "frobnicate", &[]);
        assert!(!text.contains("did you mean"), "{text}");
        assert!(text.contains("subcommands: new assign"), "{text}");
    }

    #[test]
    fn no_subcommand_at_all_is_said_plainly() {
        assert!(unknown_text(USAGE, "", &[]).starts_with("whip issue: missing a subcommand\n"));
    }

    #[test]
    fn missing_names_what_is_absent() {
        let placeholders = ["<from>", "<kind>", "<to>"];
        assert_eq!(missing(&placeholders, 0), "missing <from>, <kind> and <to>");
        assert_eq!(missing(&placeholders, 1), "missing <kind> and <to>");
        assert_eq!(missing(&placeholders, 2), "missing <to>");
    }

    #[test]
    fn an_option_and_a_word_are_told_apart() {
        assert_eq!(unexpected("--queue"), "unknown option `--queue`");
        assert_eq!(unexpected("WS-1"), "unexpected argument `WS-1`");
        assert_eq!(unexpected("-"), "unexpected argument `-`");
        let args = ["new".to_owned(), "--tracker".to_owned()];
        assert_eq!(
            missing_option(&args, "--tracker"),
            "--tracker needs a value"
        );
        assert_eq!(missing_option(&args, "--title"), "missing --title");
    }
}
