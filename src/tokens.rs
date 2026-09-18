//! Override directive parser shared by every gate that accepts an escape hatch.
//!
//! Grammar, distilled from `orieg/expanse`'s hardened PR-body parsers:
//!   - a directive must **begin its own line** (optionally inside `<!-- -->`);
//!     a mention mid-sentence, in a table cell, or in a code span never arms it
//!   - lines inside fenced code blocks are ignored
//!   - the reason must be non-empty and must not be a template placeholder
//!   - an override is **scoped**: it only covers a subject that its reason names
//!
//! The expanse incident this encodes: a PR that *described* the override
//! mechanism in a markdown table silently approved every regression in the run.

use regex::Regex;

pub const REMOVES: &[&str] = &["removes", "deletes", "remove", "delete"];
pub const ALLOW_ASSERTION_DROP: &[&str] = &["allow-assertion-drop"];
pub const ALLOW_IGNORE: &[&str] = &["allow-ignore"];
pub const ALLOW_GATE_WEAKENING: &[&str] = &["allow-gate-weakening"];

const PLACEHOLDERS: &[&str] = &[
    "todo", "tbd", "none", "n/a", "na", "reason", "why", "...", "xxx", "fixme", "-",
];

/// Reasons of every well-formed directive named in `names` found in `text`.
pub fn directive_reasons(text: &str, names: &[&str]) -> Vec<String> {
    let alternation = names
        .iter()
        .map(|n| regex::escape(n))
        .collect::<Vec<_>>()
        .join("|");
    let re = Regex::new(&format!(
        r"(?i)^[ \t]*(?:<!--[ \t]*)?(?:{alternation}):[ \t]*(.*)$"
    ))
    .expect("directive regex is static");

    let mut reasons = Vec::new();
    let mut fence: Option<&str> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let marker = ["```", "~~~"].into_iter().find(|m| trimmed.starts_with(m));
        match (fence, marker) {
            (None, Some(m)) => {
                fence = Some(m);
                continue;
            }
            (Some(open), Some(m)) if open == m => {
                fence = None;
                continue;
            }
            (Some(_), _) => continue,
            (None, None) => {}
        }
        if let Some(caps) = re.captures(line) {
            let reason = clean_reason(&caps[1]);
            if !is_placeholder(&reason) {
                reasons.push(reason);
            }
        }
    }
    reasons
}

/// True when some directive's reason names `subject` (or, for paths, a
/// directory prefix of it or its file name).
pub fn covers(reasons: &[String], subject: &str) -> bool {
    reasons.iter().any(|r| reason_names(r, subject))
}

fn reason_names(reason: &str, subject: &str) -> bool {
    let is_token_char = |c: char| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/');
    let raw_tokens = reason
        .split(|c: char| !is_token_char(c))
        .filter(|t| !t.is_empty());
    let file_name = subject.rsplit('/').next().unwrap_or(subject);
    for raw_token in raw_tokens {
        let has_slash = raw_token.contains('/');
        let token = raw_token.trim_matches(|c| matches!(c, '.' | '/'));
        if token.is_empty() {
            continue;
        }
        if token == subject || token == file_name {
            return true;
        }
        // Directory prefix: only when written with a slash (e.g. `tests/legacy` or `tests/`).
        // A bare word like `tests` in ordinary prose never acts as a directory prefix.
        if has_slash && subject.contains('/') && subject.starts_with(&format!("{token}/")) {
            return true;
        }
    }
    false
}

fn clean_reason(raw: &str) -> String {
    let mut r = raw.trim();
    // `--!>` also closes an HTML comment; left on the reason it once let a
    // placeholder through in expanse.
    for closer in ["--!>", "-->"] {
        if let Some(stripped) = r.strip_suffix(closer) {
            r = stripped.trim_end();
        }
    }
    r.to_string()
}

fn is_placeholder(reason: &str) -> bool {
    let r = reason.trim();
    if r.is_empty() {
        return true;
    }
    if r.starts_with('<') && r.ends_with('>') {
        return true;
    }
    PLACEHOLDERS.contains(&r.to_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_anchored_directive_is_accepted() {
        let body = "Summary\n\nremoves: tests/old.rs superseded by tests/new.rs\n";
        let reasons = directive_reasons(body, REMOVES);
        assert_eq!(reasons, vec!["tests/old.rs superseded by tests/new.rs"]);
        assert!(covers(&reasons, "tests/old.rs"));
    }

    #[test]
    fn html_comment_wrapping_is_accepted_and_closer_stripped() {
        let reasons = directive_reasons("<!-- deletes: benches/x.rs obsolete -->", REMOVES);
        assert_eq!(reasons, vec!["benches/x.rs obsolete"]);
    }

    #[test]
    fn prose_table_and_code_mentions_do_not_arm_the_override() {
        // The verbatim shape of the expanse #437 defect: documentation *about*
        // the directive must never act as the directive.
        let body = "\
We use the removes: token to justify deletions.
| token | meaning |
| removes: tests/old.rs | justification |
`removes: tests/old.rs because`
```
removes: tests/old.rs inside a fence
```
";
        assert!(directive_reasons(body, REMOVES).is_empty());
    }

    #[test]
    fn placeholders_are_rejected() {
        for body in [
            "removes:",
            "removes: <reason>",
            "removes: TODO",
            "removes: n/a",
            "<!-- removes: <reason> -->",
            "<!-- removes: <reason> --!>",
            "removes: ...",
        ] {
            assert!(
                directive_reasons(body, REMOVES).is_empty(),
                "placeholder accepted: {body:?}"
            );
        }
    }

    #[test]
    fn override_is_scoped_to_named_subjects() {
        let reasons =
            directive_reasons("removes: tests/legacy replaced by proptest suite", REMOVES);
        assert!(covers(&reasons, "tests/legacy/a.rs"));
        assert!(covers(&reasons, "tests/legacy/deep/b.rs"));
        assert!(!covers(&reasons, "tests/other.rs"));
        assert!(!covers(&reasons, "tests/legacy_extra.rs"));

        let by_name = directive_reasons("removes: old.rs, moved", REMOVES);
        assert!(covers(&by_name, "tests/old.rs"));
        assert!(!covers(&by_name, "tests/very_old.rs"));

        // A bare word must NOT act as a directory prefix.
        let bare = directive_reasons("removes: tests were refactored into benchmarks", REMOVES);
        assert!(!covers(&bare, "tests/a.rs"));
        assert!(!covers(&bare, "tests/legacy/a.rs"));

        // But an explicit directory prefix with a slash DOES cover it.
        let with_slash =
            directive_reasons("removes: tests/ were refactored into benchmarks", REMOVES);
        assert!(covers(&with_slash, "tests/a.rs"));
    }

    #[test]
    fn unrelated_directive_name_is_ignored() {
        assert!(directive_reasons("allow-ignore: flaky_test on CI", REMOVES).is_empty());
        let r = directive_reasons("allow-ignore: flaky_test on CI", ALLOW_IGNORE);
        assert!(covers(&r, "flaky_test"));
        assert!(!covers(&r, "flaky"));
    }
}
