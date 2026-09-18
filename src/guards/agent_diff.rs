//! Agent-guard gates that reason about the *change*: base vs head facts from
//! the tree-sitter extractor, plus deleted files.

use super::{exempt_filter, Context, GateOutcome, PathFilter};
use crate::ast::{
    analyze, is_unsupported_source, language_for, AssertVocabulary, RustFacts, TestFn,
};
use crate::config::GateSettings;
use crate::gitctx::{ChangeKind, ChangedFile};
use crate::tokens::{self, covers, directive_reasons};
use anyhow::Result;

struct FileFacts {
    file: ChangedFile,
    base: Option<RustFacts>,
    head: Option<RustFacts>,
}

struct TestPair<'a> {
    path: &'a str,
    base: &'a TestFn,
    head: &'a TestFn,
}

struct Located<'a> {
    path: &'a str,
    /// The file still exists on the head side.
    file_survives: bool,
    test: &'a TestFn,
}

/// Runs every diff-based agent-guard gate and returns one outcome per gate.
/// Disabled gates are filtered by the caller; computing them is cheap.
pub fn run(ctx: &Context) -> Result<Vec<GateOutcome>> {
    let gates = &ctx.config.gates;
    let vocab = AssertVocabulary {
        extra_macros: [
            &gates.assertion_reduction.extra_assert_macros[..],
            &gates.vacuous_tests.extra_assert_macros[..],
        ]
        .concat(),
        helper_fns: [
            &gates.assertion_reduction.assert_helper_fns[..],
            &gates.vacuous_tests.assert_helper_fns[..],
        ]
        .concat(),
    };

    let changed = ctx.git.changed_files()?;
    let mut rust = Vec::new();
    for file in changed
        .iter()
        .filter(|f| language_for(&f.path).is_some() || language_for(&f.old_path).is_some())
    {
        let base = match ctx.git.base_content(&file.old_path)? {
            Some(src) => Some(analyze(&src, &vocab)?),
            None => None,
        };
        let head = match file.kind {
            ChangeKind::Deleted => None,
            _ => match ctx.git.head_content(&file.path)? {
                Some(src) => Some(analyze(&src, &vocab)?),
                None => None,
            },
        };
        rust.push(FileFacts {
            file: file.clone(),
            base,
            head,
        });
    }

    let (pairs, removed, added) = match_tests(&rust);

    let mut ast_gates = vec![
        assertion_reduction(ctx, &rust, &pairs)?,
        vacuous_tests(ctx, &rust, &added)?,
        ignored_tests(ctx, &rust, &pairs, &added)?,
        unsafe_safety_comment(ctx, &rust)?,
    ];

    // Named degradation: source files in a language with no extractor were
    // not analysed. Saying so keeps "0 violations" from reading as coverage.
    let unseen: Vec<&str> = changed
        .iter()
        .filter(|f| f.kind != ChangeKind::Deleted && is_unsupported_source(&f.path))
        .map(|f| f.path.as_str())
        .collect();
    if !unseen.is_empty() {
        let sample = unseen
            .iter()
            .take(3)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        let note = format!(
            "{} changed source file(s) are in a language with no extractor yet and were NOT \
             analysed by this gate (e.g. {sample})",
            unseen.len()
        );
        for gate in &mut ast_gates {
            gate.notes.push(note.clone());
        }
    }

    ast_gates.push(deletion_rationale(ctx, &changed, &removed)?);
    Ok(ast_gates)
}

/// Pair tests by name within a file, then pair the leftovers across files so a
/// test moved to another file is compared instead of reported as removed+new.
fn match_tests(rust: &[FileFacts]) -> (Vec<TestPair<'_>>, Vec<Located<'_>>, Vec<Located<'_>>) {
    let mut pairs = Vec::new();
    let mut removed: Vec<Located> = Vec::new();
    let mut added: Vec<Located> = Vec::new();

    for ff in rust {
        let base_tests: &[TestFn] = ff.base.as_ref().map(|f| &f.tests[..]).unwrap_or(&[]);
        let head_tests: &[TestFn] = ff.head.as_ref().map(|f| &f.tests[..]).unwrap_or(&[]);
        let mut taken = vec![false; head_tests.len()];
        for b in base_tests {
            let hit = head_tests
                .iter()
                .enumerate()
                .find(|(i, h)| !taken[*i] && h.name == b.name);
            match hit {
                Some((i, h)) => {
                    taken[i] = true;
                    pairs.push(TestPair {
                        path: &ff.file.path,
                        base: b,
                        head: h,
                    });
                }
                None => removed.push(Located {
                    path: &ff.file.path,
                    file_survives: ff.head.is_some(),
                    test: b,
                }),
            }
        }
        for (i, h) in head_tests.iter().enumerate() {
            if !taken[i] {
                added.push(Located {
                    path: &ff.file.path,
                    file_survives: true,
                    test: h,
                });
            }
        }
    }

    let leaf = |n: &str| n.rsplit("::").next().unwrap_or(n).to_string();
    let mut still_removed = Vec::new();
    for r in removed {
        match added
            .iter()
            .position(|a| leaf(&a.test.name) == leaf(&r.test.name))
        {
            Some(i) => {
                let a = added.remove(i);
                pairs.push(TestPair {
                    path: a.path,
                    base: r.test,
                    head: a.test,
                });
            }
            None => still_removed.push(r),
        }
    }
    (pairs, still_removed, added)
}

fn leaf_name(test: &TestFn) -> &str {
    test.name.rsplit("::").next().unwrap_or(&test.name)
}

fn analyzed_files(rust: &[FileFacts], exempt: &PathFilter) -> usize {
    rust.iter()
        .filter(|f| f.head.is_some() && !exempt.matches(&f.file.path))
        .count()
}

/// Parse errors are reported by the first enabled AST gate only.
fn report_parse_errors(
    ctx: &Context,
    gate: &'static str,
    rust: &[FileFacts],
    out: &mut GateOutcome,
) {
    let g = &ctx.config.gates;
    let first_enabled = [
        ("assertion-reduction", g.assertion_reduction.enabled),
        ("vacuous-tests", g.vacuous_tests.enabled),
        ("ignored-tests", g.ignored_tests.enabled),
        ("unsafe-safety-comment", g.unsafe_safety_comment.enabled),
    ]
    .into_iter()
    .find(|(_, on)| *on)
    .map(|(id, _)| id);
    if first_enabled != Some(gate) {
        return;
    }
    let settings = g.settings(gate).expect("registered gate");
    for ff in rust {
        if ff.head.as_ref().is_some_and(|h| h.has_parse_errors) {
            out.push(
                settings.severity(),
                "Rust File Could Not Be Fully Parsed",
                Some(&ff.file.path),
                None,
                "The Rust grammar reported syntax errors, so assertion and unsafe facts for \
                 this file may be incomplete. A gate that cannot read its input does not pass."
                    .to_string(),
                "Fix the syntax error, or list the path under `exempt_paths` for the AST gates \
                 if it uses syntax the bundled grammar does not know yet.",
            );
        }
    }
}

fn assertion_reduction(
    ctx: &Context,
    rust: &[FileFacts],
    pairs: &[TestPair],
) -> Result<GateOutcome> {
    const GATE: &str = "assertion-reduction";
    let settings = &ctx.config.gates.assertion_reduction;
    let exempt = exempt_filter(settings)?;
    let reasons = directive_reasons(&ctx.directive_text, tokens::ALLOW_ASSERTION_DROP);
    let mut out = GateOutcome::new(GATE);
    out.examined = pairs.len();
    report_parse_errors(ctx, GATE, rust, &mut out);

    for p in pairs.iter().filter(|p| !exempt.matches(p.path)) {
        let (b, h) = (p.base, p.head);
        let total_drop = h.effective_asserts() < b.effective_asserts();
        let strong_drop = h.strong_asserts < b.strong_asserts;
        if !(total_drop || strong_drop) || covers(&reasons, leaf_name(h)) {
            continue;
        }
        let what = if total_drop {
            format!(
                "effective assertions dropped from {} to {}",
                b.effective_asserts(),
                h.effective_asserts()
            )
        } else {
            format!(
                "equality / pattern assertions dropped from {} to {} (weakened to a looser form)",
                b.strong_asserts, h.strong_asserts
            )
        };
        out.push(
            ctx.overridable(settings.severity()),
            "Assertion Reduction In Existing Test",
            Some(p.path),
            Some(h.line),
            format!("Test `{}`: {what}.", h.name),
            &format!(
                "Restore the assertions, or justify the drop on its own line in the PR body or \
                 a commit message: `allow-assertion-drop: {} <reason>`.",
                leaf_name(h)
            ),
        );
    }
    Ok(out)
}

fn vacuous_tests(ctx: &Context, rust: &[FileFacts], added: &[Located]) -> Result<GateOutcome> {
    const GATE: &str = "vacuous-tests";
    let settings = &ctx.config.gates.vacuous_tests;
    let exempt = exempt_filter(settings)?;
    let mut out = GateOutcome::new(GATE);
    out.examined = added.len();
    report_parse_errors(ctx, GATE, rust, &mut out);

    for a in added.iter().filter(|a| !exempt.matches(a.path)) {
        if !a.test.is_vacuous() {
            continue;
        }
        let why = if a.test.total_asserts == 0 {
            "contains no assertion".to_string()
        } else {
            format!(
                "contains only tautological assertions ({} of {})",
                a.test.tautologies, a.test.total_asserts
            )
        };
        out.push(
            settings.severity(),
            "Vacuous Test Added",
            Some(a.path),
            Some(a.test.line),
            format!("New test `{}` {why}; it cannot fail.", a.test.name),
            "Assert the behavior under test. If the suite asserts through helpers or custom \
             macros, declare them in `assert_helper_fns` / `extra_assert_macros`.",
        );
    }
    Ok(out)
}

fn ignored_tests(
    ctx: &Context,
    rust: &[FileFacts],
    pairs: &[TestPair],
    added: &[Located],
) -> Result<GateOutcome> {
    const GATE: &str = "ignored-tests";
    let settings = &ctx.config.gates.ignored_tests;
    let exempt = exempt_filter(settings)?;
    let reasons = directive_reasons(&ctx.directive_text, tokens::ALLOW_IGNORE);
    let mut out = GateOutcome::new(GATE);
    out.examined = pairs.len() + added.len();
    report_parse_errors(ctx, GATE, rust, &mut out);

    let newly_ignored = pairs
        .iter()
        .filter(|p| p.head.ignored && !p.base.ignored)
        .map(|p| (p.path, p.head))
        .chain(
            added
                .iter()
                .filter(|a| a.test.ignored)
                .map(|a| (a.path, a.test)),
        );
    for (path, test) in newly_ignored {
        if exempt.matches(path) || covers(&reasons, leaf_name(test)) {
            continue;
        }
        out.push(
            ctx.overridable(settings.severity()),
            "Test Newly Marked #[ignore]",
            Some(path),
            Some(test.line),
            format!("Test `{}` no longer runs.", test.name),
            &format!(
                "Fix the test, or justify it on its own line in the PR body or a commit \
                 message: `allow-ignore: {} <reason>`.",
                leaf_name(test)
            ),
        );
    }
    Ok(out)
}

fn unsafe_safety_comment(ctx: &Context, rust: &[FileFacts]) -> Result<GateOutcome> {
    const GATE: &str = "unsafe-safety-comment";
    let settings = &ctx.config.gates.unsafe_safety_comment;
    let exempt = exempt_filter(settings)?;
    let mut out = GateOutcome::new(GATE);
    out.examined = analyzed_files(rust, &exempt);
    report_parse_errors(ctx, GATE, rust, &mut out);

    for ff in rust {
        let Some(head) = &ff.head else { continue };
        if exempt.matches(&ff.file.path) {
            continue;
        }
        let undocumented = |f: &RustFacts| f.unsafe_sites.iter().filter(|s| !s.documented).count();
        let base_undocumented = ff.base.as_ref().map(undocumented).unwrap_or(0);
        // A site is in scope when its line was added, or — to catch a SAFETY
        // comment deleted from above an untouched block — when the file now
        // has more undocumented sites than it had on the base side.
        let regressed = undocumented(head) > base_undocumented;
        for site in head.unsafe_sites.iter().filter(|s| !s.documented) {
            if !(ff.file.added_lines.contains(&site.line) || regressed) {
                continue;
            }
            out.push(
                settings.severity(),
                "Unsafe Without SAFETY Comment",
                Some(&ff.file.path),
                Some(site.line),
                format!("Undocumented {}: `{}`", site.kind, site.snippet),
                "Add a `// SAFETY: <why the invariants hold>` comment directly above the block \
                 or the statement that contains it.",
            );
        }
    }
    Ok(out)
}

fn deletion_rationale(
    ctx: &Context,
    changed: &[ChangedFile],
    removed: &[Located],
) -> Result<GateOutcome> {
    const GATE: &str = "deletion-rationale";
    let settings = &ctx.config.gates.deletion_rationale;
    let exempt = exempt_filter(settings)?;
    let watched = PathFilter::new(&settings.paths)?;
    let reasons = directive_reasons(&ctx.directive_text, tokens::REMOVES);
    let severity = ctx.overridable(settings.severity());
    let mut out = GateOutcome::new(GATE);

    for file in changed.iter().filter(|f| f.kind == ChangeKind::Deleted) {
        if !watched.matches(&file.path) || exempt.matches(&file.path) {
            continue;
        }
        out.examined += 1;
        if covers(&reasons, &file.path) {
            continue;
        }
        out.push(
            severity,
            "File Deleted Without Rationale",
            Some(&file.path),
            None,
            format!(
                "`{}` was deleted and no `removes:` directive names it.",
                file.path
            ),
            &format!(
                "State why on its own line in the PR body or a commit message: \
                 `removes: {} <reason>` (a directory prefix covers everything under it).",
                file.path
            ),
        );
    }

    // Tests removed from a file that still exists. Tests inside a deleted file
    // are covered by that file's own rationale.
    for r in removed.iter().filter(|r| r.file_survives) {
        if !watched.matches(r.path) || exempt.matches(r.path) {
            continue;
        }
        out.examined += 1;
        if covers(&reasons, leaf_name(r.test)) {
            continue;
        }
        out.push(
            severity,
            "Test Removed Without Rationale",
            Some(r.path),
            None,
            format!(
                "Test `{}` was removed (or renamed) from `{}`.",
                r.test.name, r.path
            ),
            &format!(
                "State why on its own line in the PR body or a commit message: \
                 `removes: {} <reason>`.",
                leaf_name(r.test)
            ),
        );
    }
    Ok(out)
}
