//! Tree-sitter extraction of the facts the agent-guard gates reason about.
//!
//! Everything here is keyed on syntax nodes, never on substring matches: the
//! word `unsafe` or `assert!` inside a comment, a string literal, or a doc
//! example is not a node of the corresponding kind and is never counted.
//!
//! Known limit (see docs/ARCHITECTURE.md): the
//! body of a macro invocation is an unparsed token tree, so tests generated
//! inside `proptest! { .. }` and assertions nested inside another macro's
//! arguments are not visible.

use anyhow::{anyhow, Result};
use tree_sitter::{Node, Parser};

/// Languages with a fact extractor. Adding a language pack means: a grammar,
/// an extractor that fills [`RustFacts`]' language-neutral fields (tests,
/// assertion counts, skip markers, escape-hatch sites), and its controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Rust,
}

/// Source extensions discipline recognises but cannot analyse yet. A change
/// touching these is *named* in the report: the AST gates did not look at it.
const UNSUPPORTED_SOURCE_EXTS: &[&str] = &[
    "py", "js", "jsx", "mjs", "cjs", "ts", "tsx", "java", "kt", "kts", "scala", "go", "c", "h",
    "cc", "cpp", "cxx", "hpp", "hh", "cs", "rb", "swift", "php", "m", "mm",
];

pub fn language_for(path: &str) -> Option<Language> {
    match extension(path)? {
        "rs" => Some(Language::Rust),
        _ => None,
    }
}

pub fn is_unsupported_source(path: &str) -> bool {
    extension(path).is_some_and(|e| UNSUPPORTED_SOURCE_EXTS.contains(&e))
}

fn extension(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    name.rsplit_once('.').map(|(_, ext)| ext)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestFn {
    /// Module-qualified name, e.g. `tests::inserts_in_order`.
    pub name: String,
    /// 1-based line of the `fn` item.
    pub line: usize,
    pub total_asserts: usize,
    /// Equality / pattern assertions (`assert_eq!`, `assert_ne!`, `assert_matches!` ...).
    pub strong_asserts: usize,
    pub tautologies: usize,
    pub ignored: bool,
    pub should_panic: bool,
}

impl TestFn {
    /// Assertions that can actually fail.
    pub fn effective_asserts(&self) -> usize {
        self.total_asserts - self.tautologies
    }

    pub fn is_vacuous(&self) -> bool {
        self.effective_asserts() == 0 && !self.should_panic
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsafeSite {
    pub line: usize,
    pub kind: &'static str,
    pub documented: bool,
    pub snippet: String,
}

#[derive(Debug, Clone, Default)]
pub struct RustFacts {
    pub tests: Vec<TestFn>,
    pub unsafe_sites: Vec<UnsafeSite>,
    /// The grammar could not parse part of the file; facts may be incomplete.
    pub has_parse_errors: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AssertVocabulary {
    pub extra_macros: Vec<String>,
    pub helper_fns: Vec<String>,
}

pub fn analyze(source: &str, vocab: &AssertVocabulary) -> Result<RustFacts> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|e| anyhow!("failed to load the Rust grammar: {e}"))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| anyhow!("tree-sitter returned no tree"))?;
    let root = tree.root_node();

    let mut cx = Extractor {
        src: source.as_bytes(),
        lines: source.lines().collect(),
        line_starts: std::iter::once(0)
            .chain(source.match_indices('\n').map(|(i, _)| i + 1))
            .collect(),
        vocab,
        comments: Vec::new(),
        facts: RustFacts {
            has_parse_errors: root.has_error(),
            ..Default::default()
        },
    };
    cx.collect_comments(root);
    cx.visit(root, &mut Vec::new());
    Ok(cx.facts)
}

struct Comment {
    start_row: usize,
    end_row: usize,
    start_byte: usize,
    end_byte: usize,
    has_safety: bool,
}

struct Extractor<'a> {
    src: &'a [u8],
    lines: Vec<&'a str>,
    /// Byte offset of each line start (robust to CRLF, unlike summing `lines`).
    line_starts: Vec<usize>,
    vocab: &'a AssertVocabulary,
    comments: Vec<Comment>,
    facts: RustFacts,
}

impl<'a> Extractor<'a> {
    fn text(&self, node: Node) -> &'a str {
        node.utf8_text(self.src).unwrap_or("")
    }

    fn collect_comments(&mut self, node: Node) {
        if matches!(node.kind(), "line_comment" | "block_comment") {
            self.comments.push(Comment {
                start_row: node.start_position().row,
                end_row: node.end_position().row,
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                has_safety: self.text(node).contains("SAFETY:"),
            });
            return;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.collect_comments(child);
        }
    }

    fn visit(&mut self, node: Node, mods: &mut Vec<String>) {
        match node.kind() {
            "mod_item" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| self.text(n).to_string())
                    .unwrap_or_default();
                mods.push(name);
                self.visit_children(node, mods);
                mods.pop();
                return;
            }
            "function_item" => {
                if let Some(test) = self.test_fn(node, mods) {
                    self.facts.tests.push(test);
                }
            }
            "unsafe_block" => self.unsafe_site(node, "unsafe block"),
            "impl_item" => {
                let mut cursor = node.walk();
                if node.children(&mut cursor).any(|c| c.kind() == "unsafe") {
                    self.unsafe_site(node, "unsafe impl");
                }
            }
            _ => {}
        }
        self.visit_children(node, mods);
    }

    fn visit_children(&mut self, node: Node, mods: &mut Vec<String>) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.visit(child, mods);
        }
    }

    fn test_fn(&self, node: Node, mods: &[String]) -> Option<TestFn> {
        let mut is_test = false;
        let mut ignored = false;
        let mut should_panic = false;
        let mut prev = node.prev_sibling();
        while let Some(p) = prev {
            match p.kind() {
                "attribute_item" => {
                    let text = self.text(p);
                    let name = attribute_name(text);
                    let mut check_attr = |n: &str| match n {
                        "test" | "rstest" | "test_case" | "quickcheck" => is_test = true,
                        "ignore" => ignored = true,
                        "should_panic" => should_panic = true,
                        _ => {}
                    };
                    check_attr(&name);
                    if name == "cfg_attr" {
                        for sub in parse_cfg_attr_sub_attributes(text) {
                            check_attr(&attribute_name(&sub));
                        }
                    }
                    prev = p.prev_sibling();
                }
                "line_comment" | "block_comment" => prev = p.prev_sibling(),
                _ => break,
            }
        }
        if !is_test {
            return None;
        }

        let name = self.text(node.child_by_field_name("name")?);
        let qualified = mods
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(name))
            .collect::<Vec<_>>()
            .join("::");

        let mut test = TestFn {
            name: qualified,
            line: node.start_position().row + 1,
            total_asserts: 0,
            strong_asserts: 0,
            tautologies: 0,
            ignored,
            should_panic,
        };
        if let Some(body) = node.child_by_field_name("body") {
            self.count_asserts(body, &mut test);
        }
        Some(test)
    }

    fn count_asserts(&self, node: Node, test: &mut TestFn) {
        match node.kind() {
            "macro_invocation" => {
                if let Some(m) = node.child_by_field_name("macro") {
                    let name = last_segment(self.text(m));
                    if self.is_assert_macro(name) {
                        test.total_asserts += 1;
                        if is_strong(name) {
                            test.strong_asserts += 1;
                        }
                        let args = node
                            .children(&mut node.walk())
                            .find(|c| c.kind() == "token_tree")
                            .map(|t| self.text(t))
                            .unwrap_or("");
                        if is_tautology(name, args) {
                            test.tautologies += 1;
                        }
                    }
                }
            }
            "call_expression" => {
                if let Some(f) = node.child_by_field_name("function") {
                    let name = last_segment(self.text(f));
                    if self.vocab.helper_fns.iter().any(|h| h == name) {
                        test.total_asserts += 1;
                    }
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.count_asserts(child, test);
        }
    }

    fn is_assert_macro(&self, name: &str) -> bool {
        name.starts_with("assert")
            || name.starts_with("debug_assert")
            || name.starts_with("prop_assert")
            || self.vocab.extra_macros.iter().any(|m| m == name)
    }

    fn unsafe_site(&mut self, node: Node, kind: &'static str) {
        let documented = self.is_documented(node);
        let row = node.start_position().row;
        self.facts.unsafe_sites.push(UnsafeSite {
            line: row + 1,
            kind,
            documented,
            snippet: self
                .lines
                .get(row)
                .map(|l| l.trim().to_string())
                .unwrap_or_default(),
        });
    }

    /// A site is documented when a `SAFETY:` comment sits in the contiguous
    /// comment / attribute run directly above the unsafe node or above any
    /// ancestor up to its enclosing statement, or inline between the start of
    /// that statement and the `unsafe` keyword.
    fn is_documented(&self, node: Node) -> bool {
        let mut rows = vec![node.start_position().row];
        let mut statement = node;
        while let Some(parent) = statement.parent() {
            if matches!(
                parent.kind(),
                "block" | "source_file" | "declaration_list" | "unsafe_block"
            ) {
                break;
            }
            statement = parent;
            rows.push(statement.start_position().row);
        }
        rows.dedup();

        if rows.iter().any(|&row| self.safety_run_above(row)) {
            return true;
        }
        self.comments.iter().any(|c| {
            c.has_safety
                && c.start_byte >= statement.start_byte()
                && c.end_byte <= node.start_byte()
        })
    }

    fn safety_run_above(&self, row: usize) -> bool {
        let mut row = row;
        while row > 0 {
            row -= 1;
            let line = self.lines.get(row).copied().unwrap_or("").trim_start();
            if let Some(c) = self.comment_on_row(row) {
                if c.has_safety {
                    return true;
                }
                row = c.start_row;
            } else if line.starts_with("#[") {
                continue;
            } else {
                return false;
            }
        }
        false
    }

    /// A comment node that *begins the line* on `row` (or spans it), so a
    /// string literal that merely contains `// SAFETY:` does not qualify.
    fn comment_on_row(&self, row: usize) -> Option<&Comment> {
        let line = self.lines.get(row).copied().unwrap_or("");
        let indent = line.len() - line.trim_start().len();
        let line_start = self.line_starts.get(row).copied().unwrap_or(0);
        self.comments.iter().find(|c| {
            (c.start_row < row && c.end_row >= row)
                || (c.start_row == row && c.start_byte == line_start + indent)
        })
    }
}

fn parse_cfg_attr_sub_attributes(attr_text: &str) -> Vec<String> {
    let Some(start) = attr_text.find("cfg_attr") else {
        return Vec::new();
    };
    let rest = &attr_text[start + "cfg_attr".len()..];
    let Some(open_paren) = rest.find('(') else {
        return Vec::new();
    };
    let inside = &rest[open_paren + 1..];

    // Find first comma at paren depth 0 (relative to inside)
    let mut depth = 0;
    let mut condition_end = None;
    for (i, c) in inside.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            ',' if depth == 0 => {
                condition_end = Some(i);
                break;
            }
            _ => {}
        }
    }

    let Some(comma_pos) = condition_end else {
        return Vec::new();
    };

    let sub_attrs_text = &inside[comma_pos + 1..];
    let mut sub_attrs = Vec::new();
    let mut current = String::new();
    let mut depth = 0;
    for c in sub_attrs_text.chars() {
        match c {
            '(' | '[' | '{' => {
                depth += 1;
                current.push(c);
            }
            ')' if depth == 0 => {
                break;
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    sub_attrs.push(trimmed.to_string());
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        sub_attrs.push(trimmed.to_string());
    }

    sub_attrs
}

fn attribute_name(attr_text: &str) -> String {
    // `#[tokio::test(flavor = "multi_thread")]` -> `test`
    let inner = attr_text
        .trim_start_matches('#')
        .trim_start_matches('!')
        .trim_start_matches('[')
        .trim();
    let path: String = inner
        .chars()
        .take_while(|c| c.is_alphanumeric() || matches!(c, '_' | ':'))
        .collect();
    last_segment(&path).to_string()
}

fn last_segment(path: &str) -> &str {
    path.rsplit("::").next().unwrap_or(path).trim()
}

fn is_strong(name: &str) -> bool {
    name.contains("_eq") || name.contains("_ne") || name.contains("matches")
}

fn is_tautology(name: &str, token_tree: &str) -> bool {
    let inner = token_tree
        .trim()
        .trim_start_matches(['(', '[', '{'])
        .trim_end_matches([')', ']', '}']);
    let args = split_top_level(inner);
    let first = args.first().map(|s| s.trim()).unwrap_or("");
    if name.contains("_eq") {
        return args.len() >= 2 && first == args[1].trim() && !first.is_empty();
    }
    if name.contains("_ne") || name.contains("matches") {
        return false;
    }
    first == "true"
}

fn split_top_level(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut start, mut in_str) = (0i32, 0usize, false);
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' if i == 0 || bytes[i - 1] != b'\\' => in_str = !in_str,
            _ if in_str => {}
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(src: &str) -> RustFacts {
        analyze(src, &AssertVocabulary::default()).expect("analyze")
    }

    #[test]
    fn counts_assertions_per_test_and_ignores_comments_and_strings() {
        let f = facts(
            r#"
#[test]
fn real() {
    // assert_eq!(1, 2);
    let _s = "assert!(false)";
    assert_eq!(1 + 1, 2);
    assert!(2 > 1);
}
fn not_a_test() { assert!(true); }
"#,
        );
        assert_eq!(f.tests.len(), 1);
        assert_eq!(f.tests[0].name, "real");
        assert_eq!(f.tests[0].total_asserts, 2);
        assert_eq!(f.tests[0].strong_asserts, 1);
        assert!(!f.tests[0].is_vacuous());
    }

    #[test]
    fn detects_vacuous_and_tautological_tests() {
        let f = facts(
            r#"
mod tests {
    #[test] fn empty() {}
    #[test] fn tautology() { assert!(true); assert_eq!(1, 1); }
    #[test] #[should_panic(expected = "boom")] fn panics() { boom(); }
    #[tokio::test] async fn real() { assert_eq!(f().await, 3); }
}
"#,
        );
        let by_name = |n: &str| f.tests.iter().find(|t| t.name == n).unwrap().clone();
        assert!(by_name("tests::empty").is_vacuous());
        assert!(by_name("tests::tautology").is_vacuous());
        assert_eq!(by_name("tests::tautology").tautologies, 2);
        assert!(!by_name("tests::panics").is_vacuous());
        assert!(!by_name("tests::real").is_vacuous());
    }

    #[test]
    fn helper_fns_and_extra_macros_count_only_when_configured() {
        let src = "#[test] fn t() { check_invariants(&x); verify!(x); }";
        assert!(facts(src).tests[0].is_vacuous());
        let vocab = AssertVocabulary {
            extra_macros: vec!["verify".into()],
            helper_fns: vec!["check_invariants".into()],
        };
        let f = analyze(src, &vocab).unwrap();
        assert_eq!(f.tests[0].total_asserts, 2);
    }

    #[test]
    fn ignore_attribute_is_detected() {
        let f = facts("#[test]\n#[ignore = \"flaky\"]\nfn t() { assert_eq!(a(), 1); }");
        assert!(f.tests[0].ignored);

        let f2 = facts("#[test]\n#[cfg_attr(all(), ignore)]\nfn t2() { assert_eq!(a(), 1); }");
        assert!(f2.tests[0].ignored);

        let f3 = facts(
            "#[cfg_attr(feature = \"ignore_something\", test)]\nfn t3() { assert_eq!(a(), 1); }",
        );
        assert!(!f3.tests[0].ignored);
        assert_eq!(f3.tests.len(), 1);
    }

    #[test]
    fn safety_comment_above_block_or_statement_documents_it() {
        let f = facts(
            r#"
fn a(p: *const u8) -> u8 {
    // SAFETY: p is valid for reads.
    unsafe { *p }
}
fn b(p: *const u8) -> u8 {
    // SAFETY: p is valid for reads.
    let v = unsafe { *p };
    v
}
fn c(p: *const u8) -> u8 {
    let v = /* SAFETY: valid */ unsafe { *p };
    v
}
// SAFETY: T is Send.
unsafe impl Send for X {}
"#,
        );
        assert_eq!(f.unsafe_sites.len(), 4);
        assert!(
            f.unsafe_sites.iter().all(|s| s.documented),
            "{:?}",
            f.unsafe_sites
        );
    }

    #[test]
    fn undocumented_unsafe_is_flagged_even_without_a_space_before_the_brace() {
        let f = facts(
            r#"
fn a(p: *const u8) -> u8 { let v = unsafe{ *p }; v }
fn b(p: *const u8) -> u8 {
    // Safety: lower-case label does not count.
    unsafe { *p }
}
fn c(p: *const u8) -> u8 {
    let _doc = "// SAFETY: a string is not a comment";
    unsafe { *p }
}
fn d(p: *const u8) -> u8 {
    unsafe { *p } // SAFETY: trailing comment is after the fact
}
unsafe impl Sync for X {}
"#,
        );
        assert_eq!(f.unsafe_sites.len(), 5);
        assert!(
            f.unsafe_sites.iter().all(|s| !s.documented),
            "{:?}",
            f.unsafe_sites
        );
    }

    #[test]
    fn the_word_unsafe_in_comments_and_strings_is_not_a_site() {
        let f = facts("// unsafe { }\nfn a() { let _ = \"unsafe { x }\"; }");
        assert!(f.unsafe_sites.is_empty());
    }

    #[test]
    fn language_dispatch_is_by_extension() {
        assert_eq!(language_for("src/a.rs"), Some(Language::Rust));
        assert_eq!(language_for("src/a.py"), None);
        assert!(is_unsupported_source("pkg/mod/a.py"));
        assert!(is_unsupported_source("web/App.tsx"));
        assert!(!is_unsupported_source("src/a.rs"));
        assert!(!is_unsupported_source("docs/plan.md"));
        assert!(!is_unsupported_source("Makefile"));
    }

    #[test]
    fn parse_errors_are_surfaced() {
        assert!(facts("fn broken( {").has_parse_errors);
        assert!(!facts("fn fine() {}").has_parse_errors);
    }
}
