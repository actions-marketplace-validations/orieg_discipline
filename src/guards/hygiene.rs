//! Whole-tree hygiene gates. They sweep every tracked file (not just the
//! diff), plus the PR body when one is supplied.

use super::{exempt_filter, line_allows, Context, GateOutcome, PathFilter};
use crate::config::{GateSettings, PiiGate};
use anyhow::{Context as _, Result};
use regex::Regex;

/// Files larger than this are skipped by content scanners and named in the
/// outcome notes rather than silently passed.
const MAX_SCAN_BYTES: usize = 2 * 1024 * 1024;

pub fn agents_md(ctx: &Context) -> Result<GateOutcome> {
    const GATE: &str = "agents-md";
    let settings = &ctx.config.gates.agents_md;
    let exempt = exempt_filter(settings)?;
    let mut out = GateOutcome::new(GATE);
    out.examined = 1;

    if !ctx.git.is_tracked("AGENTS.md")? {
        out.push(
            settings.severity(),
            "Missing AGENTS.md",
            Some("AGENTS.md"),
            None,
            "The repository tracks no canonical AGENTS.md to govern AI agent behavior.".to_string(),
            "Create AGENTS.md and symlink CLAUDE.md / GEMINI.md to it.",
        );
        return Ok(out);
    }

    let canonical = ctx.git.head_content("AGENTS.md")?;
    for alias in ["CLAUDE.md", "GEMINI.md"] {
        if exempt.matches(alias) || !ctx.git.is_tracked(alias)? || ctx.git.is_symlink(alias)? {
            continue;
        }
        out.examined += 1;
        if ctx.git.head_content(alias)? != canonical {
            out.push(
                settings.severity(),
                "Forked Agent Guide",
                Some(alias),
                None,
                format!("`{alias}` is a regular file whose content differs from AGENTS.md."),
                "Replace it with a symlink to AGENTS.md so agents read one set of rules.",
            );
        }
    }
    Ok(out)
}

/// Base patterns for calendar / duration estimates. Kept as data so the
/// self-test and the unit tests exercise exactly what ships.
pub fn time_estimate_patterns() -> Vec<&'static str> {
    vec![
        // "3 weeks", "1-2 days", "~10 engineer-days", "2-hour"
        r"(?i)\b\d+(?:\s*[-–]\s*\d+)?\s*-?\s*(?:(?:business|working|calendar)\s+|(?:engineer|person|man|dev)[- ])?(?:minutes?|mins?|hours?|hrs?|days?|weeks?|wks?|months?|quarters?|sprints?|years?)\b",
        r"(?i)\b(?:next|this|following|coming)\s+(?:sprint|week|month|quarter)\b",
        r"\bQ[1-4]\b",
        r"(?i)\b(?:engineer|person|man|dev)[- ](?:hours?|days?|weeks?|months?)\b",
        r"(?i)\bby\s+(?:mon|tues|wednes|thurs|fri|satur|sun)day\b",
        r"(?i)\bover\s+the\s+weekend\b",
    ]
}

fn compile(patterns: impl IntoIterator<Item = impl AsRef<str>>, what: &str) -> Result<Vec<Regex>> {
    patterns
        .into_iter()
        .map(|p| {
            Regex::new(p.as_ref()).with_context(|| format!("invalid {what} regex `{}`", p.as_ref()))
        })
        .collect()
}

pub fn time_estimates(ctx: &Context) -> Result<GateOutcome> {
    const GATE: &str = "time-estimates";
    let settings = &ctx.config.gates.time_estimates;
    let exempt = exempt_filter(settings)?;
    let include = PathFilter::new(&settings.include)?;
    let mut banned = compile(time_estimate_patterns(), "built-in")?;
    banned.extend(compile(&settings.extra_patterns, "extra_patterns")?);
    let allowed = compile(&settings.allow_patterns, "allow_patterns")?;
    let mut out = GateOutcome::new(GATE);

    let mut scan = |label: &str, text: &str, out: &mut GateOutcome| {
        let mut fence: Option<&str> = None;
        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if let Some(m) = ["```", "~~~"].into_iter().find(|m| trimmed.starts_with(m)) {
                fence = match fence {
                    None => Some(m),
                    Some(open) if open == m => None,
                    keep => keep,
                };
                continue;
            }
            if fence.is_some() {
                continue;
            }
            let Some(hit) = banned.iter().find_map(|re| re.find(line)) else {
                continue;
            };
            if line_allows(line, GATE) {
                out.inline_exemptions += 1;
                continue;
            }
            if allowed.iter().any(|re| re.is_match(line)) {
                continue;
            }
            out.push(
                settings.severity(),
                "Time Estimate",
                Some(label),
                Some(idx + 1),
                format!("Calendar / duration estimate `{}`.", hit.as_str()),
                "Replace it with ordering, dependencies, or a gate criterion. A line that \
                 must quote the term can carry `<!-- discipline:allow(time-estimates) -->`.",
            );
        }
    };

    for path in ctx.git.tracked_files()? {
        if !include.matches(&path) || exempt.matches(&path) {
            continue;
        }
        match ctx.git.head_content(&path)? {
            Some(text) if text.len() <= MAX_SCAN_BYTES => {
                out.examined += 1;
                scan(&path, &text, &mut out);
            }
            _ => out
                .notes
                .push(format!("skipped `{path}` (binary or over the size cap)")),
        }
    }
    scan_pr_body(ctx, settings.scan_pr_body, &mut out, &mut scan);
    Ok(out)
}

fn scan_pr_body(
    ctx: &Context,
    wanted: bool,
    out: &mut GateOutcome,
    scan: &mut dyn FnMut(&str, &str, &mut GateOutcome),
) {
    if !wanted {
        return;
    }
    match &ctx.pr_body {
        Some(body) => {
            out.examined += 1;
            scan("<PR body>", body, out);
        }
        None => out
            .notes
            .push("no PR body supplied; PR-body scan did not run".to_string()),
    }
}

pub struct PiiRule {
    pub re: Regex,
    pub label: &'static str,
    /// Capture group holding a user name to test against `allowed_users`.
    pub user_group: bool,
    /// Echoing the match would repeat the secret in CI logs.
    pub redact: bool,
}

pub fn pii_rules(settings: &PiiGate) -> Result<Vec<PiiRule>> {
    let mut rules = Vec::new();
    if settings.home_paths {
        // Built from pieces so this source file does not match its own rule.
        let unix = format!(r"/(?:{}|{})/([A-Za-z0-9][A-Za-z0-9._-]*)", "Users", "home");
        let windows = format!(r"(?i)\b[A-Z]:\\{}\\([A-Za-z0-9][A-Za-z0-9._-]*)", "Users");
        for p in [unix, windows] {
            rules.push(PiiRule {
                re: Regex::new(&p)?,
                label: "home-directory path",
                user_group: true,
                redact: true,
            });
        }
    }
    if settings.lan_ips {
        rules.push(PiiRule {
            re: Regex::new(
                r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b",
            )?,
            label: "private LAN address",
            user_group: false,
            redact: false,
        });
    }
    for host in &settings.hostname_denylist {
        let host = host.trim();
        if host.is_empty() {
            continue;
        }
        rules.push(PiiRule {
            re: Regex::new(&format!(
                r"(?i)(?:^|[^A-Za-z0-9-]){}(?:$|[^A-Za-z0-9-])",
                regex::escape(host)
            ))?,
            label: "denylisted hostname",
            user_group: false,
            redact: true,
        });
    }
    for p in &settings.extra_patterns {
        rules.push(PiiRule {
            re: Regex::new(p).with_context(|| format!("invalid pii extra_patterns regex `{p}`"))?,
            label: "configured pattern",
            user_group: false,
            redact: true,
        });
    }
    Ok(rules)
}

pub fn pii(ctx: &Context) -> Result<GateOutcome> {
    const GATE: &str = "pii";
    let settings = &ctx.config.gates.pii;
    let exempt = exempt_filter(settings)?;
    let rules = pii_rules(settings)?;
    let allowed = compile(&settings.allow_patterns, "allow_patterns")?;
    let mut out = GateOutcome::new(GATE);
    let mut binary = 0usize;

    let mut scan = |label: &str, text: &str, out: &mut GateOutcome| {
        for (idx, line) in text.lines().enumerate() {
            let hit = rules.iter().find_map(|rule| {
                rule.re.captures_iter(line).find_map(|caps| {
                    let allowed_user = rule.user_group
                        && caps.get(1).is_some_and(|u| {
                            settings
                                .allowed_users
                                .iter()
                                .any(|a| a.eq_ignore_ascii_case(u.as_str()))
                        });
                    (!allowed_user).then(|| (rule, caps.get(0).map(|m| m.as_str().to_string())))
                })
            });
            let Some((rule, matched)) = hit else { continue };
            if line_allows(line, GATE) {
                out.inline_exemptions += 1;
                continue;
            }
            if allowed.iter().any(|re| re.is_match(line)) {
                continue;
            }
            let detail = match (rule.redact, matched) {
                (false, Some(m)) => format!("{} `{m}`", rule.label),
                _ => format!("{} (match not echoed)", rule.label),
            };
            out.push(
                settings.severity(),
                "Host / PII Leak",
                Some(label),
                Some(idx + 1),
                format!("Found a {detail}."),
                "Replace it with a placeholder such as `<home>` or `<host>`. A line that must \
                 keep it can carry `discipline:allow(pii)`.",
            );
        }
    };

    for path in ctx.git.tracked_files()? {
        if exempt.matches(&path) {
            continue;
        }
        match ctx.git.head_content(&path)? {
            Some(text) if text.len() <= MAX_SCAN_BYTES => {
                out.examined += 1;
                scan(&path, &text, &mut out);
            }
            Some(_) => out
                .notes
                .push(format!("skipped `{path}` (over the size cap)")),
            None => binary += 1,
        }
    }
    if binary > 0 {
        out.notes
            .push(format!("{binary} binary file(s) not scanned"));
    }
    scan_pr_body(ctx, settings.scan_pr_body, &mut out, &mut scan);
    Ok(out)
}

pub fn agent_scratch(ctx: &Context) -> Result<GateOutcome> {
    const GATE: &str = "agent-scratch";
    let settings = &ctx.config.gates.agent_scratch;
    let exempt = exempt_filter(settings)?;
    let forbidden = PathFilter::new(&settings.paths)?;
    let mut out = GateOutcome::new(GATE);

    for path in ctx.git.tracked_files()? {
        out.examined += 1;
        if forbidden.matches(&path) && !exempt.matches(&path) {
            out.push(
                settings.severity(),
                "Tracked Agent Scratch State",
                Some(&path),
                None,
                format!("`{path}` matches a forbidden agent-scratch pattern and is tracked."),
                "Untrack it with `git rm --cached` and add the pattern to .gitignore.",
            );
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any_match(patterns: &[Regex], line: &str) -> bool {
        patterns.iter().any(|re| re.is_match(line))
    }

    #[test]
    fn time_estimate_patterns_discriminate() {
        let banned = compile(time_estimate_patterns(), "t").unwrap();
        for bad in [
            "Phase 2 (1 week)",
            "ships in 1-2 days",
            "~10 engineer-days",
            "roughly 3 weeks of work",
            "done next sprint",
            "target: Q2",
            "a 2-hour task",
            "finish by Friday",
            "over the weekend",
        ] {
            assert!(any_match(&banned, bad), "missed: {bad}");
        }
        for good in [
            "Phase 1 then Phase 2",
            "blocked on the AST engine",
            "sub-50ms startup (target)",
            "version 1.80.0",
            "SHA256SUMS",
            "smallest of the three",
        ] {
            assert!(!any_match(&banned, good), "false positive: {good}");
        }
    }

    #[test]
    fn default_allow_patterns_cover_operational_durations() {
        let allowed = compile(
            &crate::config::TimeEstimateGate::default().allow_patterns,
            "t",
        )
        .unwrap();
        assert!(any_match(&allowed, "artifact retention is 30 days"));
        assert!(!any_match(&allowed, "the migration takes 30 days"));
    }

    fn rule_hits(settings: &PiiGate, line: &str) -> bool {
        pii_rules(settings).unwrap().iter().any(|r| {
            r.re.captures_iter(line).any(|c| {
                !(r.user_group
                    && c.get(1).is_some_and(|u| {
                        settings
                            .allowed_users
                            .iter()
                            .any(|a| a.eq_ignore_ascii_case(u.as_str()))
                    }))
            })
        })
    }

    #[test]
    fn pii_rules_discriminate() {
        let s = PiiGate::default();
        let home = format!("/{}/alice/project", "Users");
        let linux = format!("/{}/bob/.cache", "home");
        let win = format!(r"C:\{}\carol\x", "Users");
        let ip = ["192", "168", "1", "20"].join(".");
        for bad in [home.as_str(), linux.as_str(), win.as_str(), ip.as_str()] {
            assert!(rule_hits(&s, bad), "missed: {bad}");
        }
        let runner = format!("/{}/runner/work", "home");
        let placeholder = format!("/{}/<user>/x", "Users");
        for good in [runner.as_str(), placeholder.as_str(), "8.8.8.8", "v10.2.3"] {
            assert!(!rule_hits(&s, good), "false positive: {good}");
        }
    }

    #[test]
    fn hostname_denylist_is_whole_token_and_case_insensitive() {
        let s = PiiGate {
            hostname_denylist: vec!["buildbox".into()],
            ..PiiGate::default()
        };
        assert!(rule_hits(&s, "measured on BuildBox, 8 cores"));
        assert!(rule_hits(&s, "buildbox"));
        assert!(!rule_hits(&s, "the buildboxes are idle"));
        assert!(!rule_hits(&s, "my-buildbox-2"));
        assert!(!rule_hits(&PiiGate::default(), "measured on buildbox"));
    }

    #[test]
    fn toggles_and_extra_patterns_change_the_rule_set() {
        let off = PiiGate {
            home_paths: false,
            lan_ips: false,
            ..PiiGate::default()
        };
        assert!(pii_rules(&off).unwrap().is_empty());
        let extra = PiiGate {
            extra_patterns: vec![r"[a-z]+@corp\.example".into()],
            ..off.clone()
        };
        assert!(rule_hits(&extra, "mail dana@corp.example"));
        let bad = PiiGate {
            extra_patterns: vec!["(".into()],
            ..off
        };
        assert!(pii_rules(&bad).is_err());
    }
}
