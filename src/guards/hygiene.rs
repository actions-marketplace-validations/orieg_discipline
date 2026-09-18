//! Whole-tree hygiene gates. They sweep every tracked file (not just the
//! diff), plus the PR body when one is supplied.

use super::{exempt_filter, line_allows, Context, GateOutcome, PathFilter};
use crate::config::{GateSettings, PiiGate};
use anyhow::{Context as _, Result};
use regex::Regex;

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
        r"(?i)\b\d+(?:\.\d+)?(?:\s*[-–]\s*\d+(?:\.\d+)?)?\s*-?\s*(?:(?:business|working|calendar)\s+|(?:engineer|person|man|dev)[- ])?(?:minutes?|mins?|hours?|hrs?|days?|weeks?|wks?|months?|quarters?|sprints?|years?)\b",
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

#[derive(Default)]
struct MarkdownTableTracker {
    header_line: Option<String>,
    exempt_cols: Vec<bool>,
    in_table: bool,
}

impl MarkdownTableTracker {
    fn feed_line(&mut self, line: &str) {
        let trimmed = line.trim();
        if !trimmed.contains('|') {
            self.header_line = None;
            self.exempt_cols.clear();
            self.in_table = false;
            return;
        }

        let is_sep = {
            let cells = trimmed
                .split('|')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            !cells.is_empty()
                && cells.iter().all(|c| {
                    !c.is_empty()
                        && c.chars()
                            .all(|ch| ch == '-' || ch == ':' || ch.is_whitespace())
                })
        };

        if is_sep {
            if let Some(hdr) = self.header_line.take() {
                self.exempt_cols = Self::parse_exempt_columns(&hdr);
                self.in_table = true;
                return;
            }
        }

        if !self.in_table {
            self.header_line = Some(line.to_string());
        }
    }

    fn is_cell_exempt(&self, line: &str, hit_start: usize) -> bool {
        if !self.in_table || self.exempt_cols.is_empty() {
            return false;
        }
        let pipe_count = line[..hit_start].chars().filter(|&c| c == '|').count();
        let col_idx = pipe_count.saturating_sub(1);
        self.exempt_cols.get(col_idx).copied().unwrap_or(false)
    }

    fn parse_exempt_columns(header: &str) -> Vec<bool> {
        let cells = header
            .split('|')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        let col_re = Regex::new(
            r"(?i)\b(latency|elapsed|wall(?:[- ]clock)?|runtime|run[- ]time|p\d{2,3}|(?:hosted\s+)?runner)\b",
        )
        .expect("valid regex");
        cells.into_iter().map(|c| col_re.is_match(c)).collect()
    }
}

pub(crate) fn is_exempt_time_estimate(
    line: &str,
    hit_start: usize,
    hit_end: usize,
    matched: &str,
) -> bool {
    let before = &line[..hit_start];
    let after = &line[hit_end..];

    // 1. Question references (Q1, Q2, Q3, Q4)
    if matches!(matched, "Q1" | "Q2" | "Q3" | "Q4") {
        let before_trimmed = before.trim_end();
        let before_lower = before_trimmed.to_lowercase();
        // If preceded by scheduling / planning cues, it is a quarter estimate, not a question!
        let sched_cues = [
            "target:", "target", "done in", "in", "by", "due in", "due", "for", "release:",
            "release", "launch:", "launch", "roadmap:", "phase",
        ];
        if sched_cues.iter().any(|c| before_lower.ends_with(c)) {
            return false;
        }

        let after_trimmed = after.trim_start();
        if after_trimmed.starts_with(['—', '–', '-', ':', ')', '?'])
            || after_trimmed.starts_with(". ")
            || after_trimmed.starts_with("'s")
            || after_trimmed.starts_with("’s")
        {
            return true;
        }
        if before_lower.ends_with("question")
            || before_lower.ends_with("quoting")
            || before_lower.ends_with("answering")
            || before_lower.ends_with("ask")
        {
            return true;
        }
        if (before_trimmed.ends_with("**")
            || before_trimmed.starts_with('#')
            || before_trimmed.starts_with('('))
            && (after.contains('?') || after.contains('—') || after.contains(':'))
        {
            return true;
        }
        return false;
    }

    // 2. Historical durations / ages
    let after_trimmed = after.trim_start();
    if after.starts_with("-old")
        || after_trimmed.starts_with("old")
        || after_trimmed.starts_with("ago")
    {
        return true;
    }
    if after_trimmed.starts_with("invariants")
        || after_trimmed.starts_with("history")
        || after_trimmed.starts_with("precedent")
    {
        return true;
    }
    let before_lower = before.to_lowercase();
    if matched.contains("year") {
        let hist_cues = [
            "for over",
            "for the past",
            "for the last",
            "for ~",
            "for about",
            "over the past",
            "over the last",
            "in the past",
            "in the last",
            "survived",
            "undetected for",
            "silently for",
            "unchecked for",
        ];
        if hist_cues
            .iter()
            .any(|cue| before_lower.ends_with(cue) || before_lower.trim_end().ends_with(cue))
        {
            return true;
        }
        if before_lower.trim_end().ends_with("for")
            || before_lower.trim_end().ends_with("for ~")
            || before_lower.trim_end().ends_with("for over")
        {
            return true;
        }
    }

    // 3. Operational limits / budgets / caps / timeouts / retention
    let after_prefix = match after.char_indices().nth(25) {
        Some((idx, _)) => &after[..idx],
        None => after,
    };
    let after_lower = after_prefix.to_lowercase();
    let after_tokens = after_lower.trim_start();
    if after_tokens.starts_with("budget")
        || after_tokens.starts_with("cap")
        || after_tokens.starts_with("limit")
        || after_tokens.starts_with("timeout")
        || after_tokens.starts_with("default")
        || after_tokens.starts_with("gap")
        || after_tokens.starts_with("window")
        || after_tokens.starts_with("active window")
        || after_tokens.starts_with("per")
        || after_tokens.starts_with("average")
        || after_tokens.starts_with("ttl")
        || after_tokens.starts_with("retention")
        || after_tokens.starts_with("of wall time")
        || after_tokens.starts_with("wall time")
        || after_tokens.starts_with("description")
        || after_tokens.starts_with("read")
        || after_tokens.starts_with("overview")
        || after_tokens.starts_with("paper")
        || after_tokens.starts_with("talk")
        || after_tokens.starts_with("presentation")
    {
        return true;
    }

    // Loadavg format: "5-min 1.32, 15-min 0.47" (followed by whitespace and float)
    if after.starts_with(char::is_whitespace) {
        let first_token = after.split_whitespace().next().unwrap_or("");
        let num_str = first_token.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
        if num_str.contains('.') && num_str.parse::<f64>().is_ok() {
            return true;
        }
    }

    // Cues in preceding text
    let char_count = before.chars().count();
    let before_suffix = if char_count > 35 {
        match before.char_indices().nth(char_count - 35) {
            Some((idx, _)) => &before[idx..],
            None => before,
        }
    } else {
        before
    };
    let before_lower = before_suffix.to_lowercase();
    let before_trimmed = before_lower.trim_end();
    let before_cues = [
        "retention is",
        "retention of",
        "retention",
        "ttl",
        "timeout of",
        "timeout is",
        "timeout:",
        "timeout-minutes:",
        "timeout",
        "budget of",
        "budget is",
        "budget:",
        "budget",
        "cap of",
        "cap is",
        "cap:",
        "cap",
        "limit of",
        "limit is",
        "limit:",
        "limit",
        "max of",
        "maximum of",
        "max",
        "took",
        "takes",
        "runs",
        "ran in",
        "ran for over",
        "ran for",
        "elapsed:",
        "elapsed",
        "runtime:",
        "runtime",
        "run time",
        "wall time",
        "wall-clock",
        "wall clock",
        "wall",
        "latency",
        "observed run (~",
        "observed run",
        "measured:",
        "measured",
        "loadavg",
        "load average",
        "decaying from",
        "p50",
        "p90",
        "p95",
        "p99",
    ];
    if before_cues
        .iter()
        .any(|cue| before_trimmed.ends_with(cue) || before_lower.contains(cue))
    {
        return true;
    }

    // URL or file path check: e.g. "https://judy.sourceforge.net/doc/10minutes.htm"
    let before_non_ws = before.split_whitespace().last().unwrap_or("");
    let after_non_ws = after.split_whitespace().next().unwrap_or("");
    if before_non_ws.contains("://")
        || before_non_ws.contains('/')
        || after_non_ws.contains('/')
        || after_non_ws.starts_with(".htm")
        || after_non_ws.starts_with(".html")
    {
        return true;
    }

    false
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
        let mut table = MarkdownTableTracker::default();
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

            table.feed_line(line);

            if line_allows(line, GATE) {
                if banned.iter().any(|re| re.is_match(line)) {
                    out.inline_exemptions += 1;
                }
                continue;
            }
            if allowed.iter().any(|re| re.is_match(line)) {
                continue;
            }

            for re in &banned {
                for hit in re.find_iter(line) {
                    if table.is_cell_exempt(line, hit.start()) {
                        continue;
                    }
                    if is_exempt_time_estimate(line, hit.start(), hit.end(), hit.as_str()) {
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
            }
        }
    };

    for path in ctx.git.tracked_files()? {
        if !include.matches(&path) || exempt.matches(&path) {
            continue;
        }
        match ctx.git.head_content(&path)? {
            Some(text) => {
                out.examined += 1;
                scan(&path, &text, &mut out);
            }
            None => out.notes.push(format!("skipped `{path}` (binary file)")),
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

pub(crate) fn is_exempt_lan_ip(
    ip_str: &str,
    line: &str,
    _match_start: usize,
    match_end: usize,
) -> bool {
    let parts: Vec<&str> = ip_str.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let Ok(d) = parts[3].parse::<u8>() else {
        return false;
    };

    // If the last octet is 0 (network address) or 255 (broadcast address), it's a network definition, not a host IP.
    if d == 0 || d == 255 {
        return true;
    }

    // Check for CIDR mask (e.g. /8, /12, /16, /24)
    let after = &line[match_end..];
    if let Some(rest) = after.strip_prefix('/') {
        let mask_str = rest
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>();
        if let Ok(prefix_len) = mask_str.parse::<u32>() {
            if (1..=32).contains(&prefix_len) {
                if let (Ok(o0), Ok(o1), Ok(o2)) = (
                    parts[0].parse::<u32>(),
                    parts[1].parse::<u32>(),
                    parts[2].parse::<u32>(),
                ) {
                    let ip_num = (o0 << 24) | (o1 << 16) | (o2 << 8) | (d as u32);
                    let mask = if prefix_len == 0 {
                        0
                    } else {
                        !0u32 << (32 - prefix_len)
                    };
                    if (ip_num & !mask) == 0 {
                        return true;
                    }
                }
            }
        }
    }

    false
}

fn collect_json_strings<'a>(val: &'a serde_json::Value, out: &mut Vec<&'a str>) {
    match val {
        serde_json::Value::String(s) => out.push(s.as_str()),
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_json_strings(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, v) in map {
                out.push(key.as_str());
                collect_json_strings(v, out);
            }
        }
        _ => {}
    }
}

fn scan_json(
    label: &str,
    text: &str,
    rules: &[PiiRule],
    settings: &PiiGate,
    allowed: &[Regex],
    out: &mut GateOutcome,
) -> bool {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };

    let mut tokens = Vec::new();
    collect_json_strings(&val, &mut tokens);

    for token in tokens {
        for rule in rules {
            for caps in rule.re.captures_iter(token) {
                let m = caps.get(0).unwrap();
                if rule.label == "private LAN address"
                    && is_exempt_lan_ip(m.as_str(), token, m.start(), m.end())
                {
                    continue;
                }
                let allowed_user = rule.user_group
                    && caps.get(1).is_some_and(|u| {
                        settings
                            .allowed_users
                            .iter()
                            .any(|a| a.eq_ignore_ascii_case(u.as_str()))
                    });
                if allowed_user {
                    continue;
                }
                if allowed.iter().any(|re| re.is_match(token)) {
                    continue;
                }
                let detail = match (rule.redact, m.as_str()) {
                    (false, s) => format!("{} `{s}`", rule.label),
                    _ => format!("{} (match not echoed)", rule.label),
                };
                let line_num = text
                    .lines()
                    .position(|l| l.contains(token))
                    .map(|p| p + 1)
                    .unwrap_or(1);
                out.push(
                    settings.severity(),
                    "Host / PII Leak",
                    Some(label),
                    Some(line_num),
                    format!("Found a {detail}."),
                    "Replace it with a placeholder such as `<home>` or `<host>`. A line that must \
                     keep it can carry `discipline:allow(pii)`.",
                );
            }
        }
    }
    true
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
                    let m = caps.get(0).unwrap();
                    if rule.label == "private LAN address"
                        && is_exempt_lan_ip(m.as_str(), line, m.start(), m.end())
                    {
                        return None;
                    }
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
            Some(text) => {
                out.examined += 1;
                if path.ends_with(".json")
                    && scan_json(&path, &text, &rules, settings, &allowed, &mut out)
                {
                    continue;
                }
                scan(&path, &text, &mut out);
            }
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
    fn contextual_exemptions_discriminate() {
        // Operational / measurement contexts are exempt
        let exempt_cases = [
            ("artifact retention is 30 days", "30 days"),
            ("each shard with its own 180-minute budget", "180-minute"),
            ("cancelled at its 60-minute cap", "60-minute"),
            ("GitHub's 6-hour default", "6-hour"),
            ("the 6-hour gap between runs", "6-hour"),
            ("ran for over two hours of wall time", "two hours"),
            ("that is a 1-min average decaying", "1-min"),
            ("5-min 1.32, 15-min 0.47", "5-min"),
            ("20-year-old C library", "20-year"),
            ("invariants unchecked for 20 years", "20 years"),
            ("the 20-year invariants hold", "20-year"),
            ("bug survived 19 years", "19 years"),
            ("went undetected for ~19 years", "19 years"),
            ("**Q1 — what do our patches buy?**", "Q1"),
            ("### Q2: Why judy?", "Q2"),
            ("Q3. How does this scale?", "Q3"),
            ("only Q1's is ours", "Q1"),
            ("Quoting Q2 as", "Q2"),
            (
                "A 10-Minute Description of How Judy Arrays Work",
                "10-Minute",
            ),
        ];
        for (line, hit) in exempt_cases {
            let start = line.find(hit).unwrap();
            let end = start + hit.len();
            assert!(
                is_exempt_time_estimate(line, start, end, hit),
                "expected exempt: {line} (hit: {hit})"
            );
        }

        // Planning / scheduling estimates are NOT exempt
        let non_exempt_cases = [
            ("Ship in 3 weeks; update cache ttl.", "3 weeks"),
            ("Target: Q2.", "Q2"),
            ("Done in Q3.", "Q3"),
            ("Working for 3 weeks on migration.", "3 weeks"),
            ("Phase 2 (1 week)", "1 week"),
            ("ships in 1-2 days", "1-2 days"),
            ("~10 engineer-days", "10 engineer-days"),
        ];
        for (line, hit) in non_exempt_cases {
            let start = line.find(hit).unwrap();
            let end = start + hit.len();
            assert!(
                !is_exempt_time_estimate(line, start, end, hit),
                "expected violation (not exempt): {line} (hit: {hit})"
            );
        }
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
