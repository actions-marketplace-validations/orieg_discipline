//! Gate-integrity: a change must not quietly lower the bar it is judged by.
//!
//! `discipline.toml` is fully user-configurable, which makes it the cheapest
//! thing for an agent to edit when a gate is in the way. This gate compares
//! the configuration on the base side with the head side and demands a scoped
//! `allow-gate-weakening:` directive for every loosening.

use super::{Context, GateOutcome};
use crate::config::{DisciplineConfig, GateSettings, Severity};
use crate::tokens::{self, covers, directive_reasons};
use anyhow::Result;
use toml::Value;

/// List options where a *longer* list is looser.
const LOOSER_WHEN_GROWN: &[&str] = &[
    "exempt_paths",
    "allow_patterns",
    "allowed_users",
    "extra_assert_macros",
    "assert_helper_fns",
];
/// List options where a *shorter* list is looser.
const LOOSER_WHEN_SHRUNK: &[&str] = &["paths", "include", "extra_patterns", "hostname_denylist"];

#[derive(Debug, PartialEq, Eq)]
pub struct Weakening {
    pub gate: String,
    pub what: String,
}

pub fn config_integrity(ctx: &Context) -> Result<GateOutcome> {
    const GATE: &str = "config-integrity";
    let settings = &ctx.config.gates.config_integrity;
    let mut out = GateOutcome::new(GATE);

    let Some(base_src) = ctx.git.base_content(ctx.config_path)? else {
        out.notes.push(format!(
            "`{}` does not exist on the base side; nothing to compare against",
            ctx.config_path
        ));
        return Ok(out);
    };
    let base = match DisciplineConfig::from_toml_str(&base_src) {
        Ok(c) => c,
        Err(e) => {
            // Blocking here would deadlock the PR that repairs the base config.
            out.push(
                Severity::Warning,
                "Base Configuration Unreadable",
                Some(ctx.config_path),
                None,
                format!("The base-side configuration does not load with this binary ({e:#}); weakening could not be checked."),
                "Repair the configuration on the base branch.",
            );
            return Ok(out);
        }
    };
    let head = if ctx.git.is_tracked(ctx.config_path)? {
        match ctx.git.head_content(ctx.config_path)? {
            Some(src) => DisciplineConfig::from_toml_str(&src)?,
            None => DisciplineConfig::default_for_repo(&base.meta.name),
        }
    } else {
        DisciplineConfig::default_for_repo(&base.meta.name)
    };

    let weakenings = diff_configs(&base, &head)?;
    out.examined = Value::try_from(&base.gates)?
        .as_table()
        .map(|t| t.len())
        .unwrap_or(0);
    let reasons = directive_reasons(&ctx.directive_text, tokens::ALLOW_GATE_WEAKENING);
    for w in weakenings {
        if covers(&reasons, &w.gate) {
            continue;
        }
        out.push(
            ctx.overridable(settings.severity()),
            "Gate Weakened By This Change",
            Some(ctx.config_path),
            None,
            format!("[gates.{}] {}.", w.gate, w.what),
            &format!(
                "Revert the change, or justify it on its own line in the PR body or a commit \
                 message: `allow-gate-weakening: {} <reason>`.",
                w.gate
            ),
        );
    }
    Ok(out)
}

pub fn diff_configs(base: &DisciplineConfig, head: &DisciplineConfig) -> Result<Vec<Weakening>> {
    let base_v = Value::try_from(&base.gates)?;
    let head_v = Value::try_from(&head.gates)?;
    let (Some(base_t), Some(head_t)) = (base_v.as_table(), head_v.as_table()) else {
        return Ok(Vec::new());
    };

    let mut found = Vec::new();
    for (gate, base_gate) in base_t {
        let (Some(b), Some(h)) = (
            base_gate.as_table(),
            head_t.get(gate).and_then(Value::as_table),
        ) else {
            continue;
        };
        let mut note = |what: String| {
            found.push(Weakening {
                gate: gate.clone(),
                what,
            })
        };
        for (key, bv) in b {
            let Some(hv) = h.get(key) else { continue };
            match (bv, hv) {
                (Value::Boolean(true), Value::Boolean(false)) => {
                    note(format!("`{key}` changed from true to false"))
                }
                (Value::String(bs), Value::String(hs))
                    if key == "severity" && bs == "error" && hs == "warning" =>
                {
                    note("`severity` lowered from error to warning".to_string())
                }
                (Value::Array(ba), Value::Array(ha)) => {
                    let gained: Vec<_> = ha.iter().filter(|x| !ba.contains(x)).collect();
                    let lost: Vec<_> = ba.iter().filter(|x| !ha.contains(x)).collect();
                    if LOOSER_WHEN_GROWN.contains(&key.as_str()) && !gained.is_empty() {
                        note(format!("`{key}` gained {} entr(y/ies)", gained.len()));
                    }
                    if LOOSER_WHEN_SHRUNK.contains(&key.as_str()) && !lost.is_empty() {
                        note(format!("`{key}` lost {} entr(y/ies)", lost.len()));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(body: &str) -> DisciplineConfig {
        DisciplineConfig::from_toml_str(&format!("[meta]\nversion = 1\nname = \"t\"\n{body}"))
            .unwrap()
    }

    #[test]
    fn identical_and_stricter_configs_are_not_weakenings() {
        let base = cfg("[gates.pii]\nexempt_paths = [\"a/**\"]\n");
        assert!(diff_configs(&base, &base).unwrap().is_empty());
        let stricter = cfg("[gates.pii]\nhostname_denylist = [\"h\"]\n");
        assert!(diff_configs(&base, &stricter).unwrap().is_empty());
    }

    #[test]
    fn each_loosening_class_is_detected_and_attributed() {
        let base = cfg("[gates.pii]\nhostname_denylist = [\"h\"]\n");
        let head = cfg(
            "[gates.pii]\nlan_ips = false\nexempt_paths = [\"docs/**\"]\n\
             [gates.vacuous-tests]\nenabled = false\n\
             [gates.time-estimates]\nseverity = \"warning\"\n",
        );
        let found = diff_configs(&base, &head).unwrap();
        let has = |gate: &str, needle: &str| {
            found
                .iter()
                .any(|w| w.gate == gate && w.what.contains(needle))
        };
        assert!(has("pii", "`lan_ips` changed from true to false"));
        assert!(has("pii", "`exempt_paths` gained 1"));
        assert!(has("pii", "`hostname_denylist` lost 1"));
        assert!(has("vacuous-tests", "`enabled` changed from true to false"));
        assert!(has("time-estimates", "`severity` lowered"));
        assert_eq!(found.len(), 5, "{found:?}");
    }
}
