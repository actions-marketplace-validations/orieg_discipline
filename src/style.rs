//! Minimal ANSI styling. Replaces the `colored` crate, whose MPL-2.0 license
//! falls outside this project's dependency allow-list (see deny.toml).
//! Honors `NO_COLOR` and only styles when stdout is a terminal or a CI log.

use std::io::IsTerminal;
use std::sync::OnceLock;

fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
            return false;
        }
        std::io::stdout().is_terminal() || std::env::var_os("GITHUB_ACTIONS").is_some()
    })
}

fn paint(code: &str, text: &str) -> String {
    if enabled() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn bold(t: &str) -> String {
    paint("1", t)
}
pub fn dim(t: &str) -> String {
    paint("2", t)
}
pub fn red(t: &str) -> String {
    paint("1;31", t)
}
pub fn green(t: &str) -> String {
    paint("32", t)
}
pub fn yellow(t: &str) -> String {
    paint("33", t)
}
pub fn cyan(t: &str) -> String {
    paint("36", t)
}
