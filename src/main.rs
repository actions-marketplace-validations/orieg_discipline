use anyhow::{bail, Context as _, Result};
use clap::Parser;
use discipline::cli::{CheckArgs, Cli, Commands, ConfigArgs, OutputFormat, SuiteChoice};
use discipline::config::{split_list, DisciplineConfig, Overrides, GATES, HOSTNAME_DENYLIST_ENV};
use discipline::gitctx::GitCtx;
use discipline::guards::{run_checks, Context};
use discipline::report::render_report;
use discipline::style;
use std::path::Path;
use std::process::ExitCode;

/// 0 = pass, 1 = violations, 2 = the check itself could not run. Keeping the
/// last two apart lets CI tell "the change is bad" from "the gate is broken".
fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("{} {e:#}", style::red("discipline: could not check:"));
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool> {
    match Cli::parse().command {
        Commands::Check(args) => check(args),
        Commands::Diff(args) => check(CheckArgs {
            config: ConfigArgs {
                config: "discipline.toml".into(),
                config_override: None,
                enable: Vec::new(),
                disable: Vec::new(),
            },
            suite: SuiteChoice::AgentGuard,
            base: args.base,
            staged: false,
            pr_body_file: None,
            fail_on_warnings: false,
            format: OutputFormat::Terminal,
            json_out: None,
        }),
        Commands::Init(args) => init(args.name),
        Commands::Gates(args) => gates(&args.config),
        Commands::SelfTest => discipline::selftest::run(),
    }
}

fn load_config(args: &ConfigArgs) -> Result<DisciplineConfig> {
    let overrides = Overrides {
        config_override: args
            .config_override
            .clone()
            .filter(|s| !s.trim().is_empty()),
        enable: args.enable.iter().flat_map(|s| split_list(s)).collect(),
        disable: args.disable.iter().flat_map(|s| split_list(s)).collect(),
        hostname_denylist: std::env::var(HOSTNAME_DENYLIST_ENV)
            .map(|v| split_list(&v))
            .unwrap_or_default(),
    };
    let explicit = args.config != Path::new("discipline.toml");
    if args.config.exists() {
        DisciplineConfig::resolve(Some(&args.config), &overrides)
    } else if explicit {
        bail!(
            "configuration file {} does not exist",
            args.config.display()
        );
    } else {
        eprintln!(
            "{} no discipline.toml; using built-in defaults (every available gate on).",
            style::yellow("note:")
        );
        DisciplineConfig::resolve(None, &overrides)
    }
}

fn check(args: CheckArgs) -> Result<bool> {
    let config = load_config(&args.config)?;
    let git = GitCtx::open(&args.base, args.staged)?;

    let pr_body = match &args.pr_body_file {
        Some(p) => Some(
            std::fs::read_to_string(p)
                .with_context(|| format!("failed to read PR body file {}", p.display()))?,
        ),
        None => std::env::var("PR_BODY")
            .ok()
            .filter(|b| !b.trim().is_empty()),
    };
    let mut directive_text = pr_body.clone().unwrap_or_default();
    for msg in git.commit_messages()? {
        directive_text.push_str("\n\n");
        directive_text.push_str(&msg);
    }

    let config_path = args.config.config.to_string_lossy().replace('\\', "/");
    let ctx = Context {
        config: &config,
        git: &git,
        config_path: config_path.trim_start_matches("./"),
        staged: args.staged,
        pr_body,
        directive_text,
    };
    let summary = run_checks(&config, args.suite, &ctx)?;
    render_report(&summary, args.format, args.fail_on_warnings)?;
    if let Some(path) = &args.json_out {
        std::fs::write(path, serde_json::to_string_pretty(&summary)?)
            .with_context(|| format!("failed to write JSON report {}", path.display()))?;
    }
    Ok(summary.is_success(args.fail_on_warnings))
}

fn init(name: Option<String>) -> Result<bool> {
    let config_path = Path::new("discipline.toml");
    if config_path.exists() {
        bail!("discipline.toml already exists");
    }
    let project_name = name.unwrap_or_else(|| {
        std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "my-project".to_string())
    });
    let config = DisciplineConfig::default_for_repo(&project_name);
    std::fs::write(config_path, toml::to_string_pretty(&config)?)?;
    println!(
        "{} wrote discipline.toml for `{project_name}` with every available gate on.",
        style::green("ok:")
    );
    Ok(true)
}

fn gates(args: &ConfigArgs) -> Result<bool> {
    let config = load_config(args)?;
    println!("{:<24} {:<13} {:<9} SUMMARY", "GATE", "SUITE", "STATE");
    for g in GATES {
        let state = match config.gates.settings(g.id) {
            // Pad before styling: escape codes would count toward the width.
            _ if !g.available => style::dim(&format!("{:<9}", "planned")),
            Some(s) if s.enabled() => style::green(&format!("{:<9}", "on")),
            _ => style::yellow(&format!("{:<9}", "off")),
        };
        println!(
            "{:<24} {:<13} {} {}",
            g.id,
            g.suite.label(),
            state,
            g.summary
        );
    }
    Ok(true)
}
