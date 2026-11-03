#![forbid(unsafe_code)]
//! Dich command-line interface; package orchestration lives in `dich-engine`.
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

pub mod paths;
pub use paths::ResolvedPaths;

#[derive(Debug, Parser)]
#[command(name = "dich", about = "Versioned package store using Debian/Ubuntu sources (experimental)", version, long_about = None)]
pub struct Cli {
    /// Path to trusted source policy [default: /etc/dich/sources.toml or $XDG_CONFIG_HOME/dich/sources.toml]
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
    /// Protected cache directory [default: /var/cache/dich or $XDG_CACHE_HOME/dich]
    #[arg(long, global = true)]
    pub cache: Option<PathBuf>,
    /// Protected store directory [default: /var/lib/dich or $XDG_DATA_HOME/dich]
    #[arg(long, global = true)]
    pub store_dir: Option<PathBuf>,
    /// Force rootless (user) mode using XDG base directories
    #[arg(long, global = true, conflicts_with = "system")]
    pub rootless: bool,
    /// Force system mode using standard system directories (/etc/dich, /var/cache/dich, /var/lib/dich)
    #[arg(long, global = true, conflicts_with = "rootless")]
    pub system: bool,
    /// Explicit HTTP CONNECT proxy URL (no credentials; TLS validation remains enabled)
    #[arg(long, global = true)]
    pub https_proxy: Option<String>,
    /// Explicit maximum age for signed Release metadata, in seconds
    #[arg(long, global = true)]
    pub max_age_seconds: Option<u64>,
    /// Permit missing Valid-Until while still enforcing maximum age
    #[arg(long, global = true)]
    pub allow_missing_valid_until: bool,
    /// Emit versioned JSON output and errors
    #[arg(long, global = true)]
    pub json: bool,
    /// Structured log verbosity level (off, error, warn, info, debug)
    #[arg(long, global = true, value_enum, default_value = "off")]
    pub log_level: LogLevel,
    /// Output operation progress to stderr
    #[arg(long, global = true)]
    pub progress: bool,
    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    pub fn effective_log_level(&self) -> LogLevel {
        if self.log_level != LogLevel::Off {
            return self.log_level;
        }
        if let Ok(val) = std::env::var("DICH_LOG") {
            match val.to_lowercase().as_str() {
                "error" => LogLevel::Error,
                "warn" => LogLevel::Warn,
                "info" => LogLevel::Info,
                "debug" => LogLevel::Debug,
                _ => LogLevel::Off,
            }
        } else {
            LogLevel::Off
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Refresh authenticated package metadata
    Update,
    /// Find package names in the authenticated local cache
    Search { query: String },
    /// Display matching cached package records
    Show { package: String },
    /// List cached package versions
    Versions { package: String },
    /// Show an experimental, non-installable metadata dependency plan
    Plan {
        /// Exact package name
        package: String,
        /// Distribution identity: debian or ubuntu
        #[arg(long)]
        distribution: String,
        /// Immutable literal suite label
        #[arg(long)]
        suite: String,
        /// Native architecture for the plan
        #[arg(long)]
        architecture: String,
    },
    /// Download or reuse one exact package in the authenticated cache (does not install)
    Fetch {
        package: String,
        /// Exact Debian package version
        #[arg(long)]
        exact_version: String,
        /// Explicit configured repository component
        #[arg(long)]
        component: String,
        /// Maximum downloaded bytes (at most 256 MiB)
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        max_bytes: u64,
        /// Publish a conservative extracted tree into the existing store directory; never activate it
        #[arg(long)]
        publish_tree: bool,
    },
    /// Examine unauthenticated local Debian archives without extracting them
    Inspect {
        file: String,
        /// Additional packages explicitly supplied as one ELF dependency closure
        #[arg(long = "with", value_name = "DEB", action = clap::ArgAction::Append)]
        with: Vec<String>,
    },
    /// Plan or install an authenticated, supported DSO closure into a profile
    Install {
        package: String,
        #[arg(long, default_value = "default")]
        profile: String,
        /// Optional exact Debian version
        #[arg(long)]
        exact_version: Option<String>,
        /// Confirm fetching, extraction and profile selection
        #[arg(long)]
        yes: bool,
    },
    /// Plan or deactivate a package profile generation
    Remove {
        package: String,
        #[arg(long, default_value = "default")]
        profile: String,
        /// Confirm the atomic profile pointer change
        #[arg(long)]
        yes: bool,
    },
    /// Plan or switch a profile to its previous generation
    Rollback {
        #[arg(long, default_value = "default")]
        profile: String,
        /// Confirm the atomic profile pointer switch
        #[arg(long)]
        yes: bool,
    },
    /// Inspect locally recorded store objects
    Store {
        #[command(subcommand)]
        command: StoreCommands,
    },
    /// List active profile generations
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },
    /// Manage repositories
    Sources {
        #[command(subcommand)]
        command: SourcesCommands,
    },
    /// Garbage collect unreachable objects
    Gc {
        /// Report unreachable objects and reclaimable disk space without making any changes (default)
        #[arg(long, conflicts_with = "execute")]
        dry_run: bool,
        /// Delete unreachable trees from disk and clean up store metadata
        #[arg(long, conflicts_with = "dry_run")]
        execute: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum StoreCommands {
    /// List committed metadata without checking object bytes
    Ls,
    /// Check one object against local metadata; does not refresh repository trust
    Verify {
        id: String,
        #[arg(long, value_enum)]
        kind: StoreKind,
    },
}
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum StoreKind {
    Archive,
    Tree,
}
#[derive(Debug, Subcommand)]
pub enum ProfileCommands {
    List,
}
#[derive(Debug, Subcommand)]
pub enum SourcesCommands {
    /// List configured sources without contacting repositories
    List,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub code: &'static str,
    pub message: &'static str,
    pub trace: Vec<String>,
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self.code {
            "invalid_arguments" => 2,
            "unsupported"
            | "compatibility_rejected"
            | "profile_conflict"
            | "unsupported_platform"
            | "inspection_rejected" => 3,
            "unsatisfiable"
            | "profile_missing"
            | "rollback_unavailable"
            | "package_not_found"
            | "search_limit"
            | "install_limit" => 4,
            "integrity_rejected"
            | "verification_failed"
            | "signature_failed"
            | "tampered_metadata" => 5,
            _ => 1,
        }
    }

    pub fn hint(&self) -> Option<&'static str> {
        match self.code {
            "unsupported" | "compatibility_rejected" => {
                Some("Run 'dich inspect <deb>' to examine package compatibility constraints.")
            }
            "store_open_failed" => Some(
                "Verify the store directory path with --store-dir (default: /var/lib/dich or $XDG_DATA_HOME/dich) or check permissions.",
            ),
            "source_load_failed" => Some(
                "Verify the source policy file with --config (default: /etc/dich/sources.toml or $XDG_CONFIG_HOME/dich/sources.toml).",
            ),
            "cache_unavailable" | "cache_open_failed" => Some(
                "Verify the cache directory with --cache (default: /var/cache/dich or $XDG_CACHE_HOME/dich) or run 'dich update'.",
            ),
            "permission_denied" => Some(
                "Run with root privileges (e.g. sudo) for system paths, or use --rootless / user environment.",
            ),
            "unsatisfiable" => {
                Some("Run 'dich search <package>' to view available package versions.")
            }
            "profile_missing" => Some("Run 'dich profile list' to view active profiles."),
            "rollback_unavailable" => {
                Some("The specified profile has no previous generation recorded.")
            }
            "missing_age" => {
                Some("Specify --max-age-seconds to enforce signed Release metadata freshness.")
            }
            "missing_proxy" => {
                Some("Specify --https-proxy <http://host:port> to configure proxy routing.")
            }
            "invalid_arguments" => {
                Some("Run 'dich --help' or 'dich <command> --help' to see valid arguments.")
            }
            "unsupported_platform" => Some(
                "Store and profile operations require a Linux environment with openat2 support.",
            ),
            _ => None,
        }
    }

    pub fn render(&self, json: bool) -> String {
        let redacted_message = dich_core::redact_sensitive(self.message);
        let redacted_trace: Vec<String> = self
            .trace
            .iter()
            .map(|t| dich_core::redact_sensitive(t))
            .collect();
        if json {
            let mut err_obj = serde_json::json!({
                "code": self.code,
                "message": redacted_message,
                "exit_code": self.exit_code(),
                "trace": redacted_trace,
            });
            if let Some(hint) = self.hint() {
                err_obj["hint"] = serde_json::Value::String(hint.to_string());
            }
            serde_json::json!({
                "schema_version": 1,
                "status": "error",
                "error": err_obj,
            })
            .to_string()
        } else {
            let mut output = format!("dich: error: {redacted_message}");
            if !redacted_trace.is_empty() {
                output.push('\n');
                output.push_str(&redacted_trace.join("\n"));
            }
            if let Some(hint) = self.hint() {
                output.push_str(&format!("\nhint: {hint}"));
            }
            output
        }
    }
}

pub fn log_event(
    configured_level: LogLevel,
    json: bool,
    level: LogLevel,
    target: &str,
    message: &str,
    fields: &[(&str, &str)],
) {
    if configured_level == LogLevel::Off || level == LogLevel::Off || level > configured_level {
        return;
    }
    let level_str = match level {
        LogLevel::Error => "ERROR",
        LogLevel::Warn => "WARN",
        LogLevel::Info => "INFO",
        LogLevel::Debug => "DEBUG",
        LogLevel::Off => return,
    };
    let redacted_message = dich_core::redact_sensitive(message);
    if json {
        let mut field_map = serde_json::Map::new();
        for (k, v) in fields {
            field_map.insert(
                k.to_string(),
                serde_json::Value::String(dich_core::redact_sensitive(v)),
            );
        }
        let log_obj = serde_json::json!({
            "level": level_str,
            "target": target,
            "message": redacted_message,
            "fields": field_map,
        });
        eprintln!("{}", serde_json::to_string(&log_obj).unwrap_or_default());
    } else if fields.is_empty() {
        eprintln!("[{level_str} {target}] {redacted_message}");
    } else {
        let field_strs: Vec<String> = fields
            .iter()
            .map(|(k, v)| format!("{k}={}", dich_core::redact_sensitive(v)))
            .collect();
        eprintln!(
            "[{level_str} {target}] {redacted_message} ({})",
            field_strs.join(", ")
        );
    }
}

pub fn report_progress(
    progress_enabled: bool,
    json: bool,
    step: usize,
    total: usize,
    message: &str,
) {
    if progress_enabled && !json {
        let redacted = dich_core::redact_sensitive(message);
        eprintln!("[{step}/{total}] {redacted}");
    }
}

pub fn run(cli: Cli) -> Result<(), CliError> {
    let log_level = cli.effective_log_level();
    let paths = ResolvedPaths::resolve(&cli);
    if paths.is_rootless {
        log_event(
            log_level,
            cli.json,
            LogLevel::Debug,
            "dich::rootless",
            "operating in rootless mode using XDG base directories",
            &[
                ("store_dir", &paths.store_dir.display().to_string()),
                ("cache", &paths.cache.display().to_string()),
                ("config", &paths.config.display().to_string()),
            ],
        );
    }
    match cli.command {
        Commands::Plan {
            package,
            distribution,
            suite,
            architecture,
        } => {
            #[cfg(target_os = "linux")]
            {
                let age = cli.max_age_seconds.ok_or(CliError {
                    code: "freshness_policy_required",
                    message: "specify --max-age-seconds explicitly",
                    trace: Vec::new(),
                })?;
                let freshness = dich_apt::FreshnessPolicy::new(
                    std::time::Duration::from_secs(age),
                    std::time::Duration::from_secs(300),
                    !cli.allow_missing_valid_until,
                )
                .map_err(|_| CliError {
                    code: "invalid_freshness_policy",
                    message: "invalid metadata freshness policy",
                    trace: Vec::new(),
                })?;
                let distribution = match distribution.as_str() {
                    "debian" => dich_core::Distribution::Debian,
                    "ubuntu" => dich_core::Distribution::Ubuntu,
                    _ => {
                        return Err(CliError {
                            code: "invalid_policy",
                            message: "distribution must be debian or ubuntu",
                            trace: Vec::new(),
                        });
                    }
                };
                let policy =
                    dich_core::ArchitecturePolicy::new(distribution, &suite, &architecture)
                        .map_err(|_| CliError {
                            code: "invalid_policy",
                            message: "invalid release or architecture policy",
                            trace: Vec::new(),
                        })?;
                let sources =
                    dich_apt::load_configured_sources(&paths.config).map_err(|_| CliError {
                        code: "source_load_failed",
                        message: "could not load trusted source configuration",
                        trace: Vec::new(),
                    })?;
                if sources.len() != 1 {
                    return Err(CliError {
                        code: "unsupported_sources",
                        message: "planning currently requires exactly one configured source",
                        trace: Vec::new(),
                    });
                }
                let journal =
                    dich_apt::SnapshotJournal::open(&paths.cache).map_err(|_| CliError {
                        code: "cache_open_failed",
                        message: "could not open protected cache directory",
                        trace: Vec::new(),
                    })?;
                let universe = dich_apt::AuthenticatedUniverse::load(
                    &sources[0],
                    &journal,
                    freshness,
                    &policy,
                )
                .map_err(|_| CliError {
                    code: "plan_input_failed",
                    message: "could not load authenticated metadata under the requested policy",
                    trace: Vec::new(),
                })?;
                let plan = universe.plan(&journal, &package).map_err(|e| match e {
                    dich_apt::PlanError::Unsupported(trace) => CliError {
                        code: "unsupported",
                        message: "dependency semantics or system packages are unsupported",
                        trace,
                    },
                    dich_apt::PlanError::Unsatisfiable(trace) => CliError {
                        code: "unsatisfiable",
                        message: "no matching dependency solution",
                        trace,
                    },
                    dich_apt::PlanError::Limit => CliError {
                        code: "search_limit",
                        message: "dependency search limit exceeded",
                        trace: Vec::new(),
                    },
                    dich_apt::PlanError::InvalidRequest => CliError {
                        code: "invalid_arguments",
                        message: "invalid package name",
                        trace: Vec::new(),
                    },
                    dich_apt::PlanError::Cache => CliError {
                        code: "plan_input_failed",
                        message: "cached metadata changed or could not be authenticated",
                        trace: Vec::new(),
                    },
                })?;
                if cli.json {
                    let pins: Vec<_> = plan.pins.iter().map(|pin| serde_json::json!({"name":pin.name,"version":pin.version,"architecture":pin.architecture,"source_uri":pin.source_uri,"distribution":pin.distribution,"suite":pin.suite,"component":pin.component,"source_architecture":pin.source_architecture,"fingerprints":pin.fingerprints,"release_sha256":pin.release_sha256,"artifact_sha256":pin.artifact_sha256,"filename":pin.filename,"size":pin.size})).collect();
                    println!(
                        "{}",
                        serde_json::json!({"schema_version":1,"status":"planned","scope":"metadata_only_not_installable","packages":plan.packages,"pins":pins,"trace":plan.trace})
                    );
                } else {
                    println!("planned: metadata only; not installable");
                    for pin in plan.pins {
                        println!(
                            "{}={}\t{}\t{}\t{}\t{}\t{}",
                            pin.name,
                            pin.version,
                            pin.architecture,
                            pin.source_uri,
                            pin.suite,
                            pin.release_sha256,
                            pin.artifact_sha256
                        );
                    }
                    for event in plan.trace {
                        println!("  {event}");
                    }
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (package, distribution, suite, architecture);
                Err(CliError {
                    code: "unsupported_platform",
                    message: "planning requires Linux",
                    trace: Vec::new(),
                })
            }
        }
        command @ (Commands::Search { .. } | Commands::Show { .. } | Commands::Versions { .. }) => {
            #[cfg(target_os = "linux")]
            {
                let age = cli.max_age_seconds.ok_or(CliError {
                    code: "freshness_policy_required",
                    message: "specify --max-age-seconds explicitly",
                    trace: Vec::new(),
                })?;
                let freshness = dich_apt::FreshnessPolicy::new(
                    std::time::Duration::from_secs(age),
                    std::time::Duration::from_secs(300),
                    !cli.allow_missing_valid_until,
                )
                .map_err(|_| CliError {
                    code: "invalid_freshness_policy",
                    message: "invalid metadata freshness policy",
                    trace: Vec::new(),
                })?;
                let sources =
                    dich_apt::load_configured_sources(&paths.config).map_err(|_| CliError {
                        code: "source_load_failed",
                        message: "could not load trusted source configuration",
                        trace: Vec::new(),
                    })?;
                let cache =
                    dich_apt::SnapshotJournal::open(&paths.cache).map_err(|_| CliError {
                        code: "cache_open_failed",
                        message: "could not open protected cache directory",
                        trace: Vec::new(),
                    })?;
                let query = match &command {
                    Commands::Search { query } => dich_apt::Query::Search(query),
                    Commands::Show { package } => dich_apt::Query::Show(package),
                    Commands::Versions { package } => dich_apt::Query::Versions(package),
                    _ => {
                        return Err(CliError {
                            code: "invalid_arguments",
                            message: "invalid query command",
                            trace: Vec::new(),
                        });
                    }
                };
                let records =
                    dich_apt::query_cached(&sources, &cache, freshness, query).map_err(|_| {
                        CliError {
                            code: "query_failed",
                            message: "could not read complete authenticated cached metadata",
                            trace: Vec::new(),
                        }
                    })?;
                if records.is_empty() && !matches!(command, Commands::Search { .. }) {
                    return Err(CliError {
                        code: "not_found",
                        message: "package not found in configured cached sources",
                        trace: Vec::new(),
                    });
                }
                if cli.json {
                    let entries: Vec<_> = records.iter().map(|r| serde_json::json!({"name": r.name, "version": r.version, "architecture": r.architecture, "source": r.source, "suite": r.suite})).collect();
                    println!(
                        "{}",
                        serde_json::json!({"schema_version": 1, "status": "completed", "records": entries})
                    );
                } else {
                    for record in records {
                        println!(
                            "{}\t{}\t{}\t{}\t{}",
                            record.name,
                            record.version,
                            record.architecture,
                            record.source,
                            record.suite
                        );
                    }
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = command;
                Err(CliError {
                    code: "unsupported_platform",
                    message: "cached queries require Linux",
                    trace: Vec::new(),
                })
            }
        }
        Commands::Update => {
            #[cfg(target_os = "linux")]
            {
                paths::ensure_private_directory(&paths.cache)?;
                let proxy = cli
                    .https_proxy
                    .as_deref()
                    .map(dich_apt::HttpConnectProxy::parse)
                    .transpose()
                    .map_err(|_| CliError {
                        code: "invalid_proxy",
                        message: "proxy must be an unauthenticated http://host:port URL",
                        trace: Vec::new(),
                    })?;
                let age = cli.max_age_seconds.ok_or(CliError {
                    code: "freshness_policy_required",
                    message: "specify --max-age-seconds explicitly",
                    trace: Vec::new(),
                })?;
                let freshness = dich_apt::FreshnessPolicy::new(
                    std::time::Duration::from_secs(age),
                    std::time::Duration::from_secs(300),
                    !cli.allow_missing_valid_until,
                )
                .map_err(|_| CliError {
                    code: "invalid_freshness_policy",
                    message: "invalid metadata freshness policy",
                    trace: Vec::new(),
                })?;
                let sources =
                    dich_apt::load_configured_sources(&paths.config).map_err(|_| CliError {
                        code: "source_load_failed",
                        message: "could not load trusted source configuration",
                        trace: Vec::new(),
                    })?;
                let cache =
                    dich_apt::SnapshotJournal::open(&paths.cache).map_err(|_| CliError {
                        code: "cache_open_failed",
                        message: "could not open protected cache directory",
                        trace: Vec::new(),
                    })?;
                report_progress(
                    cli.progress,
                    cli.json,
                    1,
                    2,
                    "Authenticating repository metadata...",
                );
                log_event(
                    log_level,
                    cli.json,
                    LogLevel::Info,
                    "dich::update",
                    "refreshing package repositories",
                    &[("sources", &sources.len().to_string())],
                );
                let mut indices = 0usize;
                for source in &sources {
                    let report = match proxy.as_ref() {
                        Some(proxy) => dich_apt::update_source_with_proxy(
                            source,
                            &cache,
                            freshness,
                            dich_apt::IndexLimits::default(),
                            proxy,
                        ),
                        None => dich_apt::update_source(
                            source,
                            &cache,
                            freshness,
                            dich_apt::IndexLimits::default(),
                        ),
                    }
                    .map_err(|_| CliError {
                        code: "update_failed",
                        message: "repository update failed; earlier cache entries may have changed",
                        trace: Vec::new(),
                    })?;
                    indices += report.indices;
                }
                report_progress(
                    cli.progress,
                    cli.json,
                    2,
                    2,
                    "Updated package indices successfully",
                );
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({"schema_version": 1, "status": "completed", "sources": sources.len(), "indices": indices})
                    );
                } else {
                    println!("completed: {} sources, {indices} indices", sources.len());
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(CliError {
                    code: "unsupported_platform",
                    message: "repository update requires Linux",
                    trace: Vec::new(),
                })
            }
        }
        Commands::Fetch {
            package,
            exact_version,
            component,
            max_bytes,
            publish_tree,
        } => {
            #[cfg(target_os = "linux")]
            {
                paths::ensure_private_directory(&paths.cache)?;
                let proxy = cli
                    .https_proxy
                    .as_deref()
                    .map(dich_apt::HttpConnectProxy::parse)
                    .transpose()
                    .map_err(|_| CliError {
                        code: "invalid_proxy",
                        message: "proxy must be an unauthenticated http://host:port URL",
                        trace: Vec::new(),
                    })?;
                let age = cli.max_age_seconds.ok_or(CliError {
                    code: "freshness_policy_required",
                    message: "specify --max-age-seconds explicitly",
                    trace: Vec::new(),
                })?;
                let freshness = dich_apt::FreshnessPolicy::new(
                    std::time::Duration::from_secs(age),
                    std::time::Duration::from_secs(300),
                    !cli.allow_missing_valid_until,
                )
                .map_err(|_| CliError {
                    code: "invalid_freshness_policy",
                    message: "invalid metadata freshness policy",
                    trace: Vec::new(),
                })?;
                let sources =
                    dich_apt::load_configured_sources(&paths.config).map_err(|_| CliError {
                        code: "source_load_failed",
                        message: "could not load trusted source configuration",
                        trace: Vec::new(),
                    })?;
                if sources.len() != 1 {
                    return Err(CliError {
                        code: "unsupported_sources",
                        message: "fetch currently requires exactly one configured source",
                        trace: Vec::new(),
                    });
                }
                let journal =
                    dich_apt::SnapshotJournal::open(&paths.cache).map_err(|_| CliError {
                        code: "cache_open_failed",
                        message: "could not open protected cache directory",
                        trace: Vec::new(),
                    })?;
                let request = dich_apt::FetchRequest {
                    component: &component,
                    name: &package,
                    version: &exact_version,
                    max_bytes,
                };
                let artifact = match proxy.as_ref() {
                    Some(proxy) => dich_apt::fetch_exact_with_proxy(
                        &sources[0],
                        &journal,
                        freshness,
                        request,
                        proxy,
                    ),
                    None => dich_apt::fetch_exact(&sources[0], &journal, freshness, request),
                }
                .map_err(|_| CliError {
                    code: "fetch_failed",
                    message: "could not authenticate, download and cache the requested artifact",
                    trace: Vec::new(),
                })?;
                let state = match artifact.state {
                    dich_apt::FetchState::Downloaded => "downloaded",
                    dich_apt::FetchState::Cached => "cached",
                };
                let tree = if publish_tree {
                    paths::ensure_private_directory(&paths.store_dir)?;
                    let mut store = dich_store::MetadataDb::open(&paths.store_dir).map_err(|_| CliError {
                        code: "store_open_failed",
                        message: "could not open existing protected store directory; the artifact may remain cached",
                        trace: Vec::new(),
                    })?;
                    let (identity, outcome) = store.stage_and_publish_cached_tree(&journal, artifact.authorization()).map_err(|error| {
                        let unsupported = matches!(error, dich_store::PublicationError::Unsupported);
                        CliError {
                            code: if unsupported { "unsupported" } else { "store_publish_failed" },
                            message: "could not safely publish an extracted tree; the artifact may remain cached",
                            trace: Vec::new(),
                        }
                    })?;
                    Some((
                        identity.hex(),
                        match outcome {
                            dich_store::TreeOutcome::Published => "published",
                            dich_store::TreeOutcome::Reused => "reused",
                        },
                    ))
                } else {
                    None
                };
                let artifact = artifact.artifact();
                let artifact_hash = artifact
                    .sha256()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                let release_hash = artifact
                    .release_sha256()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                let source = artifact.source();
                let distribution = match source.distribution() {
                    dich_apt::Distribution::Debian => "debian",
                    dich_apt::Distribution::Ubuntu => "ubuntu",
                };
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({"schema_version":1,"status":"completed","state":state,"installable":false,"name":artifact.name(),"version":artifact.version(),"architecture":artifact.architecture(),"size":artifact.size(),"artifact_sha256":artifact_hash,"release_sha256":release_hash,"component":component,"source":{"distribution":distribution,"uri":source.uri(),"suite":source.suite(),"architecture":source.architecture(),"configured_fingerprints":source.fingerprints()},"tree":tree.as_ref().map(|(id, publication)| serde_json::json!({"id":id,"publication":publication,"lifecycle":"extracted","compatibility":"not_analyzed"}))})
                    );
                } else {
                    println!(
                        "completed: {state} {}={} ({}, {} bytes) in verified cache; installability not established",
                        artifact.name(),
                        artifact.version(),
                        artifact.architecture(),
                        artifact.size()
                    );
                    println!(
                        "artifact sha256: {artifact_hash}; signed Release sha256: {release_hash}"
                    );
                    println!(
                        "source: {distribution} {} {} {}",
                        source.uri(),
                        source.suite(),
                        source.architecture()
                    );
                    if let Some((id, publication)) = tree {
                        println!(
                            "{publication}: extracted tree {id}; compatibility not analyzed, not activated"
                        );
                    }
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (package, exact_version, component, max_bytes, publish_tree);
                Err(CliError {
                    code: "unsupported_platform",
                    message: "authenticated fetch requires Linux",
                    trace: Vec::new(),
                })
            }
        }
        Commands::Install {
            package,
            profile,
            exact_version,
            yes,
        } => {
            #[cfg(target_os = "linux")]
            {
                if yes {
                    paths::ensure_private_directory(&paths.cache)?;
                    paths::ensure_private_directory(&paths.store_dir)?;
                }
                let age = cli.max_age_seconds.ok_or(CliError {
                    code: "freshness_policy_required",
                    message: "specify --max-age-seconds explicitly",
                    trace: Vec::new(),
                })?;
                let freshness = dich_engine::freshness_policy(age, cli.allow_missing_valid_until)
                    .map_err(|_| CliError {
                    code: "invalid_freshness_policy",
                    message: "invalid metadata freshness policy",
                    trace: Vec::new(),
                })?;
                let sources =
                    dich_apt::load_configured_sources(&paths.config).map_err(|_| CliError {
                        code: "source_load_failed",
                        message: "could not load trusted source configuration",
                        trace: Vec::new(),
                    })?;
                if sources.len() != 1 {
                    return Err(CliError {
                        code: "unsupported_sources",
                        message: "install currently requires exactly one configured source",
                        trace: Vec::new(),
                    });
                }
                let journal =
                    dich_apt::SnapshotJournal::open(&paths.cache).map_err(|_| CliError {
                        code: "cache_open_failed",
                        message: "could not open protected cache directory",
                        trace: Vec::new(),
                    })?;
                report_progress(
                    cli.progress,
                    cli.json,
                    1,
                    3,
                    "Resolving authenticated package dependencies...",
                );
                log_event(
                    log_level,
                    cli.json,
                    LogLevel::Info,
                    "dich::install",
                    "initiating package installation",
                    &[("package", &package), ("profile", &profile)],
                );
                let plan = dich_engine::plan_install(
                    &sources[0],
                    &journal,
                    freshness,
                    &package,
                    exact_version.as_deref(),
                )
                .map_err(map_install_error)?;
                if !yes {
                    if cli.json {
                        let pins: Vec<_> = plan
                            .pins
                            .iter()
                            .map(|pin| {
                                serde_json::json!({
                                    "name":pin.name,
                                    "version":pin.version,
                                    "architecture":pin.architecture,
                                    "component":pin.component,
                                    "artifact_sha256":pin.artifact_sha256,
                                    "release_sha256":pin.release_sha256
                                })
                            })
                            .collect();
                        println!(
                            "{}",
                            serde_json::json!({
                                "schema_version":1,
                                "status":"planned",
                                "scope":"metadata_only_not_installable_until_compatibility_check",
                                "package":package,
                                "exact_version":exact_version,
                                "profile":profile,
                                "root_package":plan.root,
                                "packages":plan.packages,
                                "dependency_edges":plan.dependency_edges,
                                "pins":pins,
                                "requires_confirmation":"--yes"
                            })
                        );
                    } else {
                        println!(
                            "planned: authenticated metadata selected {} package(s); compatibility and extraction require --yes",
                            plan.pins.len()
                        );
                        for pin in plan.pins {
                            println!(
                                "{}={} {} {}",
                                pin.name, pin.version, pin.architecture, pin.artifact_sha256
                            );
                        }
                    }
                    return Ok(());
                }
                report_progress(
                    cli.progress,
                    cli.json,
                    2,
                    3,
                    "Staging and validating package closure...",
                );
                let proxy = cli
                    .https_proxy
                    .as_deref()
                    .map(dich_apt::HttpConnectProxy::parse)
                    .transpose()
                    .map_err(|_| CliError {
                        code: "invalid_proxy",
                        message: "proxy must be an unauthenticated http://host:port URL",
                        trace: Vec::new(),
                    })?;
                let report = dich_engine::install_dso_profile(
                    &sources[0],
                    &journal,
                    freshness,
                    dich_engine::InstallRequest {
                        package: &package,
                        exact_version: exact_version.as_deref(),
                        profile: &profile,
                        store_dir: &paths.store_dir,
                        proxy: proxy.as_ref(),
                    },
                )
                .map_err(map_install_error)?;
                report_progress(
                    cli.progress,
                    cli.json,
                    3,
                    3,
                    "Published profile generation successfully",
                );
                let objects: Vec<_> = report
                    .objects
                    .iter()
                    .map(|object| {
                        serde_json::json!({
                            "package":object.package,
                            "version":object.version,
                            "object_id":object.id,
                            "explicit_path":object.path,
                            "publication":match object.tree_outcome {
                                dich_store::TreeOutcome::Published => "published",
                                dich_store::TreeOutcome::Reused => "reused"
                            }
                        })
                    })
                    .collect();
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema_version":1,
                            "status":"completed",
                            "scope":"authenticated_dso_profile_selection",
                            "profile":profile,
                            "requested_package":package,
                            "generation_id":report.generation.generation_id,
                            "runtime_activation":"caller_must_load_explicit_paths_in_dlmopen_namespace",
                            "load_order":report.compatibility.load_order,
                            "objects":objects,
                            "maintainer_scripts_executed":false
                        })
                    );
                } else {
                    println!(
                        "completed: selected authenticated DSO closure in profile {profile} (generation {})",
                        report.generation.generation_id
                    );
                    println!(
                        "runtime activation requires explicit paths in a fresh glibc dlmopen namespace"
                    );
                    for object in report.objects {
                        println!(
                            "{}={} {}",
                            object.package,
                            object.version,
                            object.path.display()
                        );
                    }
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (package, profile, exact_version, yes);
                Err(CliError {
                    code: "unsupported_platform",
                    message: "authenticated profile install requires Linux",
                    trace: Vec::new(),
                })
            }
        }
        Commands::Inspect { file, with } => {
            #[cfg(target_os = "linux")]
            {
                if with.len() >= 16 {
                    return Err(CliError {
                        code: "closure_too_large",
                        message: "at most 15 additional packages may be supplied",
                        trace: Vec::new(),
                    });
                }
                let mut archives = Vec::with_capacity(with.len() + 1);
                for path in std::iter::once(&file).chain(&with) {
                    archives.push(
                        dich_deb::inspect_path(
                            std::path::Path::new(path),
                            dich_deb::Limits::default(),
                        )
                        .map_err(|_| CliError {
                            code: "inspect_failed",
                            message: "could not safely inspect local Debian archive",
                            trace: Vec::new(),
                        })?,
                    );
                }
                let report = &archives[0];
                let compatibility = if with.is_empty() {
                    dich_deb::assess_compatibility(report)
                } else {
                    dich_deb::assess_compatibility_closure(&archives)
                };
                if cli.json {
                    let scripts: Vec<_> = report
                        .scripts
                        .iter()
                        .map(|s| serde_json::json!({"name":s.name,"size":s.size,"sha256":s.sha256}))
                        .collect();
                    println!(
                        "{}",
                        serde_json::json!({"schema_version":1,"status":"completed","trust":"unverified","installable":false,"closure_archives":archives.len(),"control_entries":report.control_entries,"control_files":report.control_files,"data_entries":report.data_entries,"data_files":report.data_files,"data_file_bytes":report.data_file_bytes,"scripts":scripts,"triggers_present":report.triggers_present,"path_indicators":report.path_indicators,"elf_objects":report.elf_objects,"compatibility_report":compatibility})
                    );
                } else {
                    println!("completed: unverified local archive; installability not established");
                    println!(
                        "compatibility: {} ({} evidence items)",
                        compatibility.status.as_str(),
                        compatibility.evidence.len()
                    );
                    if !with.is_empty() {
                        println!(
                            "explicit dependency closure: {} archives; unauthenticated and not activated",
                            archives.len()
                        );
                    }
                    println!(
                        "control files: {}; data files: {}; data bytes: {}; triggers: {}",
                        report.control_files,
                        report.data_files,
                        report.data_file_bytes,
                        report.triggers_present
                    );
                    for script in &report.scripts {
                        println!(
                            "script metadata: {} {} {}",
                            script.name, script.size, script.sha256
                        );
                    }
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (file, with);
                Err(CliError {
                    code: "unsupported_platform",
                    message: "local archive inspection requires Linux",
                    trace: Vec::new(),
                })
            }
        }
        Commands::Profile {
            command: ProfileCommands::List,
        } => {
            #[cfg(target_os = "linux")]
            {
                let db = dich_store::MetadataDb::open_existing(&paths.store_dir).map_err(|_| {
                    CliError {
                        code: "store_open_failed",
                        message: "could not open existing protected store with current schema",
                        trace: Vec::new(),
                    }
                })?;
                let profiles = db.list_profiles().map_err(|_| CliError {
                    code: "profile_list_failed",
                    message: "could not validate profile generations",
                    trace: Vec::new(),
                })?;
                if cli.json {
                    let entries: Vec<_> = profiles
                        .iter()
                        .map(|profile| {
                            serde_json::json!({
                                "name": profile.profile,
                                "requested_package": profile.requested_package,
                                "generation_id": profile.generation_id,
                                "graph_id": profile.graph_id,
                                "object_count": profile.graph.nodes().len(),
                                "dependency_edge_count": profile.graph.edges().len(),
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::json!({"schema_version":1,"status":"completed","profiles":entries})
                    );
                } else if profiles.is_empty() {
                    println!("completed: no active profiles");
                } else {
                    for profile in profiles {
                        println!(
                            "{}\t{}\t{} objects",
                            profile.profile,
                            profile.generation_id,
                            profile.graph.nodes().len()
                        );
                    }
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(CliError {
                    code: "unsupported_platform",
                    message: "profile operations require Linux",
                    trace: Vec::new(),
                })
            }
        }
        Commands::Rollback { profile, yes } => {
            #[cfg(target_os = "linux")]
            {
                if yes {
                    paths::ensure_private_directory(&paths.store_dir)?;
                }
                let mut db =
                    dich_store::MetadataDb::open_existing(&paths.store_dir).map_err(|_| {
                        CliError {
                            code: "store_open_failed",
                            message: "could not open existing protected store with current schema",
                            trace: Vec::new(),
                        }
                    })?;
                report_progress(
                    cli.progress,
                    cli.json,
                    1,
                    2,
                    "Validating current and previous profile generations...",
                );
                log_event(
                    log_level,
                    cli.json,
                    LogLevel::Info,
                    "dich::rollback",
                    "initiating profile rollback",
                    &[("profile", &profile)],
                );
                let current = db
                    .read_profile_generation(&profile)
                    .map_err(|_| CliError {
                        code: "profile_read_failed",
                        message: "could not validate current profile generation",
                        trace: Vec::new(),
                    })?
                    .ok_or(CliError {
                        code: "profile_missing",
                        message: "profile has no active generation",
                        trace: Vec::new(),
                    })?;
                let previous = current.previous_id.clone().ok_or(CliError {
                    code: "rollback_unavailable",
                    message: "profile has no previous generation",
                    trace: Vec::new(),
                })?;
                if !yes {
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "schema_version":1,
                                "status":"planned",
                                "action":"switch_profile_generation",
                                "profile":profile,
                                "current_generation":current.generation_id,
                                "target_generation":previous,
                                "requires_confirmation":"--yes"
                            })
                        );
                    } else {
                        println!(
                            "planned: rollback {profile} from {} to {previous}; rerun with --yes to switch",
                            current.generation_id
                        );
                    }
                    return Ok(());
                }
                let switched = db
                    .rollback_profile_generation(&profile)
                    .map_err(|_| CliError {
                        code: "rollback_failed",
                        message: "could not atomically switch to the previous profile generation",
                        trace: Vec::new(),
                    })?;
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema_version":1,
                            "status":"completed",
                            "scope":"profile_metadata_only",
                            "profile":profile,
                            "generation_id":switched.generation_id,
                            "installable":false
                        })
                    );
                } else {
                    println!(
                        "completed: profile {profile} now selects generation {} (metadata only)",
                        switched.generation_id
                    );
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (profile, yes);
                Err(CliError {
                    code: "unsupported_platform",
                    message: "profile rollback requires Linux",
                    trace: Vec::new(),
                })
            }
        }
        Commands::Remove {
            package,
            profile,
            yes,
        } => {
            #[cfg(target_os = "linux")]
            {
                if yes {
                    paths::ensure_private_directory(&paths.store_dir)?;
                }
                let mut db =
                    dich_store::MetadataDb::open_existing(&paths.store_dir).map_err(|_| {
                        CliError {
                            code: "store_open_failed",
                            message: "could not open existing protected store with current schema",
                            trace: Vec::new(),
                        }
                    })?;
                report_progress(
                    cli.progress,
                    cli.json,
                    1,
                    2,
                    "Validating package profile generation for removal...",
                );
                log_event(
                    log_level,
                    cli.json,
                    LogLevel::Info,
                    "dich::remove",
                    "initiating profile removal",
                    &[("profile", &profile), ("package", &package)],
                );
                let current = db
                    .read_profile_generation(&profile)
                    .map_err(|_| CliError {
                        code: "profile_read_failed",
                        message: "could not validate current profile generation",
                        trace: Vec::new(),
                    })?
                    .ok_or(CliError {
                        code: "profile_missing",
                        message: "profile has no active generation",
                        trace: Vec::new(),
                    })?;
                if current.requested_package.as_deref() != Some(package.as_str()) {
                    return Err(CliError {
                        code: "package_not_installed",
                        message: "profile does not select this requested package",
                        trace: Vec::new(),
                    });
                }
                if !yes {
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "schema_version":1,
                                "status":"planned",
                                "action":"deactivate_profile_generation",
                                "profile":profile,
                                "package":package,
                                "generation_id":current.generation_id,
                                "requires_confirmation":"--yes",
                                "rollback_generation":current.previous_id
                            })
                        );
                    } else {
                        println!(
                            "planned: remove {package} from profile {profile}; rerun with --yes to deactivate the selected generation"
                        );
                    }
                    return Ok(());
                }
                let removed = db
                    .remove_package_profile_generation(&profile, &package)
                    .map_err(|_| CliError {
                        code: "remove_failed",
                        message: "could not atomically deactivate the selected profile generation",
                        trace: Vec::new(),
                    })?;
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema_version":1,
                            "status":"completed",
                            "scope":"profile_metadata_only",
                            "profile":profile,
                            "package":package,
                            "generation_id":removed.generation_id,
                            "objects_retained":true
                        })
                    );
                } else {
                    println!(
                        "completed: deactivated {package} in profile {profile}; store objects retained"
                    );
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (package, profile, yes);
                Err(CliError {
                    code: "unsupported_platform",
                    message: "profile removal requires Linux",
                    trace: Vec::new(),
                })
            }
        }
        Commands::Store { command } => {
            #[cfg(target_os = "linux")]
            {
                let db = dich_store::MetadataDb::open_existing(&paths.store_dir).map_err(|_| {
                    CliError {
                        code: "store_open_failed",
                        message: "could not open existing protected store with current schema",
                        trace: Vec::new(),
                    }
                })?;
                match command {
                    StoreCommands::Ls => {
                        let records = db.list_objects().map_err(|_| CliError {
                            code: "store_inspect_failed",
                            message: "could not inspect store metadata",
                            trace: Vec::new(),
                        })?;
                        if cli.json {
                            let objects: Vec<_> = records.iter().map(|r| {
                                let (kind, lifecycle) = match r.kind {
                                    dich_store::ObjectKind::Archive => ("archive", "downloaded"),
                                    dich_store::ObjectKind::Tree => ("tree", "extracted"),
                                };
                                serde_json::json!({"id":r.id,"kind":kind,"stored_bytes":r.stored_bytes,"recorded_lifecycle":lifecycle,"content_verified":false,"compatibility":"not_analyzed","installable":false})
                            }).collect();
                            println!(
                                "{}",
                                serde_json::json!({"schema_version":1,"status":"completed","scope":"metadata_only","objects":objects})
                            );
                        } else {
                            println!("completed: metadata only; object contents not verified");
                            for r in records {
                                println!(
                                    "{}\t{}\t{}\t{}",
                                    r.id,
                                    match r.kind {
                                        dich_store::ObjectKind::Archive => "archive",
                                        dich_store::ObjectKind::Tree => "tree",
                                    },
                                    r.stored_bytes,
                                    match r.kind {
                                        dich_store::ObjectKind::Archive =>
                                            "recorded downloaded; not analyzed",
                                        dich_store::ObjectKind::Tree =>
                                            "recorded extracted; not analyzed",
                                    }
                                );
                            }
                        }
                    }
                    StoreCommands::Verify { id, kind } => {
                        let (kind_name, lifecycle, bytes) = match kind {
                            StoreKind::Archive => (
                                "archive",
                                "downloaded",
                                db.verify_archive_object(&id).map(|r| r.total_bytes),
                            ),
                            StoreKind::Tree => (
                                "tree",
                                "extracted",
                                db.verify_tree_object(&id).map(|r| r.total_bytes),
                            ),
                        };
                        let bytes = bytes.map_err(|_| CliError {
                            code: "store_verify_failed",
                            message: "object does not match protected local metadata",
                            trace: Vec::new(),
                        })?;
                        if cli.json {
                            println!(
                                "{}",
                                serde_json::json!({"schema_version":1,"status":"completed","scope":"local_metadata_only","id":id,"kind":kind_name,"stored_bytes":bytes,"recorded_lifecycle":lifecycle,"content_verified":true,"compatibility":"not_analyzed","installable":false})
                            );
                        } else {
                            println!(
                                "completed: {kind_name} {id} matches local metadata ({bytes} bytes); repository freshness and compatibility not checked"
                            );
                        }
                    }
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = command;
                Err(CliError {
                    code: "unsupported_platform",
                    message: "store operations require Linux",
                    trace: Vec::new(),
                })
            }
        }
        Commands::Sources {
            command: SourcesCommands::List,
        } => {
            let sources =
                dich_apt::load_configured_sources(&paths.config).map_err(|_| CliError {
                    code: "source_load_failed",
                    message: "could not load trusted source configuration",
                    trace: Vec::new(),
                })?;
            if cli.json {
                let entries: Vec<_> = sources.iter().map(|source| serde_json::json!({
                    "distribution": match source.distribution() { dich_apt::Distribution::Debian => "debian", dich_apt::Distribution::Ubuntu => "ubuntu" },
                    "uri": source.uri(), "suite": source.suite(), "components": source.components(),
                    "architecture": source.architecture(), "keyring": source.keyring(), "fingerprints": source.fingerprints(),
                    "state": "configured"
                })).collect();
                println!(
                    "{}",
                    serde_json::json!({"schema_version": 1, "status": "completed", "sources": entries})
                );
            } else {
                for source in sources {
                    println!(
                        "configured\t{}\t{}\t{}\t{}",
                        source.uri(),
                        source.suite(),
                        source.architecture(),
                        source.components().join(",")
                    );
                }
            }
            Ok(())
        }
        Commands::Gc { dry_run, execute } => {
            #[cfg(target_os = "linux")]
            {
                if execute {
                    paths::ensure_private_directory(&paths.store_dir)?;
                }
                let mode = if execute {
                    dich_store::GcMode::Execute
                } else {
                    let _ = dry_run;
                    dich_store::GcMode::DryRun
                };
                let mut db =
                    dich_store::MetadataDb::open_existing(&paths.store_dir).map_err(|_| {
                        CliError {
                            code: "store_open_failed",
                            message: "could not open existing protected store with current schema",
                            trace: Vec::new(),
                        }
                    })?;
                report_progress(
                    cli.progress,
                    cli.json,
                    1,
                    2,
                    "Enumerating active roots and analyzing reachability...",
                );
                log_event(
                    log_level,
                    cli.json,
                    LogLevel::Info,
                    "dich::gc",
                    "running garbage collection",
                    &[("mode", if execute { "execute" } else { "dry-run" })],
                );
                let report = db.collect_garbage(mode).map_err(|err| CliError {
                    code: "gc_failed",
                    message: match err {
                        dich_store::PublicationError::Database => {
                            "database error during garbage collection"
                        }
                        dich_store::PublicationError::Integrity => {
                            "store integrity validation failed during garbage collection"
                        }
                        _ => "garbage collection failed",
                    },
                    trace: Vec::new(),
                })?;
                if cli.json {
                    let status = if mode == dich_store::GcMode::Execute {
                        "completed"
                    } else {
                        "planned"
                    };
                    let mode_str = if mode == dich_store::GcMode::Execute {
                        "execute"
                    } else {
                        "dry-run"
                    };
                    let json_val = serde_json::json!({
                        "schema_version": 1,
                        "status": status,
                        "mode": mode_str,
                        "roots": {
                            "active_profiles": report.roots.active_profiles,
                            "reachable_trees": report.roots.reachable_tree_count,
                            "reachable_graphs": report.roots.reachable_graph_count,
                        },
                        "unreachable": {
                            "trees": report.unreachable_trees.iter().map(|t| serde_json::json!({
                                "object_id": t.object_id,
                                "total_size": t.total_size,
                            })).collect::<Vec<_>>(),
                            "graphs": report.unreachable_graphs.iter().map(|g| serde_json::json!({
                                "graph_id": g.graph_id,
                            })).collect::<Vec<_>>(),
                        },
                        "summary": {
                            "reclaimable_bytes": report.reclaimable_bytes,
                            "reclaimed_bytes": report.reclaimed_bytes,
                            "retained_trees": report.retained_trees,
                            "retained_graphs": report.retained_graphs,
                        }
                    });
                    println!("{}", serde_json::to_string_pretty(&json_val).unwrap());
                } else {
                    render_gc_report(&report);
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (dry_run, execute);
                Err(CliError {
                    code: "unsupported_platform",
                    message: "garbage collection requires Linux",
                    trace: Vec::new(),
                })
            }
        }
    }
}

fn format_disk_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.2} GiB ({} bytes)", bytes as f64 / GIB as f64, bytes)
    } else if bytes >= MIB {
        format!("{:.2} MiB ({} bytes)", bytes as f64 / MIB as f64, bytes)
    } else if bytes >= KIB {
        format!("{:.2} KiB ({} bytes)", bytes as f64 / KIB as f64, bytes)
    } else {
        format!("{} bytes", bytes)
    }
}

#[cfg(target_os = "linux")]
fn render_gc_report(report: &dich_store::GcReport) {
    let mode_str = match report.mode {
        dich_store::GcMode::DryRun => "dry-run",
        dich_store::GcMode::Execute => "execute",
    };
    println!("Garbage collection ({mode_str}):");
    println!("Roots:");
    let profiles_str = if report.roots.active_profiles.is_empty() {
        "none".to_string()
    } else {
        report.roots.active_profiles.join(", ")
    };
    println!(
        "  Active profiles: {profiles_str} ({} total)",
        report.roots.active_profiles.len()
    );
    println!("  Reachable trees: {}", report.roots.reachable_tree_count);
    println!("  Reachable graphs: {}", report.roots.reachable_graph_count);

    if report.unreachable_trees.is_empty() && report.unreachable_graphs.is_empty() {
        println!("Unreachable objects: none");
    } else {
        let label = if report.mode == dich_store::GcMode::Execute {
            "Removed objects:"
        } else {
            "Unreachable objects:"
        };
        println!("{label}");
        println!(
            "  Trees: {} ({})",
            report.unreachable_trees.len(),
            format_disk_size(report.reclaimable_bytes)
        );
        for tree in &report.unreachable_trees {
            println!(
                "    - {} ({})",
                tree.object_id,
                format_disk_size(tree.total_size)
            );
        }
        println!("  Graphs: {}", report.unreachable_graphs.len());
        for graph in &report.unreachable_graphs {
            println!("    - {}", graph.graph_id);
        }
    }

    println!("Summary:");
    if report.mode == dich_store::GcMode::DryRun {
        println!("  Status: planned (dry-run, no changes made)");
        println!(
            "  Reclaimable space: {}",
            format_disk_size(report.reclaimable_bytes)
        );
    } else {
        println!("  Status: completed");
        println!(
            "  Reclaimed space: {}",
            format_disk_size(report.reclaimed_bytes)
        );
    }
    println!("  Retained active trees: {}", report.retained_trees);
    println!("  Retained active graphs: {}", report.retained_graphs);

    if report.mode == dich_store::GcMode::DryRun && !report.unreachable_trees.is_empty() {
        println!("\nRun 'dich gc --execute' to remove unreachable objects.");
    }
}

fn map_install_error(error: dich_engine::EngineError) -> CliError {
    match error {
        dich_engine::EngineError::Plan(dich_apt::PlanError::Unsupported(trace)) => CliError {
            code: "unsupported",
            message: "dependency semantics or system packages are outside the supported subset",
            trace,
        },
        dich_engine::EngineError::Plan(dich_apt::PlanError::Unsatisfiable(trace)) => CliError {
            code: "unsatisfiable",
            message: "no matching dependency solution",
            trace,
        },
        dich_engine::EngineError::Plan(dich_apt::PlanError::Limit) => CliError {
            code: "search_limit",
            message: "dependency search or closure limit exceeded",
            trace: Vec::new(),
        },
        dich_engine::EngineError::Plan(dich_apt::PlanError::InvalidRequest) => CliError {
            code: "invalid_arguments",
            message: "invalid package name",
            trace: Vec::new(),
        },
        dich_engine::EngineError::Plan(dich_apt::PlanError::Cache)
        | dich_engine::EngineError::Fetch => CliError {
            code: "install_input_failed",
            message: "authenticated metadata or artifact fetch failed",
            trace: Vec::new(),
        },
        dich_engine::EngineError::UnsupportedClosure(trace) => CliError {
            code: "compatibility_rejected",
            message: "package set is outside the supported DSO closure policy",
            trace,
        },
        dich_engine::EngineError::ProfileConflict => CliError {
            code: "profile_conflict",
            message: "profile already selects a different requested package",
            trace: Vec::new(),
        },
        dich_engine::EngineError::ArtifactLimit => CliError {
            code: "install_limit",
            message: "artifact or DSO closure limit exceeded",
            trace: Vec::new(),
        },
        dich_engine::EngineError::Inspection => CliError {
            code: "inspection_failed",
            message: "package inspection or architecture policy validation failed",
            trace: Vec::new(),
        },
        dich_engine::EngineError::Store(_) => CliError {
            code: "store_publish_failed",
            message: "could not safely publish or select the verified package closure",
            trace: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    #[test]
    fn verify_cli_definition() {
        Cli::command().debug_assert();
    }
    #[test]
    fn no_package_operations() {
        let c = Cli::try_parse_from(["dich", "install", "openssl@3"]).expect("parse");
        assert!(run(c).is_err());
    }
}
