#![forbid(unsafe_code)]
//! Dich command-line interface; package installation remains unsupported.
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "dich", about = "Versioned package store using Debian/Ubuntu sources (experimental)", version, long_about = None)]
pub struct Cli {
    /// Path to trusted source policy
    #[arg(long, global = true, default_value = "/etc/dich/sources.toml")]
    pub config: PathBuf,
    /// Existing protected cache directory
    #[arg(long, global = true, default_value = "/var/cache/dich")]
    pub cache: PathBuf,
    /// Existing protected store directory (never created by read commands)
    #[arg(long, global = true, default_value = "/var/lib/dich")]
    pub store_dir: PathBuf,
    /// Explicit maximum age for signed Release metadata, in seconds
    #[arg(long, global = true)]
    pub max_age_seconds: Option<u64>,
    /// Permit missing Valid-Until while still enforcing maximum age
    #[arg(long, global = true)]
    pub allow_missing_valid_until: bool,
    /// Emit versioned JSON output and errors
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Commands,
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
    },
    /// Examine an unauthenticated local Debian archive without extracting it
    Inspect { file: String },
    /// Install compatible packages into a profile (planned)
    Install {
        package: String,
        #[arg(long, default_value = "default")]
        profile: String,
    },
    /// Remove a package from profile (planned)
    Remove {
        package: String,
        #[arg(long, default_value = "default")]
        profile: String,
    },
    /// Roll back a profile generation (planned)
    Rollback {
        #[arg(long, default_value = "default")]
        profile: String,
    },
    /// Inspect locally recorded store objects
    Store {
        #[command(subcommand)]
        command: StoreCommands,
    },
    /// Manage profiles (planned)
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },
    /// Manage repositories
    Sources {
        #[command(subcommand)]
        command: SourcesCommands,
    },
    /// Garbage collect unreachable objects (planned)
    Gc {
        #[arg(long, conflicts_with = "execute")]
        dry_run: bool,
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

#[derive(Debug)]
pub struct CliError {
    pub code: &'static str,
    pub message: &'static str,
    pub trace: Vec<String>,
}
impl CliError {
    pub fn render(&self, json: bool) -> String {
        if json {
            serde_json::json!({"schema_version": 1, "status": "error", "error": {"code": self.code, "message": self.message, "trace": self.trace}}).to_string()
        } else {
            if self.trace.is_empty() {
                format!("dich: error: {}", self.message)
            } else {
                format!("dich: error: {}\n{}", self.message, self.trace.join("\n"))
            }
        }
    }
}

pub fn run(cli: Cli) -> Result<(), CliError> {
    if matches!(
        &cli.command,
        Commands::Install { .. }
            | Commands::Remove { .. }
            | Commands::Rollback { .. }
            | Commands::Gc { .. }
    ) {
        dich_core::admission::admit_execution(dich_core::admission::Evidence::Unexamined).map_err(
            |_| CliError {
                code: "unsupported",
                message: "package execution and store mutation are not supported",
                trace: Vec::new(),
            },
        )?;
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
                    dich_apt::load_configured_sources(&cli.config).map_err(|_| CliError {
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
                    dich_apt::SnapshotJournal::open(&cli.cache).map_err(|_| CliError {
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
                    dich_apt::load_configured_sources(&cli.config).map_err(|_| CliError {
                        code: "source_load_failed",
                        message: "could not load trusted source configuration",
                        trace: Vec::new(),
                    })?;
                let cache = dich_apt::SnapshotJournal::open(&cli.cache).map_err(|_| CliError {
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
                    dich_apt::load_configured_sources(&cli.config).map_err(|_| CliError {
                        code: "source_load_failed",
                        message: "could not load trusted source configuration",
                        trace: Vec::new(),
                    })?;
                let cache = dich_apt::SnapshotJournal::open(&cli.cache).map_err(|_| CliError {
                    code: "cache_open_failed",
                    message: "could not open protected cache directory",
                    trace: Vec::new(),
                })?;
                let mut indices = 0usize;
                for source in &sources {
                    let report = dich_apt::update_source(
                        source,
                        &cache,
                        freshness,
                        dich_apt::IndexLimits::default(),
                    )
                    .map_err(|_| CliError {
                        code: "update_failed",
                        message: "repository update failed; earlier cache entries may have changed",
                        trace: Vec::new(),
                    })?;
                    indices += report.indices;
                }
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
                let sources =
                    dich_apt::load_configured_sources(&cli.config).map_err(|_| CliError {
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
                    dich_apt::SnapshotJournal::open(&cli.cache).map_err(|_| CliError {
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
                let artifact=dich_apt::fetch_exact(&sources[0],&journal,freshness,request).map_err(|_| CliError { code:"fetch_failed",message:"could not authenticate, download and cache the requested artifact",trace:Vec::new() })?;
                let state = match artifact.state {
                    dich_apt::FetchState::Downloaded => "downloaded",
                    dich_apt::FetchState::Cached => "cached",
                };
                let artifact = artifact.artifact;
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
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({"schema_version":1,"status":"completed","state":state,"installable":false,"name":artifact.name(),"version":artifact.version(),"architecture":artifact.architecture(),"size":artifact.size(),"artifact_sha256":artifact_hash,"release_sha256":release_hash,"component":component})
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
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (package, exact_version, component, max_bytes);
                Err(CliError {
                    code: "unsupported_platform",
                    message: "authenticated fetch requires Linux",
                    trace: Vec::new(),
                })
            }
        }
        Commands::Inspect { file } => {
            #[cfg(target_os = "linux")]
            {
                let report = dich_deb::inspect_path(
                    std::path::Path::new(&file),
                    dich_deb::Limits::default(),
                )
                .map_err(|_| CliError {
                    code: "inspect_failed",
                    message: "could not safely inspect local Debian archive",
                    trace: Vec::new(),
                })?;
                if cli.json {
                    let scripts: Vec<_> = report
                        .scripts
                        .iter()
                        .map(|s| serde_json::json!({"name":s.name,"size":s.size,"sha256":s.sha256}))
                        .collect();
                    println!(
                        "{}",
                        serde_json::json!({"schema_version":1,"status":"completed","trust":"unverified","installable":false,"control_entries":report.control_entries,"control_files":report.control_files,"data_entries":report.data_entries,"data_files":report.data_files,"data_file_bytes":report.data_file_bytes,"scripts":scripts,"triggers_present":report.triggers_present})
                    );
                } else {
                    println!("completed: unverified local archive; installability not established");
                    println!(
                        "control files: {}; data files: {}; data bytes: {}; triggers: {}",
                        report.control_files,
                        report.data_files,
                        report.data_file_bytes,
                        report.triggers_present
                    );
                    for script in report.scripts {
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
                let _ = file;
                Err(CliError {
                    code: "unsupported_platform",
                    message: "local archive inspection requires Linux",
                    trace: Vec::new(),
                })
            }
        }
        Commands::Store { command } => {
            #[cfg(target_os = "linux")]
            {
                let db = dich_store::MetadataDb::open_existing(&cli.store_dir).map_err(|_| {
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
                            let objects: Vec<_> = records.iter().map(|r| serde_json::json!({"id":r.id,"kind":match r.kind { dich_store::ObjectKind::Archive => "archive", dich_store::ObjectKind::Tree => "tree" }, "stored_bytes":r.stored_bytes})).collect();
                            println!(
                                "{}",
                                serde_json::json!({"schema_version":1,"status":"completed","scope":"metadata_only","objects":objects})
                            );
                        } else {
                            println!("completed: metadata only; object contents not verified");
                            for r in records {
                                println!(
                                    "{}\t{}\t{}",
                                    r.id,
                                    match r.kind {
                                        dich_store::ObjectKind::Archive => "archive",
                                        dich_store::ObjectKind::Tree => "tree",
                                    },
                                    r.stored_bytes
                                );
                            }
                        }
                    }
                    StoreCommands::Verify { id, kind } => {
                        let (kind_name, bytes) = match kind {
                            StoreKind::Archive => (
                                "archive",
                                db.verify_archive_object(&id).map(|r| r.total_bytes),
                            ),
                            StoreKind::Tree => {
                                ("tree", db.verify_tree_object(&id).map(|r| r.total_bytes))
                            }
                        };
                        let bytes = bytes.map_err(|_| CliError {
                            code: "store_verify_failed",
                            message: "object does not match protected local metadata",
                            trace: Vec::new(),
                        })?;
                        if cli.json {
                            println!(
                                "{}",
                                serde_json::json!({"schema_version":1,"status":"completed","scope":"local_metadata_only","id":id,"kind":kind_name,"stored_bytes":bytes})
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
            let sources = dich_apt::load_configured_sources(&cli.config).map_err(|_| CliError {
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
        _ => Err(CliError {
            code: "not_implemented",
            message: "not implemented: this operation is not supported",
            trace: Vec::new(),
        }),
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
