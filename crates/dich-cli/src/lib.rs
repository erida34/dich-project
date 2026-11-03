#![forbid(unsafe_code)]
//! Dich command-line interface; package installation remains unsupported.
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "dich", about = "Versioned package store using Debian/Ubuntu sources (experimental)", version, long_about = None)]
pub struct Cli {
    /// Path to trusted source policy
    #[arg(long, global = true, default_value = "/etc/dich/sources.toml")]
    pub config: PathBuf,
    /// Emit versioned JSON output and errors
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Refresh authenticated package metadata (planned)
    Update,
    /// Find packages (planned)
    Search { query: String },
    /// Display package metadata (planned)
    Show { package: String },
    /// List available package versions (planned)
    Versions { package: String },
    /// Show dependency plan (planned)
    Plan { package: String },
    /// Download a verified package (planned)
    Fetch { package: String },
    /// Inspect a local Debian archive (planned)
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
    /// Manage local store (planned)
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
    Ls,
    Verify,
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
}
impl CliError {
    pub fn render(&self, json: bool) -> String {
        if json {
            serde_json::json!({"schema_version": 1, "status": "error", "error": {"code": self.code, "message": self.message}}).to_string()
        } else {
            format!("dich: error: {}", self.message)
        }
    }
}

pub fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Commands::Sources {
            command: SourcesCommands::List,
        } => {
            let sources = dich_apt::load_configured_sources(&cli.config).map_err(|_| CliError {
                code: "source_load_failed",
                message: "could not load trusted source configuration",
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
