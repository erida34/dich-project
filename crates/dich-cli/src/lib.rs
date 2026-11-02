#![forbid(unsafe_code)]
//! Dich CLI contract; no package operations are available in the scaffold.
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "dich", about = "Versioned package store using Debian/Ubuntu sources (experimental)", version, long_about = None)]
pub struct Cli {
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
    /// Manage repositories (planned)
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
    List,
}

pub fn run(_cli: Cli) -> Result<(), &'static str> {
    Err(
        "not implemented: Dich currently provides a CLI scaffold only; no package operations are supported",
    )
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
