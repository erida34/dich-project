#![forbid(unsafe_code)]
use crate::{Cli, CliError};
use std::path::{Path, PathBuf};

/// Resolved runtime configuration paths for Dich commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPaths {
    pub config: PathBuf,
    pub cache: PathBuf,
    pub store_dir: PathBuf,
    pub is_rootless: bool,
}

impl ResolvedPaths {
    pub fn resolve(cli: &Cli) -> Self {
        let is_rootless = if cli.rootless {
            true
        } else if cli.system {
            false
        } else {
            #[cfg(target_os = "linux")]
            {
                rustix::process::geteuid().as_raw() != 0
            }
            #[cfg(not(target_os = "linux"))]
            {
                false
            }
        };

        let store_dir = if let Some(dir) = &cli.store_dir {
            dir.clone()
        } else if is_rootless {
            user_data_dir()
        } else {
            PathBuf::from("/var/lib/dich")
        };

        let cache = if let Some(dir) = &cli.cache {
            dir.clone()
        } else if is_rootless {
            user_cache_dir()
        } else {
            PathBuf::from("/var/cache/dich")
        };

        let config = if let Some(path) = &cli.config {
            path.clone()
        } else if is_rootless {
            let user_cfg = user_config_path();
            if user_cfg.exists() {
                user_cfg
            } else if Path::new("/etc/dich/sources.toml").exists() {
                PathBuf::from("/etc/dich/sources.toml")
            } else {
                user_cfg
            }
        } else {
            PathBuf::from("/etc/dich/sources.toml")
        };

        Self {
            config,
            cache,
            store_dir,
            is_rootless,
        }
    }
}

fn user_data_dir() -> PathBuf {
    if let Some(val) = std::env::var_os("XDG_DATA_HOME") {
        if !val.is_empty() {
            return PathBuf::from(val).join("dich");
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("dich");
        }
    }
    PathBuf::from("/var/lib/dich")
}

fn user_cache_dir() -> PathBuf {
    if let Some(val) = std::env::var_os("XDG_CACHE_HOME") {
        if !val.is_empty() {
            return PathBuf::from(val).join("dich");
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".cache").join("dich");
        }
    }
    PathBuf::from("/var/cache/dich")
}

fn user_config_path() -> PathBuf {
    if let Some(val) = std::env::var_os("XDG_CONFIG_HOME") {
        if !val.is_empty() {
            return PathBuf::from(val).join("dich").join("sources.toml");
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home)
                .join(".config")
                .join("dich")
                .join("sources.toml");
        }
    }
    PathBuf::from("/etc/dich/sources.toml")
}

/// Ensure that a directory path exists and has secure 0700 permissions.
/// Traverses component by component without following symlinks and checks ownership.
#[cfg(target_os = "linux")]
pub fn ensure_private_directory(path: &Path) -> Result<(), CliError> {
    use rustix::fs::{self, AtFlags, CWD, FileType, Mode, OFlags};
    use rustix::process::geteuid;
    use std::path::Component;

    let mut parts = path.components();
    if parts.next() != Some(Component::RootDir) {
        return Err(CliError {
            code: "invalid_path",
            message: "directory must be an absolute path",
            trace: vec![format!("path '{}' is not absolute", path.display())],
        });
    }

    let mut root = fs::openat(
        CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| CliError {
        code: "directory_open_failed",
        message: "could not open filesystem root",
        trace: vec![format!("{}: {}", path.display(), e)],
    })?;

    let components: Vec<_> = parts.collect();
    if components.is_empty() {
        return Err(CliError {
            code: "invalid_path",
            message: "root directory cannot be used as private directory",
            trace: vec![],
        });
    }

    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(CliError {
                code: "invalid_path",
                message: "path contains invalid non-normal components",
                trace: vec![format!("component {:?}", component)],
            });
        };

        let is_leaf = index + 1 == components.len();

        match fs::openat(
            &root,
            *name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(next) => {
                let stat = fs::fstat(&next).map_err(|e| CliError {
                    code: "directory_stat_failed",
                    message: "could not inspect path component",
                    trace: vec![e.to_string()],
                })?;
                if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
                    return Err(CliError {
                        code: "invalid_path",
                        message: "path component exists but is not a directory",
                        trace: vec![format!("component {:?}", name)],
                    });
                }
                if stat.st_uid != 0 && stat.st_uid != geteuid().as_raw() {
                    return Err(CliError {
                        code: "unsafe_ownership",
                        message: "path component is not owned by root or current user",
                        trace: vec![format!("component {:?} uid {}", name, stat.st_uid)],
                    });
                }
                if stat.st_mode & 0o022 != 0 {
                    return Err(CliError {
                        code: "unsafe_permissions",
                        message: "path component is group or world writable",
                        trace: vec![format!("component {:?} mode {:o}", name, stat.st_mode)],
                    });
                }
                if is_leaf && (stat.st_mode & 0o077 != 0) {
                    if stat.st_uid == geteuid().as_raw() {
                        let _ = fs::chmodat(
                            &root,
                            *name,
                            Mode::from_bits_truncate(0o700),
                            AtFlags::empty(),
                        );
                    } else {
                        return Err(CliError {
                            code: "unsafe_permissions",
                            message: "private directory must have mode 0700",
                            trace: vec![format!("mode {:o}", stat.st_mode)],
                        });
                    }
                }
                root = next;
            }
            Err(rustix::io::Errno::NOENT) => {
                let stat = fs::fstat(&root).map_err(|e| CliError {
                    code: "directory_stat_failed",
                    message: "could not inspect parent component",
                    trace: vec![e.to_string()],
                })?;
                if stat.st_uid != geteuid().as_raw() && stat.st_uid != 0 {
                    return Err(CliError {
                        code: "unsafe_ownership",
                        message: "cannot create directory in parent not owned by current user",
                        trace: vec![format!("parent uid {}", stat.st_uid)],
                    });
                }
                fs::mkdirat(&root, *name, Mode::from_bits_truncate(0o700)).map_err(|e| {
                    if e == rustix::io::Errno::ACCESS {
                        CliError {
                            code: "permission_denied",
                            message: "permission denied creating directory component; privileged operations require root or rootless mode",
                            trace: vec![format!("mkdir {:?}: {}", name, e)],
                        }
                    } else {
                        CliError {
                            code: "directory_create_failed",
                            message: "failed to create private directory component",
                            trace: vec![format!("mkdir {:?}: {}", name, e)],
                        }
                    }
                })?;
                root = fs::openat(
                    &root,
                    *name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|e| CliError {
                    code: "directory_open_failed",
                    message: "could not open newly created directory component",
                    trace: vec![format!("open {:?}: {}", name, e)],
                })?;
            }
            Err(rustix::io::Errno::ACCESS) => {
                return Err(CliError {
                    code: "permission_denied",
                    message: "permission denied accessing directory component; privileged operations require root or rootless mode",
                    trace: vec![format!("open {:?}: {}", name, rustix::io::Errno::ACCESS)],
                });
            }
            Err(err) => {
                return Err(CliError {
                    code: "directory_open_failed",
                    message: "could not access directory component",
                    trace: vec![format!("open {:?}: {}", name, err)],
                });
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn ensure_private_directory(path: &Path) -> Result<(), CliError> {
    std::fs::create_dir_all(path).map_err(|e| CliError {
        code: "directory_create_failed",
        message: "could not create private directory",
        trace: vec![e.to_string()],
    })
}
