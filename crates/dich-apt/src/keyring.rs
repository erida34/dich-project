use crate::{SignatureError, Source};

/// Open the configured keyring without following symlinks, rejecting untrusted ownership,
/// writable directories, non-regular files and oversized input. Linux only.
#[cfg(target_os = "linux")]
pub fn read_configured_keyring(source: &Source) -> Result<Vec<u8>, SignatureError> {
    read_trusted_file(std::path::Path::new(source.keyring()), 4 * 1024 * 1024)
}

#[cfg(target_os = "linux")]
pub(crate) fn read_trusted_file(
    path: &std::path::Path,
    limit: usize,
) -> Result<Vec<u8>, SignatureError> {
    use rustix::{
        fs::{self, CWD, FileType, Mode, OFlags},
        process::geteuid,
    };
    use std::{io::Read, path::Component};

    fn trusted(fd: &impl std::os::fd::AsFd, expected: FileType) -> Result<(), SignatureError> {
        let stat = fs::fstat(fd).map_err(|_| SignatureError::KeyringAccess)?;
        if FileType::from_raw_mode(stat.st_mode) != expected
            || (stat.st_uid != 0 && stat.st_uid != geteuid().as_raw())
            || stat.st_mode & 0o022 != 0
        {
            return Err(SignatureError::KeyringAccess);
        }
        Ok(())
    }

    let mut parts = path.components();
    if parts.next() != Some(Component::RootDir) {
        return Err(SignatureError::KeyringAccess);
    }
    let components: Vec<_> = parts.collect();
    if components.is_empty()
        || components
            .iter()
            .any(|p| !matches!(p, Component::Normal(_)))
    {
        return Err(SignatureError::KeyringAccess);
    }
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut current = fs::openat(CWD, "/", flags | OFlags::DIRECTORY, Mode::empty())
        .map_err(|_| SignatureError::KeyringAccess)?;
    trusted(&current, FileType::Directory)?;
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(SignatureError::KeyringAccess);
        };
        let last = index + 1 == components.len();
        let next = fs::openat(
            &current,
            *name,
            flags
                | if last {
                    OFlags::NONBLOCK
                } else {
                    OFlags::DIRECTORY
                },
            Mode::empty(),
        )
        .map_err(|_| SignatureError::KeyringAccess)?;
        trusted(
            &next,
            if last {
                FileType::RegularFile
            } else {
                FileType::Directory
            },
        )?;
        current = next;
    }
    let mut bytes = Vec::new();
    std::fs::File::from(current)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SignatureError::KeyringAccess)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err(SignatureError::KeyringAccess);
    }
    Ok(bytes)
}

#[cfg(not(target_os = "linux"))]
pub fn read_configured_keyring(_: &Source) -> Result<Vec<u8>, SignatureError> {
    Err(SignatureError::HelperUnavailable)
}
