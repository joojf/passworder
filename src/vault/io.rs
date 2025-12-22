//! Vault file IO primitives.
//!
//! The goals of this module are:
//! - Restrictive file permissions (0600) for both vault and lock files.
//! - Safe concurrent usage via advisory file locks.
//! - Crash-safe writes via the write-temp, fsync, atomic-rename pattern.
//!
//! This module is intentionally low-level and format-agnostic: it reads/writes
//! raw bytes. Higher layers own parsing, encryption, and schema decisions.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    Shared,
    Exclusive,
}

#[derive(Debug)]
pub struct VaultLock {
    #[allow(dead_code)]
    file: File,
}

impl VaultLock {
    pub fn acquire(lock_path: &Path, mode: LockMode) -> Result<Self, VaultIoError> {
        ensure_parent_dir(lock_path)?;

        #[cfg(unix)]
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(lock_path)?;

        #[cfg(not(unix))]
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(lock_path)?;

        set_permissions_0600(lock_path)?;
        lock_file(&file, mode)?;
        Ok(Self { file })
    }
}

#[derive(Debug, Error)]
pub enum VaultIoError {
    #[error("io error")]
    Io(#[from] std::io::Error),

    #[error("unsupported platform for file locking")]
    UnsupportedPlatform,

    #[error("failed to acquire file lock")]
    LockFailed,

    #[error("vault path has no parent directory")]
    NoParentDir,
}

pub fn lock_path_for_vault(vault_path: &Path) -> PathBuf {
    let mut p = vault_path.as_os_str().to_os_string();
    p.push(".lock");
    PathBuf::from(p)
}

pub fn read_vault_bytes(vault_path: &Path) -> Result<Vec<u8>, VaultIoError> {
    let _lock = VaultLock::acquire(&lock_path_for_vault(vault_path), LockMode::Shared)?;

    let mut file = File::open(vault_path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

pub fn write_vault_bytes_atomic(vault_path: &Path, bytes: &[u8]) -> Result<(), VaultIoError> {
    let _lock = VaultLock::acquire(&lock_path_for_vault(vault_path), LockMode::Exclusive)?;
    ensure_parent_dir(vault_path)?;

    let dir = vault_path.parent().ok_or(VaultIoError::NoParentDir)?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;

    tmp.as_file_mut().write_all(bytes)?;
    tmp.as_file_mut().sync_all()?;

    #[cfg(unix)]
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;

    let _persisted = tmp.persist(vault_path).map_err(std::io::Error::from)?;
    set_permissions_0600(vault_path)?;

    fsync_dir(dir)?;
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<(), VaultIoError> {
    let parent = path.parent().ok_or(VaultIoError::NoParentDir)?;
    fs::create_dir_all(parent)?;
    Ok(())
}

fn set_permissions_0600(path: &Path) -> Result<(), VaultIoError> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn fsync_dir(dir: &Path) -> Result<(), VaultIoError> {
    #[cfg(unix)]
    {
        let file = File::open(dir)?;
        file.sync_all()?;
    }
    Ok(())
}

fn lock_file(file: &File, mode: LockMode) -> Result<(), VaultIoError> {
    #[cfg(unix)]
    unsafe {
        let op = match mode {
            LockMode::Shared => libc::LOCK_SH,
            LockMode::Exclusive => libc::LOCK_EX,
        };

        let rc = libc::flock(file.as_raw_fd(), op);
        if rc == 0 {
            return Ok(());
        }
        return Err(VaultIoError::LockFailed);
    }

    #[cfg(not(unix))]
    {
        let _ = file;
        let _ = mode;
        Err(VaultIoError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_is_atomic_and_permissions_are_restrictive() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.pwder");

        let a = vec![b'a'; 1024 * 64];
        let b = vec![b'b'; 1024 * 64];

        write_vault_bytes_atomic(&vault_path, &a).unwrap();
        let read = read_vault_bytes(&vault_path).unwrap();
        assert_eq!(read, a);

        write_vault_bytes_atomic(&vault_path, &b).unwrap();
        let read = read_vault_bytes(&vault_path).unwrap();
        assert_eq!(read, b);

        #[cfg(unix)]
        {
            let mode = fs::metadata(&vault_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);

            let lock_path = lock_path_for_vault(&vault_path);
            let lock_mode = fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(lock_mode, 0o600);
        }
    }

    #[test]
    fn concurrent_writers_do_not_corrupt_file() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let vault_path = Arc::new(dir.path().join("vault.pwder"));

        let writer = |byte: u8| {
            let vault_path = vault_path.clone();
            thread::spawn(move || {
                for _ in 0..50 {
                    let payload = vec![byte; 1024 * 32];
                    write_vault_bytes_atomic(&vault_path, &payload).unwrap();
                    let read = read_vault_bytes(&vault_path).unwrap();
                    assert_eq!(read.len(), payload.len());
                    let first = read[0];
                    assert!(first == b'x' || first == b'y');
                    assert!(read.iter().all(|b| *b == first));
                }
            })
        };

        let t1 = writer(b'x');
        let t2 = writer(b'y');

        t1.join().unwrap();
        t2.join().unwrap();

        let final_bytes = read_vault_bytes(&vault_path).unwrap();
        assert!(final_bytes.iter().all(|b| *b == b'x') || final_bytes.iter().all(|b| *b == b'y'));
    }
}
