//! Shared helpers for the integration tests.

use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};

use permissions_fixer::UmaskGuard;

static UMASK_LOCK: Mutex<()> = Mutex::new(());

pub struct MaskGuard {
    _lock: MutexGuard<'static, ()>,
    _mask: UmaskGuard,
}

/// Set the test process umask (inherited by any binary we spawn) and
/// restore it on drop; serializes tests that mutate the umask.
pub fn mask(m: u32) -> MaskGuard {
    MaskGuard {
        _lock: UMASK_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        _mask: UmaskGuard::set(m),
    }
}

pub fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_permissions_fixer"))
}

pub fn write_file(path: &Path, contents: &[u8], mode: u32) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

pub fn make_dir(path: &Path, mode: u32) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

pub fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

pub struct Run {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// Spawn the binary with the given arguments and capture its output.
pub fn run(args: Vec<String>) -> Run {
    let out = Command::new(bin())
        .args(&args)
        .output()
        .expect("spawn permissions_fixer");
    Run {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}
