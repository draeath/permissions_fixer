//! Core library for `permissions_fixer`.
//!
//! Walks the given paths — directory trees, each staying on its root's
//! filesystem, or single files — never following symlinks, and normalizes
//! the permission bits of each entry to a value derived from the current
//! process umask.

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
compile_error!("permissions_fixer supports Linux and BSD only");

pub mod exec;
pub mod mode;
pub mod scan;

/// Read the current process umask without changing it.
pub fn current_umask() -> u32 {
    // `umask(0)` returns the old mask *and sets the mask to zero*, so the
    // old value must be restored immediately; the net effect is a read.
    // SAFETY: `umask()` only manipulates the process umask.
    let old = unsafe { libc::umask(0) };
    unsafe { libc::umask(old) };
    old & 0o777
}

/// RAII guard that sets the process umask and restores the previous one on drop.
#[derive(Debug)]
pub struct UmaskGuard {
    previous: u32,
}

impl UmaskGuard {
    /// Set the process umask to `mask` until the guard is dropped.
    pub fn set(mask: u32) -> Self {
        let previous = current_umask();
        // SAFETY: `umask()` with a 9-bit value only changes the process mask.
        unsafe { libc::umask(mask) };
        Self { previous }
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: restore the saved 9-bit mask.
        unsafe { libc::umask(self.previous) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn current_umask_roundtrip() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let before = current_umask();
        {
            let _guard = UmaskGuard::set(0o037);
            assert_eq!(current_umask(), 0o037);
        }
        assert_eq!(current_umask(), before);
    }
}
