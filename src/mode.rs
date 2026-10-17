//! Umask-derived permission computation.

/// The permission bits a regular file gets under `umask` (`0666 & !umask`).
pub fn file_mode(umask: u32) -> u32 {
    0o666 & !umask & 0o777
}

/// The permission bits a directory gets under `umask` (`0777 & !umask`).
pub fn dir_mode(umask: u32) -> u32 {
    0o777 & !umask & 0o777
}

/// Add the execute bit in every permission class that has the read bit.
pub fn exec_if_read(bits: u32) -> u32 {
    bits | ((bits & 0o444) >> 2)
}

/// The desired 9-bit mode for one entry.
///
/// Executability only ever applies to files; directories already carry
/// execute in every class that has read.
pub fn desired_mode(umask: u32, is_dir: bool, executable: bool) -> u32 {
    let base = if is_dir {
        dir_mode(umask)
    } else {
        file_mode(umask)
    };
    if executable && !is_dir {
        exec_if_read(base)
    } else {
        base
    }
}

/// Merge the desired rwx bits into the current mode, preserving the
/// setuid, setgid, and sticky bits.
pub fn merge(current: u32, desired: u32) -> u32 {
    (current & 0o7000) | (desired & 0o777)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn umask_022() {
        assert_eq!(file_mode(0o022), 0o644);
        assert_eq!(dir_mode(0o022), 0o755);
    }

    #[test]
    fn umask_077() {
        assert_eq!(file_mode(0o077), 0o600);
        assert_eq!(dir_mode(0o077), 0o700);
    }

    #[test]
    fn umask_zero_and_full() {
        assert_eq!(file_mode(0), 0o666);
        assert_eq!(dir_mode(0), 0o777);
        assert_eq!(file_mode(0o777), 0);
        assert_eq!(dir_mode(0o777), 0);
    }

    #[test]
    fn umask_032() {
        assert_eq!(file_mode(0o032), 0o644);
        assert_eq!(dir_mode(0o032), 0o745);
    }

    #[test]
    fn umask_high_bits_are_ignored() {
        assert_eq!(file_mode(0o7022), 0o644);
        assert_eq!(dir_mode(0o7077), 0o700);
    }

    #[test]
    fn exec_if_read_is_per_class() {
        assert_eq!(exec_if_read(0o644), 0o755);
        assert_eq!(exec_if_read(0o600), 0o700);
        assert_eq!(exec_if_read(0o666), 0o777);
        assert_eq!(exec_if_read(0o040), 0o050);
        assert_eq!(exec_if_read(0o001), 0o001);
        assert_eq!(exec_if_read(0o700), 0o700);
        assert_eq!(exec_if_read(0), 0);
    }

    #[test]
    fn desired_mode_examples() {
        assert_eq!(desired_mode(0o022, false, false), 0o644);
        assert_eq!(desired_mode(0o022, true, false), 0o755);
        assert_eq!(desired_mode(0o022, false, true), 0o755);
        assert_eq!(desired_mode(0o077, false, false), 0o600);
        assert_eq!(desired_mode(0o077, true, false), 0o700);
        assert_eq!(desired_mode(0o077, false, true), 0o700);
        // directories are never treated as executables
        assert_eq!(desired_mode(0, true, true), 0o777);
    }

    #[test]
    fn desired_mode_exec_needs_read() {
        // umask 0277: file base is 0400 (owner read only) -> exec only for the owner
        assert_eq!(desired_mode(0o277, false, true), 0o500);
        // umask 0777: no read anywhere -> no exec anywhere
        assert_eq!(desired_mode(0o777, false, true), 0);
    }

    #[test]
    fn merge_preserves_special_bits() {
        assert_eq!(merge(0o4600, 0o644), 0o4644);
        assert_eq!(merge(0o2700, 0o755), 0o2755);
        assert_eq!(merge(0o1600, 0o644), 0o1644);
        assert_eq!(merge(0o4755, 0o755), 0o4755);
        assert_eq!(merge(0o0644, 0o755), 0o0755);
    }
}
